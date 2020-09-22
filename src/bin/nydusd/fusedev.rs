// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use nydus_utils::last_error;
use sendfd::{RecvWithFd, SendWithFd};
use std::any::Any;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Result;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{
    atomic::{AtomicI32, Ordering},
    mpsc::{channel, Receiver, Sender},
    Arc, Mutex, Once,
};

static FUSE_INIT: Once = Once::new();

use std::thread;

use rust_fsm::*;

use serde::{Deserialize, Serialize};

use fuse_rs::api::{server::Server, Vfs, VfsOptions};
use nydus_utils::{einval, eio, eother, FuseChannel, FuseSession};
use vmm_sys_util::eventfd::EventFd;

use crate::daemon;
use daemon::{DaemonError, DaemonResult, DaemonState, Error, NydusDaemon};

use crate::upgrade_manager::{
    Resource, ResourceType, UpgradeManagerError, UpgradeManagerResult, UPGRADE_MGR,
};
use crate::{EVENT_MANAGER_RUN, EXIT_EVTFD};

struct FuseServer {
    server: Arc<Server<Arc<Vfs>>>,
    ch: FuseChannel,
    // read buffer for fuse requests
    buf: Vec<u8>,
    trigger: Arc<Mutex<Sender<FusedevStateMachineInput>>>,
}

type Trigger = Sender<FusedevStateMachineInput>;

impl FuseServer {
    fn new(
        server: Arc<Server<Arc<Vfs>>>,
        se: &FuseSession,
        evtfd: EventFd,
        trigger: Arc<Mutex<Sender<FusedevStateMachineInput>>>,
    ) -> Result<FuseServer> {
        Ok(FuseServer {
            server,
            ch: se.new_channel(evtfd)?,
            buf: Vec::with_capacity(se.bufsize()),
            trigger,
        })
    }

    fn svc_loop(&mut self) -> Result<()> {
        // Safe because we have already reserved the capacity
        unsafe {
            self.buf.set_len(self.buf.capacity());
        }

        // Given error EBADF, it means kernel has shut down this session.
        let _ebadf = std::io::Error::from_raw_os_error(libc::EBADF);
        let mut exit = false;
        loop {
            if let Some(reader) = self.ch.get_reader(&mut self.buf, &mut exit)? {
                let writer = self.ch.get_writer()?;
                if let Err(e) = self.server.handle_message(reader, writer, None) {
                    match e {
                        fuse_rs::Error::EncodeMessage(_ebadf) => {
                            return Err(eio!("fuse session has been shut down"));
                        }
                        _ => {
                            error!("Handling fuse message, {}", Error::ProcessQueue(e));
                            continue;
                        }
                    }
                }
            } else {
                info!("fuse server exits");
                break;
            }

            if exit {
                info!("Fuse service is stopped manually");
                break;
            }

            // We have to ensure that fuse service loop actually runs, which means
            // the first `init` message has been handled and kernel and daemon have
            // negotiated capabilities. Then we can store those capabilities.
            FUSE_INIT.call_once(|| {
                self.trigger
                    .lock()
                    .unwrap()
                    .send(FusedevStateMachineInput::InitMsg)
                    .unwrap()
            });
        }

        Ok(())
    }
}

pub struct FusedevDaemon {
    server: Arc<Server<Arc<Vfs>>>,
    vfs: Arc<Vfs>,
    pub session: Mutex<Option<FuseSession>>,
    threads: Mutex<Vec<Option<thread::JoinHandle<Result<()>>>>>,
    event_fd: EventFd,
    state: AtomicI32,
    pub threads_cnt: u32,
    trigger: Arc<Mutex<Trigger>>,
    pub supervisor: Option<String>,
    pub id: Option<String>,
}

/// Fusedev daemon work flow is controlled by state machine.
/// `Init` means nydusd is just started and potentially configured well but not
/// yet negotiate with kernel the capabilities of both sides. It even does not try
/// to set up fuse session by mounting `/fuse/dev`.
/// `Ready` means nydusd has successfully prepared all the stuff needed to work as a
/// user-space fuse filesystem, however, the essential capabilities negotiation is not
/// done. So nydusd is still waiting for fuse `Init` message to achieve `Running` state.
/// Nydusd can as well transit to `Upgrade` state from `Init` when getting started, which
/// only happens during live upgrade progress. Then we don't have to do kernel mount again
/// to set up a session but try to reuse a fuse fd from somewhere else. In this state, we
/// don't have in hand event to send to state machine to trigger state transition. But
/// a real fuse message except `init` will transit the state in nature, which means the
/// session also begin to serve from the new nydusd process.
/// `Interrupt` state means nydusd has shutdown fuse server, which means no more message will
/// be read from kernel and handled and no pending and in-flight fuse message exists. But the
/// nydusd daemon should be alive and wait for coming events.
/// `Die` state means the whole nydusd process is going to die.
struct FusedevDaemonSM {
    sm: StateMachine<FusedevStateMachine>,
    daemon: Arc<FusedevDaemon>,
    event_collector: Receiver<FusedevStateMachineInput>,
}

state_machine! {
    derive(Debug, Clone)
    FusedevStateMachine(Init)

    Init(Mount) => Ready [StartService],
    Init(Takeover) => Upgrade [Restore],
    Ready(Stop) => Die [Umount],
    Upgrade(Successful) => Ready[StartService],
    Ready(InitMsg) => Running [Persist],
    Running => {
        Exit => Interrupt [TerminateFuseService],
        Stop =>  Die [Umount],
    },
    Interrupt(Stop) => Die,
}

impl FusedevDaemonSM {
    fn new(d: Arc<FusedevDaemon>, rx: Receiver<FusedevStateMachineInput>) -> Self {
        Self {
            sm: StateMachine::new(),
            daemon: d,
            event_collector: rx,
        }
    }

    fn kick_state_machine(mut self) -> Result<()> {
        thread::Builder::new()
            .name("state_machine".to_string())
            .spawn(move || loop {
                let event = self
                    .event_collector
                    .recv()
                    .expect("Event channel can't be broken!");
                let last = self.sm.state().clone();
                let input = &event;
                let action = self
                    .sm
                    .consume(&event)
                    .expect("Daemon state machine goes insane, this is critical error!");

                let d = self.daemon.as_ref();
                let cnt = d.threads_cnt;
                let cur = self.sm.state();
                info!(
                    "From {:?} to {:?}, input {:?} output {:?}",
                    last, cur, input, &action
                );
                match action {
                    Some(a) => match a {
                        FusedevStateMachineOutput::StartService => {
                            d.set_state(DaemonState::RUNNING);
                            d.start(cnt)
                        }
                        FusedevStateMachineOutput::Persist => d.persist(),
                        // A proper state machine can ensure that `session` must be contained!
                        FusedevStateMachineOutput::Umount => {
                            d.session.lock().unwrap().as_mut().unwrap().umount()
                        }
                        FusedevStateMachineOutput::TerminateFuseService => {
                            d.set_state(DaemonState::INTERRUPT);
                            d.interrupt();
                            Ok(())
                        }
                        FusedevStateMachineOutput::Restore => {
                            d.set_state(DaemonState::UPGRADE);
                            // Drop lock here as restore also needs daemon lock
                            let mgr = UPGRADE_MGR.lock().expect("Lock is not poisoned");
                            mgr.get_resource(ResourceType::Fd)
                                .map_or(Err(DaemonError::NoResource), |r| {
                                    r.load().map_err(|_| DaemonError::RestoreState)
                                })
                                .unwrap_or_else(|e| error!("{}", e));
                            info!("restore");
                            Ok(())
                        }
                    },
                    _ => continue,
                }
                .unwrap_or_else(|e| error!("Handle action failed. {}", e));
            })
            .map(|_| ())
    }
}

impl FusedevDaemon {
    fn kick_one_server(&self, t: Arc<Mutex<Trigger>>) -> Result<()> {
        let mut s = FuseServer::new(
            self.server.clone(),
            self.session.lock().unwrap().as_ref().unwrap(),
            // Clone event fd must succeed, otherwise fusedev daemon should not work.
            self.event_fd.try_clone().unwrap(),
            t,
        )?;

        let thread = thread::Builder::new()
            .name("fuse_server".to_string())
            .spawn(move || {
                let _ = s.svc_loop();
                EVENT_MANAGER_RUN.store(false, Ordering::Relaxed);
                EXIT_EVTFD
                    .lock()
                    .unwrap()
                    .deref()
                    .as_ref()
                    .unwrap()
                    .write(1)
                    .map_err(|e| {
                        error!("Write event fd failed, {}", e);
                        e
                    })
            })
            .map_err(Error::ThreadSpawn)?;
        self.threads.lock().unwrap().push(Some(thread));
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        let vfs = self.vfs.as_ref();
        let mut mgr = UPGRADE_MGR.lock().unwrap();

        if let Some(res) = mgr.get_resource(ResourceType::Fd) {
            let fd_res = res.as_any().downcast_ref::<FuseDevFdRes>().unwrap();
            let mut new_fd_res = fd_res.clone();
            new_fd_res.opaque.vfs_opts = vfs.get_opts();

            mgr.add_resource(new_fd_res, ResourceType::Fd);
        }

        Ok(())
    }

    fn on_event(&self, event: FusedevStateMachineInput) -> DaemonResult<()> {
        self.trigger
            .lock()
            .unwrap()
            .send(event)
            .map_err(|_| DaemonError::Channel)
    }
}

impl NydusDaemon for FusedevDaemon {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn start(&self, cnt: u32) -> Result<()> {
        for _ in 0..cnt {
            self.kick_one_server(self.trigger.clone())?;
        }
        Ok(())
    }

    fn wait(&self) -> Result<()> {
        let mut threads = self.threads.lock().unwrap();
        for t in threads.deref_mut() {
            if let Some(handle) = t.take() {
                handle.join().map_err(|_| Error::WaitDaemon)??;
            }
        }
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        self.interrupt();
        self.on_event(FusedevStateMachineInput::Stop)
            .map_err(|e| eother!(e))
            .map(|_| ())
    }

    fn id(&self) -> Option<String> {
        self.id.clone()
    }

    fn supervisor(&self) -> Option<String> {
        self.supervisor.clone()
    }

    fn interrupt(&self) {
        self.event_fd.write(1).expect("Stop fuse service loop");
    }

    fn set_state(&self, state: DaemonState) -> DaemonState {
        let old = self.get_state();
        self.state.store(state as i32, Ordering::Relaxed);
        old
    }

    fn get_state(&self) -> DaemonState {
        self.state.load(Ordering::Relaxed).into()
    }

    fn trigger_exit(&self) -> DaemonResult<()> {
        self.on_event(FusedevStateMachineInput::Exit)?;
        // Ensure all fuse threads have be terminated thus this nydusd won't
        // race fuse messages when upgrading.
        self.wait().map_err(|_| DaemonError::ServiceStop)?;
        Ok(())
    }

    fn trigger_takeover(&self) -> DaemonResult<()> {
        // Daemon won't reach `Running` state until the first fuse message arrives.
        // So we don't try to send InitMsg event from here.
        self.on_event(FusedevStateMachineInput::Takeover)?;
        self.on_event(FusedevStateMachineInput::Successful)?;

        Ok(())
    }
}

pub fn create_nydus_daemon(
    mountpoint: &str,
    fs: Arc<Vfs>,
    supervisor: Option<String>,
    id: Option<String>,
    threads_cnt: u32,
    upgrade: bool,
) -> Result<Arc<dyn NydusDaemon + Send>> {
    let (trigger, rx) = channel::<FusedevStateMachineInput>();
    let daemon = Arc::new(FusedevDaemon {
        session: Mutex::new(None),
        server: Arc::new(Server::new(fs.clone())),
        vfs: fs.clone(),
        threads: Mutex::new(Vec::new()),
        event_fd: EventFd::new(0).unwrap(),
        state: AtomicI32::new(DaemonState::INIT as i32),
        threads_cnt,
        trigger: Arc::new(Mutex::new(trigger)),
        supervisor: supervisor.clone(),
        id: id.clone(),
    });

    let machine = FusedevDaemonSM::new(daemon.clone(), rx);
    machine.kick_state_machine()?;

    let mut se = FuseSession::new(Path::new(mountpoint), "rafs", "")?;
    let mut fuse_fd = None;
    if !upgrade {
        se.mount()?;
        fuse_fd = Some(se.expose_fuse_fd());
        daemon
            .on_event(FusedevStateMachineInput::Mount)
            .map_err(|e| eother!(e))?
    }

    *daemon.session.lock().unwrap() = Some(se);

    let d = daemon.clone() as Arc<dyn NydusDaemon + Send>;
    if let Some(id) = id {
        if let Some(supervisor) = supervisor {
            let opaque = ResOpaque {
                version: 1,
                daemon_id: id.clone(),
                vfs_opts: fs.get_opts(),
                threads_cnt,
                opaque: Default::default(),
            };

            let res = FuseDevFdRes::new(fuse_fd, supervisor.as_ref(), id, daemon, opaque, fs);

            UPGRADE_MGR
                .lock()
                .expect("Not expect a poisoned Upgrade Manger lock!")
                .add_resource(res, ResourceType::Fd);
        }
    }

    Ok(d)
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
struct ResOpaque {
    version: u32,
    daemon_id: String,
    opaque: String,
    threads_cnt: u32,
    // Negotiate with kernel when do mount
    vfs_opts: VfsOptions,
}

pub struct FuseDevFdRes {
    fuse_fd: AtomicI32,
    uds_path: OsString,
    daemon_id: String,
    daemon: Arc<dyn NydusDaemon + Send + Sync>,
    opaque: ResOpaque,
    vfs: Arc<Vfs>,
}

impl Clone for FuseDevFdRes {
    fn clone(&self) -> Self {
        FuseDevFdRes {
            fuse_fd: AtomicI32::new(self.fuse_fd.load(Ordering::Relaxed)),
            uds_path: self.uds_path.clone(),
            daemon_id: self.daemon_id.clone(),
            daemon: self.daemon.clone(),
            opaque: self.opaque.clone(),
            vfs: self.vfs.clone(),
        }
    }
}

impl FuseDevFdRes {
    fn new(
        fd: Option<RawFd>,
        uds: &OsStr,
        daemon_id: String,
        daemon: Arc<dyn NydusDaemon + Send + Sync>,
        opaque: ResOpaque,
        vfs: Arc<Vfs>,
    ) -> Self {
        FuseDevFdRes {
            fuse_fd: fd.map(AtomicI32::new).unwrap_or_else(|| AtomicI32::new(-1)),
            uds_path: uds.to_os_string(),
            daemon_id,
            daemon,
            opaque,
            vfs,
        }
    }

    pub fn connect(&self) -> Result<UnixStream> {
        let stream = UnixStream::connect(&self.uds_path).map_err(|e| {
            error!("Connect to {:?} failed, {:?}", &self.uds_path, e);
            e
        })?;
        Ok(stream)
    }

    fn send_fd(&self, stream: &UnixStream) -> Result<usize> {
        let opaque_buf = serde_json::to_string(&self.opaque).unwrap().into_bytes();
        let mut fds: [RawFd; 8] = Default::default();
        fds[0] = self.fuse_fd.load(Ordering::Acquire);
        stream
            .send_with_fd(&opaque_buf, &fds)
            .map_err(|e| last_error!(e))
    }

    fn recv_fd(&self, stream: &UnixStream) -> Result<ResOpaque> {
        // TODO: Is 8K buffer large enough?
        let mut opaque = vec![0u8; 8192];
        let mut fds: [RawFd; 8] = Default::default();
        let (opaque_size, fds_count) = stream.recv_with_fd(&mut opaque, &mut fds).map_err(|e| {
            error!("Failed in receiving fd");
            e
        })?;

        if fds_count != 1 {
            warn!("There should be only one fd sent, but {} comes", fds_count);
        }

        info!("daemon id is {}, receiving fd {}", self.daemon_id, fds[0]);

        self.fuse_fd.store(fds[0], Ordering::Release);

        serde_json::from_str::<ResOpaque>(
            std::str::from_utf8(&opaque[..opaque_size]).map_err(|e| einval!(e))?,
        )
        .map_err(|e| {
            error!(" Opaque can't ba parsed, {} ", e);
            einval!(e)
        })
    }
}

impl Resource for FuseDevFdRes {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn store(&self) -> UpgradeManagerResult<()> {
        let d = self.daemon.as_ref();

        if d.get_state() != DaemonState::RUNNING {
            return Err(UpgradeManagerError::NotReady);
        }

        let stream = self.connect().map_err(UpgradeManagerError::Connect)?;
        self.send_fd(&stream)
            .map_err(|_| UpgradeManagerError::SendFd)?;

        // TODO: Ensure stream can be disconnected when being destroyed.

        Ok(())
    }

    fn load(&self) -> UpgradeManagerResult<()> {
        let stream = self.connect().map_err(UpgradeManagerError::Connect)?;
        let opaque = self
            .recv_fd(&stream)
            .map_err(|_| UpgradeManagerError::RecvFd)?;
        // TODO: Read config file again? or store config as opaque into backend?
        // FIXME:
        let d = self
            .daemon
            .as_any()
            .downcast_ref::<FusedevDaemon>()
            .unwrap();
        d.session.lock().unwrap().as_mut().unwrap().file =
            unsafe { Some(File::from_raw_fd(self.fuse_fd.load(Ordering::Acquire))) };
        self.vfs.swap_opts(opaque.vfs_opts);

        // TODO: Ensure stream can be disconnected when being destroyed.

        Ok(())
    }
}
