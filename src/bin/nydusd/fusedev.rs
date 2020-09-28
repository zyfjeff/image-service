// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::fs::File;
use std::io::Result;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicI32, Ordering},
    mpsc::{channel, Receiver, Sender},
    Arc, Mutex, Once,
};
use std::thread;

use fuse_rs::api::{server::Server, Vfs, VfsOptions};
use rust_fsm::*;
use serde::{Deserialize, Serialize};
use snapshot::Persist;
use versionize::VersionMap;
use versionize::{Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vmm_sys_util::eventfd::EventFd;

use crate::daemon;
use crate::{EVENT_MANAGER_RUN, EXIT_EVTFD};
use daemon::{DaemonError, DaemonResult, DaemonState, Error, NydusDaemon};
use nydus_utils::{eio, eother, FuseChannel, FuseSession};
use upgrade_manager::fd_resource::FdResource;
use upgrade_manager::resource::{Resource, ResourceType, VersionMapGetter};
use upgrade_manager::UPGRADE_MGR;

static FUSE_INIT: Once = Once::new();

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
    pub session: Mutex<FuseSession>,
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
/// try to push `Successful` event to state machine to trigger state transition. But
/// a real fuse message except `init` may already transit the state in nature, which means the
/// session already begin to serve within the new nydusd process.
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

    Init => {
        Mount => Ready [StartService],
        Takeover => Upgrade [Restore],
    },
    Ready => {
        Stop => Die [Umount],
        InitMsg => Running [Persist],
        Successful => Running,
        // This should rarely happen because if supervisor does not already obtain
        // internal upgrade related stuff, why should it try to kill me?
        Exit => Interrupt [TerminateFuseService],
    },
    Upgrade(Successful) => Ready[StartService],
    Running => {
        InitMsg => Running,
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
                    "from {:?} to {:?}, input {:?} output {:?}",
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
                        FusedevStateMachineOutput::Umount => d.session.lock().unwrap().umount(),
                        FusedevStateMachineOutput::TerminateFuseService => {
                            d.set_state(DaemonState::INTERRUPT);
                            d.interrupt();
                            Ok(())
                        }
                        FusedevStateMachineOutput::Restore => {
                            d.set_state(DaemonState::UPGRADE);
                            d.restore().map_err(|e| eother!(e))
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
            self.session.lock().unwrap().deref(),
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
        self.on_event(FusedevStateMachineInput::Successful)?;

        Ok(())
    }

    fn save(&self) -> DaemonResult<()> {
        if self.get_state() != DaemonState::RUNNING {
            return Err(DaemonError::NotReady);
        }

        let mut mgr = UPGRADE_MGR.lock().expect("Lock is not poisoned");

        if let Some(res) = mgr.get_resource(ResourceType::FuseDevFd) {
            // Save fuse fd and daemon opaque data to remote uds server
            return (res as &mut FdResource)
                .save(&self)
                .map_err(|_| DaemonError::SendFd);
        }

        Err(DaemonError::NoResource)
    }

    fn restore(&self) -> DaemonResult<()> {
        let mut mgr = UPGRADE_MGR.lock().expect("Lock is not poisoned");

        if let Some(res) = mgr.get_resource(ResourceType::FuseDevFd) {
            let res = res as &mut FdResource;
            // Restore daemon opaque data from remote uds server (implemented by Persist)
            let _: &Self = res.restore(self).map_err(|_| DaemonError::RecvFd)?;
            // Restore fuse fd from remote uds server
            self.session.lock().unwrap().file = unsafe { Some(File::from_raw_fd(res.fds[0])) };
            return Ok(());
        }

        Err(DaemonError::NoResource)
    }
}

impl<'a> Persist<'a> for &'a FusedevDaemon {
    type State = DaemonOpaque;
    type ConstructorArgs = &'a FusedevDaemon;
    type Error = Error;

    fn save(&self) -> Self::State {
        DaemonOpaque {
            vfs_opts: self.vfs.get_opts(),
        }
    }

    fn restore(
        daemon: Self::ConstructorArgs,
        opaque: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        daemon.vfs.set_opts(opaque.vfs_opts);
        Ok(daemon)
    }
}

pub fn create_nydus_daemon(
    mountpoint: &str,
    vfs: Arc<Vfs>,
    supervisor: Option<String>,
    id: Option<String>,
    threads_cnt: u32,
    upgrade: bool,
) -> Result<Arc<dyn NydusDaemon + Send>> {
    let (trigger, rx) = channel::<FusedevStateMachineInput>();
    let session = FuseSession::new(Path::new(mountpoint), "rafs", "")?;

    let daemon = Arc::new(FusedevDaemon {
        session: Mutex::new(session),
        server: Arc::new(Server::new(vfs.clone())),
        vfs,
        threads: Mutex::new(Vec::new()),
        event_fd: EventFd::new(0).unwrap(),
        state: AtomicI32::new(DaemonState::INIT as i32),
        threads_cnt,
        trigger: Arc::new(Mutex::new(trigger)),
        supervisor: supervisor.clone(),
        id,
    });

    let machine = FusedevDaemonSM::new(daemon.clone(), rx);
    machine.kick_state_machine()?;

    if !upgrade {
        daemon.session.lock().unwrap().mount()?;
        daemon
            .on_event(FusedevStateMachineInput::Mount)
            .map_err(|e| eother!(e))?
    }

    if let Some(supervisor) = supervisor {
        let mut mgr = UPGRADE_MGR.lock().unwrap();
        let fds = if let Some(fd) = daemon.session.lock().unwrap().expose_fuse_fd() {
            vec![fd]
        } else {
            vec![]
        };
        let res = FdResource::new(PathBuf::from(supervisor), fds);
        mgr.add_resource(ResourceType::FuseDevFd, res);
    }

    Ok(daemon)
}

#[derive(Default, Debug, Serialize, Deserialize, Clone, Versionize)]
pub struct DaemonOpaque {
    // Negotiate with kernel when do mount
    vfs_opts: VfsOptions,
}

impl VersionMapGetter for DaemonOpaque {}
