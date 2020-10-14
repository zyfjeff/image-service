// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::ffi::{CStr, CString};
use std::fs::{metadata, File, OpenOptions};
use std::io::{Result, Write};
use std::ops::{Deref, DerefMut};
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{
    atomic::{AtomicI32, AtomicU64, Ordering},
    mpsc::{channel, Receiver, Sender},
    Arc, Mutex, Once,
};
use std::thread;

use fuse_rs::api::{server::Server, Vfs, VfsOptions};
use rust_fsm::*;
use serde::{Deserialize, Serialize};
use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vmm_sys_util::eventfd::EventFd;

use crate::daemon;
use crate::{EVENT_MANAGER_RUN, EXIT_EVTFD};
use daemon::{DaemonError, DaemonResult, DaemonState, Error, NydusDaemon};
use nydus_utils::{einval, eio, eother, FuseChannel, FuseSession};
use upgrade_manager::fd_resource::FdResource;
use upgrade_manager::resource::{Resource, ResourceName, VersionMapGetter};
use upgrade_manager::UpgradeManager;

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
    /// Fuse connection ID which usually equals to `st_dev`
    conn: AtomicU64,
    failover_policy: FailoverPolicy,
    upgrade_mgr: Mutex<UpgradeManager>,
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
                        FusedevStateMachineOutput::Persist => d.persist().map_err(|e| eother!(e)),
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

    fn persist(&self) -> DaemonResult<()> {
        // With supervisor, we can persist state nowhere.
        if self.supervisor().is_none() {
            return Ok(());
        }

        let mut mgr_guard = self.upgrade_mgr.lock().unwrap();

        // There must be a fuse device fd as Mount has to be done.
        let fds = vec![self.session.lock().unwrap().expose_fuse_fd().unwrap()];

        mgr_guard.add_fd_resource(ResourceName::FuseDevFd, self.supervisor().unwrap(), fds);

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
        if let Some(res) = self
            .upgrade_mgr
            .lock()
            .unwrap()
            .get_resource(ResourceName::FuseDevFd)
        {
            // Save fuse fd and daemon opaque data to remote uds server
            return (res as &mut FdResource)
                .save(&self)
                .map_err(|_| DaemonError::SendFd);
        }

        Err(DaemonError::NoResource)
    }

    fn restore(&self) -> DaemonResult<()> {
        if self.supervisor().is_none() {
            return Err(DaemonError::NoResource);
        }

        let mut mgr_guard = self.upgrade_mgr.lock().unwrap();

        mgr_guard.add_fd_resource(ResourceName::FuseDevFd, self.supervisor().unwrap(), vec![]);

        // Must succeed as it is just added.
        let res = mgr_guard.get_resource(ResourceName::FuseDevFd).unwrap() as &mut FdResource;
        // Restore daemon opaque data from remote uds server
        let _: &Self = res.restore(self).map_err(|_| DaemonError::RecvFd)?;
        // Restore fuse fd from remote uds server

        let conn = self.conn.load(Ordering::Acquire);
        match self.failover_policy {
            FailoverPolicy::Flush => flush_fuse_connection(conn),
            FailoverPolicy::Resend => resend_fuse_requests(conn),
        }

        self.session.lock().unwrap().file = unsafe { Some(File::from_raw_fd(res.fds[0])) };
        Ok(())
    }
}

impl<'a> Persist<'a> for &'a FusedevDaemon {
    type State = DaemonOpaque;
    type ConstructorArgs = &'a FusedevDaemon;
    type Error = Error;

    fn save(&self) -> Self::State {
        DaemonOpaque {
            vfs_opts: self.vfs.get_opts(),
            conn: self.conn.load(Ordering::Acquire),
        }
    }

    fn restore(
        daemon: Self::ConstructorArgs,
        opaque: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        daemon.vfs.set_opts(opaque.vfs_opts);
        daemon.conn.store(opaque.conn, Ordering::Relaxed);
        Ok(daemon)
    }
}

fn is_mounted(mp: impl AsRef<Path>) -> Result<bool> {
    let mounts = CString::new("/proc/self/mounts").unwrap();
    let ty = CString::new("r").unwrap();

    let mounts_stream = unsafe {
        libc::setmntent(
            mounts.as_ptr() as *const libc::c_char,
            ty.as_ptr() as *const libc::c_char,
        )
    };

    loop {
        let mnt = unsafe { libc::getmntent(mounts_stream) };
        if mnt as u32 == libc::PT_NULL {
            break;
        }

        // Mount point path
        if unsafe { CStr::from_ptr((*mnt).mnt_dir) }
            == CString::new(mp.as_ref().as_os_str().as_bytes())?.as_c_str()
        {
            unsafe { libc::endmntent(mounts_stream) };
            return Ok(true);
        }
    }

    unsafe { libc::endmntent(mounts_stream) };

    Ok(false)
}

fn is_sock_residual(sock: impl AsRef<Path>) -> bool {
    if metadata(&sock).is_ok() {
        return UnixStream::connect(&sock).is_err();
    }

    false
}

/// When a nydusd starts, it checks the environment to see if a previous nydusd dies beyond expect.
///     1. See if the mount point is residual by retrieving `/proc/self/mounts`.
///     2. See if the API socket exists and the connection can established or not.
fn is_crashed(path: impl AsRef<Path>, sock: impl AsRef<Path>) -> Result<bool> {
    if is_mounted(path)? && is_sock_residual(sock) {
        warn!("A previous daemon crashed! Try to failover later.");
        return Ok(true);
    }

    Ok(false)
}

fn calc_fuse_conn(mp: impl AsRef<Path>) -> Result<u64> {
    let st = metadata(mp)?;
    Ok(st.st_dev())
}

/// There might be some in-flight fuse requests when nydusd terminates out of sudden.
/// According to FLUSH policy, those requests will be abandoned which means kernel
/// no longer waits for their responses.
fn flush_fuse_connection(conn: u64) {
    info!("Flushing fuse connection {}", conn);
    let control_fs_path = format!("/sys/fs/fuse/connections/{}/flush", conn);

    // TODO: If `flush` file does not exists, we continue the failover progress but
    // should throw alarm out.

    OpenOptions::new()
        .write(true)
        .open(control_fs_path)
        .map(|mut f| {
            f.write_all(b"1")
                .unwrap_or_else(|e| error!("Flush failed. {:?}", e))
        })
        .unwrap_or_else(|e| error!("Open `flush` file failed. {:?}", e));
}

fn resend_fuse_requests(conn: u64) {
    info!("Resending fuse connection {}", conn);
    let control_fs_path = format!("/sys/fs/fuse/connections/{}/reset", conn);

    // TODO: If `resend` file does not exists, we continue the failover progress but
    // should throw alarm out.

    OpenOptions::new()
        .write(true)
        .open(control_fs_path)
        .map(|mut f| {
            f.write_all(b"1")
                .unwrap_or_else(|e| error!("Resend failed. {:?}", e))
        })
        .unwrap_or_else(|e| error!("Open `resend` file failed. {:?}", e));
}

use std::convert::TryFrom;
pub enum FailoverPolicy {
    Flush,
    Resend,
}

impl TryFrom<&str> for FailoverPolicy {
    type Error = std::io::Error;

    fn try_from(p: &str) -> std::result::Result<Self, Self::Error> {
        match p {
            "flush" => Ok(FailoverPolicy::Flush),
            "resend" => Ok(FailoverPolicy::Resend),
            x => Err(einval!(x)),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn create_nydus_daemon(
    mountpoint: &str,
    vfs: Arc<Vfs>,
    supervisor: Option<String>,
    id: Option<String>,
    threads_cnt: u32,
    api_sock: impl AsRef<Path>,
    upgrade: bool,
    fp: FailoverPolicy,
) -> Result<Arc<dyn NydusDaemon + Send>> {
    let (trigger, rx) = channel::<FusedevStateMachineInput>();
    let session = FuseSession::new(Path::new(mountpoint), "rafs", "")?;

    let upgrade_mgr_id = format!(
        "nydus-{}",
        id.clone().unwrap_or_else(|| String::from("temp"))
    );

    let daemon = Arc::new(FusedevDaemon {
        session: Mutex::new(session),
        server: Arc::new(Server::new(vfs.clone())),
        vfs,
        threads: Mutex::new(Vec::new()),
        event_fd: EventFd::new(0).unwrap(),
        state: AtomicI32::new(DaemonState::INIT as i32),
        threads_cnt,
        trigger: Arc::new(Mutex::new(trigger)),
        supervisor,
        id,
        conn: AtomicU64::new(0),
        failover_policy: fp,
        upgrade_mgr: Mutex::new(UpgradeManager::new(upgrade_mgr_id)),
    });

    let machine = FusedevDaemonSM::new(daemon.clone(), rx);
    machine.kick_state_machine()?;

    if !upgrade && !is_crashed(mountpoint, api_sock)? {
        daemon.session.lock().unwrap().mount()?;
        daemon
            .on_event(FusedevStateMachineInput::Mount)
            .map_err(|e| eother!(e))?;
        daemon
            .conn
            .store(calc_fuse_conn(mountpoint)?, Ordering::Relaxed);
    }

    Ok(daemon)
}

#[derive(Default, Debug, Serialize, Deserialize, Clone, Versionize)]
pub struct DaemonOpaque {
    // Negotiate with kernel when do mount
    vfs_opts: VfsOptions,
    conn: u64,
}

impl VersionMapGetter for DaemonOpaque {}
