// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::ffi::{CStr, CString};
use std::fs::{metadata, OpenOptions};
use std::io::{Result, Write};
use std::ops::Deref;
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicI32, AtomicU64, Ordering},
    mpsc::{channel, Receiver, Sender},
    Arc, Mutex, MutexGuard,
};
use std::thread::{self, JoinHandle};

use fuse_rs::api::{server::Server, VersionMapGetter, Vfs};

use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vmm_sys_util::eventfd::EventFd;

use crate::daemon;
use crate::exit_event_manager;
use daemon::{
    DaemonError, DaemonResult, DaemonState, DaemonStateMachineContext, DaemonStateMachineInput,
    DaemonStateMachineSubscriber, FsBackendMountCmd, FsBackendType, NydusDaemon, RafsMountStateSet,
    Trigger,
};
use nydus_utils::{einval, eio, eother, FuseChannel, FuseSession};
use upgrade_manager::backend::unix_domain_socket::UdsBackend;
use upgrade_manager::{OpaqueKind, UpgradeManager, UpgradeMgrError};

const CTRL_FS_CONN: &str = "/sys/fs/fuse/connections";

struct FuseServer {
    server: Arc<Server<Arc<Vfs>>>,
    ch: FuseChannel,
    // read buffer for fuse requests
    buf: Vec<u8>,
}

impl FuseServer {
    fn new(server: Arc<Server<Arc<Vfs>>>, se: &FuseSession, evtfd: EventFd) -> Result<FuseServer> {
        Ok(FuseServer {
            server,
            ch: se.new_channel(evtfd)?,
            buf: Vec::with_capacity(se.bufsize()),
        })
    }

    fn svc_loop(&mut self) -> Result<()> {
        // Safe because we have already reserved the capacity
        unsafe {
            self.buf.set_len(self.buf.capacity());
        }

        // Given error EBADF, it means kernel has shut down this session.
        let _ebadf = std::io::Error::from_raw_os_error(libc::EBADF);
        loop {
            if let Some(reader) = self.ch.get_reader(&mut self.buf)? {
                let writer = self.ch.get_writer()?;
                if let Err(e) = self.server.handle_message(reader, writer, None) {
                    match e {
                        fuse_rs::Error::EncodeMessage(_ebadf) => {
                            return Err(eio!("fuse session has been shut down"));
                        }
                        _ => {
                            error!("Handling fuse message, {}", DaemonError::ProcessQueue(e));
                            continue;
                        }
                    }
                }
            } else {
                info!("fuse server exits");
                break;
            }
        }

        Ok(())
    }
}

pub struct FusedevDaemon {
    server: Arc<Server<Arc<Vfs>>>,
    vfs: Arc<Vfs>,
    pub session: Mutex<FuseSession>,
    thread_tx: Mutex<Option<Sender<JoinHandle<Result<()>>>>>,
    thread_rx: Mutex<Receiver<JoinHandle<Result<()>>>>,
    running_threads: AtomicI32,
    event_fd: EventFd,
    state: AtomicI32,
    pub threads_cnt: u32,
    trigger: Arc<Mutex<Trigger>>,
    result_receiver: Mutex<Receiver<DaemonResult<()>>>,
    pub supervisor: Option<String>,
    pub id: Option<String>,
    /// Fuse connection ID which usually equals to `st_dev`
    conn: AtomicU64,
    failover_policy: FailoverPolicy,
    upgrade_mgr: Option<Mutex<UpgradeManager>>,
}

impl FusedevDaemon {
    fn kick_one_server(&self) -> Result<()> {
        let mut s = FuseServer::new(
            self.server.clone(),
            self.session.lock().unwrap().deref(),
            // Clone event fd must succeed, otherwise fusedev daemon should not work.
            self.event_fd.try_clone().unwrap(),
        )?;

        let thread = thread::Builder::new()
            .name("fuse_server".to_string())
            .spawn(move || {
                let _ = s.svc_loop();
                exit_event_manager();
                // Ignore fuse service error when joining them.
                Ok(())
            })
            .map_err(DaemonError::ThreadSpawn)?;
        // Safe to unwrap because it should be initialized as Some when daemon being created.
        self.thread_tx
            .lock()
            .expect("Not expect poisoned lock.")
            .as_ref()
            .unwrap()
            .send(thread)
            .map_err(|e| eother!(e))?;
        self.running_threads.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

impl DaemonStateMachineSubscriber for FusedevDaemon {
    fn on_event(&self, event: DaemonStateMachineInput) -> DaemonResult<()> {
        self.trigger
            .lock()
            .unwrap()
            .send(event)
            .map_err(|e| DaemonError::Channel(format!("send {:?}", e)))?;

        self.result_receiver
            .lock()
            .expect("Not expect poisoned lock!")
            .recv()
            .map_err(|e| DaemonError::Channel(format!("recv {:?}", e)))?
    }
}

impl NydusDaemon for FusedevDaemon {
    #[inline]
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn start(&self) -> DaemonResult<()> {
        for _ in 0..self.threads_cnt {
            self.kick_one_server()
                .map_err(|e| DaemonError::StartService(format!("{:?}", e)))?;
        }

        // Safe to unwrap because it is should be initialized as Some when daemon is being created.
        drop(
            self.thread_tx
                .lock()
                .expect("Not expect poisoned lock")
                .take()
                .unwrap(),
        );
        Ok(())
    }

    fn wait(&self) -> DaemonResult<()> {
        while let Ok(handle) = self.thread_rx.lock().unwrap().recv() {
            self.running_threads.fetch_sub(1, Ordering::AcqRel);
            handle
                .join()
                .map_err(|e| {
                    DaemonError::WaitDaemon(
                        *e.downcast::<std::io::Error>()
                            .unwrap_or_else(|e| Box::new(eother!(e))),
                    )
                })?
                .map_err(DaemonError::WaitDaemon)?
        }
        if self.running_threads.load(Ordering::Acquire) != 0 {
            warn!("Not all threads are joined.");
        }
        Ok(())
    }

    fn disconnect(&self) -> DaemonResult<()> {
        self.session
            .lock()
            .expect("Not expect poisoned lock.")
            .umount()
            .map_err(DaemonError::SessionShutdown)
    }

    #[inline]
    fn id(&self) -> Option<String> {
        self.id.clone()
    }

    #[inline]
    fn supervisor(&self) -> Option<String> {
        self.supervisor.clone()
    }

    #[inline]
    fn interrupt(&self) {
        self.event_fd.write(1).expect("Stop fuse service loop");
    }

    #[inline]
    fn set_state(&self, state: DaemonState) {
        self.state.store(state as i32, Ordering::Relaxed);
    }

    #[inline]
    fn get_state(&self) -> DaemonState {
        self.state.load(Ordering::Relaxed).into()
    }

    fn save(&self) -> DaemonResult<()> {
        if !self.vfs.initialized() {
            return Err(DaemonError::NotReady);
        }

        // Unwrap should be safe because it's in live-upgrade/failover workflow
        let mut mgr_guard = self.get_upgrade_mgr().unwrap();

        // Save fuse fd
        let fds = vec![self.session.lock().unwrap().get_fuse_fd().unwrap()];
        mgr_guard.set_fds(fds);

        // Save daemon opaque
        mgr_guard.set_opaque(OpaqueKind::FuseDevice, &self)?;

        mgr_guard.set_opaque_raw(OpaqueKind::VfsState, &self.get_vfs().save())?;

        mgr_guard.save()?;

        info!(
            "Saved opaques {:?} to remote UDS server",
            mgr_guard.get_opaque_kinds()
        );

        Ok(())
    }

    fn restore(&self) -> DaemonResult<()> {
        if self.supervisor().is_none() {
            return Err(DaemonError::UpgradeManager(UpgradeMgrError::Disabled));
        }

        // Unwrap should be safe because it's in live-upgrade/failover workflow
        let mut mgr_guard = self.get_upgrade_mgr().unwrap();
        mgr_guard.restore()?;

        let _o: &FusedevDaemon = mgr_guard.get_opaque(OpaqueKind::FuseDevice, self)?;

        // Restore fuse fd
        let fds = mgr_guard.get_fds();
        self.session.lock().unwrap().set_fuse_fd(fds[0]);

        // Restore vfs
        let vfs_state = mgr_guard
            .get_opaque_raw(OpaqueKind::VfsState)?
            .ok_or_else(|| DaemonError::Common("Opaque does not exist".to_string()))?;

        // Mounts state set is allowed to be empty since nydusd can have no fs backend.
        // The resource correction is already guaranteed by `Versionize`.
        let mounts_set: Option<RafsMountStateSet> =
            mgr_guard.get_opaque_raw(OpaqueKind::RafsMounts)?;

        let trace_kinds = mgr_guard.get_opaque_kinds();

        drop(mgr_guard);

        <&Vfs>::restore(self.get_vfs(), &vfs_state)
            .map_err(|_| DaemonError::Common("Fail in restoring".to_string()))?;

        // Restore RAFS mounts
        if let Some(set) = mounts_set {
            for item in set.items {
                // Only support Rafs live-upgrade right now.
                self.mount(
                    FsBackendMountCmd {
                        fs_type: FsBackendType::Rafs,
                        mountpoint: item.mountpoint,
                        source: item.bootstrap,
                        config: item.config,
                        prefetch_files: None,
                    },
                    Some(&vfs_state),
                )?;
            }
        }

        info!("Restored opaques {:?} from remote UDS server", trace_kinds);

        // Start to serve fuse request
        let conn = self.conn.load(Ordering::Acquire);
        drain_fuse_requests(conn, &self.failover_policy, CTRL_FS_CONN)
            .unwrap_or_else(|e| error!("Failed in draining fuse requests. {}", e));

        Ok(())
    }

    #[inline]
    fn get_vfs(&self) -> &Vfs {
        &self.vfs
    }

    #[inline]
    fn get_upgrade_mgr(&self) -> Option<MutexGuard<UpgradeManager>> {
        self.upgrade_mgr.as_ref().map(|mgr| mgr.lock().unwrap())
    }
}

impl<'a> Persist<'a> for &'a FusedevDaemon {
    type State = DaemonOpaque;
    type ConstructorArgs = &'a FusedevDaemon;
    type LiveUpgradeConstructorArgs = &'a FusedevDaemon;
    type Error = ();

    fn save(&self) -> Self::State {
        DaemonOpaque {
            conn: self.conn.load(Ordering::Acquire),
        }
    }

    fn restore(
        daemon: Self::ConstructorArgs,
        opaque: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        daemon.conn.store(opaque.conn, Ordering::Release);
        Ok(daemon)
    }
}

// TODO: Perhaps, we can't rely on `/proc/self/mounts` to tell if it is mounted.
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
fn is_crashed(path: impl AsRef<Path>, sock: &impl AsRef<Path>) -> Result<bool> {
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
/// RESEND policy commands kernel fuse to re-queue those fuse requests back to *Pending*
/// queue, so nydus can re-read those messages.
fn drain_fuse_requests(conn: u64, p: &FailoverPolicy, control_fs_conn: &str) -> Result<()> {
    let f = match p {
        FailoverPolicy::Flush => "flush",
        FailoverPolicy::Resend => "resend",
    };

    // TODO: If `flush` or `resend` file does not exists, we continue the failover progress but
    // should throw alarm out.
    let mut control_fs_path = format!("{}/{}/{}", control_fs_conn, conn, f);

    // Kernel may not support `resend` policy, so fall into `flush` policy.
    if *p == FailoverPolicy::Resend && metadata(&control_fs_path).is_err() {
        info!("Fallback to flush policy");
        control_fs_path = format!("{}/{}/{}", control_fs_conn, conn, "flush");
    }

    // Finally, if the control file is absent, then do nothing ending with no handling in-flight message.
    let mut f = OpenOptions::new()
        .write(true)
        .open(&control_fs_path)
        .map_err(|e| {
            error!("Can't open control file {}, {}", &control_fs_path, e);
            e
        })?;
    f.write_all(b"1").map_err(|e| {
        error!("Can't write to control file {}, {}", &control_fs_path, e);
        e
    })?;

    Ok(())
}

use std::convert::TryFrom;
#[derive(PartialEq)]
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
    api_sock: Option<impl AsRef<Path>>,
    upgrade: bool,
    fp: FailoverPolicy,
    mount_cmd: Option<FsBackendMountCmd>,
) -> Result<Arc<dyn NydusDaemon + Send>> {
    let (trigger, events_rx) = channel::<DaemonStateMachineInput>();
    let session = FuseSession::new(Path::new(mountpoint), "rafs", "")?;

    // Create upgrade manager
    let upgrade_mgr = if let Some(supervisor) = &supervisor {
        let upgrade_mgr_id = format!("nydus-{}", id.as_ref().unwrap());
        let backend = Box::new(UdsBackend::new(PathBuf::from(supervisor)));
        Some(Mutex::new(UpgradeManager::new(upgrade_mgr_id, backend)))
    } else {
        None
    };

    let (tx, rx) = channel::<JoinHandle<Result<()>>>();
    let (result_sender, result_receiver) = channel::<DaemonResult<()>>();

    let daemon = Arc::new(FusedevDaemon {
        session: Mutex::new(session),
        server: Arc::new(Server::new(vfs.clone())),
        vfs,
        thread_tx: Mutex::new(Some(tx)),
        thread_rx: Mutex::new(rx),
        running_threads: AtomicI32::new(0),
        event_fd: EventFd::new(0).unwrap(),
        state: AtomicI32::new(DaemonState::INIT as i32),
        threads_cnt,
        trigger: Arc::new(Mutex::new(trigger)),
        result_receiver: Mutex::new(result_receiver),
        supervisor,
        id,
        conn: AtomicU64::new(0),
        failover_policy: fp,
        upgrade_mgr,
    });

    let machine = DaemonStateMachineContext::new(daemon.clone(), events_rx, result_sender);
    machine.kick_state_machine()?;

    // Without api socket, nydusd can't do neither live-upgrade nor failover, so the helper
    // finding a victim is not necessary.
    if (api_sock.as_ref().is_some()
        && !upgrade
        && !is_crashed(mountpoint, api_sock.as_ref().unwrap())?)
        || api_sock.is_none()
    {
        if let Some(cmd) = mount_cmd {
            daemon.mount(cmd, None)?;
        }
        daemon.session.lock().unwrap().mount()?;
        daemon
            .on_event(DaemonStateMachineInput::Mount)
            .map_err(|e| eother!(e))?;
        daemon
            .conn
            .store(calc_fuse_conn(mountpoint)?, Ordering::Relaxed);
    }

    Ok(daemon)
}

#[derive(Debug, Versionize)]
pub struct DaemonOpaque {
    conn: u64,
}

impl VersionMapGetter for DaemonOpaque {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::ErrorKind;
    use vmm_sys_util::tempdir::TempDir;
    #[test]
    fn test_failover_policy_fallback() {
        env_logger::init();
        let _td = TempDir::new().unwrap();
        let control_fs = _td.as_path();
        let conn = 48;
        let r = drain_fuse_requests(conn, &FailoverPolicy::Resend, &control_fs.to_str().unwrap());

        match r {
            Err(e) => assert_eq!(e.kind(), ErrorKind::NotFound),
            _ => panic!(),
        }

        // Test if failover policy can fallback?
        let control_fs_conn = control_fs.join(format!("{}", conn));
        std::fs::create_dir_all(&control_fs_conn).unwrap();
        let control_fs_path = control_fs_conn.join("flush");
        let _f = File::create(control_fs_path).unwrap();

        drain_fuse_requests(conn, &FailoverPolicy::Resend, &control_fs.to_str().unwrap()).unwrap();
    }
}
