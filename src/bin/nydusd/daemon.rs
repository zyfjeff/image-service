// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::any::Any;
use std::cmp::PartialEq;
use std::convert::From;
use std::fmt::{Display, Formatter};
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::id;
use std::str::FromStr;
use std::sync::{
    atomic::Ordering,
    mpsc::{Receiver, Sender},
    Arc, MutexGuard,
};
use std::thread;
use std::{convert, error, fmt, io};

use event_manager::{EventOps, EventSubscriber, Events};
use fuse_rs::api::{VersionMapGetter, Vfs, VfsState};
#[cfg(feature = "virtiofs")]
use fuse_rs::transport::Error as FuseTransportError;
use fuse_rs::Error as VhostUserFsError;
use rust_fsm::*;
use serde::{Deserialize, Serialize};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use nydus_utils::{einval, last_error};
use rafs::{
    fs::{Rafs, RafsConfig},
    RafsError, RafsIoRead,
};
use upgrade_manager::{OpaqueKind, UpgradeManager, UpgradeMgrError};

use crate::SubscriberWrapper;
use crate::EVENT_MANAGER_RUN;

#[allow(dead_code)]
#[derive(Debug, Hash, PartialEq, Eq)]
pub enum DaemonState {
    INIT = 1,
    RUNNING = 2,
    UPGRADING = 3,
    INTERRUPTED = 4,
    STOPPED = 5,
    UNKNOWN = 6,
}

impl Display for DaemonState {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<i32> for DaemonState {
    fn from(i: i32) -> Self {
        match i {
            1 => DaemonState::INIT,
            2 => DaemonState::RUNNING,
            3 => DaemonState::UPGRADING,
            4 => DaemonState::INTERRUPTED,
            5 => DaemonState::STOPPED,
            _ => DaemonState::UNKNOWN,
        }
    }
}

//TODO: Hopefully, there is a day when we can move this to vfs crate and define its error code.
#[derive(Debug)]
pub enum VfsErrorKind {
    Common(io::Error),
    Mount(io::Error),
    Umount(io::Error),
    Restore(io::Error),
}

impl From<RafsError> for DaemonError {
    fn from(error: RafsError) -> Self {
        DaemonError::Rafs(error)
    }
}

impl From<UpgradeMgrError> for DaemonError {
    fn from(error: UpgradeMgrError) -> Self {
        DaemonError::UpgradeManager(error)
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum DaemonError {
    /// Invalid arguments provided.
    InvalidArguments(String),
    /// Invalid config provided
    InvalidConfig(String),
    /// Failed to handle event other than input event.
    HandleEventNotEpollIn,
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
    /// No memory configured.
    NoMemoryConfigured,
    /// Invalid Virtio descriptor chain.
    #[cfg(feature = "virtiofs")]
    InvalidDescriptorChain(FuseTransportError),
    /// Processing queue failed.
    ProcessQueue(VhostUserFsError),
    /// Cannot create epoll context.
    Epoll(io::Error),
    /// Cannot clone event fd.
    EventFdClone(io::Error),
    /// Cannot spawn a new thread
    ThreadSpawn(io::Error),
    /// Failure against Passthrough FS.
    PassthroughFs(io::Error),
    /// Daemon related error
    DaemonFailure(String),

    Common(String),
    UpgradeManager(UpgradeMgrError),
    Vfs(VfsErrorKind),
    Rafs(RafsError),
    /// Daemon does not reach the stable working state yet,
    /// some capabilities may not be provided.
    NotReady,
    /// Daemon can't fulfill external requests.
    Unsupported,
    /// State-machine related error codes if something bad happens when to communicate with state-machine
    Channel(String),
    /// File system backend service related errors.
    StartService(String),
    ServiceStop,
    /// Wait daemon failure
    WaitDaemon(io::Error),
    SessionShutdown(io::Error),
    Downcast(String),
    FsTypeMismatch(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments(s) => write!(f, "Invalid argument: {}", s),
            Self::InvalidConfig(s) => write!(f, "Invalid config: {}", s),
            Self::DaemonFailure(s) => write!(f, "Daemon error: {}", s),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl error::Error for DaemonError {}

impl convert::From<DaemonError> for io::Error {
    fn from(e: DaemonError) -> Self {
        einval!(e)
    }
}

pub type DaemonResult<T> = std::result::Result<T, DaemonError>;

#[derive(Default, PartialEq, Serialize, Deserialize, Versionize, Debug)]
pub struct RafsMountStateSet {
    pub items: Vec<RafsMountState>,
}

#[derive(Versionize, Serialize, Deserialize, PartialEq, Debug)]
pub struct RafsMountState {
    pub mountpoint: String,
    // A json string serialized from RafsConfig. The reason why we don't save `RafsConfig`
    // instance here is it's impossible to implement Versionize for serde_json::Value
    pub config: String,
    pub bootstrap: String,
}

impl From<FsBackendMountCmd> for RafsMountState {
    fn from(c: FsBackendMountCmd) -> Self {
        RafsMountState {
            mountpoint: c.mountpoint,
            config: c.config,
            bootstrap: c.source,
        }
    }
}

impl RafsMountStateSet {
    pub fn new() -> Self {
        Self { items: vec![] }
    }

    pub fn add(&mut self, cmd: FsBackendMountCmd) {
        if let Some(idx) = self
            .items
            .iter()
            .position(|m| m.mountpoint == cmd.mountpoint)
        {
            self.items[idx] = cmd.into();
        } else {
            self.items.push(cmd.into());
        }
    }

    pub fn remove(&mut self, info: FsBackendUmountCmd) {
        if let Some(idx) = self
            .items
            .iter()
            .position(|mount| mount.mountpoint == info.mountpoint)
        {
            self.items.remove(idx);
        }
    }
}

impl VersionMapGetter for RafsMountStateSet {}

#[derive(Clone)]
pub enum FsBackendType {
    Rafs,
    PassthroughFs,
}

impl FromStr for FsBackendType {
    type Err = DaemonError;
    fn from_str(s: &str) -> DaemonResult<FsBackendType> {
        match s {
            "rafs" => Ok(FsBackendType::Rafs),
            "passthrough_fs" => Ok(FsBackendType::PassthroughFs),
            o => Err(DaemonError::InvalidArguments(o.to_string())),
        }
    }
}

#[derive(Clone)]
pub struct FsBackendMountCmd {
    pub fs_type: FsBackendType,
    pub source: String,
    pub config: String,
    pub mountpoint: String,
    pub prefetch_files: Option<Vec<String>>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct FsBackendUmountCmd {
    pub mountpoint: String,
}

pub trait NydusDaemon: DaemonStateMachineSubscriber {
    fn start(&self) -> DaemonResult<()>;
    fn wait(&self) -> DaemonResult<()>;
    fn stop(&self) -> DaemonResult<()> {
        self.on_event(DaemonStateMachineInput::Stop)
    }
    fn disconnect(&self) -> DaemonResult<()>;
    fn as_any(&self) -> &dyn Any;
    fn interrupt(&self) {}
    fn get_state(&self) -> DaemonState;
    fn set_state(&self, s: DaemonState);
    fn trigger_exit(&self) -> DaemonResult<()> {
        self.on_event(DaemonStateMachineInput::Exit)?;
        // Ensure all fuse threads have be terminated thus this nydusd won't
        // race fuse messages when upgrading.
        self.wait().map_err(|_| DaemonError::ServiceStop)?;
        Ok(())
    }
    fn trigger_takeover(&self) -> DaemonResult<()> {
        self.on_event(DaemonStateMachineInput::Takeover)?;
        self.on_event(DaemonStateMachineInput::Successful)?;
        Ok(())
    }
    fn id(&self) -> Option<String>;
    fn supervisor(&self) -> Option<String>;
    fn save(&self) -> DaemonResult<()>;
    fn restore(&self) -> DaemonResult<()>;
    fn get_vfs(&self) -> &Vfs;
    fn get_upgrade_mgr(&self) -> Option<MutexGuard<UpgradeManager>>;

    // FIXME: locking?
    fn mount<'a>(
        &self,
        cmd: FsBackendMountCmd,
        vfs_state: Option<&'a VfsState>,
    ) -> DaemonResult<()> {
        // TODO: Fuse-rs and Vfs should be capable to handle that the mountpoint is already mounted.
        // Otherwise vfs' clients will suffer a lot  :-(. So try to add this capability to it.
        if self.get_vfs().get_rootfs(&cmd.mountpoint).is_ok() {
            return Err(DaemonError::Vfs(VfsErrorKind::Common(IoError::new(
                IoErrorKind::AlreadyExists,
                "Already mounted",
            ))));
        }

        let backend = fs_backend_factory(&cmd)?;

        if let Some(vfs_state) = vfs_state {
            self.get_vfs()
                .restore_mount(backend, &cmd.mountpoint, vfs_state)
                .map_err(|e| DaemonError::Vfs(VfsErrorKind::Restore(e)))?;
        } else {
            self.get_vfs()
                .mount(backend, &cmd.mountpoint)
                .map_err(|e| DaemonError::Vfs(VfsErrorKind::Mount(e)))?;
        }
        info!("vfs mounted");

        // Add mounts opaque to UpgradeManager
        if let Some(mut mgr_guard) = self.get_upgrade_mgr() {
            let mut state = mgr_guard
                .get_opaque_raw(OpaqueKind::RafsMounts)?
                .unwrap_or_else(RafsMountStateSet::new);
            state.add(cmd);
            mgr_guard.set_opaque_raw(OpaqueKind::RafsMounts, &state)?;
        }

        Ok(())
    }

    fn remount(&self, cmd: FsBackendMountCmd) -> DaemonResult<()> {
        let rootfs = self
            .get_vfs()
            .get_rootfs(&cmd.mountpoint)
            .map_err(|e| DaemonError::Vfs(VfsErrorKind::Common(e)))?;

        let rafs_config = RafsConfig::from_str(&&cmd.config)?;
        let mut bootstrap = RafsIoRead::from_file(&&cmd.source)?;
        let any_fs = rootfs.deref().as_any();
        let rafs = any_fs
            .downcast_ref::<Rafs>()
            .ok_or_else(|| DaemonError::FsTypeMismatch("to rafs".to_string()))?;

        rafs.update(&mut bootstrap, rafs_config)
            .map_err(|e| match e {
                RafsError::Unsupported => DaemonError::Unsupported,
                e => DaemonError::Rafs(e),
            })?;

        // Update mounts opaque from UpgradeManager
        if let Some(mut mgr_guard) = self.get_upgrade_mgr() {
            let mut state = mgr_guard
                .get_opaque_raw(OpaqueKind::RafsMounts)?
                .unwrap_or_else(RafsMountStateSet::new);
            state.add(cmd);
            mgr_guard.set_opaque_raw(OpaqueKind::RafsMounts, &state)?;
        }

        Ok(())
    }

    fn umount(&self, cmd: FsBackendUmountCmd) -> DaemonResult<()> {
        let _ = self
            .get_vfs()
            .get_rootfs(&cmd.mountpoint)
            .map_err(|e| DaemonError::Vfs(VfsErrorKind::Common(e)))?;

        self.get_vfs()
            .umount(&cmd.mountpoint)
            .map_err(|e| DaemonError::Vfs(VfsErrorKind::Umount(e)))?;

        // Remove mount opaque from UpgradeManager
        if let Some(mut mgr_guard) = self.get_upgrade_mgr() {
            if let Some(mut state) =
                mgr_guard.get_opaque_raw(OpaqueKind::RafsMounts)? as Option<RafsMountStateSet>
            {
                state.remove(cmd);
                mgr_guard.set_opaque_raw(OpaqueKind::RafsMounts, &state)?;
            }
        }

        Ok(())
    }
}

use fuse_rs::api::BackendFileSystem;
use fuse_rs::passthrough::{Config, PassthroughFs};

/// A string including multiple directories and regular files should be separated by white-spaces, e.g.
///      <path1> <path2> <path3>
/// And each path should be relative to rafs root, e.g.
///      /foo1/bar1 /foo2/bar2
/// Specifying both regular file and directory simultaneously is supported.
fn input_prefetch_files_verify(input: &Option<Vec<String>>) -> DaemonResult<Option<Vec<PathBuf>>> {
    let prefetch_files: Option<Vec<PathBuf>> = input
        .as_ref()
        .map(|files| files.iter().map(PathBuf::from).collect());

    if let Some(ref files) = prefetch_files {
        for f in files.iter() {
            if !f.starts_with(Path::new("/")) {
                return Err(DaemonError::Common("Illegal prefetch list".to_string()));
            }
        }
    }

    Ok(prefetch_files)
}
fn fs_backend_factory(
    cmd: &FsBackendMountCmd,
) -> DaemonResult<Box<dyn BackendFileSystem<Inode = u64, Handle = u64> + Send + Sync>> {
    let prefetch_files = input_prefetch_files_verify(&cmd.prefetch_files)?;
    match cmd.fs_type {
        FsBackendType::Rafs => {
            let rafs_config = RafsConfig::from_str(cmd.config.as_str())?;
            let mut bootstrap = RafsIoRead::from_file(&cmd.source)?;
            let mut rafs = Rafs::new(rafs_config, &cmd.mountpoint, &mut bootstrap)?;
            rafs.import(&mut bootstrap, prefetch_files)?;
            info!("Rafs imported");
            Ok(Box::new(rafs))
        }
        FsBackendType::PassthroughFs => {
            // Vfs by default enables no_open and writeback, passthroughfs
            // needs to specify them explicitly.
            // TODO(liubo): enable no_open_dir.
            let fs_cfg = Config {
                root_dir: cmd.source.to_string(),
                do_import: false,
                writeback: true,
                no_open: true,
                ..Default::default()
            };
            // TODO: Passthrough Fs needs to enlarge rlimit against host. We can exploit `MountCmd`
            // `config` field to pass such a configuration into here.
            let passthrough_fs = PassthroughFs::new(fs_cfg).map_err(DaemonError::PassthroughFs)?;
            passthrough_fs
                .import()
                .map_err(DaemonError::PassthroughFs)?;
            info!("PassthroughFs imported");
            Ok(Box::new(passthrough_fs))
        }
    }
}

pub struct NydusDaemonSubscriber {
    event_fd: EventFd,
}

impl NydusDaemonSubscriber {
    pub fn new() -> Result<Self> {
        match EventFd::new(0) {
            Ok(fd) => Ok(Self { event_fd: fd }),
            Err(e) => {
                error!("Creating event fd failed. {}", e);
                Err(e)
            }
        }
    }
}

impl SubscriberWrapper for NydusDaemonSubscriber {
    fn get_event_fd(&self) -> Result<EventFd> {
        self.event_fd.try_clone()
    }
}

impl EventSubscriber for NydusDaemonSubscriber {
    fn process(&self, events: Events, event_ops: &mut EventOps) {
        self.event_fd
            .read()
            .map(|_| ())
            .map_err(|e| last_error!(e))
            .unwrap_or_else(|_| {});

        match events.event_set() {
            EventSet::IN => {
                EVENT_MANAGER_RUN.store(false, Ordering::Relaxed);
            }
            EventSet::ERROR => {
                error!("Got error on the monitored event.");
            }
            EventSet::HANG_UP => {
                event_ops
                    .remove(events)
                    .unwrap_or_else(|e| error!("Encountered error during cleanup, {}", e));
            }
            _ => {}
        }
    }

    fn init(&self, ops: &mut EventOps) {
        ops.add(Events::new(&self.event_fd, EventSet::IN))
            .expect("Cannot register event")
    }
}

pub type Trigger = Sender<DaemonStateMachineInput>;

//FIXME: This does not precisely describe how state machine work anymore.
/// Nydus daemon workflow is controlled by this state-machine.
/// `Init` means nydusd is just started and potentially configured well but not
/// yet negotiate with kernel the capabilities of both sides. It even does not try
/// to set up fuse session by mounting `/fuse/dev`(in case of `fusedev` backend).
/// `Running` means nydusd has successfully prepared all the stuff needed to work as a
/// user-space fuse filesystem, however, the essential capabilities negotiation might not be
/// done yet. It relies on `fuse-rs` to tell if capability negotiation is done.
/// Nydusd can as well transit to `Upgrade` state from `Running` when getting started, which
/// only happens during live upgrade progress. Then we don't have to do kernel mount again
/// to set up a session but try to reuse a fuse fd from somewhere else. In this state, we
/// try to push `Successful` event to state machine to trigger state transition.
/// `Interrupt` state means nydusd has shutdown fuse server, which means no more message will
/// be read from kernel and handled and no pending and in-flight fuse message exists. But the
/// nydusd daemon should be alive and wait for coming events.
/// `Die` state means the whole nydusd process is going to die.
pub struct DaemonStateMachineContext {
    sm: StateMachine<DaemonStateMachine>,
    daemon: Arc<dyn NydusDaemon + Send + Sync>,
    event_collector: Receiver<DaemonStateMachineInput>,
    result_sender: Sender<DaemonResult<()>>,
    pid: u32,
}

state_machine! {
    derive(Debug, Clone)
    pub DaemonStateMachine(Init)

    // FIXME: It's possible that failover does not succeed or resource is not capable to
    // be passed. To handle event `Stop` when being `Init`.
    Init => {
        Mount => Running [StartService],
        Takeover => Upgrading [Restore],
    },
    Running => {
        Exit => Interrupted [TerminateFuseService],
        Stop => Die[Umount],
    },
    Upgrading(Successful) => Running [StartService],
    // Quit from daemon but not disconnect from fuse front-end.
    Interrupted(Stop) => Die,
}

pub trait DaemonStateMachineSubscriber {
    fn on_event(&self, event: DaemonStateMachineInput) -> DaemonResult<()>;
}

impl DaemonStateMachineContext {
    pub fn new(
        d: Arc<dyn NydusDaemon + Send + Sync>,
        rx: Receiver<DaemonStateMachineInput>,
        result_sender: Sender<DaemonResult<()>>,
    ) -> Self {
        DaemonStateMachineContext {
            sm: StateMachine::new(),
            daemon: d,
            event_collector: rx,
            result_sender,
            pid: id(),
        }
    }

    pub fn kick_state_machine(mut self) -> Result<()> {
        thread::Builder::new()
            .name("state_machine".to_string())
            .spawn(move || loop {
                use DaemonStateMachineOutput::*;
                let event = self
                    .event_collector
                    .recv()
                    .expect("Event channel can't be broken!");
                let last = self.sm.state().clone();
                let sm_rollback = StateMachine::<DaemonStateMachine>::from_state(last.clone());
                let input = &event;
                let action = self.sm.consume(&event).unwrap_or_else(|_| {
                    error!("Event={:?}, CurrentState={:?}", input, &last);
                    panic!("Daemon state machine goes insane, this is critical error!")
                });

                let d = self.daemon.as_ref();
                let cur = self.sm.state();
                info!(
                    "State machine(pid={}): from {:?} to {:?}, input [{:?}], output [{:?}]",
                    &self.pid, last, cur, input, &action
                );
                let r = match action {
                    Some(a) => match a {
                        StartService => d.start().map(|r| {
                            d.set_state(DaemonState::RUNNING);
                            r
                        }),
                        TerminateFuseService => {
                            d.interrupt();
                            d.set_state(DaemonState::INTERRUPTED);
                            Ok(())
                        }
                        Umount => d.disconnect().map(|r| {
                            d.set_state(DaemonState::STOPPED);
                            r
                        }),
                        Restore => {
                            d.set_state(DaemonState::UPGRADING);
                            d.restore()
                        }
                    },
                    _ => Ok(()), // With no output action involved, caller should also have reply back
                }
                .map_err(|e| {
                    error!(
                        "Handle action failed, {:?}. Rollback machine to State {:?}",
                        e,
                        sm_rollback.state()
                    );
                    self.sm = sm_rollback;
                    e
                });
                self.result_sender.send(r).unwrap();
            })
            .map(|_| ())
    }
}

#[cfg(test)]
pub mod tests {
    use std::path::PathBuf;

    use upgrade_manager::backend::unix_domain_socket::UdsBackend;
    use upgrade_manager::{OpaqueKind, UpgradeManager};

    use super::*;

    #[test]
    fn test_rafs_mounts_state_with_upgrade_manager() {
        let backend = UdsBackend::new(PathBuf::from("fake"));
        let mut upgrade_mgr = UpgradeManager::new(String::from("test"), Box::new(backend));

        let mut rafs_mount = RafsMountStateSet::new();
        rafs_mount.add(FsBackendMountCmd {
            fs_type: FsBackendType::Rafs,
            source: String::from("source-fake1"),
            config: String::from("config-fake1"),
            mountpoint: String::from("mountpoint-fake1"),
            prefetch_files: None,
        });
        rafs_mount.add(FsBackendMountCmd {
            fs_type: FsBackendType::Rafs,
            source: String::from("source-fake2"),
            config: String::from("config-fake2"),
            mountpoint: String::from("mountpoint-fake2"),
            prefetch_files: None,
        });
        rafs_mount.add(FsBackendMountCmd {
            fs_type: FsBackendType::Rafs,
            source: String::from("source-fake3"),
            config: String::from("config-fake3"),
            mountpoint: String::from("mountpoint-fake2"),
            prefetch_files: None,
        });
        rafs_mount.add(FsBackendMountCmd {
            fs_type: FsBackendType::Rafs,
            source: String::from("source-fake4"),
            config: String::from("config-fake4"),
            mountpoint: String::from("mountpoint-fake4"),
            prefetch_files: None,
        });
        rafs_mount.remove(FsBackendUmountCmd {
            mountpoint: String::from("mountpoint-fake4"),
        });

        upgrade_mgr
            .set_opaque_raw(OpaqueKind::RafsMounts, &rafs_mount)
            .unwrap();

        let expected_rafs_mount: RafsMountStateSet = upgrade_mgr
            .get_opaque_raw(OpaqueKind::RafsMounts)
            .unwrap()
            .unwrap();

        assert_eq!(
            expected_rafs_mount,
            RafsMountStateSet {
                items: vec![
                    RafsMountState {
                        bootstrap: String::from("source-fake1"),
                        config: String::from("config-fake1"),
                        mountpoint: String::from("mountpoint-fake1"),
                    },
                    RafsMountState {
                        bootstrap: String::from("source-fake3"),
                        config: String::from("config-fake3"),
                        mountpoint: String::from("mountpoint-fake2"),
                    }
                ],
            }
        );
    }
}
