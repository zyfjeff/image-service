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
use std::sync::atomic::Ordering;
use std::sync::mpsc::RecvError;
use std::sync::MutexGuard;
use std::{convert, error, fmt, io};

use event_manager::{EventOps, EventSubscriber, Events};
use fuse_rs::api::{VersionMapGetter, Vfs, VfsState};
#[cfg(feature = "virtiofs")]
use fuse_rs::transport::Error as FuseTransportError;
use fuse_rs::Error as VhostUserFsError;
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
    /// Failure to initialize file system
    FsInitFailure(io::Error),
    /// Daemon related error
    DaemonFailure(String),

    Common(String),
    UpgradeManager(UpgradeMgrError),
    /// Daemon does not reach the stable working state yet,
    /// some capabilities may not be provided.
    NotReady,
    /// Daemon can't fulfill external requests.
    Unsupported,

    /// State-machine related error codes if something bad happens when to communicate with state-machine
    ChannelSend(String),
    ChannelRecv(RecvError),
    /// File system backend service related errors.
    StartService(String),
    ServiceStop,
    /// Wait daemon failure
    WaitDaemon(io::Error),
    SessionShutdown(io::Error),
    /// When rafs or other types of backend can't be correctly configured.
    Config(io::Error),
    /// Only for Rafs now, when its metadata can't be preloaded.
    Metadata(io::Error),
    Mount(io::Error),
    Vfs(io::Error),
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

#[derive(Default, Debug, PartialEq, Serialize, Deserialize, Clone, Versionize)]
pub struct RafsMountsState {
    pub items: Vec<RafsMountInfo>,
}

impl RafsMountsState {
    pub fn new() -> Self {
        Self { items: vec![] }
    }

    pub fn add(&mut self, info: RafsMountInfo) {
        if let Some(idx) = self
            .items
            .iter()
            .position(|mount| mount.mountpoint == info.mountpoint)
        {
            self.items[idx].source = info.source;
            self.items[idx].config = info.config;
        } else {
            self.items.push(RafsMountInfo {
                source: info.source,
                config: info.config,
                mountpoint: info.mountpoint,
            });
        }
    }

    pub fn remove(&mut self, info: RafsUmountInfo) {
        if let Some(idx) = self
            .items
            .iter()
            .position(|mount| mount.mountpoint == info.mountpoint)
        {
            self.items.remove(idx);
        }
    }
}

impl VersionMapGetter for RafsMountsState {}

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug, Versionize)]
pub struct RafsMountInfo {
    pub source: String,
    pub config: String,
    pub mountpoint: String,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct RafsUmountInfo {
    pub mountpoint: String,
}

pub trait NydusDaemon {
    fn start(&self) -> DaemonResult<()>;
    fn wait(&self) -> DaemonResult<()>;
    fn stop(&self) -> DaemonResult<()>;
    fn as_any(&self) -> &dyn Any;
    fn interrupt(&self) {}
    fn get_state(&self) -> DaemonState;
    fn set_state(&self, s: DaemonState);
    fn trigger_exit(&self) -> DaemonResult<()> {
        Ok(())
    }
    fn trigger_takeover(&self) -> DaemonResult<()> {
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
        info: RafsMountInfo,
        vfs_state: Option<&'a VfsState>,
        persist: bool,
    ) -> DaemonResult<()> {
        if self.get_vfs().get_rootfs(&info.mountpoint).is_ok() {
            return Err(DaemonError::Vfs(IoError::new(
                IoErrorKind::AlreadyExists,
                "Already mounted",
            )));
        }

        let rafs_config = RafsConfig::from_file(&info.config).map_err(DaemonError::Config)?;
        let mut bootstrap = RafsIoRead::from_file(&info.source).map_err(DaemonError::Metadata)?;

        let mut rafs = Rafs::new(rafs_config, &info.mountpoint, &mut bootstrap)
            .map_err(DaemonError::Metadata)?;
        rafs.import(&mut bootstrap, None)
            .map_err(DaemonError::Metadata)?;

        if let Some(vfs_state) = vfs_state {
            self.get_vfs()
                .restore_mount(Box::new(rafs), &info.mountpoint, vfs_state)
                .map_err(DaemonError::Mount)?;
        } else {
            self.get_vfs()
                .mount(Box::new(rafs), &info.mountpoint)
                .map_err(DaemonError::Mount)?;
        }

        if persist {
            // Add mounts opaque to UpgradeManager
            if let Some(mut mgr_guard) = self.get_upgrade_mgr() {
                let mut state = mgr_guard
                    .get_opaque_raw(OpaqueKind::RafsMounts)
                    .map_err(DaemonError::UpgradeManager)?
                    .unwrap_or_else(RafsMountsState::new);
                state.add(info);
                mgr_guard
                    .set_opaque_raw(OpaqueKind::RafsMounts, &state)
                    .map_err(DaemonError::UpgradeManager)?;
            }
        }

        Ok(())
    }

    fn update_mount(&self, info: RafsMountInfo) -> DaemonResult<()> {
        let rootfs = self
            .get_vfs()
            .get_rootfs(&info.mountpoint)
            .map_err(DaemonError::Vfs)?;

        let rafs_config = RafsConfig::from_file(&&info.config).map_err(DaemonError::Config)?;
        let mut bootstrap = RafsIoRead::from_file(&&info.source).map_err(DaemonError::Metadata)?;
        let any_fs = rootfs.deref().as_any();
        let rafs = any_fs
            .downcast_ref::<Rafs>()
            .ok_or_else(|| DaemonError::FsTypeMismatch("to rafs".to_string()))?;

        rafs.update(&mut bootstrap, rafs_config)
            .map_err(|e| match e {
                RafsError::Unsupported => DaemonError::Unsupported,
                e => DaemonError::Common(format!("{:?}", e)),
            })?;

        // Update mounts opaque from UpgradeManager
        if let Some(mut mgr_guard) = self.get_upgrade_mgr() {
            let mut state = mgr_guard
                .get_opaque_raw(OpaqueKind::RafsMounts)
                .map_err(DaemonError::UpgradeManager)?
                .unwrap_or_else(RafsMountsState::new);
            state.add(info);
            mgr_guard
                .set_opaque_raw(OpaqueKind::RafsMounts, &state)
                .map_err(DaemonError::UpgradeManager)?;
        }

        Ok(())
    }

    fn umount(&self, info: RafsUmountInfo) -> DaemonResult<()> {
        let _ = self
            .get_vfs()
            .get_rootfs(&info.mountpoint)
            .map_err(DaemonError::Vfs)?;

        self.get_vfs()
            .umount(&info.mountpoint)
            .map_err(DaemonError::Vfs)?;

        // Remove mount opaque from UpgradeManager
        if let Some(mut mgr_guard) = self.get_upgrade_mgr() {
            if let Some(mut state) = mgr_guard
                .get_opaque_raw(OpaqueKind::RafsMounts)
                .map_err(DaemonError::UpgradeManager)?
                as Option<RafsMountsState>
            {
                state.remove(info);
                mgr_guard
                    .set_opaque_raw(OpaqueKind::RafsMounts, &state)
                    .map_err(DaemonError::UpgradeManager)?;
            }
        }

        Ok(())
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

        let mut rafs_mount = RafsMountsState::new();
        rafs_mount.add(RafsMountInfo {
            source: String::from("source-fake1"),
            config: String::from("config-fake1"),
            mountpoint: String::from("mountpoint-fake1"),
        });
        rafs_mount.add(RafsMountInfo {
            source: String::from("source-fake2"),
            config: String::from("config-fake2"),
            mountpoint: String::from("mountpoint-fake2"),
        });
        rafs_mount.add(RafsMountInfo {
            source: String::from("source-fake3"),
            config: String::from("config-fake3"),
            mountpoint: String::from("mountpoint-fake2"),
        });
        rafs_mount.add(RafsMountInfo {
            source: String::from("source-fake4"),
            config: String::from("config-fake4"),
            mountpoint: String::from("mountpoint-fake4"),
        });
        rafs_mount.remove(RafsUmountInfo {
            mountpoint: String::from("mountpoint-fake4"),
        });

        upgrade_mgr
            .set_opaque_raw(OpaqueKind::RafsMounts, &rafs_mount)
            .unwrap();

        let expcted_rafs_mount: RafsMountsState = upgrade_mgr
            .get_opaque_raw(OpaqueKind::RafsMounts)
            .unwrap()
            .unwrap();

        assert_eq!(
            expcted_rafs_mount,
            RafsMountsState {
                items: vec![
                    RafsMountInfo {
                        source: String::from("source-fake1"),
                        config: String::from("config-fake1"),
                        mountpoint: String::from("mountpoint-fake1"),
                    },
                    RafsMountInfo {
                        source: String::from("source-fake3"),
                        config: String::from("config-fake3"),
                        mountpoint: String::from("mountpoint-fake2"),
                    }
                ],
            }
        );
    }
}
