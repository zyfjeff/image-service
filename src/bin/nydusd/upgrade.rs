/// Don't push this file into upstream
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use fuse_backend_rs::api::VersionMapGetter;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

use crate::daemon::{DaemonError, DaemonResult, FsBackendMountCmd, FsBackendUmountCmd};

pub use upgrade_manager::{OpaqueKind, UpgradeManager, UpgradeMgrError};

impl VersionMapGetter for RafsMountStateSet {}
impl VersionMapGetter for DaemonOpaque {}

impl From<UpgradeMgrError> for DaemonError {
    fn from(error: UpgradeMgrError) -> Self {
        DaemonError::UpgradeManager(error)
    }
}

#[derive(Debug, Versionize)]
pub struct DaemonOpaque {
    conn: u64,
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

#[derive(Default, PartialEq, Serialize, Deserialize, Versionize, Debug)]
pub struct RafsMountStateSet {
    pub items: HashMap<String, RafsMountState>,
}

#[derive(Versionize, Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct RafsMountState {
    pub index: u8,
    // A json string serialized from RafsConfig. The reason why we don't save `RafsConfig`
    // instance here is it's impossible to implement Versionize for serde_json::Value
    pub config: String,
    pub bootstrap: String,
}

impl RafsMountStateSet {
    pub fn new() -> Self {
        Self {
            items: HashMap::new(),
        }
    }

    pub fn add(&mut self, cmd: FsBackendMountCmd, index: u8) -> DaemonResult<()> {
        if self.items.contains_key(&cmd.mountpoint) {
            return Err(DaemonError::AlreadyExists);
        }
        let _ = self.items.insert(
            cmd.mountpoint,
            RafsMountState {
                index,
                config: cmd.config,
                bootstrap: cmd.source,
            },
        );
        Ok(())
    }

    pub fn update(&mut self, cmd: FsBackendMountCmd) -> DaemonResult<()> {
        if let Some(state) = self.items.get_mut(&cmd.mountpoint) {
            // update only affects config and source
            state.config = cmd.config;
            state.bootstrap = cmd.source;
            Ok(())
        } else {
            Err(DaemonError::NotFound)
        }
    }

    pub fn remove(&mut self, cmd: FsBackendUmountCmd) {
        self.items.remove(&cmd.mountpoint);
    }
}

pub fn add_mounts_state(
    mgr: &mut UpgradeManager,
    cmd: FsBackendMountCmd,
    vfs_index: u8,
) -> DaemonResult<()> {
    let mut state = mgr
        .get_opaque_raw(OpaqueKind::RafsMounts)?
        .unwrap_or_else(RafsMountStateSet::new);
    state.add(cmd, vfs_index)?;
    mgr.set_opaque_raw(OpaqueKind::RafsMounts, &state)?;
    Ok(())
}

pub fn update_mounts_state(mgr: &mut UpgradeManager, cmd: FsBackendMountCmd) -> DaemonResult<()> {
    let mut state = mgr
        .get_opaque_raw(OpaqueKind::RafsMounts)?
        .unwrap_or_else(RafsMountStateSet::new);
    state.update(cmd)?;
    mgr.set_opaque_raw(OpaqueKind::RafsMounts, &state)?;
    Ok(())
}

pub fn remove_mounts_state(mgr: &mut UpgradeManager, cmd: FsBackendUmountCmd) -> DaemonResult<()> {
    if let Some(mut state) =
        mgr.get_opaque_raw(OpaqueKind::RafsMounts)? as Option<RafsMountStateSet>
    {
        state.remove(cmd);
        mgr.set_opaque_raw(OpaqueKind::RafsMounts, &state)?;
    }
    Ok(())
}

// Nydus can only do live-upgrade with fusedev transport.
#[cfg(feature = "fusedev")]
pub mod fusedev_upgrade {
    use snapshot::Persist;
    use std::fs::{metadata, OpenOptions};
    use std::io::{Result, Write};
    use std::sync::atomic::Ordering;

    use fuse_backend_rs::api::Vfs;
    use fuse_backend_rs::version_manager::get_version_manager;
    use versionize::VersionMapper;

    use super::UpgradeManager;
    use super::{DaemonOpaque, FailoverPolicy, RafsMountStateSet};
    use crate::daemon::NydusDaemon;
    use crate::daemon::{DaemonError, DaemonResult, FsBackendMountCmd, FsBackendType};
    use crate::fusedev::FusedevDaemon;
    use upgrade_manager::{OpaqueKind, UpgradeMgrError};

    const CTRL_FS_CONN: &str = "/sys/fs/fuse/connections";

    pub fn init_fusedev_upgrade_mgr(mgr: &mut UpgradeManager) {
        // nydusd versions
        mgr.vm.add_version("1.3.0");
        mgr.vm.add_version("1.3.1");
        mgr.vm.add_version("1.4.0");
        mgr.vm.add_version("1.5.0");
        mgr.vm.add_version("1.6.0");
        mgr.vm.add_version("1.6.1");
        mgr.vm.add_version("1.6.2");
        mgr.vm.add_version("latest");

        // add version mapper between nydusd and fuse-backend-rs
        let mut version_mapper = VersionMapper::new();
        version_mapper
            .add("1.3.0", "0.0.2")
            .add("1.3.1", "0.0.2")
            .add("1.4.0", "0.2.0")
            .add("1.5.0", "0.3.0")
            .add("1.6.0", "0.3.0")
            .add("1.6.1", "0.3.0")
            .add("1.6.2", "0.3.0")
            .add("latest", "latest");
        mgr.vm
            .add_sub_manager(version_mapper, get_version_manager());

        // add migratable version table
        // TODO: Use macro to define upgrade matrix
        // Base version 1.3.0
        mgr.vm.add_migratable_version("1.3.0", "1.3.1");
        mgr.vm.add_migratable_version("1.3.0", "1.4.0");
        mgr.vm.add_migratable_version("1.3.0", "1.5.0");
        mgr.vm.add_migratable_version("1.3.0", "1.6.0");
        mgr.vm.add_migratable_version("1.3.0", "1.6.1");
        mgr.vm.add_migratable_version("1.3.0", "1.6.2");
        mgr.vm.add_migratable_version("1.3.0", "latest");
        // Base version 1.3.1
        mgr.vm.add_migratable_version("1.3.1", "1.4.0");
        mgr.vm.add_migratable_version("1.3.1", "1.5.0");
        mgr.vm.add_migratable_version("1.3.1", "1.6.0");
        mgr.vm.add_migratable_version("1.3.1", "1.6.1");
        mgr.vm.add_migratable_version("1.3.1", "1.6.2");
        mgr.vm.add_migratable_version("1.3.1", "latest");
        // Base version 1.4.0
        mgr.vm.add_migratable_version("1.4.0", "1.5.0");
        mgr.vm.add_migratable_version("1.4.0", "1.6.0");
        mgr.vm.add_migratable_version("1.4.0", "1.6.1");
        mgr.vm.add_migratable_version("1.4.0", "1.6.2");
        mgr.vm.add_migratable_version("1.4.0", "latest");
        // Base version 1.5.0
        mgr.vm.add_migratable_version("1.5.0", "1.6.0");
        mgr.vm.add_migratable_version("1.5.0", "1.6.1");
        mgr.vm.add_migratable_version("1.5.0", "1.6.2");
        mgr.vm.add_migratable_version("1.5.0", "latest");
        // Base version 1.6.0
        mgr.vm.add_migratable_version("1.6.0", "1.6.1");
        mgr.vm.add_migratable_version("1.6.0", "1.6.2");
        mgr.vm.add_migratable_version("1.6.0", "latest");
        // Base version 1.6.1
        mgr.vm.add_migratable_version("1.6.1", "1.6.2");
        mgr.vm.add_migratable_version("1.6.1", "latest");

        // Base version 1.6.2
        mgr.vm.add_migratable_version("1.6.2", "latest");

        // cache version map
        mgr.vm.make_version_map();
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

    pub fn save(daemon: &FusedevDaemon) -> DaemonResult<()> {
        if !daemon.get_vfs().initialized() {
            return Err(DaemonError::NotReady);
        }
        // Unwrap should be safe because it's in live-upgrade/failover workflow
        let mut mgr_guard = daemon.upgrade_mgr().unwrap();
        // Save fuse fd
        let fds = vec![daemon.session.lock().unwrap().get_fuse_fd().unwrap()];
        mgr_guard.set_fds(fds);
        // Save daemon opaque
        mgr_guard.set_opaque(OpaqueKind::FuseDevice, &daemon)?;
        mgr_guard.set_opaque(OpaqueKind::VfsState, &daemon.get_vfs())?;
        mgr_guard.save()?;
        info!(
            "Saved opaques {:?} to remote UDS server",
            mgr_guard.get_opaque_kinds()
        );
        Ok(())
    }

    pub fn restore(daemon: &FusedevDaemon) -> DaemonResult<()> {
        if daemon.supervisor().is_none() {
            return Err(DaemonError::UpgradeManager(UpgradeMgrError::Disabled));
        }
        // Unwrap should be safe because it's in live-upgrade/failover workflow
        let mut mgr_guard = daemon.upgrade_mgr().unwrap();
        mgr_guard.restore()?;
        let _o: &FusedevDaemon = mgr_guard.get_opaque(OpaqueKind::FuseDevice, daemon)?;
        // Restore fuse fd
        let fds = mgr_guard.get_fds();
        daemon.session.lock().unwrap().set_fuse_fd(fds[0]);
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
        <&Vfs>::restore(daemon.get_vfs(), &vfs_state)
            .map_err(|_| DaemonError::Common("Fail in restoring".to_string()))?;
        // Restore RAFS mounts
        if let Some(set) = mounts_set {
            for (mountpoint, state) in set.items {
                // Only support Rafs live-upgrade right now.
                daemon.restore_mount(
                    FsBackendMountCmd {
                        fs_type: FsBackendType::Rafs,
                        mountpoint,
                        source: state.bootstrap,
                        config: state.config,
                        prefetch_files: None,
                    },
                    state.index,
                )?;
            }
        }
        info!("Restored opaques {:?} from remote UDS server", trace_kinds);
        // Start to serve fuse request
        let conn = daemon.conn.load(Ordering::Acquire);
        drain_fuse_requests(conn, &daemon.failover_policy, CTRL_FS_CONN)
            .unwrap_or_else(|e| error!("Failed in draining fuse requests. {}", e));
        Ok(())
    }

    /// There might be some in-flight fuse requests when nydusd terminates out of sudden.
    /// According to FLUSH policy, those requests will be abandoned which means kernel
    /// no longer waits for their responses.
    /// RESEND policy commands kernel fuse to re-queue those fuse requests back to *Pending*
    /// queue, so nydus can re-read those messages.
    pub fn drain_fuse_requests(conn: u64, p: &FailoverPolicy, control_fs_conn: &str) -> Result<()> {
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
}

#[cfg(test)]
#[cfg(feature = "fusedev")]
pub mod tests {
    use std::fs::File;
    use std::io::ErrorKind;

    use super::{
        fusedev_upgrade::drain_fuse_requests, FailoverPolicy, OpaqueKind, RafsMountState,
        RafsMountStateSet, UpgradeManager,
    };
    use crate::daemon::{FsBackendMountCmd, FsBackendType, FsBackendUmountCmd};
    use vmm_sys_util::tempdir::TempDir;

    #[test]
    fn test_rafs_mounts_state_with_upgrade_manager() {
        let mut upgrade_mgr = UpgradeManager::new("test".to_string().into());
        upgrade_mgr.vm.add_version("latest");
        let mut rafs_mount = RafsMountStateSet::new();
        rafs_mount
            .add(
                FsBackendMountCmd {
                    fs_type: FsBackendType::Rafs,
                    source: String::from("source-fake1"),
                    config: String::from("config-fake1"),
                    mountpoint: String::from("mountpoint-fake1"),
                    prefetch_files: None,
                },
                1,
            )
            .unwrap();
        rafs_mount
            .add(
                FsBackendMountCmd {
                    fs_type: FsBackendType::Rafs,
                    source: String::from("source-fake2"),
                    config: String::from("config-fake2"),
                    mountpoint: String::from("mountpoint-fake2"),
                    prefetch_files: None,
                },
                2,
            )
            .unwrap();
        rafs_mount
            .update(FsBackendMountCmd {
                fs_type: FsBackendType::Rafs,
                source: String::from("source-fake3"),
                config: String::from("config-fake3"),
                mountpoint: String::from("mountpoint-fake2"),
                prefetch_files: None,
            })
            .unwrap();
        rafs_mount
            .add(
                FsBackendMountCmd {
                    fs_type: FsBackendType::Rafs,
                    source: String::from("source-fake4"),
                    config: String::from("config-fake4"),
                    mountpoint: String::from("mountpoint-fake4"),
                    prefetch_files: None,
                },
                4,
            )
            .unwrap();
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
            expected_rafs_mount.items.get("mountpoint-fake1").unwrap(),
            &RafsMountState {
                index: 1,
                bootstrap: String::from("source-fake1"),
                config: String::from("config-fake1"),
            }
        );
        assert_eq!(
            expected_rafs_mount.items.get("mountpoint-fake2").unwrap(),
            &RafsMountState {
                index: 2,
                bootstrap: String::from("source-fake3"),
                config: String::from("config-fake3"),
            }
        );
    }

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
