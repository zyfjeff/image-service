// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! UpgradeManager manages all resources that need to be saved (persist to storage backend) or
//! restored (reconstruct from storage backend), includes Fd and Binary data.

#[macro_use]
extern crate log;

pub mod backend;

use std::collections::HashMap;
use std::fmt;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

use snapshot::{self, Persist, Snapshot};
use versionize::{VersionManager, VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;

use backend::{unix_domain_socket::UdsBackend, Backend, BackendError};

#[derive(Debug)]
pub enum UpgradeMgrError {
    Disabled,
    NotExisted(String),
    Serialize(snapshot::Error),
    Deserialize(snapshot::Error),
    Restore(String),
    Backend(BackendError),
}

pub type Result<T> = std::result::Result<T, UpgradeMgrError>;

// Use OpaqueKind to distinguish resource instances in
// UpgradeManager, you can add more as you need.
#[derive(Hash, PartialEq, Eq, Clone, Debug, Versionize)]
pub enum OpaqueKind {
    FuseDevice,
    RafsMounts,
    VfsState,
}

impl fmt::Display for OpaqueKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::FuseDevice => write!(f, "fuse_device"),
            Self::RafsMounts => write!(f, "rafs_mount"),
            Self::VfsState => write!(f, "vfs_state"),
        }
    }
}

// Opaques stores all opaque data serialized by Snapshot,
// use `OpaqueKind` to distinguish.
#[derive(Debug, Versionize)]
struct Opaques {
    data: HashMap<OpaqueKind, Vec<u8>>,
}

// UpgradeManager manages all state that needs to be saved (persist to storage backend)
// or restored (reconstruct from storage backend), includes Fd and Binary (Opaque) data.
//
// See usage in unit testing below. First, we need to create an upgrade manager instance
// with a new backend, then add fds or opaques (implemented Persist trait) to the manager.
// We can call manager.save() or manager.restore() to save/restore all state from backend
// when needed.
#[allow(dead_code)]
pub struct UpgradeManager {
    pub vm: VersionManager,
    backend: Box<dyn Backend>,
    fds: Vec<RawFd>,
    opaques: Opaques,
}

impl UpgradeManager {
    pub fn new(supervisor: PathBuf) -> Self {
        UpgradeManager {
            vm: VersionManager::new(),
            backend: Box::new(UdsBackend::new(supervisor)),
            fds: Vec::new(),
            opaques: Opaques {
                data: HashMap::new(),
            },
        }
    }

    // Cache fds to manager
    pub fn set_fds(&mut self, fds: Vec<RawFd>) {
        self.fds = fds;
    }

    // Get fds from manager cache
    pub fn get_fds(&mut self) -> &[RawFd] {
        self.fds.as_slice()
    }

    // Cache opaque (implemented Persist trait) to manager, opaque object should implement Persist trait
    pub fn set_opaque<'a, O, V, D>(&mut self, kind: OpaqueKind, obj: &O) -> Result<()>
    where
        O: Persist<'a, State = V, Error = D>,
        V: Versionize,
        D: std::fmt::Debug,
    {
        let vm = self.vm.make_version_map();
        let latest_version = vm.latest_version();

        let mut snapshot = Snapshot::new(vm.clone(), latest_version);

        let state = obj.save();
        let mut opaque: Vec<u8> = Vec::new();

        snapshot
            .save_with_crc64(&mut opaque, &state)
            .map_err(UpgradeMgrError::Serialize)?;

        self.opaques.data.insert(kind, opaque);

        Ok(())
    }

    // Cache opaque (implemented Versionize) to manager, opaque object should implement Persist trait
    pub fn set_opaque_raw<V>(&mut self, kind: OpaqueKind, obj: &V) -> Result<()>
    where
        V: Versionize,
    {
        let vm = self.vm.make_version_map();
        let latest_version = vm.latest_version();

        let mut snapshot = Snapshot::new(vm.clone(), latest_version);
        let mut opaque: Vec<u8> = Vec::new();

        snapshot
            .save_with_crc64(&mut opaque, obj)
            .map_err(UpgradeMgrError::Serialize)?;

        self.opaques.data.insert(kind, opaque);

        Ok(())
    }

    // Get opaque (implemented Persist trait) from manager cache
    pub fn get_opaque<'a, O, V, A, D>(&mut self, kind: OpaqueKind, args: A) -> Result<O>
    where
        O: Persist<'a, State = V, ConstructorArgs = A, Error = D>,
        V: Versionize,
        D: std::fmt::Debug,
    {
        self.vm.make_version_map();
        if let Some(opaque) = self.opaques.data.get(&kind) {
            let state = Snapshot::load_with_crc64(&mut opaque.as_slice(), &self.vm)
                .map_err(UpgradeMgrError::Deserialize)?;
            let opaque = O::restore(args, &state)
                .map_err(|e| UpgradeMgrError::Restore(format!("{:?}", e)))?;

            Ok(opaque)
        } else {
            Err(UpgradeMgrError::NotExisted(kind.to_string()))
        }
    }

    // Get opaque (implemented Versionize) from manager internal storage
    pub fn get_opaque_raw<V>(&mut self, kind: OpaqueKind) -> Result<Option<V>>
    where
        V: Versionize,
    {
        self.vm.make_version_map();
        if let Some(opaque) = self.opaques.data.get(&kind) {
            let opaque = Snapshot::load_with_crc64(&mut opaque.as_slice(), &self.vm)
                .map_err(UpgradeMgrError::Deserialize)?;

            return Ok(Some(opaque));
        }

        Ok(None)
    }

    // Save all fds and opaques to backend
    pub fn save(&mut self) -> Result<()> {
        let vm = self.vm.make_version_map();
        let latest_version = vm.latest_version();

        let mut snapshot = Snapshot::new(vm.clone(), latest_version);

        let mut opaque: Vec<u8> = Vec::new();

        snapshot
            .save_with_crc64(&mut opaque, &self.opaques)
            .map_err(UpgradeMgrError::Serialize)?;

        self.backend
            .save(self.fds.as_slice(), opaque.as_slice())
            .map_err(UpgradeMgrError::Backend)?;

        Ok(())
    }

    // Restore all fds and opaques from backend, and put them to manager cache
    pub fn restore(&mut self) -> Result<()> {
        // TODO: Is 256K buffer large enough?
        let mut opaque: Vec<u8> = vec![0u8; 256 << 10];
        let mut fds: Vec<RawFd> = vec![0; 8];

        let (opaque_size, fd_count) = self
            .backend
            .restore(&mut fds, &mut opaque)
            .map_err(UpgradeMgrError::Backend)?;
        opaque.truncate(opaque_size);
        fds.truncate(fd_count);

        self.fds = fds;
        self.vm.make_version_map();
        self.opaques = Snapshot::load_with_crc64(&mut opaque.as_slice(), &self.vm)
            .map_err(UpgradeMgrError::Deserialize)?;

        Ok(())
    }

    pub fn get_opaque_kinds(&self) -> Vec<OpaqueKind> {
        self.opaques.data.keys().cloned().collect()
    }
}

#[cfg(test)]
pub mod tests {
    use std::any::TypeId;
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Error;
    use std::io::{Seek, SeekFrom};
    use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::thread;

    use sendfd::{RecvWithFd, SendWithFd};
    use snapshot::Persist;
    use versionize::{VersionMap, Versionize, VersionizeResult};
    use versionize_derive::Versionize;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    pub struct Test {
        pub foo: HashMap<String, String>,
        pub bar: String,
        pub baz: u32,
    }

    #[derive(Clone, Debug, Versionize)]
    pub struct TestState {
        foo: HashMap<String, String>,
        #[version(start = 2, default_fn = "bar_default")]
        bar: String,
        baz: u32,
    }

    fn get_versions_teststate(sem_ver: &str) -> Vec<(TypeId, u16)> {
        let mut versions = Vec::new();
        match sem_ver {
            "0.0.0" => {}
            "latest" => versions.push((TypeId::of::<TestState>(), 2)),
            _ => {}
        }
        versions
    }

    impl TestState {
        fn bar_default(_: u16) -> String {
            String::from("bar")
        }
    }

    pub struct TestArgs {
        pub baz: u32,
    }

    impl Persist<'_> for Test {
        type State = TestState;
        type ConstructorArgs = TestArgs;
        type LiveUpgradeConstructorArgs = TestArgs;
        type Error = Error;

        fn save(&self) -> Self::State {
            TestState {
                foo: self.foo.clone(),
                bar: self.bar.clone(),
                baz: self.baz,
            }
        }

        fn restore(
            args: Self::ConstructorArgs,
            state: &Self::State,
        ) -> std::result::Result<Self, Self::Error> {
            Ok(Test {
                foo: state.foo.clone(),
                bar: state.bar.clone(),
                baz: args.baz,
            })
        }
    }

    fn start_uds_server(path: PathBuf) {
        let mut received = false;
        let mut fds: Vec<RawFd> = vec![0; 1];
        let mut buf = vec![0u8; 4 << 10];

        let listener = UnixListener::bind(path).unwrap();

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if !received {
                        let (opaque_size, fds_count) = stream
                            .recv_with_fd(buf.as_mut_slice(), fds.as_mut_slice())
                            .unwrap();
                        assert_eq!(fds_count, 1);
                        buf.truncate(opaque_size);
                        fds.truncate(fds_count);
                        received = true;
                        continue;
                    }
                    stream.send_with_fd(&buf, &fds).unwrap();
                }
                Err(err) => {
                    panic!("{}", err);
                }
            }
        }
    }

    #[test]
    fn test_upgrade_manager_with_uds_backend() {
        let opaque1 = Test {
            foo: HashMap::new(),
            bar: String::from("bar1"),
            baz: 100,
        };

        let opaque2 = Test {
            foo: HashMap::new(),
            bar: String::from("bar2"),
            baz: 100,
        };

        // Start uds server for recv and reply fd + opaque
        let sock_file = TempFile::new().unwrap();
        let uds_path = sock_file.as_path().to_path_buf();
        let res_uds_path = uds_path.clone();
        // Just get a temp path for uds server creation
        drop(sock_file);

        thread::spawn(move || start_uds_server(res_uds_path));
        std::thread::sleep(std::time::Duration::from_millis(500));

        let seek_pos = 123;
        let temp_file = TempFile::new().unwrap();
        let fds = vec![temp_file.as_file().as_raw_fd()];
        temp_file.as_file().seek(SeekFrom::Start(seek_pos)).unwrap();

        let mut upgrade_mgr = UpgradeManager::new(uds_path.clone());
        upgrade_mgr.vm.add_version("0.0.1");
        upgrade_mgr.vm.add_version("latest");
        upgrade_mgr.vm.add_version_provider(get_versions_teststate);

        // Save fd + opaque to uds server
        upgrade_mgr.set_fds(fds);
        upgrade_mgr
            .set_opaque(OpaqueKind::FuseDevice, &opaque1)
            .unwrap();
        upgrade_mgr
            .set_opaque(OpaqueKind::RafsMounts, &opaque2)
            .unwrap();
        upgrade_mgr.save().unwrap();

        // Restore fd + opaque from uds server
        let mut upgrade_mgr = UpgradeManager::new(uds_path);
        upgrade_mgr.vm.add_version("0.0.1");
        upgrade_mgr.vm.add_version("latest");
        upgrade_mgr.vm.add_version_provider(get_versions_teststate);

        upgrade_mgr.restore().unwrap();

        let restored_opaque1: Test = upgrade_mgr
            .get_opaque(OpaqueKind::FuseDevice, TestArgs { baz: 100 })
            .unwrap();
        let restored_opaque2: Test = upgrade_mgr
            .get_opaque(OpaqueKind::RafsMounts, TestArgs { baz: 100 })
            .unwrap();
        let restored_fds = upgrade_mgr.get_fds();

        // Check restored opaques
        assert_eq!(restored_opaque1, opaque1);
        assert_eq!(restored_opaque2, opaque2);

        // Check restored fd
        let mut temp_file = unsafe { File::from_raw_fd(restored_fds[0]) };
        let expected = temp_file.seek(SeekFrom::Current(0)).unwrap();
        assert_eq!(seek_pos, expected);
    }
}
