// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A container image Registry Accerlation File System.

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::mem;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use fuse::filesystem::*;

use crate::dag::Dag;
use crate::layout::*;
use crate::storage::device::*;
use crate::storage::*;

// rafs superblock magic number
const RAFS_SUPER_MAGIC: u32 = 0x52414653;
// rafs version number
const RAFS_CURR_VERSION: u16 = 1;

type Inode = u64;
type Handle = u64;

struct RafsInode {
    i_no: Inode,
}

#[derive(Default)]
struct RafsSuper {
    s_magic: u32,
    s_version: u16,
    s_inodes_count: u64,
    s_blocks_count: u64,
    s_inode_size: u16,
    s_block_size: u32,
    s_root: Dag,
    s_inodes: RwLock<BTreeMap<Inode, Arc<RafsInode>>>,
}

impl RafsSuper {
    fn init(&mut self, info: RafsSuperBlockInfo) -> Result<()> {
        if info.s_magic != RAFS_SUPER_MAGIC || info.s_fs_version != RAFS_CURR_VERSION {
            Err(Error::new(ErrorKind::InvalidData, "Invalid super block"))
        } else {
            self.s_magic = info.s_magic;
            self.s_version = info.s_fs_version;
            self.s_block_size = info.s_block_size;
            self.s_blocks_count = info.s_blocks_count;
            self.s_inode_size = info.s_inode_size;
            self.s_inodes_count = info.s_inodes_count;
            Ok(())
        }
    }

    fn destroy(&mut self) {}
}

#[derive(Clone, Default)]
pub struct RafsConfig {
    pub source: String,
    pub device_config: device::Config,
}

impl RafsConfig {
    pub fn new() -> RafsConfig {
        RafsConfig {
            ..Default::default()
        }
    }

    fn dev_config(&self) -> device::Config {
        let mut c = device::Config::new();
        c.backend_type = self.device_config.backend_type;
        c.id = String::from(&self.device_config.id);
        c.path = String::from(&self.device_config.path);
        c.secret = String::from(&self.device_config.secret);
        c
    }
}

pub struct Rafs<B: backend::BlobBackend + 'static> {
    conf: RafsConfig,

    sb: RafsSuper,
    device: device::RafsDevice<B>,
    initialized: bool,
}

impl<B: backend::BlobBackend + 'static> Rafs<B> {
    pub fn new(conf: RafsConfig, b: B) -> Self {
        Rafs {
            sb: RafsSuper {
                s_root: Dag::new(),
                s_inodes: RwLock::new(BTreeMap::new()),
                ..Default::default()
            },
            device: device::RafsDevice::new(conf.dev_config(), b),
            conf: conf,
            initialized: false,
        }
    }

    // mount an rafs metadata provided by Read, to the specified virtual path
    // E.g., mount / would create a virtual path the same as the container rootfs
    fn mount<R: Read>(&mut self, r: R, path: &str) -> Result<()> {
        // FIXME: Only support single root mount for now.
        if self.initialized {
            return Err(Error::new(ErrorKind::AlreadyExists, "Already mounted"));
        }
        let mut info = RafsSuperBlockInfo::new();
        info.load(r)?;
        self.sb.init(info)?;
        self.initialized = true;
        Ok(())
    }

    // umount a prviously mounted rafs virtual path
    fn umount(&mut self, path: &str) -> Result<()> {
        self.sb.destroy();
        self.initialized = false;
        Ok(())
    }
}

impl<B: backend::BlobBackend + 'static> FileSystem for Rafs<B> {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, _: FsOptions) -> Result<FsOptions> {
        let data = RafsInode { i_no: ROOT_ID };
        self.sb
            .s_inodes
            .write()
            .unwrap()
            .insert(ROOT_ID, Arc::new(data));

        Ok(
            // These fuse features are supported by rafs by default.
            FsOptions::ASYNC_READ
                | FsOptions::PARALLEL_DIROPS
                | FsOptions::BIG_WRITES
                | FsOptions::HANDLE_KILLPRIV
                | FsOptions::ASYNC_DIO
                | FsOptions::HAS_IOCTL_DIR
                | FsOptions::WRITEBACK_CACHE
                | FsOptions::ZERO_MESSAGE_OPEN
                | FsOptions::ATOMIC_O_TRUNC,
        )
    }

    fn destroy(&self) {
        self.sb.s_inodes.write().unwrap().clear();
    }

    fn lookup(&self, ctx: Context, parent: Self::Inode, name: &CStr) -> Result<Entry> {
        Err(Error::from_raw_os_error(libc::ENOSYS))
    }

    fn forget(&self, ctx: Context, inode: Self::Inode, count: u64) {}

    fn batch_forget(&self, ctx: Context, requests: Vec<(Self::Inode, u64)>) {
        for (inode, count) in requests {
            self.forget(ctx, inode, count)
        }
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Option<Self::Handle>,
    ) -> Result<(libc::stat64, Duration)> {
        Err(Error::from_raw_os_error(libc::ENOSYS))
    }

    fn readlink(&self, ctx: Context, inode: Self::Inode) -> Result<Vec<u8>> {
        Err(Error::from_raw_os_error(libc::ENOSYS))
    }

    fn open(
        &self,
        ctx: Context,
        inode: Self::Inode,
        flags: u32,
    ) -> Result<(Option<Self::Handle>, OpenOptions)> {
        // Matches the behavior of libfuse.
        Ok((None, OpenOptions::empty()))
    }

    #[allow(clippy::too_many_arguments)]
    fn read<W: Write + ZeroCopyWriter>(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        w: W,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> Result<usize> {
        //TODO: fill in properly
        let bio = RafsBio {
            ..Default::default()
        };
        let mut desc = RafsBioDesc {
            ..Default::default()
        };
        desc.bi_vec.push(bio);
        self.device.read_to(w, desc)
    }

    #[allow(clippy::too_many_arguments)]
    fn write<R: Read + ZeroCopyReader>(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        r: R,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        flags: u32,
    ) -> Result<usize> {
        //TODO: fill in properly
        let bio = RafsBio {
            ..Default::default()
        };
        let mut desc = RafsBioDesc {
            ..Default::default()
        };
        desc.bi_vec.push(bio);
        self.device.write_from(r, desc)
    }

    fn release(
        &self,
        ctx: Context,
        inode: Self::Inode,
        flags: u32,
        handle: Self::Handle,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> Result<()> {
        Ok(())
    }

    fn statfs(&self, ctx: Context, inode: Self::Inode) -> Result<libc::statvfs64> {
        // Safe because we are zero-initializing a struct with only POD fields.
        let mut st: libc::statvfs64 = unsafe { mem::zeroed() };

        // This matches the behavior of libfuse as it returns these values if the
        // filesystem doesn't implement this method.
        st.f_namemax = 255;
        st.f_bsize = 512;

        Ok(st)
    }

    fn getxattr(
        &self,
        ctx: Context,
        inode: Self::Inode,
        name: &CStr,
        size: u32,
    ) -> Result<GetxattrReply> {
        Err(Error::from_raw_os_error(libc::ENOSYS))
    }

    fn listxattr(&self, ctx: Context, inode: Self::Inode, size: u32) -> Result<ListxattrReply> {
        Err(Error::from_raw_os_error(libc::ENOSYS))
    }

    fn opendir(
        &self,
        ctx: Context,
        inode: Self::Inode,
        flags: u32,
    ) -> Result<(Option<Self::Handle>, OpenOptions)> {
        Err(Error::from_raw_os_error(libc::ENOSYS))
    }

    fn readdir<F>(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> Result<()>
    where
        F: FnMut(DirEntry) -> Result<usize>,
    {
        Err(Error::from_raw_os_error(libc::ENOSYS))
    }

    fn readdirplus<F>(
        &self,
        ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> Result<()>
    where
        F: FnMut(DirEntry, Entry) -> Result<usize>,
    {
        Err(Error::from_raw_os_error(libc::ENOSYS))
    }

    fn releasedir(
        &self,
        ctx: Context,
        inode: Self::Inode,
        flags: u32,
        handle: Self::Handle,
    ) -> Result<()> {
        Ok(())
    }

    fn access(&self, ctx: Context, inode: Self::Inode, mask: u32) -> Result<()> {
        Err(Error::from_raw_os_error(libc::ENOSYS))
    }
}
