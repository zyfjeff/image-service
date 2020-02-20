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

use log::{info, trace, warn};

use fuse::filesystem::*;

use crate::layout::*;
use crate::storage::device::*;
use crate::storage::*;

// rafs superblock magic number
const RAFS_SUPER_MAGIC: u32 = 0x52414653;
// rafs version number
const RAFS_CURR_VERSION: u16 = 1;

type Inode = u64;
type Handle = u64;

#[derive(Default, Clone)]
struct RafsInode {
    i_ino: Inode,
    i_name: String,
    // sha256
    i_data_digest: String,
    i_parent: u64,
    i_mode: u32,
    i_uid: u32,
    i_gid: u32,
    i_flags: u64,
    i_rdev: u64,
    i_size: u64,
    i_nlink: u64,
    i_blocks: u64,
    i_atime: u64,
    i_mtime: u64,
    i_ctime: u64,
    i_chunk_cnt: u64,
    // symlink target
    i_target: String,
    // data chunks
    i_data: Vec<RafsBlk>,
    // dir
    // FIXME: hardlinks
    i_child: Vec<Inode>,
}

impl RafsInode {
    fn new() -> Self {
        RafsInode {
            ..Default::default()
        }
    }

    fn init(&mut self, parent: Inode, info: &RafsInodeInfo) {
        self.i_ino = info.i_ino;
        self.i_name = String::from(&info.name);
        self.i_data_digest = String::from(&info.digest);
        self.i_parent = parent;
        self.i_mode = info.i_mode;
        self.i_uid = info.i_uid;
        self.i_gid = info.i_gid;
        self.i_flags = info.i_flags;
        self.i_rdev = info.i_rdev;
        self.i_size = info.i_size;
        self.i_nlink = info.i_nlink;
        self.i_blocks = info.i_blocks;
        self.i_atime = info.i_atime;
        self.i_mtime = info.i_mtime;
        self.i_ctime = info.i_ctime;
        self.i_chunk_cnt = info.i_chunk_cnt;
    }

    fn is_dir(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFDIR
    }

    fn is_symlink(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFLNK
    }

    fn is_reg(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFREG
    }

    fn add_child(&mut self, ino: Inode) {
        self.i_child.push(ino);
    }
}

struct RafsSuper {
    s_magic: u32,
    s_version: u16,
    s_inode_size: u16,
    s_inodes_count: u64,
    s_block_size: u32,
    s_blocks_count: u64,
    s_inodes: RwLock<BTreeMap<Inode, Arc<RafsInode>>>,
}

impl RafsSuper {
    fn new() -> Self {
        RafsSuper {
            s_magic: 0,
            s_version: 0,
            s_inode_size: 0,
            s_inodes_count: 0,
            s_block_size: 0,
            s_blocks_count: 0,
            s_inodes: RwLock::new(BTreeMap::new()),
        }
    }

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

    fn hash_inode(&self, ino: RafsInode) -> Result<()> {
        self.s_inodes
            .write()
            .unwrap()
            .insert(ino.i_ino, Arc::new(ino));
        Ok(())
    }

    fn destroy(&mut self) -> Result<()> {
        self.s_inodes.write().unwrap().clear();
        Ok(())
    }
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
    // TODO: add vfs inode map, in order to support multiple
    // rafs super per instance, we need another indirection layer
    device: device::RafsDevice<B>,
    initialized: bool,
}

impl<B: backend::BlobBackend + 'static> Rafs<B> {
    pub fn new(conf: RafsConfig, b: B) -> Self {
        Rafs {
            sb: RafsSuper::new(),
            device: device::RafsDevice::new(conf.dev_config(), b),
            conf: conf,
            initialized: false,
        }
    }

    // mount an rafs metadata provided by Read, to the specified virtual path
    // E.g., mount / would create a virtual path the same as the container rootfs
    pub fn mount<R: Read>(&mut self, r: &mut R, path: &str) -> Result<()> {
        info! {"Mounting rafs at {}", &path};
        // FIXME: Only support single root mount for now.
        if self.initialized {
            warn! {"Rafs already initialized"}
            return Err(Error::new(ErrorKind::AlreadyExists, "Already mounted"));
        }
        self.import(r).or_else(|_| self.sb.destroy())?;
        self.initialized = true;
        info! {"Mounted rafs at {}", &path};
        Ok(())
    }

    // umount a prviously mounted rafs virtual path
    pub fn umount(&mut self, path: &str) -> Result<()> {
        info! {"Umounting rafs"}
        self.sb.destroy()?;
        self.initialized = false;
        Ok(())
    }

    fn import<R: Read>(&mut self, mut r: &mut R) -> Result<()> {
        // import superblock
        let mut info = RafsSuperBlockInfo::new();
        info.load(&mut r)?;
        self.sb.init(info)?;

        // import root inode
        let mut root_info = RafsInodeInfo::new();
        root_info.load(&mut r)?;
        let mut root_inode = RafsInode::new();
        root_inode.init(root_info.i_ino, &root_info);
        self.unpack_dir(&mut root_inode, &mut r)?;
        self.sb.hash_inode(root_inode)
    }

    fn unpack_dir<R: Read>(&self, dir: &mut RafsInode, mut r: &mut R) -> Result<()> {
        loop {
            let mut info = RafsInodeInfo::new();
            match info.load(&mut r) {
                Ok(0) => break,
                Ok(n) => {
                    trace!("unpacked {}", info.name);
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => break,
                Err(e) => return Err(e),
            }

            let mut inode = RafsInode::new();
            inode.init(dir.i_ino, &info);
            dir.add_child(info.i_ino);
            if inode.is_dir() {
                self.unpack_dir(&mut inode, &mut r)?;
            } else {
                self.unpack_node(&mut inode, &mut r)?;
            }
        }
        // Must hash at last because we need to clone
        self.sb.hash_inode(dir.clone())
    }

    fn unpack_node<R: Read>(&self, inode: &mut RafsInode, r: &mut R) -> Result<()> {
        if inode.is_symlink() {
            let mut info = RafsLinkDataInfo::new(inode.i_chunk_cnt as usize);
            info.load(r)?;
        } else if inode.is_reg() {
            let mut info = RafsChunkInfo::new();
            info.load(r)?;
        }
        Ok(())
    }
}

fn ebadf() -> Error {
    Error::from_raw_os_error(libc::EBADF)
}

fn enosys() -> Error {
    Error::from_raw_os_error(libc::ENOSYS)
}

fn einval() -> Error {
    Error::from_raw_os_error(libc::EINVAL)
}

impl<B: backend::BlobBackend + 'static> FileSystem for Rafs<B> {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, _: FsOptions) -> Result<FsOptions> {
        // TODO: add fuse ROOT_ID inode mapping
        // self.sb.alloc_inode(ROOT_ID)?;

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
        let p = self
            .sb
            .s_inodes
            .read()
            .unwrap()
            .get(&parent)
            .ok_or(ebadf())?;
        Err(enosys())
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
        Err(enosys())
    }

    fn readlink(&self, ctx: Context, inode: Self::Inode) -> Result<Vec<u8>> {
        Err(enosys())
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
        let blk = RafsBlk::new();
        let bio = RafsBio::new(&blk);
        let mut desc = RafsBioDesc::new();
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
        let blk = RafsBlk::new();
        let bio = RafsBio::new(&blk);
        let mut desc = RafsBioDesc::new();
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
        Err(enosys())
    }

    fn listxattr(&self, ctx: Context, inode: Self::Inode, size: u32) -> Result<ListxattrReply> {
        Err(enosys())
    }

    fn opendir(
        &self,
        ctx: Context,
        inode: Self::Inode,
        flags: u32,
    ) -> Result<(Option<Self::Handle>, OpenOptions)> {
        Err(enosys())
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
        Err(enosys())
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
        Err(enosys())
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
        Err(enosys())
    }
}
