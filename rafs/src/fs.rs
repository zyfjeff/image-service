// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A container image Registry Accerlation File System.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::{cmp, mem};

use fuse::filesystem::*;
use fuse::protocol::*;

use crate::layout::*;
use crate::storage::device::*;
use crate::storage::*;

// rafs superblock magic number
const RAFS_SUPER_MAGIC: u32 = 0x52414653;
// rafs version number
const RAFS_CURR_VERSION: u16 = 2;

const RAFS_INODE_BLOCKSIZE: u32 = 4096;
const RAFS_DEFAULT_ATTR_TIMEOUT: u64 = 1 << 32;
const RAFS_DEFAULT_ENTRY_TIMEOUT: u64 = RAFS_DEFAULT_ATTR_TIMEOUT;

const DOT: &'static str = ".";
const DOTDOT: &'static str = "..";

type Inode = u64;
type Handle = u64;
type SuperIndex = u64;

#[derive(Default, Clone, Debug)]
struct RafsInode {
    i_ino: Inode,
    i_name: String,
    // sha256
    i_data_digest: RafsDigest,
    i_parent: u64,
    i_mode: u32,
    i_uid: u32,
    i_gid: u32,
    i_flags: u64,
    i_rdev: u32,
    i_size: u64,
    i_nlink: u32,
    i_blocks: u64,
    i_atime: u64,
    i_mtime: u64,
    i_ctime: u64,
    i_atimensec: u64,
    i_mtimensec: u64,
    i_ctimensec: u64,
    // xattr
    i_xattr: HashMap<String, Vec<u8>>,
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

    fn init(&mut self, info: &RafsInodeInfo) {
        self.i_ino = info.i_ino;
        self.i_name = String::from(&info.name);
        self.i_data_digest = info.digest.clone();
        self.i_parent = info.i_parent;
        self.i_mode = info.i_mode;
        self.i_uid = info.i_uid;
        self.i_gid = info.i_gid;
        self.i_flags = info.i_flags;
        self.i_rdev = info.i_rdev as u32;
        self.i_size = info.i_size;
        self.i_nlink = info.i_nlink as u32;
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

    fn has_xattr(&self) -> bool {
        self.i_flags & INO_FLAG_XATTR == INO_FLAG_XATTR
    }

    fn is_reg(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFREG
    }

    fn add_child(&mut self, ino: Inode) {
        self.i_child.push(ino);
    }

    fn get_attr(&self) -> Attr {
        Attr {
            ino: self.i_ino,
            size: self.i_size,
            blocks: self.i_blocks,
            atime: self.i_atime,
            ctime: self.i_ctime,
            mtime: self.i_mtime,
            mode: self.i_mode,
            nlink: self.i_nlink,
            uid: self.i_uid,
            gid: self.i_gid,
            rdev: self.i_rdev,
            blksize: RAFS_INODE_BLOCKSIZE,
            ..Default::default()
        }
    }

    fn alloc_bio_desc(&self, size: usize, offset: u64) -> Result<RafsBioDesc> {
        let mut desc = RafsBioDesc::new();
        let end = offset + size as u64;
        for blk in self.i_data.iter() {
            if blk.file_pos < offset {
                continue;
            } else if blk.file_pos > end {
                break;
            }
            let blk_start = cmp::max(blk.file_pos, offset) - blk.file_pos;
            let blk_end = cmp::min(blk.file_pos + blk.len as u64, end);
            let bio = RafsBio::new(&blk, blk_start as u32, (blk_end - blk_start) as usize);

            desc.bi_vec.push(bio);
        }
        Ok(desc)
    }
}

// Rafs block
#[derive(Clone, Default, Debug)]
pub struct RafsBlk {
    // block hash
    pub block_id: RafsDigest,
    // blob containing the block
    pub blob_id: String,
    // position of the block within the file
    pub file_pos: u64,
    // valid data length of the block, uncompressed
    // zero means hole block
    pub len: usize,
    // offset of the block within the blob
    pub blob_offset: u64,
    // size of the block, compressed
    pub compr_size: usize,
}

impl RafsBlk {
    pub fn new() -> Self {
        RafsBlk {
            ..Default::default()
        }
    }
}

impl From<RafsChunkInfo> for RafsBlk {
    fn from(info: RafsChunkInfo) -> Self {
        RafsBlk {
            block_id: info.blockid,
            blob_id: String::from(&info.blobid),
            file_pos: info.pos,
            len: info.len as usize,
            blob_offset: info.offset,
            compr_size: info.size as usize,
        }
    }
}

struct RafsSuper {
    s_magic: u32,
    s_version: u16,
    s_inode_size: u16,
    s_inodes_count: u64,
    s_root_inode: Inode,
    s_block_size: u32,
    s_blocks_count: u64,
    s_attr_timeout: Duration,
    s_entry_timeout: Duration,
    s_index: SuperIndex,
    s_inodes: RwLock<BTreeMap<Inode, Arc<RafsInode>>>,
}

impl RafsSuper {
    fn new() -> Self {
        RafsSuper {
            s_magic: 0,
            s_version: 0,
            s_inode_size: 0,
            s_inodes_count: 0,
            s_root_inode: 0,
            s_block_size: 0,
            s_blocks_count: 0,
            s_attr_timeout: Duration::from_secs(RAFS_DEFAULT_ATTR_TIMEOUT),
            s_entry_timeout: Duration::from_secs(RAFS_DEFAULT_ENTRY_TIMEOUT),
            s_index: 0,
            s_inodes: RwLock::new(BTreeMap::new()),
        }
    }

    fn init(&mut self, info: RafsSuperBlockInfo) -> Result<()> {
        if info.s_magic != RAFS_SUPER_MAGIC || info.s_fs_version != RAFS_CURR_VERSION {
            warn!(
                "invalid superblock, magic {}, version {}",
                &info.s_magic, info.s_fs_version
            );
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

    fn get_entry(&self, ino: Inode) -> Result<Entry> {
        let inodes = self.s_inodes.read().unwrap();
        let inode = inodes.get(&ino).ok_or(ebadf())?;
        let entry = Entry {
            attr: inode.get_attr().into(),
            inode: inode.i_ino,
            generation: 0,
            attr_timeout: self.s_attr_timeout,
            entry_timeout: self.s_entry_timeout,
        };

        Ok(entry)
    }

    fn destroy(&mut self) -> Result<()> {
        self.s_inodes.write().unwrap().clear();
        Ok(())
    }

    fn do_readdir<F>(
        &self,
        ctx: Context,
        inode: Inode,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> Result<()>
    where
        F: FnMut(DirEntry) -> Result<usize>,
    {
        if size == 0 {
            return Ok(());
        }
        let inodes = self.s_inodes.read().unwrap();
        let rafs_inode = inodes.get(&inode).ok_or(ebadf())?;
        if !rafs_inode.is_dir() {
            return Err(ebadf());
        }

        let mut next = offset + 1;
        for child in rafs_inode.i_child[offset as usize..].iter() {
            let child_inode = inodes.get(&child).ok_or(ebadf())?;
            match add_entry(DirEntry {
                ino: child_inode.i_ino,
                offset: next,
                type_: 0,
                name: child_inode.i_name.clone().as_bytes(),
            }) {
                Ok(0) => break,
                Ok(_) => next += 1,
                Err(r) => return Err(r),
            }
        }
        Ok(())
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct RafsConfig {
    pub device_config: device::Config,
}

impl RafsConfig {
    pub fn new() -> RafsConfig {
        RafsConfig {
            ..Default::default()
        }
    }

    fn dev_config(&self) -> device::Config {
        self.device_config.clone()
    }
}

pub struct Rafs<B: backend::BlobBackend + 'static> {
    conf: RafsConfig,

    sb: RafsSuper,
    fuse_inodes: RwLock<HashMap<Inode, (SuperIndex, Inode)>>,
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
            fuse_inodes: RwLock::new(HashMap::new()),
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
        self.device.init()?;
        self.import(r).or_else(|e| {
            self.sb.destroy()?;
            Err(e)
        })?;
        self.initialized = true;
        self.fuse_inodes
            .write()
            .unwrap()
            .insert(ROOT_ID, (self.sb.s_index, self.sb.s_root_inode));
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

    fn import<R: Read>(&mut self, r: &mut R) -> Result<()> {
        // import superblock
        let mut info = RafsSuperBlockInfo::new();
        info.load(r)?;
        self.sb.init(info)?;

        // import root inode
        let mut root_info = RafsInodeInfo::new();
        root_info.load(r)?;
        let mut root_inode = RafsInode::new();
        root_inode.init(&root_info);
        self.unpack_dir(&mut root_inode, r)?;
        self.sb.s_root_inode = root_inode.i_ino;
        // TODO: add multiple super block support
        self.sb.s_index = 100;
        self.sb.hash_inode(root_inode)
    }

    fn unpack_dir<R: Read>(&self, dir: &mut RafsInode, r: &mut R) -> Result<Option<RafsInodeInfo>> {
        trace!("unpacking dir {} ino {}", &dir.i_name, dir.i_ino);
        let mut res = None;
        let mut next = None;
        loop {
            let mut info: RafsInodeInfo;
            match next {
                Some(i) => {
                    info = i;
                    next = None;
                }
                None => {
                    info = RafsInodeInfo::new();
                    match info.load(r) {
                        Ok(0) => break,
                        Ok(n) => {
                            trace!(
                                "got inode {} ino {} parent {}",
                                &info.name,
                                info.i_ino,
                                info.i_parent
                            );
                        }
                        Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => break,
                        Err(e) => {
                            error!("error after loading RafsInodeInfo {:?}", e);
                            return Err(e);
                        }
                    }
                }
            }
            if info.i_parent != dir.i_ino {
                res = Some(info);
                break;
            }

            let mut inode = RafsInode::new();
            inode.init(&info);
            dir.add_child(info.i_ino);
            if inode.is_dir() {
                match self.unpack_dir(&mut inode, r)? {
                    Some(node) => next = Some(node),
                    None => continue,
                }
            } else {
                self.unpack_node(&mut inode, r)?;
            }
        }
        trace!("unpacked dir {}", &dir.i_name);
        // Must hash at last because we need to clone
        self.sb.hash_inode(dir.clone())?;
        Ok(res)
    }

    fn unpack_node<R: Read>(&self, inode: &mut RafsInode, r: &mut R) -> Result<()> {
        trace!(
            "unpacking inode {} xattr {} symlink {} regular {} chunk_cnt {}",
            &inode.i_name,
            inode.has_xattr(),
            inode.is_symlink(),
            inode.is_reg(),
            inode.i_chunk_cnt,
        );
        if inode.has_xattr() {
            let mut info = RafsInodeXattrInfos::new();
            info.load(r)?;
            inode.i_xattr = info.into();
        }
        if inode.is_symlink() {
            let mut info = RafsLinkDataInfo::new(inode.i_chunk_cnt as usize);
            info.load(r)?;
        } else if inode.is_reg() {
            for _ in 0..inode.i_chunk_cnt {
                let mut info = RafsChunkInfo::new();
                info.load(r)?;
                inode.i_data.push(info.into())
            }
        }
        trace!("unpacked inode {}", &inode.i_name);
        self.sb.hash_inode(inode.clone())?;
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

fn enoent() -> Error {
    Error::from_raw_os_error(libc::ENOENT)
}

fn enoattr() -> Error {
    Error::from_raw_os_error(libc::ENODATA)
}

impl<'a, B: backend::BlobBackend + 'static> FileSystem for Rafs<B> {
    fn init(&self, opts: FsOptions) -> Result<FsOptions> {
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
                | FsOptions::ATOMIC_O_TRUNC
                | FsOptions::CACHE_SYMLINKS
                | FsOptions::ZERO_MESSAGE_OPENDIR,
        )
    }

    fn destroy(&self) {
        self.sb.s_inodes.write().unwrap().clear();
        self.fuse_inodes.write().unwrap().clear();
    }

    fn lookup(&self, ctx: Context, parent: u64, name: &CStr) -> Result<Entry> {
        let inodes = self.sb.s_inodes.read().unwrap();
        let p = inodes.get(&parent).ok_or(ebadf())?;
        if !p.is_dir() {
            return Err(ebadf());
        }
        let target = name.to_str().or_else(|_| Err(ebadf()))?;
        if target == DOT || (parent == ROOT_ID && target == DOTDOT) {
            let mut entry = self.sb.get_entry(parent)?;
            entry.inode = parent;
            return Ok(entry);
        }
        for ino in p.i_child.iter() {
            let child = inodes.get(&ino).ok_or(ebadf())?;
            if !target.eq(&child.i_name) {
                continue;
            }
            let entry = self.sb.get_entry(child.i_ino)?;
            self.fuse_inodes
                .write()
                .unwrap()
                .insert(child.i_ino, (self.sb.s_index, child.i_ino));
            return Ok(entry);
        }
        Err(enoent())
    }

    fn forget(&self, ctx: Context, inode: u64, count: u64) {
        self.fuse_inodes.write().unwrap().remove(&inode);
    }

    fn batch_forget(&self, ctx: Context, requests: Vec<(u64, u64)>) {
        for (inode, count) in requests {
            self.forget(ctx, inode, count)
        }
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: u64,
        handle: Option<u64>,
    ) -> Result<(libc::stat64, Duration)> {
        let inodes = self.sb.s_inodes.read().unwrap();
        let rafs_inode = inodes.get(&inode).ok_or(enoent())?;
        Ok((rafs_inode.get_attr().into(), self.sb.s_attr_timeout))
    }

    fn readlink(&self, ctx: Context, inode: u64) -> Result<Vec<u8>> {
        let inodes = self.sb.s_inodes.read().unwrap();
        let rafs_inode = inodes.get(&inode).ok_or(enoent())?;
        if !rafs_inode.is_symlink() {
            return Err(einval());
        }
        // clone because we don't want to consume Arc rafs inode
        Ok(rafs_inode.i_target.clone().into_bytes())
    }

    #[allow(clippy::too_many_arguments)]
    fn read<W: Write + ZeroCopyWriter>(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        w: W,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> Result<usize> {
        let inodes = self.sb.s_inodes.read().unwrap();
        let rafs_inode = inodes.get(&inode).ok_or(enoent())?;

        let desc = rafs_inode.alloc_bio_desc(size as usize, offset)?;

        self.device.read_to(w, desc)
    }

    #[allow(clippy::too_many_arguments)]
    fn write<R: Read + ZeroCopyReader>(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        r: R,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        flags: u32,
    ) -> Result<usize> {
        let inodes = self.sb.s_inodes.read().unwrap();
        let rafs_inode = inodes.get(&inode).ok_or(enoent())?;

        let desc = rafs_inode.alloc_bio_desc(size as usize, offset)?;
        self.device.write_from(r, desc)
    }

    fn release(
        &self,
        ctx: Context,
        inode: u64,
        flags: u32,
        handle: u64,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> Result<()> {
        Ok(())
    }

    fn statfs(&self, ctx: Context, inode: u64) -> Result<libc::statvfs64> {
        // Safe because we are zero-initializing a struct with only POD fields.
        let mut st: libc::statvfs64 = unsafe { mem::zeroed() };

        // This matches the behavior of libfuse as it returns these values if the
        // filesystem doesn't implement this method.
        st.f_namemax = 255;
        st.f_bsize = 512;
        st.f_blocks = self.sb.s_blocks_count;
        st.f_fsid = self.sb.s_magic as u64 + self.sb.s_index;
        st.f_files = self.sb.s_inodes_count;

        Ok(st)
    }

    fn getxattr(&self, ctx: Context, inode: u64, name: &CStr, size: u32) -> Result<GetxattrReply> {
        let inode = self
            .sb
            .s_inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or(enoent())?;

        let key = name.to_str().or_else(|_| Err(einval()))?;
        let value = inode.i_xattr.get(key).ok_or(enoattr())?;
        match size {
            0 => Ok(GetxattrReply::Count(value.len() as u32)),
            _ => Ok(GetxattrReply::Value(value.clone())),
        }
    }

    fn listxattr(&self, ctx: Context, inode: u64, size: u32) -> Result<ListxattrReply> {
        let inode = self
            .sb
            .s_inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or(enoent())?;

        match size {
            0 => {
                let mut count = 0;
                for (key, _) in inode.i_xattr.iter() {
                    count += key.len();
                }
                Ok(ListxattrReply::Count(count as u32))
            }
            _ => {
                let mut buf = Vec::new();
                for (key, _) in inode.i_xattr.iter() {
                    buf.append(&mut key.clone().into_bytes());
                    buf.append(&mut vec![0u8; 1])
                }
                Ok(ListxattrReply::Names(buf))
            }
        }
    }

    fn readdir<F>(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> Result<()>
    where
        F: FnMut(DirEntry) -> Result<usize>,
    {
        self.sb.do_readdir(ctx, inode, size, offset, add_entry)
    }

    fn readdirplus<F>(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> Result<()>
    where
        F: FnMut(DirEntry, Entry) -> Result<usize>,
    {
        self.sb.do_readdir(ctx, inode, size, offset, |dir_entry| {
            let entry = self.sb.get_entry(dir_entry.ino)?;
            add_entry(dir_entry, entry)
        })
    }

    fn releasedir(&self, ctx: Context, inode: u64, flags: u32, handle: u64) -> Result<()> {
        Ok(())
    }

    fn access(&self, ctx: Context, inode: u64, mask: u32) -> Result<()> {
        let inodes = self.sb.s_inodes.read().unwrap();
        let rafs_inode = inodes.get(&inode).ok_or(enoent())?;
        let st = rafs_inode.get_attr();
        let mode = mask as i32 & (libc::R_OK | libc::W_OK | libc::X_OK);

        if mode == libc::F_OK {
            return Ok(());
        }

        if (mode & libc::R_OK) != 0
            && ctx.uid != 0
            && (st.uid != ctx.uid || st.mode & 0o400 == 0)
            && (st.gid != ctx.gid || st.mode & 0o040 == 0)
            && st.mode & 0o004 == 0
        {
            return Err(Error::from_raw_os_error(libc::EACCES));
        }

        if (mode & libc::W_OK) != 0
            && ctx.uid != 0
            && (st.uid != ctx.uid || st.mode & 0o200 == 0)
            && (st.gid != ctx.gid || st.mode & 0o020 == 0)
            && st.mode & 0o002 == 0
        {
            return Err(Error::from_raw_os_error(libc::EACCES));
        }

        // root can only execute something if it is executable by one of the owner, the group, or
        // everyone.
        if (mode & libc::X_OK) != 0
            && (ctx.uid != 0 || st.mode & 0o111 == 0)
            && (st.uid != ctx.uid || st.mode & 0o100 == 0)
            && (st.gid != ctx.gid || st.mode & 0o010 == 0)
            && st.mode & 0o001 == 0
        {
            return Err(Error::from_raw_os_error(libc::EACCES));
        }

        Ok(())
    }
}
