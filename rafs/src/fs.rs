// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// A container image Registry Acceleration File System.

//! RAFS: a readonly FUSE file system designed for Cloud Native.

use std::ffi::CStr;
use std::io::{Error, ErrorKind, Result};
use std::sync::Arc;
use std::time::Duration;

use fuse_rs::abi::linux_abi::Attr;
use fuse_rs::api::filesystem::*;
use fuse_rs::api::BackendFileSystem;
use serde::Deserialize;

use crate::io_stats;
use crate::io_stats::StatsFop;
use crate::metadata::RafsSuper;
use crate::storage::device;
use crate::storage::*;
use crate::*;

/// Type of RAFS inode.
pub type Inode = u64;
/// Type of RAFS fuse handle.
pub type Handle = u64;

/// Rafs default attribute timeout value.
pub const RAFS_DEFAULT_ATTR_TIMEOUT: u64 = 1 << 32;
/// Rafs default entry timeout value.
pub const RAFS_DEFAULT_ENTRY_TIMEOUT: u64 = RAFS_DEFAULT_ATTR_TIMEOUT;

const DOT: &str = ".";
const DOTDOT: &str = "..";

/// Rafs storage backend configuration information.
#[derive(Clone, Default, Deserialize)]
pub struct RafsConfig {
    pub device: factory::Config,
    pub mode: String,
    pub iostats_files: bool,
}

impl RafsConfig {
    pub fn new() -> RafsConfig {
        RafsConfig {
            ..Default::default()
        }
    }
}

/// Main entrance of the RAFS readonly FUSE file system.
pub struct Rafs {
    device: device::RafsDevice,
    sb: RafsSuper,
    initialized: bool,
    ios: Arc<io_stats::GlobalIOStats>,
}

impl Rafs {
    pub fn new(conf: RafsConfig, id: &str) -> Result<Self> {
        let rafs = Rafs {
            device: device::RafsDevice::new(conf.device.clone())?,
            sb: RafsSuper::new(conf.mode.as_str())?,
            initialized: false,
            ios: io_stats::ios_new(id),
        };

        rafs.ios.toggle_files_recording(conf.iostats_files);

        Ok(rafs)
    }

    /// Import an rafs metadata to initialize the filesystem instance.
    pub fn import(&mut self, r: &mut RafsIoReader) -> Result<()> {
        if self.initialized {
            warn! {"Rafs already initialized"}
            return Err(Error::new(ErrorKind::AlreadyExists, "Already mounted"));
        }

        self.sb.load(r).or_else(|e| {
            self.sb.destroy();
            Err(e)
        })?;

        self.device.init(&self.sb.meta)?;

        self.initialized = true;
        info!("rafs imported");

        Ok(())
    }

    /// umount a previously mounted rafs virtual path
    pub fn destroy(&mut self) -> Result<()> {
        info! {"Destroy rafs"}

        if self.initialized {
            self.sb.destroy();
            self.device.close()?;
            self.initialized = false;
        }

        Ok(())
    }

    fn do_readdir<F>(&self, ino: Inode, size: u32, offset: u64, mut add_entry: F) -> Result<()>
    where
        F: FnMut(DirEntry) -> Result<usize>,
    {
        if size == 0 {
            return Ok(());
        }

        let parent = self.sb.get_inode(ino)?;
        if !parent.is_dir() {
            return Err(ebadf());
        }

        let mut idx = offset as usize;
        while idx < parent.get_child_count()? {
            let child = parent.get_child_by_index(idx as u64)?;
            match add_entry(DirEntry {
                ino: child.ino(),
                offset: (idx + 1) as u64,
                type_: 0,
                name: child.name()?.as_bytes(),
            }) {
                Ok(0) => {
                    self.ios.new_file_counter(child.ino());
                    break;
                }
                Ok(_) => {
                    idx += 1;
                    self.ios.new_file_counter(child.ino())
                } // TODO: should we check `size` here?
                Err(r) => return Err(r),
            }
        }

        Ok(())
    }

    fn negative_entry(&self) -> Entry {
        Entry {
            attr: Attr {
                ..Default::default()
            }
            .into(),
            inode: 0,
            generation: 0,
            attr_timeout: self.sb.meta.attr_timeout,
            entry_timeout: self.sb.meta.entry_timeout,
        }
    }
}

fn ebadf() -> Error {
    Error::from_raw_os_error(libc::EBADF)
}

fn einval() -> Error {
    Error::from_raw_os_error(libc::EINVAL)
}

impl BackendFileSystem for Rafs {
    fn mount(&self) -> Result<(Entry, u64)> {
        let root_inode = self.sb.get_inode(ROOT_ID)?;
        self.ios.new_file_counter(root_inode.ino());
        let entry = root_inode.get_entry();
        Ok((entry, self.sb.get_max_ino()))
    }
}

impl Rafs {
    fn lookup_wrapped(&self, ino: u64, name: &CStr) -> Result<Entry> {
        let target = name.to_str().or_else(|_| Err(ebadf()))?;
        let parent = self.sb.get_inode(ino)?;
        if !parent.is_dir() {
            return Err(ebadf());
        }

        if target == DOT || (ino == ROOT_ID && target == DOTDOT) {
            let mut entry = parent.get_entry();
            entry.inode = ino;
            Ok(entry)
        } else if target == DOTDOT {
            Ok(self
                .sb
                .get_inode(parent.parent())
                .map(|i| i.get_entry())
                .unwrap_or_else(|_| self.negative_entry()))
        } else {
            Ok(parent
                .get_child_by_name(target)
                .map(|i| {
                    self.ios.new_file_counter(i.ino());
                    i.get_entry()
                })
                .unwrap_or_else(|_| self.negative_entry()))
        }
    }
}

impl FileSystem for Rafs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, _opts: FsOptions) -> Result<FsOptions> {
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

    fn destroy(&self) {}

    fn lookup(&self, _ctx: Context, ino: u64, name: &CStr) -> Result<Entry> {
        let start = self.ios.ios_latency_start();
        let r = self.lookup_wrapped(ino, name);
        self.ios.ios_file_stats_update(ino, StatsFop::Lookup, 0, &r);
        self.ios.ios_latency_end(&start, StatsFop::Lookup);
        r
    }

    fn forget(&self, _ctx: Context, _inode: u64, _count: u64) {}

    fn batch_forget(&self, ctx: Context, requests: Vec<(u64, u64)>) {
        for (inode, count) in requests {
            self.forget(ctx, inode, count)
        }
    }

    fn getattr(
        &self,
        _ctx: Context,
        ino: u64,
        _handle: Option<u64>,
    ) -> Result<(libc::stat64, Duration)> {
        let inode = self.sb.get_inode(ino)?;
        let r = Ok((inode.get_attr().into(), self.sb.meta.attr_timeout));
        self.ios.ios_file_stats_update(ino, StatsFop::Stat, 0, &r);
        r
    }

    fn readlink(&self, _ctx: Context, ino: u64) -> Result<Vec<u8>> {
        let inode = self.sb.get_inode(ino)?;

        Ok(inode.get_symlink()?.as_bytes().to_vec())
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        _ctx: Context,
        ino: u64,
        _handle: u64,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> Result<usize> {
        let inode = self.sb.get_inode(ino)?;
        if offset >= inode.size() {
            return Ok(0);
        }
        let desc = inode.alloc_bio_desc(offset, size as usize)?;
        let start = self.ios.ios_latency_start();
        let r = self.device.read_to(w, desc);
        self.ios
            .ios_file_stats_update(ino, StatsFop::Read, size as usize, &r);
        self.ios.ios_latency_end(&start, io_stats::StatsFop::Read);
        r
    }

    fn release(
        &self,
        _ctx: Context,
        _inode: u64,
        _flags: u32,
        _handle: u64,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> Result<()> {
        Ok(())
    }

    fn statfs(&self, _ctx: Context, _inode: u64) -> Result<libc::statvfs64> {
        // Safe because we are zero-initializing a struct with only POD fields.
        let mut st: libc::statvfs64 = unsafe { std::mem::zeroed() };

        // This matches the behavior of libfuse as it returns these values if the
        // filesystem doesn't implement this method.
        st.f_namemax = 255;
        st.f_bsize = 512;
        st.f_fsid = self.sb.meta.magic as u64;
        st.f_files = self.sb.meta.inodes_count;

        Ok(st)
    }

    fn getxattr(&self, _ctx: Context, inode: u64, name: &CStr, size: u32) -> Result<GetxattrReply> {
        let key = name.to_str().or_else(|_| Err(einval()))?;
        let inode = self.sb.get_inode(inode)?;

        // Keep for simplicity, not optimized for performance.
        for (k, v) in inode.get_xattrs()? {
            if key == k {
                return match size {
                    0 => Ok(GetxattrReply::Count((v.len() + 1) as u32)),
                    _ => Ok(GetxattrReply::Value(v.to_vec())),
                };
            }
        }

        match size {
            0 => Ok(GetxattrReply::Count(0)),
            _ => Ok(GetxattrReply::Value(Vec::new())),
        }
    }

    fn listxattr(&self, _ctx: Context, inode: u64, size: u32) -> Result<ListxattrReply> {
        let inode = self.sb.get_inode(inode)?;
        let mut count = 0;
        let mut buf = Vec::new();

        for (k, _v) in inode.get_xattrs()? {
            match size {
                0 => count += k.len() + 1,
                _ => {
                    buf.append(&mut k.as_bytes().to_vec());
                    buf.append(&mut vec![0u8; 1])
                }
            }
        }

        match size {
            0 => Ok(ListxattrReply::Count(count as u32)),
            _ => Ok(ListxattrReply::Names(buf)),
        }
    }

    fn readdir(
        &self,
        _ctx: Context,
        inode: u64,
        _handle: u64,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry) -> Result<usize>,
    ) -> Result<()> {
        self.do_readdir(inode, size, offset, add_entry)
    }

    fn readdirplus(
        &self,
        _ctx: Context,
        ino: u64,
        _handle: u64,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry, Entry) -> Result<usize>,
    ) -> Result<()> {
        self.do_readdir(ino, size, offset, |dir_entry| {
            let inode = self.sb.get_inode(dir_entry.ino)?;
            add_entry(dir_entry, inode.get_entry())
        })
    }

    fn releasedir(&self, _ctx: Context, _inode: u64, _flags: u32, _handle: u64) -> Result<()> {
        Ok(())
    }

    fn access(&self, ctx: Context, ino: u64, mask: u32) -> Result<()> {
        let inode = self.sb.get_inode(ino)?;
        let st = inode.get_attr();
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
            return Err(eaccess());
        }

        if (mode & libc::W_OK) != 0
            && ctx.uid != 0
            && (st.uid != ctx.uid || st.mode & 0o200 == 0)
            && (st.gid != ctx.gid || st.mode & 0o020 == 0)
            && st.mode & 0o002 == 0
        {
            return Err(eaccess());
        }

        // root can only execute something if it is executable by one of the owner, the group, or
        // everyone.
        if (mode & libc::X_OK) != 0
            && (ctx.uid != 0 || st.mode & 0o111 == 0)
            && (st.uid != ctx.uid || st.mode & 0o100 == 0)
            && (st.gid != ctx.gid || st.mode & 0o010 == 0)
            && st.mode & 0o001 == 0
        {
            return Err(eaccess());
        }

        Ok(())
    }
}
