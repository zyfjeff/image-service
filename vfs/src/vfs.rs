// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A vfs for real filesystems switching

use libc;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{Error, Read, Result, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bimap::hash::BiHashMap;

use fuse::filesystem::*;

use crate::pseudo_fs::PseudoFs;

const PSEUDO_FS_SUPER: u64 = 1;

type Inode = u64;
type SuperIndex = u64;

#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
struct InodeData {
    super_index: SuperIndex,
    ino: Inode,
}

impl InodeData {
    fn is_pseudo(&self) -> bool {
        self.super_index == PSEUDO_FS_SUPER
    }
}

struct MountPointData {
    super_index: SuperIndex,
    ino: Inode,
    root_entry: Entry,
}

pub struct Vfs<F: FileSystem> {
    next_inode: AtomicU64,
    next_super: AtomicU64,
    root: PseudoFs,
    // inodes maintains mapping between fuse inode and (pseudo fs or mounted fs) inode data
    inodes: RwLock<BiHashMap<Inode, InodeData>>,
    // mountpoints maps from pseudo fs inode to mounted fs mountpoint data
    mountpoints: RwLock<HashMap<Inode, Arc<MountPointData>>>,
    // superblocks keeps track of all mounted file systems
    superblocks: RwLock<HashMap<SuperIndex, Arc<F>>>,
}

impl<F: FileSystem> Vfs<F> {
    pub fn new() -> Self {
        let vfs = Vfs {
            next_inode: AtomicU64::new(ROOT_ID + 1),
            next_super: AtomicU64::new(PSEUDO_FS_SUPER + 1),
            inodes: RwLock::new(BiHashMap::new()),
            mountpoints: RwLock::new(HashMap::new()),
            superblocks: RwLock::new(HashMap::new()),
            root: PseudoFs::new(PSEUDO_FS_SUPER),
        };
        vfs.inodes.write().unwrap().insert(
            ROOT_ID,
            InodeData {
                super_index: PSEUDO_FS_SUPER,
                ino: ROOT_ID,
            },
        );

        vfs
    }

    pub fn mount(&self, fs: F, path: &str) -> Result<()> {
        let entry = fs.lookup(Context::new(), ROOT_ID, &CString::new(".").unwrap())?;
        let inode = self.root.mount(path)?;
        let index = self.next_super.fetch_add(1, Ordering::Relaxed);
        // TODO: handle over mount on the same mountpoint
        self.mountpoints.write().unwrap().insert(
            inode,
            Arc::new(MountPointData {
                super_index: index,
                ino: ROOT_ID,
                root_entry: entry,
            }),
        );
        self.superblocks
            .write()
            .unwrap()
            .insert(index, Arc::new(fs));
        // Special case, mount on pseudo fs root, need to hash it so that
        // future access to vfs ROOT_ID points to the new mount
        if inode == ROOT_ID {
            self.inodes.write().unwrap().insert(
                inode,
                InodeData {
                    super_index: index,
                    ino: inode,
                },
            );
        }
        Ok(())
    }

    // bimap insert_no_overwrite ensures hashed inode number uniqueness
    // We assume we never run out of u64 fuse inode number
    fn hash_inode(&self, index: u64, inode: u64) -> Result<u64> {
        let mut ino = self.next_inode.fetch_add(1, Ordering::Relaxed);
        let mut inodes = self.inodes.write().unwrap();
        ino = match inodes.insert_no_overwrite(
            ino,
            InodeData {
                super_index: index,
                ino: inode,
            },
        ) {
            Ok(()) => ino,
            Err((_, _)) => {
                // conflicts, find out the existing one
                ino = inodes
                    .get_by_right(&InodeData {
                        super_index: index,
                        ino: inode,
                    })
                    .unwrap()
                    .clone();
                ino
            }
        };

        debug!(
            "vfs hash inode index {} ino {} fuse ino {}",
            index, inode, ino
        );
        Ok(ino)
    }
}

impl<F: FileSystem + Send + Sync + 'static> FileSystem for Vfs<F> {
    fn init(&self, _: FsOptions) -> Result<FsOptions> {
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
        self.inodes.write().unwrap().clear();
        self.superblocks.write().unwrap().clear();
        self.root.destroy();
    }

    fn lookup(&self, ctx: Context, parent: u64, name: &CStr) -> Result<Entry> {
        let pidata = match self.inodes.read().unwrap().get_by_left(&parent) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        let mut entry: Entry;
        if pidata.is_pseudo() {
            entry = self.root.lookup(ctx, pidata.ino, name)?;
            // check mountpoints
            let mnt = match self
                .mountpoints
                .read()
                .unwrap()
                .get(&entry.inode)
                .map(Arc::clone)
            {
                Some(mnt) => mnt,
                None => {
                    entry.inode = self.hash_inode(pidata.super_index, entry.inode)?;
                    return Ok(entry);
                }
            };
            // cross mountpoint, return mount root entry
            entry = mnt.root_entry.clone();
            entry.inode = self.hash_inode(mnt.super_index, mnt.ino)?;
            trace!(
                "vfs lookup cross mountpoint, return new mount index {} inode {} fuse inode {}",
                mnt.super_index,
                mnt.ino,
                entry.inode
            );
            return Ok(entry);
        }

        // parent is in an underlying rootfs
        let fs = self
            .superblocks
            .read()
            .unwrap()
            .get(&pidata.super_index)
            .map(Arc::clone)
            .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
        entry = fs.lookup(ctx, pidata.ino, name)?;

        // lookup succees, hash it to a real fuse inode
        entry.inode = self.hash_inode(pidata.super_index, entry.inode)?;

        Ok(entry)
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: u64,
        handle: Option<u64>,
    ) -> Result<(libc::stat64, Duration)> {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.getattr(ctx, idata.ino, handle)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.getattr(ctx, idata.ino, handle)
        }
    }

    fn setattr(
        &self,
        ctx: Context,
        inode: u64,
        attr: libc::stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> Result<(libc::stat64, Duration)> {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.setattr(ctx, idata.ino, attr, handle, valid)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.setattr(ctx, idata.ino, attr, handle, valid)
        }
    }

    fn readlink(&self, ctx: Context, inode: u64) -> Result<Vec<u8>> {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.readlink(ctx, idata.ino)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.readlink(ctx, idata.ino)
        }
    }

    fn symlink(&self, ctx: Context, linkname: &CStr, parent: u64, name: &CStr) -> Result<Entry> {
        let idata = match self.inodes.read().unwrap().get_by_left(&parent) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.symlink(ctx, linkname, idata.ino, name)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.symlink(ctx, linkname, idata.ino, name)
        }
    }

    fn mknod(
        &self,
        ctx: Context,
        inode: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
    ) -> Result<Entry> {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.mknod(ctx, idata.ino, name, mode, rdev, umask)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.mknod(ctx, idata.ino, name, mode, rdev, umask)
        }
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        umask: u32,
    ) -> Result<Entry> {
        let idata = match self.inodes.read().unwrap().get_by_left(&parent) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.mkdir(ctx, idata.ino, name, mode, umask)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.mkdir(ctx, idata.ino, name, mode, umask)
        }
    }

    fn unlink(&self, ctx: Context, parent: u64, name: &CStr) -> Result<()> {
        let idata = match self.inodes.read().unwrap().get_by_left(&parent) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.unlink(ctx, idata.ino, name)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.unlink(ctx, idata.ino, name)
        }
    }

    fn rmdir(&self, ctx: Context, parent: u64, name: &CStr) -> Result<()> {
        let idata = match self.inodes.read().unwrap().get_by_left(&parent) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.rmdir(ctx, idata.ino, name)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.rmdir(ctx, idata.ino, name)
        }
    }

    fn rename(
        &self,
        ctx: Context,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> Result<()> {
        let idata_old = match self.inodes.read().unwrap().get_by_left(&olddir) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        let idata_new = match self.inodes.read().unwrap().get_by_left(&newdir) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata_old.super_index != idata_new.super_index {
            return Err(Error::from_raw_os_error(libc::EINVAL));
        }

        if idata_old.is_pseudo() && idata_new.is_pseudo() {
            self.root
                .rename(ctx, idata_old.ino, oldname, idata_new.ino, newname, flags)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata_old.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.rename(ctx, idata_old.ino, oldname, idata_new.ino, newname, flags)
        }
    }

    fn link(&self, ctx: Context, inode: u64, newparent: u64, newname: &CStr) -> Result<Entry> {
        let idata_old = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        let idata_new = match self.inodes.read().unwrap().get_by_left(&newparent) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata_old.super_index != idata_new.super_index {
            return Err(Error::from_raw_os_error(libc::EINVAL));
        }

        if idata_old.is_pseudo() && idata_new.is_pseudo() {
            self.root.link(ctx, idata_old.ino, idata_new.ino, newname)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata_old.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.link(ctx, idata_old.ino, idata_new.ino, newname)
        }
    }

    fn open(&self, _ctx: Context, _inode: u64, _flags: u32) -> Result<(Option<u64>, OpenOptions)> {
        // Matches the behavior of libfuse.
        Ok((None, OpenOptions::empty()))
    }

    fn create(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        flags: u32,
        umask: u32,
    ) -> Result<(Entry, Option<u64>, OpenOptions)> {
        let idata = match self.inodes.read().unwrap().get_by_left(&parent) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.create(ctx, idata.ino, name, mode, flags, umask)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.create(ctx, idata.ino, name, mode, flags, umask)
        }
    }

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
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root
                .read(ctx, idata.ino, handle, w, size, offset, lock_owner, flags)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.read(ctx, idata.ino, handle, w, size, offset, lock_owner, flags)
        }
    }

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
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.write(
                ctx,
                idata.ino,
                handle,
                r,
                size,
                offset,
                lock_owner,
                delayed_write,
                flags,
            )
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.write(
                ctx,
                idata.ino,
                handle,
                r,
                size,
                offset,
                lock_owner,
                delayed_write,
                flags,
            )
        }
    }

    fn flush(&self, ctx: Context, inode: u64, handle: u64, lock_owner: u64) -> Result<()> {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.flush(ctx, idata.ino, handle, lock_owner)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.flush(ctx, idata.ino, handle, lock_owner)
        }
    }

    fn fsync(&self, ctx: Context, inode: u64, datasync: bool, handle: u64) -> Result<()> {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.fsync(ctx, idata.ino, datasync, handle)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.fsync(ctx, idata.ino, datasync, handle)
        }
    }

    fn fallocate(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> Result<()> {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root
                .fallocate(ctx, inode, handle, mode, offset, length)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.fallocate(ctx, inode, handle, mode, offset, length)
        }
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
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.release(
                ctx,
                idata.ino,
                flags,
                handle,
                flush,
                flock_release,
                lock_owner,
            )
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.release(
                ctx,
                idata.ino,
                flags,
                handle,
                flush,
                flock_release,
                lock_owner,
            )
        }
    }

    fn statfs(&self, ctx: Context, inode: u64) -> Result<libc::statvfs64> {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.statfs(ctx, idata.ino)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.statfs(ctx, idata.ino)
        }
    }

    fn setxattr(
        &self,
        ctx: Context,
        inode: u64,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> Result<()> {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.setxattr(ctx, idata.ino, name, value, flags)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.setxattr(ctx, idata.ino, name, value, flags)
        }
    }

    fn getxattr(&self, ctx: Context, inode: u64, name: &CStr, size: u32) -> Result<GetxattrReply> {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.getxattr(ctx, idata.ino, name, size)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.getxattr(ctx, idata.ino, name, size)
        }
    }

    fn listxattr(&self, ctx: Context, inode: u64, size: u32) -> Result<ListxattrReply> {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.listxattr(ctx, idata.ino, size)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.listxattr(ctx, idata.ino, size)
        }
    }

    fn removexattr(&self, ctx: Context, inode: u64, name: &CStr) -> Result<()> {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.removexattr(ctx, idata.ino, name)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.removexattr(ctx, idata.ino, name)
        }
    }

    fn opendir(
        &self,
        _ctx: Context,
        _inode: u64,
        _flags: u32,
    ) -> Result<(Option<u64>, OpenOptions)> {
        // Matches the behavior of libfuse.
        Ok((None, OpenOptions::empty()))
    }

    fn readdir<FF>(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        mut add_entry: FF,
    ) -> Result<()>
    where
        FF: FnMut(DirEntry) -> Result<usize>,
    {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root
                .readdir(ctx, idata.ino, handle, size, offset, |mut dir_entry| {
                    let mnt = match self
                        .mountpoints
                        .read()
                        .unwrap()
                        .get(&dir_entry.ino)
                        .map(Arc::clone)
                    {
                        Some(mnt) => mnt,
                        None => {
                            dir_entry.ino = self.hash_inode(idata.super_index, dir_entry.ino)?;
                            return add_entry(dir_entry);
                        }
                    };

                    // cross mountpoint, return mount root entry
                    dir_entry.ino = self.hash_inode(mnt.super_index, mnt.ino)?;
                    add_entry(dir_entry)
                })
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.readdir(ctx, idata.ino, handle, size, offset, |mut dir_entry| {
                dir_entry.ino = self.hash_inode(idata.super_index, dir_entry.ino)?;
                add_entry(dir_entry)
            })
        }
    }

    fn readdirplus<FF>(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        mut add_entry: FF,
    ) -> Result<()>
    where
        FF: FnMut(DirEntry, Entry) -> Result<usize>,
    {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.readdirplus(
                ctx,
                idata.ino,
                handle,
                size,
                offset,
                |mut dir_entry, mut entry| {
                    let mnt = match self
                        .mountpoints
                        .read()
                        .unwrap()
                        .get(&dir_entry.ino)
                        .map(Arc::clone)
                    {
                        Some(mnt) => mnt,
                        None => {
                            dir_entry.ino = self.hash_inode(idata.super_index, dir_entry.ino)?;
                            entry.inode = dir_entry.ino;
                            return add_entry(dir_entry, entry);
                        }
                    };

                    // cross mountpoint, return mount root entry
                    dir_entry.ino = self.hash_inode(mnt.super_index, mnt.ino)?;
                    entry = mnt.root_entry.clone();
                    add_entry(dir_entry, entry)
                },
            )
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.readdirplus(
                ctx,
                idata.ino,
                handle,
                size,
                offset,
                |mut dir_entry, mut entry| {
                    dir_entry.ino = self.hash_inode(idata.super_index, dir_entry.ino)?;
                    entry.inode = dir_entry.ino;
                    add_entry(dir_entry, entry)
                },
            )
        }
    }

    fn fsyncdir(&self, ctx: Context, inode: u64, datasync: bool, handle: u64) -> Result<()> {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.fsyncdir(ctx, idata.ino, datasync, handle)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.fsyncdir(ctx, idata.ino, datasync, handle)
        }
    }

    fn releasedir(&self, _ctx: Context, _inode: u64, _flags: u32, _handle: u64) -> Result<()> {
        Ok(())
    }

    fn access(&self, ctx: Context, inode: u64, mask: u32) -> Result<()> {
        let idata = match self.inodes.read().unwrap().get_by_left(&inode) {
            Some(data) => data.clone(),
            None => return Err(Error::from_raw_os_error(libc::ENOENT)),
        };

        if idata.is_pseudo() {
            self.root.access(ctx, idata.ino, mask)
        } else {
            let fs = self
                .superblocks
                .read()
                .unwrap()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or(Error::from_raw_os_error(libc::ENOENT))?;
            fs.access(ctx, idata.ino, mask)
        }
    }
}
