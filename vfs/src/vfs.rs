// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A vfs for real filesystems switching

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{Error, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bimap::hash::BiHashMap;
use fuse_rs::abi::linux_abi::*;
#[cfg(feature = "vhost-user-fs")]
use fuse_rs::abi::virtio_fs;
use fuse_rs::api::filesystem::*;
#[cfg(feature = "vhost-user-fs")]
use fuse_rs::transport::FsCacheReqHandler;

use crate::pseudo_fs::PseudoFs;

#[derive(Debug, Clone)]
pub enum Either<A, B> {
    /// First branch of the type
    Left(A),
    /// Second branch of the type
    Right(B),
}
use arc_swap::ArcSwap;
use std::ops::Deref;
use Either::*;

type Inode = u64;
type Handle = u64;
type SuperIndex = u64;
type BackendFilesystem = Box<dyn FileSystem<Inode = u64, Handle = u64> + Sync + Send>;

const PSEUDO_FS_SUPER: SuperIndex = 1;

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

#[derive(Debug, Copy, Clone)]
pub struct VfsOptions {
    pub no_open: bool,
    pub no_opendir: bool,
    pub no_writeback: bool,
    in_opts: FsOptions,
    out_opts: FsOptions,
}

impl Default for VfsOptions {
    fn default() -> Self {
        VfsOptions {
            no_open: true,
            no_opendir: true,
            no_writeback: false,
            in_opts: FsOptions::ASYNC_READ,
            out_opts: FsOptions::ASYNC_READ
                | FsOptions::PARALLEL_DIROPS
                | FsOptions::BIG_WRITES
                | FsOptions::HANDLE_KILLPRIV
                | FsOptions::ASYNC_DIO
                | FsOptions::HAS_IOCTL_DIR
                | FsOptions::WRITEBACK_CACHE
                | FsOptions::ZERO_MESSAGE_OPEN
                | FsOptions::ATOMIC_O_TRUNC
                | FsOptions::CACHE_SYMLINKS
                | FsOptions::DO_READDIRPLUS
                | FsOptions::READDIRPLUS_AUTO
                | FsOptions::ZERO_MESSAGE_OPENDIR,
        }
    }
}

pub struct Vfs {
    next_inode: AtomicU64,
    next_super: AtomicU64,
    root: PseudoFs,
    // inodes maintains mapping between fuse inode and (pseudo fs or mounted fs) inode data
    inodes: RwLock<BiHashMap<Inode, InodeData>>,
    // mountpoints maps from pseudo fs inode to mounted fs mountpoint data
    mountpoints: ArcSwap<HashMap<Inode, Arc<MountPointData>>>,
    // superblocks keeps track of all mounted file systems
    superblocks: ArcSwap<HashMap<SuperIndex, Arc<BackendFilesystem>>>,
    opts: ArcSwap<VfsOptions>,
    lock: Mutex<()>,
}

impl Default for Vfs {
    fn default() -> Self {
        Self::new(VfsOptions::default())
    }
}

impl Vfs {
    pub fn new(opts: VfsOptions) -> Self {
        let vfs = Vfs {
            next_inode: AtomicU64::new(ROOT_ID + 1),
            next_super: AtomicU64::new(PSEUDO_FS_SUPER + 1),
            inodes: RwLock::new(BiHashMap::new()),
            mountpoints: ArcSwap::new(Arc::new(HashMap::new())),
            superblocks: ArcSwap::new(Arc::new(HashMap::new())),
            root: PseudoFs::new(PSEUDO_FS_SUPER),
            opts: ArcSwap::new(Arc::new(opts)),
            lock: Mutex::new(()),
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

    pub fn mount(&self, fs: BackendFilesystem, path: &str) -> Result<()> {
        let entry = fs.lookup(
            Context {
                uid: 0,
                gid: 0,
                pid: 0,
            },
            ROOT_ID,
            &CString::new(".").unwrap(),
        )?;

        // Serialize mount operations. Do not expect poisoned lock here.
        let _guard = self.lock.lock().unwrap();
        let inode = self.root.mount(path)?;
        let index = self.next_super.fetch_add(1, Ordering::Relaxed);

        // TODO: handle over mount on the same mountpoint
        // #################################################
        // TODO: confirm the visibility of mountpoints and superblocks, which one should be committed
        // first?
        // #################################################
        let mut mountpoints = self.mountpoints.load().deref().deref().clone();
        mountpoints.insert(
            inode,
            Arc::new(MountPointData {
                super_index: index,
                ino: ROOT_ID,
                root_entry: entry,
            }),
        );
        self.mountpoints.store(Arc::new(mountpoints));

        let mut superblocks = self.superblocks.load().deref().deref().clone();
        superblocks.insert(index, Arc::new(fs));
        self.superblocks.store(Arc::new(superblocks));

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
    fn hash_inode(&self, index: u64, inode: u64) -> u64 {
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
                ino = *inodes
                    .get_by_right(&InodeData {
                        super_index: index,
                        ino: inode,
                    })
                    .unwrap();
                ino
            }
        };

        trace!(
            "vfs hash inode index {} ino {} fuse ino {}",
            index,
            inode,
            ino
        );
        ino
    }

    fn get_real_rootfs(
        &self,
        inode: u64,
    ) -> Result<(Either<&PseudoFs, Arc<BackendFilesystem>>, InodeData)> {
        let idata = self
            .inodes
            .read()
            .unwrap()
            .get_by_left(&inode)
            .copied()
            .ok_or_else(|| Error::from_raw_os_error(libc::ENOENT))?;

        if idata.is_pseudo() {
            Ok((Left(&self.root), idata))
        } else {
            let fs = self
                .superblocks
                .load()
                .get(&idata.super_index)
                .map(Arc::clone)
                .ok_or_else(|| Error::from_raw_os_error(libc::ENOENT))?;
            Ok((Right(fs), idata))
        }
    }
}

impl FileSystem for Vfs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, opts: FsOptions) -> Result<FsOptions> {
        let mut n_opts = *self.opts.load().deref().deref();
        if n_opts.no_open {
            n_opts.no_open = !(opts & FsOptions::ZERO_MESSAGE_OPEN).is_empty();
        }
        n_opts.no_opendir = !(opts & FsOptions::ZERO_MESSAGE_OPENDIR).is_empty();
        if n_opts.no_writeback {
            n_opts.out_opts.remove(FsOptions::WRITEBACK_CACHE);
        }
        n_opts.in_opts = opts;

        let out_opts = n_opts.out_opts;
        self.opts.store(Arc::new(n_opts));

        Ok(out_opts)
    }

    fn destroy(&self) {
        let inodes: Vec<u64> = self
            .inodes
            .read()
            .unwrap()
            .iter()
            .filter(|(_, &idata)| idata.super_index != PSEUDO_FS_SUPER && idata.ino != ROOT_ID)
            .map(|(&a, _)| a)
            .collect();
        let mut vfsinodes = self.inodes.write().unwrap();
        for inode in inodes.iter() {
            vfsinodes.remove_by_left(inode);
        }
        self.superblocks
            .load()
            .iter()
            .for_each(|(_, f)| f.destroy());
    }

    fn lookup(&self, ctx: Context, parent: Inode, name: &CStr) -> Result<Entry> {
        match self.get_real_rootfs(parent)? {
            (Left(fs), idata) => {
                let mut entry = fs.lookup(ctx, idata.ino, name)?;
                match self.mountpoints.load().get(&entry.inode) {
                    Some(mnt) => {
                        // cross mountpoint, return mount root entry
                        entry = mnt.root_entry;
                        entry.inode = self.hash_inode(mnt.super_index, mnt.ino);
                        trace!(
                            "vfs lookup cross mountpoint, return new mount index {} inode {} fuse inode {}",
                            mnt.super_index,
                            mnt.ino,
                            entry.inode
                        );
                    }
                    None => entry.inode = self.hash_inode(idata.super_index, entry.inode),
                }
                Ok(entry)
            }
            (Right(fs), idata) => {
                // parent is in an underlying rootfs
                let mut entry = fs.lookup(ctx, idata.ino, name)?;
                // lookup success, hash it to a real fuse inode
                entry.inode = self.hash_inode(idata.super_index, entry.inode);
                Ok(entry)
            }
        }
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Option<Handle>,
    ) -> Result<(libc::stat64, Duration)> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.getattr(ctx, idata.ino, handle),
            (Right(fs), idata) => fs.getattr(ctx, idata.ino, handle.map(|h| h)),
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
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.setattr(ctx, idata.ino, attr, handle, valid),
            (Right(fs), idata) => fs.setattr(ctx, idata.ino, attr, handle.map(|h| h), valid),
        }
    }

    fn readlink(&self, ctx: Context, inode: u64) -> Result<Vec<u8>> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.readlink(ctx, idata.ino),
            (Right(fs), idata) => fs.readlink(ctx, idata.ino),
        }
    }

    fn symlink(&self, ctx: Context, linkname: &CStr, parent: u64, name: &CStr) -> Result<Entry> {
        match self.get_real_rootfs(parent)? {
            (Left(fs), idata) => fs.symlink(ctx, linkname, idata.ino, name),
            (Right(fs), idata) => fs.symlink(ctx, linkname, idata.ino, name).map(|mut e| {
                e.inode = self.hash_inode(idata.super_index, e.inode);
                e
            }),
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
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.mknod(ctx, idata.ino, name, mode, rdev, umask),
            (Right(fs), idata) => fs
                .mknod(ctx, idata.ino, name, mode, rdev, umask)
                .map(|mut e| {
                    e.inode = self.hash_inode(idata.super_index, e.inode);
                    e
                }),
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
        match self.get_real_rootfs(parent)? {
            (Left(fs), idata) => fs.mkdir(ctx, idata.ino, name, mode, umask),
            (Right(fs), idata) => fs.mkdir(ctx, idata.ino, name, mode, umask).map(|mut e| {
                e.inode = self.hash_inode(idata.super_index, e.inode);
                e
            }),
        }
    }

    fn unlink(&self, ctx: Context, parent: u64, name: &CStr) -> Result<()> {
        match self.get_real_rootfs(parent)? {
            (Left(fs), idata) => fs.unlink(ctx, idata.ino, name),
            (Right(fs), idata) => fs.unlink(ctx, idata.ino, name),
        }
    }

    fn rmdir(&self, ctx: Context, parent: u64, name: &CStr) -> Result<()> {
        match self.get_real_rootfs(parent)? {
            (Left(fs), idata) => fs.rmdir(ctx, idata.ino, name),
            (Right(fs), idata) => fs.rmdir(ctx, idata.ino, name),
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
        let (root, idata_old) = self.get_real_rootfs(olddir)?;
        let (_, idata_new) = self.get_real_rootfs(newdir)?;

        if idata_old.super_index != idata_new.super_index {
            return Err(Error::from_raw_os_error(libc::EINVAL));
        }

        match root {
            Left(fs) => fs.rename(ctx, idata_old.ino, oldname, idata_new.ino, newname, flags),
            Right(fs) => fs.rename(ctx, idata_old.ino, oldname, idata_new.ino, newname, flags),
        }
    }

    fn link(&self, ctx: Context, inode: u64, newparent: u64, newname: &CStr) -> Result<Entry> {
        let (root, idata_old) = self.get_real_rootfs(inode)?;
        let (_, idata_new) = self.get_real_rootfs(newparent)?;

        if idata_old.super_index != idata_new.super_index {
            return Err(Error::from_raw_os_error(libc::EINVAL));
        }

        match root {
            Left(fs) => fs.link(ctx, idata_old.ino, idata_new.ino, newname),
            Right(fs) => fs
                .link(ctx, idata_old.ino, idata_new.ino, newname)
                .map(|mut e| {
                    e.inode = self.hash_inode(idata_new.super_index, e.inode);
                    e
                }),
        }
    }

    fn open(&self, ctx: Context, inode: u64, flags: u32) -> Result<(Option<u64>, OpenOptions)> {
        if self.opts.load().no_open {
            Err(Error::from_raw_os_error(libc::ENOSYS))
        } else {
            match self.get_real_rootfs(inode)? {
                (Left(fs), idata) => fs.open(ctx, idata.ino, flags),
                (Right(fs), idata) => fs
                    .open(ctx, idata.ino, flags)
                    .map(|(h, opt)| (h.map(Into::into), opt)),
            }
        }
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
        match self.get_real_rootfs(parent)? {
            (Left(fs), idata) => fs.create(ctx, idata.ino, name, mode, flags, umask),
            (Right(fs), idata) => {
                fs.create(ctx, idata.ino, name, mode, flags, umask)
                    .map(|(mut a, b, c)| {
                        a.inode = self.hash_inode(idata.super_index, a.inode);
                        (a, b.map(|h| h), c)
                    })
            }
        }
    }

    fn read(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> Result<usize> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => {
                fs.read(ctx, idata.ino, handle, w, size, offset, lock_owner, flags)
            }
            (Right(fs), idata) => {
                fs.read(ctx, idata.ino, handle, w, size, offset, lock_owner, flags)
            }
        }
    }

    fn write(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        r: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        flags: u32,
    ) -> Result<usize> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.write(
                ctx,
                idata.ino,
                handle,
                r,
                size,
                offset,
                lock_owner,
                delayed_write,
                flags,
            ),
            (Right(fs), idata) => fs.write(
                ctx,
                idata.ino,
                handle,
                r,
                size,
                offset,
                lock_owner,
                delayed_write,
                flags,
            ),
        }
    }

    fn flush(&self, ctx: Context, inode: u64, handle: u64, lock_owner: u64) -> Result<()> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.flush(ctx, idata.ino, handle, lock_owner),
            (Right(fs), idata) => fs.flush(ctx, idata.ino, handle, lock_owner),
        }
    }

    fn fsync(&self, ctx: Context, inode: u64, datasync: bool, handle: u64) -> Result<()> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.fsync(ctx, idata.ino, datasync, handle),
            (Right(fs), idata) => fs.fsync(ctx, idata.ino, datasync, handle),
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
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.fallocate(ctx, idata.ino, handle, mode, offset, length),
            (Right(fs), idata) => fs.fallocate(ctx, idata.ino, handle, mode, offset, length),
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
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.release(
                ctx,
                idata.ino,
                flags,
                handle,
                flush,
                flock_release,
                lock_owner,
            ),
            (Right(fs), idata) => fs.release(
                ctx,
                idata.ino,
                flags,
                handle,
                flush,
                flock_release,
                lock_owner,
            ),
        }
    }

    fn statfs(&self, ctx: Context, inode: u64) -> Result<libc::statvfs64> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.statfs(ctx, idata.ino),
            (Right(fs), idata) => fs.statfs(ctx, idata.ino),
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
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.setxattr(ctx, idata.ino, name, value, flags),
            (Right(fs), idata) => fs.setxattr(ctx, idata.ino, name, value, flags),
        }
    }

    fn getxattr(&self, ctx: Context, inode: u64, name: &CStr, size: u32) -> Result<GetxattrReply> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.getxattr(ctx, idata.ino, name, size),
            (Right(fs), idata) => fs.getxattr(ctx, idata.ino, name, size),
        }
    }

    fn listxattr(&self, ctx: Context, inode: u64, size: u32) -> Result<ListxattrReply> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.listxattr(ctx, idata.ino, size),
            (Right(fs), idata) => fs.listxattr(ctx, idata.ino, size),
        }
    }

    fn removexattr(&self, ctx: Context, inode: u64, name: &CStr) -> Result<()> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.removexattr(ctx, idata.ino, name),
            (Right(fs), idata) => fs.removexattr(ctx, idata.ino, name),
        }
    }

    fn opendir(
        &self,
        ctx: Context,
        inode: u64,
        flags: u32,
    ) -> Result<(Option<Handle>, OpenOptions)> {
        if self.opts.load().no_opendir {
            Err(Error::from_raw_os_error(libc::ENOSYS))
        } else {
            match self.get_real_rootfs(inode)? {
                (Left(fs), idata) => fs.opendir(ctx, idata.ino, flags),
                (Right(fs), idata) => fs
                    .opendir(ctx, idata.ino, flags)
                    .map(|(h, opt)| (h.map(Into::into), opt)),
            }
        }
    }

    fn readdir(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry) -> Result<usize>,
    ) -> Result<()> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => {
                fs.readdir(
                    ctx,
                    idata.ino,
                    handle,
                    size,
                    offset,
                    &mut |mut dir_entry| {
                        match self.mountpoints.load().get(&dir_entry.ino) {
                            // cross mountpoint, return mount root entry
                            Some(mnt) => {
                                dir_entry.ino = self.hash_inode(mnt.super_index, mnt.ino);
                            }
                            None => {
                                dir_entry.ino = self.hash_inode(idata.super_index, dir_entry.ino);
                            }
                        }
                        add_entry(dir_entry)
                    },
                )
            }

            (Right(fs), idata) => fs.readdir(
                ctx,
                idata.ino,
                handle,
                size,
                offset,
                &mut |mut dir_entry| {
                    dir_entry.ino = self.hash_inode(idata.super_index, dir_entry.ino);
                    add_entry(dir_entry)
                },
            ),
        }
    }

    fn readdirplus(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry, Entry) -> Result<usize>,
    ) -> Result<()> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.readdirplus(
                ctx,
                idata.ino,
                handle,
                size,
                offset,
                &mut |mut dir_entry, mut entry| {
                    match self.mountpoints.load().get(&dir_entry.ino) {
                        Some(mnt) => {
                            // cross mountpoint, return mount root entry
                            dir_entry.ino = self.hash_inode(mnt.super_index, mnt.ino);
                            entry = mnt.root_entry;
                        }
                        None => {
                            dir_entry.ino = self.hash_inode(idata.super_index, dir_entry.ino);
                            entry.inode = dir_entry.ino;
                        }
                    }

                    add_entry(dir_entry, entry)
                },
            ),

            (Right(fs), idata) => fs.readdirplus(
                ctx,
                idata.ino,
                handle,
                size,
                offset,
                &mut |mut dir_entry, mut entry| {
                    dir_entry.ino = self.hash_inode(idata.super_index, dir_entry.ino);
                    entry.inode = dir_entry.ino;
                    add_entry(dir_entry, entry)
                },
            ),
        }
    }

    fn fsyncdir(&self, ctx: Context, inode: u64, datasync: bool, handle: u64) -> Result<()> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.fsyncdir(ctx, idata.ino, datasync, handle),
            (Right(fs), idata) => fs.fsyncdir(ctx, idata.ino, datasync, handle),
        }
    }

    fn releasedir(&self, ctx: Context, inode: u64, flags: u32, handle: u64) -> Result<()> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.releasedir(ctx, idata.ino, flags, handle),
            (Right(fs), idata) => fs.releasedir(ctx, idata.ino, flags, handle),
        }
    }

    fn access(&self, ctx: Context, inode: u64, mask: u32) -> Result<()> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.access(ctx, idata.ino, mask),
            (Right(fs), idata) => fs.access(ctx, idata.ino, mask),
        }
    }

    #[cfg(feature = "vhost-user-fs")]
    fn setupmapping(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        vu_req: &mut dyn FsCacheReqHandler,
    ) -> Result<()> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => {
                fs.setupmapping(ctx, idata.ino, handle, foffset, len, flags, moffset, vu_req)
            }
            (Right(fs), idata) => {
                fs.setupmapping(ctx, idata.ino, handle, foffset, len, flags, moffset, vu_req)
            }
        }
    }

    #[cfg(feature = "vhost-user-fs")]
    fn removemapping(
        &self,
        ctx: Context,
        inode: Inode,
        requests: Vec<virtio_fs::RemovemappingOne>,
        vu_req: &mut dyn FsCacheReqHandler,
    ) -> Result<()> {
        match self.get_real_rootfs(inode)? {
            (Left(fs), idata) => fs.removemapping(ctx, idata.ino, requests, vu_req),
            (Right(fs), idata) => fs.removemapping(ctx, idata.ino, requests, vu_req),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeFs {}
    impl FileSystem for FakeFs {
        type Inode = Inode;
        type Handle = Handle;
    }
    struct FakeFileSystemOne {}
    impl FileSystem for FakeFileSystemOne {
        type Inode = u64;
        type Handle = u64;
        fn lookup(&self, _: Context, _: Inode, _: &CStr) -> Result<Entry> {
            Ok(Entry {
                inode: 1,
                generation: 0,
                attr: Attr::default().into(),
                attr_timeout: Duration::new(0, 0),
                entry_timeout: Duration::new(0, 0),
            })
        }
    }
    struct FakeFileSystemTwo {}
    impl FileSystem for FakeFileSystemTwo {
        type Inode = u64;
        type Handle = u64;
        fn lookup(&self, _: Context, _: Inode, _: &CStr) -> Result<Entry> {
            Ok(Entry {
                inode: 1,
                generation: 0,
                attr: Attr::default().into(),
                attr_timeout: Duration::new(0, 0),
                entry_timeout: Duration::new(0, 0),
            })
        }
    }

    #[test]
    fn test_vfs_init() {
        let vfs = Vfs::default();

        let out_opts = FsOptions::ASYNC_READ
            | FsOptions::PARALLEL_DIROPS
            | FsOptions::BIG_WRITES
            | FsOptions::HANDLE_KILLPRIV
            | FsOptions::ASYNC_DIO
            | FsOptions::HAS_IOCTL_DIR
            | FsOptions::WRITEBACK_CACHE
            | FsOptions::ZERO_MESSAGE_OPEN
            | FsOptions::ATOMIC_O_TRUNC
            | FsOptions::CACHE_SYMLINKS
            | FsOptions::DO_READDIRPLUS
            | FsOptions::READDIRPLUS_AUTO
            | FsOptions::ZERO_MESSAGE_OPENDIR;
        let opts = vfs.opts.load();

        assert_eq!(opts.no_open, true);
        assert_eq!(opts.no_opendir, true);
        assert_eq!(opts.no_writeback, false);
        assert_eq!(opts.in_opts, FsOptions::ASYNC_READ);
        assert_eq!(opts.out_opts, out_opts);

        vfs.init(FsOptions::ASYNC_READ).unwrap();
        let opts = vfs.opts.load();
        assert_eq!(opts.no_open, false);
        assert_eq!(opts.no_opendir, false);
        assert_eq!(opts.no_writeback, false);
    }

    #[test]
    fn test_vfs_lookup() {
        // TODO
    }

    #[test]
    fn test_vfs_readdir() {
        // TODO
    }

    #[test]
    fn test_mount_different_fs_types() {
        let vfs = Vfs::new(VfsOptions::default());
        let fs1 = FakeFileSystemOne {};
        let fs2 = FakeFileSystemTwo {};
        assert!(vfs.mount(Box::new(fs1), "/foo").is_ok());
        assert!(vfs.mount(Box::new(fs2), "/bar").is_ok());
    }
}
