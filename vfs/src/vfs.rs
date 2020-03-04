// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A vfs for real filesystems switching

use libc;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{Error, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use bimap::hash::BiHashMap;

use fuse::filesystem::*;

use crate::pseudo_fs::PseudoFs;

const PSEUDO_FS_SUPER: u64 = 1;

type Inode = u64;
type SuperIndex = u64;

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
struct InodeData {
    super_index: SuperIndex,
    ino: Inode,
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
        Ok(())
    }

    // bimap insert_no_overwrite ensures hashed inode number uniqueness
    fn hash_inode(&self, index: u64, inode: u64) -> Result<u64> {
        let mut ino = self.next_inode.fetch_add(1, Ordering::Relaxed);
        ino = match self.inodes.write().unwrap().insert_no_overwrite(
            ino,
            InodeData {
                super_index: index,
                ino: inode,
            },
        ) {
            Ok(()) => ino,
            Err((ino, _)) => ino,
        };

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
        if pidata.super_index == PSEUDO_FS_SUPER {
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
        entry.inode = self.hash_inode(entry.inode, pidata.super_index)?;

        Ok(entry)
    }
}
