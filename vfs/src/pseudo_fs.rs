// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A pseudo fs for path walking to other real filesystems
//
// There are several assumptions adopted when designing the PseudoFs:
// - The PseudoFs is used to mount other filesystems, so it only supports directories.
// - There won't be too much directories/sub-directories managed by a PseudoFs instance, so linear
//   search is used when searching for child inodes.
// - Inodes managed by the PseudoFs is readonly, even for the permission bits.

use std::collections::HashMap;
use std::ffi::CStr;
use std::io::{Error, Result};
use std::ops::Deref;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use fuse_rs::abi::linux_abi::Attr;
use fuse_rs::api::filesystem::*;

// ID 0 is reserved for invalid entry, and ID 1 is used for ROOT_ID.
const PSEUDOFS_NEXT_INODE: u64 = 2;
const PSEUDOFS_DEFAULT_ATTR_TIMEOUT: u64 = 1 << 32;
const PSEUDOFS_DEFAULT_ENTRY_TIMEOUT: u64 = PSEUDOFS_DEFAULT_ATTR_TIMEOUT;

type Inode = u64;
type Handle = u64;

struct PseudoInode {
    ino: u64,
    parent: u64,
    children: ArcSwap<Vec<Arc<PseudoInode>>>,
    name: String,
}

impl PseudoInode {
    // It's protected by Pseudofs.lock.
    fn insert_child(&self, child: Arc<PseudoInode>) {
        let mut children = self.children.load().deref().deref().clone();

        children.push(child);

        self.children.store(Arc::new(children));
    }
}

pub struct PseudoFs {
    index: u64,
    next_inode: AtomicU64,
    root_inode: Arc<PseudoInode>,
    inodes: ArcSwap<HashMap<u64, Arc<PseudoInode>>>,
    lock: Mutex<()>, // Write protect PseudoFs.inodes and PseudoInode.children
}

impl PseudoFs {
    pub fn new(index: u64) -> Self {
        let root_inode = Arc::new(PseudoInode {
            ino: ROOT_ID,
            parent: ROOT_ID,
            children: ArcSwap::new(Arc::new(Vec::new())),
            name: String::from("/"),
        });
        let fs = PseudoFs {
            next_inode: AtomicU64::new(PSEUDOFS_NEXT_INODE),
            index,
            root_inode: root_inode.clone(),
            inodes: ArcSwap::new(Arc::new(HashMap::new())),
            lock: Mutex::new(()),
        };

        // Create the root inode. We have just created the lock, so it should be safe to unwrap().
        let _guard = fs.lock.lock().unwrap();
        fs.insert_inode(root_inode);
        drop(_guard);

        fs
    }

    // mount creates path walk nodes all the way from root
    // to @path, and returns pseudo fs inode number for the path
    pub fn mount(&self, mountpoint: &str) -> Result<u64> {
        let path = Path::new(mountpoint);
        if !path.has_root() {
            error!("pseudo fs mount failure: invalid mount path {}", mountpoint);
            return Err(Error::from_raw_os_error(libc::EINVAL));
        }

        let mut pathbuf = PathBuf::from("/");
        let mut inode = self.root_inode.clone();

        for component in path.components() {
            debug!("pseudo fs mount iterate {:?}", component.as_os_str());
            if component == Component::RootDir {
                continue;
            }
            // lookup or create component
            inode = self.do_lookup_create(&inode, component.as_os_str().to_str().unwrap());
            pathbuf.push(inode.name.clone());
        }

        // Now we have all path components exist, return the last one
        Ok(inode.ino)
    }

    fn new_inode(&self, parent: u64, name: &str) -> Arc<PseudoInode> {
        let ino = self.next_inode.fetch_add(1, Ordering::Relaxed);

        Arc::new(PseudoInode {
            ino,
            parent,
            name: String::from(name),
            children: ArcSwap::new(Arc::new(Vec::new())),
        })
    }

    // Caller must hold PseudoFs.lock.
    fn insert_inode(&self, inode: Arc<PseudoInode>) {
        let mut hashmap = self.inodes.load().deref().deref().clone();

        hashmap.insert(inode.ino, inode);

        self.inodes.store(Arc::new(hashmap));
    }

    // Caller must hold PseudoFs.lock.
    fn create_inode(&self, name: &str, parent: &Arc<PseudoInode>) -> Arc<PseudoInode> {
        let inode = self.new_inode(parent.ino, name);

        self.insert_inode(inode.clone());
        parent.insert_child(inode.clone());

        inode
    }

    fn do_lookup_create(&self, parent: &Arc<PseudoInode>, name: &str) -> Arc<PseudoInode> {
        // Optimistic check with reader lock.
        for child in parent.children.load().iter() {
            if child.name == name {
                return Arc::clone(child);
            }
        }

        // Double check with writer lock held.
        let _guard = self.lock.lock();
        for child in parent.children.load().iter() {
            if child.name == name {
                return Arc::clone(child);
            }
        }

        self.create_inode(name, parent)
    }

    fn get_entry(&self, ino: u64) -> Entry {
        let mut attr = Attr {
            ..Default::default()
        };
        attr.ino = ino;
        attr.mode = libc::S_IFDIR | libc::S_IRWXU | libc::S_IRWXG | libc::S_IRWXO;
        let now = SystemTime::now();
        attr.ctime = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        attr.mtime = attr.ctime;
        attr.atime = attr.ctime;
        attr.blksize = 4096;
        Entry {
            inode: ino,
            generation: 0,
            attr: attr.into(),
            attr_timeout: Duration::from_secs(PSEUDOFS_DEFAULT_ATTR_TIMEOUT),
            entry_timeout: Duration::from_secs(PSEUDOFS_DEFAULT_ENTRY_TIMEOUT),
        }
    }

    fn do_readdir<F>(&self, parent: u64, size: u32, offset: u64, mut add_entry: F) -> Result<()>
    where
        F: FnMut(DirEntry) -> Result<usize>,
    {
        if size == 0 {
            return Ok(());
        }

        let inodes = self.inodes.load();
        let inode = inodes
            .get(&parent)
            .ok_or_else(|| Error::from_raw_os_error(libc::ENOENT))?;
        let mut next = offset + 1;
        let children = inode.children.load();

        for child in children[offset as usize..].iter() {
            match add_entry(DirEntry {
                ino: child.ino,
                offset: next,
                type_: 0,
                name: child.name.clone().as_bytes(),
            }) {
                Ok(0) => break,
                Ok(_) => next += 1,
                Err(r) => return Err(r),
            }
        }

        Ok(())
    }
}

impl FileSystem for PseudoFs {
    type Inode = Inode;
    type Handle = Handle;

    fn lookup(&self, _: Context, parent: u64, name: &CStr) -> Result<Entry> {
        let inodes = self.inodes.load();
        let pinode = inodes
            .get(&parent)
            .ok_or_else(|| Error::from_raw_os_error(libc::ENOENT))?;
        let child_name = name
            .to_str()
            .map_err(|_| Error::from_raw_os_error(libc::EINVAL))?;
        let mut ino: u64 = 0;
        if child_name == "." {
            ino = pinode.ino;
        } else if child_name == ".." {
            ino = pinode.parent;
        } else {
            for child in pinode.children.load().iter() {
                if child.name == child_name {
                    ino = child.ino;
                    break;
                }
            }
        }

        if ino == 0 {
            // not found
            Err(Error::from_raw_os_error(libc::ENOENT))
        } else {
            Ok(self.get_entry(ino))
        }
    }

    fn getattr(&self, _: Context, inode: u64, _: Option<u64>) -> Result<(libc::stat64, Duration)> {
        let ino = self
            .inodes
            .load()
            .get(&inode)
            .map(|inode| inode.ino)
            .ok_or_else(|| Error::from_raw_os_error(libc::ENOENT))?;
        let entry = self.get_entry(ino);

        Ok((entry.attr, entry.attr_timeout))
    }

    fn readdir<F>(
        &self,
        _ctx: Context,
        inode: u64,
        _: u64,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> Result<()>
    where
        F: FnMut(DirEntry) -> Result<usize>,
    {
        self.do_readdir(inode, size, offset, add_entry)
    }

    fn readdirplus<F>(
        &self,
        _ctx: Context,
        inode: u64,
        _handle: u64,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> Result<()>
    where
        F: FnMut(DirEntry, Entry) -> Result<usize>,
    {
        self.do_readdir(inode, size, offset, |dir_entry| {
            let entry = self.get_entry(dir_entry.ino);
            add_entry(dir_entry, entry)
        })
    }

    fn access(&self, _ctx: Context, _inode: u64, _mask: u32) -> Result<()> {
        Ok(())
    }
}
