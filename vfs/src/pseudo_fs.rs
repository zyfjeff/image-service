// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A pseudo fs for path walking to other real filesystems

use std::collections::HashMap;
use std::ffi::CStr;
use std::io::{Error, Result};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use fuse_rs::abi::linux_abi::Attr;
use fuse_rs::api::filesystem::*;

const PSEUDOFS_NEXT_INODE: u64 = 2;
const PSEUDOFS_DEFAULT_ATTR_TIMEOUT: u64 = 1 << 32;
const PSEUDOFS_DEFAULT_ENTRY_TIMEOUT: u64 = PSEUDOFS_DEFAULT_ATTR_TIMEOUT;

type Inode = u64;
type Handle = u64;

struct PseudoInode {
    ino: u64,
    parent: u64,
    name: String,
    children: RwLock<Vec<Arc<PseudoInode>>>,
}

pub struct PseudoFs {
    index: u64,
    next_inode: AtomicU64,
    inodes: RwLock<HashMap<u64, Arc<PseudoInode>>>,
}

impl PseudoFs {
    pub fn new(index: u64) -> Self {
        let fs = PseudoFs {
            next_inode: AtomicU64::new(PSEUDOFS_NEXT_INODE),
            index,
            inodes: RwLock::new(HashMap::new()),
        };
        fs.inodes.write().unwrap().insert(
            ROOT_ID,
            Arc::new(PseudoInode {
                ino: ROOT_ID,
                parent: ROOT_ID,
                name: String::from("/"),
                children: RwLock::new(Vec::new()),
            }),
        );
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
        let mut inode = self
            .inodes
            .read()
            .unwrap()
            .get(&ROOT_ID)
            .map(Arc::clone)
            .unwrap();

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
        let inode = Arc::new(PseudoInode {
            ino,
            parent,
            name: String::from(name),
            children: RwLock::new(Vec::new()),
        });
        self.inodes.write().unwrap().insert(ino, inode.clone());

        inode
    }

    fn do_lookup_create(&self, parent: &Arc<PseudoInode>, name: &str) -> Arc<PseudoInode> {
        // Optimistic check with reader lock.
        for child in parent.children.read().unwrap().iter() {
            if child.name == name {
                return Arc::clone(child);
            }
        }

        // Double check with writer lock.
        let mut children = parent.children.write().unwrap();
        for child in children.iter() {
            if child.name == name {
                return Arc::clone(child);
            }
        }

        // not found, create new
        let inode = self.new_inode(parent.ino, name);
        children.push(inode.clone());

        inode
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

        let inode = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .map(Arc::clone)
            .ok_or_else(|| Error::from_raw_os_error(libc::ENOENT))?;

        let mut next = offset + 1;
        let children = inode.children.read().unwrap();

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
        let pinode = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .map(Arc::clone)
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
            for child in pinode.children.read().unwrap().iter() {
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
        let info = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(|| Error::from_raw_os_error(libc::ENOENT))?;

        let entry = self.get_entry(info.ino);
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
