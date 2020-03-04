// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A pseudo fs for path walking to other real filesystems

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{Error, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use fuse::filesystem::*;
use fuse::protocol::Attr;

const PSEUDOFS_NEXT_INODE: u64 = 2;
const PSEUDOFS_DEFAULT_ATTR_TIMEOUT: u64 = 1 << 32;
const PSEUDOFS_DEFAULT_ENTRY_TIMEOUT: u64 = PSEUDOFS_DEFAULT_ATTR_TIMEOUT;

struct PseudoInode {
    ino: u64,
    super_index: u64,
    name: String,
    childs: RwLock<Vec<u64>>,
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
            index: index,
            inodes: RwLock::new(HashMap::new()),
        };
        fs.inodes.write().unwrap().insert(
            ROOT_ID,
            Arc::new(PseudoInode {
                ino: ROOT_ID,
                super_index: index,
                name: String::from("/"),
                childs: RwLock::new(Vec::new()),
            }),
        );
        fs
    }

    // mount creates path walk nodes all the way from root
    // to @path, and returns pseudo fs inode number for the path
    pub fn mount(&self, path: &str) -> Result<u64> {
        // alloc parent path all the way
        // self.make_parent_dir(path);
        // lock, check and add the target path
        let inode: u64;
        if path == "/" {
            inode = ROOT_ID;
        } else {
            inode = self.next_inode.fetch_add(1, Ordering::Relaxed);
        }
        // make node
        Ok(inode)
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
}

impl FileSystem for PseudoFs {
    fn lookup(&self, _: Context, parent: u64, name: &CStr) -> Result<Entry> {
        if parent != ROOT_ID || !name.eq(&CString::new(".").unwrap()) {
            Err(Error::from_raw_os_error(libc::ENOSYS))
        } else {
            Ok(self.get_entry(ROOT_ID))
        }
    }
}
