// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::io::Error;
use std::sync::{Arc, Mutex, RwLock};

use crate::fs::RafsBlk;
use crate::layout::RafsDigest;
use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;

#[derive(Clone)]
enum CacheStatus {
    Ready,
    NotReady,
}

#[derive(Clone)]
struct BlobCacheEntry {
    status: CacheStatus,
    chunk_info: RafsBlk,
    fd: libc::c_int,
}

impl BlobCacheEntry {
    fn new(chunk: &RafsBlk, fd: libc::c_int) -> BlobCacheEntry {
        BlobCacheEntry {
            status: CacheStatus::NotReady,
            chunk_info: chunk.clone(),
            fd,
        }
    }

    fn read(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.chunk_info.compr_size as usize];
        let res = unsafe {
            // we use libc::pread to support concurrent read of blob file
            libc::pread(
                self.fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                self.chunk_info.blob_offset as i64,
            )
        };
        if res < 0 {
            error!("read from blob file err! {}", Error::last_os_error());
            return Err(Error::last_os_error());
        }
        Ok(buf)
    }

    fn write(&self, src: &[u8]) -> io::Result<usize> {
        let res = unsafe {
            libc::pwrite(
                self.fd,
                src.as_ptr().cast(),
                std::cmp::min(src.len(), self.chunk_info.compr_size),
                self.chunk_info.blob_offset as i64,
            )
        };
        if res < 0 {
            error!("write to blob file err! {}", Error::last_os_error());
            return Err(Error::last_os_error());
        }
        Ok(res as usize)
    }
}

pub struct BlobCache {
    cache: RwLock<HashMap<RafsDigest, Arc<Mutex<BlobCacheEntry>>>>,
    /* we should store libc fds */
    fd_table: RwLock<HashMap<String, libc::c_int>>,
    work_dir: String,
    pub backend: Box<dyn BlobBackend + Sync + Send>,
}

impl BlobCache {
    fn get_blob_fd(&self, blk: &RafsBlk) -> libc::c_int {
        if let Some(fd) = self.fd_table.read().unwrap().get(&blk.blob_id) {
            return *fd;
        }
        let mut fd_table = self.fd_table.write().unwrap();
        let blob_file_path = CString::new(format!("{}/{}", self.work_dir, blk.blob_id))
            .expect("Invalid blob file path");
        let fd =
            unsafe { libc::open(blob_file_path.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o644) };
        if fd < 0 {
            error!("open blob file err!");
            return fd;
        }
        fd_table.insert(blk.blob_id.clone(), fd);
        fd
    }

    fn close_all_blob_fd(&self) {
        for fd in self.fd_table.write().unwrap().values() {
            let err = unsafe { libc::close(*fd) };
            if err < 0 {
                error!("close fd err {}", Error::last_os_error());
            }
        }
    }

    fn get(&self, blk: &RafsBlk) -> Option<Arc<Mutex<BlobCacheEntry>>> {
        match self.cache.read().unwrap().get(&blk.block_id) {
            Some(entry) => Some(entry.clone()),
            None => None,
        }
    }

    fn set(&self, blk: &RafsBlk) -> Option<Arc<Mutex<BlobCacheEntry>>> {
        let mut cache_map = self.cache.write().unwrap();
        if let Some(entry) = cache_map.get(&blk.block_id) {
            return Some(entry.clone());
        }
        let fd = self.get_blob_fd(blk);
        if fd < 0 {
            return None;
        }
        cache_map.insert(
            blk.block_id.clone(),
            Arc::new(Mutex::new(BlobCacheEntry::new(blk, fd))),
        );
        match cache_map.get(&blk.block_id) {
            Some(entry) => Some(entry.clone()),
            None => None,
        }
    }

    fn read_from_backend(&self, blk: &RafsBlk) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.backend
            .read(&blk.blob_id, &mut buf, blk.blob_offset, blk.compr_size)?;
        Ok(buf)
    }

    fn entry_read(&self, entry: &Arc<Mutex<BlobCacheEntry>>) -> io::Result<Vec<u8>> {
        let b_entry = {
            // need mutex lock protection
            let mut chunk_info = entry.lock().unwrap();
            if let CacheStatus::NotReady = chunk_info.status {
                // do downloading
                let buf = self.read_from_backend(&chunk_info.chunk_info)?;
                chunk_info.write(buf.as_slice())?;
                chunk_info.status = CacheStatus::Ready;
            }
            (*chunk_info).clone()
        };
        b_entry.read()
    }
}

impl RafsCache for BlobCache {
    /* whether has a block data */
    fn has(&self, blk: &RafsBlk) -> bool {
        self.cache.read().unwrap().contains_key(&blk.block_id)
    }

    /* evict block data */
    fn evict(&self, blk: &RafsBlk) -> io::Result<()> {
        self.cache.write().unwrap().remove(&blk.block_id);
        Ok(())
    }

    /* flush cache */
    fn flush(&self) -> io::Result<()> {
        Err(Error::from_raw_os_error(libc::ENOSYS))
    }

    fn read(&self, blk: &RafsBlk) -> io::Result<Vec<u8>> {
        if let Some(entry) = self.get(blk) {
            return self.entry_read(&entry);
        }
        if let Some(entry) = self.set(blk) {
            return self.entry_read(&entry);
        }
        error!("blob cache set err");
        Err(Error::from_raw_os_error(libc::EIO))
    }

    fn write(&self, _blk: &RafsBlk, _buf: &[u8]) -> io::Result<usize> {
        Err(Error::from_raw_os_error(libc::ENOSYS))
    }

    fn compressed(&self) -> bool {
        true
    }

    fn release(&mut self) {
        // close all blob file fds
        self.close_all_blob_fd();
        self.backend.close();
    }
}

pub fn new<S: std::hash::BuildHasher>(
    config: &HashMap<String, String, S>,
    backend: Box<dyn BlobBackend + Sync + Send>,
) -> io::Result<BlobCache> {
    let work_dir = match config.get("work_dir") {
        Some(dir) => dir,
        None => ".",
    };
    Ok(BlobCache {
        cache: RwLock::new(HashMap::new()),
        fd_table: RwLock::new(HashMap::new()),
        work_dir: String::from(work_dir),
        backend,
    })
}

#[cfg(test)]
mod blob_cache_tests {
    use crate::fs::RafsBlk;
    use crate::layout::RafsDigest;
    use crate::storage::backend::BlobBackend;
    use crate::storage::cache::blobcache;
    use crate::storage::cache::RafsCache;
    use std::collections::HashMap;
    use std::io::Result;

    struct MockBackend {}

    impl BlobBackend for MockBackend {
        // Read a range of data from blob into the provided slice
        fn read(
            &self,
            _blobid: &str,
            buf: &mut Vec<u8>,
            _offset: u64,
            count: usize,
        ) -> Result<usize> {
            let mut i = 0;
            while i < count {
                buf.push(i as u8);
                i += 1;
            }
            Ok(i)
        }

        // Write a range of data to blob from the provided slice
        fn write(&self, _blobid: &str, _buf: &[u8], _offset: u64) -> Result<usize> {
            Ok(0)
        }

        // Close a backend
        fn close(&mut self) {}
    }

    #[test]
    fn test_add() {
        // config
        let mut config = HashMap::new();
        config.insert(String::from("work_dir"), String::from("."));
        let blob_cache = blobcache::new(
            &config,
            Box::new(MockBackend {}) as Box<dyn BlobBackend + Send + Sync>,
        )
        .unwrap();
        let mut expect = Vec::new();
        let block_id = [1u8; 32];
        let blobid = "blobcache";
        // generate init data
        blob_cache
            .backend
            .read(blobid, expect.as_mut(), 0, 100)
            .unwrap();
        let mut chunk = RafsBlk::new();
        chunk.block_id = RafsDigest::from_buf(&block_id);
        chunk.blob_id = blobid.to_string();
        chunk.file_pos = 0;
        chunk.blob_offset = 0;
        chunk.compr_size = 100;

        let r1 = blob_cache.read(&chunk).unwrap();
        assert_eq!(expect, r1);
        let r2 = blob_cache.read(&chunk).unwrap();
        assert_eq!(expect, r2);
    }
}
