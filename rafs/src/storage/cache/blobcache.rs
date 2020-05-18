// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use nix::sys::uio;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::Error;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex, RwLock};

use crate::fs::RafsBlk;
use crate::layout::{RafsDigest, RafsSuperBlockInfo};
use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;
use crate::storage::device::RafsBuffer;

#[derive(Clone)]
enum CacheStatus {
    Ready,
    NotReady,
}

#[derive(Clone)]
struct BlobCacheEntry {
    status: CacheStatus,
    chunk_info: RafsBlk,
    fd: RawFd,
}

impl BlobCacheEntry {
    fn new(chunk: &RafsBlk, fd: RawFd) -> BlobCacheEntry {
        BlobCacheEntry {
            status: CacheStatus::NotReady,
            chunk_info: chunk.clone(),
            fd,
        }
    }

    fn read(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.chunk_info.compr_size as usize];
        let nr_read = uio::pread(
            self.fd,
            buf.as_mut_slice(),
            self.chunk_info.blob_offset as i64,
        )
        .map_err(|_| Error::last_os_error())?;
        debug!(
            "read {}(off={}) bytes from blob file",
            nr_read, self.chunk_info.blob_offset
        );
        Ok(buf)
    }

    fn write(&self, src: &[u8]) -> io::Result<usize> {
        let nr_write = uio::pwrite(self.fd, src, self.chunk_info.blob_offset as i64)
            .map_err(|_| Error::last_os_error())?;
        debug!(
            "write {}(off={}) bytes to blob file",
            nr_write, self.chunk_info.blob_offset
        );
        Ok(nr_write)
    }
}

pub struct BlobCache {
    cache: RwLock<HashMap<RafsDigest, Arc<Mutex<BlobCacheEntry>>>>,
    file_table: RwLock<HashMap<String, File>>,
    work_dir: String,
    blksize: u32,
    pub backend: Box<dyn BlobBackend + Sync + Send>,
}

impl BlobCache {
    fn get_blob_fd(&self, blk: &RafsBlk) -> io::Result<RawFd> {
        if let Some(file) = self.file_table.read().unwrap().get(&blk.blob_id) {
            return Ok(file.as_raw_fd());
        }
        let mut file_table = self.file_table.write().unwrap();
        let blob_file_path = format!("{}/{}", self.work_dir, blk.blob_id);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(blob_file_path)?;
        let fd = file.as_raw_fd();
        file_table.insert(blk.blob_id.clone(), file);
        Ok(fd)
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
        let fd = self.get_blob_fd(blk).unwrap();
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
        let res = self
            .backend
            .read(&blk.blob_id, &mut buf, blk.blob_offset, blk.compr_size)?;
        if res != blk.compr_size {
            error!("read from backend err!");
            return Err(Error::from_raw_os_error(libc::EIO));
        }
        Ok(buf)
    }

    fn entry_read(&self, entry: &Arc<Mutex<BlobCacheEntry>>) -> io::Result<RafsBuffer> {
        let b_entry = {
            // need mutex lock protection
            let mut chunk_info = entry.lock().unwrap();
            if let CacheStatus::NotReady = chunk_info.status {
                // check on local disk
                if let Some(buf) = chunk_info
                    .read()
                    .map_or(None, |b| utils::decompress(b.as_slice(), self.blksize).ok())
                {
                    if chunk_info.chunk_info.block_id == RafsDigest::from_buf(buf.as_slice()) {
                        chunk_info.status = CacheStatus::Ready;
                        return Ok(RafsBuffer::new_decompressed(buf));
                    }
                }
                // do downloading
                let buf = self.read_from_backend(&chunk_info.chunk_info)?;
                chunk_info.write(buf.as_slice())?;
                chunk_info.status = CacheStatus::Ready;
                return Ok(RafsBuffer::new_compressed(buf));
            }
            (*chunk_info).clone()
        };
        Ok(RafsBuffer::new_compressed(b_entry.read()?))
    }
}

impl RafsCache for BlobCache {
    /* whether has a block data */
    fn has(&self, blk: &RafsBlk) -> bool {
        self.cache.read().unwrap().contains_key(&blk.block_id)
    }

    fn init(&mut self, sb_info: &RafsSuperBlockInfo) -> io::Result<()> {
        self.blksize = sb_info.s_block_size;
        Ok(())
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

    fn read(&self, blk: &RafsBlk) -> io::Result<RafsBuffer> {
        if let Some(entry) = self.get(blk).or_else(|| self.set(blk)) {
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
        self.backend.close();
    }
}

pub fn new<S: std::hash::BuildHasher>(
    config: &HashMap<String, String, S>,
    backend: Box<dyn BlobBackend + Sync + Send>,
) -> io::Result<BlobCache> {
    let work_dir = config
        .get("work_dir")
        .map_or(Ok("."), |p| -> io::Result<&str> {
            if fs::metadata(p)?.is_dir() {
                Ok(p.as_str())
            } else {
                Err(Error::from_raw_os_error(libc::ENOTDIR))
            }
        })?;
    Ok(BlobCache {
        cache: RwLock::new(HashMap::new()),
        file_table: RwLock::new(HashMap::new()),
        work_dir: String::from(work_dir),
        backend,
        blksize: (1024u32 * 1024u32),
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
        config.insert(String::from("work_dir"), String::from("/tmp"));
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
