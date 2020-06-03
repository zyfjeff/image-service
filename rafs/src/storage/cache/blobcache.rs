// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use nix::sys::uio;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::{Error, ErrorKind};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex, RwLock};

use crate::metadata::layout::OndiskDigest;
use crate::metadata::{RafsChunkInfo, RafsDigest, RafsSuperMeta};
use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;
use crate::storage::device::RafsBuffer;

#[derive(Clone)]
enum CacheStatus {
    Ready,
    NotReady,
}

struct BlobCacheEntry {
    status: CacheStatus,
    chunk: Arc<dyn RafsChunkInfo>,
    fd: RawFd,
}

impl BlobCacheEntry {
    fn new(chunk: Arc<dyn RafsChunkInfo>, fd: RawFd) -> BlobCacheEntry {
        BlobCacheEntry {
            status: CacheStatus::NotReady,
            chunk,
            fd,
        }
    }

    fn read(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.chunk.compress_size() as usize];
        let nr_read = uio::pread(self.fd, buf.as_mut_slice(), self.chunk.blob_offset() as i64)
            .map_err(|_| Error::last_os_error())?;
        debug!(
            "read {}(off={}) bytes from blob file",
            nr_read,
            self.chunk.blob_offset()
        );
        Ok(buf)
    }

    fn write(&self, src: &[u8]) -> io::Result<usize> {
        let nr_write = uio::pwrite(self.fd, src, self.chunk.blob_offset() as i64)
            .map_err(|_| Error::last_os_error())?;
        debug!(
            "write {}(off={}) bytes to blob file",
            nr_write,
            self.chunk.blob_offset()
        );
        Ok(nr_write)
    }
}

pub struct BlobCache {
    cache: RwLock<HashMap<String, Arc<Mutex<BlobCacheEntry>>>>,
    file_table: RwLock<HashMap<String, File>>,
    work_dir: String,
    blksize: u32,
    pub backend: Box<dyn BlobBackend + Sync + Send>,
}

impl BlobCache {
    fn get_blob_fd(&self, blob_id: &str) -> io::Result<RawFd> {
        if let Some(file) = self.file_table.read().unwrap().get(&blob_id.to_string()) {
            return Ok(file.as_raw_fd());
        }
        let mut file_table = self.file_table.write().unwrap();
        let blob_file_path = format!("{}/{}", self.work_dir, blob_id);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(blob_file_path)?;
        let fd = file.as_raw_fd();
        file_table.insert(blob_id.to_string(), file);
        Ok(fd)
    }

    fn get(&self, blk: Arc<dyn RafsChunkInfo>) -> Option<Arc<Mutex<BlobCacheEntry>>> {
        let block_id = blk.block_id().to_string();
        match self.cache.read().unwrap().get(&block_id) {
            Some(entry) => Some(entry.clone()),
            None => None,
        }
    }

    fn set(
        &self,
        blob_id: &str,
        blk: Arc<dyn RafsChunkInfo>,
    ) -> Option<Arc<Mutex<BlobCacheEntry>>> {
        let mut cache_map = self.cache.write().unwrap();
        if let Some(entry) = cache_map.get(&blob_id.to_string()) {
            return Some(entry.clone());
        }
        let fd = self.get_blob_fd(blob_id).unwrap();
        cache_map.insert(
            blob_id.to_string(),
            Arc::new(Mutex::new(BlobCacheEntry::new(blk, fd))),
        );
        match cache_map.get(&blob_id.to_string()) {
            Some(entry) => Some(entry.clone()),
            None => None,
        }
    }

    fn read_from_backend(
        &self,
        blob_id: &str,
        blk: &Arc<dyn RafsChunkInfo>,
    ) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let res = self.backend.read(
            blob_id,
            &mut buf,
            blk.blob_offset(),
            blk.compress_size() as usize,
        )?;
        if res != blk.compress_size() as usize {
            error!("read from backend err!");
            return Err(Error::from_raw_os_error(libc::EIO));
        }
        Ok(buf)
    }

    fn entry_read(
        &self,
        blob_id: &str,
        entry: &Arc<Mutex<BlobCacheEntry>>,
    ) -> io::Result<RafsBuffer> {
        let b_entry = {
            // need mutex lock protection
            let mut cache_entry = entry.lock().unwrap();
            if let CacheStatus::NotReady = cache_entry.status {
                // check on local disk
                if let Some(buf) = cache_entry
                    .read()
                    .map_or(None, |b| utils::decompress(b.as_slice(), self.blksize).ok())
                {
                    let block_id = cache_entry.chunk.block_id().to_string();
                    if block_id == OndiskDigest::from_buf(buf.as_slice()).to_string() {
                        cache_entry.status = CacheStatus::Ready;
                        return Ok(RafsBuffer::new_decompressed(buf));
                    }
                }
                // do downloading
                let buf = self.read_from_backend(blob_id, &cache_entry.chunk)?;
                cache_entry.write(buf.as_slice())?;
                cache_entry.status = CacheStatus::Ready;
                return Ok(RafsBuffer::new_compressed(buf));
            }
            cache_entry
        };
        Ok(RafsBuffer::new_compressed(b_entry.read()?))
    }
}

impl RafsCache for BlobCache {
    /* whether has a block data */
    fn has(&self, blk: Arc<dyn RafsChunkInfo>) -> bool {
        let block_id = blk.block_id().to_string();
        self.cache.read().unwrap().contains_key(&block_id)
    }

    fn init(&mut self, sb_meta: &RafsSuperMeta) -> io::Result<()> {
        self.blksize = sb_meta.block_size;
        Ok(())
    }

    /* evict block data */
    fn evict(&self, blk: Arc<dyn RafsChunkInfo>) -> io::Result<()> {
        let block_id = blk.block_id().to_string();
        self.cache.write().unwrap().remove(&block_id);
        Ok(())
    }

    /* flush cache */
    fn flush(&self) -> io::Result<()> {
        Err(Error::from_raw_os_error(libc::ENOSYS))
    }

    fn read(&self, blob_id: &str, blk: Arc<dyn RafsChunkInfo>) -> io::Result<RafsBuffer> {
        if let Some(entry) = self.get(blk.clone()).or_else(|| self.set(blob_id, blk)) {
            return self.entry_read(blob_id, &entry);
        }
        error!("blob cache set err");
        Err(Error::from_raw_os_error(libc::EIO))
    }

    fn write(
        &self,
        _blob_id: &str,
        _blk: Arc<dyn RafsChunkInfo>,
        _buf: &[u8],
    ) -> io::Result<usize> {
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
            let path = fs::metadata(p).map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!("fail to stat blobcache work_dir {}: {}", p, e),
                )
            })?;
            if path.is_dir() {
                Ok(p.as_str())
            } else {
                Err(Error::new(
                    ErrorKind::NotFound,
                    format!("blobcache work_dir {} is not a directory", p),
                ))
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
    use std::collections::HashMap;
    use std::io::Result;
    use std::sync::Arc;

    use crate::metadata::layout::{OndiskChunkInfo, OndiskDigest};
    use crate::storage::backend::BlobBackend;
    use crate::storage::cache::blobcache;
    use crate::storage::cache::RafsCache;

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

        let mut chunk = OndiskChunkInfo::new();
        chunk.block_id = OndiskDigest::from_raw(&block_id);
        chunk.file_offset = 0;
        chunk.blob_offset = 0;
        chunk.compress_size = 100;

        let r1 = blob_cache
            .read(blobid, Arc::new(chunk))
            .expect("read err")
            .decompressed(&|b| Ok(b.to_vec()))
            .unwrap();
        assert_eq!(expect, r1);
        let r2 = blob_cache
            .read(blobid, Arc::new(chunk))
            .expect("read err")
            .decompressed(&|b| Ok(b.to_vec()))
            .unwrap();
        assert_eq!(expect, r2);
        std::fs::remove_file("/tmp/blobcache").expect("remove test file err!");
    }
}
