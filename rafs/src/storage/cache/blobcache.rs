// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Error, ErrorKind, Result};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex, RwLock};

use nix::sys::uio;
use vm_memory::{VolatileMemory, VolatileSlice};

use crate::metadata::layout::{OndiskBlobTableEntry, OndiskDigest};
use crate::metadata::{RafsChunkInfo, RafsDigest, RafsSuperMeta};
use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;
use crate::storage::compress;
use crate::storage::device::RafsBio;
use crate::storage::utils::{alloc_buf, copyv, readv};

#[derive(Clone, Eq, PartialEq)]
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

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let nr_read = uio::pread(self.fd, buf, self.chunk.blob_decompress_offset() as i64)
            .map_err(|_| Error::last_os_error())?;

        trace!(
            "read {}(offset={}) bytes from cache file",
            nr_read,
            self.chunk.blob_decompress_offset()
        );

        Ok(nr_read)
    }

    fn readv(&self, bufs: &[VolatileSlice], offset: u64, max_size: usize) -> Result<usize> {
        readv(self.fd, bufs, offset, max_size)
    }

    fn write(&self, src: &[u8]) -> Result<usize> {
        let nr_write = uio::pwrite(self.fd, src, self.chunk.blob_decompress_offset() as i64)
            .map_err(|_| Error::last_os_error())?;

        trace!(
            "write {}(offset={}) bytes to cache file",
            nr_write,
            self.chunk.blob_decompress_offset()
        );

        Ok(nr_write)
    }

    fn cache(&mut self, buf: &[u8], sz: usize) {
        // The whole chunk is ready, try to cache it.
        if sz == buf.len() {
            if let Ok(w_size) = self.write(buf).map_err(|err| {
                warn!("Cache write blob file failed: {}", err);
                err
            }) {
                if w_size == sz {
                    self.status = CacheStatus::Ready;
                    return;
                }
            } else {
                return;
            }
        }
        warn!("Cache write failed, the buf length not match");
    }
}

#[derive(Default)]
struct BlocCacheState {
    chunk_map: HashMap<Vec<u8>, Arc<Mutex<BlobCacheEntry>>>,
    file_map: HashMap<String, File>,
    work_dir: String,
}

impl BlocCacheState {
    fn get_blob_fd(&mut self, blob_id: &str) -> Result<RawFd> {
        if let Some(file) = self.file_map.get(blob_id) {
            return Ok(file.as_raw_fd());
        }

        let blob_file_path = format!("{}/{}", self.work_dir, blob_id);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(blob_file_path)?;
        let fd = file.as_raw_fd();

        self.file_map.insert(blob_id.to_string(), file);

        Ok(fd)
    }
}

pub struct BlobCache {
    cache: RwLock<BlocCacheState>,
    blksize: u32,
    pub backend: Box<dyn BlobBackend + Sync + Send>,
}

impl BlobCache {
    fn get(&self, blk: &Arc<dyn RafsChunkInfo>) -> Option<Arc<Mutex<BlobCacheEntry>>> {
        // Do not expect poisoned lock here.
        self.cache
            .read()
            .unwrap()
            .chunk_map
            .get(blk.block_id().data())
            .cloned()
    }

    fn set(
        &self,
        blob_id: &str,
        blk: &Arc<dyn RafsChunkInfo>,
    ) -> Result<Arc<Mutex<BlobCacheEntry>>> {
        let block_id = blk.block_id();
        // Do not expect poisoned lock here.
        let mut cache = self.cache.write().unwrap();

        // Double check if someone else has inserted the blob chunk concurrently.
        if let Some(entry) = cache.chunk_map.get(block_id.data()) {
            Ok(entry.clone())
        } else {
            let fd = cache.get_blob_fd(blob_id)?;
            let entry = Arc::new(Mutex::new(BlobCacheEntry::new(blk.clone(), fd)));

            cache
                .chunk_map
                .insert(block_id.data().to_owned(), entry.clone());

            Ok(entry)
        }
    }

    fn entry_read(
        &self,
        blob_id: &str,
        entry: &Arc<Mutex<BlobCacheEntry>>,
        bio: &RafsBio,
        bufs: &[VolatileSlice],
        offset: u64,
    ) -> Result<usize> {
        let mut cache_entry = entry.lock().unwrap();
        let chunk = &cache_entry.chunk;
        let c_offset = chunk.blob_compress_offset();
        let c_size = chunk.compress_size() as usize;
        let d_size = chunk.decompress_size() as usize;

        // hit cache if cache ready
        if CacheStatus::Ready == cache_entry.status {
            trace!("hit blob cache {} {}", chunk.block_id().to_string(), c_size);
            return cache_entry.readv(bufs, offset + chunk.blob_decompress_offset(), bio.size);
        }

        // Optimize for the case where the first VolatileSlice covers the whole chunk.
        if bufs.len() == 1 && bufs[0].len() >= d_size as usize && offset == 0 {
            // Reuse the destination data buffer.
            let buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), d_size) };

            // try to recovery cache from disk
            if let Ok(sz) = cache_entry.read(buf) {
                if sz == buf.len() && chunk.block_id().data() == OndiskDigest::from_buf(buf).data()
                {
                    trace!(
                        "recovery blob cache {} {}",
                        chunk.block_id().to_string(),
                        c_size
                    );
                    cache_entry.status = CacheStatus::Ready;
                    return Ok(sz);
                }
            }

            // Non-compressed source data is easy to handle
            if !chunk.is_compressed() {
                // read from backend into the destination buffer
                let sz = self.backend.read(blob_id, buf, c_offset)?;
                cache_entry.cache(buf, sz);
                return Ok(sz);
            }

            let mut chunk_data = alloc_buf(c_size);
            let sz = self
                .backend
                .read(blob_id, chunk_data.as_mut_slice(), c_offset)?;
            if sz != c_size {
                return Err(Error::new(
                    ErrorKind::Other,
                    "Data read from backend is too small.",
                ));
            }
            let sz = compress::decompress(chunk_data.as_mut_slice(), buf)?;
            if sz != d_size {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Decompression failed. Input invalid or too long?",
                ));
            }

            cache_entry.cache(buf, sz);
            return Ok(d_size);
        }

        let mut dst_buf = alloc_buf(d_size as usize);
        // try to recovery cache from disk
        if let Ok(sz) = cache_entry.read(dst_buf.as_mut_slice()) {
            if sz == d_size
                && chunk.block_id().data() == OndiskDigest::from_buf(dst_buf.as_mut_slice()).data()
            {
                trace!(
                    "recovery blob cache {} {}",
                    chunk.block_id().to_string(),
                    c_size
                );
                cache_entry.status = CacheStatus::Ready;
                return copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size);
            }
        }

        let mut c_buf = alloc_buf(c_size);
        let sz = self.backend.read(blob_id, c_buf.as_mut_slice(), c_offset)?;
        if !chunk.is_compressed() {
            cache_entry.cache(c_buf.as_mut_slice(), sz);
            return copyv(c_buf.as_mut_slice(), bufs, offset, bio.size);
        }

        let sz = compress::decompress(c_buf.as_mut_slice(), dst_buf.as_mut_slice())?;
        cache_entry.cache(dst_buf.as_mut_slice(), sz);
        copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size)
    }
}

impl RafsCache for BlobCache {
    /* whether has a block data */
    fn has(&self, blk: Arc<dyn RafsChunkInfo>) -> bool {
        // Doesn't expected poisoned lock here.
        self.cache
            .read()
            .unwrap()
            .chunk_map
            .contains_key(blk.block_id().data())
    }

    fn init(&mut self, sb_meta: &RafsSuperMeta, blobs: &[OndiskBlobTableEntry]) -> Result<()> {
        self.blksize = sb_meta.block_size;
        self.backend.init_blob(blobs);
        Ok(())
    }

    /* evict block data */
    fn evict(&self, blk: Arc<dyn RafsChunkInfo>) -> Result<()> {
        // Doesn't expected poisoned lock here.
        self.cache
            .write()
            .unwrap()
            .chunk_map
            .remove(blk.block_id().data());

        Ok(())
    }

    /* flush cache */
    fn flush(&self) -> Result<()> {
        Err(Error::from_raw_os_error(libc::ENOSYS))
    }

    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        let blob_id = &bio.blob_id;
        let chunk = &bio.chunkinfo;

        if let Some(entry) = self.get(chunk) {
            self.entry_read(blob_id, &entry, bio, bufs, offset)
        } else {
            let entry = self.set(blob_id, chunk)?;
            self.entry_read(blob_id, &entry, bio, bufs, offset)
        }
    }

    fn write(&self, _blob_id: &str, _blk: &Arc<dyn RafsChunkInfo>, _buf: &[u8]) -> Result<usize> {
        Err(Error::from_raw_os_error(libc::ENOSYS))
    }

    fn release(&mut self) {
        self.backend.close();
    }
}

pub fn new<S: std::hash::BuildHasher>(
    config: &HashMap<String, String, S>,
    backend: Box<dyn BlobBackend + Sync + Send>,
) -> Result<BlobCache> {
    let work_dir = config
        .get("work_dir")
        .map_or(Ok("."), |p| -> Result<&str> {
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
        cache: RwLock::new(BlocCacheState {
            chunk_map: HashMap::new(),
            file_map: HashMap::new(),
            work_dir: String::from(work_dir),
        }),
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
    use crate::storage::compress::Algorithm;
    use crate::storage::device::RafsBio;
    use vm_memory::VolatileSlice;

    struct MockBackend {}

    impl BlobBackend for MockBackend {
        // Read a range of data from blob into the provided slice
        fn read(&self, _blob_id: &str, buf: &mut [u8], _offset: u64) -> Result<usize> {
            let mut i = 0;
            while i < buf.len() {
                buf[i] = i as u8;
                i += 1;
            }
            Ok(i)
        }

        // Write a range of data to blob from the provided slice
        fn write(&self, _blob_id: &str, _buf: &[u8], _offset: u64) -> Result<usize> {
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
        let mut expect = vec![0u8; 100];
        let block_id = [1u8; 32];
        let blob_id = "blobcache";
        // generate init data
        blob_cache
            .backend
            .read(blob_id, expect.as_mut(), 0)
            .unwrap();

        let mut chunk = OndiskChunkInfo::new();
        chunk.block_id = OndiskDigest::from_raw(&block_id);
        chunk.file_offset = 0;
        chunk.blob_compress_offset = 0;
        chunk.compress_size = 100;
        chunk.blob_decompress_offset = 0;
        chunk.decompress_size = 100;
        chunk.flags = 0;
        let bio = RafsBio::new(
            Arc::new(chunk),
            blob_id.to_string(),
            Algorithm::None,
            0,
            100,
            1024 * 1024,
        );
        let mut buf = vec![0u8; 100];
        let vbuf = unsafe { [VolatileSlice::new(buf.as_mut_ptr(), 4096)] };
        assert_eq!(blob_cache.read(&bio, &vbuf, 0).unwrap(), 100);
        assert_eq!(&buf[0..100], expect.as_slice());
        assert_eq!(blob_cache.read(&bio, &vbuf, 0).unwrap(), 100);
        assert_eq!(&buf[0..100], expect.as_slice());
        std::fs::remove_file("/tmp/blobcache").expect("remove test file err!");
    }
}
