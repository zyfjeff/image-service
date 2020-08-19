// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Result;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use nix::sys::uio;
extern crate spmc;
use vm_memory::VolatileSlice;

use crate::metadata::digest::{self, RafsDigest};
use crate::metadata::layout::OndiskBlobTableEntry;
use crate::metadata::{RafsChunkInfo, RafsSuperMeta};
use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;
use crate::storage::cache::*;
use crate::storage::compress;
use crate::storage::device::RafsBio;
use crate::storage::factory::CacheConfig;
use crate::storage::utils::{alloc_buf, copyv, digest_check, readv};

use nydus_utils::{einval, enoent, enosys, last_error};

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

    fn read(&self, buf: &mut [u8], digester: digest::Algorithm) -> Result<usize> {
        let d_offset = self.chunk.decompress_offset() as i64;
        let d_size = self.chunk.decompress_size();

        let data_offset = unsafe { libc::lseek(self.fd, d_offset, libc::SEEK_DATA) };

        // The seek data offset should be equal to d_offset if the cache ready.
        if data_offset != d_offset {
            return Err(einval!());
        }

        let nr_read = uio::pread(self.fd, buf, d_offset).map_err(|_| last_error!())?;
        if nr_read == 0 || nr_read != d_size as usize {
            return Err(einval!());
        }

        if !digest_check(buf, &self.chunk.block_id(), digester) {
            return Err(einval!());
        }

        trace!(
            "read {}(offset={}) bytes from cache file",
            nr_read,
            d_offset
        );

        Ok(nr_read)
    }

    fn readv(&self, bufs: &[VolatileSlice], offset: u64, max_size: usize) -> Result<usize> {
        readv(self.fd, bufs, offset, max_size)
    }

    fn write(&self, src: &[u8]) -> Result<usize> {
        let nr_write = uio::pwrite(self.fd, src, self.chunk.decompress_offset() as i64)
            .map_err(|_| last_error!())?;

        trace!(
            "write {}(offset={}) bytes to cache file",
            nr_write,
            self.chunk.decompress_offset()
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
struct BlobCacheState {
    chunk_map: HashMap<RafsDigest, Arc<Mutex<BlobCacheEntry>>>,
    file_map: HashMap<String, File>,
    work_dir: String,
}

impl BlobCacheState {
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
    cache: Arc<RwLock<BlobCacheState>>,
    validate: bool,
    pub backend: Arc<dyn BlobBackend + Sync + Send>,
    prefetch_worker: PrefetchWorker,
}

impl BlobCache {
    fn get(&self, blk: Arc<dyn RafsChunkInfo>) -> Option<Arc<Mutex<BlobCacheEntry>>> {
        // Do not expect poisoned lock here.
        self.cache
            .read()
            .unwrap()
            .chunk_map
            .get(&blk.block_id())
            .cloned()
    }

    fn set(
        &self,
        blob_id: &str,
        blk: Arc<dyn RafsChunkInfo>,
    ) -> Result<Arc<Mutex<BlobCacheEntry>>> {
        let block_id = blk.block_id();
        // Do not expect poisoned lock here.
        let mut cache = self.cache.write().unwrap();

        // Double check if someone else has inserted the blob chunk concurrently.
        if let Some(entry) = cache.chunk_map.get(&block_id) {
            Ok(entry.clone())
        } else {
            let fd = cache.get_blob_fd(blob_id)?;
            let entry = Arc::new(Mutex::new(BlobCacheEntry::new(blk, fd)));

            cache.chunk_map.insert(*block_id.clone(), entry.clone());

            Ok(entry)
        }
    }

    fn entry_read(
        &self,
        blob_id: &str,
        entry: &Mutex<BlobCacheEntry>,
        bio: &RafsBio,
        bufs: &[VolatileSlice],
        offset: u64,
        validate: bool,
    ) -> Result<usize> {
        let mut cache_entry = entry.lock().unwrap();
        let chunk = &cache_entry.chunk;

        let c_size = chunk.compress_size() as usize;
        let d_size = chunk.decompress_size() as usize;

        // Hit cache if cache ready
        if CacheStatus::Ready == cache_entry.status {
            trace!("hit blob cache {} {}", chunk.block_id().to_string(), c_size);
            if !self.validate {
                return cache_entry.readv(bufs, offset + chunk.decompress_offset(), bio.size);
            }
            // We need read whole chunk to validate digest.
            let mut src_buf = alloc_buf(d_size);
            cache_entry.read(&mut src_buf, bio.digester)?;
            return copyv(&src_buf, bufs, offset, bio.size);
        }

        let digester = if validate { Some(bio.digester) } else { None };

        // Optimize for the case where the first VolatileSlice covers the whole chunk.
        if bufs.len() == 1 && bufs[0].len() >= d_size as usize && offset == 0 {
            // Reuse the destination data buffer.
            let dst_buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), d_size) };

            // Try to recovery cache from disk
            if cache_entry.read(dst_buf, bio.digester).is_ok() {
                trace!(
                    "recovery blob cache {} {}",
                    chunk.block_id().to_string(),
                    c_size
                );
                cache_entry.status = CacheStatus::Ready;
                return Ok(d_size);
            }

            // Non-compressed source data is easy to handle
            if !chunk.is_compressed() {
                // read from backend into the destination buffer
                self.read_by_chunk(blob_id, chunk.as_ref(), dst_buf, &mut [], digester)?;
                cache_entry.cache(dst_buf, d_size);
                return Ok(d_size);
            }

            let mut src_buf = alloc_buf(c_size);
            self.read_by_chunk(
                blob_id,
                chunk.as_ref(),
                src_buf.as_mut_slice(),
                dst_buf,
                digester,
            )?;
            cache_entry.cache(dst_buf, d_size);
            return Ok(d_size);
        }

        // Try to recovery cache from disk
        let mut dst_buf = alloc_buf(d_size);
        if cache_entry
            .read(dst_buf.as_mut_slice(), bio.digester)
            .is_ok()
        {
            trace!(
                "recovery blob cache {} {}",
                chunk.block_id().to_string(),
                c_size
            );
            cache_entry.status = CacheStatus::Ready;
            return copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size);
        }

        if !chunk.is_compressed() {
            let mut dst_buf = alloc_buf(c_size);
            self.read_by_chunk(
                blob_id,
                chunk.as_ref(),
                dst_buf.as_mut_slice(),
                &mut [],
                digester,
            )?;
            cache_entry.cache(dst_buf.as_mut_slice(), d_size);
            return copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size);
        }

        let mut src_buf = alloc_buf(c_size);
        self.read_by_chunk(
            blob_id,
            chunk.as_ref(),
            src_buf.as_mut_slice(),
            dst_buf.as_mut_slice(),
            digester,
        )?;
        cache_entry.cache(dst_buf.as_mut_slice(), d_size);
        copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size)
    }
}

impl RafsCache for BlobCache {
    fn backend(&self) -> &(dyn BlobBackend + Sync + Send) {
        self.backend.as_ref()
    }

    fn has(&self, blk: Arc<dyn RafsChunkInfo>) -> bool {
        // Doesn't expected poisoned lock here.
        self.cache
            .read()
            .unwrap()
            .chunk_map
            .contains_key(&blk.block_id())
    }

    fn init(&self, _sb_meta: &RafsSuperMeta, blobs: &[OndiskBlobTableEntry]) -> Result<()> {
        for b in blobs {
            let _ = self.backend.prefetch_blob(
                b.blob_id.as_str(),
                b.readahead_offset,
                b.readahead_size,
            );
        }
        // TODO start blob cache level prefetch
        Ok(())
    }

    fn evict(&self, blk: Arc<dyn RafsChunkInfo>) -> Result<()> {
        // Doesn't expected poisoned lock here.
        self.cache
            .write()
            .unwrap()
            .chunk_map
            .remove(&blk.block_id());

        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Err(enosys!())
    }

    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        let blob_id = &bio.blob_id;
        let chunk = bio.chunkinfo.clone();

        if let Some(entry) = self.get(chunk.clone()) {
            self.entry_read(blob_id, &entry, bio, bufs, offset, self.validate)
        } else {
            let entry = self.set(blob_id, chunk)?;
            self.entry_read(blob_id, &entry, bio, bufs, offset, self.validate)
        }
    }

    fn write(&self, _blob_id: &str, _blk: &dyn RafsChunkInfo, _buf: &[u8]) -> Result<usize> {
        Err(enosys!())
    }

    fn release(&self) {}
    /// Bypass memory blob cache index, fetch blocks from backend and directly
    /// mirror them into blob cache file.
    /// Continuous chunks may be compressed or not.
    fn prefetch(&self, bios: &mut [RafsBio]) -> Result<usize> {
        let (mut tx, rx) = spmc::channel::<MergedBackendRequest>();

        // TODO: Make thread count configurable.
        for num in 0..self.prefetch_worker.threads_count {
            let backend = Arc::clone(&self.backend);
            let cache = Arc::clone(&self.cache);
            let rx = rx.clone();
            let _thread = thread::Builder::new()
                .name(format!("prefetch_thread_{}", num))
                .spawn(move || {
                    while let Ok(mr) = rx.recv() {
                        let blob_offset = mr.blob_offset;
                        let blob_size = mr.blob_size;
                        let continuous_chunks = &mr.chunks;
                        let blob_id = &mr.blob_id;

                        if continuous_chunks.is_empty() {
                            continue;
                        }

                        trace!(
                            "Merged req id {} req offset {} size {}",
                            blob_id,
                            blob_offset,
                            blob_size
                        );

                        let head_chunk = &continuous_chunks[0];
                        let head_chunk_offset_decompressed = head_chunk.decompress_offset() as i64;

                        let mut c_guard = cache.write().unwrap();
                        let c = c_guard.get_blob_fd(blob_id.as_str()).unwrap();
                        // TODO: Detect the blobcache file to see if it is already fulfilled.
                        // It's rough now since the whole merged request may not be all fulfilled.
                        // But we assume it is less likely.
                        let data_offset = unsafe {
                            libc::lseek(c, head_chunk_offset_decompressed, libc::SEEK_DATA)
                        };
                        if data_offset == head_chunk_offset_decompressed {
                            continue;
                        }

                        drop(c_guard);

                        let mut c_buf = alloc_buf(blob_size as usize);
                        // Blob id must be unique.
                        // TODO: Currently, request length to backend may span a whole chunk,
                        // Do we need to split it into smaller pieces?
                        let _ = backend.read(blob_id.as_str(), c_buf.as_mut_slice(), blob_offset);
                        for c in continuous_chunks {
                            // Deal with mixture of compressed and uncompressed chunks.
                            let offset_merged = c.compress_offset() - blob_offset;
                            let fd = cache
                                .write()
                                .unwrap()
                                .get_blob_fd(blob_id.as_str())
                                .unwrap();
                            if c.is_compressed() {
                                // Decompression failure can't be handled, panic helps us note it in the first place.
                                let mut d_buf = alloc_buf(c.decompress_size() as usize);
                                compress::decompress(
                                    &c_buf[offset_merged as usize
                                        ..(offset_merged as usize + c.compress_size() as usize)],
                                    d_buf.as_mut_slice(),
                                )
                                .unwrap();
                                let _ = uio::pwrite(fd, &d_buf, c.decompress_offset() as i64)
                                    .map_err(|_| last_error!());
                            } else {
                                let _ = uio::pwrite(
                                    fd,
                                    &c_buf[offset_merged as usize
                                        ..(offset_merged as usize + c.compress_size() as usize)],
                                    c.decompress_offset() as i64,
                                )
                                .map_err(|_| last_error!());
                            }
                        }
                    }
                    info!("Prefetch thread exits.")
                });
        }

        // Ideally, prefetch task can run within a separated thread from loading prefetch table.
        // However, due to current implementation, doing so needs modifying key data structure like
        // `Superblock` on `Rafs`. So let's suspend this action.
        let mut bios = bios.to_vec();
        let merging_size = self.prefetch_worker.merging_size;
        let _thread = thread::Builder::new().spawn({
            move || {
                generate_merged_requests(bios.as_mut_slice(), &mut tx, merging_size);
            }
        });

        Ok(0)
    }
}

#[derive(Clone, Deserialize)]
struct BlobCacheConfig {
    #[serde(default = "default_work_dir")]
    work_dir: String,
}

fn default_work_dir() -> String {
    ".".to_string()
}

pub fn new(config: CacheConfig, backend: Arc<dyn BlobBackend + Sync + Send>) -> Result<BlobCache> {
    let blob_config: BlobCacheConfig =
        serde_json::from_value(config.cache_config).map_err(|e| einval!(e))?;
    let work_dir = {
        let path = fs::metadata(&blob_config.work_dir)
            .or_else(|_| {
                fs::create_dir_all(&blob_config.work_dir)?;
                fs::metadata(&blob_config.work_dir)
            })
            .map_err(|e| {
                last_error!(format!(
                    "fail to stat blobcache work_dir {}: {}",
                    blob_config.work_dir, e
                ))
            })?;
        if path.is_dir() {
            Ok(blob_config.work_dir.as_str())
        } else {
            Err(enoent!(format!(
                "blobcache work_dir {} is not a directory",
                blob_config.work_dir
            )))
        }
    }?;

    Ok(BlobCache {
        cache: Arc::new(RwLock::new(BlobCacheState {
            chunk_map: HashMap::new(),
            file_map: HashMap::new(),
            work_dir: work_dir.to_string(),
        })),
        validate: config.cache_validate,
        backend,
        prefetch_worker: config.prefetch_worker,
    })
}

#[cfg(test)]
mod blob_cache_tests {
    use std::alloc::{alloc, dealloc, Layout};
    use std::io::Result;
    use std::slice::from_raw_parts;
    use std::sync::Arc;

    use vm_memory::{VolatileMemory, VolatileSlice};
    use vmm_sys_util::tempdir::TempDir;

    use crate::metadata::digest::{self, RafsDigest};
    use crate::metadata::layout::OndiskChunkInfo;
    use crate::metadata::RAFS_DEFAULT_BLOCK_SIZE;
    use crate::storage::backend::BlobBackend;
    use crate::storage::cache::blobcache;
    use crate::storage::cache::PrefetchWorker;
    use crate::storage::cache::RafsCache;
    use crate::storage::compress;
    use crate::storage::device::RafsBio;
    use crate::storage::factory::CacheConfig;

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
    }

    #[test]
    fn test_add() {
        // new blob cache
        let tmp_dir = TempDir::new().unwrap();
        let s = format!(
            r###"
        {{
            "work_dir": {:?}
        }}
        "###,
            tmp_dir.as_path().to_path_buf().join("cache"),
        );

        let cache_config = CacheConfig {
            cache_validate: true,
            cache_type: String::from("blobcache"),
            cache_config: serde_json::from_str(&s).unwrap(),
            prefetch_worker: PrefetchWorker::default(),
        };
        let blob_cache = blobcache::new(
            cache_config,
            Arc::new(MockBackend {}) as Arc<dyn BlobBackend + Send + Sync>,
        )
        .unwrap();

        // generate backend data
        let mut expect = vec![1u8; 100];
        let blob_id = "blobcache";
        blob_cache
            .backend
            .read(blob_id, expect.as_mut(), 0)
            .unwrap();

        // generate chunk and bio
        let mut chunk = OndiskChunkInfo::new();
        chunk.block_id = RafsDigest::from_buf(&expect, digest::Algorithm::Blake3).into();
        chunk.file_offset = 0;
        chunk.compress_offset = 0;
        chunk.compress_size = 100;
        chunk.decompress_offset = 0;
        chunk.decompress_size = 100;
        let bio = RafsBio::new(
            Arc::new(chunk),
            blob_id.to_string(),
            compress::Algorithm::None,
            digest::Algorithm::Blake3,
            50,
            50,
            RAFS_DEFAULT_BLOCK_SIZE as u32,
        );

        // read from cache
        let r1 = unsafe {
            let layout = Layout::from_size_align(50, 1).unwrap();
            let ptr = alloc(layout);
            let vs = VolatileSlice::new(ptr, 50);
            blob_cache.read(&bio, &[vs], 50).unwrap();
            let data = Vec::from(from_raw_parts(ptr, 50).clone());
            dealloc(ptr, layout);
            data
        };

        let r2 = unsafe {
            let layout = Layout::from_size_align(50, 1).unwrap();
            let ptr = alloc(layout);
            let vs = VolatileSlice::new(ptr, 50);
            blob_cache.read(&bio, &[vs], 50).unwrap();
            let data = Vec::from(from_raw_parts(ptr, 50).clone());
            dealloc(ptr, layout);
            data
        };

        assert_eq!(r1, &expect[50..]);
        assert_eq!(r2, &expect[50..]);
    }
}
