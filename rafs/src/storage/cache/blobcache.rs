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
use vm_memory::{VolatileMemory, VolatileSlice};

use crate::metadata::layout::OndiskBlobTableEntry;
use crate::metadata::{RafsChunkInfo, RafsSuperMeta};
use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;
use crate::storage::device::RafsBio;
use crate::storage::utils::{alloc_buf, copyv, digest_check, readv};

use nydus_utils::{eio, enoent, enosys, last_error};

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
        let nr_read = uio::pread(self.fd, buf, self.chunk.decompress_offset() as i64)
            .map_err(|e| last_error!(e))?;

        trace!(
            "read {}(offset={}) bytes from cache file",
            nr_read,
            self.chunk.decompress_offset()
        );

        // TODO: log improvement
        if nr_read == 0 {
            return Err(eio!());
        }
        if nr_read != self.chunk.decompress_size() as usize {
            return Err(eio!("can't read enough data from cache"));
        }

        if !digest_check(buf, self.chunk.block_id()) {
            return Err(eio!());
        }

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
    cache: Arc<RwLock<BlocCacheState>>,
    blksize: u32,
    chunk_validate: bool,
    pub backend: Arc<dyn BlobBackend + Sync + Send>,
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
        chunk_validate: bool,
    ) -> Result<usize> {
        let mut cache_entry = entry.lock().unwrap();
        let chunk = &cache_entry.chunk;

        let c_size = chunk.compress_size() as usize;
        let d_size = chunk.decompress_size() as usize;

        // hit cache if cache ready
        if CacheStatus::Ready == cache_entry.status {
            trace!("hit blob cache {} {}", chunk.block_id().to_string(), c_size);
            return cache_entry.readv(bufs, offset + chunk.decompress_offset(), bio.size);
        }

        // Optimize for the case where the first VolatileSlice covers the whole chunk.
        if bufs.len() == 1 && bufs[0].len() >= d_size as usize && offset == 0 {
            // Reuse the destination data buffer.
            let dst_buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), d_size) };

            // try to recovery cache from disk
            if cache_entry.read(dst_buf).is_ok() {
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
                self.read_from_backend(blob_id, chunk, dst_buf, &mut [], chunk_validate)?;
                cache_entry.cache(dst_buf, d_size);
                return Ok(d_size);
            }

            let mut src_buf = alloc_buf(c_size);
            self.read_from_backend(
                blob_id,
                chunk,
                src_buf.as_mut_slice(),
                dst_buf,
                chunk_validate,
            )?;
            cache_entry.cache(dst_buf, d_size);
            return Ok(d_size);
        }

        // try to recovery cache from disk
        let mut dst_buf = alloc_buf(d_size);
        if cache_entry.read(dst_buf.as_mut_slice()).is_ok() {
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
            self.read_from_backend(
                blob_id,
                chunk,
                dst_buf.as_mut_slice(),
                &mut [],
                chunk_validate,
            )?;
            cache_entry.cache(dst_buf.as_mut_slice(), d_size);
            return copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size);
        }

        let mut src_buf = alloc_buf(c_size);
        self.read_from_backend(
            blob_id,
            chunk,
            src_buf.as_mut_slice(),
            dst_buf.as_mut_slice(),
            chunk_validate,
        )?;
        cache_entry.cache(dst_buf.as_mut_slice(), d_size);
        copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size)
    }
}

#[derive(Default, Clone)]
struct MergedBlobRequest {
    // Chunks that are continuous to each other.
    pub chunks: Vec<Arc<dyn RafsChunkInfo>>,
    pub blob_offset: u64,
    pub blob_size: u32,
    pub blob_id: String,
}

impl<'a> MergedBlobRequest {
    fn reset(&mut self) {
        self.blob_offset = 0;
        self.blob_size = 0;
        self.blob_id.truncate(0);
        self.chunks.clear();
    }

    fn merge_begin(&mut self, first_cki: Arc<dyn RafsChunkInfo>, blob_id: &str) {
        self.blob_offset = first_cki.blob_compress_offset();
        self.blob_size = first_cki.compress_size();
        // let thin_cki = Self::digest_chunkinfo(first_cki);
        self.chunks.push(first_cki);
        self.blob_id = String::from(blob_id);
    }

    fn merge_one_chunk(&mut self, cki: Arc<dyn RafsChunkInfo>) {
        self.blob_size += cki.compress_size();
        // let thin_cki = Self::digest_chunkinfo(cki);
        self.chunks.push(cki);
    }
}

fn is_chunk_continuous(prior: &RafsBio, cur: &RafsBio) -> bool {
    let prior_cki = &prior.chunkinfo;
    let cur_cki = &cur.chunkinfo;

    let prior_end = prior_cki.blob_compress_offset() + prior_cki.compress_size() as u64;
    let cur_offset = cur_cki.blob_compress_offset();

    if prior_end == cur_offset && prior.blob_id == cur.blob_id {
        return true;
    }

    false
}

fn generate_merged_requests(bios: &mut [RafsBio], tx: &mut spmc::Sender<MergedBlobRequest>) {
    bios.sort_by_key(|entry| entry.chunkinfo.blob_compress_offset());
    let mut index: usize = 1;
    let first_cki = &bios[0].chunkinfo;
    let mut mr = MergedBlobRequest::default();
    mr.merge_begin(Arc::clone(first_cki), &bios[0].blob_id);

    if bios.len() == 1 {
        tx.send(mr).unwrap();
        return;
    }

    loop {
        let cki = &bios[index].chunkinfo;
        let prior_bio = &bios[index - 1];
        let cur_bio = &bios[index];

        // Even more chunks are continuous, still split them per as certain size.
        // So that to achieve an appropriate request size to backend.
        // TODO: Try to make `certain size` configurable?
        const MERGE_SIZE: u32 = 128 * 1024;
        if is_chunk_continuous(prior_bio, cur_bio) && mr.blob_size <= MERGE_SIZE {
            mr.merge_one_chunk(Arc::clone(&cki));
        } else {
            // New a MR if a non-continuous chunk is met.
            tx.send(mr.clone()).unwrap();
            mr.reset();
            mr.merge_begin(Arc::clone(&cki), &cur_bio.blob_id);
        }

        index += 1;

        if index >= bios.len() {
            tx.send(mr).unwrap();
            break;
        }
    }
}

impl RafsCache for BlobCache {
    fn backend(&self) -> &Box<dyn BlobBackend + Sync + Send> {
        &self.backend
    }

    /* whether has a block data */
    fn has(&self, blk: Arc<dyn RafsChunkInfo>) -> bool {
        // Doesn't expected poisoned lock here.
        self.cache
            .read()
            .unwrap()
            .chunk_map
            .contains_key(blk.block_id().data())
    }

    fn init(&self, _sb_meta: &RafsSuperMeta, blobs: &[OndiskBlobTableEntry]) -> Result<()> {
        for b in blobs {
            let _ = self.backend.prefetch_blob(b);
        }
        // TODO start blob cache level prefetch
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
        Err(enosys!())
    }

    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        let blob_id = &bio.blob_id;
        let chunk = &bio.chunkinfo;

        if let Some(entry) = self.get(chunk) {
            self.entry_read(blob_id, &entry, bio, bufs, offset, self.chunk_validate)
        } else {
            let entry = self.set(blob_id, chunk)?;
            self.entry_read(blob_id, &entry, bio, bufs, offset, self.chunk_validate)
        }
    }

    fn write(&self, _blob_id: &str, _blk: &Arc<dyn RafsChunkInfo>, _buf: &[u8]) -> Result<usize> {
        Err(enosys!())
    }

    fn release(&self) {}
    /// Bypass memory blob cache index, fetch blocks from backend and directly
    /// mirror them into blob cache file.
    /// Continuous chunks may be compressed or not.
    fn prefetch(&self, bios: &mut [RafsBio]) -> Result<usize> {
        let (mut tx, rx) = spmc::channel::<MergedBlobRequest>();

        // TODO: Make thread count configurable.
        for num in 0..8 {
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
                        trace!(
                            "Merged req id {} req offset {} size {}",
                            blob_id,
                            blob_offset,
                            blob_size
                        );
                        let mut c_buf = alloc_buf(blob_size as usize);
                        // Blob id must be unique.
                        // TODO: Currently, request length to backend may span a whole chunk,
                        // Do we need to split it into smaller pieces?
                        let _ = backend.read(blob_id.as_str(), c_buf.as_mut_slice(), blob_offset);
                        for c in continuous_chunks {
                            // Deal with mixture of compressed and uncompressed chunks.
                            let offset_merged = c.blob_compress_offset() - blob_offset;
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
                                let _ = uio::pwrite(fd, &d_buf, c.blob_decompress_offset() as i64)
                                    .map_err(|_| last_error!());
                            } else {
                                let _ = uio::pwrite(
                                    fd,
                                    &c_buf[offset_merged as usize
                                        ..(offset_merged as usize + c.compress_size() as usize)],
                                    c.blob_decompress_offset() as i64,
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
        let _thread = thread::Builder::new().spawn({
            move || {
                generate_merged_requests(bios.as_mut_slice(), &mut tx);
            }
        });

        Ok(0)
    }
}

pub fn new<S: std::hash::BuildHasher>(
    config: &HashMap<String, String, S>,
    backend: Arc<dyn BlobBackend + Sync + Send>,
) -> Result<BlobCache> {
    let work_dir = config
        .get("work_dir")
        .map_or(Ok("."), |p| -> Result<&str> {
            let path = fs::metadata(p).map_err(|e| {
                last_error!(format!("fail to stat blobcache work_dir {}: {}", p, e))
            })?;
            if path.is_dir() {
                Ok(p.as_str())
            } else {
                Err(enoent!(format!(
                    "blobcache work_dir {} is not a directory",
                    p
                )))
            }
        })?;
    let chunk_validate: bool = config
        .get("chunk_validate")
        .map(|v| v == "true")
        .unwrap_or(false);

    Ok(BlobCache {
        cache: Arc::new(RwLock::new(BlocCacheState {
            chunk_map: HashMap::new(),
            file_map: HashMap::new(),
            work_dir: String::from(work_dir),
<<<<<<< HEAD
        })),
=======
        }),
        chunk_validate,
>>>>>>> blobcache: add chunk validate option
        backend,
    })
}

#[cfg(test)]
mod blob_cache_tests {
    use std::alloc::{alloc, dealloc, Layout};
    use std::collections::HashMap;
    use std::io::Result;
    use std::slice::from_raw_parts;
    use std::sync::Arc;

    use vm_memory::{VolatileMemory, VolatileSlice};

    use crate::metadata::layout::{OndiskChunkInfo, OndiskDigest};
    use crate::metadata::RAFS_DEFAULT_BLOCK_SIZE;
    use crate::storage::backend::BlobBackend;
    use crate::storage::cache::blobcache;
    use crate::storage::cache::RafsCache;
    use crate::storage::compress;
    use crate::storage::device::RafsBio;

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
        fn close(&self) {}
    }

    #[test]
    fn test_add() {
        // new blob cache
        let mut config = HashMap::new();
        config.insert(String::from("work_dir"), String::from("/tmp"));
        let blob_cache = blobcache::new(
            &config,
            Box::new(MockBackend {}) as Box<dyn BlobBackend + Send + Sync>,
        )
        .unwrap();

        // generate backend data
        let mut expect = vec![0u8; 100];
        let block_id = [1u8; 32];
        let blob_id = "blobcache";
        blob_cache
            .backend
            .read(blob_id, expect.as_mut(), 0)
            .unwrap();

        // generate chunk and bio
        let mut chunk = OndiskChunkInfo::new();
        chunk.block_id = OndiskDigest::from_raw(&block_id);
        chunk.file_offset = 0;
        chunk.compress_offset = 0;
        chunk.compress_size = 100;
        chunk.decompress_offset = 0;
        chunk.decompress_size = 100;
        let bio = RafsBio::new(
            Arc::new(chunk),
            blob_id.to_string(),
            compress::Algorithm::None,
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

        std::fs::remove_file("/tmp/blobcache").expect("remove test file err!");
    }
}
