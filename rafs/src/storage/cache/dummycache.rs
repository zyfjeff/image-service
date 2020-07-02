// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Result;
use std::sync::Arc;

use vm_memory::VolatileSlice;

use crate::metadata::layout::OndiskBlobTableEntry;
use crate::metadata::{RafsChunkInfo, RafsSuperMeta};
use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;
use crate::storage::device::RafsBio;
use crate::storage::utils::{alloc_buf, copyv};

pub struct DummyCache {
<<<<<<< HEAD
    pub backend: Arc<dyn BlobBackend + Sync + Send>,
}

impl DummyCache {
    pub fn new(backend: Arc<dyn BlobBackend + Sync + Send>) -> DummyCache {
        DummyCache { backend }
    }
=======
    pub backend: Box<dyn BlobBackend + Sync + Send>,
    chunk_validate: bool,
>>>>>>> blobcache: add chunk validate option
}

impl RafsCache for DummyCache {
    fn backend(&self) -> &Box<dyn BlobBackend + Sync + Send> {
        &self.backend
    }

    fn has(&self, _blk: Arc<dyn RafsChunkInfo>) -> bool {
        true
    }

    fn init(&self, _sb_meta: &RafsSuperMeta, blobs: &[OndiskBlobTableEntry]) -> Result<()> {
        for b in blobs {
            let _ = self.backend.prefetch_blob(b);
        }
        Ok(())
    }

    fn evict(&self, _blk: Arc<dyn RafsChunkInfo>) -> Result<()> {
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }

    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        let blob_id = &bio.blob_id;
        let chunk = &bio.chunkinfo;

        let c_size = chunk.compress_size() as usize;
        let d_size = chunk.decompress_size() as usize;

        // TODO: chunk validation
        if !chunk.is_compressed() {
            return self
                .backend
                .readv(blob_id, bufs, offset + chunk.compress_offset(), bio.size);
        }

        if bufs.len() == 1 && offset == 0 {
            if bufs[0].len() >= c_size as usize {
                // Reuse the destination buffer to received the compressed data.
                let src_buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), c_size) };
                let mut dst_buf = alloc_buf(d_size);
                self.read_from_backend(
                    blob_id,
                    chunk,
                    src_buf,
                    dst_buf.as_mut_slice(),
                    self.chunk_validate,
                )?;
                return copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size);
            } else {
                // Allocate a buffer to received the compressed data without zeroing
                let mut src_buf = alloc_buf(c_size);
                if bufs[0].len() >= d_size {
                    // Use the destination buffer to received the decompressed data.
                    let dst_buf =
                        unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), d_size) };
                    return Ok(self.read_from_backend(
                        blob_id,
                        chunk,
                        src_buf.as_mut_slice(),
                        dst_buf,
                        self.chunk_validate,
                    )?);
                }
                let mut dst_buf = alloc_buf(d_size);
                self.read_from_backend(
                    blob_id,
                    chunk,
                    src_buf.as_mut_slice(),
                    dst_buf.as_mut_slice(),
                    self.chunk_validate,
                )?;
                return copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size);
            }
        }

        let mut src_buf = alloc_buf(c_size);
        let mut dst_buf = alloc_buf(d_size);
        self.read_from_backend(
            blob_id,
            chunk,
            src_buf.as_mut_slice(),
            dst_buf.as_mut_slice(),
            self.chunk_validate,
        )?;
        copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size)
    }

    /// Prefetch works when blobcache is enabled
    fn prefetch(&self, _bios: &mut [RafsBio]) -> Result<usize> {
        warn!("Want to prefetch, however no blobcache is enabled!");
        Ok(0)
    }

    fn write(&self, blob_id: &str, blk: &Arc<dyn RafsChunkInfo>, buf: &[u8]) -> Result<usize> {
        self.backend.write(blob_id, buf, blk.compress_offset())
    }

    fn release(&self) {}
}

pub fn new<S: std::hash::BuildHasher>(
    config: &HashMap<String, String, S>,
    backend: Arc<dyn BlobBackend + Sync + Send>,
) -> Result<DummyCache> {
    let chunk_validate: bool = config
        .get("chunk_validate")
        .map(|v| v == "true")
        .unwrap_or(false);
    Ok(DummyCache {
        backend,
        chunk_validate,
    })
}
