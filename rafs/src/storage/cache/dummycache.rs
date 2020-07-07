// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::Arc;

use vm_memory::VolatileSlice;

use crate::metadata::layout::OndiskBlobTableEntry;
use crate::metadata::{RafsChunkInfo, RafsSuperMeta};
use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;
use crate::storage::device::RafsBio;
use crate::storage::factory::CacheConfig;
use crate::storage::utils::{alloc_buf, copyv};

pub struct DummyCache {
    pub backend: Arc<dyn BlobBackend + Sync + Send>,
    validate: bool,
}

impl RafsCache for DummyCache {
    fn backend(&self) -> &(dyn BlobBackend + Sync + Send) {
        self.backend.as_ref()
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

        if !chunk.is_compressed() {
            if !self.validate {
                return self.backend.readv(
                    blob_id,
                    bufs,
                    offset + chunk.compress_offset(),
                    bio.size,
                );
            }
            // We need read whole chunk to validate digest.
            let mut src_buf = alloc_buf(c_size);
            self.read_by_chunk(
                blob_id,
                chunk.as_ref(),
                &mut src_buf,
                &mut [],
                self.validate,
            )?;
            return copyv(&src_buf, bufs, offset, bio.size);
        }

        if bufs.len() == 1 && offset == 0 {
            if bufs[0].len() >= c_size as usize {
                // Reuse the destination buffer to received the compressed data.
                let src_buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), c_size) };
                let mut dst_buf = alloc_buf(d_size);
                self.read_by_chunk(
                    blob_id,
                    chunk.as_ref(),
                    src_buf,
                    dst_buf.as_mut_slice(),
                    self.validate,
                )?;
                return copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size);
            } else {
                // Allocate a buffer to received the compressed data without zeroing
                let mut src_buf = alloc_buf(c_size);
                if bufs[0].len() >= d_size {
                    // Use the destination buffer to received the decompressed data.
                    let dst_buf =
                        unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), d_size) };
                    return Ok(self.read_by_chunk(
                        blob_id,
                        chunk.as_ref(),
                        src_buf.as_mut_slice(),
                        dst_buf,
                        self.validate,
                    )?);
                }
                let mut dst_buf = alloc_buf(d_size);
                self.read_by_chunk(
                    blob_id,
                    chunk.as_ref(),
                    src_buf.as_mut_slice(),
                    dst_buf.as_mut_slice(),
                    self.validate,
                )?;
                return copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size);
            }
        }

        let mut src_buf = alloc_buf(c_size);
        let mut dst_buf = alloc_buf(d_size);
        self.read_by_chunk(
            blob_id,
            chunk.as_ref(),
            src_buf.as_mut_slice(),
            dst_buf.as_mut_slice(),
            self.validate,
        )?;
        copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size)
    }

    /// Prefetch works when blobcache is enabled
    fn prefetch(&self, _bios: &mut [RafsBio]) -> Result<usize> {
        warn!("Want to prefetch, however no blobcache is enabled!");
        Ok(0)
    }

    fn write(&self, blob_id: &str, blk: &dyn RafsChunkInfo, buf: &[u8]) -> Result<usize> {
        self.backend.write(blob_id, buf, blk.compress_offset())
    }

    fn release(&self) {}
}

pub fn new(
    config: &CacheConfig,
    backend: Arc<dyn BlobBackend + Sync + Send>,
) -> Result<DummyCache> {
    Ok(DummyCache {
        backend,
        validate: config.cache_validate,
    })
}
