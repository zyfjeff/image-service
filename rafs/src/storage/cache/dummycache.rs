// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::{Error, ErrorKind, Result};
use std::sync::Arc;

use vm_memory::VolatileSlice;

use crate::metadata::layout::OndiskBlobTableEntry;
use crate::metadata::{RafsChunkInfo, RafsSuperMeta};
use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;
use crate::storage::compress;
use crate::storage::device::RafsBio;
use crate::storage::utils::{alloc_buf, copyv};

pub struct DummyCache {
    pub backend: Box<dyn BlobBackend + Sync + Send>,
}

impl DummyCache {
    pub fn new(backend: Box<dyn BlobBackend + Sync + Send>) -> DummyCache {
        DummyCache { backend }
    }

    pub fn alloc_decompress(
        &self,
        src_buf: &mut [u8],
        bio: &RafsBio,
        bufs: &[VolatileSlice],
        offset: u64,
        d_size: usize,
    ) -> Result<usize> {
        let mut dst_buf = alloc_buf(d_size);
        let sz = compress::decompress(src_buf, dst_buf.as_mut_slice())?;
        if sz != d_size {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Decompression failed. Input invalid or too long?",
            ));
        }
        copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size)
    }

    pub fn decompress(
        &self,
        src_buf: &mut [u8],
        bio: &RafsBio,
        bufs: &[VolatileSlice],
        offset: u64,
        d_size: usize,
    ) -> Result<usize> {
        if bufs[0].len() >= d_size {
            // Use the destination buffer to received the decompressed data.
            let dst_buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), d_size) };
            let sz = compress::decompress(src_buf, dst_buf)?;
            if sz != dst_buf.len() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Decompression failed. Input invalid or too long?",
                ));
            }
            return Ok(sz);
        }
        self.alloc_decompress(src_buf, bio, bufs, offset, d_size)
    }
}

impl RafsCache for DummyCache {
    fn has(&self, _blk: Arc<dyn RafsChunkInfo>) -> bool {
        true
    }

    fn init(&mut self, _sb_meta: &RafsSuperMeta, blobs: &[OndiskBlobTableEntry]) -> Result<()> {
        self.backend.init_blob(blobs);
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
            return self.backend.readv(
                blob_id,
                bufs,
                offset + chunk.blob_decompress_offset(),
                bio.size,
            );
        }

        if bufs.len() == 1 && offset == 0 {
            if bufs[0].len() >= c_size as usize {
                // Reuse the destination buffer to received the compressed data.
                let src_buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), c_size) };
                self.backend
                    .read(blob_id, src_buf, chunk.blob_compress_offset())?;
                return self.alloc_decompress(src_buf, bio, bufs, offset, d_size);
            } else {
                // Allocate a buffer to received the compressed data without zeroing
                let mut src_buf = alloc_buf(c_size);
                self.backend.read(
                    blob_id,
                    src_buf.as_mut_slice(),
                    chunk.blob_compress_offset(),
                )?;
                return self.decompress(src_buf.as_mut_slice(), bio, bufs, offset, d_size);
            }
        }

        let mut src_buf = alloc_buf(c_size);
        self.backend.read(
            blob_id,
            src_buf.as_mut_slice(),
            chunk.blob_compress_offset(),
        )?;

        self.alloc_decompress(src_buf.as_mut_slice(), bio, bufs, offset, d_size)
    }

    fn write(&self, blob_id: &str, blk: &Arc<dyn RafsChunkInfo>, buf: &[u8]) -> Result<usize> {
        self.backend.write(blob_id, buf, blk.blob_compress_offset())
    }

    fn release(&mut self) {
        self.backend.close();
    }
}

pub fn new(backend: Box<dyn BlobBackend + Sync + Send>) -> Result<DummyCache> {
    Ok(DummyCache { backend })
}
