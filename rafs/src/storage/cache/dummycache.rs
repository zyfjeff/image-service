// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::{Error, ErrorKind, Result};
use std::sync::Arc;

use vm_memory::VolatileSlice;

use crate::metadata::{RafsChunkInfo, RafsSuperMeta};
use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;
use crate::storage::compress;
use crate::storage::device::RafsBio;
use crate::storage::utils::{copyv, DataBuf};

pub struct DummyCache {
    pub backend: Box<dyn BlobBackend + Sync + Send>,
}

impl DummyCache {
    pub fn new(backend: Box<dyn BlobBackend + Sync + Send>) -> DummyCache {
        DummyCache { backend }
    }
}

impl RafsCache for DummyCache {
    fn has(&self, _blk: Arc<dyn RafsChunkInfo>) -> bool {
        true
    }

    fn init(&mut self, _sb_meta: &RafsSuperMeta) -> Result<()> {
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
        let result;

        if !chunk.is_compressed() {
            result = self.backend.readv(
                blob_id,
                bufs,
                offset + chunk.blob_decompress_offset(),
                bio.size,
            );
        } else if bufs.len() == 1 && bufs[0].len() == bio.blksize as usize && offset == 0 {
            // Allocate a buffer to received the compressed data without zeroing
            let src_size = chunk.compress_size() as usize;
            let mut src_buf = DataBuf::alloc(src_size);
            self.backend.read(
                blob_id,
                src_buf.as_mut_slice(),
                chunk.blob_compress_offset(),
            )?;

            // Use the destination buffer to received the decompressed data.
            let dst_size = bufs[0].len();
            let dst_buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), dst_size) };
            let sz = compress::decompress(src_buf.as_mut_slice(), dst_buf)?;
            result = if sz != dst_size {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "Decompression failed. Input invalid or too long?",
                ))
            } else {
                Ok(sz)
            };
        } else if bufs.len() == 1 && bufs[0].len() >= chunk.compress_size() as usize {
            // Reuse the destination buffer to received the compressed data.
            let src_buf = unsafe {
                std::slice::from_raw_parts_mut(bufs[0].as_ptr(), chunk.compress_size() as usize)
            };
            self.backend
                .read(blob_id, src_buf, chunk.blob_compress_offset())?;

            // Allocate a buffer to received the decompressed data without zeroing
            let dst_size = bio.blksize as usize;
            let mut dst_buf = DataBuf::alloc(dst_size);
            let sz = compress::decompress(src_buf, dst_buf.as_mut_slice())?;
            result = if sz != dst_size {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "Decompression failed. Input invalid or too long?",
                ))
            } else {
                copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size)
            };
        } else {
            // Allocate a buffer to received the compressed data without zeroing
            let src_size = chunk.compress_size() as usize;
            let mut src_buf = DataBuf::alloc(src_size);
            self.backend.read(
                blob_id,
                src_buf.as_mut_slice(),
                chunk.blob_compress_offset(),
            )?;

            // Allocate a buffer to received the decompressed data without zeroing
            let dst_size = bio.blksize as usize;
            let mut dst_buf = DataBuf::alloc(dst_size);
            let sz = compress::decompress(src_buf.as_mut_slice(), dst_buf.as_mut_slice())?;
            result = if sz != dst_size {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "Decompression failed. Input invalid or too long?",
                ))
            } else {
                copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size)
            };
        }

        result
    }

    fn write(&self, blob_id: &str, blk: Arc<dyn RafsChunkInfo>, buf: &[u8]) -> Result<usize> {
        self.backend.write(blob_id, buf, blk.blob_compress_offset())
    }

    fn release(&mut self) {
        self.backend.close();
    }
}

pub fn new(backend: Box<dyn BlobBackend + Sync + Send>) -> Result<DummyCache> {
    Ok(DummyCache { backend })
}
