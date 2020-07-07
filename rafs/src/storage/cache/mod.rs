// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::Arc;

use vm_memory::VolatileSlice;

use crate::metadata::layout::OndiskBlobTableEntry;
use crate::metadata::{RafsChunkInfo, RafsSuperMeta};
use crate::storage::backend::BlobBackend;
use crate::storage::compress;
use crate::storage::device::RafsBio;
use crate::storage::utils::digest_check;

use nydus_utils::eio;

pub mod blobcache;
pub mod dummycache;

pub trait RafsCache {
    /// Whether has block data
    fn has(&self, blk: Arc<dyn RafsChunkInfo>) -> bool;

    /// Do init after super block loaded
    fn init(&self, sb_info: &RafsSuperMeta, blobs: &[OndiskBlobTableEntry]) -> Result<()>;

    /// Evict block data
    fn evict(&self, blk: Arc<dyn RafsChunkInfo>) -> Result<()>;

    /// Flush cache
    fn flush(&self) -> Result<()>;

    /// Read a chunk data through cache, always used in decompressed cache
    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize>;

    /// Write a chunk data through cache
    fn write(&self, blob_id: &str, blk: &dyn RafsChunkInfo, buf: &[u8]) -> Result<usize>;

    fn prefetch(&self, bio: &mut [RafsBio]) -> Result<usize>;

    /// Release cache
    fn release(&self);

    fn backend(&self) -> &(dyn BlobBackend + Sync + Send);

    /// 1. Read a chunk from backend
    /// 2. Decompress chunk if necessary
    /// 3. Validate chunk digest if necessary
    fn read_by_chunk<'a>(
        &self,
        blob_id: &str,
        chunk: &dyn RafsChunkInfo,
        src_buf: &'a mut [u8],
        mut dst_buf: &'a mut [u8],
        digest_validate: bool,
    ) -> Result<usize> {
        let c_offset = chunk.compress_offset();
        let d_size = chunk.decompress_size() as usize;

        self.backend().read(blob_id, src_buf, c_offset)?;
        if dst_buf.is_empty() {
            dst_buf = src_buf;
        } else {
            compress::decompress(src_buf, dst_buf)?;
        }

        if dst_buf.len() != d_size {
            return Err(eio!("invalid backend data"));
        }

        if digest_validate && !digest_check(dst_buf, &chunk.block_id()) {
            return Err(eio!("failed to validate backend data"));
        }

        Ok(dst_buf.len())
    }
}
