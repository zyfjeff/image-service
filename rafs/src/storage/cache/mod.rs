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
    // whether has a block data
    fn has(&self, blk: Arc<dyn RafsChunkInfo>) -> bool;

    // do init after super block loaded
    fn init(&self, sb_info: &RafsSuperMeta, blobs: &[OndiskBlobTableEntry]) -> Result<()>;

    // evict block data
    fn evict(&self, blk: Arc<dyn RafsChunkInfo>) -> Result<()>;

    // flush cache
    fn flush(&self) -> Result<()>;

    // read a chunk data through cache, always used in decompressed cache
    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize>;

    // write a chunk data through cache
    fn write(&self, blob_id: &str, blk: &Arc<dyn RafsChunkInfo>, buf: &[u8]) -> Result<usize>;

    fn prefetch(&self, bio: &mut [RafsBio]) -> Result<usize>;

    // release cache
    fn release(&self);

    #[allow(clippy::borrowed_box)]
    fn backend(&self) -> &Box<dyn BlobBackend + Sync + Send>;

    // read a chunk from backend
    // decompress chunk if necessary
    // validate chunk digest if necessary
    fn read_from_backend<'a>(
        &self,
        blob_id: &str,
        chunk: &Arc<dyn RafsChunkInfo>,
        src_buf: &'a mut [u8],
        mut dst_buf: &'a mut [u8],
        chunk_validate: bool,
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

        if chunk_validate && !digest_check(dst_buf, chunk.block_id()) {
            return Err(eio!("failed to validate backend data"));
        }

        Ok(dst_buf.len())
    }
}
