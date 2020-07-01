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

    #[allow(clippy::borrowed_box)]
    fn backend(&self) -> &Box<dyn BlobBackend + Sync + Send>;

    // read a chunk from backend and check chunk digest
    fn read_from_backend(
        &self,
        blob_id: &str,
        src_buf: &mut [u8],
        dst_buf: &mut [u8],
        offset: u64,
        compressed: bool,
    ) -> Result<usize> {
        self.backend().read(blob_id, src_buf, offset)?;
        if compressed {
            compress::decompress(src_buf, dst_buf)?;
        }
        Ok(dst_buf.len())
    }

    // write a chunk data through cache
    fn write(&self, blob_id: &str, blk: &Arc<dyn RafsChunkInfo>, buf: &[u8]) -> Result<usize>;

    fn prefetch(&self, bio: &mut [RafsBio]) -> Result<usize>;

    // release cache
    fn release(&self);
}
