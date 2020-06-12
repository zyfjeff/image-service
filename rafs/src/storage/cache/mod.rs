// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::Arc;

use crate::metadata::RafsChunkInfo;
use crate::metadata::RafsSuperMeta;
use crate::storage::compress;

use vm_memory::VolatileSlice;

pub mod blobcache;
pub mod dummycache;

// Rafs blob IO info
pub struct RafsBio {
    /// reference to the chunk
    pub chunkinfo: Arc<dyn RafsChunkInfo>,
    /// blob id of chunk
    pub blob_id: String,
    /// compression algorithm of chunk
    pub compressor: compress::Algorithm,
    /// offset within the chunk
    pub offset: u32,
    /// size within the chunk
    pub size: usize,
    /// block size to read in one shot
    pub blksize: u32,
}

impl RafsBio {
    pub fn new(
        chunkinfo: Arc<dyn RafsChunkInfo>,
        blob_id: String,
        compressor: compress::Algorithm,
        offset: u32,
        size: usize,
        blksize: u32,
    ) -> Self {
        RafsBio {
            chunkinfo,
            blob_id,
            compressor,
            offset,
            size,
            blksize,
        }
    }
}

pub trait RafsCache {
    // whether has a block data
    fn has(&self, blk: Arc<dyn RafsChunkInfo>) -> bool;

    // do init after super block loaded
    fn init(&mut self, sb_info: &RafsSuperMeta) -> Result<()>;

    // evict block data
    fn evict(&self, blk: Arc<dyn RafsChunkInfo>) -> Result<()>;

    // flush cache
    fn flush(&self) -> Result<()>;

    // read a chunk data through cache, always used in decompressed cache
    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize>;

    // write a chunk data through cache
    fn write(&self, blob_id: &str, blk: Arc<dyn RafsChunkInfo>, buf: &[u8]) -> Result<usize>;

    // release cache
    fn release(&mut self);
}
