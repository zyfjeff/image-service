// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::Arc;

use crate::metadata::RafsChunkInfo;
use crate::metadata::RafsSuperMeta;
use crate::storage::device::RafsBuffer;

pub mod blobcache;
pub mod dummycache;

pub trait RafsCache {
    // whether has a block data
    fn has(&self, blk: Arc<dyn RafsChunkInfo>) -> bool;

    // do init after super block loaded
    fn init(&mut self, sb_info: &RafsSuperMeta) -> io::Result<()>;

    // evict block data
    fn evict(&self, blk: Arc<dyn RafsChunkInfo>) -> io::Result<()>;

    // flush cache
    fn flush(&self) -> io::Result<()>;

    // read a chunk data through cache, always used in compressed cache
    // TODO: interface for decompressed cache with zero copy
    fn read(&self, blob_id: &str, blk: Arc<dyn RafsChunkInfo>) -> io::Result<RafsBuffer>;

    // write a chunk data through cache
    fn write(&self, blob_id: &str, blk: Arc<dyn RafsChunkInfo>, buf: &[u8]) -> io::Result<usize>;

    // release cache
    fn release(&mut self);
}
