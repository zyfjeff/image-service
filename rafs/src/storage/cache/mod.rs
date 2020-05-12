// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::fs::RafsBlk;
use std::io;

pub mod blobcache;
pub mod dummycache;

pub trait RafsCache {
    /* whether has a block data */
    fn has(&self, blk: &RafsBlk) -> bool;

    /* evict block data */
    fn evict(&self, blk: &RafsBlk) -> io::Result<()>;

    /* flush cache */
    fn flush(&self) -> io::Result<()>;

    /* read a chunk data through cache, always used in compressed cache */
    /* TODO: interface for decompressed cache with zero copy */
    fn read(&self, blk: &RafsBlk) -> io::Result<Vec<u8>>;

    /* write a chunk data through cache */
    fn write(&self, blk: &RafsBlk, buf: &[u8]) -> io::Result<usize>;

    /* whether cache store compressed data or not */
    fn compressed(&self) -> bool;

    /* release cache */
    fn release(&mut self);
}
