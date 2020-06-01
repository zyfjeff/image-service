// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be
// found in the LICENSE file.

#[cfg(feature = "fusedev")]
#[macro_use]
extern crate log;
#[cfg(feature = "fusedev")]
pub mod fuse;
#[cfg(feature = "fusedev")]
pub use self::fuse::{FuseChannel, FuseSession};

use lz4 as liblz4;
use std::io::Result;

/*
#[allow(dead_code)]
fn compress_with_lz4_old(src: &[u8], dst: &mut Vec<u8>) -> Result<usize> {
    Ok(LZ4::encode_block(src, dst))
}

#[allow(dead_code)]
fn decompress_with_lz4_old(src: &[u8], dst: &mut Vec<u8>) -> Result<usize> {
    Ok(LZ4::decode_block(src, dst))
}

#[allow(dead_code)]
fn compress_with_lz4(src: &Vec<u8>) -> Result<Vec<u8>> {
    Ok(lz4_compress::compress(src.as_slice()))
}

#[allow(dead_code)]
fn decompress_with_lz4(src: &[u8]) -> Result<Vec<u8>> {
    lz4_compress::decompress(src).map_err(|e| Error::new(ErrorKind::InvalidData, format!("{}", e)))
}

#[allow(dead_code)]
fn compression_lz4(src: &Vec<u8>) -> Result<Vec<u8>> {
    Ok(prelude::compress(src))
}

#[allow(dead_code)]
fn decompression_lz4(src: &Vec<u8>) -> Result<Vec<u8>> {
    prelude::decompress(src).map_err(|e| Error::new(ErrorKind::InvalidData, format!("{:?}", e)))
}
*/

// compression format:
// 1. Default ratio
// 2. No prepend size
fn compress_liblz4(input: &[u8]) -> Result<Vec<u8>> {
    liblz4::block::compress(input, None, false)
}

// Size must be provided otherwise the rust binding tries
// to guess the size as if it were prepended and fail
fn decompress_liblz4(input: &[u8], blksize: u32) -> Result<Vec<u8>> {
    liblz4::block::decompress(input, Some(blksize as i32))
}

// For compatibility reason, we use liblz4 version to compress/decompress directly
// with data blocks so that we don't really care about lz4 header magic numbers like
// as being done with all these rust lz4 implementations
pub fn compress(src: &[u8]) -> Result<Vec<u8>> {
    compress_liblz4(src)
}

pub fn decompress(src: &[u8], blksize: u32) -> Result<Vec<u8>> {
    decompress_liblz4(src, blksize)
}

pub fn log_level_to_verbosity(level: log::LevelFilter) -> usize {
    level as usize - 1
}

pub fn div_round_up(n: u64, d: u64) -> u64 {
    (n + d - 1) / d
}
