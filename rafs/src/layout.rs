// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Rafs ondisk layout structures.

use std::io::{Read, Result, Write};

const MAX_RAFS_NAME: usize = 255;
const RAFS_SHA256_LENGTH: usize = 32;
const RAFS_BLOB_ID_MAX_LENGTH: usize = 72;
const RAFS_SUPERBLOCK_SIZE: usize = 8192;

trait RafsLayoutLoadStore {
    // load rafs ondisk metadata in packed format
    fn load<R: Read>(&self, r: R) -> Result<usize>;

    // store rafs ondisk metadata in a packed format
    fn store<W: Write>(&self, w: W) -> Result<usize>;
}

// Ondisk rafs inode, 512 bytes
struct RafsInodeInfo {
    name: [char; MAX_RAFS_NAME + 1],
    digest: [char; RAFS_SHA256_LENGTH],
    i_parent: u64,
    i_ino: u64,
    i_mode: u32,
    i_uid: u32,
    i_gid: u32,
    i_flags: u32,
    i_rdev: u64,
    i_size: u64,
    i_nlink: u64,
    i_blocks: u64,
    i_atime: u64,
    i_mtime: u64,
    i_ctime: u64,
    i_chunk_cnt: u64,
    i_reserved: [char; 120],
}

impl RafsLayoutLoadStore for RafsInodeInfo {
    fn load<R: Read>(&self, _r: R) -> Result<usize> {
        Ok(0)
    }

    fn store<W: Write>(&self, _w: W) -> Result<usize> {
        Ok(0)
    }
}

// Ondisk rafs superblock, 8192 bytes
#[derive(Copy, Clone)]
struct RafsSuperBlockInfo {
    s_inodes_count: u64,
    s_blocks_count: u64,
    s_inode_size: u16,
    s_padding1: [char; 2],
    s_block_size: u32,
    s_fs_version: u16,
    s_pandding2: [char; 2],
    s_magic: u32,
    s_reserved: [char; 8259],
}

impl RafsLayoutLoadStore for RafsSuperBlockInfo {
    fn load<R: Read>(&self, _r: R) -> Result<usize> {
        Ok(0)
    }

    fn store<W: Write>(&self, _w: W) -> Result<usize> {
        Ok(0)
    }
}

// Ondis rafs chunk
#[derive(Copy, Clone)]
struct RafsChunkInfo {
    blockid: [char; RAFS_SHA256_LENGTH],
    blobid: [char; RAFS_BLOB_ID_MAX_LENGTH],
    pos: u64,
    len: u32,
    offset: u64,
    size: u32,
    reserved: u64,
}

impl RafsLayoutLoadStore for RafsChunkInfo {
    fn load<R: Read>(&self, _r: R) -> Result<usize> {
        Ok(0)
    }

    fn store<W: Write>(&self, _w: W) -> Result<usize> {
        Ok(0)
    }
}
