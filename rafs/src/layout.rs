// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Rafs ondisk layout structures.

use std::convert::TryInto;
use std::io::{Error, Read, Result, Write};
use std::str;

const MAX_RAFS_NAME: usize = 255;
const RAFS_SHA256_LENGTH: usize = 32;
const RAFS_BLOB_ID_MAX_LENGTH: usize = 72;
const RAFS_SUPERBLOCK_SIZE: usize = 8192;

pub trait RafsLayoutLoadStore {
    // load rafs ondisk metadata in packed format
    fn load<R: Read>(&mut self, r: R) -> Result<usize>;

    // store rafs ondisk metadata in a packed format
    fn store<W: Write>(&self, w: W) -> Result<usize>;
}

// Ondisk rafs inode, 512 bytes
struct RafsInodeInfo {
    name: String,   //[char; MAX_RAFS_NAME + 1],
    digest: String, //[char; RAFS_SHA256_LENGTH],
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
    i_reserved: [u8; 120],
}

fn read_le_u64(input: &mut &[u8]) -> u64 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u64>());
    *input = rest;
    u64::from_le_bytes(int_bytes.try_into().unwrap())
}

fn read_le_u32(input: &mut &[u8]) -> u32 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u32>());
    *input = rest;
    u32::from_le_bytes(int_bytes.try_into().unwrap())
}

fn read_le_u16(input: &mut &[u8]) -> u16 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u16>());
    *input = rest;
    u16::from_le_bytes(int_bytes.try_into().unwrap())
}

fn read_string(input: &mut &[u8], count: usize) -> Result<String> {
    let (buf, rest) = input.split_at(count);
    *input = rest;
    match str::from_utf8(&buf) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => Err(Error::from_raw_os_error(libc::EINVAL)),
    }
}

impl RafsLayoutLoadStore for RafsInodeInfo {
    fn load<R: Read>(&mut self, mut r: R) -> Result<usize> {
        let mut input = [0; 512];
        r.read_exact(&mut input)?;

        // Now we know input has enough bytes to fill in RafsInodeInfo
        self.name = read_string(&mut &input[..], MAX_RAFS_NAME + 1)?;
        self.digest = read_string(&mut &input[..], RAFS_SHA256_LENGTH)?;
        self.i_parent = read_le_u64(&mut &input[..]);
        self.i_ino = read_le_u64(&mut &input[..]);
        self.i_mode = read_le_u32(&mut &input[..]);
        self.i_uid = read_le_u32(&mut &input[..]);
        self.i_gid = read_le_u32(&mut &input[..]);
        self.i_flags = read_le_u32(&mut &input[..]);
        self.i_rdev = read_le_u64(&mut &input[..]);
        self.i_size = read_le_u64(&mut &input[..]);
        self.i_nlink = read_le_u64(&mut &input[..]);
        self.i_blocks = read_le_u64(&mut &input[..]);
        self.i_atime = read_le_u64(&mut &input[..]);
        self.i_mtime = read_le_u64(&mut &input[..]);
        self.i_ctime = read_le_u64(&mut &input[..]);
        self.i_chunk_cnt = read_le_u64(&mut &input[..]);

        Ok(512)
    }

    fn store<W: Write>(&self, mut w: W) -> Result<usize> {
        w.write(self.name.as_bytes())?;
        w.write(self.digest.as_bytes())?;
        w.write(&u64::to_le_bytes(self.i_parent))?;
        w.write(&u64::to_le_bytes(self.i_ino))?;
        w.write(&u32::to_le_bytes(self.i_mode))?;
        w.write(&u32::to_le_bytes(self.i_uid))?;
        w.write(&u32::to_le_bytes(self.i_gid))?;
        w.write(&u32::to_le_bytes(self.i_flags))?;
        w.write(&u64::to_le_bytes(self.i_rdev))?;
        w.write(&u64::to_le_bytes(self.i_size))?;
        w.write(&u64::to_le_bytes(self.i_nlink))?;
        w.write(&u64::to_le_bytes(self.i_blocks))?;
        w.write(&u64::to_le_bytes(self.i_atime))?;
        w.write(&u64::to_le_bytes(self.i_mtime))?;
        w.write(&u64::to_le_bytes(self.i_ctime))?;
        w.write(&u64::to_le_bytes(self.i_chunk_cnt))?;
        w.write(&vec![0; 120])?;
        Ok(0)
    }
}

// Ondisk rafs superblock, 8192 bytes
pub struct RafsSuperBlockInfo {
    pub s_inodes_count: u64,
    pub s_blocks_count: u64,
    pub s_inode_size: u16,
    pub s_padding1: u16,
    pub s_block_size: u32,
    pub s_fs_version: u16,
    pub s_pandding2: u16,
    pub s_magic: u32,
    pub s_reserved: [u8; 8259],
}

impl RafsSuperBlockInfo {
    pub fn new() -> Self {
        RafsSuperBlockInfo {
            s_inodes_count: 0,
            s_blocks_count: 0,
            s_inode_size: 0,
            s_padding1: 0,
            s_block_size: 0,
            s_fs_version: 0,
            s_pandding2: 0,
            s_magic: 0,
            s_reserved: [0u8; 8259],
        }
    }
}

impl RafsLayoutLoadStore for RafsSuperBlockInfo {
    fn load<R: Read>(&mut self, mut r: R) -> Result<usize> {
        let mut input = [0; 8192];
        r.read_exact(&mut input)?;

        // Now we know input has enough bytes to load RafsSuperBlockInfo
        self.s_inodes_count = read_le_u64(&mut &input[..]);
        self.s_blocks_count = read_le_u64(&mut &input[..]);
        self.s_inode_size = read_le_u16(&mut &input[..]);
        read_le_u16(&mut &input[..]);
        self.s_block_size = read_le_u32(&mut &input[..]);
        self.s_fs_version = read_le_u16(&mut &input[..]);
        read_le_u16(&mut &input[..]);
        self.s_magic = read_le_u32(&mut &input[..]);
        Ok(8192)
    }

    fn store<W: Write>(&self, mut w: W) -> Result<usize> {
        w.write(&u64::to_le_bytes(self.s_inodes_count))?;
        w.write(&u64::to_le_bytes(self.s_blocks_count))?;
        w.write(&u16::to_le_bytes(self.s_inode_size))?;
        w.write(&u16::to_le_bytes(0))?;
        w.write(&u32::to_le_bytes(self.s_block_size))?;
        w.write(&u16::to_le_bytes(self.s_fs_version))?;
        w.write(&u16::to_le_bytes(0))?;
        w.write(&u32::to_le_bytes(self.s_magic))?;
        w.write(&vec![0; 8259])?;
        Ok(0)
    }
}

// Ondis rafs chunk, 136 bytes
struct RafsChunkInfo {
    blockid: String, // [char; RAFS_SHA256_LENGTH],
    blobid: String,  // [char; RAFS_BLOB_ID_MAX_LENGTH],
    pos: u64,
    len: u32,
    offset: u64,
    size: u32,
    reserved: u64,
}

impl RafsLayoutLoadStore for RafsChunkInfo {
    fn load<R: Read>(&mut self, mut r: R) -> Result<usize> {
        let mut input = [0; 136];
        r.read_exact(&mut input)?;

        // Now we know there is enough bytes to fill RafsChunkInfo
        self.blockid = read_string(&mut &input[..], RAFS_SHA256_LENGTH)?;
        self.blobid = read_string(&mut &input[..], RAFS_BLOB_ID_MAX_LENGTH)?;
        self.pos = read_le_u64(&mut &input[..]);
        self.len = read_le_u32(&mut &input[..]);
        self.offset = read_le_u64(&mut &input[..]);
        self.size = read_le_u32(&mut &input[..]);

        Ok(136)
    }

    fn store<W: Write>(&self, mut w: W) -> Result<usize> {
        w.write(self.blockid.as_bytes())?;
        w.write(self.blobid.as_bytes())?;
        w.write(&u64::to_le_bytes(self.pos))?;
        w.write(&u32::to_le_bytes(self.len))?;
        w.write(&u64::to_le_bytes(self.offset))?;
        w.write(&u32::to_le_bytes(self.size))?;
        w.write(&u64::to_le_bytes(0))?;
        Ok(0)
    }
}
