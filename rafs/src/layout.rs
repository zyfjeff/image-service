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
const RAFS_INODE_INFO_SIZE: usize = 512;
const RAFS_CHUNK_INFO_SIZE: usize = 136;

pub trait RafsLayoutLoadStore {
    // load rafs ondisk metadata in packed format
    fn load<R: Read>(&mut self, r: &mut R) -> Result<usize>;

    // store rafs ondisk metadata in a packed format
    fn store<W: Write>(&self, w: W) -> Result<usize>;
}

// Ondisk rafs inode, 512 bytes
pub struct RafsInodeInfo {
    pub name: String,   //[char; MAX_RAFS_NAME + 1],
    pub digest: String, //[char; RAFS_SHA256_LENGTH],
    pub i_parent: u64,
    pub i_ino: u64,
    pub i_mode: u32,
    pub i_uid: u32,
    pub i_gid: u32,
    pub i_rdev: u64,
    pub i_size: u64,
    pub i_nlink: u64,
    pub i_blocks: u64,
    pub i_atime: u64,
    pub i_mtime: u64,
    pub i_ctime: u64,
    pub i_chunk_cnt: u64,
    pub i_flags: u64,
}

impl RafsInodeInfo {
    pub fn new() -> Self {
        RafsInodeInfo {
            name: String::from(""),
            digest: String::from(""),
            i_parent: 0,
            i_ino: 0,
            i_mode: 0,
            i_uid: 0,
            i_gid: 0,
            i_flags: 0,
            i_rdev: 0,
            i_size: 0,
            i_nlink: 0,
            i_blocks: 0,
            i_atime: 0,
            i_mtime: 0,
            i_ctime: 0,
            i_chunk_cnt: 0,
        }
    }
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
    fn load<R: Read>(&mut self, r: &mut R) -> Result<usize> {
        let mut input = [0; RAFS_INODE_INFO_SIZE];
        r.read_exact(&mut input)?;

        // Now we know input has enough bytes to fill in RafsInodeInfo
        self.name = read_string(&mut &input[..], MAX_RAFS_NAME + 1)?;
        self.digest = read_string(&mut &input[..], RAFS_SHA256_LENGTH)?;
        self.i_parent = read_le_u64(&mut &input[..]);
        self.i_ino = read_le_u64(&mut &input[..]);
        self.i_mode = read_le_u32(&mut &input[..]);
        self.i_uid = read_le_u32(&mut &input[..]);
        self.i_gid = read_le_u32(&mut &input[..]);
        self.i_rdev = read_le_u64(&mut &input[..]);
        self.i_size = read_le_u64(&mut &input[..]);
        self.i_nlink = read_le_u64(&mut &input[..]);
        self.i_blocks = read_le_u64(&mut &input[..]);
        self.i_atime = read_le_u64(&mut &input[..]);
        self.i_mtime = read_le_u64(&mut &input[..]);
        self.i_ctime = read_le_u64(&mut &input[..]);
        self.i_chunk_cnt = read_le_u64(&mut &input[..]);
        self.i_flags = read_le_u64(&mut &input[..]);

        Ok(RAFS_INODE_INFO_SIZE)
    }

    fn store<W: Write>(&self, mut w: W) -> Result<usize> {
        let mut count = w.write(self.name.as_bytes())?;
        count += w.write(self.digest.as_bytes())?;
        count += w.write(&u64::to_le_bytes(self.i_parent))?;
        count += w.write(&u64::to_le_bytes(self.i_ino))?;
        count += w.write(&u32::to_le_bytes(self.i_mode))?;
        count += w.write(&u32::to_le_bytes(self.i_uid))?;
        count += w.write(&u32::to_le_bytes(self.i_gid))?;
        count += w.write(&u64::to_le_bytes(self.i_rdev))?;
        count += w.write(&u64::to_le_bytes(self.i_size))?;
        count += w.write(&u64::to_le_bytes(self.i_nlink))?;
        count += w.write(&u64::to_le_bytes(self.i_blocks))?;
        count += w.write(&u64::to_le_bytes(self.i_atime))?;
        count += w.write(&u64::to_le_bytes(self.i_mtime))?;
        count += w.write(&u64::to_le_bytes(self.i_ctime))?;
        count += w.write(&u64::to_le_bytes(self.i_chunk_cnt))?;
        count += w.write(&u64::to_le_bytes(self.i_flags))?;
        w.write(&vec![0; RAFS_INODE_INFO_SIZE - count])?;
        Ok(RAFS_INODE_INFO_SIZE)
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
        }
    }
}

impl RafsLayoutLoadStore for RafsSuperBlockInfo {
    fn load<R: Read>(&mut self, r: &mut R) -> Result<usize> {
        let mut input = [0; RAFS_SUPERBLOCK_SIZE];
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
        Ok(RAFS_SUPERBLOCK_SIZE)
    }

    fn store<W: Write>(&self, mut w: W) -> Result<usize> {
        let mut count = w.write(&u64::to_le_bytes(self.s_inodes_count))?;
        count += w.write(&u64::to_le_bytes(self.s_blocks_count))?;
        count += w.write(&u16::to_le_bytes(self.s_inode_size))?;
        count += w.write(&u16::to_le_bytes(0))?;
        count += w.write(&u32::to_le_bytes(self.s_block_size))?;
        count += w.write(&u16::to_le_bytes(self.s_fs_version))?;
        count += w.write(&u16::to_le_bytes(0))?;
        count += w.write(&u32::to_le_bytes(self.s_magic))?;
        w.write(&vec![0; RAFS_SUPERBLOCK_SIZE - count])?;
        Ok(RAFS_SUPERBLOCK_SIZE)
    }
}

// Ondis rafs chunk, 136 bytes
#[derive(Default)]
pub struct RafsChunkInfo {
    pub blockid: String, // [char; RAFS_SHA256_LENGTH],
    pub blobid: String,  // [char; RAFS_BLOB_ID_MAX_LENGTH],
    pub pos: u64,
    pub len: u32,
    pub offset: u64,
    pub size: u32,
    reserved: u64,
}

impl RafsChunkInfo {
    pub fn new() -> Self {
        RafsChunkInfo {
            ..Default::default()
        }
    }
}

impl RafsLayoutLoadStore for RafsChunkInfo {
    fn load<R: Read>(&mut self, r: &mut R) -> Result<usize> {
        let mut input = [0; RAFS_CHUNK_INFO_SIZE];
        r.read_exact(&mut input)?;

        // Now we know there is enough bytes to fill RafsChunkInfo
        self.blockid = read_string(&mut &input[..], RAFS_SHA256_LENGTH)?;
        self.blobid = read_string(&mut &input[..], RAFS_BLOB_ID_MAX_LENGTH)?;
        self.pos = read_le_u64(&mut &input[..]);
        self.len = read_le_u32(&mut &input[..]);
        self.offset = read_le_u64(&mut &input[..]);
        self.size = read_le_u32(&mut &input[..]);

        Ok(RAFS_CHUNK_INFO_SIZE)
    }

    fn store<W: Write>(&self, mut w: W) -> Result<usize> {
        w.write(self.blockid.as_bytes())?;
        w.write(self.blobid.as_bytes())?;
        w.write(&u64::to_le_bytes(self.pos))?;
        w.write(&u32::to_le_bytes(self.len))?;
        w.write(&u64::to_le_bytes(self.offset))?;
        w.write(&u32::to_le_bytes(self.size))?;
        w.write(&u64::to_le_bytes(0))?;
        Ok(RAFS_CHUNK_INFO_SIZE)
    }
}
