// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Rafs ondisk layout structures.

use std::convert::TryInto;
use std::fmt;
use std::io::{Error, Read, Result, Write};
use std::str;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

pub const MAX_RAFS_NAME: usize = 255;
pub const RAFS_SHA256_LENGTH: usize = 32;
pub const RAFS_BLOB_ID_MAX_LENGTH: usize = 72;

pub const RAFS_SUPER_VERSION: usize = 0x2;
pub const RAFS_SUPERBLOCK_SIZE: usize = 8192;
pub const RAFS_INODE_INFO_SIZE: usize = 512;
pub const RAFS_CHUNK_INFO_SIZE: usize = 136;

pub const DEFAULT_RAFS_BLOCK_SIZE: usize = 1024 * 1024;
pub const RAFS_SUPER_MAGIC: u32 = 0x52414653;

pub trait RafsLayoutLoadStore {
    // load rafs ondisk metadata in packed format
    fn load<R: Read>(&mut self, r: &mut R) -> Result<usize>;

    // store rafs ondisk metadata in a packed format
    fn store<W: Write>(&self, w: W) -> Result<usize>;
}

// Ondisk rafs inode, 512 bytes
#[derive(Clone, Default, Debug)]
pub struct RafsInodeInfo {
    pub name: String,       //[char; MAX_RAFS_NAME + 1],
    pub digest: RafsDigest, //[char; RAFS_SHA256_LENGTH],
    pub i_parent: u64,
    pub i_ino: u64,
    pub i_mode: u32,
    pub i_uid: u32,
    pub i_gid: u32,
    pub i_padding: u32,
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
            ..Default::default()
        }
    }
}

impl fmt::Display for RafsInodeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "inode name: {}, digest: {}, ino: {})",
            &self.name, &self.digest, self.i_ino
        )
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

fn read_rafs_digest(input: &mut &[u8]) -> Result<RafsDigest> {
    let (buf, rest) = input.split_at(RafsDigest::size());
    *input = rest;
    let mut d = RafsDigest::new();
    d.data.clone_from_slice(&buf);
    Ok(d)
}

impl RafsLayoutLoadStore for RafsInodeInfo {
    fn load<R: Read>(&mut self, r: &mut R) -> Result<usize> {
        let mut input = [0u8; RAFS_INODE_INFO_SIZE];
        r.read_exact(&mut input)?;
        let mut p = &input[..];

        // Now we know input has enough bytes to fill in RafsInodeInfo
        self.name = read_string(&mut p, MAX_RAFS_NAME + 1)?;
        self.digest = read_rafs_digest(&mut p)?;
        self.i_parent = read_le_u64(&mut p);
        self.i_ino = read_le_u64(&mut p);
        self.i_mode = read_le_u32(&mut p);
        self.i_uid = read_le_u32(&mut p);
        self.i_gid = read_le_u32(&mut p);
        self.i_padding = read_le_u32(&mut p);
        self.i_rdev = read_le_u64(&mut p);
        self.i_size = read_le_u64(&mut p);
        self.i_nlink = read_le_u64(&mut p);
        self.i_blocks = read_le_u64(&mut p);
        self.i_atime = read_le_u64(&mut p);
        self.i_mtime = read_le_u64(&mut p);
        self.i_ctime = read_le_u64(&mut p);
        self.i_chunk_cnt = read_le_u64(&mut p);
        self.i_flags = read_le_u64(&mut p);
        trace!("loaded inode: {}", &self);

        Ok(RAFS_INODE_INFO_SIZE)
    }

    fn store<W: Write>(&self, mut w: W) -> Result<usize> {
        let mut count = w.write(self.name.as_bytes())?;
        count += w.write(&self.digest.data[..])?;
        count += w.write(&u64::to_le_bytes(self.i_parent))?;
        count += w.write(&u64::to_le_bytes(self.i_ino))?;
        count += w.write(&u32::to_le_bytes(self.i_mode))?;
        count += w.write(&u32::to_le_bytes(self.i_uid))?;
        count += w.write(&u32::to_le_bytes(self.i_gid))?;
        count += w.write(&u32::to_le_bytes(self.i_padding))?;
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
        trace!("written inode: {}", &self);
        Ok(RAFS_INODE_INFO_SIZE)
    }
}

// Ondisk rafs superblock, 8192 bytes
#[derive(Copy, Clone, Default, Debug)]
pub struct RafsSuperBlockInfo {
    /// inode count
    pub s_inodes_count: u64,
    /// blocks count
    pub s_blocks_count: u64,
    /// inode size
    pub s_inode_size: u16,
    pub s_padding1: u16,
    /// block size
    pub s_block_size: u32,
    /// RAFS version
    pub s_fs_version: u16,
    pub s_pandding2: u16,
    /// RAFS super magic
    pub s_magic: u32,
}

impl RafsSuperBlockInfo {
    pub fn new() -> Self {
        RafsSuperBlockInfo {
            ..Default::default()
        }
    }
}

impl fmt::Display for RafsSuperBlockInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "superblock magic: {}, version: {}, {} {} {} {}",
            &self.s_magic,
            self.s_fs_version,
            self.s_inodes_count,
            self.s_blocks_count,
            self.s_inode_size,
            self.s_block_size
        )
    }
}

impl RafsLayoutLoadStore for RafsSuperBlockInfo {
    fn load<R: Read>(&mut self, r: &mut R) -> Result<usize> {
        let mut input = [0u8; RAFS_SUPERBLOCK_SIZE];
        r.read_exact(&mut input)?;
        let mut p = &input[..];

        // Now we know input has enough bytes to load RafsSuperBlockInfo
        self.s_inodes_count = read_le_u64(&mut p);
        self.s_blocks_count = read_le_u64(&mut p);
        self.s_inode_size = read_le_u16(&mut p);
        read_le_u16(&mut p);
        self.s_block_size = read_le_u32(&mut p);
        self.s_fs_version = read_le_u16(&mut p);
        read_le_u16(&mut p);
        self.s_magic = read_le_u32(&mut p);
        trace!("loaded superblock: {}", &self);
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
        trace!("written superblock: {}", &self);
        Ok(RAFS_SUPERBLOCK_SIZE)
    }
}

// Ondisk rafs chunk, 136 bytes
#[derive(Clone, Default, Debug)]
pub struct RafsChunkInfo {
    pub blockid: RafsDigest, // [char; RAFS_SHA256_LENGTH],
    pub blobid: String,      // [char; RAFS_BLOB_ID_MAX_LENGTH],
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

impl fmt::Display for RafsChunkInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "chunkinfo blockid: {}, blobid: {} pos: {}, len: {}, offset: {}, size: {}",
            &self.blockid, &self.blobid, self.pos, self.len, self.offset, self.size
        )
    }
}

impl RafsLayoutLoadStore for RafsChunkInfo {
    fn load<R: Read>(&mut self, r: &mut R) -> Result<usize> {
        let mut input = [0u8; RAFS_CHUNK_INFO_SIZE];
        trace!("loading chunk");
        r.read_exact(&mut input)?;
        let mut p = &input[..];

        // Now we know there is enough bytes to fill RafsChunkInfo
        self.blockid = read_rafs_digest(&mut p)?;
        self.blobid = read_string(&mut p, RAFS_BLOB_ID_MAX_LENGTH)?;
        self.pos = read_le_u64(&mut p);
        self.len = read_le_u32(&mut p);
        self.offset = read_le_u64(&mut p);
        self.size = read_le_u32(&mut p);
        trace!("loaded chunk: {}", &self);

        Ok(RAFS_CHUNK_INFO_SIZE)
    }

    fn store<W: Write>(&self, mut w: W) -> Result<usize> {
        w.write(&self.blockid.data[..])?;
        w.write(self.blobid.as_bytes())?;
        w.write(&u64::to_le_bytes(self.pos))?;
        w.write(&u32::to_le_bytes(self.len))?;
        w.write(&u64::to_le_bytes(self.offset))?;
        w.write(&u32::to_le_bytes(self.size))?;
        w.write(&u64::to_le_bytes(0))?;
        trace!("written chunk: {}", &self);
        Ok(RAFS_CHUNK_INFO_SIZE)
    }
}

// symlink data, aligned with size of RafsChunkInfo
#[derive(Clone, Default, Debug)]
pub struct RafsLinkDataInfo {
    pub target: String,
    pub ondisk_size: usize,
}

impl RafsLinkDataInfo {
    pub fn new(cnt: usize) -> Self {
        RafsLinkDataInfo {
            target: String::from(""),
            ondisk_size: cnt * RAFS_CHUNK_INFO_SIZE,
        }
    }
}

impl RafsLayoutLoadStore for RafsLinkDataInfo {
    fn load<R: Read>(&mut self, r: &mut R) -> Result<usize> {
        let mut input = vec![0; libc::PATH_MAX as usize];
        r.read_exact(&mut input[..self.ondisk_size])?;
        let mut p = &input[..];

        self.target = read_string(&mut p, self.ondisk_size + 1)?;
        Ok(self.ondisk_size)
    }

    fn store<W: Write>(&self, mut w: W) -> Result<usize> {
        let count = w.write(self.target.as_bytes())?;
        w.write(&vec![0; self.ondisk_size - count])?;
        Ok(self.ondisk_size)
    }
}

#[derive(Default, Debug, Clone)]
pub struct RafsDigest {
    data: [u8; RAFS_SHA256_LENGTH],
}

impl RafsDigest {
    fn size() -> usize {
        RAFS_SHA256_LENGTH
    }

    fn new() -> Self {
        RafsDigest {
            ..Default::default()
        }
    }

    fn from_buf(buf: &[u8]) -> Self {
        let mut hash = Sha256::new();
        let mut hash_buf = vec![];
        hash.input(buf);
        hash.result(&mut hash_buf);
        let mut digest = RafsDigest::new();
        digest.data.clone_from_slice(&hash_buf);
        digest
    }
}

impl fmt::Display for RafsDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.data[..].iter() {
            write!(f, "{}", c)?;
        }
        Ok(())
    }
}
