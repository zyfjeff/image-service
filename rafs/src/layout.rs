// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Rafs ondisk layout structures.

use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::mem::size_of;
use std::str;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

pub const INO_FLAG_HARDLINK: u64 = 0x1000;
pub const INO_FLAG_SYMLINK: u64 = 0x2000;
pub const INO_FLAG_XATTR: u64 = 0x4000;

pub const MAX_RAFS_NAME: usize = 255;
pub const RAFS_SHA256_LENGTH: usize = 32;
pub const RAFS_BLOB_ID_MAX_LENGTH: usize = 72;

pub const RAFS_SUPER_VERSION: usize = 0x400;
pub const RAFS_SUPER_MIN_VERSION: usize = 0x400;
pub const RAFS_SUPERBLOCK_SIZE: usize = 8192;
pub const RAFS_INODE_INFO_SIZE: usize = 512;
pub const RAFS_CHUNK_INFO_SIZE: usize = 128;

pub const DEFAULT_RAFS_BLOCK_SIZE: u64 = 1024 * 1024;
pub const RAFS_SUPER_MAGIC: u32 = 0x5241_4653;

const RAFS_XATTR_ALIGNMENT: usize = 8;

pub trait RafsLayoutLoadStore {
    // load rafs ondisk metadata in packed format
    fn load<R: Read>(&mut self, r: &mut R) -> Result<usize>;

    // store rafs ondisk metadata in a packed format
    fn store<W: Write>(&self, w: W) -> Result<usize>;
}

// Ondisk rafs inode, 512 bytes
#[derive(Clone, Default, Debug)]
pub struct RafsInodeInfo {
    /// file name, [char; MAX_RAFS_NAME + 1]
    pub name: String,
    /// sha256(sha256(chunk) + ...), [char; RAFS_SHA256_LENGTH]
    pub digest: RafsDigest,
    /// parent inode number
    pub i_parent: u64,
    /// from fs stat()
    pub i_ino: u64,
    pub i_projid: u32,
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
    /// HARDLINK | SYMLINK | PREFETCH_HINT
    pub i_flags: u64,
    /// chunks count
    pub i_chunk_cnt: u64,
}

impl RafsInodeInfo {
    pub fn new() -> Self {
        RafsInodeInfo {
            ..Default::default()
        }
    }

    pub fn is_dir(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFDIR
    }

    pub fn is_symlink(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFLNK
    }

    pub fn has_xattr(&self) -> bool {
        self.i_flags & INO_FLAG_XATTR == INO_FLAG_XATTR
    }

    pub fn is_reg(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFREG
    }

    pub fn is_hardlink(&self) -> bool {
        self.i_nlink > 1
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
        Ok(s) => {
            let s: Vec<&str> = s.split_terminator('\0').collect();
            Ok(s[0].to_string())
        }
        Err(_) => Err(Error::from_raw_os_error(libc::EINVAL)),
    }
}

fn read_opaque(input: &mut &[u8], count: usize) -> Result<Vec<u8>> {
    let (buf, rest) = input.split_at(count);
    *input = rest;
    Ok(buf.into())
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
        self.i_projid = read_le_u32(&mut p);
        self.i_mode = read_le_u32(&mut p);
        self.i_uid = read_le_u32(&mut p);
        self.i_gid = read_le_u32(&mut p);
        self.i_rdev = read_le_u64(&mut p);
        self.i_size = read_le_u64(&mut p);
        self.i_nlink = read_le_u64(&mut p);
        self.i_blocks = read_le_u64(&mut p);
        self.i_atime = read_le_u64(&mut p);
        self.i_mtime = read_le_u64(&mut p);
        self.i_ctime = read_le_u64(&mut p);
        self.i_flags = read_le_u64(&mut p);
        self.i_chunk_cnt = read_le_u64(&mut p);
        trace!("loaded inode: {}", &self);

        Ok(RAFS_INODE_INFO_SIZE)
    }

    fn store<W: Write>(&self, mut w: W) -> Result<usize> {
        let name = self.name.as_bytes();
        let name_padding = vec![0; MAX_RAFS_NAME + 1 - name.len()];
        let mut count = w.write(name)?;
        count += w.write(&name_padding.as_slice())?;

        count += w.write(&self.digest.data[..])?;
        count += w.write(&u64::to_le_bytes(self.i_parent))?;
        count += w.write(&u64::to_le_bytes(self.i_ino))?;
        count += w.write(&u32::to_le_bytes(self.i_projid))?;
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
        count += w.write(&u64::to_le_bytes(self.i_flags))?;
        count += w.write(&u64::to_le_bytes(self.i_chunk_cnt))?;
        w.write_all(&vec![0; RAFS_INODE_INFO_SIZE - count])?;
        trace!("written inode: {}", &self);
        Ok(RAFS_INODE_INFO_SIZE)
    }
}

// Ondisk rafs superblock, 8192 bytes
#[derive(Copy, Clone, Default, Debug)]
pub struct RafsSuperBlockInfo {
    /// RAFS super magic
    pub s_magic: u32,
    /// RAFS version
    pub s_fs_version: u32,
    /// superblock on disk size
    pub s_sb_size: u32,
    /// inode size
    pub s_inode_size: u32,
    /// block size
    pub s_block_size: u32,
    /// chunk info metadata size
    pub s_chunkinfo_size: u32,
    /// superblock flags
    pub s_flags: u64,
}

impl RafsSuperBlockInfo {
    pub fn new() -> Self {
        RafsSuperBlockInfo {
            s_magic: RAFS_SUPER_MAGIC as u32,
            s_fs_version: RAFS_SUPER_VERSION as u32,
            s_sb_size: RAFS_SUPERBLOCK_SIZE as u32,
            s_inode_size: RAFS_INODE_INFO_SIZE as u32,
            s_block_size: DEFAULT_RAFS_BLOCK_SIZE as u32,
            s_chunkinfo_size: RAFS_CHUNK_INFO_SIZE as u32,
            ..Default::default()
        }
    }
}

impl fmt::Display for RafsSuperBlockInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "superblock {:?}", self)
    }
}

impl RafsLayoutLoadStore for RafsSuperBlockInfo {
    fn load<R: Read>(&mut self, r: &mut R) -> Result<usize> {
        let mut input = [0u8; RAFS_SUPERBLOCK_SIZE];
        r.read_exact(&mut input)?;
        let mut p = &input[..];

        // Now we know input has enough bytes to load RafsSuperBlockInfo
        self.s_magic = read_le_u32(&mut p);
        self.s_fs_version = read_le_u32(&mut p);
        self.s_sb_size = read_le_u32(&mut p);
        self.s_inode_size = read_le_u32(&mut p);
        self.s_block_size = read_le_u32(&mut p);
        self.s_chunkinfo_size = read_le_u32(&mut p);
        self.s_flags = read_le_u64(&mut p);
        trace!("loaded superblock: {}", &self);
        if self.s_magic != RAFS_SUPER_MAGIC
            || self.s_fs_version < RAFS_SUPER_MIN_VERSION as u32
            || self.s_fs_version > RAFS_SUPER_VERSION as u32
            || self.s_sb_size != RAFS_SUPERBLOCK_SIZE as u32
        {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid superblock"));
        }
        Ok(RAFS_SUPERBLOCK_SIZE)
    }

    fn store<W: Write>(&self, mut w: W) -> Result<usize> {
        let mut count = w.write(&u32::to_le_bytes(self.s_magic))?;
        count += w.write(&u32::to_le_bytes(self.s_fs_version))?;
        count += w.write(&u32::to_le_bytes(self.s_sb_size))?;
        count += w.write(&u32::to_le_bytes(self.s_inode_size))?;
        count += w.write(&u32::to_le_bytes(self.s_block_size))?;
        count += w.write(&u32::to_le_bytes(self.s_chunkinfo_size))?;
        count += w.write(&u32::to_le_bytes(self.s_magic))?;
        w.write_all(&vec![0; RAFS_SUPERBLOCK_SIZE - count])?;
        trace!("written superblock: {}", &self);
        Ok(RAFS_SUPERBLOCK_SIZE)
    }
}

// Ondisk rafs chunk, 136 bytes
#[derive(Clone, Default, Debug)]
pub struct RafsChunkInfo {
    /// sha256(chunk), [char; RAFS_SHA256_LENGTH]
    pub blockid: RafsDigest,
    /// random string, [char; RAFS_BLOB_ID_MAX_LENGTH]
    pub blobid: String,
    /// file position of block, with fixed block length
    pub file_offset: u64,
    /// blob offset
    pub blob_offset: u64,
    /// compressed size
    pub compress_size: u32,
    /// reserved
    reserved: u32,
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
            "chunkinfo blockid: {}, blobid: {} file offset: {}, blob offset: {}, compressed size: {}",
            &self.blockid, &self.blobid, self.file_offset, self.blob_offset, self.compress_size
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
        self.file_offset = read_le_u64(&mut p);
        self.blob_offset = read_le_u64(&mut p);
        self.compress_size = read_le_u32(&mut p);
        trace!("loaded chunk: {}", &self);

        Ok(RAFS_CHUNK_INFO_SIZE)
    }

    fn store<W: Write>(&self, mut w: W) -> Result<usize> {
        w.write_all(&self.blockid.data[..])?;

        let blobid = self.blobid.as_bytes();
        let blobid_padding = vec![0; RAFS_BLOB_ID_MAX_LENGTH - blobid.len()];
        w.write_all(blobid)?;
        w.write_all(blobid_padding.as_slice())?;

        w.write_all(&u64::to_le_bytes(self.file_offset))?;
        w.write_all(&u64::to_le_bytes(self.blob_offset))?;
        w.write_all(&u32::to_le_bytes(self.compress_size))?;
        w.write_all(&u32::to_le_bytes(self.reserved))?; // padding
        trace!("written chunk: {}", &self);
        Ok(RAFS_CHUNK_INFO_SIZE)
    }
}

// symlink data, aligned with size of RafsChunkInfo
#[derive(Clone, Default, Debug)]
pub struct RafsLinkDataInfo {
    pub ondisk_size: usize,
    pub target: String,
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
        w.write_all(&vec![0; self.ondisk_size - count])?;
        Ok(self.ondisk_size)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Hash)]
pub struct RafsDigest {
    pub data: [u8; RAFS_SHA256_LENGTH],
}

impl RafsDigest {
    pub fn size() -> usize {
        RAFS_SHA256_LENGTH
    }

    pub fn new() -> Self {
        RafsDigest {
            ..Default::default()
        }
    }

    pub fn from_buf(buf: &[u8]) -> Self {
        let mut hash = Sha256::new();
        let mut hash_buf = [0; RAFS_SHA256_LENGTH];
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
            write!(f, "{:02x}", c)?;
        }
        Ok(())
    }
}

// Aligned to RAFS_XATTR_ALIGNMENT bytes
#[derive(Debug, Clone, Default)]
pub struct RafsInodeXattrInfos {
    // byte length of the xattr area
    pub ondisk_size: u32,
    // number of xattrs
    pub count: u32,
    // xattr array
    pub data: HashMap<String, Vec<u8>>,
}

impl RafsInodeXattrInfos {
    pub fn new() -> Self {
        RafsInodeXattrInfos {
            ..Default::default()
        }
    }
}

impl Into<HashMap<String, Vec<u8>>> for RafsInodeXattrInfos {
    fn into(self) -> HashMap<String, Vec<u8>> {
        self.data
    }
}

impl RafsLayoutLoadStore for RafsInodeXattrInfos {
    fn load<R: Read>(&mut self, r: &mut R) -> Result<usize> {
        let mut input = vec![0u8; size_of::<u32>()];
        r.read_exact(&mut input[..])?;
        let mut p = &input[..];
        self.ondisk_size = read_le_u32(&mut p);

        input = Vec::new();
        input.resize(self.ondisk_size as usize, 0);
        r.read_exact(&mut input[..self.ondisk_size as usize - size_of::<u32>()])?;
        let mut p = &input[..];
        self.count = read_le_u32(&mut p);
        for _ in 0..self.count {
            let key_size = read_le_u32(&mut p);
            let key = read_string(&mut p, key_size as usize)?;
            let value_size = read_le_u32(&mut p);
            let value = read_opaque(&mut p, value_size as usize)?;
            trace!(
                "key_size {} key {} value_size {} value {:?}",
                key_size,
                key,
                value_size,
                value_size
            );
            self.data.insert(key, value);
        }

        trace!("loaded xattr {:?}", self);
        Ok(self.ondisk_size as usize + size_of::<u32>())
    }

    fn store<W: Write>(&self, mut w: W) -> Result<usize> {
        if self.count == 0 {
            return Ok(0);
        }

        let mut buf: Vec<u8> = Vec::new();

        buf.write_all(&u32::to_le_bytes(self.count as u32))?;
        for (key, value) in self.data.iter() {
            buf.write_all(&u32::to_le_bytes(key.len() as u32))?;
            buf.write_all(key.as_bytes())?;
            buf.write_all(&u32::to_le_bytes(value.len() as u32))?;
            if !value.is_empty() {
                buf.write_all(&value)?;
            }
        }

        // round up
        let ondisk_size = (buf.len() + size_of::<u32>() + RAFS_XATTR_ALIGNMENT - 1)
            / RAFS_XATTR_ALIGNMENT
            * RAFS_XATTR_ALIGNMENT;

        let mut count = w.write(&u32::to_le_bytes(ondisk_size as u32))?;
        count += w.write(&buf)?;
        w.write_all(&vec![0; ondisk_size - count])?;

        info!("written size {} xattr {:?}", ondisk_size, self);
        Ok(ondisk_size)
    }
}
