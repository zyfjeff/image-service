// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! RAFS on disk layout structures.
//!
//! # RAFS File System Meta Data Format Version 5
//! Previously RAFS has different formats for on disk meta data and runtime meta data. So when
//! initializing an RAFS instance, it will sequentially read and parse the on disk meta data,
//! build a copy of in memory runtime meta data. This may cause slow startup and cost too much
//! memory to build in memory meta data.
//!
//! The RAFS File System Meta Data Format Version 5 (aka V5) is defined to support directly mapping
//! RAFS meta data into process as runtime meta data, so we could parse RAFS on disk meta data on
//! demand. The V5 meta data format has following changes:
//! 1) file system version number been bumped to 0x500.
//! 2) Directory inodes will sequentially assign globally unique `child index` to it's child inodes.
//!    Two fields, "child_index" and "child_count", have been added to the OndiskInode struct.
//! 3) For inodes with hard link count as 1, the `child index` equals to its assigned inode number.
//! 4) For inodes with hard link count bigger than 1, the `child index` may be different from the
//!    assigned inode number. Among those child entries linking to the same inode, there's will be
//!    one and only one child entry having the inode number as its assigned `child index'.
//! 5) A child index mapping table is introduced, which is used to map `child index` into offset
//!    from the base of the super block. The formula to calculate the inode offset is:
//!      inode_offset_from_sb = inode_table[child_index] << 3
//! 6) The child index mapping table follows the super block by default.
//!
//! Giving above definition, we could get the inode object for an inode number or child index as:
//!    inode_ptr = sb_base_ptr + inode_offset_from_sb(inode_number)
//!    inode_ptr = sb_base_ptr + inode_offset_from_sb(child_index)

use std::convert::TryFrom;
use std::io::{Error, ErrorKind, Result};
use std::str;

use super::*;
use crate::{einval, enoent};

pub const INO_FLAG_HARDLINK: u64 = 0x1000;
pub const INO_FLAG_SYMLINK: u64 = 0x2000;
pub const INO_FLAG_XATTR: u64 = 0x4000;
pub const INO_FLAG_ALL: u64 = INO_FLAG_HARDLINK | INO_FLAG_SYMLINK | INO_FLAG_XATTR;

pub const CHUNK_FLAG_COMPRESSED: u32 = 0x1000;

pub const RAFS_SUPERBLOCK_SIZE: usize = 8192;
pub const RAFS_SUPERBLOCK_RESERVED_SIZE: usize = RAFS_SUPERBLOCK_SIZE - 64;
pub const RAFS_SUPER_MAGIC: u32 = 0x5241_4653;
pub const RAFS_SUPER_VERSION_V4: u32 = 0x400;
pub const RAFS_SUPER_VERSION_V5: u32 = 0x500;
pub const RAFS_SUPER_MIN_VERSION: u32 = RAFS_SUPER_VERSION_V4;
pub const RAFS_INODE_INFO_SIZE: usize = 512;
pub const RAFS_INODE_INFO_RESERVED_SIZE: usize = RAFS_INODE_INFO_SIZE - 400;
pub const RAFS_CHUNK_INFO_SIZE: usize = 64;
pub const RAFS_ALIGNMENT: usize = 8;

macro_rules! impl_metadata_converter {
    ($T: ty) => {
        impl TryFrom<&[u8]> for &$T {
            type Error = Error;

            fn try_from(buf: &[u8]) -> std::result::Result<Self, Self::Error> {
                let ptr = buf as *const [u8] as *const u8;
                if buf.len() != std::mem::size_of::<$T>()
                    || ptr as usize & (std::mem::align_of::<$T>() - 1) != 0
                {
                    return Err(einval());
                }

                Ok(unsafe { &*(ptr as *const $T) })
            }
        }

        impl TryFrom<&mut [u8]> for &mut $T {
            type Error = Error;

            fn try_from(buf: &mut [u8]) -> std::result::Result<Self, Self::Error> {
                let ptr = buf as *const [u8] as *const u8;
                if buf.len() != std::mem::size_of::<$T>()
                    || ptr as usize & (std::mem::align_of::<$T>() - 1) != 0
                {
                    return Err(einval());
                }

                Ok(unsafe { &mut *(ptr as *const $T as *mut $T) })
            }
        }

        impl AsRef<[u8]> for $T {
            fn as_ref(&self) -> &[u8] {
                let ptr = self as *const $T as *const u8;
                unsafe { &*std::slice::from_raw_parts(ptr, std::mem::size_of::<$T>()) }
            }
        }

        impl AsMut<[u8]> for $T {
            fn as_mut(&mut self) -> &mut [u8] {
                let ptr = self as *mut $T as *mut u8;
                unsafe { &mut *std::slice::from_raw_parts_mut(ptr, std::mem::size_of::<$T>()) }
            }
        }
    };
}

macro_rules! impl_pub_getter_setter {
    ($G: ident, $S: ident, $F: ident, $U: ty) => {
        pub fn $G(&self) -> $U {
            <$U>::from_le(self.$F)
        }

        pub fn $S(&mut self, $F: $U) {
            self.$F = <$U>::to_le($F);
        }
    };
}

macro_rules! impl_getter_setter {
    ($G: ident, $S: ident, $F: ident, $U: ty) => {
        fn $G(&self) -> $U {
            <$U>::from_le(self.$F)
        }

        fn $S(&mut self, $F: $U) {
            self.$F = <$U>::to_le($F);
        }
    };
}

/// RAFS SuperBlock on disk data format, 8192 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OndiskSuperBlock {
    /// RAFS super magic
    s_magic: u32,
    /// RAFS version
    s_fs_version: u32,
    /// superblock on disk size
    s_sb_size: u32,
    /// inode size
    s_inode_size: u32,
    /// block size
    s_block_size: u32,
    /// chunk info metadata size
    s_chunkinfo_size: u32,
    /// superblock flags
    s_flags: u64,
    /// V5: Number of unique inodes(hard link counts as 1).
    s_inodes_count: u64,
    /// V5: Offset of inode table
    s_inode_table_offset: u64,
    /// V5: Offset of inode table
    s_blob_table_offset: u64,
    /// V5: Size of inode table.
    s_inode_table_entries: u32,
    /// V5: Size of inode table.
    s_blob_table_entries: u32,
    /// Unused area.
    s_reserved: [u8; RAFS_SUPERBLOCK_RESERVED_SIZE],
}

impl Default for OndiskSuperBlock {
    fn default() -> Self {
        Self {
            s_magic: u32::to_le(RAFS_SUPER_MAGIC as u32),
            s_fs_version: u32::to_le(RAFS_SUPER_VERSION_V5),
            s_sb_size: u32::to_le(RAFS_SUPERBLOCK_SIZE as u32),
            s_inode_size: u32::to_le(RAFS_INODE_INFO_SIZE as u32),
            s_block_size: u32::to_le(RAFS_DEFAULT_BLOCK_SIZE as u32),
            s_chunkinfo_size: u32::to_le(RAFS_CHUNK_INFO_SIZE as u32),
            s_flags: u64::to_le(0),
            s_inodes_count: u64::to_le(0),
            s_inode_table_entries: u32::to_le(0),
            s_inode_table_offset: u64::to_le(0),
            s_blob_table_entries: u32::to_le(0),
            s_blob_table_offset: u64::to_le(0),
            s_reserved: [0u8; RAFS_SUPERBLOCK_RESERVED_SIZE],
        }
    }
}

impl OndiskSuperBlock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.magic() != RAFS_SUPER_MAGIC
            || self.version() < RAFS_SUPER_MIN_VERSION as u32
            || self.version() > RAFS_SUPER_VERSION_V5 as u32
            || self.sb_size() != RAFS_SUPERBLOCK_SIZE as u32
            || self.inode_size() != RAFS_INODE_INFO_SIZE as u32
            || self.chunkinfo_size() != RAFS_CHUNK_INFO_SIZE as u32
        {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid superblock"));
        }

        match self.version() {
            RAFS_SUPER_VERSION_V4 => {
                if self.inodes_count() != 0
                    || self.inode_table_offset() != 0
                    || self.inode_table_entries() != 0
                {
                    return Err(Error::new(ErrorKind::InvalidData, "Invalid superblock"));
                }
            }
            RAFS_SUPER_VERSION_V5 => {
                if self.inodes_count() == 0
                    || self.inode_table_offset() < RAFS_SUPERBLOCK_SIZE as u64
                    || self.inode_table_offset() & 0x7 != 0
                    || self.inode_table_entries() >= (1 << 29)
                    || self.inodes_count() > self.inode_table_entries() as u64
                {
                    return Err(Error::new(ErrorKind::InvalidData, "Invalid superblock"));
                }
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid superblock version number",
                ));
            }
        }

        // TODO: validate block_size, flags and reserved.

        Ok(())
    }

    impl_pub_getter_setter!(magic, set_magic, s_magic, u32);
    impl_pub_getter_setter!(version, set_version, s_fs_version, u32);
    impl_pub_getter_setter!(sb_size, set_sb_size, s_sb_size, u32);
    impl_pub_getter_setter!(inode_size, set_inode_size, s_inode_size, u32);
    impl_pub_getter_setter!(block_size, set_block_size, s_block_size, u32);
    impl_pub_getter_setter!(chunkinfo_size, set_chunkinfo_size, s_chunkinfo_size, u32);
    impl_pub_getter_setter!(flags, set_flags, s_flags, u64);
    impl_pub_getter_setter!(inodes_count, set_inodes_count, s_inodes_count, u64);
    impl_pub_getter_setter!(
        inode_table_entries,
        set_inode_table_entries,
        s_inode_table_entries,
        u32
    );
    impl_pub_getter_setter!(
        inode_table_offset,
        set_inode_table_offset,
        s_inode_table_offset,
        u64
    );
    impl_pub_getter_setter!(
        blob_table_entries,
        set_blob_table_entries,
        s_blob_table_entries,
        u32
    );
    impl_pub_getter_setter!(
        blob_table_offset,
        set_blob_table_offset,
        s_blob_table_offset,
        u64
    );

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }

    pub fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        w.write_all(self.as_ref())?;
        Ok(self.as_ref().len())
    }
}

impl_metadata_converter!(OndiskSuperBlock);

impl fmt::Display for OndiskSuperBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "superblock: magic {:x}, version {:x}, sb_size {:x}, inode_size {:x}, block_size {:x}, chunkinfo_size {:x}, flags {:x}, inode_count {}",
               self.magic(), self.version(), self.sb_size(), self.inode_size(), self.block_size(),
               self.chunkinfo_size(), self.flags(), self.s_inodes_count)
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct OndiskInodeTable {
    data: Vec<u32>,
}

impl OndiskInodeTable {
    pub fn new(entries: usize) -> Self {
        let table_size = entries + (RAFS_ALIGNMENT - (entries & (RAFS_ALIGNMENT - 1)));
        OndiskInodeTable {
            data: vec![0; table_size],
        }
    }

    pub fn size(&self) -> usize {
        self.data.len() * std::mem::size_of::<u32>()
    }

    pub fn set(&mut self, ino: Inode, inode_offset: u32) -> Result<()> {
        if ino > self.data.len() as u64 {
            return Err(enoent());
        }

        let offset = inode_offset >> 3;
        self.data[(ino - 1) as usize] = offset as u32;

        Ok(())
    }

    pub fn get(&self, ino: Inode) -> Result<u32> {
        if ino > self.data.len() as u64 {
            return Err(enoent());
        }

        let offset = u32::from_le(self.data[(ino - 1) as usize]) as usize;
        if offset <= (RAFS_SUPERBLOCK_SIZE >> 3) || offset >= (1usize << 29) {
            return Err(enoent());
        }

        Ok((offset << 3) as u32)
    }

    pub fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let (_, data, _) = unsafe { self.data.align_to::<u8>() };
        w.write_all(data)?;
        Ok(data.len())
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let (_, data, _) = unsafe { self.data.align_to_mut::<u8>() };
        r.read_exact(data)?;
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct OndiskBlobTable {
    data: Vec<OndiskDigest>,
}

impl OndiskBlobTable {
    pub fn new(entries: usize) -> Self {
        OndiskBlobTable {
            data: vec![OndiskDigest::new(); entries],
        }
    }

    pub fn size(&self) -> usize {
        self.data.len() * RAFS_SHA256_LENGTH
    }

    pub fn set(&mut self, index: u32, digest: OndiskDigest) -> Result<()> {
        if index > (self.data.len() - 1) as u32 {
            return Err(enoent());
        }
        self.data[index as usize] = digest;
        Ok(())
    }

    pub fn get(&self, index: u32) -> Result<&OndiskDigest> {
        if index > (self.data.len() - 1) as u32 {
            return Err(enoent());
        }
        Ok(&self.data[index as usize])
    }

    pub fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut size = 0;
        self.data
            .iter()
            .map(|d| {
                size += d.data.len();
                w.write_all(&d.data)
            })
            .collect::<Result<()>>()?;
        Ok(size)
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let (_, data, _) = unsafe { self.data.align_to_mut::<u8>() };
        r.read_exact(data)?;
        Ok(())
    }
}

/// Ondisk rafs inode, 512 bytes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OndiskInode {
    /// file name, [char; RAFS_MAX_NAME + 1]
    i_name: [u8; RAFS_MAX_NAME + 1],
    /// sha256(sha256(chunk) + ...), [char; RAFS_SHA256_LENGTH]
    i_digest: OndiskDigest,
    /// parent inode number
    i_parent: u64,
    /// from fs stat()
    i_ino: u64,
    i_projid: u32,
    i_mode: u32,
    i_uid: u32,
    i_gid: u32,
    i_rdev: u64,
    i_size: u64,
    i_nlink: u64,
    i_blocks: u64,
    i_atime: u64,
    i_mtime: u64,
    i_ctime: u64,
    /// HARDLINK | SYMLINK | PREFETCH_HINT
    i_flags: u64,
    /// chunks count
    i_chunk_cnt: u64,
    i_child_index: u32,
    i_child_count: u32,
    i_reserved: [u8; RAFS_INODE_INFO_RESERVED_SIZE],
}

impl Default for OndiskInode {
    fn default() -> Self {
        Self {
            i_name: [0u8; RAFS_MAX_NAME + 1],
            i_digest: OndiskDigest::default(),
            i_parent: 0,
            i_ino: 0,
            i_projid: 0,
            i_mode: 0,
            i_uid: 0,
            i_gid: 0,
            i_rdev: 0,
            i_size: 0,
            i_nlink: 0,
            i_blocks: 0,
            i_atime: 0,
            i_mtime: 0,
            i_ctime: 0,
            i_flags: 0,
            i_chunk_cnt: 0,
            i_child_index: 0,
            i_child_count: 0,
            i_reserved: [0u8; RAFS_INODE_INFO_RESERVED_SIZE],
        }
    }
}

impl OndiskInode {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }

    pub fn store(&self, w: &mut RafsIoWriter) -> Result<()> {
        w.write_all(self.as_ref())
    }
}

impl RafsInode for OndiskInode {
    fn validate(&self) -> Result<()> {
        unimplemented!();
    }

    fn name(&self) -> &str {
        // Assume the caller has validated the object by calling self.validate()
        parse_string(&self.i_name[0..=RAFS_MAX_NAME]).unwrap()
    }

    fn set_name(&mut self, name: &str) -> Result<()> {
        let len = name.len();
        if len > RAFS_MAX_NAME {
            return Err(einval());
        }

        self.i_name[..len].copy_from_slice(name.as_bytes());
        self.i_name[len] = 0;

        Ok(())
    }

    fn digest(&self) -> &OndiskDigest {
        &self.i_digest
    }

    fn set_digest(&mut self, digest: &OndiskDigest) {
        self.i_digest = *digest;
    }

    impl_getter_setter!(parent, set_parent, i_parent, u64);
    impl_getter_setter!(ino, set_ino, i_ino, u64);
    impl_getter_setter!(projid, set_projid, i_projid, u32);
    impl_getter_setter!(mode, set_mode, i_mode, u32);
    impl_getter_setter!(uid, set_uid, i_uid, u32);
    impl_getter_setter!(gid, set_gid, i_gid, u32);
    impl_getter_setter!(rdev, set_rdev, i_rdev, u64);
    impl_getter_setter!(size, set_size, i_size, u64);
    impl_getter_setter!(nlink, set_nlink, i_nlink, u64);
    impl_getter_setter!(blocks, set_blocks, i_blocks, u64);
    impl_getter_setter!(atime, set_atime, i_atime, u64);
    impl_getter_setter!(mtime, set_mtime, i_mtime, u64);
    impl_getter_setter!(ctime, set_ctime, i_ctime, u64);
    impl_getter_setter!(flags, set_flags, i_flags, u64);
    impl_getter_setter!(chunk_cnt, set_chunk_cnt, i_chunk_cnt, u64);
    impl_getter_setter!(child_index, set_child_index, i_child_index, u32);
    impl_getter_setter!(child_count, set_child_count, i_child_count, u32);
}

impl_metadata_converter!(OndiskInode);

impl fmt::Display for OndiskInode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "inode name: {}, digest: {}, ino: {})",
            self.name(),
            self.digest(),
            self.ino()
        )
    }
}

/// On disk Rafs data chunk information.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OndiskChunkInfo {
    /// sha256(chunk), [char; RAFS_SHA256_LENGTH]
    block_id: OndiskDigest,
    /// blob index (blob_digest = blob_table[blob_index])
    blob_index: u32,
    /// compressed size
    compress_size: u32,
    /// file position of block, with fixed block length
    file_offset: u64,
    /// blob offset
    blob_offset: u64,
    /// CHUNK_FLAG_COMPRESSED
    flags: u32,
    /// reserved
    reserved: u32,
}

impl OndiskChunkInfo {
    pub fn new() -> Self {
        OndiskChunkInfo::default()
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }

    pub fn store(&self, w: &mut RafsIoWriter) -> Result<()> {
        w.write_all(self.as_ref())
    }
}

impl RafsChunkInfo for OndiskChunkInfo {
    fn validate(&self, _sb: &RafsSuperMeta) -> Result<()> {
        self.block_id.validate()?;
        Ok(())
    }

    fn block_id(&self) -> &OndiskDigest {
        &self.block_id
    }

    fn block_id_mut(&mut self) -> &mut OndiskDigest {
        &mut self.block_id
    }

    fn set_block_id(&mut self, digest: &OndiskDigest) {
        self.block_id = *digest;
    }

    impl_getter_setter!(blob_index, set_blob_index, blob_index, u32);
    impl_getter_setter!(file_offset, set_file_offset, file_offset, u64);
    impl_getter_setter!(blob_offset, set_blob_offset, blob_offset, u64);
    impl_getter_setter!(compress_size, set_compress_size, compress_size, u32);
}

impl_metadata_converter!(OndiskChunkInfo);

impl Default for OndiskChunkInfo {
    fn default() -> Self {
        OndiskChunkInfo {
            block_id: OndiskDigest::default(),
            blob_index: 0,
            file_offset: 0,
            blob_offset: 0,
            compress_size: 0,
            flags: 0,
            reserved: 0,
        }
    }
}

impl fmt::Display for OndiskChunkInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "chunkinfo block_id: {}, blob_index: {} file offset: {}, blob offset: {}, compressed size: {}",
            self.block_id(), self.blob_index(), self.file_offset(), self.blob_offset(),
            self.compress_size()
        )
    }
}

/// On disk Rafs SHA256 digest data.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct OndiskDigest {
    data: [u8; RAFS_SHA256_LENGTH],
}

impl OndiskDigest {
    pub fn new() -> Self {
        OndiskDigest {
            ..Default::default()
        }
    }

    pub fn from_buf(buf: &[u8]) -> Self {
        let mut hash = Sha256::new();
        let mut hash_buf = [0; RAFS_SHA256_LENGTH];
        hash.input(buf);
        hash.result(&mut hash_buf);
        let mut digest = OndiskDigest::new();
        digest.data.clone_from_slice(&hash_buf);
        digest
    }

    pub fn from_raw(sha: &mut Sha256) -> Self {
        let mut hash = [0; RAFS_SHA256_LENGTH];
        sha.result(&mut hash);
        let mut digest = OndiskDigest::new();
        digest.data.clone_from_slice(&hash);
        digest
    }
}

impl RafsDigest for OndiskDigest {
    fn validate(&self) -> Result<()> {
        Ok(())
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl_metadata_converter!(OndiskDigest);

impl fmt::Display for OndiskDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.data[..].iter() {
            write!(f, "{:02x}", c)?;
        }
        Ok(())
    }
}

/// On disk sysmlink data.
#[repr(C)]
#[derive(Clone, Default, Debug)]
pub struct OndiskSymlinkInfo {
    pub data: Vec<u8>,
}

impl OndiskSymlinkInfo {
    pub fn new() -> Self {
        OndiskSymlinkInfo {
            ..Default::default()
        }
    }

    pub fn to_str(&self) -> Result<&str> {
        parse_string(self.data.as_slice())
    }

    pub fn from_raw(data: &[u8]) -> Result<Self> {
        let raw_size = data.len() + 1;
        if raw_size > libc::PATH_MAX as usize {
            return Err(einval());
        }

        let size = raw_size + (RAFS_ALIGNMENT - (raw_size & (RAFS_ALIGNMENT - 1)));
        let mut buf = vec![0; size];
        buf[..data.len()].copy_from_slice(data);
        // Need one extra padding '0'
        buf[data.len()] = 0;

        Ok(OndiskSymlinkInfo { data: buf })
    }

    pub fn count(&self) -> usize {
        self.data.len() / RAFS_ALIGNMENT
    }

    pub fn size(&self) -> usize {
        self.data.len() * std::mem::size_of::<u8>()
    }

    pub fn store(&mut self, w: &mut RafsIoWriter) -> Result<usize> {
        w.write_all(&self.data)?;
        Ok(self.data.len())
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(&mut self.data)?;
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Default, Debug)]
pub struct OndiskXAttrPair {
    size: u32,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl OndiskXAttrPair {
    pub fn new() -> Self {
        OndiskXAttrPair {
            ..Default::default()
        }
    }
    pub fn set(&mut self, key: &str, value: Vec<u8>) {
        self.key = key.as_bytes().to_vec();
        self.value = value;
    }
}

/// On disk sysmlink data.
#[repr(C)]
#[derive(Clone, Default, Debug)]
pub struct OndiskXAttr {
    size: u32,
    data: Vec<OndiskXAttrPair>,
}

impl OndiskXAttr {
    pub fn new() -> Self {
        OndiskXAttr {
            ..Default::default()
        }
    }

    pub fn push(&mut self, pair: OndiskXAttrPair) {
        self.data.push(pair);
    }
}

pub fn save_symlink_ondisk(data: &[u8], w: &mut RafsIoWriter) -> Result<usize> {
    let (sz, _) = calc_symlink_size(data.len())?;
    let mut buf = vec![0; sz];

    buf[..data.len()].copy_from_slice(data);
    buf[data.len()] = 0;
    w.write_all(&buf)?;

    Ok(sz)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn test_rafs_ondisk_superblock_v4() {
        let mut sb = OndiskSuperBlock::new();
        sb.set_version(RAFS_SUPER_VERSION_V4);

        assert_eq!(
            std::mem::size_of::<OndiskSuperBlock>(),
            RAFS_SUPERBLOCK_SIZE
        );

        assert_eq!(sb.magic(), RAFS_SUPER_MAGIC);
        assert_eq!(sb.version(), RAFS_SUPER_VERSION_V4 as u32);
        assert_eq!(sb.sb_size(), RAFS_SUPERBLOCK_SIZE as u32);
        assert_eq!(sb.inode_size(), RAFS_INODE_INFO_SIZE as u32);
        assert_eq!(sb.block_size(), RAFS_DEFAULT_BLOCK_SIZE as u32);
        assert_eq!(sb.chunkinfo_size(), RAFS_CHUNK_INFO_SIZE as u32);
        assert_eq!(sb.flags(), 0);
        sb.validate().unwrap();

        sb.set_magic(0x1);
        assert_eq!(sb.magic(), 1);
        assert_eq!(sb.s_magic, 0x1);
        sb.set_magic(RAFS_SUPER_MAGIC);
        sb.set_version(2);
        assert_eq!(sb.version(), 2);
        sb.set_sb_size(3);
        assert_eq!(sb.sb_size(), 3);
        sb.set_inode_size(4);
        assert_eq!(sb.inode_size(), 4);
        sb.set_inode_size(5);
        assert_eq!(sb.inode_size(), 5);
        sb.set_chunkinfo_size(6);
        assert_eq!(sb.chunkinfo_size(), 6);
        sb.set_flags(7);
        assert_eq!(sb.flags(), 7);
        sb.validate().unwrap_err();
    }

    #[test]
    fn test_rafs_ondisk_superblock_v5() {
        let mut sb = OndiskSuperBlock::new();
        sb.set_inodes_count(1000);
        sb.set_inode_table_entries(1024);
        sb.set_inode_table_offset(RAFS_SUPERBLOCK_SIZE as u64);

        assert_eq!(
            std::mem::size_of::<OndiskSuperBlock>(),
            RAFS_SUPERBLOCK_SIZE
        );

        assert_eq!(sb.magic(), RAFS_SUPER_MAGIC);
        assert_eq!(sb.version(), RAFS_SUPER_VERSION_V5 as u32);
        assert_eq!(sb.sb_size(), RAFS_SUPERBLOCK_SIZE as u32);
        assert_eq!(sb.inode_size(), RAFS_INODE_INFO_SIZE as u32);
        assert_eq!(sb.block_size(), RAFS_DEFAULT_BLOCK_SIZE as u32);
        assert_eq!(sb.chunkinfo_size(), RAFS_CHUNK_INFO_SIZE as u32);
        assert_eq!(sb.flags(), 0);
        sb.validate().unwrap();

        sb.set_magic(0x1);
        assert_eq!(sb.magic(), 1);
        assert_eq!(sb.s_magic, 0x1);
        sb.validate().unwrap_err();
        sb.set_magic(RAFS_SUPER_MAGIC);

        sb.set_version(2);
        assert_eq!(sb.version(), 2);
        sb.validate().unwrap_err();
        sb.set_version(RAFS_SUPER_VERSION_V5);

        sb.set_sb_size(3);
        assert_eq!(sb.sb_size(), 3);
        sb.set_sb_size(RAFS_SUPERBLOCK_SIZE as u32);
        sb.set_inode_size(4);
        assert_eq!(sb.inode_size(), 4);
        sb.set_inode_size(5);
        assert_eq!(sb.inode_size(), 5);
        sb.set_inode_size(RAFS_INODE_INFO_SIZE as u32);
        sb.set_chunkinfo_size(6);
        assert_eq!(sb.chunkinfo_size(), 6);
        sb.set_chunkinfo_size(RAFS_CHUNK_INFO_SIZE as u32);
        sb.set_flags(7);
        assert_eq!(sb.flags(), 7);
        sb.set_flags(0);

        sb.validate().unwrap();

        sb.set_inodes_count(2000);
        sb.validate().unwrap_err();
        sb.set_inodes_count(0);
        sb.validate().unwrap_err();
        sb.set_inodes_count(100);

        sb.set_inode_table_offset(RAFS_SUPERBLOCK_SIZE as u64 + 1);
        sb.validate().unwrap_err();
        sb.set_inode_table_offset(RAFS_SUPERBLOCK_SIZE as u64);

        sb.set_inode_table_entries(1 << 30);
        sb.validate().unwrap_err();
        sb.set_inode_table_entries(1 << 29);
        sb.validate().unwrap_err();
        sb.set_inode_table_entries((1 << 29) - 1);
        sb.validate().unwrap();
    }

    #[test]
    fn test_rafs_ondisk_inode() {
        let mut inode = OndiskInode::new();
        let mut sb = RafsSuper::new();

        assert_eq!(std::mem::size_of::<OndiskInode>(), RAFS_INODE_INFO_SIZE);
        inode.validate(&sb.s_meta).unwrap_err();

        sb.s_meta.s_inodes_count = 100;
        inode.set_parent(ROOT_ID);
        inode.set_ino(ROOT_ID);

        assert_eq!(inode.name(), "");
        inode.set_name("test").unwrap();
        assert_eq!(inode.name(), "test");

        sb.s_meta.s_inodes_count = 0;
        inode.validate(&sb.s_meta).unwrap_err();
        sb.s_meta.s_inodes_count = ROOT_ID;
        inode.validate(&sb.s_meta).unwrap_err();
        sb.s_meta.s_inodes_count = ROOT_ID + 1;
        inode.validate(&sb.s_meta).unwrap();
        sb.s_meta.s_inodes_count = 100;

        inode.set_ino(ROOT_ID + 1);
        inode.validate(&sb.s_meta).unwrap();
        inode.set_parent(ROOT_ID + 1);
        inode.validate(&sb.s_meta).unwrap_err();
        inode.set_parent(0);
        inode.validate(&sb.s_meta).unwrap_err();
        inode.set_parent(ROOT_ID);
        inode.set_ino(0);
        inode.validate(&sb.s_meta).unwrap_err();
        inode.set_ino(ROOT_ID + 1);
        inode.validate(&sb.s_meta).unwrap();

        inode.i_name = [0x40u8; RAFS_MAX_NAME + 1];
        inode.validate(&sb.s_meta).unwrap_err();
        inode.i_name[RAFS_MAX_NAME] = 0;
        inode.validate(&sb.s_meta).unwrap();

        inode.i_flags = u64::to_le(!0);
        inode.validate(&sb.s_meta).unwrap_err();
        inode.set_flags(INO_FLAG_SYMLINK | INO_FLAG_HARDLINK);
        inode.validate(&sb.s_meta).unwrap_err();
        inode.set_flags(INO_FLAG_SYMLINK | INO_FLAG_XATTR);
        inode.validate(&sb.s_meta).unwrap_err();
        inode.set_mode(libc::S_IFLNK);
        inode.validate(&sb.s_meta).unwrap();
        assert_eq!(inode.flags(), INO_FLAG_XATTR | INO_FLAG_SYMLINK);
        inode.set_mode(0);
        inode.set_flags(0);

        inode.set_name(&"t".repeat(RAFS_MAX_NAME + 1)).unwrap_err();
        inode.set_name(&"t".repeat(RAFS_MAX_NAME)).unwrap();
        assert_eq!(inode.name().len(), RAFS_MAX_NAME);
        inode.validate(&sb.s_meta).unwrap();

        inode.set_nlink(std::u32::MAX as u64);
        inode.validate(&sb.s_meta).unwrap();
        inode.set_nlink(std::u32::MAX as u64 + 1);
        inode.validate(&sb.s_meta).unwrap_err();
        inode.set_nlink(std::u32::MAX as u64);
        assert_eq!(inode.nlink(), std::u32::MAX as u64);
        inode.validate(&sb.s_meta).unwrap();

        inode.set_rdev(std::u32::MAX as u64 + 1);
        inode.validate(&sb.s_meta).unwrap_err();
        inode.set_rdev(std::u32::MAX as u64);
        assert_eq!(inode.rdev(), std::u32::MAX as u64);
        inode.validate(&sb.s_meta).unwrap();

        inode.set_mode(libc::S_IFREG);
        inode.set_size(1);
        inode.validate(&sb.s_meta).unwrap_err();
        inode.set_chunk_cnt(1);
        inode.validate(&sb.s_meta).unwrap();
    }

    #[test]
    fn test_rafs_ondisk_chunk_info() {
        let mut chunk = OndiskChunkInfo::new();
        let ptr = &chunk as *const OndiskChunkInfo as *const u8;

        assert_eq!(std::mem::size_of::<OndiskChunkInfo>(), 128);
        assert_eq!(std::mem::size_of_val(&chunk), 128);
        assert_eq!(std::mem::align_of_val(&chunk), 8);
        assert_eq!(chunk.blockid().data() as *const [u8] as *const u8, ptr);
        assert_eq!(ptr, &chunk.block_id.data as *const u8);

        assert_eq!(chunk.blob_offset, 0);
        assert_eq!(chunk.file_offset, 0);
        assert_eq!(chunk.compress_size, 0);
        chunk.set_file_offset(0x1);
        chunk.set_blob_offset(0x2);
        chunk.set_compress_size(0x3);
        assert_eq!(chunk.file_offset, 0x1);
        assert_eq!(chunk.blob_offset, 0x2);
        assert_eq!(chunk.compress_size, 0x3);
        assert_eq!(chunk.file_offset(), 0x1);
        assert_eq!(chunk.blob_offset(), 0x2);
        assert_eq!(chunk.compress_size(), 0x3);

        assert_eq!(chunk.blobid(), "");
        chunk.set_blobid("test").unwrap();
        assert_eq!(chunk.blobid(), "test");
    }

    #[test]
    fn test_rafs_ondisk_digest() {
        let buf = [0u8; RAFS_SHA256_LENGTH];
        let ptr = &buf as *const [u8];
        let digest: &OndiskDigest = buf.as_ref().try_into().unwrap();

        assert_eq!(std::mem::size_of::<OndiskDigest>(), 32);
        assert_eq!(std::mem::size_of_val(digest), 32);
        assert_eq!(std::mem::align_of_val(digest), 1);
        assert_eq!(digest.data() as *const [u8], ptr);
        assert_eq!(ptr, &digest.data as *const [u8]);

        let mut buf = [0xa5u8; RAFS_SHA256_LENGTH];
        let ptr = &mut buf as *mut [u8];
        let digest: &mut OndiskDigest = buf.as_mut().try_into().unwrap();
        assert_eq!(ptr, &mut digest.data as *mut [u8]);
        assert_eq!(digest.data()[0], 0xa5);
        assert_eq!(digest.data()[RAFS_SHA256_LENGTH - 1], 0xa5);

        digest.digest("a5".as_bytes());
        assert_eq!(
            digest.data,
            [
                0x66, 0x22, 0x0e, 0x71, 0x59, 0x1b, 0x2d, 0x93, 0x3c, 0x0e, 0x93, 0x5c, 0x13, 0x8e,
                0xbf, 0xd6, 0x07, 0x10, 0xb9, 0x1f, 0xe2, 0xfb, 0x75, 0x99, 0xec, 0xed, 0x44, 0x30,
                0xb3, 0xdb, 0xb3, 0xc9
            ]
        );
    }
}
