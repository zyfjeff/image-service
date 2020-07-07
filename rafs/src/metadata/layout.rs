// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

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
use std::convert::TryInto;
use std::io::{Error, Result};
use std::mem::size_of;

use nydus_utils::{einval, enoent};

use super::*;

pub const INO_FLAG_SYMLINK: u64 = 0x1;
pub const INO_FLAG_HARDLINK: u64 = 0x2;
pub const INO_FLAG_XATTR: u64 = 0x4;
pub const INO_FLAG_ALL: u64 = INO_FLAG_HARDLINK | INO_FLAG_SYMLINK | INO_FLAG_XATTR;

pub const CHUNK_FLAG_COMPRESSED: u32 = 0x1;

pub const RAFS_SUPERBLOCK_SIZE: usize = 8192;
pub const RAFS_SUPERBLOCK_RESERVED_SIZE: usize = RAFS_SUPERBLOCK_SIZE - 56;
pub const RAFS_SUPER_MAGIC: u32 = 0x5241_4653;
pub const RAFS_SUPER_VERSION_V4: u32 = 0x400;
pub const RAFS_SUPER_VERSION_V5: u32 = 0x500;
pub const RAFS_SUPER_MIN_VERSION: u32 = RAFS_SUPER_VERSION_V4;
pub const RAFS_ALIGNMENT: usize = 8;

macro_rules! impl_metadata_converter {
    ($T: ty) => {
        impl TryFrom<&[u8]> for &$T {
            type Error = Error;

            fn try_from(buf: &[u8]) -> std::result::Result<Self, Self::Error> {
                let ptr = buf as *const [u8] as *const u8;
                if buf.len() != size_of::<$T>()
                    || ptr as usize & (std::mem::align_of::<$T>() - 1) != 0
                {
                    return Err(einval!("convert failed"));
                }

                Ok(unsafe { &*(ptr as *const $T) })
            }
        }

        impl TryFrom<&mut [u8]> for &mut $T {
            type Error = Error;

            fn try_from(buf: &mut [u8]) -> std::result::Result<Self, Self::Error> {
                let ptr = buf as *const [u8] as *const u8;
                if buf.len() != size_of::<$T>()
                    || ptr as usize & (std::mem::align_of::<$T>() - 1) != 0
                {
                    return Err(einval!("convert failed"));
                }

                Ok(unsafe { &mut *(ptr as *const $T as *mut $T) })
            }
        }

        impl AsRef<[u8]> for $T {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                let ptr = self as *const $T as *const u8;
                unsafe { &*std::slice::from_raw_parts(ptr, size_of::<$T>()) }
            }
        }

        impl AsMut<[u8]> for $T {
            #[inline]
            fn as_mut(&mut self) -> &mut [u8] {
                let ptr = self as *mut $T as *mut u8;
                unsafe { &mut *std::slice::from_raw_parts_mut(ptr, size_of::<$T>()) }
            }
        }
    };
}

macro_rules! impl_pub_getter_setter {
    ($G: ident, $S: ident, $F: ident, $U: ty) => {
        #[inline]
        pub fn $G(&self) -> $U {
            <$U>::from_le(self.$F)
        }

        #[inline]
        pub fn $S(&mut self, $F: $U) {
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
    /// block size
    s_block_size: u32,
    /// superblock flags
    s_flags: u64,
    /// V5: Number of unique inodes(hard link counts as 1).
    s_inodes_count: u64,
    /// V5: Offset of inode table
    s_inode_table_offset: u64,
    /// V5: Offset of blob table
    s_blob_table_offset: u64,
    /// V5: Size of inode table
    s_inode_table_entries: u32,
    /// V5: Entries of blob table
    s_blob_table_size: u32,
    /// Unused area
    s_reserved: [u8; RAFS_SUPERBLOCK_RESERVED_SIZE],
}

impl Default for OndiskSuperBlock {
    fn default() -> Self {
        Self {
            s_magic: u32::to_le(RAFS_SUPER_MAGIC as u32),
            s_fs_version: u32::to_le(RAFS_SUPER_VERSION_V5),
            s_sb_size: u32::to_le(RAFS_SUPERBLOCK_SIZE as u32),
            s_block_size: u32::to_le(RAFS_DEFAULT_BLOCK_SIZE as u32),
            s_flags: u64::to_le(0),
            s_inodes_count: u64::to_le(0),
            s_inode_table_entries: u32::to_le(0),
            s_inode_table_offset: u64::to_le(0),
            s_blob_table_size: u32::to_le(0),
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
        {
            return Err(err_invalid_superblock!());
        }

        match self.version() {
            RAFS_SUPER_VERSION_V4 => {
                if self.inodes_count() != 0
                    || self.inode_table_offset() != 0
                    || self.inode_table_entries() != 0
                {
                    return Err(err_invalid_superblock!());
                }
            }
            RAFS_SUPER_VERSION_V5 => {
                if self.inodes_count() == 0
                    || self.inode_table_offset() < RAFS_SUPERBLOCK_SIZE as u64
                    || self.inode_table_offset() & 0x7 != 0
                {
                    return Err(err_invalid_superblock!());
                }
            }
            _ => {
                return Err(einval!("invalid superblock version number"));
            }
        }

        // TODO: validate block_size, flags and reserved.

        Ok(())
    }

    impl_pub_getter_setter!(magic, set_magic, s_magic, u32);
    impl_pub_getter_setter!(version, set_version, s_fs_version, u32);
    impl_pub_getter_setter!(sb_size, set_sb_size, s_sb_size, u32);
    impl_pub_getter_setter!(block_size, set_block_size, s_block_size, u32);
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
    impl_pub_getter_setter!(blob_table_size, set_blob_table_size, s_blob_table_size, u32);
    impl_pub_getter_setter!(
        blob_table_offset,
        set_blob_table_offset,
        s_blob_table_offset,
        u64
    );

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }
}

impl RafsStore for OndiskSuperBlock {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
        w.write_all(self.as_ref())?;
        Ok(self.as_ref().len())
    }
}

impl_metadata_converter!(OndiskSuperBlock);

impl fmt::Display for OndiskSuperBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "superblock: magic {:x}, version {:x}, sb_size {:x}, block_size {:x}, flags {:x}, inode_count {}",
               self.magic(), self.version(), self.sb_size(), self.block_size(),
               self.flags(), self.s_inodes_count)
    }
}

#[repr(C)]
#[derive(Clone, Default)]
pub struct OndiskInodeTable {
    pub(crate) data: Vec<u32>,
}

impl OndiskInodeTable {
    pub fn new(entries: usize) -> Self {
        let table_size = align_to_rafs(entries * size_of::<u32>()) / size_of::<u32>();
        OndiskInodeTable {
            data: vec![0; table_size],
        }
    }

    #[inline]
    pub fn size(&self) -> usize {
        align_to_rafs(self.data.len() * size_of::<u32>())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.len() == 0
    }

    pub fn set(&mut self, ino: Inode, inode_offset: u32) -> Result<()> {
        if ino > self.data.len() as u64 {
            return Err(einval!("invalid inode number"));
        }

        let offset = inode_offset >> 3;
        self.data[(ino - 1) as usize] = offset as u32;

        Ok(())
    }

    pub fn get(&self, ino: Inode) -> Result<u32> {
        if ino > self.data.len() as u64 {
            return Err(enoent!("inode not found"));
        }

        let offset = u32::from_le(self.data[(ino - 1) as usize]) as usize;
        if offset <= (RAFS_SUPERBLOCK_SIZE >> 3) || offset >= (1usize << 29) {
            return Err(einval!("invalid inode offset"));
        }

        Ok((offset << 3) as u32)
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let (_, data, _) = unsafe { self.data.align_to_mut::<u8>() };
        r.read_exact(data)?;
        Ok(())
    }
}

impl RafsStore for OndiskInodeTable {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let (_, data, _) = unsafe { self.data.align_to::<u8>() };
        w.write_all(data)?;
        Ok(data.len())
    }
}

#[derive(Clone, Debug, Default)]
pub struct OndiskBlobTableEntry {
    pub readahead_offset: u32,
    pub readahead_size: u32,
    pub blob_id: String,
}

impl OndiskBlobTableEntry {
    pub fn size(&self) -> usize {
        size_of::<u32>() * 2 + self.blob_id.len()
    }
}

#[derive(Clone, Debug, Default)]
pub struct OndiskBlobTable {
    pub entries: Vec<OndiskBlobTableEntry>,
}

impl OndiskBlobTable {
    pub fn new() -> Self {
        OndiskBlobTable {
            entries: Vec::new(),
        }
    }

    #[inline]
    pub fn minimum_size(blob_id_size: usize) -> usize {
        align_to_rafs(size_of::<u32>() * 2 + blob_id_size)
    }

    /// Get blob table size, aligned with RAFS_ALIGNMENT bytes
    pub fn size(&self) -> usize {
        // blob entry splited with '\0'
        align_to_rafs(
            self.entries
                .iter()
                .fold(0usize, |size, entry| size + entry.size() + 1)
                - 1,
        )
    }

    pub fn add(&mut self, blob_id: String, readahead_offset: u32, readahead_size: u32) -> u32 {
        self.entries.push(OndiskBlobTableEntry {
            blob_id,
            readahead_offset,
            readahead_size,
        });
        (self.entries.len() - 1) as u32
    }

    #[inline]
    pub fn get(&self, blob_index: u32) -> Result<OndiskBlobTableEntry> {
        if blob_index > (self.entries.len() - 1) as u32 {
            return Err(enoent!("blob not found"));
        }
        Ok(self.entries[blob_index as usize].clone())
    }

    pub fn load(&mut self, r: &mut RafsIoReader, size: usize) -> Result<()> {
        let mut input = vec![0u8; size];

        r.read_exact(&mut input)?;
        self.load_from_slice(&input)
    }

    pub fn load_from_slice(&mut self, input: &[u8]) -> Result<()> {
        let mut input_rest = input;
        loop {
            let (readahead, rest) = input_rest.split_at(std::mem::size_of::<u64>());
            let (readahead_offset, readahead_size) = readahead.split_at(std::mem::size_of::<u32>());

            let readahead_offset =
                u32::from_le_bytes(readahead_offset.try_into().map_err(|e| einval!(e))?);
            let readahead_size =
                u32::from_le_bytes(readahead_size.try_into().map_err(|e| einval!(e))?);

            let (blob_id, rest) = parse_string(rest)?;

            self.entries.push(OndiskBlobTableEntry {
                blob_id: blob_id.to_string(),
                readahead_offset,
                readahead_size,
            });
            if rest.is_empty() || rest.as_bytes()[0] == b'\0' {
                break;
            }
            input_rest = rest.as_bytes();
        }

        Ok(())
    }

    pub fn get_all(&self) -> Vec<OndiskBlobTableEntry> {
        self.entries.clone()
    }
}

impl RafsStore for OndiskBlobTable {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut size = 0;

        self.entries
            .iter()
            .enumerate()
            .map(|(idx, entry)| {
                w.write_all(&u32::to_le_bytes(entry.readahead_offset))?;
                w.write_all(&u32::to_le_bytes(entry.readahead_size))?;
                w.write_all(entry.blob_id.as_bytes())?;
                if idx != self.entries.len() - 1 {
                    size += size_of::<u32>() * 2 + entry.blob_id.len() + 1;
                    w.write_all(&[b'\0'])?;
                } else {
                    size += size_of::<u32>() * 2 + entry.blob_id.len();
                }
                Ok(())
            })
            .collect::<Result<()>>()?;
        w.seek_offset((align_to_rafs(size) - size) as u64)?;

        Ok(size)
    }
}

/// Ondisk rafs inode
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct OndiskInode {
    /// sha256(sha256(chunk) + ...), [char; RAFS_SHA256_LENGTH]
    pub i_digest: OndiskDigest,
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
    /// for dir, child start index
    pub i_child_index: u32,
    /// for dir, means child count.
    /// for regular file, means chunk info count.
    pub i_child_count: u32,
    /// file name size, [char; i_name_size]
    pub i_name_size: u16,
    /// symlink path size, [char; i_symlink_size]
    pub i_symlink_size: u16,
}

impl OndiskInode {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn set_name_size(&mut self, name_len: usize) {
        self.i_name_size = align_to_rafs(name_len) as u16;
    }

    #[inline]
    pub fn set_symlink_size(&mut self, symlink_len: usize) {
        self.i_symlink_size = align_to_rafs(symlink_len) as u16;
    }

    #[inline]
    pub fn size(&self) -> usize {
        size_of::<Self>() + (self.i_name_size + self.i_symlink_size) as usize
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }

    #[inline]
    pub fn is_dir(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFDIR
    }

    #[inline]
    pub fn is_symlink(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFLNK
    }

    #[inline]
    pub fn is_reg(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFREG
    }

    #[inline]
    pub fn is_hardlink(&self) -> bool {
        self.i_nlink > 1
    }

    #[inline]
    pub fn has_xattr(&self) -> bool {
        self.i_flags & INO_FLAG_XATTR == INO_FLAG_XATTR
    }
}

pub struct OndiskInodeWrapper<'a> {
    pub name: &'a String,
    pub symlink: Option<&'a String>,
    pub inode: &'a OndiskInode,
}

impl<'a> RafsStore for OndiskInodeWrapper<'a> {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut size: usize = 0;

        let inode_data = self.inode.as_ref();
        w.write_all(inode_data)?;
        size += inode_data.len();

        let name = self.name.as_bytes();
        w.write_all(name)?;
        size += name.len();

        let padding = self.inode.i_name_size as usize - name.len();
        w.seek_offset(padding as u64)?;
        size += padding;

        if let Some(symlink) = self.symlink {
            let symlink_path = symlink.as_bytes();
            w.write_all(symlink_path)?;
            size += symlink_path.len();
            let padding = self.inode.i_symlink_size as usize - symlink_path.len();
            w.seek_offset(padding as u64)?;
            size += padding;
        }

        Ok(size)
    }
}

impl_metadata_converter!(OndiskInode);

/// On disk Rafs data chunk information.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OndiskChunkInfo {
    /// sha256(chunk), [char; RAFS_SHA256_LENGTH]
    pub block_id: OndiskDigest,
    /// blob index (blob_id = blob_table[blob_index])
    pub blob_index: u32,
    /// CHUNK_FLAG_COMPRESSED
    pub flags: u32,

    /// compressed size
    pub compress_size: u32,
    /// decompressed size
    pub decompress_size: u32,
    /// blob compressed offset
    pub blob_compress_offset: u64,
    /// blob decompressed offset
    pub blob_decompress_offset: u64,

    /// file position of block, with fixed block length
    pub file_offset: u64,
    /// reserved
    pub reserved: u64,
}

impl OndiskChunkInfo {
    pub fn new() -> Self {
        OndiskChunkInfo::default()
    }

    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        r.read_exact(self.as_mut())
    }
}

impl RafsStore for OndiskChunkInfo {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
        w.write_all(self.as_ref())?;
        Ok(self.as_ref().len())
    }
}

impl RafsChunkInfo for OndiskChunkInfo {
    fn validate(&self, _sb: &RafsSuperMeta) -> Result<()> {
        self.block_id.validate()?;
        Ok(())
    }

    #[inline]
    fn block_id(&self) -> Arc<dyn RafsDigest> {
        Arc::new(self.block_id)
    }

    #[inline]
    fn is_compressed(&self) -> bool {
        self.flags & CHUNK_FLAG_COMPRESSED == CHUNK_FLAG_COMPRESSED
    }

    impl_getter!(blob_index, blob_index, u32);
    impl_getter!(blob_compress_offset, blob_compress_offset, u64);
    impl_getter!(compress_size, compress_size, u32);
    impl_getter!(blob_decompress_offset, blob_decompress_offset, u64);
    impl_getter!(decompress_size, decompress_size, u32);
    impl_getter!(file_offset, file_offset, u64);
}

impl_metadata_converter!(OndiskChunkInfo);

impl Default for OndiskChunkInfo {
    fn default() -> Self {
        OndiskChunkInfo {
            block_id: OndiskDigest::default(),
            blob_index: 0,
            file_offset: 0,
            compress_size: 0,
            decompress_size: 0,
            blob_compress_offset: 0,
            blob_decompress_offset: 0,
            flags: 0,
            reserved: 0,
        }
    }
}

impl fmt::Display for OndiskChunkInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "file_offset {}, blob_compress_offset {}, compress_size {}, blob_decompress_offset {}, decompress_size {}, block_id {}",
            self.file_offset,
            self.blob_compress_offset,
            self.compress_size,
            self.blob_decompress_offset,
            self.decompress_size,
            self.block_id.to_string(),
        )
    }
}

/// On disk Rafs SHA256 digest data.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Hash)]
pub struct OndiskDigest {
    data: [u8; RAFS_SHA256_LENGTH],
}

impl OndiskDigest {
    pub fn new() -> Self {
        OndiskDigest {
            ..Default::default()
        }
    }

    pub fn from_digest(sha: Sha256) -> Self {
        let mut digest = OndiskDigest::new();
        digest.data.clone_from_slice(&sha.finalize());
        digest
    }

    pub fn from_buf(buf: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(buf);
        Self::from_digest(hash)
    }

    pub fn from_raw(data: &[u8; RAFS_SHA256_LENGTH]) -> Self {
        OndiskDigest { data: *data }
    }
}

impl RafsDigest for OndiskDigest {
    fn validate(&self) -> Result<()> {
        Ok(())
    }

    #[inline]
    fn data(&self) -> &[u8] {
        &self.data
    }

    #[inline]
    fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    fn to_string(&self) -> String {
        let mut ret = String::new();

        for c in &self.data {
            write!(ret, "{:02x}", c).unwrap();
        }

        ret
    }
}

impl_metadata_converter!(OndiskDigest);

/// On disk xattr data.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct OndiskXAttrs {
    pub size: u64,
}

impl_metadata_converter!(OndiskXAttrs);

impl OndiskXAttrs {
    pub fn new() -> Self {
        OndiskXAttrs {
            ..Default::default()
        }
    }

    #[inline]
    pub fn size(self) -> usize {
        self.size as usize
    }

    #[inline]
    pub fn aligned_size(self) -> usize {
        align_to_rafs(self.size())
    }
}

pub type XattrName = Vec<u8>;
pub type XattrValue = Vec<u8>;

#[derive(Clone, Default)]
pub struct XAttrs {
    pub pairs: HashMap<String, Vec<u8>>,
}

impl XAttrs {
    pub fn size(&self) -> usize {
        let mut size: usize = 0;

        for (key, value) in self.pairs.iter() {
            size += size_of::<u32>();
            size += key.as_bytes().len() + 1 + value.len();
        }

        size
    }

    #[inline]
    pub fn aligned_size(&self) -> usize {
        align_to_rafs(self.size())
    }
}

impl RafsStore for XAttrs {
    fn store_inner(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut size = 0;

        if !self.pairs.is_empty() {
            let size_data = (self.size() as u64).to_le_bytes();
            w.write_all(&size_data)?;
            size += size_data.len();

            for (key, value) in self.pairs.iter() {
                let pair_size = key.as_bytes().len() + 1 + value.len();
                let pair_size_data = (pair_size as u32).to_le_bytes();
                w.write_all(&pair_size_data)?;
                size += pair_size_data.len();

                let key_data = key.as_bytes();
                w.write_all(key_data)?;
                w.write_all(&[0u8])?;
                size += key_data.len() + 1;

                w.write_all(value)?;
                size += value.len();
            }
        }

        let padding = align_to_rafs(size) - size;
        w.seek_offset(padding as u64)?;
        size += padding;

        Ok(size)
    }
}

#[inline]
pub fn align_to_rafs(size: usize) -> usize {
    if size & (RAFS_ALIGNMENT - 1) == 0 {
        return size;
    }
    size + (RAFS_ALIGNMENT - (size & (RAFS_ALIGNMENT - 1)))
}

/// Parse a `buf` to utf-8 string.
pub fn parse_string(buf: &[u8]) -> Result<(&str, &str)> {
    std::str::from_utf8(buf)
        .map(|origin| {
            if let Some(pos) = origin.find('\0') {
                origin.split_at(pos)
            } else {
                (origin, "")
            }
        })
        .map_err(|_| einval!("failed to parse string"))
}

/// Parse a 'buf' to xattr pair then callback.
pub fn parse_xattr<F>(data: &[u8], size: usize, mut cb: F) -> Result<()>
where
    F: FnMut(&str, XattrValue) -> bool,
{
    let mut i: usize = 0;
    let mut rest_data = &data[0..size];

    while i < size {
        let (pair_size, rest) = rest_data.split_at(size_of::<u32>());
        let pair_size = u32::from_le_bytes(
            pair_size
                .try_into()
                .map_err(|_| einval!("failed to parse xattr pair size"))?,
        ) as usize;
        i += size_of::<u32>();

        let (pair, rest) = rest.split_at(pair_size);
        if let Some(pos) = pair.iter().position(|&c| c == 0) {
            let (name, value) = pair.split_at(pos);
            let name =
                std::str::from_utf8(name).map_err(|_| einval!("failed to convert xattr name"))?;
            let value = value[1..].to_vec();
            if !cb(name, value) {
                break;
            }
        }
        i += pair_size;

        rest_data = rest;
    }

    Ok(())
}

/// Parse a 'buf' to xattr name list.
pub fn parse_xattr_names(data: &[u8], size: usize) -> Result<Vec<XattrName>> {
    let mut result = Vec::new();

    parse_xattr(data, size, |name, _| {
        result.push(name.as_bytes().to_vec());
        true
    })?;

    Ok(result)
}

/// Parse a 'buf' to xattr value by xattr name.
pub fn parse_xattr_value(data: &[u8], size: usize, name: &str) -> Result<Option<XattrValue>> {
    let mut value = None;

    parse_xattr(data, size, |_name, _value| {
        if _name == name {
            value = Some(_value);
            // stop the iteration if we found the xattr name.
            return false;
        }
        true
    })?;

    Ok(value)
}
