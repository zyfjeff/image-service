// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! RAFS on disk layout structures.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::{Error, ErrorKind, Result};
use std::str;

use fuse_rs::abi::linux_abi::Attr;
use fuse_rs::api::filesystem::ROOT_ID;

use super::*;
use crate::einval;

pub const INO_FLAG_HARDLINK: u64 = 0x1000;
pub const INO_FLAG_SYMLINK: u64 = 0x2000;
pub const INO_FLAG_XATTR: u64 = 0x4000;
pub const INO_FLAG_ALL: u64 = INO_FLAG_HARDLINK | INO_FLAG_SYMLINK | INO_FLAG_XATTR;

pub const RAFS_SUPERBLOCK_SIZE: usize = 8192;
pub const RAFS_SUPERBLOCK_RESERVED_SIZE: usize = RAFS_SUPERBLOCK_SIZE - 32;
pub const RAFS_SUPER_MAGIC: u32 = 0x5241_4653;
pub const RAFS_SUPER_VERSION: u32 = 0x400;
pub const RAFS_SUPER_MIN_VERSION: u32 = 0x400;
pub const RAFS_INODE_INFO_SIZE: usize = 512;
pub const RAFS_INODE_INFO_RESERVED_SIZE: usize = RAFS_INODE_INFO_SIZE - 392;
pub const RAFS_CHUNK_INFO_SIZE: usize = 128;
pub const RAFS_XATTR_ALIGNMENT: usize = 8;

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
    /// Unused area.
    s_reserved: [u8; RAFS_SUPERBLOCK_RESERVED_SIZE],
}

impl OndiskSuperBlock {
    pub fn new() -> Self {
        OndiskSuperBlock {
            s_magic: u32::to_le(RAFS_SUPER_MAGIC as u32),
            s_fs_version: u32::to_le(RAFS_SUPER_VERSION),
            s_sb_size: u32::to_le(RAFS_SUPERBLOCK_SIZE as u32),
            s_inode_size: u32::to_le(RAFS_INODE_INFO_SIZE as u32),
            s_block_size: u32::to_le(RAFS_DEFAULT_BLOCK_SIZE as u32),
            s_chunkinfo_size: u32::to_le(RAFS_CHUNK_INFO_SIZE as u32),
            s_flags: u64::to_le(0),
            s_reserved: [0u8; RAFS_SUPERBLOCK_RESERVED_SIZE],
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.magic() != RAFS_SUPER_MAGIC
            || self.version() < RAFS_SUPER_MIN_VERSION as u32
            || self.version() > RAFS_SUPER_VERSION as u32
            || self.sb_size() != RAFS_SUPERBLOCK_SIZE as u32
            || self.inode_size() != RAFS_INODE_INFO_SIZE as u32
            || self.chunkinfo_size() != RAFS_CHUNK_INFO_SIZE as u32
        {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid superblock"));
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
}

impl_metadata_converter!(OndiskSuperBlock);

impl fmt::Display for OndiskSuperBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "superblock: magic {:x}, version {:x}, sb_size {:x}, inode_size {:x}, block_size {:x}, chunkinfo_size {:x}, flags {:x}",
               self.magic(), self.version(), self.sb_size(), self.inode_size(), self.block_size(),
               self.chunkinfo_size(), self.flags())
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
    i_reserved: [u8; RAFS_INODE_INFO_RESERVED_SIZE],
}

impl OndiskInode {
    pub fn new() -> Self {
        OndiskInode {
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
            i_reserved: [0u8; RAFS_INODE_INFO_RESERVED_SIZE],
        }
    }
}

impl RafsInode for OndiskInode {
    fn validate(&self, sb: &RafsSuperMeta) -> Result<()> {
        let name = parse_string(&self.i_name[0..=RAFS_MAX_NAME])?;

        if name.len() > RAFS_MAX_NAME {
            return Err(einval());
        }
        if self.parent() < ROOT_ID
            || self.parent() >= sb.s_inodes_count
            || self.ino() < ROOT_ID
            || self.ino() >= sb.s_inodes_count
            || (self.ino() == self.parent() && self.ino() != ROOT_ID)
            || self.flags() & !INO_FLAG_ALL != 0
            || (self.flags() & INO_FLAG_SYMLINK != 0) != self.is_symlink()
            || (self.is_hardlink() && self.is_symlink())
            || self.nlink() > (std::u32::MAX as u64)
            || self.rdev() > (std::u32::MAX as u64)
        {
            return Err(einval());
        }

        if self.is_reg() {
            if (self.size() + RAFS_INODE_BLOCKSIZE as u64 - 1) / RAFS_INODE_BLOCKSIZE as u64
                != self.chunk_cnt()
            {
                return Err(einval());
            }
        } else if self.is_symlink() {
            // TODO
        } else if self.is_hardlink() {
            // TODO
        }

        // TODO: validate i_size: 0, i_nlink: 0, i_blocks: 0, i_chunk_cnt: 0,

        Ok(())
    }

    fn get_entry(&self, sb: &RafsSuperMeta) -> Entry {
        Entry {
            attr: self.get_attr().into(),
            inode: self.i_ino,
            generation: 0,
            attr_timeout: sb.s_attr_timeout,
            entry_timeout: sb.s_entry_timeout,
        }
    }

    fn get_attr(&self) -> Attr {
        Attr {
            ino: self.ino(),
            size: self.size(),
            blocks: self.blocks(),
            atime: self.atime(),
            ctime: self.ctime(),
            mtime: self.mtime(),
            mode: self.mode(),
            nlink: self.nlink() as u32,
            uid: self.uid(),
            gid: self.gid(),
            rdev: self.rdev() as u32,
            blksize: RAFS_INODE_BLOCKSIZE,
            ..Default::default()
        }
    }

    fn get_symblink(&self) -> Result<&[u8]> {
        unimplemented!()
    }

    fn get_xattrs(&self) -> Result<HashMap<String, Vec<u8>>> {
        unimplemented!()
    }

    fn get_child_count(&self) -> Result<usize> {
        unimplemented!()
    }

    fn get_child_by_index(&self, _index: usize) -> Result<&dyn RafsInode> {
        unimplemented!()
    }

    fn get_child_by_name(&self, _target: &str, _sb: &RafsSuper) -> Result<&dyn RafsInode> {
        unimplemented!()
    }

    fn alloc_bio_desc(&self, _blksize: u32, _size: usize, _offset: u64) -> Result<RafsBioDesc> {
        unimplemented!()
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
    blockid: OndiskDigest,
    /// random string, [char; RAFS_BLOB_ID_MAX_LENGTH]
    blobid: [u8; RAFS_BLOB_ID_MAX_LENGTH],
    /// file position of block, with fixed block length
    file_offset: u64,
    /// blob offset
    blob_offset: u64,
    /// compressed size
    compress_size: u32,
    /// reserved
    reserved: u32,
}

impl OndiskChunkInfo {
    pub fn new() -> Self {
        OndiskChunkInfo::default()
    }
}

impl RafsChunkInfo for OndiskChunkInfo {
    fn validate(&self, _sb: &RafsSuperMeta) -> Result<()> {
        self.blockid.validate()?;
        parse_string(&self.blobid)?;

        // TODO: validate file_offset, blob_offset, compress_size

        Ok(())
    }

    fn blockid(&self) -> &OndiskDigest {
        &self.blockid
    }

    fn blockid_mut(&mut self) -> &mut OndiskDigest {
        &mut self.blockid
    }

    fn set_blockid(&mut self, digest: &OndiskDigest) {
        self.blockid = *digest;
    }

    fn blobid(&self) -> &str {
        // Assume the caller has validated the object by calling self.validate()
        parse_string(&self.blobid).unwrap()
    }

    fn set_blobid(&mut self, blobid: &str) -> Result<()> {
        let len = blobid.len();
        if len >= RAFS_BLOB_ID_MAX_LENGTH {
            return Err(einval());
        }

        self.blobid[..len].copy_from_slice(blobid.as_bytes());
        self.blobid[len] = 0;

        Ok(())
    }

    impl_getter_setter!(file_offset, set_file_offset, file_offset, u64);
    impl_getter_setter!(blob_offset, set_blob_offset, blob_offset, u64);
    impl_getter_setter!(compress_size, set_compress_size, compress_size, u32);
}

impl_metadata_converter!(OndiskChunkInfo);

impl Default for OndiskChunkInfo {
    fn default() -> Self {
        OndiskChunkInfo {
            blockid: OndiskDigest::default(),
            blobid: [0; RAFS_BLOB_ID_MAX_LENGTH],
            file_offset: 0,
            blob_offset: 0,
            compress_size: 0,
            reserved: 0,
        }
    }
}

impl fmt::Display for OndiskChunkInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "chunkinfo blockid: {}, blobid: {} file offset: {}, blob offset: {}, compressed size: {}",
            self.blockid(), self.blobid(), self.file_offset(), self.blob_offset(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn test_rafs_ondisk_superblock() {
        let mut sb = OndiskSuperBlock::new();

        assert_eq!(
            std::mem::size_of::<OndiskSuperBlock>(),
            RAFS_SUPERBLOCK_SIZE
        );

        assert_eq!(sb.magic(), RAFS_SUPER_MAGIC);
        assert_eq!(sb.version(), RAFS_SUPER_VERSION as u32);
        assert_eq!(sb.sb_size(), RAFS_SUPERBLOCK_SIZE as u32);
        assert_eq!(sb.inode_size(), RAFS_INODE_INFO_SIZE as u32);
        assert_eq!(sb.block_size(), RAFS_DEFAULT_BLOCK_SIZE as u32);
        assert_eq!(sb.chunkinfo_size(), RAFS_CHUNK_INFO_SIZE as u32);
        assert_eq!(sb.flags(), 0);
        sb.validate().unwrap();

        sb.set_magic(0x1);
        assert_eq!(sb.magic(), 1);
        assert_eq!(sb.s_magic, 0x1);
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
        assert_eq!(ptr, &chunk.blockid.data as *const u8);

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
