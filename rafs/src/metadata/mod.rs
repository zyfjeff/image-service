// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Structs and Traits for RAFS file system meta data management.

use std::collections::HashMap;
use std::fmt;
use std::io::Result;
use std::time::Duration;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use fuse_rs::abi::linux_abi::Attr;
use fuse_rs::api::filesystem::Entry;

use self::cached::CachedInodes;
use self::layout::{
    OndiskDigest, OndiskSuperBlock, INO_FLAG_XATTR, RAFS_SUPER_VERSION_V4, RAFS_SUPER_VERSION_V5,
};
use self::noop::NoopInodes;
use crate::fs::{Inode, RAFS_DEFAULT_ATTR_TIMEOUT, RAFS_DEFAULT_ENTRY_TIMEOUT};
use crate::metadata::direct_map::DirectMapInodes;
use crate::metadata::layout::{OndiskInode, RAFS_CHUNK_INFO_SIZE};
use crate::storage::device::RafsBioDesc;
use crate::{ebadf, einval, enosys, RafsIoReader, RafsIoWriter};

pub mod cached;
pub mod direct_map;
pub mod layout;
pub(crate) mod noop;

pub const RAFS_SHA256_LENGTH: usize = 32;
pub const RAFS_BLOB_ID_MAX_LENGTH: usize = 72;
pub const RAFS_INODE_BLOCKSIZE: u32 = 4096;
pub const RAFS_MAX_NAME: usize = 255;
pub const RAFS_DEFAULT_BLOCK_SIZE: usize = 1024 * 1024;
pub const RAFS_MAX_METADATA_SIZE: usize = 0x8000_0000;

/// Cached Rafs super block metadata.
pub struct RafsSuperMeta {
    pub s_magic: u32,
    pub s_version: u32,
    pub s_sb_size: u32,
    pub s_inode_size: u32,
    pub s_root_inode: Inode,
    pub s_block_size: u32,
    pub s_blocks_count: u64,
    pub s_inodes_count: u64,
    pub s_chunkinfo_size: u32,
    pub s_flags: u64,
    pub s_mapping_table_entries: u32,
    pub s_mapping_table_offset: u64,
    pub s_attr_timeout: Duration,
    pub s_entry_timeout: Duration,
}

/// Cached Rafs super block and inode information.
pub struct RafsSuper {
    pub s_meta: RafsSuperMeta,
    pub s_inodes: Box<dyn RafsSuperInodes>,
    load_inodes: bool,
    cache_inodes: bool,
}

impl RafsSuper {
    pub fn new() -> Self {
        RafsSuper {
            s_meta: RafsSuperMeta {
                s_magic: 0,
                s_version: 0,
                s_sb_size: 0,
                s_inode_size: 0,
                s_inodes_count: 0,
                s_root_inode: 0,
                s_block_size: 0,
                s_blocks_count: 0,
                s_chunkinfo_size: 0,
                s_flags: 0,
                s_mapping_table_entries: 0,
                s_mapping_table_offset: 0,
                s_attr_timeout: Duration::from_secs(RAFS_DEFAULT_ATTR_TIMEOUT),
                s_entry_timeout: Duration::from_secs(RAFS_DEFAULT_ENTRY_TIMEOUT),
            },
            s_inodes: Box::new(NoopInodes::new()),
            load_inodes: true,
            cache_inodes: false,
        }
    }

    pub fn destroy(&mut self) {
        self.s_inodes.destroy();
    }

    /// Load RAFS super block and optionally cache inodes.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let mut sb = OndiskSuperBlock::new();

        r.read_exact(sb.as_mut())?;
        sb.validate()?;

        self.s_meta.s_magic = sb.magic();
        self.s_meta.s_version = sb.version();
        self.s_meta.s_sb_size = sb.sb_size();
        self.s_meta.s_inode_size = sb.inode_size();
        self.s_meta.s_block_size = sb.block_size();
        self.s_meta.s_chunkinfo_size = sb.chunkinfo_size();
        self.s_meta.s_flags = sb.flags();
        self.s_meta.s_blocks_count = 0;
        match self.s_meta.s_version {
            RAFS_SUPER_VERSION_V4 => {
                self.s_meta.s_inodes_count = std::u64::MAX;
            }
            RAFS_SUPER_VERSION_V5 => {
                self.s_meta.s_inodes_count = sb.inodes_count();
                self.s_meta.s_mapping_table_entries = sb.mapping_table_entries();
                self.s_meta.s_mapping_table_offset = sb.mapping_table_offset();
            }
            _ => return Err(ebadf()),
        }

        // TODO: how about flags, chunkinfo_size?

        match sb.version() {
            RAFS_SUPER_VERSION_V4 => {
                let mut inodes = Box::new(CachedInodes::new());
                inodes.load(&mut self.s_meta, r)?;
                self.s_inodes.destroy();
                self.s_inodes = inodes;
            }
            RAFS_SUPER_VERSION_V5 => {
                if self.load_inodes {
                    if self.cache_inodes {
                        unimplemented!();
                    } else {
                        let mut inodes = Box::new(DirectMapInodes::new());
                        inodes.load(&mut self.s_meta, r)?;
                        self.s_inodes.destroy();
                        self.s_inodes = inodes;
                    }
                }
            }
            _ => return Err(einval()),
        }

        Ok(())
    }

    /// Store RAFS metadata to backend storage.
    pub fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut sb = OndiskSuperBlock::new();

        sb.set_magic(self.s_meta.s_magic);
        sb.set_version(self.s_meta.s_version);
        sb.set_sb_size(self.s_meta.s_sb_size);
        sb.set_inode_size(self.s_meta.s_inode_size);
        sb.set_block_size(self.s_meta.s_block_size);
        sb.set_chunkinfo_size(self.s_meta.s_chunkinfo_size);
        sb.set_flags(self.s_meta.s_flags);
        match self.s_meta.s_version {
            RAFS_SUPER_VERSION_V4 => {}
            RAFS_SUPER_VERSION_V5 => {
                sb.set_inodes_count(self.s_meta.s_inodes_count);
                sb.set_mapping_table_entries(self.s_meta.s_mapping_table_entries);
                sb.set_mapping_table_offset(self.s_meta.s_mapping_table_offset);
            }
            _ => return Err(einval()),
        }
        sb.validate()?;
        w.write_all(sb.as_ref())?;
        trace!("written superblock: {}", &sb);

        // TODO: write out other metadata

        Ok(std::mem::size_of::<OndiskSuperBlock>())
    }

    pub fn get_inode(&self, ino: Inode) -> Result<&dyn RafsInode> {
        self.s_inodes.get_inode(ino)
    }
}

/// Trait to manage all inodes of a file system.
pub trait RafsSuperInodes {
    fn load(&mut self, sb: &mut RafsSuperMeta, r: &mut RafsIoReader) -> Result<()>;
    fn destroy(&mut self);

    fn get_inode(&self, ino: Inode) -> Result<&dyn RafsInode>;

    fn get_symlink<'a, 'b>(&'a self, _inode: &'b OndiskInode) -> Result<&'b [u8]> {
        Err(enosys())
    }

    fn get_xattrs(&self, _inode: &OndiskInode) -> Result<HashMap<String, Vec<u8>>> {
        Err(enosys())
    }

    fn alloc_bio_desc<'a, 'b>(
        &'a self,
        _blksize: u32,
        _size: usize,
        _offset: u64,
        _inode: &'b OndiskInode,
    ) -> Result<RafsBioDesc<'b>> {
        Err(enosys())
    }
}

/// Trait to access Rafs Inode Information.
pub trait RafsInode {
    /// Validate the object for safety.
    ///
    /// The object may be transmuted from a raw buffer read from an external file, so the caller
    /// must validate it before accessing any fields of the object.
    fn validate(&self, sb: &RafsSuperMeta) -> Result<()>;

    fn get_entry(&self, sb: &RafsSuperMeta) -> Entry;
    fn get_attr(&self) -> Attr;
    fn get_symlink(&self, sb: &RafsSuper) -> Result<&[u8]>;
    fn get_xattrs(&self, sb: &RafsSuper) -> Result<HashMap<String, Vec<u8>>>;
    fn get_child_count(&self, sb: &RafsSuper) -> Result<usize>;
    fn get_child_by_index<'a, 'b>(
        &'a self,
        index: usize,
        sb: &'b RafsSuper,
    ) -> Result<&'b dyn RafsInode>;
    fn get_child_by_name<'a, 'b>(
        &'a self,
        target: &str,
        sb: &'b RafsSuper,
    ) -> Result<&'b dyn RafsInode>;
    fn alloc_bio_desc(
        &self,
        blksize: u32,
        size: usize,
        offset: u64,
        sb: &RafsSuper,
    ) -> Result<RafsBioDesc>;

    // Simply accessors below
    fn name(&self) -> &str;
    fn set_name(&mut self, name: &str) -> Result<()>;
    fn digest(&self) -> &OndiskDigest;
    fn set_digest(&mut self, digest: &OndiskDigest);
    fn parent(&self) -> Inode;
    fn set_parent(&mut self, parent: Inode);
    fn ino(&self) -> Inode;
    fn set_ino(&mut self, ino: Inode);
    fn projid(&self) -> u32;
    fn set_projid(&mut self, projid: u32);
    fn mode(&self) -> u32;
    fn set_mode(&mut self, mode: u32);
    fn uid(&self) -> u32;
    fn set_uid(&mut self, uid: u32);
    fn gid(&self) -> u32;
    fn set_gid(&mut self, gid: u32);
    fn rdev(&self) -> u64;
    fn set_rdev(&mut self, rdev: u64);
    fn size(&self) -> u64;
    fn set_size(&mut self, size: u64);
    fn nlink(&self) -> u64;
    fn set_nlink(&mut self, nlink: u64);
    fn blocks(&self) -> u64;
    fn set_blocks(&mut self, blocks: u64);
    fn atime(&self) -> u64;
    fn set_atime(&mut self, atime: u64);
    fn mtime(&self) -> u64;
    fn set_mtime(&mut self, mtime: u64);
    fn ctime(&self) -> u64;
    fn set_ctime(&mut self, ctime: u64);
    fn flags(&self) -> u64;
    fn set_flags(&mut self, flags: u64);
    fn chunk_cnt(&self) -> u64;
    fn set_chunk_cnt(&mut self, chunk_cnt: u64);
    fn child_index(&self) -> u32;
    fn set_child_index(&mut self, child_count: u32);
    fn child_count(&self) -> u32;
    fn set_child_count(&mut self, child_count: u32);

    fn is_dir(&self) -> bool {
        self.mode() & libc::S_IFMT == libc::S_IFDIR
    }

    fn is_symlink(&self) -> bool {
        self.mode() & libc::S_IFMT == libc::S_IFLNK
    }

    fn is_reg(&self) -> bool {
        self.mode() & libc::S_IFMT == libc::S_IFREG
    }

    fn is_hardlink(&self) -> bool {
        self.nlink() > 1
    }

    fn has_xattr(&self) -> bool {
        self.flags() & INO_FLAG_XATTR == INO_FLAG_XATTR
    }
}

/// Trait to access Rafs Data Chunk Information.
pub trait RafsChunkInfo {
    /// Validate the object for safety.
    ///
    /// The object may be transmuted from a raw buffer read from an external file, so the caller
    /// must validate it before accessing any fields of the object.
    fn validate(&self, sb: &RafsSuperMeta) -> Result<()>;

    fn blockid(&self) -> &OndiskDigest;
    fn blockid_mut(&mut self) -> &mut OndiskDigest;
    fn set_blockid(&mut self, digest: &OndiskDigest);

    fn blobid(&self) -> &str;
    fn set_blobid(&mut self, blobid: &str) -> Result<()>;

    fn file_offset(&self) -> u64;
    fn set_file_offset(&mut self, val: u64);

    fn blob_offset(&self) -> u64;
    fn set_blob_offset(&mut self, val: u64);

    fn compress_size(&self) -> u32;
    fn set_compress_size(&mut self, val: u32);
}

/// Trait to access Rafs SHA256 message digest data.
pub trait RafsDigest {
    /// Validate the object for safety.
    ///
    /// The object may be transmuted from a raw buffer read from an external file, so the caller
    /// must validate it before accessing any fields of the object.
    fn validate(&self) -> Result<()>;

    /// Get size of Rafs SHA256 message digest data.
    fn size() -> usize {
        RAFS_SHA256_LENGTH
    }

    /// Compute SHA256 message digest in the `buf`.
    fn digest(&mut self, buf: &[u8]) {
        let mut hash = Sha256::new();
        let data = self.data_mut();
        hash.input(buf);
        hash.result(data);
    }

    /// Get a reference to the underlying data.
    fn data(&self) -> &[u8];

    /// Get a mutable reference to the underlying data.
    fn data_mut(&mut self) -> &mut [u8];
}

pub fn parse_string(buf: &[u8]) -> Result<&str> {
    std::str::from_utf8(buf)
        .map(|s| {
            if let Some(pos) = s.find('\0') {
                s.split_at(pos).0
            } else {
                s
            }
        })
        .map_err(|_| einval())
}

pub fn calc_symlink_size(sz: usize) -> Result<(usize, usize)> {
    if sz >= libc::PATH_MAX as usize {
        Err(einval())
    } else {
        // Need one extra padding '0'
        let size = (sz + RAFS_CHUNK_INFO_SIZE) & !(RAFS_CHUNK_INFO_SIZE - 1);
        Ok((size, size / RAFS_CHUNK_INFO_SIZE))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::metadata::layout::{
        OndiskInode, RAFS_CHUNK_INFO_SIZE, RAFS_INODE_INFO_SIZE, RAFS_SUPERBLOCK_SIZE,
        RAFS_SUPER_MAGIC,
    };
    use crate::{RafsIoRead, RafsIoWrite};
    use fuse_rs::api::filesystem::ROOT_ID;
    use std::io::{Read, Write};
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    pub struct CachedIoBuf {
        data: Arc<Mutex<(Vec<u8>, usize)>>,
    }

    impl CachedIoBuf {
        pub fn new() -> Self {
            CachedIoBuf {
                data: Arc::new(Mutex::new((Vec::new(), 0))),
            }
        }

        pub fn set_buf(&mut self, buf: &[u8]) {
            let mut data = self.data.lock().unwrap();
            data.1 = 0;
            data.0.clear();
            data.0.extend_from_slice(buf);
        }

        pub fn append_buf(&mut self, buf: &[u8]) {
            let mut data = self.data.lock().unwrap();
            data.0.extend_from_slice(buf);
        }

        pub fn len(&self) -> usize {
            let data = self.data.lock().unwrap();
            data.0.len()
        }

        pub fn as_buf(&self) -> (*const u8, usize) {
            let data = self.data.lock().unwrap();
            (data.0.as_ptr(), data.0.len())
        }
    }

    impl Read for CachedIoBuf {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let mut data = self.data.lock().unwrap();
            let min = std::cmp::min(data.0.len() - data.1, buf.len());
            if min > 0 {
                buf[..min].copy_from_slice(&data.0[data.1..data.1 + min]);
                data.1 += min;
            }

            Ok(min)
        }
    }

    impl Write for CachedIoBuf {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.append_buf(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl AsRawFd for CachedIoBuf {
        fn as_raw_fd(&self) -> RawFd {
            0
        }
    }

    impl RafsIoRead for CachedIoBuf {}
    impl RafsIoWrite for CachedIoBuf {}

    #[test]
    fn test_rafs_superblock_v4_load_store() {
        let buf = CachedIoBuf::new();

        let mut sb = RafsSuper::new();
        sb.s_meta.s_magic = RAFS_SUPER_MAGIC;
        sb.s_meta.s_version = RAFS_SUPER_VERSION_V4;
        sb.s_meta.s_sb_size = 0x2000;
        sb.s_meta.s_inode_size = RAFS_INODE_INFO_SIZE as u32;
        sb.s_meta.s_block_size = RAFS_DEFAULT_BLOCK_SIZE as u32;
        sb.s_meta.s_chunkinfo_size = RAFS_CHUNK_INFO_SIZE as u32;
        sb.s_meta.s_flags = 1;

        let mut buf1: Box<dyn RafsIoWrite> = Box::new(buf.clone());
        sb.store(&mut buf1).unwrap();

        let mut ondisk = OndiskInode::new();
        ondisk.set_name("root").unwrap();
        ondisk.set_parent(ROOT_ID);
        ondisk.set_ino(ROOT_ID);
        ondisk.set_mode(libc::S_IFDIR);
        buf1.write_all(ondisk.as_ref()).unwrap();

        assert_eq!(buf.data.lock().unwrap().0.len(), 0x2000 + 512);

        let mut buf2: Box<dyn RafsIoRead> = Box::new(buf.clone());
        let mut sb2 = RafsSuper::new();
        sb2.load(&mut buf2).unwrap();

        assert_eq!(sb.s_meta.s_magic, sb2.s_meta.s_magic);
        assert_eq!(sb.s_meta.s_version, sb2.s_meta.s_version);
        assert_eq!(sb.s_meta.s_sb_size, sb2.s_meta.s_sb_size);
        assert_eq!(sb.s_meta.s_inode_size, sb2.s_meta.s_inode_size);
        assert_eq!(sb.s_meta.s_block_size, sb2.s_meta.s_block_size);
        assert_eq!(sb.s_meta.s_chunkinfo_size, sb2.s_meta.s_chunkinfo_size);
        assert_eq!(sb.s_meta.s_flags, sb2.s_meta.s_flags);
    }

    #[test]
    fn test_rafs_superblock_v5_load_store() {
        let buf = CachedIoBuf::new();

        let mut sb = RafsSuper::new();
        sb.s_meta.s_magic = RAFS_SUPER_MAGIC;
        sb.s_meta.s_version = RAFS_SUPER_VERSION_V5;
        sb.s_meta.s_sb_size = 0x2000;
        sb.s_meta.s_inode_size = RAFS_INODE_INFO_SIZE as u32;
        sb.s_meta.s_block_size = RAFS_DEFAULT_BLOCK_SIZE as u32;
        sb.s_meta.s_chunkinfo_size = RAFS_CHUNK_INFO_SIZE as u32;
        sb.s_meta.s_flags = 1;
        sb.s_meta.s_mapping_table_offset = RAFS_SUPERBLOCK_SIZE as u64;
        sb.s_meta.s_mapping_table_entries = 1024;
        sb.s_meta.s_inodes_count = 1000;

        let mut buf1: Box<dyn RafsIoWrite> = Box::new(buf.clone());
        sb.store(&mut buf1).unwrap();

        let mut ondisk = OndiskInode::new();
        ondisk.set_name("root").unwrap();
        ondisk.set_parent(ROOT_ID);
        ondisk.set_ino(ROOT_ID);
        ondisk.set_mode(libc::S_IFDIR);
        buf1.write_all(ondisk.as_ref()).unwrap();

        assert_eq!(buf.data.lock().unwrap().0.len(), 0x2000 + 512);

        let mut buf2: Box<dyn RafsIoRead> = Box::new(buf.clone());
        let mut sb2 = RafsSuper::new();
        sb2.load_inodes = false;
        sb2.load(&mut buf2).unwrap();

        assert_eq!(sb.s_meta.s_magic, sb2.s_meta.s_magic);
        assert_eq!(sb.s_meta.s_version, sb2.s_meta.s_version);
        assert_eq!(sb.s_meta.s_sb_size, sb2.s_meta.s_sb_size);
        assert_eq!(sb.s_meta.s_inode_size, sb2.s_meta.s_inode_size);
        assert_eq!(sb.s_meta.s_block_size, sb2.s_meta.s_block_size);
        assert_eq!(sb.s_meta.s_chunkinfo_size, sb2.s_meta.s_chunkinfo_size);
        assert_eq!(sb.s_meta.s_flags, sb2.s_meta.s_flags);
    }

    #[test]
    fn test_ondisk_parse_string() {
        assert!(parse_string(&[0, 159, 146, 150]).is_err());
        assert_eq!(parse_string(&[240, 159, 146, 150]).unwrap(), "💖");
        assert_eq!(parse_string(&[240, 159, 146, 150, 0]).unwrap(), "💖");
        assert_eq!(
            parse_string(&[240, 159, 146, 150, 0, 0, 0, 0]).unwrap(),
            "💖"
        );
        assert_eq!(
            parse_string(&[240, 159, 146, 150, 0, 41, 0, 41]).unwrap(),
            "💖"
        );
    }
}
