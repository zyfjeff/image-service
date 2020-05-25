// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Structs and Traits for RAFS file system meta data management.

use std::borrow::Cow;
use std::cmp;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Write;
use std::io::Result;
use std::time::Duration;

use crate::storage::device::{RafsBio, RafsBioDesc};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use fuse_rs::abi::linux_abi::Attr;
use fuse_rs::api::filesystem::Entry;

// use self::cached::CachedInodes;
use self::layout::*;
use self::noop::NoopInodes;
use crate::fs::{Inode, RAFS_DEFAULT_ATTR_TIMEOUT, RAFS_DEFAULT_ENTRY_TIMEOUT};
use crate::metadata::direct::DirectMapping;
use crate::*;
use crate::{ebadf, einval, RafsIoReader, RafsIoWriter};

// pub mod cached;
pub mod direct;
pub mod layout;
pub mod noop;

pub const RAFS_SHA256_LENGTH: usize = 32;
pub const RAFS_BLOB_ID_MAX_LENGTH: usize = 72;
pub const RAFS_INODE_BLOCKSIZE: u32 = 4096;
pub const RAFS_MAX_NAME: usize = 255;
pub const RAFS_DEFAULT_BLOCK_SIZE: usize = 1024 * 1024;
pub const RAFS_MAX_METADATA_SIZE: usize = 0x8000_0000;

/// Cached Rafs super block metadata.
#[derive(Clone, Copy)]
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
    pub s_inode_table_entries: u32,
    pub s_inode_table_offset: u64,
    pub s_blob_table_entries: u32,
    pub s_blob_table_offset: u64,
    pub s_attr_timeout: Duration,
    pub s_entry_timeout: Duration,
}

/// Cached Rafs super block and inode information.
pub struct RafsSuper {
    pub s_meta: RafsSuperMeta,
    pub s_inodes: Box<dyn RafsSuperInodes + Sync + Send>,
    load_inodes: bool,
    cache_inodes: bool,
}

impl Default for RafsSuper {
    fn default() -> Self {
        Self {
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
                s_inode_table_entries: 0,
                s_inode_table_offset: 0,
                s_blob_table_entries: 0,
                s_blob_table_offset: 0,
                s_attr_timeout: Duration::from_secs(RAFS_DEFAULT_ATTR_TIMEOUT),
                s_entry_timeout: Duration::from_secs(RAFS_DEFAULT_ENTRY_TIMEOUT),
            },
            s_inodes: Box::new(NoopInodes::new()),
            load_inodes: true,
            cache_inodes: false,
        }
    }
}

impl RafsSuper {
    pub fn new() -> Self {
        Self::default()
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
                self.s_meta.s_inode_table_entries = sb.inode_table_entries();
                self.s_meta.s_inode_table_offset = sb.inode_table_offset();
            }
            _ => return Err(ebadf()),
        }

        match sb.version() {
            RAFS_SUPER_VERSION_V4 => {
                // let mut inodes = Box::new(CachedInodes::new());
                // inodes.load(&mut self.s_meta, r)?;
                // self.s_inodes.destroy();
                // self.s_inodes = inodes;
            }
            RAFS_SUPER_VERSION_V5 => {
                if self.load_inodes {
                    if self.cache_inodes {
                        unimplemented!();
                    } else {
                        let mut inode_table =
                            OndiskInodeTable::new(sb.inode_table_entries() as usize);
                        inode_table.load(r)?;

                        let mut blob_table = OndiskBlobTable::new(sb.blob_table_entries() as usize);
                        blob_table.load(r)?;

                        let mut inodes = Box::new(DirectMapping::new(inode_table, blob_table));
                        inodes.load(r)?;

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
                sb.set_inode_table_entries(self.s_meta.s_inode_table_entries);
                sb.set_inode_table_offset(self.s_meta.s_inode_table_offset);
            }
            _ => return Err(einval()),
        }
        sb.validate()?;
        w.write_all(sb.as_ref())?;
        trace!("written superblock: {}", &sb);

        // TODO: write out other metadata

        Ok(std::mem::size_of::<OndiskSuperBlock>())
    }

    pub fn get_inode(&self, ino: Inode) -> Result<Box<dyn RafsInode>> {
        self.s_inodes.get_inode(ino, self.s_meta)
    }
}

/// Trait to manage all inodes of a file system.
pub trait RafsSuperInodes {
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()>;

    fn destroy(&mut self);

    fn get_inode(&self, ino: Inode, s_meta: RafsSuperMeta) -> Result<Box<dyn RafsInode>>;
}

/// Trait to access Rafs Inode Information.
pub trait RafsInode {
    /// Validate the object for safety.
    ///
    /// The object may be transmuted from a raw buffer read from an external file, so the caller
    /// must validate it before accessing any fields of the object.
    fn validate(&self) -> Result<()>;

    fn name(&self) -> Result<&str>;
    fn get_symlink(&self) -> Result<&str>;
    fn get_chunk_info(&self, idx: u32) -> Result<&OndiskChunkInfo>;
    fn get_child_by_name(&self, name: &str) -> Result<&dyn RafsInode>;
    fn get_child(&self, idx: u32) -> Result<&dyn RafsInode>;
    fn get_child_count(&self) -> Result<usize>;
    fn get_blob_id(&self, idx: u32) -> Result<&OndiskDigest>;
    fn get_entry(&self) -> Entry;
    fn get_attr(&self) -> Attr;
    fn get_xattrs(&self) -> Result<HashMap<String, Vec<u8>>>;
    fn alloc_bio_desc<'b>(&'b self, offset: u64, size: usize) -> Result<RafsBioDesc<'b>>;

    fn is_dir(&self) -> bool;
    fn is_symlink(&self) -> bool;
    fn is_reg(&self) -> bool;
    fn is_hardlink(&self) -> bool;
    fn has_xattr(&self) -> bool;

    fn digest(&self) -> &OndiskDigest;
    fn set_digest(&mut self, digest: OndiskDigest);

    fn ino(&self) -> u64;
    fn set_ino(&mut self, ino: u64);

    fn parent(&self) -> u64;
    fn set_parent(&mut self, ino: u64);

    fn size(&self) -> u64;
    fn set_size(&mut self, size: u64);
}

/// Trait to access Rafs Data Chunk Information.
pub trait RafsChunkInfo {
    /// Validate the object for safety.
    ///
    /// The object may be transmuted from a raw buffer read from an external file, so the caller
    /// must validate it before accessing any fields of the object.
    fn validate(&self, sb: &RafsSuperMeta) -> Result<()>;

    fn block_id(&self) -> &OndiskDigest;
    fn block_id_mut(&mut self) -> &mut OndiskDigest;
    fn set_block_id(&mut self, digest: &OndiskDigest);

    fn blob_index(&self) -> u32;
    fn set_blob_index(&mut self, blob_index: u32);

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
    fn size(&self) -> usize {
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

    fn as_str(&self) -> Result<Cow<str>> {
        let mut ret = String::new();
        for c in self.data() {
            write!(ret, "{:02x}", c).map_err(|_| einval())?;
        }
        Ok(Cow::Owned(ret))
    }
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
