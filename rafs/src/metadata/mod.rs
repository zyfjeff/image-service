// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Structs and Traits for RAFS file system meta data management.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write;
use std::io::{Error, Result, Seek, SeekFrom};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use fuse_rs::abi::linux_abi::Attr;
use fuse_rs::api::filesystem::Entry;

use self::direct::DirectMapping;
use self::layout::*;
use self::noop::NoopInodes;
use crate::fs::{Inode, RAFS_DEFAULT_ATTR_TIMEOUT, RAFS_DEFAULT_ENTRY_TIMEOUT};
use crate::metadata::cached::CachedInodes;
use crate::storage::compress;
use crate::storage::device::{RafsBio, RafsBioDesc};
use crate::*;

use nydus_utils::{ebadf, einval};

pub mod cached;
pub mod direct;
pub mod layout;
pub mod noop;

pub const RAFS_SHA256_LENGTH: usize = 32;
pub const RAFS_BLOB_ID_MAX_LENGTH: usize = 72;
pub const RAFS_INODE_BLOCKSIZE: u32 = 4096;
pub const RAFS_MAX_NAME: usize = 255;
pub const RAFS_DEFAULT_BLOCK_SIZE: u64 = 1024 * 1024;
pub const RAFS_MAX_METADATA_SIZE: usize = 0x8000_0000;

#[macro_export]
macro_rules! impl_getter_setter {
    ($G: ident, $S: ident, $F: ident, $U: ty) => {
        fn $G(&self) -> $U {
            self.$F
        }

        fn $S(&mut self, $F: $U) {
            self.$F = $F;
        }
    };
}

#[macro_export]
macro_rules! impl_getter {
    ($G: ident, $F: ident, $U: ty) => {
        fn $G(&self) -> $U {
            self.$F
        }
    };
}

/// Cached Rafs super block metadata.
#[derive(Clone, Copy, Default, Debug)]
pub struct RafsSuperMeta {
    pub magic: u32,
    pub version: u32,
    pub sb_size: u32,
    pub root_inode: Inode,
    pub block_size: u32,
    pub inodes_count: u64,
    pub flags: u64,
    pub inode_table_entries: u32,
    pub inode_table_offset: u64,
    pub blob_table_size: u32,
    pub blob_table_offset: u64,
    pub blob_readahead_offset: u32,
    pub blob_readahead_size: u32,
    pub attr_timeout: Duration,
    pub entry_timeout: Duration,
}

impl RafsSuperMeta {
    pub fn get_compressor(&self) -> compress::Algorithm {
        self.flags.to_be_bytes().last().unwrap().into()
    }
}

pub enum RafsMode {
    Direct,
    Cached,
}

impl FromStr for RafsMode {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "direct" => Ok(Self::Direct),
            "cached" => Ok(Self::Cached),
            _ => Err(einval!("rafs mode should be direct or cached")),
        }
    }
}

impl fmt::Display for RafsMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Cached => write!(f, "cached"),
        }
    }
}

/// Cached Rafs super block and inode information.
pub struct RafsSuper {
    pub mode: RafsMode,
    pub meta: RafsSuperMeta,
    pub inodes: Box<dyn RafsSuperInodes + Sync + Send>,
}

impl Default for RafsSuper {
    fn default() -> Self {
        Self {
            mode: RafsMode::Direct,
            meta: RafsSuperMeta {
                magic: 0,
                version: 0,
                sb_size: 0,
                inodes_count: 0,
                root_inode: 0,
                block_size: 0,
                flags: 0,
                inode_table_entries: 0,
                inode_table_offset: 0,
                blob_table_size: 0,
                blob_table_offset: 0,
                blob_readahead_offset: 0,
                blob_readahead_size: 0,
                attr_timeout: Duration::from_secs(RAFS_DEFAULT_ATTR_TIMEOUT),
                entry_timeout: Duration::from_secs(RAFS_DEFAULT_ENTRY_TIMEOUT),
            },
            inodes: Box::new(NoopInodes::new()),
        }
    }
}

impl RafsSuper {
    pub fn new(mode: &str) -> Result<Self> {
        let mut rs = Self::default();

        match mode {
            "direct" => {
                rs.mode = RafsMode::Direct;
            }
            "cached" => {
                rs.mode = RafsMode::Cached;
            }
            _ => {
                return Err(einval!("Rafs mode should be 'direct' or 'cached'"));
            }
        }

        Ok(rs)
    }

    pub fn destroy(&mut self) {
        self.inodes.destroy();
    }

    /// Load RAFS super block and optionally cache inodes.
    pub fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let mut sb = OndiskSuperBlock::new();

        r.read_exact(sb.as_mut())?;
        sb.validate()?;

        self.meta.magic = sb.magic();
        self.meta.version = sb.version();
        self.meta.sb_size = sb.sb_size();
        self.meta.block_size = sb.block_size();
        self.meta.flags = sb.flags();

        match self.meta.version {
            RAFS_SUPER_VERSION_V4 => {
                self.meta.inodes_count = std::u64::MAX;
            }
            RAFS_SUPER_VERSION_V5 => {
                self.meta.inodes_count = sb.inodes_count();
                self.meta.inode_table_entries = sb.inode_table_entries();
                self.meta.inode_table_offset = sb.inode_table_offset();
                self.meta.blob_table_offset = sb.blob_table_offset();
                self.meta.blob_table_size = sb.blob_table_size();
            }
            _ => return Err(ebadf!("invalid superblock version number")),
        }

        match sb.version() {
            RAFS_SUPER_VERSION_V4 => {
                // TODO: Support Rafs v4
                unimplemented!();
            }
            RAFS_SUPER_VERSION_V5 => match self.mode {
                RafsMode::Direct => {
                    let mut inodes = Box::new(DirectMapping::new(&self.meta));
                    inodes.load(r)?;
                    self.inodes = inodes;
                }
                RafsMode::Cached => {
                    r.seek(SeekFrom::Start(sb.blob_table_offset()))?;
                    let mut blob_table = OndiskBlobTable::new();
                    blob_table.load(r, sb.blob_table_size() as usize)?;

                    let mut inodes = Box::new(CachedInodes::new(self.meta, blob_table));
                    inodes.load(r)?;
                    self.inodes = inodes;
                }
            },
            _ => return Err(einval!("invalid superblock version number")),
        }

        Ok(())
    }

    /// Store RAFS metadata to backend storage.
    pub fn store(&self, w: &mut RafsIoWriter) -> Result<usize> {
        let mut sb = OndiskSuperBlock::new();

        sb.set_magic(self.meta.magic);
        sb.set_version(self.meta.version);
        sb.set_sb_size(self.meta.sb_size);
        sb.set_block_size(self.meta.block_size);
        sb.set_flags(self.meta.flags);

        match self.meta.version {
            RAFS_SUPER_VERSION_V4 => {}
            RAFS_SUPER_VERSION_V5 => {
                sb.set_inodes_count(self.meta.inodes_count);
                sb.set_inode_table_entries(self.meta.inode_table_entries);
                sb.set_inode_table_offset(self.meta.inode_table_offset);
            }
            _ => return Err(einval!("invalid superblock version number")),
        }

        sb.validate()?;
        w.write_all(sb.as_ref())?;

        trace!("written superblock: {}", &sb);

        Ok(std::mem::size_of::<OndiskSuperBlock>())
    }

    pub fn get_inode(&self, ino: Inode) -> Result<Arc<dyn RafsInode>> {
        self.inodes.get_inode(ino)
    }

    pub fn get_max_ino(&self) -> Inode {
        self.inodes.get_max_ino()
    }
}

/// Trait to manage all inodes of a file system.
pub trait RafsSuperInodes {
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()>;

    fn destroy(&mut self);

    fn get_inode(&self, ino: Inode) -> Result<Arc<dyn RafsInode>>;

    fn get_max_ino(&self) -> Inode;

    fn get_blobs(&self) -> Vec<OndiskBlobTableEntry> {
        Vec::new()
    }
}

/// Trait to access Rafs Inode Information.
pub trait RafsInode {
    /// Validate the object for safety.
    /// The object may be transmuted from a raw buffer read from an external file, so the caller
    /// must validate it before accessing any fields of the object.
    fn validate(&self) -> Result<()>;

    fn name(&self) -> Result<String>;
    fn get_symlink(&self) -> Result<String>;
    fn get_child_by_name(&self, name: &str) -> Result<Arc<dyn RafsInode>>;
    fn get_child_by_index(&self, idx: Inode) -> Result<Arc<dyn RafsInode>>;
    fn get_child_count(&self) -> Result<usize>;
    fn get_chunk_info(&self, idx: u32) -> Result<Arc<dyn RafsChunkInfo>>;
    fn get_chunk_blob_id(&self, idx: u32) -> Result<String>;
    fn get_entry(&self) -> Entry;
    fn get_attr(&self) -> Attr;
    fn get_xattr(&self, name: &str) -> Result<Option<XattrValue>>;
    fn get_xattrs(&self) -> Result<Vec<XattrName>>;
    fn alloc_bio_desc(&self, offset: u64, size: usize) -> Result<RafsBioDesc>;

    fn is_dir(&self) -> bool;
    fn is_symlink(&self) -> bool;
    fn is_reg(&self) -> bool;
    fn is_hardlink(&self) -> bool;
    fn has_xattr(&self) -> bool;

    fn ino(&self) -> u64;
    fn parent(&self) -> u64;
    fn size(&self) -> u64;
}

/// Trait to access Rafs Data Chunk Information.
pub trait RafsChunkInfo: Sync + Send {
    fn validate(&self, sb: &RafsSuperMeta) -> Result<()>;

    fn block_id(&self) -> Arc<dyn RafsDigest>;
    fn blob_index(&self) -> u32;

    fn blob_compress_offset(&self) -> u64;
    fn compress_size(&self) -> u32;
    fn blob_decompress_offset(&self) -> u64;
    fn decompress_size(&self) -> u32;

    fn file_offset(&self) -> u64;
    fn is_compressed(&self) -> bool;
}

/// Trait to access Rafs SHA256 message digest data.
pub trait RafsDigest {
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

    fn to_string(&self) -> String;
}
