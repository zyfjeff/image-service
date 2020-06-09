// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use rafs::RafsIoWrite;
use std::fmt;
use std::fs::{self, File};
use std::io::prelude::*;
use std::io::{Error, ErrorKind, Result, SeekFrom};
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use rafs::metadata::layout::*;
use rafs::metadata::*;
use utils::compress;

#[derive(Clone, Debug, PartialEq)]
pub enum Overlay {
    LowerAddition,
    UpperAddition,
    UpperOpaque,
    UpperRemoval,
    UpperModification,
}

impl fmt::Display for Overlay {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Overlay::LowerAddition => write!(f, "lower added"),
            Overlay::UpperAddition => write!(f, "upper added"),
            Overlay::UpperOpaque => write!(f, "upper opaqued"),
            Overlay::UpperRemoval => write!(f, "upper removed"),
            Overlay::UpperModification => write!(f, "upper modified"),
        }
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} ino {}, parent {}, childs {}, child index {}",
            // self.get_type(),
            self.get_rootfs(),
            self.inode.i_ino,
            self.inode.i_parent,
            self.inode.i_child_count,
            self.inode.i_child_index,
        )
    }
}

#[derive(Clone)]
pub struct Node {
    pub index: u64,
    /// inode name
    pub name: String,
    /// type
    pub overlay: Overlay,
    /// source path
    pub root: PathBuf,
    /// file path
    pub path: PathBuf,
    /// file inode info
    pub inode: OndiskInode,
    /// chunks info of file
    pub chunks: Vec<OndiskChunkInfo>,
    // chunks info of symlink file
    pub symlink: Option<String>,
    // xattr list of file
    pub xattrs: XAttrs,
}

impl Node {
    pub fn new(root: PathBuf, path: PathBuf, overlay: Overlay) -> Node {
        Node {
            index: 0,
            name: String::new(),
            root,
            path,
            overlay,
            inode: OndiskInode::new(),
            chunks: Vec::new(),
            symlink: None,
            xattrs: XAttrs::default(),
        }
    }

    fn build_inode_xattr(&mut self) -> Result<()> {
        let mut file_xattrs = xattr::list(&self.path)?.peekable();

        if file_xattrs.peek().is_none() {
            return Ok(());
        }

        let mut xattrs = XAttrs::default();
        for (count, key) in file_xattrs.enumerate() {
            let key = key
                .to_str()
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?
                .to_string();
            let value = xattr::get(&self.path, &key)?;
            xattrs.pairs.insert(key, value.unwrap_or_default());
        }

        self.xattrs = xattrs;
        self.inode.i_flags |= INO_FLAG_XATTR as u64;

        Ok(())
    }

    #[allow(clippy::borrowed_box)]
    pub fn dump_blob(
        &mut self,
        f_blob: &mut Box<dyn RafsIoWrite>,
        blob_hash: &mut Sha256,
        blob_offset: &mut u64,
        blob_compression_algorithm: compress::Algorithm,
    ) -> Result<OndiskDigest> {
        let mut inode_digest = OndiskDigest::new();

        if self.is_symlink() {
            return Ok(inode_digest);
        }

        if self.is_dir() {
            return Ok(inode_digest);
        }

        let file_size = self.inode.i_size;
        let mut inode_hash = Sha256::new();
        let mut file = File::open(&self.path)?;

        for i in 0..self.inode.i_child_count {
            let mut chunk = OndiskChunkInfo::new();

            // get chunk info
            chunk.file_offset = i as u64 * RAFS_DEFAULT_BLOCK_SIZE;
            let chunk_size = if i == self.inode.i_child_count - 1 {
                file_size as usize - (RAFS_DEFAULT_BLOCK_SIZE as usize * i as usize)
            } else {
                RAFS_DEFAULT_BLOCK_SIZE as usize
            };

            // get chunk data
            file.seek(SeekFrom::Start(chunk.file_offset))?;
            let mut chunk_data = vec![0; chunk_size];
            file.read_exact(&mut chunk_data)?;

            // calc chunk digest
            let digest = OndiskDigest::from_buf(chunk_data.as_slice());
            chunk.block_id = digest;

            // compress chunk data
            let compressed = utils::compress::compress(&chunk_data, blob_compression_algorithm)?;
            let compressed_size = compressed.len();
            chunk.blob_offset = *blob_offset;
            chunk.compress_size = compressed_size as u32;
            if !blob_compression_algorithm.is_none() {
                chunk.flags |= CHUNK_FLAG_COMPRESSED;
            }

            // move cursor to offset of next chunk
            *blob_offset += compressed_size as u64;

            trace!(
                "\tbuilding chunk: file_offset {}, blob_offset {}, compress_size {}, chunk_size {}, compression_algorithm {}, block_id {}",
                chunk.file_offset,
                chunk.blob_offset,
                chunk.compress_size,
                chunk_size,
                blob_compression_algorithm,
                chunk.block_id.to_string(),
            );

            // calc blob hash
            blob_hash.input(&compressed);

            // dump compressed chunk data to blob
            f_blob.write_all(&compressed)?;

            // calc inode digest
            inode_hash.input(&chunk.block_id.data());

            // stash chunk
            self.chunks.push(chunk);
        }

        // finish calc inode digest
        let mut inode_hash_buf = [0; RAFS_SHA256_LENGTH];
        inode_hash.result(&mut inode_hash_buf);
        inode_digest.data_mut().clone_from_slice(&inode_hash_buf);

        self.inode.i_digest = inode_digest;

        Ok(inode_digest)
    }

    #[allow(clippy::borrowed_box)]
    pub fn dump_bootstrap(
        &mut self,
        f_bootstrap: &mut Box<dyn RafsIoWrite>,
        blob_index: u32,
    ) -> Result<()> {
        // dump inode info
        let mut symlink_path: &[u8] = &[];
        if let Some(symlink) = &self.symlink {
            symlink_path = symlink.as_bytes();
        }
        let inode_size = self
            .inode
            .store(f_bootstrap, self.name.as_bytes(), symlink_path)?;

        // dump inode xattr
        if !self.xattrs.pairs.is_empty() {
            self.xattrs.store(f_bootstrap)?;
        }

        // dump chunk info
        for chunk in &mut self.chunks {
            chunk.blob_index = blob_index;
            chunk.store(f_bootstrap)?;
        }

        Ok(())
    }

    fn build_inode_stat(&mut self) -> Result<()> {
        let meta = self.meta();

        self.inode.i_mode = meta.st_mode();
        self.inode.i_uid = meta.st_uid();
        self.inode.i_gid = meta.st_gid();
        self.inode.i_projid = 0;
        self.inode.i_rdev = meta.st_rdev();
        self.inode.i_size = meta.st_size();
        self.inode.i_nlink = meta.st_nlink();
        self.inode.i_blocks = meta.st_blocks();
        self.inode.i_atime = meta.st_atime() as u64;
        self.inode.i_mtime = meta.st_mtime() as u64;
        self.inode.i_ctime = meta.st_ctime() as u64;

        Ok(())
    }

    pub fn build_inode(&mut self, hardlink_node: Option<Node>) -> Result<()> {
        if self.get_rootfs() == PathBuf::from("/") {
            self.name = String::from("/");
            self.inode.set_name_size(self.name.as_bytes().len());
            self.build_inode_stat()?;
            return Ok(());
        }

        let file_name = self
            .path
            .file_name()
            .unwrap()
            .to_owned()
            .into_string()
            .unwrap();

        self.name = file_name;
        self.inode.set_name_size(self.name.as_bytes().len());
        self.build_inode_stat()?;
        self.build_inode_xattr()?;

        if self.is_reg() {
            if self.is_hardlink() {
                if let Some(hardlink_node) = hardlink_node {
                    self.inode.i_flags |= INO_FLAG_HARDLINK as u64;
                    self.inode.i_digest = hardlink_node.inode.i_digest;
                    self.inode.i_child_count = 0;
                    return Ok(());
                }
            }
            self.inode.i_child_count =
                utils::div_round_up(self.inode.i_size, RAFS_DEFAULT_BLOCK_SIZE) as u32;
        } else if self.is_symlink() {
            self.inode.i_flags |= INO_FLAG_SYMLINK as u64;
            let target_path = fs::read_link(&self.path)?;
            self.symlink = Some(target_path.to_str().unwrap().to_owned());
            self.inode
                .set_symlink_size(self.symlink.as_ref().unwrap().len());
        }

        Ok(())
    }

    pub fn meta(&self) -> impl MetadataExt {
        self.path.symlink_metadata().unwrap()
    }

    pub fn is_dir(&self) -> bool {
        self.meta().st_mode() & libc::S_IFMT == libc::S_IFDIR
    }

    pub fn is_symlink(&self) -> bool {
        self.meta().st_mode() & libc::S_IFMT == libc::S_IFLNK
    }

    pub fn is_reg(&self) -> bool {
        self.meta().st_mode() & libc::S_IFMT == libc::S_IFREG
    }

    pub fn is_hardlink(&self) -> bool {
        self.meta().st_nlink() > 1
    }

    pub fn get_real_ino(&self) -> u64 {
        self.meta().st_ino()
    }

    pub fn get_type(&self) -> &str {
        let mut file_type = "";

        if self.is_symlink() {
            file_type = "symlink";
        } else if self.is_dir() {
            file_type = "dir"
        } else if self.is_reg() {
            if self.is_hardlink() {
                file_type = "hardlink";
            } else {
                file_type = "file";
            }
        }

        file_type
    }

    pub fn get_rootfs(&self) -> PathBuf {
        Path::new("/").join(self.path.strip_prefix(&self.root).unwrap())
    }
}
