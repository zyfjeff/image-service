// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use rafs::RafsIoWrite;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::prelude::*;
use std::io::{Result, SeekFrom};
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str;

use sha2::digest::Digest;
use sha2::Sha256;

use nydus_utils::div_round_up;
use nydus_utils::einval;

use rafs::metadata::layout::*;
use rafs::metadata::RafsDigest;
use rafs::metadata::*;
use rafs::storage::compress;
use rafs::storage::utils::digest;

pub type ChunkCache = HashMap<OndiskDigest, OndiskChunkInfo>;

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
            "{} {:?}: index {} ino {} child_count {} child_index {} i_name_size {} i_symlink_size {} i_nlink {} has_xattr {}",
            self.get_type().unwrap(),
            self.rootfs(),
            self.index,
            self.inode.i_ino,
            self.inode.i_child_count,
            self.inode.i_child_index,
            self.inode.i_name_size,
            self.inode.i_symlink_size,
            self.inode.i_nlink,
            self.inode.has_xattr(),
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
            let key = key.to_str().ok_or_else(|| einval!())?.to_string();
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
        compress_offset: &mut u64,
        decompress_offset: &mut u64,
        chunk_cache: &mut ChunkCache,
        compressor: compress::Algorithm,
    ) -> Result<usize> {
        if self.is_symlink()? {
            self.inode.i_digest = OndiskDigest::from_buf(self.symlink.as_ref().unwrap().as_bytes());
            return Ok(0);
        }

        if self.is_dir()? {
            return Ok(0);
        }

        let file_size = self.inode.i_size;
        let mut blob_size = 0usize;
        let mut inode_hash = Sha256::new();
        let mut file = File::open(&self.path)?;

        for i in 0..self.inode.i_child_count {
            // get chunk info
            let mut chunk = OndiskChunkInfo::new();
            let file_offset = i as u64 * RAFS_DEFAULT_BLOCK_SIZE;
            let chunk_size = if i == self.inode.i_child_count - 1 {
                file_size as usize - (RAFS_DEFAULT_BLOCK_SIZE as usize * i as usize)
            } else {
                RAFS_DEFAULT_BLOCK_SIZE as usize
            };

            // get chunk data
            file.seek(SeekFrom::Start(file_offset))?;
            let mut chunk_data = vec![0; chunk_size];
            file.read_exact(&mut chunk_data)?;

            // calc chunk digest
            chunk.block_id = digest(chunk_data.as_slice());
            // calc inode digest
            inode_hash.update(&chunk.block_id.data());

            if let Some(cached_chunk) = chunk_cache.get(&chunk.block_id) {
                chunk.clone_from(&cached_chunk);
                chunk.file_offset = file_offset;
                self.chunks.push(chunk);
                trace!(
                    "\tbuilding duplicated chunk: {} compressor {}",
                    chunk,
                    compressor,
                );
                continue;
            }

            // compress chunk data
            let (compressed, is_compressed) = compress::compress(&chunk_data, compressor)?;
            let compressed_size = compressed.len();
            if is_compressed {
                chunk.flags |= CHUNK_FLAG_COMPRESSED;
            }

            chunk.file_offset = file_offset;
            chunk.compress_offset = *compress_offset;
            chunk.decompress_offset = *decompress_offset;
            chunk.compress_size = compressed_size as u32;
            chunk.decompress_size = chunk_size as u32;
            blob_size += compressed_size;

            // move cursor to offset of next chunk
            *compress_offset += compressed_size as u64;
            *decompress_offset += chunk_size as u64;

            // calc blob hash
            blob_hash.update(&compressed);

            // dump compressed chunk data to blob
            f_blob.write_all(&compressed)?;

            // stash chunk
            chunk_cache.insert(chunk.block_id, chunk);
            self.chunks.push(chunk);

            trace!("\tbuilding chunk: {} compressor {}", chunk, compressor,);
        }

        // finish calc inode digest
        self.inode.i_digest = OndiskDigest::from_digest(inode_hash);

        Ok(blob_size)
    }

    #[allow(clippy::borrowed_box)]
    pub fn dump_bootstrap(
        &mut self,
        f_bootstrap: &mut Box<dyn RafsIoWrite>,
        blob_index: u32,
    ) -> Result<usize> {
        let mut node_size = 0;

        // dump inode info
        let inode = OndiskInodeWrapper {
            name: self.name.as_str(),
            symlink: self.symlink.as_deref(),
            inode: &self.inode,
        };
        let inode_size = inode.store(f_bootstrap)?;
        node_size += inode_size;

        // dump inode xattr
        if !self.xattrs.pairs.is_empty() {
            let xattr_size = self.xattrs.store(f_bootstrap)?;
            node_size += xattr_size;
        }

        // dump chunk info
        for chunk in &mut self.chunks {
            chunk.blob_index = blob_index;
            let chunk_size = chunk.store(f_bootstrap)?;
            node_size += chunk_size;
        }

        Ok(node_size)
    }

    fn build_inode_stat(&mut self) -> Result<()> {
        let meta = self.meta()?;

        self.inode.i_mode = meta.st_mode();
        self.inode.i_projid = 0;
        self.inode.i_size = meta.st_size();
        self.inode.i_nlink = meta.st_nlink();
        // block count in 512B units per stat(2)
        self.inode.i_blocks = div_round_up(self.inode.i_size, 512);

        Ok(())
    }

    pub fn build_inode(&mut self) -> Result<()> {
        if self.rootfs() == PathBuf::from("/") {
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

        if self.is_reg()? {
            self.inode.i_child_count = self.chunk_count() as u32;
        } else if self.is_symlink()? {
            self.inode.i_flags |= INO_FLAG_SYMLINK as u64;
            let target_path = fs::read_link(&self.path)?;
            self.symlink = Some(target_path.to_str().unwrap().to_owned());
            self.inode
                .set_symlink_size(self.symlink.as_ref().unwrap().len());
        }

        self.build_inode_xattr()?;

        Ok(())
    }

    pub fn meta(&self) -> Result<impl MetadataExt> {
        self.path.symlink_metadata().map_err(|e| einval!(e))
    }

    /// Generate the path relative to original rootfs.
    /// For example:
    /// `/absolute/path/to/rootfs/file` after converting `/file`
    pub fn rootfs(&self) -> PathBuf {
        Path::new("/").join(self.path.strip_prefix(&self.root).unwrap())
    }

    pub fn is_dir(&self) -> Result<bool> {
        Ok(self.meta()?.st_mode() & libc::S_IFMT == libc::S_IFDIR)
    }

    pub fn is_symlink(&self) -> Result<bool> {
        Ok(self.meta()?.st_mode() & libc::S_IFMT == libc::S_IFLNK)
    }

    pub fn is_reg(&self) -> Result<bool> {
        Ok(self.meta()?.st_mode() & libc::S_IFMT == libc::S_IFREG)
    }

    pub fn is_hardlink(&self) -> Result<bool> {
        Ok(self.meta()?.st_nlink() > 1)
    }

    pub fn get_real_ino(&self) -> Result<u64> {
        Ok(self.meta()?.st_ino())
    }

    pub fn chunk_count(&self) -> usize {
        if !self.is_reg().unwrap() {
            return 0;
        }
        div_round_up(self.inode.i_size, RAFS_DEFAULT_BLOCK_SIZE) as usize
    }

    pub fn get_type(&self) -> Result<&str> {
        let mut file_type = "";

        if self.is_symlink()? {
            file_type = "symlink";
        } else if self.is_dir()? {
            file_type = "dir"
        } else if self.is_reg()? {
            if self.is_hardlink()? {
                file_type = "hardlink";
            } else {
                file_type = "file";
            }
        }

        Ok(file_type)
    }
}
