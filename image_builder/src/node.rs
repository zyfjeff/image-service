// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::{c_void, CString};
use std::fmt;
use std::fs::{self, File};
use std::io::prelude::*;
use std::io::{Error, Result, SeekFrom};
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use rafs::layout::*;

use utils;

#[derive(Clone, Debug, PartialEq)]
pub enum Overlay {
    LowerAddition,
    UpperAddition,
    UpperOpaque,
    UpperRemoval,
    UpperModification,
}

impl fmt::Display for Overlay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Overlay::LowerAddition => write!(f, "lower added"),
            Overlay::UpperAddition => write!(f, "upper added"),
            Overlay::UpperOpaque => write!(f, "upper opaqued"),
            Overlay::UpperRemoval => write!(f, "upper removed"),
            Overlay::UpperModification => write!(f, "upper modified"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Node {
    /// type
    pub overlay: Overlay,
    /// offset of blob file
    pub blob_offset: u64,
    /// source path
    pub root: String,
    /// file path
    pub path: String,
    /// parent dir of file
    pub parent: Option<Box<Node>>,
    /// file inode info
    pub inode: RafsInodeInfo,
    /// chunks info of file
    pub chunks: Vec<RafsChunkInfo>,
    /// chunks info of symlink file
    pub link_chunks: Vec<RafsLinkDataInfo>,
    /// xattr info of file
    pub xattr_chunks: RafsInodeXattrInfos,
}

impl Node {
    pub fn new(
        blob_offset: u64,
        root: String,
        path: String,
        parent: Option<Box<Node>>,
        overlay: Overlay,
    ) -> Node {
        Node {
            blob_offset,
            root,
            path,
            parent,
            overlay,
            inode: RafsInodeInfo::new(),
            chunks: Vec::new(),
            link_chunks: Vec::new(),
            xattr_chunks: RafsInodeXattrInfos::new(),
        }
    }

    pub fn build(&mut self, hardlink_node: Option<Node>) -> Result<bool> {
        self.build_inode(hardlink_node)?;
        let file_type = self.get_type();
        if file_type != "" {
            info!(
                "upper building {} {}",
                file_type,
                self.rootfs_path().to_str().unwrap()
            );
            return Ok(true);
        }
        info!("skip build {}", self.rootfs_path().to_str().unwrap());
        Ok(false)
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

    pub fn rootfs_path(&self) -> PathBuf {
        Path::new("/").join(
            Path::new(self.path.as_str())
                .strip_prefix(self.root.as_str())
                .unwrap(),
        )
    }

    fn meta(&self) -> Box<dyn MetadataExt> {
        let path = Path::new(self.path.as_str());
        Box::new(path.symlink_metadata().unwrap())
    }

    fn is_dir(&self) -> bool {
        self.inode.i_mode & libc::S_IFMT == libc::S_IFDIR
    }

    fn is_symlink(&self) -> bool {
        self.inode.i_mode & libc::S_IFMT == libc::S_IFLNK
    }

    fn is_reg(&self) -> bool {
        self.inode.i_mode & libc::S_IFMT == libc::S_IFREG
    }

    fn is_hardlink(&self) -> bool {
        self.inode.i_nlink > 1
    }

    fn build_inode_xattr(&mut self) -> Result<()> {
        let filepath = CString::new(self.path.as_str())?;
        // Safe because we are calling into C functions.
        let name_size =
            unsafe { libc::llistxattr(filepath.as_ptr() as *const i8, std::ptr::null_mut(), 0) };
        if name_size <= 0 {
            return Ok(());
        }

        let mut buf: Vec<u8> = Vec::new();
        buf.resize(name_size as usize, 0);
        // Safe because we are calling into C functions.
        unsafe {
            let ret = libc::llistxattr(
                filepath.as_ptr() as *const i8,
                buf.as_mut_ptr() as *mut i8,
                name_size as usize,
            );
            if ret <= 0 {
                return Ok(());
            }
        };

        let names = match str::from_utf8(&buf) {
            Ok(s) => {
                let s: Vec<&str> = s.split_terminator('\0').collect();
                Ok(s)
            }
            Err(_) => Err(Error::from_raw_os_error(libc::EINVAL)),
        }?;

        let mut count = 0;
        for n in names.iter() {
            // make sure name is nul terminated
            let mut name = (*n).to_string();
            name.push('\0');
            let value_size = unsafe {
                libc::lgetxattr(
                    filepath.as_ptr() as *const i8,
                    name.as_ptr() as *const i8,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if value_size < 0 {
                continue;
            }
            if value_size == 0 {
                count += 1;
                self.xattr_chunks.data.insert(name, vec![]);
                continue;
            }
            // Need to read xattr value
            let mut value_buf: Vec<u8> = Vec::new();
            value_buf.resize(value_size as usize, 0);
            // Safe because we are calling into C functions.
            unsafe {
                let ret = libc::lgetxattr(
                    filepath.as_ptr() as *const i8,
                    name.as_ptr() as *const i8,
                    value_buf.as_mut_ptr() as *mut c_void,
                    value_size as usize,
                );
                if ret < 0 {
                    continue;
                }
                if ret == 0 {
                    count += 1;
                    self.xattr_chunks.data.insert(name, vec![]);
                    continue;
                }
            };
            count += 1;
            self.xattr_chunks.data.insert(name, value_buf);
        }

        if count > 0 {
            self.inode.i_flags |= INO_FLAG_XATTR;
            self.xattr_chunks.count = count;
            trace!(
                "inode {} has xattr {:?}",
                self.inode.name,
                self.xattr_chunks
            );
        }
        Ok(())
    }

    fn build_inode(&mut self, hardlink_node: Option<Node>) -> Result<()> {
        if self.parent.is_none() {
            self.inode.name = String::from("/");
            self.inode.i_parent = 0;
            self.inode.i_ino = 1;
            self.inode.i_mode = libc::S_IFDIR;
            return Ok(());
        }

        let file_name = Path::new(self.path.as_str())
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        let parent = self.parent.as_ref().unwrap();
        let meta = self.meta();

        self.inode.name = String::from(file_name);
        self.inode.i_parent = parent.inode.i_ino;
        self.inode.i_ino = meta.st_ino();
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

        self.build_inode_xattr()?;

        if self.is_reg() {
            if self.is_hardlink() {
                if let Some(hardlink_node) = hardlink_node {
                    self.inode.i_flags |= INO_FLAG_HARDLINK;
                    self.inode.digest = hardlink_node.inode.digest;
                    self.inode.i_chunk_cnt = 0;
                    return Ok(());
                }
            }
            let file_size = self.inode.i_size;
            let chunk_count = (file_size as f64 / DEFAULT_RAFS_BLOCK_SIZE as f64).ceil() as u64;
            self.inode.i_chunk_cnt = chunk_count;
        } else if self.is_symlink() {
            self.inode.i_flags |= INO_FLAG_SYMLINK;
            let target_path = fs::read_link(self.path.as_str())?;
            let target_path_str = target_path.to_str().unwrap();
            let chunk_info_count = (target_path_str.as_bytes().len() as f64
                / RAFS_CHUNK_INFO_SIZE as f64)
                .ceil() as usize;
            self.inode.i_chunk_cnt = chunk_info_count as u64;
        }

        Ok(())
    }

    pub fn dump_blob(&mut self, mut f_blob: &File, blob_hash: &mut Sha256) -> Result<RafsDigest> {
        let mut inode_digest = RafsDigest::new();

        if self.is_symlink() {
            let target_path = fs::read_link(self.path.as_str())?;
            let target_path_str = target_path.to_str().unwrap();
            let mut chunk = RafsLinkDataInfo::new(self.inode.i_chunk_cnt as usize);
            chunk.target = String::from(target_path_str);
            // stash symlink chunk
            self.link_chunks.push(chunk);
            return Ok(inode_digest);
        }

        if self.is_dir() {
            return Ok(inode_digest);
        }

        let file_size = self.inode.i_size;
        let mut inode_hash = Sha256::new();
        let mut file = File::open(self.path.as_str())?;

        for i in 0..self.inode.i_chunk_cnt {
            let mut chunk = RafsChunkInfo::new();

            // get chunk info
            chunk.file_offset = (i * DEFAULT_RAFS_BLOCK_SIZE as u64) as u64;
            let len = if i == self.inode.i_chunk_cnt - 1 {
                (file_size % DEFAULT_RAFS_BLOCK_SIZE as u64) as usize
            } else {
                DEFAULT_RAFS_BLOCK_SIZE
            };

            // get chunk data
            file.seek(SeekFrom::Start(chunk.file_offset))?;
            let mut chunk_data = vec![0; len];
            file.read_exact(&mut chunk_data)?;

            // calc chunk digest
            chunk.blockid = RafsDigest::from_buf(chunk_data.as_slice());

            // compress chunk data
            let compressed = utils::compress(&chunk_data)?;
            let compressed_size = compressed.len();
            chunk.blob_offset = self.blob_offset;
            chunk.compress_size = compressed_size as u32;

            // move cursor to offset of next chunk
            self.blob_offset += compressed_size as u64;

            trace!(
                "\tbuilding chunk: file offset {}, blob offset {}, size {}",
                chunk.file_offset,
                chunk.blob_offset,
                chunk.compress_size,
            );

            // calc blob hash
            blob_hash.input(&compressed);

            // dump compressed chunk data to blob
            f_blob.write_all(&compressed)?;

            // calc inode digest
            inode_hash.input(&chunk.blockid.data);

            // stash chunk
            self.chunks.push(chunk);
        }

        // finish calc inode digest
        let mut inode_hash_buf = [0; RAFS_SHA256_LENGTH];
        inode_hash.result(&mut inode_hash_buf);
        inode_digest.data.clone_from_slice(&inode_hash_buf);

        trace!(
            "\tbuilding inode: name {}, ino {}, digest {}, parent {}, chunk_cnt {}",
            self.inode.name,
            self.inode.i_ino,
            self.inode.digest,
            self.inode.i_parent,
            self.inode.i_chunk_cnt,
        );

        self.inode.digest = inode_digest.clone();

        Ok(inode_digest)
    }

    pub fn dump_bootstrap(&mut self, f_bootstrap: &File, blob_id: Option<String>) -> Result<()> {
        // dump inode info to bootstrap
        self.inode.store(f_bootstrap)?;

        // dump inode xattr to bootstrap
        self.xattr_chunks.store(f_bootstrap)?;

        // dump chunk info to bootstrap
        for chunk in &mut self.chunks {
            if let Some(blob_id) = &blob_id {
                chunk.blobid = blob_id.to_owned();
            }
            chunk.store(f_bootstrap)?;
        }

        // or dump symlink chunk info to bootstrap
        for chunk in &self.link_chunks {
            chunk.store(f_bootstrap)?;
        }

        Ok(())
    }
}
