// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::{c_void, CString};
use std::fs::{self, File};
use std::io::prelude::*;
use std::io::{Error, Result, SeekFrom};
use std::os::linux::fs::MetadataExt;
use std::path::Path;
use std::str;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use rafs::layout::*;

use utils;

#[derive(Default, Clone, Debug)]
pub struct Node {
    /// image blob id
    blob_id: String,
    /// offset of blob file
    pub blob_offset: u64,
    /// file path
    path: String,
    /// parent dir of file
    parent: Option<Box<Node>>,
    /// file inode info
    inode: RafsInodeInfo,
    /// chunks info of file
    chunks: Vec<RafsChunkInfo>,
    /// chunks info of symlink file
    link_chunks: Vec<RafsLinkDataInfo>,
    /// xattr info of file
    xattr_chunks: RafsInodeXattrInfos,
}

impl Node {
    pub fn new(
        blob_id: String,
        blob_offset: u64,
        path: String,
        parent: Option<Box<Node>>,
    ) -> Node {
        Node {
            blob_id,
            blob_offset,
            path,
            parent,
            inode: RafsInodeInfo::new(),
            chunks: Vec::new(),
            link_chunks: Vec::new(),
            xattr_chunks: RafsInodeXattrInfos::new(),
        }
    }

    pub fn dump(&mut self, f_blob: &File, f_bootstrap: &File, hardlink_node: Option<Box<Node>>) -> Result<u64> {
        let mut file_type = "";
        if self.is_dir() {
            file_type = "dir";
        } else if self.is_symlink() {
            file_type = "symlink"
        } else if self.is_reg() {
            if self.is_hardlink() {
                file_type = "hardlink";
            } else {
                file_type = "file";
            }
        }

        if file_type != "" {
            info!("building {} {}", file_type, self.path);
            self.build_inode()?;
            self.dump_blob(f_blob, hardlink_node)?;
            self.dump_bootstrap(f_bootstrap)?;
        } else {
            info!("skip build {}", self.path);
        }

        Ok(self.inode.i_ino)
    }

    fn meta(&self) -> Box<dyn MetadataExt> {
        let path = Path::new(self.path.as_str());
        Box::new(path.metadata().unwrap())
    }

    fn is_dir(&mut self) -> bool {
        return self.meta().st_mode() & libc::S_IFMT == libc::S_IFDIR;
    }

    fn is_symlink(&mut self) -> bool {
        return self.meta().st_mode() & libc::S_IFMT == libc::S_IFLNK;
    }

    fn is_reg(&mut self) -> bool {
        return self.meta().st_mode() & libc::S_IFMT == libc::S_IFREG;
    }

    fn is_hardlink(&self) -> bool {
        return self.meta().st_nlink() > 1;
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
                let s: Vec<&str> = s.split_terminator("\0").collect();
                Ok(s)
            }
            Err(_) => Err(Error::from_raw_os_error(libc::EINVAL)),
        }?;

        let mut count = 0;
        for n in names.iter() {
            // make sure name is nul terminated
            let mut name = n.to_string();
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

    fn build_inode(&mut self) -> Result<()> {
        if self.parent.is_none() {
            self.inode.name = String::from("/");
            self.inode.i_parent = 0;
            self.inode.i_ino = 1;
            self.inode.i_mode = libc::S_IFDIR;
            return Ok(());
        }

        let file_name = Path::new(self.path.as_str()).file_name().unwrap().to_str().unwrap();
        let parent = self.parent.as_ref().unwrap();
        let meta = self.meta();

        self.inode.name = String::from(file_name);
        self.inode.i_parent = parent.inode.i_ino;
        self.inode.i_ino = meta.st_ino();
        self.inode.i_mode = meta.st_mode();
        self.inode.i_uid = meta.st_uid();
        self.inode.i_gid = meta.st_gid();
        self.inode.i_padding = 0;
        self.inode.i_rdev = meta.st_rdev();
        self.inode.i_size = meta.st_size();
        self.inode.i_nlink = meta.st_nlink();
        self.inode.i_blocks = meta.st_blocks();
        self.inode.i_atime = meta.st_atime() as u64;
        self.inode.i_mtime = meta.st_mtime() as u64;
        self.inode.i_ctime = meta.st_ctime() as u64;

        self.build_inode_xattr()?;

        if self.is_reg() {
            self.inode.i_flags |= INO_FLAG_HARDLINK;
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

    fn dump_blob(&mut self, mut f_blob: &File, hardlink_node: Option<Box<Node>>) -> Result<()> {
        if self.is_dir() {
            return Ok(());
        }

        if self.is_hardlink() && hardlink_node.is_some() {
            let hardlink_node = hardlink_node.unwrap();
            self.inode.digest = hardlink_node.inode.digest;
            return Ok(());
        }

        if self.is_symlink() {
            let target_path = fs::read_link(self.path.as_str())?;
            let target_path_str = target_path.to_str().unwrap();
            let mut chunk = RafsLinkDataInfo::new(self.inode.i_chunk_cnt as usize);
            chunk.target = String::from(target_path_str);
            // stash symlink chunk
            self.link_chunks.push(chunk);
            return Ok(());
        }

        let file_size = self.inode.i_size;
        let mut inode_hash = Sha256::new();
        let mut file = File::open(self.path.as_str())?;

        for i in 0..self.inode.i_chunk_cnt {
            let mut chunk = RafsChunkInfo::new();

            // get chunk info
            chunk.blobid = String::from(self.blob_id.as_str());
            chunk.pos = (i * DEFAULT_RAFS_BLOCK_SIZE as u64) as u64;
            if i == self.inode.i_chunk_cnt - 1 {
                chunk.len = (file_size % DEFAULT_RAFS_BLOCK_SIZE as u64) as u32;
            } else {
                chunk.len = DEFAULT_RAFS_BLOCK_SIZE as u32;
            }

            // get chunk data
            file.seek(SeekFrom::Start(chunk.pos))?;
            let mut chunk_data = vec![0; chunk.len as usize];
            file.read_exact(&mut chunk_data)?;

            // calc chunk digest
            chunk.blockid = RafsDigest::from_buf(chunk_data.as_slice());

            // compress chunk data
            let compressed = utils::compress_with_lz4(&chunk_data)?;
            let compressed_size = compressed.len();
            chunk.offset = self.blob_offset;
            chunk.size = compressed_size as u32;

            // move cursor to offset of next chunk
            self.blob_offset = self.blob_offset + compressed_size as u64;

            trace!(
                "\tbuilding chunk: pos {}, len {}, offset {}, size {}",
                chunk.pos,
                chunk.len,
                chunk.offset,
                chunk.size,
            );

            // dump compressed chunk data to blob
            f_blob.write(&compressed)?;

            // calc inode digest
            inode_hash.input(&chunk.blockid.data);

            // stash chunk
            self.chunks.push(chunk);
        }

        // finish calc inode digest
        let mut inode_hash_buf = [0; RAFS_SHA256_LENGTH];
        inode_hash.result(&mut inode_hash_buf);
        let mut inode_digest = RafsDigest::new();
        inode_digest.data.clone_from_slice(&inode_hash_buf);
        self.inode.digest = inode_digest;

        trace!(
            "\tbuilding inode: name {}, ino {}, digest {}, parent {}, chunk_cnt {}",
            self.inode.name,
            self.inode.i_ino,
            self.inode.digest,
            self.inode.i_parent,
            self.inode.i_chunk_cnt,
        );

        Ok(())
    }

    fn dump_bootstrap(&self, mut f_bootstrap: &File) -> Result<()> {
        // dump inode info to bootstrap
        self.inode.store(&mut f_bootstrap)?;

        // dump inode xattr to bootstrap
        self.xattr_chunks.store(&mut f_bootstrap)?;

        // dump chunk info to bootstrap
        for chunk in &self.chunks {
            chunk.store(&mut f_bootstrap)?;
        }

        // or dump symlink chunk info to bootstrap
        for chunk in &self.link_chunks {
            chunk.store(&mut f_bootstrap)?;
        }

        Ok(())
    }
}
