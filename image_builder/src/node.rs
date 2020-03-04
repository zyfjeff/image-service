// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::{self, File};
use std::io::prelude::*;
use std::io::Result;
use std::io::SeekFrom;
use std::os::linux::fs::MetadataExt;
use std::path::Path;

use compress::lz4;
use crypto::digest::Digest;
use crypto::sha2::Sha256;

use rafs::layout::*;

pub struct Node<'a> {
    blob_id: &'a str,
    blob_offset: u64,
    meta: &'a dyn MetadataExt,
    path: &'a str,
    parent: &'a Option<Box<Node<'a>>>,
    inode: RafsInodeInfo,
    chunks: Vec<RafsChunkInfo>,
}

impl<'a> Node<'a> {
    pub fn new(
        blob_id: &'a str,
        blob_offset: u64,
        meta: &'a dyn MetadataExt,
        path: &'a str,
        parent: &'a Option<Box<Node>>,
    ) -> Node<'a> {
        Node {
            blob_id,
            blob_offset,
            meta,
            path,
            parent,
            inode: RafsInodeInfo::new(),
            chunks: vec![],
        }
    }

    pub fn build(&mut self, mut f_blob: &File, mut f_bootstrap: &File) -> Result<()> {
        let mut file_type = "file";
        if self.meta.st_mode() & libc::S_IFDIR > 0 {
            file_type = "dir";
        }
        trace!("building {} {}", file_type, self.path);

        self.build_inode()?;
        self.build_chunks(&mut f_blob, &mut f_bootstrap)?;

        Ok(())
    }

    fn build_inode(&mut self) -> Result<()> {
        if self.parent.is_none() {
            self.inode.i_parent = 0;
            self.inode.i_ino = 1;
            self.inode.i_mode = libc::S_IFDIR;
            return Ok(());
        }

        let file_name = Path::new(self.path).file_name().unwrap().to_str().unwrap();

        self.inode.name = String::from(file_name);
        let parent = self.parent.as_ref().unwrap();
        self.inode.i_parent = parent.inode.i_ino;
        self.inode.i_ino = self.meta.st_ino();
        self.inode.i_mode = self.meta.st_mode();
        self.inode.i_uid = self.meta.st_uid();
        self.inode.i_gid = self.meta.st_gid();
        self.inode.i_padding = 0;
        self.inode.i_rdev = self.meta.st_rdev();
        self.inode.i_size = self.meta.st_size();
        self.inode.i_nlink = self.meta.st_nlink();
        self.inode.i_blocks = self.meta.st_blocks();
        self.inode.i_atime = self.meta.st_atime() as u64;
        self.inode.i_mtime = self.meta.st_mtime() as u64;
        self.inode.i_ctime = self.meta.st_ctime() as u64;

        // self.inode.digest
        // self.inode.i_chunk_cnt
        // self.inode.i_flags = 0;

        Ok(())
    }

    fn build_reg_chunk(&mut self, mut f_blob: &File, mut f_bootstrap: &File) -> Result<()> {
        let file_size = self.inode.i_size;
        let chunk_count = (file_size as f64 / DEFAULT_RAFS_BLOCK_SIZE as f64).ceil() as u64;
        self.inode.i_chunk_cnt = chunk_count;

        // offset cursor in blob for compressed chunk data
        let mut offset = 0;
        let mut inode_hash = Sha256::new();
        let mut file = File::open(self.path)?;

        for i in 0..chunk_count {
            let mut chunk = RafsChunkInfo::new();

            // get chunk info
            chunk.blobid = String::from(self.blob_id);
            chunk.pos = (i * DEFAULT_RAFS_BLOCK_SIZE as u64) as u64;
            if i == chunk_count - 1 {
                chunk.len = (file_size % DEFAULT_RAFS_BLOCK_SIZE as u64) as u32;
            } else {
                chunk.len = DEFAULT_RAFS_BLOCK_SIZE as u32;
            }
            chunk.offset = self.blob_offset;
            chunk.size = file_size as u32;
            trace!(
                "\tchunk: pos {}, len {}, offset {}, size {}",
                chunk.pos,
                chunk.len,
                chunk.offset,
                chunk.size
            );

            // get chunk data
            file.seek(SeekFrom::Start(chunk.pos))?;
            let mut chunk_data = vec![0; chunk.len as usize];
            file.read_exact(&mut chunk_data)?;

            // calc chunk digest
            chunk.blockid = RafsDigest::from_buf(chunk_data.as_slice());

            // compress chunk data
            let mut compressed = Vec::new();
            let compressed_size = lz4::encode_block(&chunk_data, &mut compressed);
            chunk.offset = 0;
            chunk.size = compressed_size as u32;
            offset = offset + compressed_size;

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

        // dump inode info to bootstrap
        self.inode.store(&mut f_bootstrap)?;

        // dump chunk info to bootstrap
        for chunk in &self.chunks {
            chunk.store(&mut f_bootstrap)?;
        }

        Ok(())
    }

    fn build_symlink_chunk(&mut self) -> Result<()> {
        let target_path = fs::read_link(self.path);
        let chunk_info_count = 0;
        let mut chunk = RafsLinkDataInfo::new(chunk_info_count);
        chunk.target = String::from(self.path);

        Ok(())
    }

    fn build_chunks(&mut self, mut f_blob: &File, mut f_bootstrap: &File) -> Result<()> {
        let file_mode = self.meta.st_mode();

        if file_mode & libc::S_IFREG > 0 {
            self.build_reg_chunk(f_blob, f_bootstrap)?;
        } else if file_mode & libc::S_IFLNK > 0 {
            self.build_symlink_chunk()?;
        }

        Ok(())
    }
}
