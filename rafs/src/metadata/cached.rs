// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A manager to cache all file system metadata into memory.
//!
//! All file system metadata will be loaded, validated and cached into memory when loading the
//! file system. And currently the cache layer only supports readonly file systems.
use std::cmp;
use std::collections::{BTreeMap, HashMap};
use std::io::{ErrorKind, Read, Result};
use std::sync::Arc;

use fuse_rs::abi::linux_abi;
use fuse_rs::api::filesystem::Entry;

use crate::fs::Inode;
use crate::metadata::layout::*;
use crate::metadata::*;
use crate::storage::compress::Algorithm::LZ4Block;
use crate::storage::device::{RafsBio, RafsBioDesc};
use crate::{einval, enoent, RafsIoReader};

pub struct CachedInodes {
    s_blob: Arc<OndiskBlobTable>,
    s_meta: Arc<RafsSuperMeta>,
    s_inodes: BTreeMap<Inode, Arc<CachedInode>>,
}

impl CachedInodes {
    pub fn new(meta: RafsSuperMeta, blobs: OndiskBlobTable) -> Self {
        CachedInodes {
            s_blob: Arc::new(blobs),
            s_inodes: BTreeMap::new(),
            s_meta: Arc::new(meta),
        }
    }

    /// v5 layout is based on BFS, which means parents always are in front of children
    fn load_all_inodes(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let mut dir_inos = Vec::new();
        'outer: loop {
            let mut inode = CachedInode::new(&self.s_blob, &self.s_meta);
            match inode.load(&self.s_meta, r) {
                Ok(_) => {
                    trace!("got inode ino {} parent {}", inode.ino(), inode.parent());
                }
                Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => break 'outer,
                Err(e) => {
                    error!("error when loading CachedInode {:?}", e);
                    return Err(e);
                }
            }
            let child_inode = self.add_node(inode)?;
            if child_inode.is_dir() {
                // dir inodes push into parent last
                dir_inos.push(child_inode.i_ino);
                continue;
            }
            self.add_into_parent(&child_inode)?;
        }
        while !dir_inos.is_empty() {
            let ino = dir_inos.pop().unwrap();
            self.add_into_parent(&self.get_node(ino)?)?;
        }

        Ok(())
    }

    fn add_node(&mut self, inode: CachedInode) -> Result<Arc<CachedInode>> {
        // load detail infos
        let ino = inode.i_ino;
        self.hash_inode(Arc::new(inode))?;
        self.get_node(ino)
    }

    fn get_node(&self, ino: Inode) -> Result<Arc<CachedInode>> {
        Ok(self.s_inodes.get(&ino).ok_or_else(enoent)?.clone())
    }

    fn get_node_mut(&mut self, ino: Inode) -> Result<&mut Arc<CachedInode>> {
        self.s_inodes.get_mut(&ino).ok_or_else(enoent)
    }

    fn hash_inode(&mut self, inode: Arc<CachedInode>) -> Result<()> {
        let mut skip = false;

        if inode.is_hardlink() {
            if let Some(i) = self.s_inodes.get(&inode.i_ino) {
                skip = !i.i_data.is_empty();
            }
        }
        if !skip {
            self.s_inodes.insert(inode.i_ino, inode);
        }

        Ok(())
    }

    fn add_into_parent(&mut self, child_inode: &Arc<CachedInode>) -> Result<()> {
        trace!(
            "try add {} into {}",
            child_inode.ino(),
            child_inode.parent()
        );
        if let Ok(parent_inode) = self.get_node_mut(child_inode.parent()) {
            Arc::get_mut(parent_inode)
                .unwrap()
                .add_child(child_inode.clone());
        }
        Ok(())
    }
}

impl RafsSuperInodes for CachedInodes {
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        self.load_all_inodes(r)
    }

    fn destroy(&mut self) {
        self.s_inodes.clear();
    }

    fn get_inode(&self, ino: Inode) -> Result<Arc<dyn RafsInode>> {
        self.s_inodes
            .get(&ino)
            .map_or(Err(enoent()), |i| Ok(i.clone()))
    }

    fn get_max_ino(&self) -> u64 {
        self.s_inodes.len() as u64
    }
}

#[derive(Default, Clone, Debug)]
pub struct CachedInode {
    i_ino: Inode,
    i_name: String,
    i_data_digest: OndiskDigest,
    i_parent: u64,
    i_mode: u32,
    i_projid: u32,
    i_uid: u32,
    i_gid: u32,
    i_flags: u64,
    i_rdev: u64,
    i_size: u64,
    i_nlink: u64,
    i_blocks: u64,
    i_atime: u64,
    i_mtime: u64,
    i_ctime: u64,
    i_chunk_cnt: u64,
    i_target: String, // for symbol link

    // extra info need cache
    i_blksize: u32,

    i_xattr: HashMap<String, Vec<u8>>,
    i_data: Vec<Arc<CachedChunkInfo>>,
    i_child: Vec<Arc<CachedInode>>,
    i_blob_table: Arc<OndiskBlobTable>,
    i_meta: Arc<RafsSuperMeta>,
}

impl CachedInode {
    pub fn new(blob_table: &Arc<OndiskBlobTable>, meta: &Arc<RafsSuperMeta>) -> Self {
        CachedInode {
            i_blob_table: blob_table.clone(),
            i_meta: meta.clone(),
            ..Default::default()
        }
    }

    fn load_name(&mut self, name_size: usize, r: &mut RafsIoReader) -> Result<()> {
        if name_size > 0 {
            let mut name_buf = vec![0u8; name_size];
            r.read_exact(name_buf.as_mut_slice())?;
            self.i_name = parse_string(&name_buf)?.0.to_string();
        }
        Ok(())
    }

    fn load_symlink(&mut self, symlink_size: usize, r: &mut RafsIoReader) -> Result<()> {
        if self.is_symlink() && symlink_size > 0 {
            let mut symbol_buf = vec![0u8; symlink_size];
            r.read_exact(symbol_buf.as_mut_slice())?;
            self.i_target = parse_string(&symbol_buf)?.0.to_string();
        }
        Ok(())
    }

    fn load_xattr(&mut self, r: &mut RafsIoReader) -> Result<()> {
        if self.has_xattr() {
            let mut xattrs = OndiskXAttrs::new();
            r.read_exact(xattrs.as_mut())?;
            let mut xattr_buf = vec![0u8; xattrs.aligned_size()];
            r.read_exact(xattr_buf.as_mut_slice())?;
            self.i_xattr = parse_xattrs(&xattr_buf, xattrs.aligned_size())?;
        }
        Ok(())
    }

    fn load_chunk_info(&mut self, r: &mut RafsIoReader) -> Result<()> {
        if self.is_reg() && self.i_chunk_cnt > 0 {
            let mut chunk = OndiskChunkInfo::new();
            for _i in 0..self.i_chunk_cnt {
                chunk.load(r)?;
                self.i_data.push(Arc::new(CachedChunkInfo::from(&chunk)));
            }
        }
        Ok(())
    }

    pub fn load(&mut self, sb: &RafsSuperMeta, r: &mut RafsIoReader) -> Result<()> {
        // OndiskInode...name...symbol link...chunks
        let mut inode = OndiskInode::new();

        // parse ondisk inode
        // OndiskInode|name|symbol|xattr|chunks
        r.read_exact(inode.as_mut())?;
        self.copy_from_ondisk(&inode);
        self.load_name(inode.i_name_size as usize, r)?;
        self.load_symlink(inode.i_symlink_size as usize, r)?;
        self.load_xattr(r)?;
        self.load_chunk_info(r)?;
        self.i_blksize = sb.block_size;
        self.validate()?;

        Ok(())
    }

    fn copy_from_ondisk(&mut self, inode: &OndiskInode) {
        self.i_ino = inode.i_ino;
        self.i_data_digest = inode.i_digest;
        self.i_parent = inode.i_parent;
        self.i_mode = inode.i_mode;
        self.i_projid = inode.i_projid;
        self.i_uid = inode.i_uid;
        self.i_gid = inode.i_gid;
        self.i_flags = inode.i_flags;
        self.i_rdev = inode.i_rdev;
        self.i_size = inode.i_size;
        self.i_nlink = inode.i_nlink;
        self.i_blocks = inode.i_blocks;
        self.i_atime = inode.i_atime;
        self.i_mtime = inode.i_mtime;
        self.i_ctime = inode.i_ctime;
        if self.is_reg() {
            self.i_chunk_cnt = inode.i_child_count as u64;
        }
    }

    fn add_child(&mut self, child: Arc<CachedInode>) {
        self.i_child.push(child);
    }
}

impl RafsInode for CachedInode {
    fn validate(&self) -> Result<()> {
        // TODO: validate

        Ok(())
    }

    fn name(&self) -> Result<String> {
        Ok(self.i_name.clone())
    }

    fn get_symlink(&self) -> Result<String> {
        if !self.is_symlink() {
            Err(einval())
        } else {
            Ok(self.i_target.clone())
        }
    }

    fn get_child_by_name(&self, name: &str) -> Result<Arc<dyn RafsInode>> {
        for inode in self.i_child.iter() {
            if inode.i_name.eq(name) {
                return Ok(inode.clone());
            }
        }

        Err(enoent())
    }

    fn get_child_by_index(&self, index: Inode) -> Result<Arc<dyn RafsInode>> {
        Ok(self.i_child[index as usize].clone())
    }

    fn get_child_count(&self) -> Result<usize> {
        Ok(self.i_child.len())
    }

    fn get_chunk_info(&self, idx: u32) -> Result<Arc<dyn RafsChunkInfo>> {
        Ok(self.i_data[idx as usize].clone())
    }

    fn get_chunk_blob_id(&self, idx: u32) -> Result<String> {
        self.i_blob_table.get(idx)
    }

    fn get_entry(&self) -> Entry {
        Entry {
            attr: self.get_attr().into(),
            inode: self.i_ino,
            generation: 0,
            attr_timeout: self.i_meta.attr_timeout,
            entry_timeout: self.i_meta.entry_timeout,
        }
    }

    fn get_attr(&self) -> linux_abi::Attr {
        linux_abi::Attr {
            ino: self.i_ino,
            size: self.i_size,
            blocks: self.i_blocks,
            atime: self.i_atime,
            ctime: self.i_ctime,
            mtime: self.i_mtime,
            mode: self.i_mode,
            nlink: self.i_nlink as u32,
            uid: self.i_uid,
            gid: self.i_gid,
            rdev: self.i_rdev as u32,
            blksize: RAFS_INODE_BLOCKSIZE,
            ..Default::default()
        }
    }

    fn get_xattrs(&self) -> Result<HashMap<String, Vec<u8>>> {
        Ok(self.i_xattr.clone())
    }

    fn alloc_bio_desc(&self, offset: u64, size: usize) -> Result<RafsBioDesc> {
        let mut desc = RafsBioDesc::new();
        let end = offset + size as u64;
        let blksize = self.i_blksize;

        for blk in self.i_data.iter() {
            if (blk.file_offset() + blksize as u64) <= offset {
                continue;
            } else if blk.file_offset() >= end {
                break;
            }
            let bio = RafsBio::new(
                blk.clone(),
                self.get_chunk_blob_id(blk.blob_index())?,
                LZ4Block,
                cmp::max(blk.file_offset(), offset) as u32,
                cmp::min(end - blk.file_offset(), blksize as u64) as usize,
                blksize,
            );
            desc.bi_size += bio.size;
            desc.bi_vec.push(bio);
        }

        Ok(desc)
    }

    fn is_dir(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFDIR
    }

    fn is_symlink(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFLNK
    }

    fn is_reg(&self) -> bool {
        self.i_mode & libc::S_IFMT == libc::S_IFREG
    }

    fn is_hardlink(&self) -> bool {
        self.i_nlink > 1
    }

    fn has_xattr(&self) -> bool {
        self.i_flags & INO_FLAG_XATTR == INO_FLAG_XATTR
    }

    impl_getter!(ino, i_ino, u64);
    impl_getter!(parent, i_parent, u64);
    impl_getter!(size, i_size, u64);
}

/// Cached information about an Rafs Data Chunk.
#[derive(Clone, Default, Debug)]
pub struct CachedChunkInfo {
    // block hash
    c_block_id: Arc<OndiskDigest>,
    // blob containing the block
    c_blob_index: u32,
    // position of the block within the file
    c_file_offset: u64,
    // offset of the block within the blob
    c_blob_compress_offset: u64,
    c_blob_decompress_offset: u64,
    // size of the block, compressed
    c_compr_size: u32,
    c_decompress_size: u32,
    c_flags: u32,
}

impl CachedChunkInfo {
    pub fn new() -> Self {
        CachedChunkInfo {
            ..Default::default()
        }
    }

    pub fn load(&mut self, sb: &RafsSuperMeta, r: &mut RafsIoReader) -> Result<()> {
        let mut chunk = OndiskChunkInfo::new();

        r.read_exact(chunk.as_mut())?;
        chunk.validate(sb)?;
        self.copy_from_ondisk(&chunk);

        Ok(())
    }

    fn copy_from_ondisk(&mut self, chunk: &OndiskChunkInfo) {
        self.c_block_id = Arc::new(chunk.block_id);
        self.c_blob_index = chunk.blob_index();
        self.c_blob_compress_offset = chunk.blob_compress_offset();
        self.c_blob_decompress_offset = chunk.blob_decompress_offset();
        self.c_decompress_size = chunk.decompress_size();
        self.c_file_offset = chunk.file_offset();
        self.c_compr_size = chunk.compress_size();
        self.c_flags = chunk.flags;
    }
}

impl RafsChunkInfo for CachedChunkInfo {
    fn validate(&self, _sb: &RafsSuperMeta) -> Result<()> {
        self.c_block_id.validate()?;
        Ok(())
    }

    fn block_id(&self) -> Arc<dyn RafsDigest> {
        self.c_block_id.clone()
    }

    impl_getter!(blob_index, c_blob_index, u32);
    impl_getter!(blob_compress_offset, c_blob_compress_offset, u64);
    impl_getter!(compress_size, c_compr_size, u32);
    impl_getter!(blob_decompress_offset, c_blob_decompress_offset, u64);
    impl_getter!(decompress_size, c_decompress_size, u32);
    impl_getter!(file_offset, c_file_offset, u64);

    fn is_compressed(&self) -> bool {
        self.c_flags & CHUNK_FLAG_COMPRESSED == CHUNK_FLAG_COMPRESSED
    }
}

impl From<&OndiskChunkInfo> for CachedChunkInfo {
    fn from(info: &OndiskChunkInfo) -> Self {
        let mut chunk = CachedChunkInfo::new();
        chunk.copy_from_ondisk(info);
        chunk
    }
}
