// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A manager to cache all file system metadata into memory.
//!
//! All file system metadata will be loaded, validated and cached into memory when loading the
//! file system. And currently the cache layer only supports readonly file systems.
use std::cmp;
use std::collections::{BTreeMap, HashMap};
use std::io::{ErrorKind, Result};
use std::sync::Arc;

use fuse_rs::abi::linux_abi::Attr;
use fuse_rs::api::filesystem::{Entry, ROOT_ID};

use crate::fs::Inode;
use crate::metadata::layout::{
    OndiskChunkInfo, OndiskDigest, OndiskInode, RAFS_CHUNK_INFO_SIZE, RAFS_SUPER_VERSION_V4,
    RAFS_SUPER_VERSION_V5,
};
use crate::metadata::{
    parse_string, RafsChunkInfo, RafsDigest, RafsInode, RafsSuper, RafsSuperInodes, RafsSuperMeta,
    RAFS_BLOB_ID_MAX_LENGTH, RAFS_INODE_BLOCKSIZE, RAFS_MAX_NAME,
};
use crate::storage::device::{RafsBio, RafsBioDesc};
use crate::{ebadf, einval, enoent, RafsIoReader};

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

pub struct CachedInodes {
    s_inodes: BTreeMap<Inode, Arc<CachedInode>>,
}

impl CachedInodes {
    pub fn new() -> Self {
        CachedInodes {
            s_inodes: BTreeMap::new(),
        }
    }

    fn load_dir_dfs(
        &mut self,
        mut dir: CachedInode,
        sb: &mut RafsSuperMeta,
        r: &mut RafsIoReader,
    ) -> Result<Option<CachedInode>> {
        trace!("loading dir {} ino {}", &dir.i_name, dir.i_ino);

        if dir.has_xattr() {
            dir.load_xattr(sb, r)?;
        }

        let mut res = None;
        let mut next = None;
        'outer: loop {
            let inode: CachedInode = match next.take() {
                Some(i) => i,
                None => {
                    let mut inode = CachedInode::new();
                    match inode.load(sb, r) {
                        Ok(_) => {
                            trace!(
                                "got inode {} ino {} parent {}",
                                inode.name(),
                                inode.ino(),
                                inode.parent()
                            );
                        }
                        Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => break 'outer,
                        Err(e) => {
                            error!("error when loading CachedInode {:?}", e);
                            return Err(e);
                        }
                    }
                    inode
                }
            };

            // The next inode is out of current directory, return it.
            if inode.i_parent != dir.i_ino {
                res = Some(inode);
                break;
            }

            let ino = inode.ino();
            if inode.is_dir() {
                if let Some(node) = self.load_dir_dfs(inode, sb, r)? {
                    next = Some(node);
                }
            } else {
                self.load_node(inode, sb, r)?;
            }

            // The inode should have been insert into the hashmap.
            let inode = self.s_inodes.get(&ino).unwrap();
            dir.add_child(inode.clone());
        }

        trace!("loaded dir {}", &dir.name());
        self.hash_inode(Arc::new(dir))?;

        Ok(res)
    }

    fn load_node(
        &mut self,
        mut inode: CachedInode,
        sb: &RafsSuperMeta,
        r: &mut RafsIoReader,
    ) -> Result<()> {
        trace!(
            "loading inode {} xattr {} symlink {} regular {} chunk_cnt {}",
            &inode.i_name,
            inode.has_xattr(),
            inode.is_symlink(),
            inode.is_reg(),
            inode.i_chunk_cnt,
        );

        if inode.has_xattr() {
            inode.load_xattr(sb, r)?;
        }
        if inode.is_reg() {
            inode.load_chunkinfo(sb, r)?;
        } else if inode.is_symlink() {
            inode.load_symlink(sb, r)?;
        }

        trace!("loaded inode {}", &inode.i_name);
        self.hash_inode(Arc::new(inode))?;

        Ok(())
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
}

impl RafsSuperInodes for CachedInodes {
    fn load(&mut self, sb: &mut RafsSuperMeta, r: &mut RafsIoReader) -> Result<()> {
        // import root inode
        let mut root_inode = CachedInode::new();
        root_inode.load(sb, r)?;
        sb.s_root_inode = root_inode.i_ino;

        if sb.s_version == RAFS_SUPER_VERSION_V4 {
            sb.s_inodes_count = std::u64::MAX;
        }
        // Load and cache all inodes starting from the root directory.
        self.load_dir_dfs(root_inode, sb, r)?;
        if sb.s_version == RAFS_SUPER_VERSION_V4 {
            sb.s_inodes_count = self.s_inodes.len() as u64;
        }

        // root inode must have ROOT_ID as its inode number
        if sb.s_root_inode != ROOT_ID {
            let root_inode = self.s_inodes.get(&sb.s_root_inode).unwrap().clone();
            self.s_inodes.insert(ROOT_ID, root_inode);
            sb.s_root_inode = ROOT_ID;
        }

        Ok(())
    }

    fn destroy(&mut self) {
        self.s_inodes.clear();
    }

    fn get_inode(&self, ino: Inode) -> Result<&dyn RafsInode> {
        self.s_inodes
            .get(&ino)
            .map(|i| i.as_ref() as &dyn RafsInode)
            .ok_or_else(enoent)
    }

    fn get_blob_id<'a>(&'a self, _index: u32) -> Result<&'a OndiskDigest> {
        unimplemented!() // TODO
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
    i_child_index: u32,
    i_child_count: u32,

    /*
    i_atimensec: u64,
    i_mtimensec: u64,
    i_ctimensec: u64,
     */
    i_target: String,
    i_xattr: HashMap<String, Vec<u8>>,
    i_data: Vec<CachedChunkInfo>,
    i_child: Vec<Arc<CachedInode>>,
}

impl CachedInode {
    pub fn new() -> Self {
        CachedInode {
            ..Default::default()
        }
    }

    pub fn load(&mut self, sb: &RafsSuperMeta, r: &mut RafsIoReader) -> Result<()> {
        let mut inode = OndiskInode::new();

        r.read_exact(inode.as_mut())?;
        inode.validate(sb)?;
        self.copy_from_ondisk(&inode, sb.s_version);
        trace!("loaded inode: {}", &inode);

        Ok(())
    }

    fn load_xattr(&mut self, _sb: &RafsSuperMeta, _r: &mut RafsIoReader) -> Result<()> {
        /*
        let mut input = vec![0u8; size_of::<u32>()];
        r.read_exact(&mut input[..])?;
        let mut sz = u32::from_le_bytes(input);
        if sz < 2 * size_of::<u32>() {
            return Err(einval());
        }

        sz -= size_of::<u32>();
        let mut input = vec![0u8; sz];
        r.read_exact(&mut input)?;
        let mut pos = size_of::<u32>();
        let count = u32::from_le_bytes(&input[..pos]);
        for _ in 0..count {
            if pos + size_of::<u32>() >= sz {
                return Err(einval());
            }
            let key_size = u32::from_le_bytes(&input[pos..pos + size_of::<u32>()]);
            pos += size_of::<u32>();
            if pos + key_size >= sz {
                return Err(einval());
            }
            let key = parse_string(&input[pos..pos + key_size])?;
            pos += key_size;
            if pos + size_of::<u32>() >= sz {
                return Err(einval());
            }
            let value_size = u32::from_le_bytes(&input[pos..pos + size_of::<u32>()]);
            pos += size_of::<u32>();
            if pos + value_size_size >= sz {
                return Err(einval());
            }
            self.i_xattr.insert(key.to_string(), input[pos..pos + value_size].into_vec());
            pos += value_size;
        }
        trace!("loaded xattr {:?}", self);

        Ok(())
         */
        unimplemented!()
    }

    fn load_symlink(&mut self, _sb: &RafsSuperMeta, r: &mut RafsIoReader) -> Result<()> {
        let sz = self.i_chunk_cnt as usize * RAFS_CHUNK_INFO_SIZE;
        if sz == 0 || sz > (libc::PATH_MAX as usize) + RAFS_CHUNK_INFO_SIZE - 1 {
            return Err(ebadf());
        }

        let mut input = vec![0u8; sz];
        r.read_exact(&mut input)?;
        let str = parse_string(&input)?;
        if str.len() >= libc::PATH_MAX as usize {
            Err(ebadf())
        } else {
            self.i_target = str.to_string();
            Ok(())
        }
    }

    fn load_chunkinfo(&mut self, sb: &RafsSuperMeta, r: &mut RafsIoReader) -> Result<()> {
        for _ in 0..self.i_chunk_cnt {
            let mut info = CachedChunkInfo::new();
            info.load(sb, r)?;
            self.i_data.push(info.into())
        }

        Ok(())
    }

    fn copy_from_ondisk(&mut self, inode: &OndiskInode, fs_version: u32) {
        self.i_ino = inode.ino();
        self.i_name = inode.name().to_string();
        self.i_data_digest = inode.digest().clone();
        self.i_parent = inode.parent();
        self.i_mode = inode.mode();
        self.i_projid = inode.projid();
        self.i_uid = inode.uid();
        self.i_gid = inode.gid();
        self.i_flags = inode.flags();
        self.i_rdev = inode.rdev();
        self.i_size = inode.size();
        self.i_nlink = inode.nlink();
        self.i_blocks = inode.blocks();
        self.i_atime = inode.atime();
        self.i_mtime = inode.mtime();
        self.i_ctime = inode.ctime();
        self.i_chunk_cnt = inode.chunk_cnt();
        if fs_version == RAFS_SUPER_VERSION_V5 {
            self.i_child_index = inode.child_index();
            self.i_child_count = inode.child_count();
        }
    }

    fn add_child(&mut self, child: Arc<CachedInode>) {
        self.i_child.push(child);
    }
}

impl RafsInode for CachedInode {
    fn validate(&self, _sb: &RafsSuperMeta) -> Result<()> {
        // TODO: validate

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

    fn get_symlink(&self, _sb: &RafsSuper) -> Result<&[u8]> {
        if !self.is_symlink() {
            Err(einval())
        } else {
            Ok(self.i_target.as_bytes())
        }
    }

    fn get_xattrs(&self, _sb: &RafsSuper) -> Result<HashMap<String, Vec<u8>>> {
        Ok(self.i_xattr.clone())
    }

    fn get_child_count(&self, _sb: &RafsSuper) -> Result<usize> {
        Ok(self.i_child.len())
    }

    fn get_child_by_index<'a, 'b>(
        &'a self,
        index: usize,
        _sb: &'b RafsSuper,
    ) -> Result<&'b dyn RafsInode> {
        if index >= self.i_child.len() {
            Err(enoent())
        } else {
            // Logically we should do a sb.s_inodes.get(self.i_child[index].ino()),
            // so a transmute() to avoid the HashMap looking up and it's safe because all inodes
            // have the same lifetime as the superblock.
            let inode = self.i_child[index].as_ref();
            Ok(unsafe { std::mem::transmute::<&'a dyn RafsInode, &'b dyn RafsInode>(inode) })
        }
    }

    fn get_child_by_name<'a, 'b>(
        &'a self,
        target: &str,
        _sb: &'b RafsSuper,
    ) -> Result<&'b dyn RafsInode> {
        for inode in self.i_child.iter() {
            if target.eq(inode.name()) {
                // Logically we should do a sb.s_inodes.get(self.i_child[index].ino()),
                // so a transmute() to avoid the HashMap looking up and it's safe because all inodes
                // have the same lifetime as the superblock.
                return Ok(unsafe {
                    std::mem::transmute::<&'a dyn RafsInode, &'b dyn RafsInode>(inode.as_ref())
                });
            }
        }

        Err(enoent())
    }

    fn alloc_bio_desc<'a>(
        &'a self,
        blksize: u32,
        size: usize,
        offset: u64,
        _sb: &'a RafsSuper,
    ) -> Result<RafsBioDesc<'a>> {
        let mut desc = RafsBioDesc::new();
        let end = offset + size as u64;

        for blk in self.i_data.iter() {
            if (blk.file_offset() + blksize as u64) <= offset {
                continue;
            } else if blk.file_offset() >= end {
                break;
            }

            let blob_id = _sb.s_inodes.get_blob_id(blk.blob_index())?;
            let file_start = cmp::max(blk.file_offset(), offset);
            let file_end = cmp::min(blk.file_offset() + blksize as u64, end);
            let bio = RafsBio::new(
                blk,
                blob_id, // TODO
                (file_start - blk.file_offset()) as u32,
                (file_end - file_start) as usize,
                blksize,
            );

            desc.bi_vec.push(bio);
            desc.bi_size += bio.size;
        }

        Ok(desc)
    }

    fn name(&self) -> &str {
        &self.i_name
    }

    fn set_name(&mut self, name: &str) -> Result<()> {
        let len = name.len();
        if len > RAFS_MAX_NAME {
            return Err(einval());
        }

        self.i_name = name.to_string();

        Ok(())
    }

    fn digest(&self) -> &OndiskDigest {
        &self.i_data_digest
    }

    fn set_digest(&mut self, digest: &OndiskDigest) {
        self.i_data_digest = *digest;
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
    impl_getter_setter!(child_index, set_child_index, i_child_index, u32);
    impl_getter_setter!(child_count, set_child_count, i_child_count, u32);
}

/// Cached information about an Rafs Data Chunk.
#[derive(Clone, Default, Debug)]
pub struct CachedChunkInfo {
    // block hash
    c_block_id: OndiskDigest,
    // blob containing the block
    c_blob_index: u32,
    // position of the block within the file
    c_file_offset: u64,
    // offset of the block within the blob
    c_blob_offset: u64,
    // size of the block, compressed
    c_compr_size: u32,
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
        self.c_block_id = chunk.block_id().clone();
        self.c_blob_index = chunk.blob_index();
        self.c_blob_offset = chunk.blob_offset();
        self.c_file_offset = chunk.file_offset();
        self.c_compr_size = chunk.compress_size();
    }
}

impl RafsChunkInfo for CachedChunkInfo {
    fn validate(&self, _sb: &RafsSuperMeta) -> Result<()> {
        self.c_block_id.validate()?;
        Ok(())
    }

    fn block_id(&self) -> &OndiskDigest {
        &self.c_block_id
    }

    fn block_id_mut(&mut self) -> &mut OndiskDigest {
        &mut self.c_block_id
    }

    fn set_block_id(&mut self, digest: &OndiskDigest) {
        self.c_block_id = *digest;
    }

    impl_getter_setter!(blob_index, set_blob_index, c_blob_index, u32);
    impl_getter_setter!(file_offset, set_file_offset, c_file_offset, u64);
    impl_getter_setter!(blob_offset, set_blob_offset, c_blob_offset, u64);
    impl_getter_setter!(compress_size, set_compress_size, c_compr_size, u32);
}

impl From<&OndiskChunkInfo> for CachedChunkInfo {
    fn from(info: &OndiskChunkInfo) -> Self {
        CachedChunkInfo {
            c_block_id: info.block_id().clone(),
            c_blob_index: info.blob_index(),
            c_file_offset: info.file_offset(),
            c_blob_offset: info.blob_offset(),
            c_compr_size: info.compress_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::layout::{save_symlink_ondisk, INO_FLAG_SYMLINK};
    use crate::metadata::{calc_symlink_size, CachedIoBuf, RafsSuper};
    use crate::{RafsIoRead, RafsIoWrite};

    #[test]
    fn test_rafs_cached_inode_load() {
        let mut ondisk = OndiskInode::new();
        let mut buf = CachedIoBuf::new();
        let mut inode = CachedInode::new();
        let mut sb = RafsSuper::new();

        sb.s_meta.s_inodes_count = 100;
        ondisk.set_name("test").unwrap();
        ondisk.set_parent(2);
        ondisk.set_ino(3);

        buf.append_buf(ondisk.as_ref());
        let mut buf: Box<dyn RafsIoRead> = Box::new(buf);
        inode.load(&sb.s_meta, &mut buf).unwrap();

        assert_eq!(ondisk.parent(), inode.parent());
        assert_eq!(ondisk.name(), inode.name());
        assert_eq!(ondisk.ino(), inode.ino());
        assert_eq!(ondisk.get_attr().ino, inode.get_attr().ino);
        assert_eq!(ondisk.get_attr().blksize, inode.get_attr().blksize);
    }

    #[test]
    fn test_rafs_cached_inode_load_symlink() {
        let mut sb = RafsSuper::new();
        let mut buf = CachedIoBuf::new();
        let mut buf1: Box<dyn RafsIoRead> = Box::new(buf.clone());
        let target = "t".repeat(8192);
        let mut inode = CachedInode::new();

        sb.s_meta.s_inodes_count = 100;
        buf.append_buf(target.as_ref());
        inode.load_symlink(&sb.s_meta, &mut buf1).unwrap_err();
        inode.i_chunk_cnt = 4096;
        inode.load_symlink(&sb.s_meta, &mut buf1).unwrap_err();

        inode.i_chunk_cnt = ((4096 + RAFS_CHUNK_INFO_SIZE - 1) / RAFS_CHUNK_INFO_SIZE) as u64;
        let target = "t".repeat(4096);
        buf.set_buf(target.as_ref());
        inode.load_symlink(&sb.s_meta, &mut buf1).unwrap_err();

        inode.i_chunk_cnt = ((4096 + RAFS_CHUNK_INFO_SIZE - 1) / RAFS_CHUNK_INFO_SIZE) as u64;
        let target = "t".repeat(4095);
        buf.set_buf(target.as_ref());
        buf.append_buf(&[0u8]);
        inode.load_symlink(&sb.s_meta, &mut buf1).unwrap();
    }

    #[test]
    fn test_rafs_cached_inode_alloc_bio_desc() {
        let mut inode = CachedInode::new();
        let sb = RafsSuper::new();

        inode.set_chunk_cnt(2);
        inode.i_data.push(CachedChunkInfo {
            c_block_id: Default::default(),
            c_blob_id: "1".to_string(),
            c_file_offset: 0,
            c_blob_offset: 0,
            c_compr_size: 4096,
        });
        inode.i_data.push(CachedChunkInfo {
            c_block_id: Default::default(),
            c_blob_id: "1".to_string(),
            c_file_offset: 4096,
            c_blob_offset: 4096,
            c_compr_size: 4096,
        });

        let descs = inode.alloc_bio_desc(4096, 1, 0, &sb).unwrap();
        assert_eq!(descs.bi_size, 1);
        assert_eq!(descs.bi_vec.len(), 1);
        assert_eq!(descs.bi_vec[0].offset, 0);
        assert_eq!(descs.bi_vec[0].size, 1);
        assert_eq!(descs.bi_vec[0].blksize, 4096);

        let descs = inode.alloc_bio_desc(4096, 1, 4096, &sb).unwrap();
        assert_eq!(descs.bi_size, 1);
        assert_eq!(descs.bi_vec.len(), 1);
        assert_eq!(descs.bi_vec[0].offset, 0);
        assert_eq!(descs.bi_vec[0].size, 1);
        assert_eq!(descs.bi_vec[0].blksize, 4096);

        let descs = inode.alloc_bio_desc(4096, 4097, 0, &sb).unwrap();
        assert_eq!(descs.bi_size, 4097);
        assert_eq!(descs.bi_vec.len(), 2);
        assert_eq!(descs.bi_vec[0].offset, 0);
        assert_eq!(descs.bi_vec[0].size, 4096);
        assert_eq!(descs.bi_vec[0].blksize, 4096);
        assert_eq!(descs.bi_vec[1].offset, 0);
        assert_eq!(descs.bi_vec[1].size, 1);
        assert_eq!(descs.bi_vec[1].blksize, 4096);

        let descs = inode.alloc_bio_desc(4096, 8193, 0, &sb).unwrap();
        assert_eq!(descs.bi_size, 8192);
        assert_eq!(descs.bi_vec.len(), 2);
        assert_eq!(descs.bi_vec[0].offset, 0);
        assert_eq!(descs.bi_vec[0].size, 4096);
        assert_eq!(descs.bi_vec[0].blksize, 4096);
        assert_eq!(descs.bi_vec[1].offset, 0);
        assert_eq!(descs.bi_vec[1].size, 4096);
        assert_eq!(descs.bi_vec[1].blksize, 4096);

        let descs = inode.alloc_bio_desc(4096, 2, 8191, &sb).unwrap();
        assert_eq!(descs.bi_size, 1);
        assert_eq!(descs.bi_vec.len(), 1);
        assert_eq!(descs.bi_vec[0].offset, 4095);
        assert_eq!(descs.bi_vec[0].size, 1);
        assert_eq!(descs.bi_vec[0].blksize, 4096);

        let descs = inode.alloc_bio_desc(4096, 1, 8192, &sb).unwrap();
        assert_eq!(descs.bi_size, 0);

        let descs = inode.alloc_bio_desc(4096, 1, 8193, &sb).unwrap();
        assert_eq!(descs.bi_size, 0);
    }

    #[test]
    fn test_rafs_cached_chunk_info() {
        let mut chunkinfo = CachedChunkInfo::new();
        let sb = RafsSuper::new();

        chunkinfo.c_blob_id = "t".repeat(RAFS_BLOB_ID_MAX_LENGTH);
        chunkinfo.validate(&sb.s_meta).unwrap_err();
        chunkinfo.c_blob_id = "t".repeat(RAFS_BLOB_ID_MAX_LENGTH - 1);
        chunkinfo.validate(&sb.s_meta).unwrap();

        chunkinfo
            .set_blobid(&"t".repeat(RAFS_BLOB_ID_MAX_LENGTH))
            .unwrap_err();
        chunkinfo
            .set_blobid(&"t".repeat(RAFS_BLOB_ID_MAX_LENGTH - 1))
            .unwrap();
    }

    #[test]
    fn test_rafs_cached_chunk_info_load() {
        let mut ondisk = OndiskChunkInfo::new();
        let mut buf = CachedIoBuf::new();
        let mut sb = RafsSuper::new();

        sb.s_meta.s_inodes_count = 100;
        ondisk.set_blob_offset(10);
        ondisk.set_compress_size(5);
        buf.append_buf(ondisk.as_ref());

        let mut buf: Box<dyn RafsIoRead> = Box::new(buf);
        let mut chunk = CachedChunkInfo::new();
        chunk.load(&sb.s_meta, &mut buf).unwrap();

        assert_eq!(chunk.blob_offset(), 10);
        assert_eq!(chunk.compress_size(), 5);
    }

    #[test]
    fn test_rafs_cached_load_dfs() {
        let mut buf = CachedIoBuf::new();
        let mut sb = RafsSuper::new();
        sb.s_meta.s_inodes_count = 100;

        let mut ondisk = OndiskInode::new();
        ondisk.set_name("root").unwrap();
        ondisk.set_parent(ROOT_ID);
        ondisk.set_ino(ROOT_ID);
        ondisk.set_mode(libc::S_IFDIR);
        buf.append_buf(ondisk.as_ref());

        let mut ondisk = OndiskInode::new();
        ondisk.set_name("a").unwrap();
        ondisk.set_parent(ROOT_ID);
        ondisk.set_ino(ROOT_ID + 1);
        ondisk.set_chunk_cnt(2);
        ondisk.set_mode(libc::S_IFREG);
        ondisk.set_size(RAFS_INODE_BLOCKSIZE as u64 * 2);
        buf.append_buf(ondisk.as_ref());
        let mut ondisk = OndiskChunkInfo::new();
        ondisk.set_blob_offset(0);
        ondisk.set_compress_size(5);
        buf.append_buf(ondisk.as_ref());
        let mut ondisk = OndiskChunkInfo::new();
        ondisk.set_blob_offset(10);
        ondisk.set_compress_size(5);
        buf.append_buf(ondisk.as_ref());

        let mut ondisk = OndiskInode::new();
        ondisk.set_name("b").unwrap();
        ondisk.set_parent(ROOT_ID);
        ondisk.set_ino(ROOT_ID + 2);
        ondisk.set_mode(libc::S_IFDIR);
        buf.append_buf(ondisk.as_ref());

        let mut ondisk = OndiskInode::new();
        ondisk.set_name("c").unwrap();
        ondisk.set_parent(ROOT_ID + 2);
        ondisk.set_ino(ROOT_ID + 3);
        ondisk.set_mode(libc::S_IFLNK);
        let (_, chunks) = calc_symlink_size("/a/b/d".len()).unwrap();
        ondisk.set_chunk_cnt(chunks as u64);
        ondisk.set_flags(INO_FLAG_SYMLINK);
        buf.append_buf(ondisk.as_ref());
        let mut buf1: Box<dyn RafsIoWrite> = Box::new(buf.clone());
        save_symlink_ondisk("/a/b/d".as_bytes(), &mut buf1).unwrap();

        let mut inodes = CachedInodes::new();
        let mut buf2: Box<dyn RafsIoRead> = Box::new(buf.clone());
        inodes.load(&mut sb.s_meta, &mut buf2).unwrap();
    }
}
