// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Error, Result};
use std::mem::size_of;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::slice;
use std::sync::Arc;

use crate::fs::Inode;
use crate::metadata::layout::{
    OndiskChunkInfo, OndiskInode, RAFS_CHUNK_INFO_SIZE, RAFS_INODE_INFO_SIZE, RAFS_SUPERBLOCK_SIZE,
    RAFS_XATTR_ALIGNMENT,
};
use crate::metadata::{
    parse_string, RafsChunkInfo, RafsInode, RafsSuperInodes, RafsSuperMeta, RAFS_MAX_METADATA_SIZE,
};
use crate::storage::device::{RafsBio, RafsBioDesc};
use crate::*;

struct DirectMapping {
    base: *const u8,
    end: *const u8,
    size: usize,
}

impl DirectMapping {
    fn new() -> Self {
        DirectMapping {
            base: std::ptr::null(),
            end: std::ptr::null(),
            size: 0,
        }
    }

    fn from_raw_fd(fd: RawFd) -> Result<Self> {
        let file = unsafe { File::from_raw_fd(fd) };
        let md = file.metadata()?;
        let _ = file.into_raw_fd();
        let len = md.len();
        if len < RAFS_SUPERBLOCK_SIZE as u64
            || len > RAFS_MAX_METADATA_SIZE as u64
            || len & (RAFS_XATTR_ALIGNMENT as u64 - 1) != 0
        {
            return Err(ebadf());
        }

        let size = len as usize;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ,
                libc::MAP_ANONYMOUS | libc::MAP_NORESERVE | libc::MAP_PRIVATE,
                fd,
                0,
            )
        } as *const u8;
        // Safe because the mmap area should covered the range [start, end)
        let end = unsafe { base.add(size) };

        Ok(DirectMapping { base, end, size })
    }

    fn cast_to_ref<'a, 'b, T>(&'a self, base: *const u8, offset: usize) -> Result<&'b T> {
        let start = base.wrapping_add(offset as usize);
        let end = start.wrapping_add(size_of::<T>());

        if start < self.base
            || end < self.base
            || end > self.end
            || start as usize & (std::mem::align_of::<T>() - 1) != 0
        {
            return Err(einval());
        }

        Ok(unsafe { &*(start as *const T) })
    }
}

impl Drop for DirectMapping {
    fn drop(&mut self) {
        if self.base != std::ptr::null() {
            unsafe { libc::munmap(self.base as *mut u8 as *mut libc::c_void, self.size) };
            self.base = std::ptr::null();
            self.end = std::ptr::null();
            self.size = 0;
        }
    }
}

pub struct DirectMapInodes {
    // TODO: use ArcSwap here to support swapping underlying metadata file.
    mapping: Arc<DirectMapping>,
    index_2_offset: Vec<u32>,
}

impl DirectMapInodes {
    pub fn new() -> Self {
        DirectMapInodes {
            mapping: Arc::new(DirectMapping::new()),
            index_2_offset: Vec::new(),
        }
    }

    fn get_inode_internal(&self, ino: Inode) -> Result<&OndiskInode> {
        if ino >= self.index_2_offset.len() as u64 {
            return Err(enoent());
        }
        let offset = u32::from_le(self.index_2_offset[ino as usize]) as usize;
        if offset <= (RAFS_SUPERBLOCK_SIZE >> 3) || offset >= (1usize << 29) {
            Err(enoent())
        } else {
            self.mapping
                .cast_to_ref::<OndiskInode>(self.mapping.base, offset << 3)
        }
    }

    fn get_chunk_info<'a, 'b>(
        &'a self,
        inode: &'b OndiskInode,
        idx: u64,
    ) -> Result<&'b OndiskChunkInfo> {
        let ptr = inode as *const OndiskInode as *const u8;
        let chunk = ptr
            .wrapping_add(size_of::<OndiskInode>() + size_of::<OndiskChunkInfo>() * idx as usize);

        self.mapping.cast_to_ref::<OndiskChunkInfo>(chunk, 0)
    }
}

impl RafsSuperInodes for DirectMapInodes {
    fn load(&mut self, _sb: &mut RafsSuperMeta, r: &mut RafsIoReader) -> Result<()> {
        let fd = unsafe { libc::dup(r.as_raw_fd()) };
        if fd < 0 {
            return Err(Error::last_os_error());
        }

        let mapping = DirectMapping::from_raw_fd(fd)?;
        self.mapping = Arc::new(mapping);

        Ok(())
    }

    fn destroy(&mut self) {
        self.mapping = Arc::new(DirectMapping::new());
    }

    fn get_inode(&self, ino: u64) -> Result<&dyn RafsInode> {
        let inode = self.get_inode_internal(ino)?;
        Ok(inode as &dyn RafsInode)
    }

    fn get_symlink<'a, 'b>(&'a self, inode: &'b OndiskInode) -> Result<&'b [u8]> {
        let inode = self.get_inode_internal(inode.ino())?;
        let sz = inode.chunk_cnt() as usize * RAFS_CHUNK_INFO_SIZE;
        if sz == 0 || sz > (libc::PATH_MAX as usize) + RAFS_CHUNK_INFO_SIZE - 1 {
            return Err(ebadf());
        }

        let start = (inode as *const OndiskInode as *const u8).wrapping_add(RAFS_INODE_INFO_SIZE);
        let end = start.wrapping_add(sz);
        if start < self.mapping.base || end < self.mapping.base || end > self.mapping.end {
            return Err(einval());
        }

        let input = unsafe { slice::from_raw_parts(start, sz) };
        let str = parse_string(input)?;
        if str.len() >= libc::PATH_MAX as usize {
            Err(ebadf())
        } else {
            Ok(str.as_bytes())
        }
    }

    fn get_xattrs(&self, _inode: &OndiskInode) -> Result<HashMap<String, Vec<u8>>> {
        unimplemented!()
    }

    fn alloc_bio_desc<'a, 'b>(
        &'a self,
        blksize: u32,
        size: usize,
        offset: u64,
        inode: &'b OndiskInode,
    ) -> Result<RafsBioDesc<'b>> {
        let mut desc = RafsBioDesc::new();
        let end = offset + size as u64;

        for idx in 0..inode.chunk_cnt() {
            let blk = self.get_chunk_info(inode, idx)?;
            if (blk.file_offset() + blksize as u64) <= offset {
                continue;
            } else if blk.file_offset() >= end {
                break;
            }

            let file_start = cmp::max(blk.file_offset(), offset);
            let file_end = cmp::min(blk.file_offset() + blksize as u64, end);
            let bio = RafsBio::new(
                blk,
                (file_start - blk.file_offset()) as u32,
                (file_end - file_start) as usize,
                blksize,
            );

            desc.bi_vec.push(bio);
            desc.bi_size += bio.size;
        }

        Ok(desc)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::CachedIoBuf;
    use super::*;
    use crate::metadata::layout::{save_symlink_ondisk, OndiskSuperBlock, INO_FLAG_SYMLINK};
    use crate::metadata::{calc_symlink_size, RafsSuper, RAFS_INODE_BLOCKSIZE};
    use fuse_rs::api::filesystem::ROOT_ID;

    #[test]
    fn test_rafs_directmap_load_v5() {
        let mut buf = CachedIoBuf::new();

        let mut sb = OndiskSuperBlock::new();
        sb.set_inode_size(4);
        sb.set_mapping_table_offset(RAFS_SUPERBLOCK_SIZE as u64);
        buf.write_all(sb.as_ref()).unwrap();

        let mut table = vec![0u8; 32];
        table[4] = 0x4;
        table[5] = 0x4;
        table[8] = 0x44;
        table[9] = 0x4;
        table[12] = 0xa4;
        table[13] = 0x4;
        table[16] = 0xe4;
        table[17] = 0x4;
        buf.write_all(table.as_ref()).unwrap();

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

        let (base, size) = buf.as_buf();
        let end = unsafe { base.add(size) };
        let mut inodes = DirectMapInodes::new();
        inodes.mapping = Arc::new(DirectMapping { base, end, size });
        inodes.index_2_offset.push(0);
        inodes.index_2_offset.push(0x404);
        inodes.index_2_offset.push(0x444);
        inodes.index_2_offset.push(0x4a4);
        inodes.index_2_offset.push(0x4e4);
        inodes.index_2_offset.push(0);
        inodes.index_2_offset.push(0);
        inodes.index_2_offset.push(0);

        let mut sb2 = RafsSuper::new();
        sb2.s_inodes = Box::new(inodes);
        sb2.s_meta.s_magic = sb.magic();
        sb2.s_meta.s_version = sb.version();
        sb2.s_meta.s_sb_size = sb.sb_size();
        sb2.s_meta.s_inode_size = sb.inode_size();
        sb2.s_meta.s_block_size = sb.block_size();
        sb2.s_meta.s_chunkinfo_size = sb.chunkinfo_size();
        sb2.s_meta.s_flags = sb.flags();
        sb2.s_meta.s_blocks_count = 0;
        sb2.s_meta.s_inodes_count = sb.inodes_count();
        sb2.s_meta.s_mapping_table_entries = sb.mapping_table_entries();
        sb2.s_meta.s_mapping_table_offset = sb.mapping_table_offset();

        let inode = sb2.s_inodes.get_inode(ROOT_ID).unwrap();
        assert_eq!(inode.ino(), ROOT_ID);
        assert_eq!(inode.parent(), ROOT_ID);
        assert_eq!(inode.is_dir(), true);

        let inode = sb2.s_inodes.get_inode(ROOT_ID + 1).unwrap();
        assert_eq!(inode.ino(), ROOT_ID + 1);
        assert_eq!(inode.parent(), ROOT_ID);
        assert_eq!(inode.is_reg(), true);
        assert_eq!(inode.chunk_cnt(), 2);
        // TODO: chunk

        let inode = sb2.s_inodes.get_inode(ROOT_ID + 2).unwrap();
        assert_eq!(inode.ino(), ROOT_ID + 2);
        assert_eq!(inode.parent(), ROOT_ID);
        assert_eq!(inode.is_dir(), true);

        let inode = sb2.s_inodes.get_inode(ROOT_ID + 3).unwrap();
        assert_eq!(inode.name(), "c");
        assert_eq!(inode.ino(), ROOT_ID + 3);
        assert_eq!(inode.parent(), ROOT_ID + 2);
        assert_eq!(inode.is_symlink(), true);
        assert_eq!(inode.chunk_cnt(), 1);
        assert_eq!(inode.get_symlink(&sb2).unwrap(), "/a/b/d".as_bytes());
    }
}
