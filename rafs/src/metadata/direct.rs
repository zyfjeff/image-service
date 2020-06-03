// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::{Error, Result};
use std::mem::size_of;
use std::os::unix::io::FromRawFd;
use std::slice;

use crate::metadata::layout::*;
use crate::metadata::*;

/// Impl get / set accessor for an object.
#[allow(unused_macros)]
macro_rules! impl_getter_setter {
    ($G: ident, $S: ident, $F: ident, $U: ty) => {
        fn $G(&self) -> $U {
            self.data.$F
        }

        fn $S(&mut self, $F: $U) {
            self.data.$F = $F;
        }
    };
}

/// Impl get accessor for an object.
macro_rules! impl_getter {
    ($G: ident, $F: ident, $U: ty) => {
        fn $G(&self) -> $U {
            self.data.$F
        }
    };
}

/// Direct mode use mmap to access Ondisk metadata.
#[derive(Clone)]
pub struct DirectMapping {
    pub inode_table: OndiskInodeTable,
    pub blob_table: OndiskBlobTable,
    pub base: *const u8,
    pub end: *const u8,
    pub size: usize,
}

unsafe impl Send for DirectMapping {}
unsafe impl Sync for DirectMapping {}

impl Default for DirectMapping {
    fn default() -> Self {
        Self {
            inode_table: OndiskInodeTable::default(),
            blob_table: OndiskBlobTable::default(),
            base: std::ptr::null(),
            end: std::ptr::null(),
            size: 0,
        }
    }
}

impl DirectMapping {
    pub fn new(inode_table: OndiskInodeTable, blob_table: OndiskBlobTable) -> Self {
        let mut dm = Self::default();
        dm.inode_table = inode_table;
        dm.blob_table = blob_table;
        dm
    }

    /// Mmap to metadata ondisk data directly.
    fn cast_to_ref<'a, 'b, T>(&'a self, base: *const u8, offset: usize) -> Result<&'b T> {
        let start = base.wrapping_add(offset);
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

impl RafsSuperInodes for DirectMapping {
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let fd = unsafe { libc::dup(r.as_raw_fd()) };
        if fd < 0 {
            return Err(Error::last_os_error());
        }

        let file = unsafe { File::from_raw_fd(fd) };
        let md = file.metadata()?;
        let len = md.len();
        if len < RAFS_SUPERBLOCK_SIZE as u64
            || len > RAFS_MAX_METADATA_SIZE as u64
            || len & (RAFS_ALIGNMENT as u64 - 1) != 0
        {
            return Err(ebadf());
        }
        let size = len as usize;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ,
                libc::MAP_NORESERVE | libc::MAP_PRIVATE,
                fd,
                0,
            )
        } as *const u8;

        // Safe because the mmap area should covered the range [start, end)
        let end = unsafe { base.add(size) };

        self.base = base;
        self.end = end;
        self.size = size;

        Ok(())
    }

    fn destroy(&mut self) {
        if !self.base.is_null() {
            unsafe { libc::munmap(self.base as *mut u8 as *mut libc::c_void, self.size) };
            self.base = std::ptr::null();
            self.end = std::ptr::null();
            self.size = 0;
        }
    }

    /// Find inode offset by ino from inode table and mmap to OndiskInode.
    fn get_inode(&self, ino: Inode, meta: RafsSuperMeta) -> Result<Box<dyn RafsInode>> {
        let offset = self.inode_table.get(ino)?;

        let inode = self.cast_to_ref::<OndiskInode>(self.base, offset as usize)?;

        Ok(Box::new(OndiskInodeMapping {
            mapping: self.clone(),
            data: inode,
            meta,
        }) as Box<dyn RafsInode>)
    }

    fn get_max_ino(&self) -> Inode {
        self.inode_table.len() as u64
    }
}

pub struct OndiskInodeMapping<'a> {
    pub mapping: DirectMapping,
    pub data: &'a OndiskInode,
    pub meta: RafsSuperMeta,
}

impl<'a> OndiskInodeMapping<'a> {}

impl<'a> RafsInode for OndiskInodeMapping<'a> {
    fn validate(&self) -> Result<()> {
        unimplemented!();
    }

    fn name(&self) -> Result<&str> {
        let start = self.data as *const OndiskInode as *const u8;

        let name = unsafe {
            slice::from_raw_parts(
                start.wrapping_add(size_of::<OndiskInode>()),
                self.data.i_name_size as usize,
            )
        };

        parse_string(name)
    }

    fn get_symlink(&self) -> Result<&str> {
        let start = self.data as *const OndiskInode as *const u8;
        let start = start.wrapping_add(size_of::<OndiskInode>() + self.data.i_name_size as usize);

        let symlink = unsafe { slice::from_raw_parts(start, self.data.i_symlink_size as usize) };

        parse_string(symlink)
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn get_chunk_info(&self, idx: u32) -> Result<Arc<OndiskChunkInfo>> {
        if !self.is_reg() {
            return Err(enoent());
        }

        if self.data.i_child_count == 0 || idx > self.data.i_child_count - 1 {
            return Err(enoent());
        }

        let start = self.data as *const OndiskInode as *const u8;

        let mut offset = self.data.size();
        if self.data.has_xattr() {
            let xattrs = start.wrapping_add(self.data.size()) as *const OndiskXAttrs;
            offset += size_of::<OndiskXAttrs>() + unsafe { (*xattrs).aligned_size() };
        }
        offset += size_of::<OndiskChunkInfo>() * idx as usize;

        let chunk = self.mapping.cast_to_ref::<OndiskChunkInfo>(start, offset)?;

        Ok(Arc::new(*chunk))
    }

    fn get_child_by_name(&self, name: &str) -> Result<Box<dyn RafsInode>> {
        let child_count = self.data.i_child_count;

        if !self.is_dir() {
            return Err(einval());
        }

        for idx in 0..child_count {
            let inode = self.get_child_by_index(idx as u64)?;
            if inode.name()? == name {
                return Ok(inode);
            }
        }

        Err(enoent())
    }

    fn get_child_by_index(&self, idx: Inode) -> Result<Box<dyn RafsInode>> {
        let child_count = self.data.i_child_count as u64;
        let child_index = self.data.i_child_index as u64;

        if !self.is_dir() {
            return Err(einval());
        }

        if idx > child_count - 1 {
            return Err(enoent());
        }

        match idx.checked_add(child_index) {
            None => Err(enoent()),
            Some(idx) => Ok(self.mapping.get_inode(idx, self.meta)?),
        }
    }

    fn get_child_count(&self) -> Result<usize> {
        Ok(self.data.i_child_count as usize)
    }

    fn get_chunk_blob_id(&self, idx: u32) -> Result<Box<dyn RafsDigest>> {
        let digest = self.mapping.blob_table.get(idx)?;
        Ok(digest as Box<dyn RafsDigest>)
    }

    fn get_entry(&self) -> Entry {
        Entry {
            attr: self.get_attr().into(),
            inode: self.data.i_ino,
            generation: 0,
            attr_timeout: self.meta.attr_timeout,
            entry_timeout: self.meta.entry_timeout,
        }
    }

    fn get_attr(&self) -> Attr {
        Attr {
            ino: self.data.i_ino,
            size: self.data.i_size,
            blocks: self.data.i_blocks,
            atime: self.data.i_atime,
            ctime: self.data.i_ctime,
            mtime: self.data.i_mtime,
            mode: self.data.i_mode,
            nlink: self.data.i_nlink as u32,
            uid: self.data.i_uid,
            gid: self.data.i_gid,
            rdev: self.data.i_rdev as u32,
            blksize: RAFS_INODE_BLOCKSIZE,
            ..Default::default()
        }
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn get_xattrs(&self) -> Result<HashMap<String, Vec<u8>>> {
        if !self.data.has_xattr() {
            return Ok(HashMap::new());
        }

        let start = self.data as *const OndiskInode as *const u8;
        let start = start.wrapping_add(self.data.size());
        let xattrs = start as *const OndiskXAttrs;
        let xattrs_size = unsafe { (*xattrs).size() };
        let xattrs_aligned_size = unsafe { (*xattrs).aligned_size() };

        let xattrs_data = unsafe {
            slice::from_raw_parts(
                start.wrapping_add(size_of::<OndiskXAttrs>()),
                xattrs_aligned_size,
            )
        };

        parse_xattrs(xattrs_data, xattrs_size)
    }

    fn alloc_bio_desc(&self, offset: u64, size: usize) -> Result<RafsBioDesc> {
        let blksize = self.meta.block_size;
        let mut desc = RafsBioDesc::new();
        let end = offset + size as u64;

        for idx in 0..self.data.i_child_count {
            let blk = self.get_chunk_info(idx)?;
            if (blk.file_offset + blksize as u64) <= offset {
                continue;
            } else if blk.file_offset >= end {
                break;
            }

            let blob_id = self.get_chunk_blob_id(blk.blob_index)?;
            let file_start = cmp::max(blk.file_offset, offset);
            let file_end = cmp::min(blk.file_offset + blksize as u64, end);
            let bio = RafsBio::new(
                blk.clone(),
                blob_id,
                (file_start - blk.file_offset) as u32,
                (file_end - file_start) as usize,
                blksize,
            );

            desc.bi_size += bio.size;
            desc.bi_vec.push(bio);
        }

        Ok(desc)
    }

    fn is_dir(&self) -> bool {
        self.data.is_dir()
    }

    fn is_symlink(&self) -> bool {
        self.data.is_symlink()
    }

    fn is_reg(&self) -> bool {
        self.data.is_reg()
    }

    fn is_hardlink(&self) -> bool {
        self.data.is_hardlink()
    }

    fn has_xattr(&self) -> bool {
        self.data.has_xattr()
    }

    fn digest(&self) -> &OndiskDigest {
        &self.data.i_digest
    }

    impl_getter!(ino, i_ino, u64);
    impl_getter!(parent, i_parent, u64);
    impl_getter!(size, i_size, u64);
}
