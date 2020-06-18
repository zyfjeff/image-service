// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

/// A metadata driver to directly use on disk metadata as runtime in-memory metadata.
///
/// To reduce memory footprint and speed up filesystem initialization, the V5 on disk metadata
/// layout has been designed to support directly mapping as runtime metadata. So we don't need to
/// define another set of runtime data structures to cache on-disk metadata in memory.
///
/// To support modification to the runtime metadata, several technologies have been adopted:
/// * - arc-swap is used to support RCU-like update instead of Mutex/RwLock.
/// * - `offset` instead of `pointer` is used to record data structure position.
/// * - reference count to the referenced resources/objects.
///
/// # Security
/// The metadata file may be provided by untrusted parties, so we must ensure strong validations
/// before making use of any metadata, especially we are using them in memory-mapped mode. The
/// rule is to call validate() after creating any data structure from the on-disk metadata.
use std::fs::File;
use std::io::{Error, Result};
use std::mem::{size_of, ManuallyDrop};
use std::ops::Deref;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::slice;
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};

use crate::metadata::layout::*;
use crate::metadata::*;
use crate::storage::utils::readahead;

/// Impl get accessor for inode object.
macro_rules! impl_inode_getter {
    ($G: ident, $F: ident, $U: ty) => {
        #[inline]
        fn $G(&self) -> $U {
            let state = self.state();
            let inode = self.inode(state.deref());

            inode.$F
        }
    };
}

/// Impl get accessor for inode object.
macro_rules! impl_inode_wrapper {
    ($G: ident, $U: ty) => {
        #[inline]
        fn $G(&self) -> $U {
            let state = self.state();
            let inode = self.inode(state.deref());

            inode.$G()
        }
    };
}

/// Impl get accessor for chunkinfo object.
macro_rules! impl_chunkinfo_getter {
    ($G: ident, $U: ty) => {
        #[inline]
        fn $G(&self) -> $U {
            let state = self.state();

            self.chunk(state.deref()).$G()
        }
    };
}

/// The underlying struct to maintain memory mapped metadata for a file system.
///
/// Only the DirectMappingState may store raw pointers.
/// Other data structures should not store raw pointers, instead they should hold a reference to
/// the DirectMappingState object and store an offset, so a `pointer` could be reconstruct by
/// `DirectMappingState.base + offset`.
#[derive(Clone)]
struct DirectMappingState {
    meta: RafsSuperMeta,
    inode_table: ManuallyDrop<OndiskInodeTable>,
    blob_table: OndiskBlobTable,
    base: *const u8,
    end: *const u8,
    size: usize,
    fd: RawFd,
    mmapped_inode_table: bool,
}

impl DirectMappingState {
    fn new(meta: &RafsSuperMeta) -> Self {
        DirectMappingState {
            meta: *meta,
            inode_table: ManuallyDrop::new(OndiskInodeTable::default()),
            blob_table: OndiskBlobTable::default(),
            fd: -1,
            base: std::ptr::null(),
            end: std::ptr::null(),
            size: 0,
            mmapped_inode_table: false,
        }
    }

    /// Mmap to metadata ondisk data directly.
    fn cast_to_ref<'a, 'b, T>(&'a self, base: *const u8, offset: usize) -> Result<&'b T> {
        let start = base.wrapping_add(offset);
        let end = start.wrapping_add(size_of::<T>());

        if start > end
            || start < self.base
            || end < self.base
            || end > self.end
            || start as usize & (std::mem::align_of::<T>() - 1) != 0
        {
            return Err(einval());
        }

        Ok(unsafe { &*(start as *const T) })
    }

    #[inline]
    fn validate_range(&self, offset: usize, size: usize) -> Result<()> {
        let start = self.base.wrapping_add(offset);
        let end = start.wrapping_add(size);

        if start > end || start < self.base || end < self.base || end > self.end {
            return Err(einval());
        }

        Ok(())
    }
}

impl Drop for DirectMappingState {
    fn drop(&mut self) {
        // Drop the inode_table if it's not a memory-mapped one.
        if !self.mmapped_inode_table {
            unsafe {
                ManuallyDrop::drop(&mut self.inode_table);
            }
        }
        if !self.base.is_null() {
            unsafe { libc::munmap(self.base as *mut u8 as *mut libc::c_void, self.size) };
            self.base = std::ptr::null();
            self.end = std::ptr::null();
            self.size = 0;
        }
        if self.fd >= 0 {
            let _ = nix::unistd::close(self.fd);
            self.fd = -1;
        }
    }
}

#[derive(Clone)]
pub struct DirectMapping {
    state: ArcSwap<DirectMappingState>,
}

// Safe to Send/Sync because the underlying data structures are readonly
unsafe impl Send for DirectMapping {}
unsafe impl Sync for DirectMapping {}

impl DirectMapping {
    pub fn new(meta: &RafsSuperMeta) -> Self {
        let state = DirectMappingState::new(meta);

        Self {
            state: ArcSwap::new(Arc::new(state)),
        }
    }

    #[inline]
    fn get_inode_wrapper(
        &self,
        ino: Inode,
        state: &DirectMappingState,
    ) -> Result<OndiskInodeWrapper> {
        let offset = state.inode_table.get(ino)? as usize;
        let _inode = state.cast_to_ref::<OndiskInode>(state.base, offset)?;
        let wrapper = OndiskInodeWrapper {
            mapping: self.clone(),
            offset,
        };

        // TODO: use bitmap to record validation result.
        wrapper.validate()?;

        Ok(wrapper)
    }
}

impl RafsSuperInodes for DirectMapping {
    #[allow(clippy::cast_ptr_alignment)]
    fn load(&mut self, r: &mut RafsIoReader) -> Result<()> {
        let old_state = self.state.load();

        // Validate file size
        let fd = unsafe { libc::dup(r.as_raw_fd()) };
        if fd < 0 {
            return Err(Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let md = file.metadata()?;
        let len = md.len();
        let size = len as usize;
        if len < RAFS_SUPERBLOCK_SIZE as u64
            || len > RAFS_MAX_METADATA_SIZE as u64
            || len & (RAFS_ALIGNMENT as u64 - 1) != 0
        {
            return Err(ebadf());
        }

        // Validate inode table layout
        let inode_table_start = old_state.meta.inode_table_offset;
        let inode_table_size = old_state.meta.inode_table_entries as u64 * size_of::<u32>() as u64;
        let inode_table_end = inode_table_start
            .checked_add(inode_table_size)
            .ok_or_else(ebadf)?;
        if inode_table_start < RAFS_SUPERBLOCK_SIZE as u64
            || inode_table_start >= len
            || inode_table_start > inode_table_end
            || inode_table_end > len
        {
            return Err(ebadf());
        }

        // Validate blob table layout
        let blob_table_start = old_state.meta.blob_table_offset;
        let blob_table_size = old_state.meta.blob_table_size as u64;
        let blob_table_end = blob_table_start
            .checked_add(blob_table_size)
            .ok_or_else(ebadf)?;
        if blob_table_start < RAFS_SUPERBLOCK_SIZE as u64
            || blob_table_start >= len
            || blob_table_start > blob_table_end
            || blob_table_end > len
        {
            return Err(ebadf());
        }

        // prefetch the metadata file
        readahead(fd, 0, len);

        // mmap the metadata file into current process for direct access
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
        if base as *mut core::ffi::c_void == libc::MAP_FAILED {
            return Err(Error::last_os_error());
        }
        if base.is_null() {
            return Err(ebadf());
        }
        // Safe because the mmap area should covered the range [start, end)
        let end = unsafe { base.add(size) };

        // Load blob table. Safe because we have validated the inode table layout.
        let blob_slice = unsafe {
            slice::from_raw_parts(
                base.add(blob_table_start as usize),
                blob_table_size as usize,
            )
        };
        let mut blob_table = OndiskBlobTable::new();
        blob_table.load_from_slice(blob_slice).map_err(|e| {
            unsafe { libc::munmap(base as *mut u8 as *mut libc::c_void, size) };
            e
        })?;

        // Load(Map) inode table. Safe because we have validated the inode table layout.
        // Though we have passed *mut u32 to Vec::from_raw_parts(), it will trigger invalid memory
        // access if the underlying memory is written to.
        let inode_table = unsafe {
            OndiskInodeTable {
                data: Vec::from_raw_parts(
                    base.add(inode_table_start as usize) as *const u32 as *mut u32,
                    old_state.meta.inode_table_entries as usize,
                    old_state.meta.inode_table_entries as usize,
                ),
            }
        };

        let state = DirectMappingState {
            meta: old_state.meta,
            inode_table: ManuallyDrop::new(inode_table),
            blob_table,
            fd: file.into_raw_fd(),
            base,
            end,
            size,
            mmapped_inode_table: true,
        };

        // Swap new and old DirectMappingState object, the old object will be destroyed when the
        // reference count reaches zero.
        self.state.store(Arc::new(state));

        Ok(())
    }

    fn destroy(&mut self) {
        let state = DirectMappingState::new(&RafsSuperMeta::default());

        self.state.store(Arc::new(state));
    }

    /// Find inode offset by ino from inode table and mmap to OndiskInode.
    #[inline]
    fn get_inode(&self, ino: Inode) -> Result<Arc<dyn RafsInode>> {
        let state = self.state.load();
        let wrapper = self.get_inode_wrapper(ino, state.deref())?;

        Ok(Arc::new(wrapper) as Arc<dyn RafsInode>)
    }

    fn get_max_ino(&self) -> Inode {
        let state = self.state.load();

        state.inode_table.len() as u64
    }

    fn get_blobs(&self) -> Vec<OndiskBlobTableEntry> {
        let state = self.state.load();

        state.blob_table.get_all()
    }
}

pub struct OndiskInodeWrapper {
    pub mapping: DirectMapping,
    pub offset: usize,
}

impl OndiskInodeWrapper {
    #[inline]
    fn state(&self) -> Guard<Arc<DirectMappingState>> {
        self.mapping.state.load()
    }

    #[allow(clippy::cast_ptr_alignment)]
    #[inline]
    fn inode<'a>(&self, state: &'a DirectMappingState) -> &'a OndiskInode {
        unsafe {
            let ptr = state.base.add(self.offset);
            &*(ptr as *const OndiskInode)
        }
    }

    fn name_ref<'a>(&self, state: &'a DirectMappingState) -> Result<&'a str> {
        let offset = self.offset + size_of::<OndiskInode>();
        let name = unsafe {
            let start = state.base.add(offset);
            slice::from_raw_parts(start, self.inode(state).i_name_size as usize)
        };

        Ok(parse_string(name)?.0)
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn get_xattr_size(&self) -> Result<usize> {
        let state = self.state();
        let inode = self.inode(state.deref());

        if inode.has_xattr() {
            let offset = self.offset + inode.size();
            state.validate_range(offset, size_of::<OndiskXAttrs>())?;
            unsafe {
                let xattrs = state.base.add(offset) as *const OndiskXAttrs;
                Ok(size_of::<OndiskXAttrs>() + (*xattrs).aligned_size())
            }
        } else {
            Ok(0)
        }
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn get_xattr_data(&self) -> Result<(&[u8], usize)> {
        let state = self.state();
        let inode = self.inode(state.deref());

        if !inode.has_xattr() {
            return Ok((&[], 0));
        }

        let offset = self.offset + inode.size();
        let start = unsafe { state.base.add(offset) };
        let xattrs = start as *const OndiskXAttrs;
        let xattr_size = unsafe { (*xattrs).size() };
        let xattrs_aligned_size = unsafe { (*xattrs).aligned_size() };

        state.validate_range(offset, size_of::<OndiskXAttrs>() + xattrs_aligned_size)?;

        let xattr_data = unsafe {
            slice::from_raw_parts(start.wrapping_add(size_of::<OndiskXAttrs>()), xattr_size)
        };

        Ok((xattr_data, xattr_size))
    }
}

impl RafsInode for OndiskInodeWrapper {
    fn validate(&self) -> Result<()> {
        // TODO: please help to review/enhance this and all other validate(), otherwise there's
        // always security risks because the image metadata may be provided by untrusted parties.
        let state = self.state();
        let inode = self.inode(state.deref());

        // * - parent inode nuber must be less than child inode number unless child is a hardlink.
        // * - inode link count must not be zero.
        // * - name_size must be less than 255. Due to alignment, the check is not so strict.
        // * - name_size and symlink_size must be correctly aligned.
        // Should we store raw size instead of aligned size for name and symlink?
        if inode.i_parent == inode.i_ino
            || (inode.i_parent > inode.i_ino && inode.i_nlink == 1)
            || inode.i_nlink == 0
            || inode.i_name_size as usize > (RAFS_MAX_NAME + 1)
            || inode.i_name_size & (RAFS_ALIGNMENT as u16 - 1) != 0
            || inode.i_symlink_size & (RAFS_ALIGNMENT as u16 - 1) != 0
        {
            error!("inode validation failure, inode {:#?}", inode);
            return Err(ebadf());
        }

        let xattr_size = if inode.has_xattr() {
            self.get_xattr_size()?
        } else {
            0
        };

        if inode.is_reg() {
            let size = inode.size()
                + xattr_size
                + inode.i_child_count as usize * size_of::<OndiskChunkInfo>();
            state.validate_range(self.offset, size)?;
        } else if inode.is_dir() {
            let max_ino = state.inode_table.len();
            // * - child inode number must be bigger than parent's inode number
            // * - child inode number has mapping in the inode table
            if (inode.i_child_index as u64) <= inode.i_ino
                || (inode.i_child_index - 1) as usize > max_ino
                || inode.i_child_count as usize > max_ino
            {
                return Err(ebadf());
            }

            let size = inode.size() + xattr_size;
            state.validate_range(self.offset, size)?;
        }

        Ok(())
    }

    /// Get name of the inode.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn name(&self) -> Result<String> {
        let state = self.state();

        self.name_ref(state.deref()).map(|v| v.to_owned())
    }

    /// Get symlink target of the inode.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn get_symlink(&self) -> Result<String> {
        let state = self.state();
        let inode = self.inode(state.deref());
        let offset = self.offset + size_of::<OndiskInode>() + inode.i_name_size as usize;
        // TODO: the symlink is aligned, should we store raw size?
        let symlink = unsafe {
            let start = state.base.add(offset);
            slice::from_raw_parts(start, inode.i_symlink_size as usize)
        };

        Ok(parse_string(symlink)?.0.to_owned())
    }

    /// Get the child with the specified name.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn get_child_by_name(&self, name: &str) -> Result<Arc<dyn RafsInode>> {
        let state = self.state();
        let inode = self.inode(state.deref());

        if !inode.is_dir() {
            return Err(einval());
        }

        let mut first = 0 as i32;
        let mut last = (inode.i_child_count - 1) as i32;

        // Binary search by child name.
        // This implemention is more convenient and slightly outperforms than slice::binary_search.
        while first <= last {
            let pivot = first + ((last - first) >> 1);

            let wrapper = self
                .mapping
                .get_inode_wrapper((inode.i_child_index as i32 + pivot) as u64, state.deref())?;
            let target = wrapper.name_ref(state.deref())?;

            if target == name {
                return Ok(Arc::new(wrapper) as Arc<dyn RafsInode>);
            }

            if target > name {
                last = pivot - 1;
            } else {
                first = pivot + 1;
            }
        }

        Err(enoent())
    }

    /// Get the child with the specified index.
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    fn get_child_by_index(&self, idx: Inode) -> Result<Arc<dyn RafsInode>> {
        let state = self.state();
        let inode = self.inode(state.deref());
        let child_count = inode.i_child_count as u64;
        let child_index = inode.i_child_index as u64;

        if !inode.is_dir() {
            return Err(einval());
        }
        if idx >= child_count {
            return Err(enoent());
        }

        self.mapping.get_inode(idx + child_index)
    }

    /// Get chunk information with index `idx`
    ///
    /// # Safety
    /// It depends on Self::validate() to ensure valid memory layout.
    #[allow(clippy::cast_ptr_alignment)]
    fn get_chunk_info(&self, idx: u32) -> Result<Arc<dyn RafsChunkInfo>> {
        let state = self.state();
        let inode = self.inode(state.deref());

        if !inode.is_reg() || inode.i_child_count == 0 || idx > inode.i_child_count - 1 {
            return Err(enoent());
        }

        let mut offset = self.offset + inode.size();
        if inode.has_xattr() {
            unsafe {
                let xattrs = state.base.add(offset) as *const OndiskXAttrs;
                offset += size_of::<OndiskXAttrs>() + (*xattrs).aligned_size();
            }
        }
        offset += size_of::<OndiskChunkInfo>() * idx as usize;

        let chunk = state.cast_to_ref::<OndiskChunkInfo>(state.base, offset)?;
        let wrapper = OndiskChunkInfoWrapper::new(chunk, self.mapping.clone(), offset);
        wrapper.validate(&state.meta)?;

        Ok(Arc::new(wrapper))
    }

    #[inline]
    fn get_chunk_blob_id(&self, idx: u32) -> Result<String> {
        Ok(self.state().blob_table.get(idx)?.blob_id)
    }

    fn get_entry(&self) -> Entry {
        let state = self.state();
        let inode = self.inode(state.deref());

        Entry {
            attr: self.get_attr().into(),
            inode: inode.i_ino,
            generation: 0,
            attr_timeout: state.meta.attr_timeout,
            entry_timeout: state.meta.entry_timeout,
        }
    }

    fn get_attr(&self) -> Attr {
        let state = self.state();
        let inode = self.inode(state.deref());

        Attr {
            ino: inode.i_ino,
            size: inode.i_size,
            blocks: inode.i_blocks,
            atime: inode.i_atime,
            ctime: inode.i_ctime,
            mtime: inode.i_mtime,
            mode: inode.i_mode,
            nlink: inode.i_nlink as u32,
            uid: inode.i_uid,
            gid: inode.i_gid,
            rdev: inode.i_rdev as u32,
            blksize: RAFS_INODE_BLOCKSIZE,
            ..Default::default()
        }
    }

    fn get_xattr(&self, name: &str) -> Result<Option<XattrValue>> {
        let (xattr_data, xattr_size) = self.get_xattr_data()?;
        parse_xattr_value(xattr_data, xattr_size, name)
    }

    fn get_xattrs(&self) -> Result<Vec<XattrName>> {
        let (xattr_data, xattr_size) = self.get_xattr_data()?;
        parse_xattr_names(xattr_data, xattr_size)
    }

    #[inline]
    fn get_child_count(&self) -> Result<usize> {
        let state = self.state();
        let inode = self.inode(state.deref());

        Ok(inode.i_child_count as usize)
    }

    fn alloc_bio_desc(&self, offset: u64, size: usize) -> Result<RafsBioDesc> {
        let state = self.mapping.state.load();
        let inode = self.inode(state.deref());
        let blksize = state.meta.block_size;
        let end = offset + size as u64;

        let mut desc = RafsBioDesc::new();

        for idx in 0..inode.i_child_count {
            let chunk = self.get_chunk_info(idx)?;
            if (chunk.file_offset() + blksize as u64) <= offset {
                continue;
            } else if chunk.file_offset() >= end {
                break;
            }

            let blob_id = self.get_chunk_blob_id(chunk.blob_index())?;
            let chunk_start = if offset > chunk.file_offset() {
                offset - chunk.file_offset()
            } else {
                0
            };
            let chunk_end = if end < (chunk.file_offset() + chunk.decompress_size() as u64) {
                end - chunk.file_offset()
            } else {
                chunk.decompress_size() as u64
            };

            let compressor = state.meta.get_compressor();
            let bio = RafsBio::new(
                chunk,
                blob_id,
                compressor,
                chunk_start as u32,
                (chunk_end - chunk_start) as usize,
                blksize,
            );

            desc.bi_size += bio.size;
            desc.bi_vec.push(bio);
        }

        Ok(desc)
    }

    impl_inode_wrapper!(is_dir, bool);
    impl_inode_wrapper!(is_reg, bool);
    impl_inode_wrapper!(is_symlink, bool);
    impl_inode_wrapper!(is_hardlink, bool);
    impl_inode_wrapper!(has_xattr, bool);
    impl_inode_getter!(ino, i_ino, u64);
    impl_inode_getter!(parent, i_parent, u64);
    impl_inode_getter!(size, i_size, u64);
}

struct OndiskChunkInfoWrapper {
    mapping: DirectMapping,
    offset: usize,
    digest: Arc<OndiskDigest>,
}

unsafe impl Send for OndiskChunkInfoWrapper {}
unsafe impl Sync for OndiskChunkInfoWrapper {}

impl OndiskChunkInfoWrapper {
    #[inline]
    fn new(chunk: &OndiskChunkInfo, mapping: DirectMapping, offset: usize) -> Self {
        Self {
            mapping,
            offset,
            digest: Arc::new(chunk.block_id),
        }
    }

    #[inline]
    fn state(&self) -> Guard<Arc<DirectMappingState>> {
        self.mapping.state.load()
    }

    /// Dereference the underlying OndiskChunkInfo object.
    ///
    /// # Safety
    /// The OndiskChunkInfoWrapper could only be constructed from a valid OndiskChunkInfo pointer,
    /// so it's safe to dereference the underlying OndiskChunkInfo object.
    #[allow(clippy::cast_ptr_alignment)]
    #[inline]
    fn chunk<'a>(&self, state: &'a DirectMappingState) -> &'a OndiskChunkInfo {
        unsafe {
            let ptr = state.base.add(self.offset);
            &*(ptr as *const OndiskChunkInfo)
        }
    }
}

impl RafsChunkInfo for OndiskChunkInfoWrapper {
    #[inline]
    fn validate(&self, sb: &RafsSuperMeta) -> Result<()> {
        let state = self.state();

        state.validate_range(self.offset, size_of::<OndiskChunkInfo>())?;

        self.chunk(state.deref()).validate(sb)
    }

    #[inline]
    fn block_id(&self) -> Arc<dyn RafsDigest> {
        self.digest.clone()
    }

    impl_chunkinfo_getter!(blob_index, u32);
    impl_chunkinfo_getter!(blob_compress_offset, u64);
    impl_chunkinfo_getter!(compress_size, u32);
    impl_chunkinfo_getter!(blob_decompress_offset, u64);
    impl_chunkinfo_getter!(decompress_size, u32);
    impl_chunkinfo_getter!(file_offset, u64);
    impl_chunkinfo_getter!(is_compressed, bool);
}
