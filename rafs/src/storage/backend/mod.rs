// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Result};

use vm_memory::VolatileSlice;

use crate::storage::utils::copyv;

pub mod dummy;
#[cfg(feature = "backend-localfs")]
pub mod localfs;
#[cfg(feature = "backend-oss")]
pub mod oss;
#[cfg(feature = "backend-registry")]
pub mod registry;
#[cfg(any(feature = "backend-oss", feature = "backend-registry"))]
pub mod request;

/// Rafs blob backend API
pub trait BlobBackend {
    /// prefetch blob if supported
    /// TODO: Now `blob_readahead_offset` is type of `u32`. Better that we can change
    /// it to u64 someday.
    fn prefetch_blob(
        &self,
        _blob_id: &str,
        _blob_readahead_offset: u32,
        _blob_readahead_size: u32,
    ) -> Result<()> {
        Ok(())
    }

    /// Read a range of data from blob into the provided slice
    fn read(&self, blob_id: &str, buf: &mut [u8], offset: u64) -> Result<usize>;

    /// Read mutilple range of data from blob into the provided slices
    fn readv(
        &self,
        blob_id: &str,
        bufs: &[VolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> Result<usize> {
        if bufs.len() == 1 && max_size >= bufs[0].len() {
            let buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), bufs[0].len()) };
            self.read(blob_id, buf, offset)
        } else {
            // Use std::alloc to avoid zeroing the allocated buffer.
            let size = bufs.iter().fold(0usize, move |size, s| size + s.len());
            let layout = std::alloc::Layout::from_size_align(size, 8).unwrap();
            let ptr = unsafe { std::alloc::alloc(layout) };
            let data = unsafe { std::slice::from_raw_parts_mut(ptr, size) };

            self.read(blob_id, data, offset)?;
            let result = copyv(&data, bufs, offset, max_size);

            unsafe { std::alloc::dealloc(ptr, layout) };

            result
        }
    }

    /// Write a range of data to blob from the provided slice
    fn write(&self, blob_id: &str, buf: &[u8], offset: u64) -> Result<usize>;
}

// Rafs blob backend upload API
pub trait BlobBackendUploader {
    type Reader: Read + Send + 'static;

    fn upload(
        &self,
        blob_id: &str,
        source: Self::Reader,
        size: usize,
        callback: fn((usize, usize)),
    ) -> Result<usize>;
}
