// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Result};

use vm_memory::VolatileSlice;

use crate::storage::utils::copyv;

#[allow(dead_code)]
pub mod request;

#[allow(dead_code)]
pub mod dummy;

mod error;
pub use error::ReqErr;

#[allow(dead_code)]
pub mod oss;

#[allow(dead_code)]
pub mod registry;

pub mod localfs;

// Rafs blob backend API
pub trait BlobBackend {
    // Read a range of data from blob into the provided slice
    fn read(&self, blob_id: &str, buf: &mut [u8], offset: u64) -> Result<usize>;

    // Read mutilple range of data from blob into the provided slices
    fn readv(
        &self,
        blob_id: &str,
        bufs: &[VolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> Result<usize> {
        let size = bufs.iter().fold(0usize, move |size, s| size + s.len());
        let mut src = vec![0u8; size];

        self.read(blob_id, src.as_mut_slice(), offset)?;

        copyv(&src, bufs, offset, max_size)
    }

    // Write a range of data to blob from the provided slice
    fn write(&self, blob_id: &str, buf: &[u8], offset: u64) -> Result<usize>;

    // Close a backend
    fn close(&mut self);
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
