// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A readonly filesystem with separated metadata and data, to support on-demand loading.

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;

use std::any::Any;
use std::fs::File;
use std::io::Result;
use std::io::SeekFrom;
use std::io::{Read, Seek, Write};
use std::os::unix::io::AsRawFd;

use crate::metadata::layout::align_to_rafs;
use nydus_utils::einval;

#[macro_use]
mod error;
pub mod fs;
pub mod metadata;
pub mod storage;

#[macro_use]
extern crate lazy_static;
#[allow(dead_code)]
pub mod io_stats;

/// A helper trait for RafsIoReader.
pub trait RafsIoRead: Read + AsRawFd + Seek {}

/// A helper trait for RafsIoWriter.
pub trait RafsIoWrite: Write + Seek {
    fn as_any(&self) -> &dyn Any;
}

impl RafsIoRead for File {}
impl RafsIoWrite for File {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl dyn RafsIoWrite {
    /// seek to current + offset position, it's thread unsafe.
    fn seek_offset(&mut self, off: u64) -> Result<u64> {
        self.seek(SeekFrom::Current(off as i64))
    }
    /// align file size to RAFS_ALIGNMENT.
    pub fn seal(&mut self) -> Result<()> {
        let file = self
            .as_any()
            .downcast_ref::<File>()
            .ok_or_else(|| einval!("invalid File type"))?;
        file.set_len(align_to_rafs(file.metadata()?.len() as usize) as u64)
    }
}

/// Handler to read file system metadata.
pub type RafsIoReader = Box<dyn RafsIoRead>;

/// Handler to write file system metadata.
pub type RafsIoWriter = Box<dyn RafsIoWrite>;
