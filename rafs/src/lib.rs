// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A readonly filesystem with separated bootstrap and data, to support on-demand loading.

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;

use std::any::Any;
use std::fs::File;
use std::io::Result;
use std::io::{Read, Seek, Write};
use std::os::unix::io::AsRawFd;

use crate::metadata::layout::RAFS_ALIGNMENT;
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
    /// write padding to align to RAFS_ALIGNMENT.
    pub fn write_padding(&mut self, size: usize) -> Result<()> {
        if size > RAFS_ALIGNMENT {
            return Err(einval!("invalid padding size"));
        }
        let padding = [0u8; RAFS_ALIGNMENT];
        self.write_all(&padding[0..size])
    }
}

/// Handler to read file system bootstrap.
pub type RafsIoReader = Box<dyn RafsIoRead>;

/// Handler to write file system bootstrap.
pub type RafsIoWriter = Box<dyn RafsIoWrite>;
