// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A readonly filesystem with separated metadata and data, to support on-demand loading.

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;

use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::unix::io::AsRawFd;

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
pub trait RafsIoWrite: Write {}

impl RafsIoRead for File {}
impl RafsIoWrite for File {}

/// Handler to read file system metadata.
pub type RafsIoReader = Box<dyn RafsIoRead>;

/// Handler to write file system metadata.
pub type RafsIoWriter = Box<dyn RafsIoWrite>;

/// Rafs related common error code.
#[macro_export]
macro_rules! err_decompress_failed {
    () => {{
        use nydus_utils::eio;
        eio!("decompression failed")
    }};
}
#[macro_export]
macro_rules! err_invalid_superblock {
    () => {{
        use nydus_utils::einval;
        einval!("invalid superblock")
    }};
}
#[macro_export]
macro_rules! err_not_directory {
    () => {{
        use nydus_utils::enotdir;
        enotdir!("is not a directory")
    }};
}
