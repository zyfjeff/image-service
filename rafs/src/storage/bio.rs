// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use vm_memory::VolatileSlice;

pub struct Auth {
    pub id: String,
    pub secret: String,
}

pub struct Config {
    // Storage path, can be a directory or a URL to some remote storage
    pub path: String,
    // auth info used to access the storage
    pub auth: Auth,
}

pub struct RafsBio<'a> {
    pub bi_flags: u32,
    pub bi_size: usize,
    pub bi_blksize: usize,
    pub bi_vec: Vec<RafsBioVec<'a>>,
}

pub struct RafsBioVec<'a> {
    pub blkinfo: RafsBlkInfo,
    pub offset: u32,
    pub buffer: VolatileSlice<'a>,
}

pub struct RafsBlkInfo {}

#[allow(unused_variables)]
pub trait Storage {
    // Open a device
    fn init(&self, conf: Config) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    // Close a device
    fn close(&self) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    // Submit IO to the open device
    fn submit_io(&self, bio: RafsBio) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }
}
