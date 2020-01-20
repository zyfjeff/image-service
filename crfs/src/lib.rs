// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::libc;

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

#[allow(unused_variables)]
pub trait Storage {
    // Open a device
    fn init(&self, conf: Config) -> io::Result {
        OK()
    }

    // Close a device
    fn close(&self) -> io::Result {
        OK()
    }

    // Submit IO to the open device
    fn submit_io(&self, bio: rafs_bio) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }
}
