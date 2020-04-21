// Copyright 2020 Alibaba Cloud. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use nix::sys::uio;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Error, Result};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use crate::storage::backend::request::ReqErr;
use crate::storage::backend::{BlobBackend, BlobBackendUploader};

#[derive(Debug)]
pub struct LocalFs {
    // directory to blob files
    dir: String,
}

pub fn new<S: std::hash::BuildHasher>(config: &HashMap<String, String, S>) -> Result<LocalFs> {
    let dir = config
        .get("dir")
        .ok_or_else(|| ReqErr::inv_input("dir required"))?;

    fs::create_dir_all(dir)?;

    Ok(LocalFs {
        dir: (*dir).to_owned(),
    })
}

impl BlobBackend for LocalFs {
    fn read(&self, blobid: &str, buf: &mut Vec<u8>, offset: u64, count: usize) -> Result<usize> {
        let blob = Path::new(&self.dir).join(blobid);
        let file = OpenOptions::new()
            .read(true)
            .open(&blob)
            .expect("open local blob file failed");
        let fd = file.as_raw_fd();

        debug!("local blob file reading: offset={}, size={}", offset, count);
        buf.resize(count, 0u8);
        let len = uio::pread(fd, buf, offset as i64).map_err(|_| Error::last_os_error())?;
        debug!("local blob file read {} bytes", len);

        Ok(len)
    }

    fn write(&self, _blobid: &str, _buf: &[u8], _offset: u64) -> Result<usize> {
        unimplemented!("write operation not supported with localfs");
    }

    fn close(&mut self) {}
}

impl BlobBackendUploader for LocalFs {
    type Reader = std::fs::File;

    fn upload(
        &self,
        blobid: &str,
        mut reader: std::fs::File,
        _size: usize,
        _callback: fn((usize, usize)),
    ) -> Result<usize> {
        let blob = Path::new(&self.dir).join(blobid);

        let mut w = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&blob)?;

        let len = io::copy(&mut reader, &mut w)?;
        Ok(len as usize)
    }
}
