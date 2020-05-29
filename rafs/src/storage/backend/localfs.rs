// Copyright 2020 Alibaba Cloud. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be
// found in the LICENSE file.

use nix::sys::uio;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Error, Result};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::RwLock;

use crate::storage::backend::request::ReqErr;
use crate::storage::backend::{BlobBackend, BlobBackendUploader};

#[derive(Debug)]
pub struct LocalFs {
    // directory to blob files
    dir: String,
    // blobid-File map
    file_table: RwLock<HashMap<String, File>>,
}

pub fn new<S: std::hash::BuildHasher>(config: &HashMap<String, String, S>) -> Result<LocalFs> {
    let dir = config
        .get("dir")
        .ok_or_else(|| ReqErr::inv_input("dir required"))?;

    fs::create_dir_all(dir)?;

    Ok(LocalFs {
        dir: (*dir).to_owned(),
        file_table: RwLock::new(HashMap::new()),
    })
}

impl LocalFs {
    fn get_blob_fd(&self, blob_id: &str) -> Result<RawFd> {
        if let Some(file) = self.file_table.read().unwrap().get(blob_id) {
            return Ok(file.as_raw_fd());
        }

        let mut file_table = self.file_table.write().unwrap();
        let blob_file_path = Path::new(&self.dir).join(blob_id);
        let file = OpenOptions::new().read(true).open(&blob_file_path)?;
        let fd = file.as_raw_fd();
        file_table.insert(blob_id.to_string(), file);
        Ok(fd)
    }
}

impl BlobBackend for LocalFs {
    fn read(&self, blobid: &str, buf: &mut Vec<u8>, offset: u64, count: usize) -> Result<usize> {
        let fd = self.get_blob_fd(blobid)?;

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
        if let Some(parent) = blob.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut w = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&blob)
            .map_err(|e| {
                error!("localfs update: open failed {:?}", e);
                e
            })?;
        let len = io::copy(&mut reader, &mut w)?;
        Ok(len as usize)
    }
}
