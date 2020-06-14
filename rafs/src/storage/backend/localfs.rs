// Copyright 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Error, Result};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::RwLock;

use nix::sys::uio;
use vm_memory::VolatileSlice;

use crate::storage::backend::ReqErr;
use crate::storage::backend::{BlobBackend, BlobBackendUploader};
use crate::storage::utils::{readahead, readv};

#[derive(Debug, Default)]
pub struct LocalFs {
    // the specified blob file
    blob_file: String,
    // directory to blob files
    dir: String,
    // readahead blob file
    readahead: bool,
    // blobid-File map
    file_table: RwLock<HashMap<String, File>>,
}

pub fn new<S: std::hash::BuildHasher>(config: &HashMap<String, String, S>) -> Result<LocalFs> {
    let readahead = config
        .get("readahead")
        .map(|r| r == "true")
        .unwrap_or(false);

    match (config.get("blob_file"), config.get("dir")) {
        (Some(blob_file), _) => Ok(LocalFs {
            blob_file: String::from(blob_file),
            readahead,
            file_table: RwLock::new(HashMap::new()),
            ..Default::default()
        }),

        (_, Some(dir)) => Ok(LocalFs {
            dir: String::from(dir),
            readahead,
            file_table: RwLock::new(HashMap::new()),
            ..Default::default()
        }),

        _ => Err(ReqErr::inv_input("blob file or dir is required")),
    }
}

impl LocalFs {
    fn get_blob_fd(&self, blob_id: &str) -> Result<RawFd> {
        let (id, blob_file_path) = if self.use_blob_file() {
            (
                self.blob_file.as_str(),
                Path::new(&self.blob_file).to_path_buf(),
            )
        } else {
            (blob_id, Path::new(&self.dir).join(blob_id))
        };

        // Don't expect poisoned lock here.
        if let Some(file) = self.file_table.read().unwrap().get(id) {
            return Ok(file.as_raw_fd());
        }

        let file = OpenOptions::new().read(true).open(&blob_file_path)?;
        let metadata = file.metadata();
        let fd = file.as_raw_fd();

        // Don't expect poisoned lock here.
        let mut table_guard = self.file_table.write().unwrap();
        // Double check whether someone else inserted the file concurrently.
        if let Some(other) = table_guard.get(id) {
            return Ok(other.as_raw_fd());
        } else {
            table_guard.insert(id.to_string(), file);
            drop(table_guard);
        }

        if self.readahead {
            if let Ok(md) = metadata {
                readahead(fd, 0, md.len());
            }
        }

        Ok(fd)
    }

    fn use_blob_file(&self) -> bool {
        !self.blob_file.is_empty()
    }
}

impl BlobBackend for LocalFs {
    fn read(&self, blob_id: &str, buf: &mut [u8], offset: u64) -> Result<usize> {
        let fd = self.get_blob_fd(blob_id)?;

        debug!(
            "local blob file reading: offset={}, size={}",
            offset,
            buf.len()
        );
        let len = uio::pread(fd, buf, offset as i64).map_err(|_| Error::last_os_error())?;
        debug!("local blob file read {} bytes", len);

        Ok(len)
    }

    fn readv(
        &self,
        blob_id: &str,
        bufs: &[VolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> Result<usize> {
        let fd = self.get_blob_fd(blob_id)?;

        readv(fd, bufs, offset, max_size)
    }

    fn write(&self, _blob_id: &str, _buf: &[u8], _offset: u64) -> Result<usize> {
        unimplemented!("write operation not supported with localfs");
    }

    fn close(&mut self) {}
}

impl BlobBackendUploader for LocalFs {
    type Reader = std::fs::File;

    fn upload(
        &self,
        blob_id: &str,
        mut reader: std::fs::File,
        _size: usize,
        _callback: fn((usize, usize)),
    ) -> Result<usize> {
        let blob = if self.use_blob_file() {
            Path::new(&self.blob_file).to_path_buf()
        } else {
            Path::new(&self.dir).join(blob_id)
        };

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

        io::copy(&mut reader, &mut w).map(|sz| sz as usize)
    }
}
