// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(dead_code)]
pub mod request;

#[allow(dead_code)]
pub mod dummy;

#[allow(dead_code)]
pub mod oss;

#[allow(dead_code)]
pub mod registry;

use std::collections::HashMap;
use std::fs::File;
use std::io::{Error, Read, Result};

// Rafs blob backend API
pub trait BlobBackend {
    // Initialize the blob backend
    // Each backend should define its own config type
    fn init(&mut self, config: HashMap<&str, &str>) -> Result<()>;

    // Read a range of data from blob into the provided slice
    fn read(&self, blobid: &str, buf: &mut Vec<u8>, offset: u64, count: usize) -> Result<usize>;

    // Write a range of data to blob from the provided slice
    fn write(&self, blobid: &str, buf: &Vec<u8>, offset: u64) -> Result<usize>;

    // Close a backend
    fn close(&mut self);
}

// Rafs blob backend upload API
pub trait BlobBackendUploader {
    type Reader: Read + Send + 'static;

    fn upload(
        &self,
        blobid: &str,
        source: Self::Reader,
        size: usize,
        callback: fn((usize, usize)),
    ) -> Result<usize>;
}

impl dyn BlobBackend {
    pub fn parse_config(conf: &str) -> HashMap<&str, &str> {
        let mut config = HashMap::new();
        let conf: Vec<_> = conf.split(",").collect();
        for pairs in conf {
            let pair: Vec<_> = pairs.split("=").collect();
            if pair.len() == 2 {
                config.insert(pair[0], pair[1]);
            }
        }
        config
    }
    pub fn map_type(backend_type: &str) -> Result<Box<dyn BlobBackend + Send + Sync>> {
        match backend_type {
            "oss" => Ok(Box::new(oss::new()) as Box<dyn BlobBackend + Send + Sync>),
            "registry" => Ok(Box::new(registry::new()) as Box<dyn BlobBackend + Send + Sync>),
            _ => {
                error!("unsupported backend type {}", backend_type);
                Err(Error::from_raw_os_error(libc::EINVAL))
            }
        }
    }
    pub fn map_uploader_type(
        backend_type: &str,
        config: HashMap<&str, &str>,
    ) -> Result<Box<dyn BlobBackendUploader<Reader = File>>> {
        match backend_type {
            "oss" => {
                let mut backend = oss::new();
                backend.init(config)?;
                Ok(Box::new(backend) as Box<dyn BlobBackendUploader<Reader = File>>)
            }
            "registry" => {
                let mut backend = registry::new();
                backend.init(config)?;
                Ok(Box::new(backend) as Box<dyn BlobBackendUploader<Reader = File>>)
            }
            _ => {
                error!("unsupported backend type {}", backend_type);
                Err(Error::from_raw_os_error(libc::EINVAL))
            }
        }
    }
}
