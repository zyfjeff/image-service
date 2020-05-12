// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::storage::backend::*;
use crate::storage::cache::*;

use serde::Deserialize;

use std::collections::HashMap;
use std::fs::File;
use std::io::{Error, Result};

// storage backend config
#[derive(Default, Clone, Deserialize)]
pub struct Config {
    pub backend: BackendConfig,
    pub cache: CacheConfig,
}

#[derive(Default, Clone, Deserialize)]
pub struct BackendConfig {
    #[serde(rename = "type")]
    pub backend_type: String,
    #[serde(rename = "config")]
    pub backend_config: HashMap<String, String>,
}

#[derive(Default, Clone, Deserialize)]
pub struct CacheConfig {
    #[serde(default, rename = "type")]
    pub cache_type: String,
    #[serde(default, rename = "config")]
    pub cache_config: HashMap<String, String>,
}

pub fn new_backend(config: &BackendConfig) -> Result<Box<dyn BlobBackend + Send + Sync>> {
    match config.backend_type.as_str() {
        "oss" => {
            Ok(Box::new(oss::new(&config.backend_config)?) as Box<dyn BlobBackend + Send + Sync>)
        }
        "registry" => {
            Ok(Box::new(registry::new(&config.backend_config)?)
                as Box<dyn BlobBackend + Send + Sync>)
        }
        _ => {
            error!("unsupported backend type {}", config.backend_type);
            Err(Error::from_raw_os_error(libc::EINVAL))
        }
    }
}

pub fn new_rw_layer(config: &Config) -> Result<Box<dyn RafsCache + Send + Sync>> {
    let backend = new_backend(&config.backend)?;
    match config.cache.cache_type.as_str() {
        "blobcache" => Ok(
            Box::new(blobcache::new(&config.cache.cache_config, backend)?)
                as Box<dyn RafsCache + Send + Sync>,
        ),
        _ => Ok(Box::new(dummycache::new(backend)?) as Box<dyn RafsCache + Send + Sync>),
    }
}

pub fn new_uploader(config: &BackendConfig) -> Result<Box<dyn BlobBackendUploader<Reader = File>>> {
    match config.backend_type.as_str() {
        "oss" => {
            let backend = oss::new(&config.backend_config)?;
            Ok(Box::new(backend) as Box<dyn BlobBackendUploader<Reader = File>>)
        }
        "registry" => {
            let backend = registry::new(&config.backend_config)?;
            Ok(Box::new(backend) as Box<dyn BlobBackendUploader<Reader = File>>)
        }
        _ => {
            error!("unsupported backend type {}", config.backend_type);
            Err(Error::from_raw_os_error(libc::EINVAL))
        }
    }
}
