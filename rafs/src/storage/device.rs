// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::io::Result;
use vm_memory::VolatileSlice;

use crate::storage::backend::*;

// A rafs storage device config
#[derive(Default, Clone)]
pub struct Config {
    // backend type
    pub backend_type: BackendType,
    // Storage path, can be a directory or a URL to some remote storage
    pub path: String,
    // optional auth info used to access the storage
    pub id: String,
    pub secret: String,
}

impl Config {
    pub fn new() -> Config {
        Config {
            ..Default::default()
        }
    }

    pub fn hashmap(&self) -> HashMap<&str, &str> {
        let mut hmap: HashMap<&str, &str> = HashMap::new();
        hmap.insert("path", &self.path);
        hmap.insert("id", &self.id);
        hmap.insert("secret", &self.secret);
        hmap
    }
}

// A rafs storage device
pub struct RafsDevice<B: BlobBackend> {
    c: Config,
    b: B,
}

impl<B: BlobBackend> RafsDevice<B> {
    pub fn new(c: Config, b: B) -> Self {
        match c.backend_type {
            _ => RafsDevice { c: c, b: b },
        }
    }
}

impl<B: BlobBackend> RafsStorageDevice for RafsDevice<B> {
    fn init(&mut self) -> Result<()> {
        self.b.init(self.c.hashmap())
    }

    fn close(&mut self) -> Result<()> {
        self.b.close();
        Ok(())
    }
}

pub trait RafsStorageDevice {
    fn init(&mut self) -> Result<()>;
    fn close(&mut self) -> Result<()>;
}

pub struct RafsBio<'a> {
    bi_flags: u32,
    bi_size: usize,
    bi_blksize: usize,
    bi_vec: Vec<RafsBioVec<'a>>,
}

pub struct RafsBioVec<'a> {
    pub blkinfo: RafsBlkInfo,
    pub offset: u32,
    pub buffer: VolatileSlice<'a>,
}

pub struct RafsBlkInfo {}
