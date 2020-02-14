// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::io::{Read, Result, Write};

use fuse::filesystem::{ZeroCopyReader, ZeroCopyWriter};

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

impl<B: BlobBackend> RafsDevice<B> {
    fn init(&mut self) -> Result<()> {
        self.b.init(self.c.hashmap())
    }

    fn close(&mut self) -> Result<()> {
        self.b.close();
        Ok(())
    }

    // Read a range of data from blob into the provided writer
    fn read_to<W: Write + ZeroCopyWriter>(&self, _w: W, _bio: RafsBioDesc) -> Result<usize> {
        Ok(0)
    }

    // Write a range of data to blob from the provided reader
    fn write_from<R: Read + ZeroCopyReader>(&self, _r: R, _bio: RafsBioDesc) -> Result<usize> {
        Ok(0)
    }
}

// Rafs device blob IO descriptor
pub struct RafsBioDesc<'a> {
    // Blob IO flags
    bi_flags: u32,
    // Totol IO size to be performed
    bi_size: usize,
    // Array of blob IO info. Corresponding data should
    // be read from (written to) IO stream sequencially
    bi_vec: Vec<RafsBio<'a>>,
}

// Rafs blob IO info
pub struct RafsBio<'a> {
    pub blkinfo: RafsBlk<'a>,
    // offset within the block
    pub offset: u32,
    // size of data to transfer
    pub size: usize,
}

// Rafs block
pub struct RafsBlk<'a> {
    // block hash
    pub block_id: &'a str,
    // blob containing the block
    pub blob_id: &'a str,
    // position of the block within the file
    pub file_pos: u64,
    // size of the block, uncompressed
    pub uncompr_bsize: usize,
    // valid data length of the block, uncompressed
    // zero means hole block
    pub len: usize,
    // offset of the block within the blob
    pub blob_offset: u64,
    // size of the block, compressed
    pub compr_size: usize,
}
