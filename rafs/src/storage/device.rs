// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::io;
use std::io::{Error, Read, Write};

use vm_memory::VolatileSlice;

use fuse::filesystem::{ZeroCopyReader, ZeroCopyWriter};
use vhost_rs::descriptor_utils::FileReadWriteVolatile;

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
    pub fn init(&mut self) -> io::Result<()> {
        self.b.init(self.c.hashmap())
    }

    pub fn close(&mut self) -> io::Result<()> {
        self.b.close();
        Ok(())
    }

    // Read a range of data from blob into the provided writer
    pub fn read_to<W: Write + ZeroCopyWriter>(
        &self,
        mut w: W,
        desc: RafsBioDesc,
    ) -> io::Result<usize> {
        let mut count: usize = 0;
        for bio in desc.bi_vec.iter() {
            let mut f = RafsBioDevice::new(bio, &self)?;
            let offset = bio.blkinfo.blob_offset + bio.offset as u64;
            count += w.write_from(&mut f, bio.size, offset)?;
        }
        Ok(count)
    }

    // Write a range of data to blob from the provided reader
    pub fn write_from<R: Read + ZeroCopyReader>(
        &self,
        mut r: R,
        desc: RafsBioDesc,
    ) -> io::Result<usize> {
        let mut count: usize = 0;
        for bio in desc.bi_vec.iter() {
            let mut f = RafsBioDevice::new(bio, &self)?;
            let offset = bio.blkinfo.blob_offset + bio.offset as u64;
            count += r.read_to(&mut f, bio.size, offset)?;
        }
        Ok(count)
    }
}

struct RafsBioDevice<'a, B: BlobBackend> {
    bio: &'a RafsBio<'a>,
    dev: &'a RafsDevice<B>,
}

impl<'a, B: BlobBackend> RafsBioDevice<'a, B> {
    fn new(bio: &'a RafsBio<'a>, b: &'a RafsDevice<B>) -> io::Result<Self> {
        // FIXME: make sure bio is valid
        Ok(RafsBioDevice { bio: bio, dev: b })
    }

    fn blob_offset(&self) -> u64 {
        let blkinfo = &self.bio.blkinfo;
        blkinfo.blob_offset + self.bio.offset as u64
    }
}

impl<B: BlobBackend> FileReadWriteVolatile for RafsBioDevice<'_, B> {
    fn read_volatile(&mut self, slice: VolatileSlice) -> Result<usize, Error> {
        Ok(slice.len())
    }

    fn write_volatile(&mut self, slice: VolatileSlice) -> Result<usize, Error> {
        Ok(slice.len())
    }

    fn read_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize, Error> {
        let mut buf = vec![0u8; self.bio.blkinfo.compr_size];
        self.dev
            .b
            .read(self.bio.blkinfo.blob_id, &mut buf, offset)?;
        // TODO: add decompression
        slice.copy_from(&buf[self.bio.offset as usize..self.bio.offset as usize + self.bio.size]);
        let mut count = self.bio.offset as usize + self.bio.size - self.bio.offset as usize;
        if slice.len() < count {
            count = slice.len()
        }
        Ok(count)
    }

    fn write_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize, Error> {
        let mut buf = vec![0u8; slice.len()];
        // TODO: add compression
        slice.copy_to(&mut buf);
        self.dev.b.write(self.bio.blkinfo.blob_id, &buf, offset)?;
        slice.copy_from(&buf[self.bio.offset as usize..self.bio.offset as usize + self.bio.size]);
        let mut count = self.bio.offset as usize + self.bio.size - self.bio.offset as usize;
        if slice.len() < count {
            count = slice.len()
        }
        Ok(count)
    }
}

// Rafs device blob IO descriptor
#[derive(Default, Debug)]
pub struct RafsBioDesc<'a> {
    // Blob IO flags
    pub bi_flags: u32,
    // Totol IO size to be performed
    pub bi_size: usize,
    // Array of blob IO info. Corresponding data should
    // be read from (written to) IO stream sequencially
    pub bi_vec: Vec<RafsBio<'a>>,
}

// Rafs blob IO info
#[derive(Copy, Clone, Default, Debug)]
pub struct RafsBio<'a> {
    pub blkinfo: RafsBlk<'a>,
    // offset within the block
    pub offset: u32,
    // size of data to transfer
    pub size: usize,
}

// Rafs block
#[derive(Copy, Clone, Default, Debug)]
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
