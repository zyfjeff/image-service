// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::{Deserialize, Serialize};
use std::cmp;
use std::collections::HashMap;
use std::io;
use std::io::{Error, Read, Write};

use fuse_rs::api::filesystem::{ZeroCopyReader, ZeroCopyWriter};
use fuse_rs::transport::FileReadWriteVolatile;
use vm_memory::VolatileSlice;

use crate::fs::RafsBlk;
use crate::storage::backend::*;

use utils;

static ZEROS: &'static [u8] = &[0u8; 4096]; // why 4096? volatile slice default size, unfortunately

// A rafs storage device config
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Config {
    // backend type
    pub backend_type: String,
    // Storage path, can be a directory or a URL to some remote storage
    pub endpoint: String,
    // OSS bucket name
    pub bucket_name: String,
    // optional auth info used to access the storage
    pub access_key_id: String,
    pub access_key_secret: String,
}

impl Config {
    pub fn new() -> Config {
        Config {
            ..Default::default()
        }
    }

    pub fn hashmap(&self) -> HashMap<&str, &str> {
        let mut hmap: HashMap<&str, &str> = HashMap::new();
        hmap.insert("endpoint", &self.endpoint);
        hmap.insert("access_key_id", &self.access_key_id);
        hmap.insert("access_key_secret", &self.access_key_secret);
        hmap.insert("bucket_name", &self.bucket_name);
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
            debug!("reading bio desc {:?}", bio);
            count += w.write_from(&mut f, bio.size, bio.offset as u64)?;
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
    buf: Vec<u8>,
}

impl<'a, B: BlobBackend> RafsBioDevice<'a, B> {
    fn new(bio: &'a RafsBio<'a>, b: &'a RafsDevice<B>) -> io::Result<Self> {
        // FIXME: make sure bio is valid
        Ok(RafsBioDevice {
            bio: bio,
            dev: b,
            buf: Vec::new(),
        })
    }

    fn blob_offset(&self) -> u64 {
        let blkinfo = &self.bio.blkinfo;
        blkinfo.blob_offset + self.bio.offset as u64
    }
}

impl<B: BlobBackend> FileReadWriteVolatile for RafsBioDevice<'_, B> {
    fn read_volatile(&mut self, slice: VolatileSlice) -> Result<usize, Error> {
        // Skip because we don't really use it
        Ok(slice.len())
    }

    fn write_volatile(&mut self, slice: VolatileSlice) -> Result<usize, Error> {
        // Skip because we don't really use it
        Ok(slice.len())
    }

    fn read_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize, Error> {
        if self.buf.len() == 0 {
            let mut buf = Vec::new();
            let len = self.dev.b.read(
                &self.bio.blkinfo.blob_id,
                &mut buf,
                self.bio.blkinfo.blob_offset,
                self.bio.blkinfo.compr_size,
            )?;
            debug_assert_eq!(len, buf.len());
            self.buf = utils::decompress(&buf, self.bio.blksize)?;
        }

        let count = cmp::min(
            cmp::min(
                self.bio.offset as usize + self.bio.size - offset as usize,
                slice.len(),
            ),
            self.buf.len() - offset as usize,
        );
        slice.copy_from(&self.buf[offset as usize..offset as usize + count]);
        Ok(count)
    }

    // The default read_vectored_at_volatile only read to the first slice, so we have to overload it.
    fn read_vectored_at_volatile(
        &mut self,
        bufs: &[VolatileSlice],
        offset: u64,
    ) -> Result<usize, Error> {
        let mut f_offset: u64 = offset;
        let mut count: usize = 0;
        if self.bio.blkinfo.compr_size == 0 {
            return self.fill_hole(bufs);
        }
        for buf in bufs.iter() {
            let res = self.read_at_volatile(*buf, f_offset)?;
            count += res;
            f_offset += res as u64;
            if res == 0
                || count >= self.bio.size
                || f_offset >= self.bio.offset as u64 + self.bio.size as u64
            {
                break;
            }
        }
        Ok(count)
    }

    fn write_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize, Error> {
        let mut buf = vec![0u8; slice.len()];
        slice.copy_to(&mut buf);
        let compressed = utils::compress(&buf)?;
        self.dev
            .b
            .write(&self.bio.blkinfo.blob_id, &compressed, offset)?;
        // Need to return slice length because that's what upper layer asks to write
        Ok(slice.len())
    }
}

impl<B: BlobBackend> RafsBioDevice<'_, B> {
    fn fill_hole(&self, bufs: &[VolatileSlice]) -> Result<usize, Error> {
        let mut count: usize = 0;
        let mut remain: usize = self.bio.size;
        for &buf in bufs.iter() {
            let cnt = cmp::min(remain, buf.len());
            buf.copy_from(&ZEROS[ZEROS.len() - cnt..]);
            count += cnt;
            remain -= cnt;
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

impl RafsBioDesc<'_> {
    pub fn new() -> Self {
        RafsBioDesc {
            ..Default::default()
        }
    }
}

// Rafs blob IO info
#[derive(Copy, Clone, Debug)]
pub struct RafsBio<'a> {
    pub blkinfo: &'a RafsBlk,
    // offset within the block
    pub offset: u32,
    // size of data to transfer
    pub size: usize,
    // block size to read in one shot
    pub blksize: u32,
}

impl<'a> RafsBio<'a> {
    pub fn new(b: &'a RafsBlk, offset: u32, size: usize, blksize: u32) -> Self {
        RafsBio {
            blkinfo: b,
            offset: offset,
            size: size,
            blksize: blksize,
        }
    }
}
