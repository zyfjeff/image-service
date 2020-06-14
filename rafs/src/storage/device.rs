// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::cmp;
use std::io;
use std::io::Error;
use std::sync::Arc;

use fuse_rs::api::filesystem::{ZeroCopyReader, ZeroCopyWriter};
use fuse_rs::transport::FileReadWriteVolatile;
use vm_memory::VolatileSlice;

use crate::metadata::RafsChunkInfo;
use crate::metadata::RafsSuperMeta;
use crate::storage::cache::RafsCache;
use crate::storage::compress;
use crate::storage::factory;

static ZEROS: &[u8] = &[0u8; 4096]; // why 4096? volatile slice default size, unfortunately

// A rafs storage device
pub struct RafsDevice {
    rw_layer: Box<dyn RafsCache + Send + Sync>,
}

impl RafsDevice {
    pub fn new(config: factory::Config) -> io::Result<RafsDevice> {
        Ok(RafsDevice {
            rw_layer: factory::new_rw_layer(&config)?,
        })
    }

    pub fn init(&mut self, sb_meta: &RafsSuperMeta) -> io::Result<()> {
        self.rw_layer.init(sb_meta)
    }

    pub fn close(&mut self) -> io::Result<()> {
        self.rw_layer.release();
        Ok(())
    }

    /// Read a range of data from blob into the provided writer
    pub fn read_to(&self, w: &mut dyn ZeroCopyWriter, desc: RafsBioDesc) -> io::Result<usize> {
        let mut count: usize = 0;
        for bio in desc.bi_vec.iter() {
            let mut f = RafsBioDevice::new(bio, &self)?;
            count += w.write_from(&mut f, bio.size, bio.offset as u64)?;
        }
        Ok(count)
    }

    /// Write a range of data to blob from the provided reader
    pub fn write_from(&self, r: &mut dyn ZeroCopyReader, desc: RafsBioDesc) -> io::Result<usize> {
        let mut count: usize = 0;
        for bio in desc.bi_vec.iter() {
            let mut f = RafsBioDevice::new(bio, &self)?;
            let offset = bio.chunkinfo.blob_compress_offset() + bio.offset as u64;
            count += r.read_to(&mut f, bio.size, offset)?;
        }
        Ok(count)
    }
}

struct RafsBioDevice<'a> {
    bio: &'a RafsBio,
    dev: &'a RafsDevice,
    buf: Vec<u8>,
}

impl<'a> RafsBioDevice<'a> {
    fn new(bio: &'a RafsBio, b: &'a RafsDevice) -> io::Result<Self> {
        // FIXME: make sure bio is valid
        Ok(RafsBioDevice {
            bio,
            dev: b,
            buf: Vec::new(),
        })
    }

    fn blob_offset(&self) -> u64 {
        self.bio.chunkinfo.blob_compress_offset() + self.bio.offset as u64
    }
}

impl FileReadWriteVolatile for RafsBioDevice<'_> {
    fn read_volatile(&mut self, slice: VolatileSlice) -> Result<usize, Error> {
        // Skip because we don't really use it
        Ok(slice.len())
    }

    fn write_volatile(&mut self, slice: VolatileSlice) -> Result<usize, Error> {
        // Skip because we don't really use it
        Ok(slice.len())
    }

    fn read_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize, Error> {
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
        if self.bio.chunkinfo.compress_size() == 0 {
            return self.fill_hole(bufs);
        }

        self.dev.rw_layer.read(&self.bio, bufs, offset)
    }

    fn write_at_volatile(&mut self, slice: VolatileSlice, _offset: u64) -> Result<usize, Error> {
        let mut buf = vec![0u8; slice.len()];
        slice.copy_to(&mut buf);
        let wbuf = if self.bio.chunkinfo.is_compressed() {
            compress::compress(&buf, self.bio.compressor)?
        } else {
            Cow::Owned(buf)
        };
        self.dev
            .rw_layer
            .write(&self.bio.blob_id, self.bio.chunkinfo.clone(), &wbuf)?;
        // Need to return slice length because that's what upper layer asks to write
        Ok(slice.len())
    }
}

impl RafsBioDevice<'_> {
    fn fill_hole(&self, bufs: &[VolatileSlice]) -> Result<usize, Error> {
        let mut count: usize = 0;
        let mut remain: usize = self.bio.size;
        for &buf in bufs.iter() {
            let mut total = cmp::min(remain, buf.len());
            while total > 0 {
                let cnt = cmp::min(total, ZEROS.len());
                buf.copy_from(&ZEROS[ZEROS.len() - cnt..]);
                count += cnt;
                remain -= cnt;
                total -= cnt;
            }
        }
        Ok(count)
    }
}

// Rafs device blob IO descriptor
#[derive(Default)]
pub struct RafsBioDesc {
    // Blob IO flags
    pub bi_flags: u32,
    // Totol IO size to be performed
    pub bi_size: usize,
    // Array of blob IO info. Corresponding data should be read from/write to IO stream sequentially
    pub bi_vec: Vec<RafsBio>,
}

impl RafsBioDesc {
    pub fn new() -> Self {
        RafsBioDesc {
            ..Default::default()
        }
    }
}

// Rafs blob IO info
pub struct RafsBio {
    /// reference to the chunk
    pub chunkinfo: Arc<dyn RafsChunkInfo>,
    /// blob id of chunk
    pub blob_id: String,
    /// compression algorithm of chunk
    pub compressor: compress::Algorithm,
    /// offset within the chunk
    pub offset: u32,
    /// size within the chunk
    pub size: usize,
    /// block size to read in one shot
    pub blksize: u32,
}

impl RafsBio {
    pub fn new(
        chunkinfo: Arc<dyn RafsChunkInfo>,
        blob_id: String,
        compressor: compress::Algorithm,
        offset: u32,
        size: usize,
        blksize: u32,
    ) -> Self {
        RafsBio {
            chunkinfo,
            blob_id,
            compressor,
            offset,
            size,
            blksize,
        }
    }
}
