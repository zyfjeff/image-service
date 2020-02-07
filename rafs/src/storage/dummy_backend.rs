// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::io::{Read, Result, Write};

use vm_memory::VolatileSlice;

use crate::storage::backend::BlobBackend;
use fuse::filesystem::{ZeroCopyReader, ZeroCopyWriter};
use vhost_rs::descriptor_utils::FileReadWriteVolatile;

struct Dummy {}

impl FileReadWriteVolatile for Dummy {
    fn read_volatile(&mut self, _slice: VolatileSlice) -> Result<usize> {
        Ok(0)
    }

    fn write_volatile(&mut self, _slice: VolatileSlice) -> Result<usize> {
        Ok(0)
    }

    fn read_at_volatile(&mut self, _slice: VolatileSlice, _offset: u64) -> Result<usize> {
        Ok(0)
    }

    fn write_at_volatile(&mut self, _slice: VolatileSlice, _offset: u64) -> Result<usize> {
        Ok(0)
    }
}

impl Dummy {
    fn new() -> Dummy {
        Dummy {}
    }
}

impl BlobBackend for Dummy {
    fn init(&self, _config: HashMap<&str, &str>) -> Result<()> {
        Ok(())
    }

    fn read_to<W: Write + ZeroCopyWriter>(
        &self,
        _w: W,
        _blobid: &str,
        _count: usize,
        _offset: u64,
    ) -> Result<usize> {
        Ok(0)
    }

    fn write_from<R: Read + ZeroCopyReader>(
        &self,
        _r: R,
        _blobid: &str,
        _count: usize,
        _offset: u64,
    ) -> Result<usize> {
        Ok(0)
    }

    fn delete(&self, _blobid: &str) -> Result<()> {
        Ok(())
    }
}
