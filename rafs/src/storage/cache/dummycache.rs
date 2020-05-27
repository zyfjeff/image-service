// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be
// found in the LICENSE file.

use crate::fs::RafsBlk;
use crate::layout::RafsSuperBlockInfo;
use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;
use crate::storage::device::RafsBuffer;
use std::io::{Error, Result};

pub struct DummyCache {
    pub backend: Box<dyn BlobBackend + Sync + Send>,
}

impl DummyCache {
    pub fn new(backend: Box<dyn BlobBackend + Sync + Send>) -> DummyCache {
        DummyCache { backend }
    }
}

impl RafsCache for DummyCache {
    fn has(&self, _blk: &RafsBlk) -> bool {
        true
    }

    fn init(&mut self, _sb_info: &RafsSuperBlockInfo) -> Result<()> {
        Ok(())
    }

    fn evict(&self, _blk: &RafsBlk) -> Result<()> {
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }

    fn read(&self, blk: &RafsBlk) -> Result<RafsBuffer> {
        let mut buf = Vec::new();
        let len = self
            .backend
            .read(&blk.blob_id, &mut buf, blk.blob_offset, blk.compr_size)?;
        if len != blk.compr_size {
            return Err(Error::from_raw_os_error(libc::EIO));
        }
        Ok(RafsBuffer::new_compressed(buf))
    }

    fn write(&self, blk: &RafsBlk, buf: &[u8]) -> Result<usize> {
        self.backend.write(&blk.blob_id, buf, blk.blob_offset)
    }

    fn compressed(&self) -> bool {
        true
    }

    fn release(&mut self) {
        self.backend.close();
    }
}

pub fn new(backend: Box<dyn BlobBackend + Sync + Send>) -> Result<DummyCache> {
    Ok(DummyCache { backend })
}
