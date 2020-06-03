// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be
// found in the LICENSE file.

use std::io::{Error, Result};
use std::sync::Arc;

use crate::metadata::RafsChunkInfo;
use crate::metadata::RafsSuperMeta;
use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;
use crate::storage::device::RafsBuffer;

pub struct DummyCache {
    pub backend: Box<dyn BlobBackend + Sync + Send>,
}

impl DummyCache {
    pub fn new(backend: Box<dyn BlobBackend + Sync + Send>) -> DummyCache {
        DummyCache { backend }
    }
}

impl RafsCache for DummyCache {
    fn has(&self, _blk: Arc<dyn RafsChunkInfo>) -> bool {
        true
    }

    fn init(&mut self, _sb_meta: &RafsSuperMeta) -> Result<()> {
        Ok(())
    }

    fn evict(&self, _blk: Arc<dyn RafsChunkInfo>) -> Result<()> {
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }

    fn read(&self, blob_id: &str, blk: Arc<dyn RafsChunkInfo>) -> Result<RafsBuffer> {
        let mut buf = Vec::new();
        let len = self.backend.read(
            blob_id,
            &mut buf,
            blk.blob_offset(),
            blk.compress_size() as usize,
        )?;
        if len != blk.compress_size() as usize {
            return Err(Error::from_raw_os_error(libc::EIO));
        }
        Ok(RafsBuffer::new_compressed(buf))
    }

    fn write(&self, blob_id: &str, blk: Arc<dyn RafsChunkInfo>, buf: &[u8]) -> Result<usize> {
        self.backend.write(blob_id, buf, blk.blob_offset())
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
