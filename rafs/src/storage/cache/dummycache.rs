// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::Arc;

use vm_memory::VolatileSlice;

use crate::metadata::RafsChunkInfo;
use crate::metadata::RafsSuperMeta;
use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;

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

    fn read(
        &self,
        blob_id: &str,
        blk: Arc<dyn RafsChunkInfo>,
        blksize: u32,
        mut decompressed: &mut Vec<u8>,
    ) -> Result<()> {
        decompressed.resize(blk.compress_size() as usize, 0u8);
        self.backend
            .read(blob_id, &mut decompressed, blk.blob_compress_offset())?;

        if blk.is_compressed() {
            let _decompressed = &utils::compress::decompress(decompressed.as_slice(), blksize)?;
            decompressed.resize(_decompressed.len() as usize, 0u8);
            decompressed.copy_from_slice(_decompressed);
        }

        Ok(())
    }

    fn readv(&self, blob_id: &str, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        self.backend.readv(blob_id, bufs, offset)
    }

    fn write(&self, blob_id: &str, blk: Arc<dyn RafsChunkInfo>, buf: &[u8]) -> Result<usize> {
        self.backend.write(blob_id, buf, blk.blob_compress_offset())
    }

    fn release(&mut self) {
        self.backend.close();
    }
}

pub fn new(backend: Box<dyn BlobBackend + Sync + Send>) -> Result<DummyCache> {
    Ok(DummyCache { backend })
}
