// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::Arc;

use vm_memory::VolatileSlice;

use crate::metadata::RafsChunkInfo;
use crate::metadata::RafsSuperMeta;
use crate::storage::backend::BlobBackend;
use crate::storage::cache::{RafsBio, RafsCache};
use crate::storage::utils::copyv;
use nydus_utils::compress;

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

    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        let blob_id = bio.blob_id.as_str();
        let chunk = bio.chunkinfo.clone();

        if chunk.is_compressed() {
            let mut compressed = vec![0u8; chunk.compress_size() as usize];
            self.backend.read(
                blob_id,
                compressed.as_mut_slice(),
                chunk.blob_compress_offset(),
            )?;
            let decompressed = &compress::decompress(&compressed, bio.blksize)?;
            return copyv(&decompressed, bufs, offset);
        }

        self.backend
            .readv(blob_id, bufs, offset + chunk.blob_decompress_offset())
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
