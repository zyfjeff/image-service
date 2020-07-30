// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::Arc;
use std::thread;

use vm_memory::VolatileSlice;

use crate::metadata::layout::OndiskBlobTableEntry;
use crate::metadata::{RafsChunkInfo, RafsSuperMeta};
use crate::storage::backend::BlobBackend;
use crate::storage::cache::*;
use crate::storage::device::RafsBio;
use crate::storage::factory::CacheConfig;
use crate::storage::utils::{alloc_buf, copyv};

pub struct DummyCache {
    pub backend: Arc<dyn BlobBackend + Sync + Send>,
    validate: bool,
}

impl RafsCache for DummyCache {
    fn backend(&self) -> &(dyn BlobBackend + Sync + Send) {
        self.backend.as_ref()
    }

    fn has(&self, _blk: Arc<dyn RafsChunkInfo>) -> bool {
        true
    }

    fn init(&self, _sb_meta: &RafsSuperMeta, blobs: &[OndiskBlobTableEntry]) -> Result<()> {
        for b in blobs {
            let _ = self.backend.prefetch_blob(
                b.blob_id.as_str(),
                b.readahead_offset,
                b.readahead_size,
            );
        }
        Ok(())
    }

    fn evict(&self, _blk: Arc<dyn RafsChunkInfo>) -> Result<()> {
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }

    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        let blob_id = &bio.blob_id;
        let chunk = &bio.chunkinfo;

        let c_size = chunk.compress_size() as usize;
        let d_size = chunk.decompress_size() as usize;

        let digester = if self.validate {
            Some(bio.digester)
        } else {
            None
        };

        if !chunk.is_compressed() {
            if !self.validate {
                return self.backend.readv(
                    blob_id,
                    bufs,
                    offset + chunk.compress_offset(),
                    bio.size,
                );
            }
            // We need read whole chunk to validate digest.
            let mut src_buf = alloc_buf(c_size);
            self.read_by_chunk(blob_id, chunk.as_ref(), &mut src_buf, &mut [], digester)?;
            return copyv(&src_buf, bufs, offset, bio.size);
        }

        if bufs.len() == 1 && offset == 0 {
            if bufs[0].len() >= c_size as usize {
                // Reuse the destination buffer to received the compressed data.
                let src_buf = unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), c_size) };
                let mut dst_buf = alloc_buf(d_size);
                self.read_by_chunk(
                    blob_id,
                    chunk.as_ref(),
                    src_buf,
                    dst_buf.as_mut_slice(),
                    digester,
                )?;
                return copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size);
            } else {
                // Allocate a buffer to received the compressed data without zeroing
                let mut src_buf = alloc_buf(c_size);
                if bufs[0].len() >= d_size {
                    // Use the destination buffer to received the decompressed data.
                    let dst_buf =
                        unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), d_size) };
                    return Ok(self.read_by_chunk(
                        blob_id,
                        chunk.as_ref(),
                        src_buf.as_mut_slice(),
                        dst_buf,
                        digester,
                    )?);
                }
                let mut dst_buf = alloc_buf(d_size);
                self.read_by_chunk(
                    blob_id,
                    chunk.as_ref(),
                    src_buf.as_mut_slice(),
                    dst_buf.as_mut_slice(),
                    digester,
                )?;
                return copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size);
            }
        }

        let mut src_buf = alloc_buf(c_size);
        let mut dst_buf = alloc_buf(d_size);
        self.read_by_chunk(
            blob_id,
            chunk.as_ref(),
            src_buf.as_mut_slice(),
            dst_buf.as_mut_slice(),
            digester,
        )?;
        copyv(dst_buf.as_mut_slice(), bufs, offset, bio.size)
    }

    /// Prefetch works when blobcache is enabled
    fn prefetch(&self, bios: &mut [RafsBio]) -> Result<usize> {
        let (mut tx, rx) = spmc::channel::<MergedBackendRequest>();
        for num in 0..2 {
            let backend = Arc::clone(&self.backend);
            let rx = rx.clone();
            let _thread = thread::Builder::new()
                .name(format!("prefetch_thread_{}", num))
                .spawn(move || {
                    while let Ok(mr) = rx.recv() {
                        let blob_offset = mr.blob_offset;
                        let blob_size = mr.blob_size;
                        let blob_id = &mr.blob_id;
                        trace!(
                            "Merged req id {} req offset {} size {}",
                            blob_id,
                            blob_offset,
                            blob_size
                        );
                        // Blob id must be unique.
                        // TODO: Currently, request length to backend may span a whole chunk,
                        // Do we need to split it into smaller pieces?
                        if backend
                            .prefetch_blob(blob_id, blob_offset as u32, blob_size)
                            .is_err()
                        {
                            error!(
                                "Readahead from {} for {} bytes failed",
                                blob_offset, blob_size
                            )
                        }
                    }
                    info!("Prefetch thread exits.")
                });
        }

        let mut bios = bios.to_vec();
        let _thread = thread::Builder::new().spawn({
            move || {
                generate_merged_requests(bios.as_mut_slice(), &mut tx);
            }
        });

        Ok(0)
    }

    fn write(&self, blob_id: &str, blk: &dyn RafsChunkInfo, buf: &[u8]) -> Result<usize> {
        self.backend.write(blob_id, buf, blk.compress_offset())
    }

    fn release(&self) {}
}

pub fn new(config: CacheConfig, backend: Arc<dyn BlobBackend + Sync + Send>) -> Result<DummyCache> {
    Ok(DummyCache {
        backend,
        validate: config.cache_validate,
    })
}
