// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::sync::Arc;

use vm_memory::VolatileSlice;

use crate::metadata::digest;
use crate::metadata::layout::OndiskBlobTableEntry;
use crate::metadata::{RafsChunkInfo, RafsSuperMeta};
use crate::storage::backend::BlobBackend;
use crate::storage::compress;
use crate::storage::device::RafsBio;
use crate::storage::utils::digest_check;

use nydus_utils::eio;

pub mod blobcache;
pub mod dummycache;

#[derive(Default, Clone)]
struct MergedBackendRequest {
    // Chunks that are continuous to each other.
    pub chunks: Vec<Arc<dyn RafsChunkInfo>>,
    pub blob_offset: u64,
    pub blob_size: u32,
    pub blob_id: String,
}

impl<'a> MergedBackendRequest {
    fn reset(&mut self) {
        self.blob_offset = 0;
        self.blob_size = 0;
        self.blob_id.truncate(0);
        self.chunks.clear();
    }

    fn merge_begin(&mut self, first_cki: Arc<dyn RafsChunkInfo>, blob_id: &str) {
        self.blob_offset = first_cki.compress_offset();
        self.blob_size = first_cki.compress_size();
        self.chunks.push(first_cki);
        self.blob_id = String::from(blob_id);
    }

    fn merge_one_chunk(&mut self, cki: Arc<dyn RafsChunkInfo>) {
        self.blob_size += cki.compress_size();
        self.chunks.push(cki);
    }
}

fn is_chunk_continuous(prior: &RafsBio, cur: &RafsBio) -> bool {
    let prior_cki = &prior.chunkinfo;
    let cur_cki = &cur.chunkinfo;

    let prior_end = prior_cki.compress_offset() + prior_cki.compress_size() as u64;
    let cur_offset = cur_cki.compress_offset();

    if prior_end == cur_offset && prior.blob_id == cur.blob_id {
        return true;
    }

    false
}

fn generate_merged_requests(
    bios: &mut [RafsBio],
    tx: &mut spmc::Sender<MergedBackendRequest>,
    merging_size: usize,
) {
    bios.sort_by_key(|entry| entry.chunkinfo.compress_offset());
    let mut index: usize = 1;
    if bios.is_empty() {
        return;
    }
    let first_cki = &bios[0].chunkinfo;
    let mut mr = MergedBackendRequest::default();
    mr.merge_begin(Arc::clone(first_cki), &bios[0].blob_id);

    if bios.len() == 1 {
        tx.send(mr).unwrap();
        return;
    }

    loop {
        let cki = &bios[index].chunkinfo;
        let prior_bio = &bios[index - 1];
        let cur_bio = &bios[index];

        // Even more chunks are continuous, still split them per as certain size.
        // So that to achieve an appropriate request size to backend.
        if is_chunk_continuous(prior_bio, cur_bio) && mr.blob_size <= merging_size as u32 {
            mr.merge_one_chunk(Arc::clone(&cki));
        } else {
            // New a MR if a non-continuous chunk is met.
            tx.send(mr.clone()).unwrap();
            mr.reset();
            mr.merge_begin(Arc::clone(&cki), &cur_bio.blob_id);
        }

        index += 1;

        if index >= bios.len() {
            tx.send(mr).unwrap();
            break;
        }
    }
}

#[derive(Clone, Default, Deserialize)]
pub struct PrefetchWorker {
    pub threads_count: usize,
    pub merging_size: usize,
}

pub trait RafsCache {
    /// Whether has block data
    fn has(&self, blk: Arc<dyn RafsChunkInfo>) -> bool;

    /// Do init after super block loaded
    fn init(&self, sb_info: &RafsSuperMeta, blobs: &[OndiskBlobTableEntry]) -> Result<()>;

    /// Evict block data
    fn evict(&self, blk: Arc<dyn RafsChunkInfo>) -> Result<()>;

    /// Flush cache
    fn flush(&self) -> Result<()>;

    /// Read a chunk data through cache, always used in decompressed cache
    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize>;

    /// Write a chunk data through cache
    fn write(&self, blob_id: &str, blk: &dyn RafsChunkInfo, buf: &[u8]) -> Result<usize>;

    fn prefetch(&self, bio: &mut [RafsBio]) -> Result<usize>;

    /// Release cache
    fn release(&self);

    fn backend(&self) -> &(dyn BlobBackend + Sync + Send);

    /// 1. Read a chunk from backend
    /// 2. Decompress chunk if necessary
    /// 3. Validate chunk digest if necessary
    fn read_by_chunk<'a>(
        &self,
        blob_id: &str,
        chunk: &dyn RafsChunkInfo,
        src_buf: &'a mut [u8],
        mut dst_buf: &'a mut [u8],
        digester: Option<digest::Algorithm>,
    ) -> Result<usize> {
        let c_offset = chunk.compress_offset();
        let d_size = chunk.decompress_size() as usize;

        self.backend().read(blob_id, src_buf, c_offset)?;
        if dst_buf.is_empty() {
            dst_buf = src_buf;
        } else {
            compress::decompress(src_buf, dst_buf)?;
        }

        if dst_buf.len() != d_size {
            return Err(eio!(format!(
                "invalid chunk data, expected size: {} != {}",
                d_size,
                dst_buf.len(),
            )));
        }

        if let Some(digester) = digester {
            if !digest_check(dst_buf, &chunk.block_id(), digester) {
                return Err(eio!(format!(
                    "invalid chunk data, expected digest: {}",
                    chunk.block_id()
                )));
            }
        }

        Ok(dst_buf.len())
    }
}
