// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use nydus_utils::einval;
use rafs::metadata::RafsDigest;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::fs::DirEntry;
use std::fs::OpenOptions;
use std::io::{Error, Result};
use std::mem::size_of;
use std::path::PathBuf;
use std::str::FromStr;

use sha2::digest::Digest;
use sha2::Sha256;

use rafs::metadata::layout::*;
use rafs::metadata::*;
use rafs::storage::compress;
use rafs::{RafsIoRead, RafsIoWrite};

use crate::node::*;

// const OCISPEC_WHITEOUT_PREFIX: &str = ".wh.";
// const OCISPEC_WHITEOUT_OPAQUE: &str = ".wh..wh..opq";

pub struct Builder {
    /// source root path
    root: PathBuf,
    /// blob file writer
    f_blob: Box<dyn RafsIoWrite>,
    /// bootstrap file writer
    f_bootstrap: Box<dyn RafsIoWrite>,
    /// parent bootstrap file reader
    f_parent_bootstrap: Option<Box<dyn RafsIoRead>>,
    /// blob id (user specified or sha256(blob))
    blob_id: String,
    /// blob chunk compress flag
    compressor: compress::Algorithm,
    /// readahead file list, use BTreeMap to keep stable iteration order
    readahead_nodes: BTreeMap<PathBuf, Option<Node>>,
    /// Specify files or directories which need to prefetch. Their inode indexes will
    /// be persist to prefetch table.
    hint_readahead_files: BTreeMap<PathBuf, Option<u64>>,
    /// node chunks info cache for hardlink, HashMap<i_ino, Node>
    inode_map: HashMap<u64, Node>,
    /// multiple layers build: upper source nodes
    additions: Vec<Node>,
    removals: HashMap<PathBuf, bool>,
    opaques: HashMap<PathBuf, bool>,
    ra_policy: ReadaheadPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReadaheadPolicy {
    None,
    /// Readahead will be issued from Fs layer, which leverages inode/chunkinfo to prefetch data
    /// from blob no mather where it resides(OSS/Localfs). Basically, it is willing to cache the
    /// data into blobcache(if exists). It's more nimble. With this policy applied, image builder
    /// currently puts readahead files' data into a continuous region within blob which behaves very
    /// similar to `Blob` policy.
    Fs,
    /// Readahead will be issued directly from backend/blob layer
    Blob,
}

impl FromStr for ReadaheadPolicy {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "none" => Ok(Self::None),
            "fs" => Ok(Self::Fs),
            "blob" => Ok(Self::Blob),
            _ => Err(einval!("Invalid ra-policy string got.")),
        }
    }
}

impl Builder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root: String,
        blob_path: String,
        bootstrap_path: String,
        parent_bootstrap_path: String,
        blob_id: String,
        compressor: compress::Algorithm,
        hint_readahead_files: BTreeMap<PathBuf, Option<u64>>,
        ra_policy: ReadaheadPolicy,
    ) -> Result<Builder> {
        let f_blob = Box::new(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(blob_path)?,
        );
        let f_bootstrap = Box::new(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(bootstrap_path)?,
        );

        let f_parent_bootstrap: Option<Box<dyn RafsIoRead>> = if parent_bootstrap_path != "" {
            Some(Box::new(
                OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(parent_bootstrap_path)?,
            ))
        } else {
            None
        };

        Ok(Builder {
            root: PathBuf::from(root),
            f_blob,
            f_bootstrap,
            f_parent_bootstrap,
            blob_id,
            compressor,
            inode_map: HashMap::new(),
            readahead_nodes: BTreeMap::new(),
            hint_readahead_files,
            additions: Vec::new(),
            removals: HashMap::new(),
            opaques: HashMap::new(),
            ra_policy,
        })
    }

    fn get_lower_idx(&self, lowers: &[Node], path: PathBuf) -> Option<usize> {
        for (idx, lower) in lowers.iter().enumerate() {
            if lower.path == path {
                return Some(idx);
            }
        }
        None
    }

    /// Gain file or directory inode indexes which will be put into prefetch table.
    fn need_prefetch(&mut self, path: &PathBuf, index: u64) -> bool {
        if self.ra_policy == ReadaheadPolicy::None {
            return false;
        }

        for f in self.hint_readahead_files.keys() {
            // As path is canonicalized, it should be reliable.
            if path.as_os_str() == f.as_os_str() {
                if self.ra_policy == ReadaheadPolicy::Fs {
                    if let Some(i) = self.hint_readahead_files.get_mut(path) {
                        *i = Some(index);
                    }
                }
                return true;
            } else if path.starts_with(f) {
                return true;
            }
        }

        false
    }

    fn new_node(&self, path: &PathBuf) -> Node {
        Node::new(self.root.clone(), path.clone(), Overlay::UpperAddition)
    }

    /// Directory walk by BFS
    pub fn walk(&mut self) -> Result<()> {
        let mut dirs = vec![0];
        // Rafs' inode number starts from 1 which belongs to root inode.
        let mut iter_ino = 1;
        let mut root_node = self.new_node(&self.root);
        root_node.build_inode()?;
        root_node.index = iter_ino;
        root_node.inode.i_ino = iter_ino;

        self.inode_map
            .insert(root_node.inode.i_ino, root_node.clone());
        self.additions.push(root_node);

        while !dirs.is_empty() {
            let mut next_dirs = Vec::new();

            for dir_idx in &dirs {
                let dir_node = self.additions.get_mut(*dir_idx).unwrap();
                let children = fs::read_dir(&dir_node.path)?;
                let dir_ino = dir_node.inode.i_ino;
                let mut child_count = 0;
                // Now the first child is given birth.
                dir_node.inode.i_child_index = (iter_ino + 1) as u32;

                let mut children = children.collect::<Result<Vec<DirEntry>>>()?;
                children.sort_by_key(|entry| entry.file_name());

                for entry in children {
                    let path = entry.path();
                    let mut node = self.new_node(&path);
                    let real_ino = node.get_real_ino()?;

                    // ignore special file
                    if node.get_type()? == "" {
                        continue;
                    }
                    // Inode number is not continuous, we may have holes between
                    // them if hardlink appears.
                    iter_ino += 1;
                    child_count += 1;
                    if let Some(harklink) = self.inode_map.get(&real_ino) {
                        node.inode.i_ino = harklink.inode.i_ino;
                    } else {
                        node.inode.i_ino = iter_ino;
                    }
                    node.build_inode()?;

                    // Inode number always equals to its index within disk inode table.
                    node.index = iter_ino;
                    node.inode.i_parent = dir_ino;

                    if node.is_dir()? && !node.is_symlink()? {
                        next_dirs.push(self.additions.len());
                    }
                    if self.inode_map.get(&real_ino).is_none() {
                        self.inode_map.insert(real_ino, node.clone());
                    }
                    self.additions.push(node.clone());

                    if self.need_prefetch(&node.rootfs(), iter_ino) {
                        self.readahead_nodes.insert(node.rootfs(), Some(node));
                    }
                }

                let dir_node = self.additions.get_mut(*dir_idx).unwrap();
                dir_node.inode.i_child_count = child_count;
            }
            dirs = next_dirs;
        }

        Ok(())
    }

    fn dump(&mut self) -> Result<()> {
        // inode table
        let super_block_size = size_of::<OndiskSuperBlock>();
        let inode_table_entries = self.additions.len() as u32;
        let mut inode_table = OndiskInodeTable::new(inode_table_entries as usize);
        let inode_table_size = inode_table.size();
        let mut prefetch_table_size = 0;
        let mut prefetch_table = PrefetchTable::new();
        if self.ra_policy == ReadaheadPolicy::Fs {
            prefetch_table_size = align_to_rafs(self.hint_readahead_files.len() * size_of::<u32>());
        }

        // blob table, blob id use sha256 string (length 64) as default
        let blob_id_size = if self.blob_id != "" {
            self.blob_id.len()
        } else {
            64
        };
        let blob_table_size = OndiskBlobTable::minimum_size(blob_id_size);
        let prefetch_table_offset = super_block_size + inode_table_size;
        let mut blob_table = OndiskBlobTable::new();
        let blob_table_offset = (prefetch_table_offset + prefetch_table_size) as u64;

        // super block
        let mut super_block = OndiskSuperBlock::new();
        let inodes_count = self.inode_map.len() as u64;
        super_block.set_inodes_count(inodes_count);
        super_block.set_inode_table_offset(super_block_size as u64);
        super_block.set_inode_table_entries(inode_table_entries);
        super_block.set_blob_table_offset(blob_table_offset);
        super_block.set_blob_table_size(blob_table_size as u32);
        super_block.set_prefetch_table_offset(prefetch_table_offset as u64);
        super_block.set_flags(super_block.flags() | self.compressor as u64);
        super_block.set_prefetch_table_size(prefetch_table_size as u32);

        // dump blob
        let mut compress_offset = 0u64;
        let mut decompress_offset = 0u64;
        let mut blob_hash = Sha256::new();
        let mut chunk_cache: ChunkCache = HashMap::new();
        let mut inode_offset =
            (super_block_size + inode_table_size + prefetch_table_size + blob_table_size) as u32;

        info!(
            "inode table starts at {}, prefetch table starts at {}, blob table starts at {}, inodes starts at {}",
            super_block_size, prefetch_table_offset, blob_table_offset, inode_offset
        );

        for node in &mut self.additions {
            let rootfs_path = node.rootfs();
            let file_type = node.get_type()?;
            inode_table.set(node.index, inode_offset)?;
            // add inode size
            inode_offset += node.inode.size() as u32;
            if node.inode.has_xattr() && !node.xattrs.pairs.is_empty() {
                inode_offset += (size_of::<OndiskXAttrs>() + node.xattrs.aligned_size()) as u32;
            }
            // Replace inode because its metadata might be changed somehow.
            if let Some(n) = self.readahead_nodes.get_mut(&rootfs_path) {
                *n = Some(node.clone());
            }
            // add chunks size
            if node.is_reg()? {
                inode_offset +=
                    (node.inode.i_child_count as usize * size_of::<OndiskChunkInfo>()) as u32;
            }
        }

        // sort readahead list by file size for better prefetch
        let mut readahead_nodes = self
            .readahead_nodes
            .values_mut()
            .filter_map(|node| node.as_mut())
            .collect::<Vec<&mut Node>>();
        readahead_nodes.sort_by_key(|node| node.inode.i_size);

        // fist, dump readahead nodes
        let blob_readahead_offset = 0;
        let mut blob_readahead_size = 0;
        for readahead_node in &mut readahead_nodes {
            debug!("upper building readahead {}", readahead_node);

            blob_readahead_size += readahead_node.dump_blob(
                &mut self.f_blob,
                &mut blob_hash,
                &mut compress_offset,
                &mut decompress_offset,
                &mut chunk_cache,
                self.compressor,
            )? as u32;
        }

        if self.ra_policy != ReadaheadPolicy::Blob {
            blob_readahead_size = 0;
        }

        // then, dump other nodes
        for node in &mut self.additions {
            if let Some(Some(readahead_node)) = self.readahead_nodes.get(&node.rootfs()) {
                // prepare correct readahead node data for bootstrap dump
                node.clone_from(&readahead_node);
            } else {
                debug!("upper building {}", node);
                node.dump_blob(
                    &mut self.f_blob,
                    &mut blob_hash,
                    &mut compress_offset,
                    &mut decompress_offset,
                    &mut chunk_cache,
                    self.compressor,
                )?;
            }
        }

        // set blob id, blob hash as default
        if self.blob_id == "" {
            self.blob_id = OndiskDigest::from_digest(blob_hash).to_string();
        }
        blob_table.add(
            self.blob_id.clone(),
            blob_readahead_offset,
            blob_readahead_size,
        );

        // dump bootstrap
        super_block.store(&mut self.f_bootstrap)?;
        inode_table.store(&mut self.f_bootstrap)?;
        if self.ra_policy == ReadaheadPolicy::Fs {
            self.hint_readahead_files
                .values()
                .filter(|_| true)
                .for_each(|idx| prefetch_table.add_entry(idx.unwrap() as u32));
            prefetch_table.store(&mut self.f_bootstrap)?;
        }
        blob_table.store(&mut self.f_bootstrap)?;

        let len = self.additions.len();
        for i in 0..len {
            let idx = len - 1 - i;
            if self.additions[idx].is_dir()? {
                self.additions[idx].inode.i_digest = self.digest_node(&self.additions[idx])?;
            }
            self.additions[idx].dump_bootstrap(&mut self.f_bootstrap, 0)?;
            trace!(
                "inode digest {:?} {:?}",
                self.additions[idx].rootfs(),
                self.additions[idx].inode.i_digest
            );
        }

        Ok(())
    }

    fn digest_node(&self, node: &Node) -> Result<OndiskDigest> {
        if !node.is_dir()? {
            return Ok(node.inode.i_digest);
        }

        let mut inode_hash = Sha256::new();
        let mut inode_digest = OndiskDigest::new();
        let child_index = node.inode.i_child_index;
        let child_count = node.inode.i_child_count;

        for idx in child_index..child_index + child_count {
            let child = &self.additions[(idx - 1) as usize];
            inode_hash.input(&child.inode.i_digest.data());
        }

        let mut inode_hash_buf = [0; RAFS_SHA256_LENGTH];
        inode_hash.result(&mut inode_hash_buf);
        inode_digest.data_mut().clone_from_slice(&inode_hash_buf);

        Ok(inode_digest)
    }

    pub fn build(&mut self) -> Result<String> {
        self.walk()?;
        self.dump()?;

        Ok(self.blob_id.to_owned())
    }
}
