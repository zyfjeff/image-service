// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use rafs::metadata::RafsDigest;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::fs::DirEntry;
use std::fs::OpenOptions;
use std::io::Result;
use std::mem::size_of;
use std::path::PathBuf;

use sha2::digest::Digest;
use sha2::Sha256;

use rafs::metadata::layout::*;
use rafs::metadata::RafsStore;
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
}

impl Builder {
    pub fn new(
        root: String,
        blob_path: String,
        bootstrap_path: String,
        parent_bootstrap_path: String,
        blob_id: String,
        compressor: compress::Algorithm,
        hint_readahead_files: BTreeMap<PathBuf, Option<u64>>,
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
        for f in self.hint_readahead_files.keys() {
            // As path is canonicalized, it should be reliable.
            if path.as_os_str() == f.as_os_str() {
                self.hint_readahead_files.insert(path.clone(), Some(index));
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
        let mut iter_ino: u64 = 1;
        let mut root_node = self.new_node(&self.root);
        root_node.build_inode(None)?;
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
                let mut child_count: usize = 0;

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

                    iter_ino += 1;
                    child_count += 1;
                    let mut hardlink: Option<Node> = None;
                    if let Some(_hardlink) = self.inode_map.get(&real_ino) {
                        node.inode.i_ino = _hardlink.inode.i_ino;
                        hardlink = Some(_hardlink.clone());
                    } else {
                        node.inode.i_ino = iter_ino;
                    }
                    node.build_inode(hardlink)?;

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
                dir_node.inode.i_child_count = child_count as u32;
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
        let mut prefetch_table = PrefetchTable::new();
        let prefetch_table_size = align_to_rafs(self.hint_readahead_files.len() * size_of::<u32>());

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
        let mut blob_compress_offset = 0u64;
        let mut blob_decompress_offset = 0u64;
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
            if file_type != "" {
                debug!(
                    "upper building {} {:?}: index {} ino {} child_count {} child_index {} i_name_size {} i_symlink_size {} i_nlink {} has_xattr {}",
                    file_type,
                    &rootfs_path,
                    node.index,
                    node.inode.i_ino,
                    node.inode.i_child_count,
                    node.inode.i_child_index,
                    node.inode.i_name_size,
                    node.inode.i_symlink_size,
                    node.inode.i_nlink,
                    node.inode.has_xattr(),
                );
            }
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

        self.hint_readahead_files
            .values()
            .filter(|_| true)
            .for_each(|idx| prefetch_table.add_entry(idx.unwrap() as u32));

        // fist, dump readahead nodes
        let blob_readahead_offset = 0;
        let mut blob_readahead_size = 0;
        for readahead_node in &mut readahead_nodes {
            debug!("upper building readahead {}", readahead_node);

            blob_readahead_size += readahead_node.dump_blob(
                &mut self.f_blob,
                &mut blob_hash,
                &mut blob_compress_offset,
                &mut blob_decompress_offset,
                &mut chunk_cache,
                self.compressor,
            )? as u32;
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
                    &mut blob_compress_offset,
                    &mut blob_decompress_offset,
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
        prefetch_table.store(&mut self.f_bootstrap)?;
        blob_table.store(&mut self.f_bootstrap)?;

        for node in &mut self.additions {
            node.dump_bootstrap(&mut self.f_bootstrap, 0)?;
        }

        Ok(())
    }

    pub fn build(&mut self) -> Result<String> {
        self.walk()?;
        self.dump()?;

        Ok(self.blob_id.to_owned())
    }
}
