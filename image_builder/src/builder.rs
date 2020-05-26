// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be
// found in the LICENSE file.

// use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Result;
// use std::os::linux::fs::MetadataExt;
use std::path::PathBuf;

use rafs::metadata::layout::*;
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
    /// record current blob offset cursor
    blob_offset: u64,
    /// blob id (user specified or sha256(blob))
    blob_id: String,
    /// blob sha256
    blob_hash: Sha256,
    /// node chunks info cache for hardlink, HashMap<i_ino, Node>
    inode_map: HashMap<u64, Node>,
    /// mutilple layers build: upper source nodes
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
            blob_offset: 0,
            blob_id,
            blob_hash: Sha256::new(),
            inode_map: HashMap::new(),
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

    fn fill_blob_id(&mut self) {
        for node in &mut self.additions {
            for chunk in &mut node.chunks {
                chunk.blob_index = 0;
            }
        }
    }

    fn new_node(&self, path: &PathBuf) -> Node {
        Node::new(
            self.blob_offset,
            self.root.clone(),
            path.clone(),
            Overlay::UpperAddition,
        )
    }

    /// Directory walk by BFS
    pub fn walk(&mut self) -> Result<()> {
        let mut dirs = vec![0];
        let mut ino: u64 = 1;
        let mut root_node = self.new_node(&self.root);
        root_node.build_inode(None)?;

        root_node.inode.i_ino = 1;
        self.inode_map
            .insert(root_node.inode.i_ino, root_node.clone());
        self.additions.push(root_node);

        while !dirs.is_empty() {
            let mut next_dirs = Vec::new();

            for dir_idx in &dirs {
                let dir_node = self.additions.get_mut(*dir_idx).unwrap();
                let childs = fs::read_dir(&dir_node.path)?;
                let dir_ino = dir_node.inode.i_ino;
                let mut child_count: usize = 0;

                dir_node.inode.i_child_index = (ino + 1) as u32;

                for child in childs {
                    let entry = &child?;
                    let path = entry.path();
                    let mut node = self.new_node(&path);
                    node.build_inode(None)?;

                    ino += 1;
                    child_count += 1;
                    node.inode.i_ino = ino;
                    node.inode.i_parent = dir_ino;

                    if node.is_dir() && !node.is_symlink() {
                        next_dirs.push(self.additions.len());
                    }
                    self.inode_map.insert(node.inode.i_ino, node.clone());
                    self.additions.push(node);
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
        let inode_table_entries = self.additions.len() as u32;
        let mut inode_table = OndiskInodeTable::new(inode_table_entries as usize);
        let inode_table_size = inode_table.size();
        let inode_table_offset = RAFS_SUPERBLOCK_SIZE as u64;

        // blob table
        let blob_table_entries: usize = 1;
        let blob_table = OndiskBlobTable::new(blob_table_entries);
        let blob_table_size = blob_table.size();
        let blob_table_offset = (RAFS_SUPERBLOCK_SIZE + inode_table_size) as u64;

        // super block
        let mut super_block = OndiskSuperBlock::new();
        let inodes_count = self.inode_map.len() as u64;
        super_block.set_inodes_count(inodes_count);
        super_block.set_inode_table_offset(inode_table_offset);
        super_block.set_inode_table_entries(inode_table_entries);
        super_block.set_blob_table_offset(blob_table_offset);
        super_block.set_blob_table_entries(blob_table_entries as u32);

        // dump blob
        let mut inode_offset = (RAFS_SUPERBLOCK_SIZE + inode_table_size + blob_table_size) as u32;
        for node in &mut self.additions {
            inode_table.set(node.inode.i_ino, inode_offset)?;
            inode_offset += node.inode.size() as u32;
            node.dump_blob(&mut self.f_blob, &mut self.blob_hash)?;
            inode_offset += (node.chunks.len() * std::mem::size_of::<OndiskChunkInfo>()) as u32;
        }
        let blob_id = OndiskDigest::from_raw(&mut self.blob_hash);
        let mut blob_table = OndiskBlobTable::new(1);
        blob_table.set(0, blob_id)?;

        // dump bootstrap
        super_block.store(&mut self.f_bootstrap)?;
        inode_table.store(&mut self.f_bootstrap)?;
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
