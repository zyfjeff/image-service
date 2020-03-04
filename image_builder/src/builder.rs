// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Result;
use std::path::Path;

use rafs::layout::*;

use crate::node::*;

pub struct Builder<'a> {
    /// source root path
    root: &'a str,
    /// blob file writer
    f_blob: File,
    /// bootstrap file writer
    f_bootstrap: File,
    /// record current blob offset cursor
    blob_offset: u64,
    /// blob id (user specified)
    blob_id: &'a str,
}

impl<'a> Builder<'a> {
    pub fn new(
        root: &'a str,
        blob_path: &'a str,
        bootstrap_path: &'a str,
        blob_id: &'a str,
    ) -> Result<Builder<'a>> {
        env_logger::init();

        let f_blob = OpenOptions::new()
            .write(true)
            .create(true)
            .open(blob_path)?;
        let f_bootstrap = OpenOptions::new()
            .write(true)
            .create(true)
            .open(bootstrap_path)?;

        Ok(Builder {
            root,
            f_blob,
            f_bootstrap,
            blob_offset: 0,
            blob_id,
        })
    }

    fn dump_superblock(&mut self) -> Result<RafsSuperBlockInfo> {
        trace!("building superblock {}", self.root);
        let mut sb = RafsSuperBlockInfo::new();

        sb.s_inodes_count = 0;
        sb.s_blocks_count = 0;
        sb.s_inode_size = RAFS_INODE_INFO_SIZE as u16;
        sb.s_padding1 = 0;
        sb.s_block_size = DEFAULT_RAFS_BLOCK_SIZE as u32;
        sb.s_fs_version = RAFS_SUPER_VERSION as u16;
        sb.s_padding2 = 0;
        sb.s_magic = RAFS_SUPER_MAGIC;

        // dump superblock to bootstrap
        sb.store(&mut self.f_bootstrap)?;

        Ok(sb)
    }

    fn walk_dirs(&mut self, file: &Path, parent_node: &Option<Box<Node>>) -> Result<()> {
        if file.is_dir() {
            for entry in fs::read_dir(file)? {
                let entry = entry?;
                let path = entry.path();
                let meta = &entry.metadata()?;

                let mut node = Node::new(
                    self.blob_id,
                    self.blob_offset,
                    meta,
                    path.to_str().unwrap(),
                    parent_node,
                );

                node.dump(&mut self.f_blob, &mut self.f_bootstrap)?;
                self.blob_offset = node.blob_offset();

                if path.is_dir() {
                    self.walk_dirs(&path, &Some(Box::new(node)))?;
                }
            }
        }
        Ok(())
    }

    pub fn build(&mut self) -> Result<()> {
        self.dump_superblock()?;

        let root_path = Path::new(self.root);
        let root_meta = &root_path.metadata()?;
        let mut root_node = Node::new(self.blob_id, self.blob_offset, root_meta, "/", &None);
        root_node.dump(&mut self.f_blob, &mut self.f_bootstrap)?;

        self.walk_dirs(root_path, &Some(Box::new(root_node)))?;

        Ok(())
    }
}
