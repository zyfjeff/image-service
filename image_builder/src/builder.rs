// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Result;
use std::os::linux::fs::MetadataExt;
use std::path::Path;

use rafs::layout::*;

use crate::node::*;

pub struct Builder {
    /// source root path
    root: String,
    /// blob file writer
    f_blob: File,
    /// bootstrap file writer
    f_bootstrap: File,
    /// record current blob offset cursor
    blob_offset: u64,
    /// blob id (user specified)
    blob_id: String,
    /// node chunks info cache, HashMap<i_ino, Node>
    inode_map: HashMap<u64, Node>,
}

impl Builder {
    pub fn new(
        root: String,
        blob_path: String,
        bootstrap_path: String,
        blob_id: String,
    ) -> Result<Builder> {
        let f_blob = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(blob_path)?;
        let f_bootstrap = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(bootstrap_path)?;

        Ok(Builder {
            root,
            f_blob,
            f_bootstrap,
            blob_offset: 0,
            blob_id,
            inode_map: HashMap::new(),
        })
    }

    fn dump_superblock(&mut self) -> Result<RafsSuperBlockInfo> {
        info!("building superblock");
        let mut sb = RafsSuperBlockInfo::new();
        // all fields are initilized by RafsSuperBlockInfo::new()
        sb.s_flags = 0;

        // dump superblock to bootstrap
        sb.store(&mut self.f_bootstrap)?;

        Ok(sb)
    }

    fn walk_dirs(&mut self, file: &Path, parent_node: Option<Box<Node>>) -> Result<()> {
        if file.is_dir() {
            for entry in fs::read_dir(file)? {
                let entry = entry?;
                let path = entry.path();
                let meta = entry.metadata()?;

                let mut node = Node::new(
                    self.blob_id.clone(),
                    self.blob_offset,
                    self.root.clone(),
                    path.to_str().unwrap().to_string(),
                    parent_node.clone(),
                );

                let ino = meta.st_ino();
                let hardlink_node = self.inode_map.get(&ino);
                if hardlink_node.is_some() {
                    let hardlink_node = Box::new(hardlink_node.unwrap().clone());
                    node.dump(&mut self.f_blob, &mut self.f_bootstrap, Some(hardlink_node))?;
                } else {
                    node.dump(&mut self.f_blob, &mut self.f_bootstrap, None)?;
                    self.inode_map.insert(ino, node.clone());
                }
                self.blob_offset = node.clone().blob_offset;

                if path.is_dir() {
                    self.walk_dirs(&path, Some(Box::new(node)))?;
                }
            }
        }
        Ok(())
    }

    pub fn build(&mut self) -> Result<()> {
        self.dump_superblock()?;

        let root = self.root.clone();
        let root_path = Path::new(root.as_str());
        let root_path_str = root_path.to_str().unwrap().to_string();
        let mut root_node = Node::new(
            self.blob_id.clone(),
            self.blob_offset,
            root_path_str.clone(),
            root_path_str,
            None,
        );
        root_node.dump(&mut self.f_blob, &mut self.f_bootstrap, None)?;

        self.walk_dirs(root_path, Some(Box::new(root_node)))?;

        Ok(())
    }
}
