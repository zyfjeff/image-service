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

const OCISPEC_WHITEOUT_PREFIX: &str = ".wh.";
const OCISPEC_WHITEOUT_OPAQUE: &str = ".wh..wh..opq";

pub struct Builder {
    /// source root path
    root: String,
    /// blob file writer
    f_blob: File,
    /// bootstrap file writer
    f_bootstrap: File,
    /// parent bootstrap file reader
    f_parent_bootstrap: Option<File>,
    /// record current blob offset cursor
    blob_offset: u64,
    /// blob id (user specified)
    blob_id: String,
    /// node chunks info cache for hardlink, HashMap<i_ino, Node>
    inode_map: HashMap<u64, Node>,
    /// mutilple layers build: source nodes
    additions: HashMap<String, Node>,
    removals: HashMap<String, bool>,
    opaques: HashMap<String, bool>,
    /// mutilple layers build: parent + source nodes
    finals: Vec<Node>,
}

impl Builder {
    pub fn new(
        root: String,
        blob_path: String,
        bootstrap_path: String,
        parent_bootstrap_path: String,
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

        let mut f_parent_bootstrap = None;
        if parent_bootstrap_path != "" {
            f_parent_bootstrap = Some(
                OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(parent_bootstrap_path)?,
            );
        }

        Ok(Builder {
            root,
            f_blob,
            f_bootstrap,
            f_parent_bootstrap,
            blob_offset: 0,
            blob_id,
            inode_map: HashMap::new(),
            additions: HashMap::new(),
            removals: HashMap::new(),
            opaques: HashMap::new(),
            finals: Vec::new(),
        })
    }

    fn apply(&mut self) -> Result<()> {
        let mut bootstrap = self.f_parent_bootstrap.as_ref().unwrap();
        let mut sb = RafsSuperBlockInfo::new();
        sb.load(&mut bootstrap)?;

        let mut inodes: HashMap<u64, String> = HashMap::new();

        loop {
            let mut inode = RafsInodeInfo::new();
            let ret = inode.load(&mut bootstrap);
            if ret.is_err() {
                break;
            }

            let mut path = Path::new(&inode.name).to_path_buf();

            let parent_path = inodes.get(&inode.i_parent);
            if parent_path.is_some() {
                path = Path::new(parent_path.unwrap()).join(&inode.name);
            }

            let path = path.to_str().unwrap();

            let mut xattr_chunks = RafsInodeXattrInfos::new();
            if inode.has_xattr() {
                xattr_chunks.load(&mut bootstrap)?;
            }

            let mut file_type = "unknown";

            if inode.is_dir() {
                file_type = "dir";
                inodes.insert(inode.i_ino, path.to_owned());
            }

            let mut chunks = Vec::new();
            if inode.is_reg() {
                file_type = "file";
                if inode.is_hardlink() {
                    file_type = "hardlink";
                }
                for _ in 0..inode.i_chunk_cnt {
                    let mut chunk = RafsChunkInfo::new();
                    chunk.load(&mut bootstrap)?;
                    chunks.push(chunk);
                }
            }

            let mut link_chunks = Vec::new();
            if inode.is_symlink() {
                file_type = "symlink";
                let mut link_chunk = RafsLinkDataInfo::new(inode.i_chunk_cnt as usize);
                link_chunk.load(&mut bootstrap)?;
                link_chunks.push(link_chunk);
            }

            let mut dir = Path::new(path).to_path_buf();
            dir.pop();
            if self
                .opaques
                .get(&dir.to_str().unwrap().to_owned())
                .is_some()
            {
                info!("upper opaqued\t{} {}", file_type, path);
                continue;
            }

            if self.removals.get(&path.to_owned()).is_none() {
                let node = Node {
                    blob_id: self.blob_id.to_owned(),
                    blob_offset: self.blob_offset,
                    root: self.root.to_owned(),
                    path: path.to_owned(),
                    parent: None,
                    inode,
                    chunks,
                    link_chunks,
                    xattr_chunks,
                };
                let updated = self.additions.get(&path.to_owned());
                if updated.is_some() {
                    self.finals.push(updated.unwrap().clone());
                    self.additions.remove(&path.to_owned());
                    info!("upper updated\t{} {}", file_type, path);
                } else {
                    self.finals.push(node);
                    info!("lower added\t{} {}", file_type, path);
                }
            } else {
                info!("upper deleted\t{} {}", file_type, path);
            }
        }

        for (path, node) in &mut self.additions {
            self.finals.push(node.clone());
            info!("upper added\t{}\t{}", node.get_type(), path);
        }

        Ok(())
    }

    fn dump_superblock(&mut self) -> Result<RafsSuperBlockInfo> {
        info!("upper building\tsuperblock");
        let mut sb = RafsSuperBlockInfo::new();
        // all fields are initilized by RafsSuperBlockInfo::new()
        sb.s_flags = 0;

        // dump superblock to bootstrap
        sb.store(&mut self.f_bootstrap)?;

        Ok(sb)
    }

    fn walk_dirs(&mut self, file: &Path, parent_node: Option<Box<Node>>) -> Result<()> {
        if file.is_dir() {
            let opaque_path = file.join(OCISPEC_WHITEOUT_OPAQUE);
            if opaque_path.metadata().is_ok() {
                let relative_path =
                    Path::new("/").join(file.strip_prefix(self.root.as_str()).unwrap());
                let path = relative_path.to_str().unwrap();
                self.opaques.insert(path.to_owned(), true);
                return Ok(());
            }

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

                let mut relative_path =
                    Path::new("/").join(path.strip_prefix(self.root.as_str()).unwrap());
                let mut name = relative_path.file_name().unwrap().to_str().unwrap();
                if name.starts_with(OCISPEC_WHITEOUT_PREFIX) {
                    let mut _relative_path = relative_path.to_owned();
                    _relative_path.pop();
                    name = &name[OCISPEC_WHITEOUT_PREFIX.len()..];
                    relative_path = _relative_path.join(name);
                    let relative_path_str = relative_path.to_str().unwrap();
                    self.removals.insert(relative_path_str.to_owned(), true);
                    continue;
                }

                let ino = meta.st_ino();
                let hardlink_node = self.inode_map.get(&ino);
                if hardlink_node.is_some() {
                    let hardlink_node = Box::new(hardlink_node.unwrap().clone());
                    node.dump(&mut self.f_blob, &mut self.f_bootstrap, Some(hardlink_node))?;
                } else {
                    node.dump(&mut self.f_blob, &mut self.f_bootstrap, None)?;
                    self.inode_map.insert(ino, node.clone());
                }
                self.blob_offset = node.blob_offset;

                self.additions
                    .insert(relative_path.to_str().unwrap().to_owned(), node.clone());

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

        // reset blob offset cursor
        self.blob_offset = 0;

        if self.f_parent_bootstrap.is_some() {
            self.apply()?;
        }

        Ok(())
    }
}
