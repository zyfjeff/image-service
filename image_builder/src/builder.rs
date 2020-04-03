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

        let mut dir_ino_paths: HashMap<u64, String> = HashMap::new();
        let mut dir_path_inos: HashMap<String, u64> = HashMap::new();

        loop {
            let mut inode = RafsInodeInfo::new();
            let ret = inode.load(&mut bootstrap);
            if ret.is_err() {
                break;
            }

            let path;

            let parent_path = dir_ino_paths.get(&inode.i_parent);
            if parent_path.is_some() {
                path = Path::new(self.root.as_str())
                    .join(parent_path.unwrap())
                    .join(&inode.name);
            } else {
                if inode.name == "/" {
                    path = Path::new(self.root.as_str()).to_path_buf();
                } else {
                    path = Path::new(self.root.as_str()).join(&inode.name);
                }
            }

            let path = path.to_str().unwrap();

            let mut xattr_chunks = RafsInodeXattrInfos::new();
            if inode.has_xattr() {
                xattr_chunks.load(&mut bootstrap)?;
            }

            if inode.is_dir() {
                dir_ino_paths.insert(inode.i_ino, path.to_owned());
                dir_path_inos.insert(path.to_owned(), inode.i_ino);
            }

            let mut chunks = Vec::new();
            if inode.is_reg() {
                for _ in 0..inode.i_chunk_cnt {
                    let mut chunk = RafsChunkInfo::new();
                    chunk.load(&mut bootstrap)?;
                    chunks.push(chunk);
                }
            }

            let mut link_chunks = Vec::new();
            if inode.is_symlink() {
                let mut link_chunk = RafsLinkDataInfo::new(inode.i_chunk_cnt as usize);
                link_chunk.load(&mut bootstrap)?;
                link_chunks.push(link_chunk);
            }

            let mut overlay = Overlay::LowerAddition;

            if let Some(dir) = Path::new(path).parent() {
                if self
                    .opaques
                    .get(&dir.to_str().unwrap().to_owned())
                    .is_some()
                {
                    overlay = Overlay::UpperOpaque;
                }
            }

            let mut node = Node {
                blob_id: self.blob_id.to_owned(),
                blob_offset: self.blob_offset,
                root: self.root.to_owned(),
                path: path.to_owned(),
                parent: None,
                overlay,
                inode,
                chunks,
                link_chunks,
                xattr_chunks,
            };

            if self.removals.get(path).is_none() {
                if let Some(updated) = self.additions.get_mut(path) {
                    updated.overlay = Overlay::UpperModification;
                    node = updated.clone();
                    self.additions.remove(path);
                } else {
                    if node.overlay != Overlay::UpperOpaque {
                        node.overlay = Overlay::LowerAddition;
                    }
                }
            } else {
                node.overlay = Overlay::UpperRemoval;
            }

            self.finals.push(node);
        }

        for (_, node) in &mut self.additions {
            self.finals.push(node.clone());
        }

        for node in &mut self.finals {
            let parent_path = Path::new(&node.path).parent();
            if let Some(path) = parent_path {
                if let Some(i_parent) = dir_path_inos.get(path.to_str().unwrap()) {
                    node.inode.i_parent = *i_parent;
                }
            }
            if let Some(i_ino) = dir_path_inos.get(node.path.as_str()) {
                node.inode.i_ino = *i_ino;
            }
            info!(
                "{} {} {}",
                node.overlay,
                node.get_type(),
                node.rootfs_path().to_str().unwrap(),
            );
            match node.overlay {
                Overlay::UpperOpaque => {}
                Overlay::UpperRemoval => {}
                _ => {
                    node.dump(None, Some(&mut self.f_bootstrap))?;
                }
            }
        }

        Ok(())
    }

    fn dump_superblock(&mut self) -> Result<RafsSuperBlockInfo> {
        info!("upper building superblock");
        let mut sb = RafsSuperBlockInfo::new();
        // all fields are initilized by RafsSuperBlockInfo::new()
        sb.s_flags = 0;

        // dump superblock to bootstrap
        sb.store(&mut self.f_bootstrap)?;

        Ok(sb)
    }

    fn walk_dirs(&mut self, file: &Path, parent_node: Option<Box<Node>>) -> Result<()> {
        let meta = file.symlink_metadata()?;

        let is_symlink = meta.st_mode() & libc::S_IFMT == libc::S_IFLNK;

        if file.is_dir() && !is_symlink {
            let opaque_path = file.join(OCISPEC_WHITEOUT_OPAQUE);
            if opaque_path.metadata().is_ok() {
                self.opaques.insert(file.to_str().unwrap().to_owned(), true);
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
                    path.to_str().unwrap().to_owned(),
                    parent_node.clone(),
                    Overlay::UpperAddition,
                );

                let mut name = path.file_name().unwrap().to_str().unwrap();
                if name.starts_with(OCISPEC_WHITEOUT_PREFIX) {
                    name = &name[OCISPEC_WHITEOUT_PREFIX.len()..];
                    if let Some(parent_dir) = path.parent() {
                        let path = parent_dir.join(name);
                        self.removals
                            .insert(path.to_str().unwrap().to_owned(), true);
                        continue;
                    }
                }

                let mut f_bootstrap = Some(&self.f_bootstrap);
                if self.f_parent_bootstrap.is_some() {
                    f_bootstrap = None;
                }

                let ino = meta.st_ino();
                let hardlink_node = self.inode_map.get(&ino);
                if hardlink_node.is_some() {
                    let hardlink_node = Box::new(hardlink_node.unwrap().clone());
                    node.build(Some(hardlink_node))?;
                    node.dump(Some(&mut self.f_blob), f_bootstrap)?;
                } else {
                    node.build(None)?;
                    node.dump(Some(&mut self.f_blob), f_bootstrap)?;
                    self.inode_map.insert(ino, node.clone());
                }
                self.blob_offset = node.blob_offset;

                self.additions
                    .insert(path.to_str().unwrap().to_owned(), node.clone());

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
            Overlay::LowerAddition,
        );

        let mut f_bootstrap = Some(&self.f_bootstrap);
        if self.f_parent_bootstrap.is_some() {
            f_bootstrap = None;
        }
        root_node.build(None)?;
        root_node.dump(Some(&mut self.f_blob), f_bootstrap)?;

        self.walk_dirs(root_path, Some(Box::new(root_node)))?;

        // reset blob offset cursor
        self.blob_offset = 0;

        if self.f_parent_bootstrap.is_some() {
            self.apply()?;
        }

        Ok(())
    }
}
