// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Result};
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
    /// blob id (user specified or sha256(blob))
    blob_id: String,
    /// blob sha256
    blob_hash: Sha256,
    /// node chunks info cache for hardlink, HashMap<i_ino, Node>
    inode_map: HashMap<u64, Node>,
    /// mutilple layers build: upper source nodes
    additions: Vec<Node>,
    removals: HashMap<String, bool>,
    opaques: HashMap<String, bool>,
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

        let f_parent_bootstrap = if parent_bootstrap_path != "" {
            Some(
                OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(parent_bootstrap_path)?,
            )
        } else {
            None
        };

        Ok(Builder {
            root,
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

    fn get_lower_idx(&self, lowers: &[Node], path: String) -> Option<usize> {
        for (idx, lower) in lowers.iter().enumerate() {
            if lower.path == path {
                return Some(idx);
            }
        }
        None
    }

    fn apply(&mut self) -> Result<()> {
        let mut bootstrap = self.f_parent_bootstrap.as_ref().unwrap();
        let mut sb = RafsSuperBlockInfo::new();
        sb.load(&mut bootstrap)?;

        let mut nodes: HashMap<u64, Node> = HashMap::new();
        let mut lowers: Vec<Node> = Vec::new();

        loop {
            let mut inode = RafsInodeInfo::new();

            match inode.load(&mut bootstrap) {
                Ok(0) => break,
                Ok(_) => {}
                Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => {
                    return Err(e);
                }
            }

            let mut xattr_chunks = RafsInodeXattrInfos::new();
            if inode.has_xattr() {
                xattr_chunks.load(&mut bootstrap)?;
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

            let mut path = inode.name.to_owned();

            let mut parent = None;
            if let Some(parent_node) = nodes.get_mut(&inode.i_parent) {
                parent = Some(Box::new(parent_node.clone()));
                let _path = Path::new(parent_node.path.as_str()).join(inode.name.to_owned());
                path = _path.to_str().unwrap().to_owned();
            }

            let mut overlay = if self.removals.get(&path).is_some() {
                Overlay::UpperRemoval
            } else {
                Overlay::LowerAddition
            };

            if let Some(parent) = &parent {
                if self.opaques.get(&parent.path).is_some() {
                    overlay = Overlay::UpperOpaque;
                }
            }

            let node = Node {
                blob_offset: self.blob_offset,
                root: self.root.to_owned(),
                path: path.clone(),
                parent,
                overlay,
                inode: inode.clone(),
                chunks,
                link_chunks,
                xattr_chunks,
            };

            nodes.insert(inode.i_ino, node.clone());
            lowers.push(node.clone());
        }

        for addition in &self.additions {
            let addition_path = addition.rootfs_path();
            let mut _addition = addition.clone();
            _addition.path = addition_path.to_str().unwrap().to_owned();
            if let Some(idx) = self.get_lower_idx(&lowers, _addition.path.clone()) {
                _addition.inode.i_ino = lowers[idx].inode.i_ino;
                _addition.inode.i_parent = lowers[idx].inode.i_parent;
                _addition.overlay = Overlay::UpperModification;
                lowers[idx] = _addition;
            } else if let Some(parent_path) = addition_path.parent() {
                if let Some(idx) =
                    self.get_lower_idx(&lowers, parent_path.to_str().unwrap().to_owned())
                {
                    _addition.inode.i_parent = lowers[idx].inode.i_ino;
                    _addition.overlay = Overlay::UpperAddition;
                    lowers.insert(idx + 1, _addition);
                } else {
                    _addition.overlay = Overlay::UpperAddition;
                    lowers.push(_addition);
                }
            }
        }

        for lower in &mut lowers {
            info!(
                "{} {} {} inode {}, parent {}",
                lower.overlay,
                lower.get_type(),
                lower.path,
                lower.inode.i_ino,
                lower.inode.i_parent
            );
            if lower.overlay != Overlay::UpperRemoval && lower.overlay != Overlay::UpperOpaque {
                lower.dump_bootstrap(&self.f_bootstrap, None)?;
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

    fn dump_bootstrap(&mut self) -> Result<()> {
        for node in &mut self.additions {
            node.dump_bootstrap(&self.f_bootstrap, Some(self.blob_id.to_owned()))?;
        }

        Ok(())
    }

    fn fill_blob_id(&mut self) {
        for node in &mut self.additions {
            for chunk in &mut node.chunks {
                chunk.blobid = self.blob_id.to_owned();
            }
        }
    }

    fn dump_blob(&mut self, file: &Path, parent_node: Option<Box<Node>>) -> Result<()> {
        let meta = file.symlink_metadata()?;

        if parent_node.is_none() {
            let path = file.to_str().unwrap().to_owned();

            let mut root_node = Node::new(
                self.blob_offset,
                self.root.to_owned(),
                path,
                None,
                Overlay::LowerAddition,
            );

            root_node.build(None)?;
            root_node.dump_blob(&self.f_blob, &mut self.blob_hash)?;

            self.additions.push(root_node.clone());

            self.dump_blob(file, Some(Box::new(root_node)))?;

            return Ok(());
        }

        let is_symlink = meta.st_mode() & libc::S_IFMT == libc::S_IFLNK;

        if file.is_dir() && !is_symlink {
            let rootfs_path = Path::new("/").join(file.strip_prefix(self.root.as_str()).unwrap());
            let rootfs_path = rootfs_path.to_str().unwrap();

            let opaque_path = file.join(OCISPEC_WHITEOUT_OPAQUE);
            if opaque_path.metadata().is_ok() {
                self.opaques.insert(rootfs_path.to_owned(), true);
            }

            for entry in fs::read_dir(file)? {
                let entry = entry?;
                let path = entry.path();
                let meta = entry.metadata()?;

                let mut node = Node::new(
                    self.blob_offset,
                    self.root.clone(),
                    path.to_str().unwrap().to_owned(),
                    parent_node.clone(),
                    Overlay::UpperAddition,
                );

                let mut name = path.file_name().unwrap().to_str().unwrap();

                if name == OCISPEC_WHITEOUT_OPAQUE {
                    continue;
                }

                if name.starts_with(OCISPEC_WHITEOUT_PREFIX) {
                    name = &name[OCISPEC_WHITEOUT_PREFIX.len()..];
                    if let Some(parent_dir) = path.parent() {
                        let path = parent_dir.join(name);
                        let rootfs_path =
                            Path::new("/").join(path.strip_prefix(self.root.as_str()).unwrap());
                        let rootfs_path = rootfs_path.to_str().unwrap();
                        self.removals.insert(rootfs_path.to_owned(), true);
                        continue;
                    }
                }

                let ino = meta.st_ino();
                let keep;
                let hardlink_node = self.inode_map.get(&ino);

                if let Some(hardlink_node) = hardlink_node {
                    keep = node.build(Some(hardlink_node.clone()))?;
                } else {
                    keep = node.build(None)?;
                    if keep {
                        self.inode_map.insert(ino, node.clone());
                    }
                }

                if !keep {
                    continue;
                }

                node.dump_blob(&self.f_blob, &mut self.blob_hash)?;
                self.blob_offset = node.blob_offset;
                self.additions.push(node.clone());
                if path.is_dir() {
                    self.dump_blob(&path, Some(Box::new(node)))?;
                }
            }
        }

        Ok(())
    }

    pub fn build(&mut self) -> Result<String> {
        self.dump_superblock()?;

        let root = self.root.clone();
        let root_path = Path::new(root.as_str());

        self.dump_blob(root_path, None)?;

        let blob_hash = self.blob_hash.result_str();
        if self.blob_id == "" {
            self.blob_id = format!("sha256:{}", blob_hash);
        }

        if self.f_parent_bootstrap.is_none() {
            self.dump_bootstrap()?;
        } else {
            self.fill_blob_id();
            self.apply()?;
        }

        Ok(self.blob_id.to_owned())
    }
}
