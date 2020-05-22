// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be
// found in the LICENSE file.

// use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Result};
// use std::os::linux::fs::MetadataExt;
use std::path::PathBuf;

use rafs::metadata::layout::*;
use rafs::metadata::{RafsChunkInfo, RafsInode, RafsSuper};
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

    fn apply(&mut self) -> Result<()> {
        let mut parent_bootstrap = self.f_parent_bootstrap.as_mut().unwrap();

        let mut sb = RafsSuper::new();
        sb.load(&mut parent_bootstrap)?;

        let mut nodes: HashMap<u64, Node> = HashMap::new();
        let mut lowers: Vec<Node> = Vec::new();

        loop {
            let mut inode = OndiskInode::new();

            match inode.load(&mut parent_bootstrap) {
                Ok(_) => {}
                Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => {
                    return Err(e);
                }
            }

            // let mut xattr_chunks = RafsInodeXattrInfos::new();
            // if inode.has_xattr() {
            //     xattr_chunks.load(&mut bootstrap)?;
            // }

            let mut chunks = Vec::new();
            if inode.is_reg() {
                for _ in 0..inode.chunk_cnt() {
                    let mut chunk = OndiskChunkInfo::new();
                    chunk.load(&mut parent_bootstrap)?;
                    chunks.push(chunk);
                }
            }

            // let mut link_chunks = Vec::new();
            // if inode.is_symlink() {
            //     let mut link_chunk = RafsLinkDataInfo::new(inode.i_chunk_cnt as usize);
            //     link_chunk.load(&mut bootstrap)?;
            //     link_chunks.push(link_chunk);
            // }

            let mut path = PathBuf::from(inode.name());

            let mut parent = None;
            if let Some(parent_node) = nodes.get_mut(&inode.parent()) {
                parent = Some(Box::new(parent_node.clone()));
                path = parent_node.path.join(inode.name());
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
                root: self.root.clone(),
                path: path.clone(),
                overlay,
                inode,
                chunks,
                link_chunk: None,
                // xattr_chunks,
            };

            nodes.insert(inode.ino(), node.clone());
            lowers.push(node.clone());
        }

        for addition in &self.additions {
            let addition_path = addition.get_rootfs();
            let mut _addition = addition.clone();
            _addition.path = addition_path.clone();
            if let Some(idx) = self.get_lower_idx(&lowers, _addition.path.clone()) {
                _addition.inode.set_ino(lowers[idx].inode.ino());
                _addition.inode.set_parent(lowers[idx].inode.parent());
                _addition.overlay = Overlay::UpperModification;
                lowers[idx] = _addition;
            } else if let Some(parent_path) = addition_path.parent() {
                if let Some(idx) = self.get_lower_idx(&lowers, parent_path.to_path_buf()) {
                    _addition.inode.set_parent(lowers[idx].inode.ino());
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
                "{} {} {:?} inode {}, parent {}",
                lower.overlay,
                lower.get_type(),
                lower.path,
                lower.inode.ino(),
                lower.inode.parent(),
            );
            if lower.overlay != Overlay::UpperRemoval && lower.overlay != Overlay::UpperOpaque {
                lower.dump_bootstrap(&mut self.f_bootstrap, 0)?;
            }
        }

        Ok(())
    }

    fn fill_blob_id(&mut self) {
        for node in &mut self.additions {
            for chunk in &mut node.chunks {
                chunk.set_blob_index(0);
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

        root_node.inode.set_ino(1);
        self.inode_map
            .insert(root_node.inode.ino(), root_node.clone());
        self.additions.push(root_node);

        while !dirs.is_empty() {
            let mut next_dirs = Vec::new();

            for dir_idx in &dirs {
                let dir_node = self.additions.get_mut(*dir_idx).unwrap();
                let childs = fs::read_dir(&dir_node.path)?;
                let dir_ino = dir_node.inode.ino();
                let mut child_count: usize = 0;

                dir_node.inode.set_child_index((ino + 1) as u32);

                for child in childs {
                    let entry = &child?;
                    let path = entry.path();
                    let mut node = self.new_node(&path);
                    node.build_inode(None)?;

                    ino += 1;
                    child_count += 1;
                    node.inode.set_ino(ino);
                    node.inode.set_parent(dir_ino);

                    if node.is_dir() && !node.is_symlink() {
                        next_dirs.push(self.additions.len());
                    }
                    self.inode_map.insert(node.inode.ino(), node.clone());
                    self.additions.push(node);
                }

                let dir_node = self.additions.get_mut(*dir_idx).unwrap();
                dir_node.inode.set_child_count(child_count as u32);
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
            inode_table.set(node.inode.ino(), inode_offset)?;
            inode_offset += RAFS_INODE_INFO_SIZE as u32;
            node.dump_blob(&mut self.f_blob, &mut self.blob_hash)?;
            inode_offset += (node.chunks.len() * RAFS_CHUNK_INFO_SIZE) as u32;
            if let Some(link_chunk) = &node.link_chunk {
                inode_offset += link_chunk.size() as u32;
            }
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Result;

    #[test]
    fn test_builder() -> Result<()> {
        let f_blob = Box::new(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open("/home/imeoer/blob")?,
        );
        let f_bootstrap = Box::new(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open("/home/imeoer/bootstrap")?,
        );

        let mut builder = super::Builder {
            root: PathBuf::from("/home/imeoer/parent"),
            f_blob,
            f_bootstrap,
            f_parent_bootstrap: None,
            blob_offset: 0,
            blob_id: String::from(""),
            blob_hash: Sha256::new(),
            inode_map: HashMap::new(),
            additions: Vec::new(),
            removals: HashMap::new(),
            opaques: HashMap::new(),
        };
        builder.build()?;

        let f_bootstrap = Box::new(
            OpenOptions::new()
                .write(false)
                .create(false)
                .read(true)
                .open("/home/imeoer/bootstrap")?,
        );

        let mut f_bootstrap: Box<dyn RafsIoRead> = f_bootstrap;
        let mut super_block = RafsSuper::new();
        super_block.load(&mut f_bootstrap).unwrap();

        for i in 1..15 {
            let inode = super_block.get_inode(i)?;
            if inode.is_symlink() {
                let link = super_block.get_symlink(inode)?;
                println!("link {:?}", link.to_str()?);
            }
            println!("inode {:?} {} {}", inode.name(), inode.size(), inode.ino());
        }

        Ok(())
    }
}
