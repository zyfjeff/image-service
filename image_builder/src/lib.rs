// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs;
use std::io::Result;
use std::os::linux::fs::MetadataExt;
use std::path::Path;

use rafs::layout::*;

struct Node<'a> {
  blob_id: &'a str,
  offset: u64,
  meta: &'a dyn MetadataExt,
  path: &'a str,
  parent: &'a Option<Box<Node<'a>>>,
  inode: RafsInodeInfo,
}

impl<'a> Node<'a> {
  fn new(
    blob_id: &'a str,
    offset: u64,
    meta: &'a dyn MetadataExt,
    path: &'a str,
    parent: &'a Option<Box<Node>>,
  ) -> Node<'a> {
    Node {
      blob_id,
      offset,
      meta,
      path,
      parent,
      inode: RafsInodeInfo::new(),
    }
  }
  fn build_inode(&mut self) -> Result<()> {
    println!("\tbuilding inode {}", self.meta.st_ino());
    if self.parent.is_none() {
      self.inode.i_parent = 0;
      self.inode.i_ino = 1;
      self.inode.i_mode = libc::S_IFDIR;
      return Ok(());
    }
    let file_name = Path::new(self.path).file_name().unwrap().to_str().unwrap();
    self.inode.name = String::from(file_name);
    // self.inode.digest
    let parent = self.parent.as_ref().unwrap();
    self.inode.i_parent = parent.inode.i_ino;
    self.inode.i_ino = self.meta.st_ino();
    self.inode.i_mode = self.meta.st_mode();
    self.inode.i_uid = self.meta.st_uid();
    self.inode.i_gid = self.meta.st_gid();
    self.inode.i_padding = 0;
    self.inode.i_rdev = self.meta.st_rdev();
    self.inode.i_size = self.meta.st_size();
    self.inode.i_nlink = self.meta.st_nlink();
    self.inode.i_blocks = self.meta.st_blocks();
    self.inode.i_atime = self.meta.st_atime() as u64;
    self.inode.i_mtime = self.meta.st_mtime() as u64;
    self.inode.i_ctime = self.meta.st_ctime() as u64;
    // self.inode.i_chunk_cnt
    // self.inode.i_flags = 0;
    Ok(())
  }
  fn build_chunk(&mut self) -> Result<()> {
    if self.inode.i_mode != libc::S_IFDIR {
      let file_size = self.inode.i_size;
      let chunk_count = (file_size as f64 / DEFAULT_RAFS_BLOCK_SIZE as f64).ceil() as u64;
      println!("\tbuilding chunk, count: {}", chunk_count);
      for i in 0..chunk_count {
        let mut chunk = RafsChunkInfo::new();
        // chunk.blockid
        chunk.blobid = String::from(self.blob_id);
        chunk.pos = (i * DEFAULT_RAFS_BLOCK_SIZE as u64) as u64;
        if i == chunk_count - 1 {
          chunk.len = (file_size % DEFAULT_RAFS_BLOCK_SIZE as u64) as u32;
        } else {
          chunk.len = DEFAULT_RAFS_BLOCK_SIZE as u32;
        }
        chunk.offset = self.offset;
        chunk.size = file_size as u32;
      }
    }
    Ok(())
  }
  fn build(&mut self) -> Result<()> {
    let mut file_type = "file";
    if self.meta.st_mode() & libc::S_IFDIR > 0 {
      file_type = "dir";
    }
    println!("building {} {}", file_type, self.path);
    self.build_inode()?;
    self.build_chunk()?;
    Ok(())
  }
}

pub struct Builder<'a> {
  root: &'a str,
  blob_offset: u64,
  blob_id: &'a str,
}

impl<'a> Builder<'a> {
  pub fn new(root: &'a str, blob_id: &'a str) -> Builder<'a> {
    Builder {
      root,
      blob_offset: 0,
      blob_id,
    }
  }
  fn build_superblock(&mut self) -> Result<RafsSuperBlockInfo> {
    println!("building superblock {}", self.root);
    let mut sb = RafsSuperBlockInfo::new();
    sb.s_inodes_count = 0;
    sb.s_blocks_count = 0;
    sb.s_inode_size = RAFS_INODE_INFO_SIZE as u16;
    sb.s_padding1 = 0;
    sb.s_block_size = DEFAULT_RAFS_BLOCK_SIZE as u32;
    sb.s_fs_version = RAFS_SUPER_VERSION as u16;
    sb.s_padding2 = 0;
    sb.s_magic = RAFS_SUPER_MAGIC;
    Ok(sb)
  }
  fn walk_dirs(&mut self, file: &Path, parent_node: &Option<Box<Node>>) -> Result<()> {
    if file.is_dir() {
      for entry in fs::read_dir(file)? {
        let entry = entry?;
        let path = entry.path();
        let meta = &entry.metadata()?;
        self.blob_offset = self.blob_offset + 1;
        let mut node = Node::new(
          self.blob_id,
          self.blob_offset,
          meta,
          path.to_str().unwrap(),
          parent_node,
        );
        node.build()?;
        if path.is_dir() {
          self.walk_dirs(&path, &Some(Box::new(node)))?;
        }
      }
    }
    Ok(())
  }
  pub fn build(&mut self) -> Result<()> {
    self.build_superblock()?;
    let root_path = Path::new(self.root);
    let root_meta = &root_path.metadata()?;
    self.blob_offset = self.blob_offset + 1;
    let mut root_node = Node::new(self.blob_id, self.blob_offset, root_meta, "/", &None);
    root_node.build()?;
    return self.walk_dirs(root_path, &Some(Box::new(root_node)));
  }
}
