// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs;
use std::io::Result;
use std::os::linux::fs::MetadataExt;
use std::path::Path;

use rafs::layout::*;

struct Node<'a> {
  path: &'a str,
  parent: &'a Option<Box<Node<'a>>>,
  inode: RafsInodeInfo,
}

impl<'a> Node<'a> {
  fn new(path: &'a str, parent: &'a Option<Box<Node>>) -> Node<'a> {
    Node {
      path,
      parent,
      inode: RafsInodeInfo::new(),
    }
  }
  fn build_inode(&mut self, meta: &dyn MetadataExt) -> Result<()> {
    if self.parent.is_none() {
      self.inode.i_parent = 0;
      self.inode.i_ino = 1;
      self.inode.i_mode = libc::S_IFDIR;
      return Ok(());
    }
    self.inode.name = String::from(Path::new(self.path).file_name().unwrap().to_str().unwrap());
    // self.inode.digest
    let parent = self.parent.as_ref().unwrap();
    self.inode.i_parent = parent.inode.i_ino;
    self.inode.i_ino = meta.st_ino();
    self.inode.i_mode = meta.st_mode();
    self.inode.i_uid = meta.st_uid();
    self.inode.i_gid = meta.st_gid();
    self.inode.i_padding = 0;
    self.inode.i_rdev = meta.st_rdev();
    self.inode.i_size = meta.st_size();
    self.inode.i_nlink = meta.st_nlink();
    self.inode.i_blocks = meta.st_blocks();
    self.inode.i_atime = meta.st_atime() as u64;
    self.inode.i_mtime = meta.st_mtime() as u64;
    self.inode.i_ctime = meta.st_ctime() as u64;
    // self.inode.i_chunk_cnt
    // self.inode.i_flags = 0;
    Ok(())
  }
  fn build_chunk(&mut self) -> Result<()> {
    let _sb = RafsChunkInfo::new();
    Ok(())
  }
  fn build(&mut self, meta: &dyn MetadataExt) -> Result<()> {
    self.build_inode(meta)?;
    self.build_chunk()?;
    Ok(())
  }
}

pub struct Builder {
  root: String,
}

impl Builder {
  pub fn new(root: &str) -> Builder {
    Builder {
      root: root.to_owned(),
    }
  }
  fn build_superblock(&self) -> Result<RafsSuperBlockInfo> {
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
  fn walk_dirs(&self, file: &Path, parent_node: &Option<Box<Node>>) -> Result<()> {
    if file.is_dir() {
      for entry in fs::read_dir(file)? {
        let entry = entry?;
        let path = entry.path();
        let relative_path = format!(
          "/{}",
          path
            .strip_prefix(self.root.as_str())
            .unwrap()
            .to_str()
            .unwrap(),
        );
        println!("building {}", relative_path);
        let mut node = Node::new(relative_path.as_str(), parent_node);
        node.build(&entry.metadata()?)?;
        if path.is_dir() {
          self.walk_dirs(&path, &Some(Box::new(node)))?;
        }
      }
    }
    Ok(())
  }
  pub fn build(&self) -> Result<()> {
    self.build_superblock()?;
    let root_path = Path::new(self.root.as_str());
    let mut root_node = Node {
      path: "/",
      parent: &None,
      inode: RafsInodeInfo::new(),
    };
    root_node.build(&root_path.metadata()?)?;
    return self.walk_dirs(root_path, &Some(Box::new(root_node)));
  }
}
