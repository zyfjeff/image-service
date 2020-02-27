// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::{self, DirEntry};
use std::io::Result;
use std::os::linux::fs::MetadataExt;
use std::path::Path;

use rafs::layout::RafsInodeInfo;

pub fn build(path: &str) -> Result<()> {
  walk_dirs(Path::new(path), &inspect_entry)
}

fn walk_dirs(dir: &Path, cb: &dyn Fn(&DirEntry) -> Result<()>) -> Result<()> {
  if dir.is_dir() {
    for entry in fs::read_dir(dir)? {
      let entry = entry?;
      let path = entry.path();
      cb(&entry)?;
      if path.is_dir() {
        walk_dirs(&path, cb)?;
      }
    }
  }
  Ok(())
}

fn inspect_entry(entry: &DirEntry) -> Result<()> {
  let meta = entry.metadata()?;

  let mut inode = RafsInodeInfo::new();
  // inode.name
  // inode.digest
  // inode.i_parent
  inode.i_ino = meta.st_ino();
  inode.i_mode = meta.st_mode();
  inode.i_uid = meta.st_uid();
  inode.i_gid = meta.st_gid();
  // inode.i_padding
  inode.i_rdev = meta.st_rdev();
  inode.i_size = meta.st_size();
  inode.i_nlink = meta.st_nlink();
  inode.i_blocks = meta.st_blocks();
  inode.i_atime = meta.st_atime() as u64;
  inode.i_mtime = meta.st_mtime() as u64;
  inode.i_ctime = meta.st_ctime() as u64;
  // inode.i_chunk_cnt
  inode.i_flags = 0;

  println!("{:?}", inode);
  Ok(())
}
