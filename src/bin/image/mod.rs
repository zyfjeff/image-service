// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs;
use std::io::Result;
use std::os::linux::fs::MetadataExt;
use std::path::Path;

use rafs::layout::RafsInodeInfo;

pub struct Builder {
  root: String,
}

fn inspect(path: &str, meta: &dyn MetadataExt) -> Result<()> {
  println!("{}", path);
  let mut inode = RafsInodeInfo::new();
  inode.name = String::from(path);
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

  // println!("{:?}", inode);
  Ok(())
}

impl Builder {
  pub fn new(root: &str) -> Builder {
    Builder {
      root: root.to_owned(),
    }
  }
  fn walk_dirs(
    &self,
    file: &Path,
    cb: &dyn Fn(&str, &dyn MetadataExt) -> Result<()>,
  ) -> Result<()> {
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
        cb(relative_path.as_str(), &entry.metadata()?)?;
        if path.is_dir() {
          self.walk_dirs(&path, cb)?;
        }
      }
    }
    Ok(())
  }
  pub fn build(&self) -> Result<()> {
    let root_path = Path::new(self.root.as_str());
    inspect("/", &fs::metadata(root_path)?)?;
    self.walk_dirs(root_path, &inspect)
  }
}
