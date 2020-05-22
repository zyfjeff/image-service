// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A noop meta data driver for place-holding.

use std::io::Result;

use super::*;
use crate::metadata::RafsInode;
use crate::RafsIoReader;

pub struct NoopInodes {}

impl Default for NoopInodes {
    fn default() -> Self {
        Self {}
    }
}

impl NoopInodes {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RafsSuperInodes for NoopInodes {
    fn load(&mut self, _sb: &mut RafsSuperMeta, _r: &mut RafsIoReader) -> Result<()> {
        unimplemented!()
    }

    fn destroy(&mut self) {}

    fn get_inode(&self, _ino: u64) -> Result<&dyn RafsInode> {
        unimplemented!()
    }

    fn get_blob_id<'a>(&'a self, _index: u32) -> Result<&'a OndiskDigest> {
        unimplemented!()
    }

    fn get_chunk_info(&self, _inode: &dyn RafsInode, _idx: u64) -> Result<&OndiskChunkInfo> {
        unimplemented!()
    }

    fn get_symlink(&self, _inode: &dyn RafsInode) -> Result<OndiskSymlinkInfo> {
        unimplemented!()
    }
}
