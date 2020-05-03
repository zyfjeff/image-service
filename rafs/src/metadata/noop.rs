// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A noop meta data driver for place-holding.

use std::io::Result;

use super::{RafsSuperInodes, RafsSuperMeta};
use crate::metadata::RafsInode;
use crate::RafsIoReader;

pub struct NoopInodes {}

impl NoopInodes {
    pub fn new() -> Self {
        NoopInodes {}
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
}
