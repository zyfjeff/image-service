// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::io::Result;
use std::sync::{Arc, Mutex, RwLock};

use crate::storage::backend::BlobBackend;

#[derive(Default, Clone)]
struct DummyTarget {
    path: String,
}

impl DummyTarget {
    fn new(blobid: &str) -> DummyTarget {
        DummyTarget {
            path: blobid.to_owned(),
        }
    }
}

pub struct Dummy {
    targets: RwLock<HashMap<String, Arc<Mutex<DummyTarget>>>>,
}

pub fn new() -> Dummy {
    Dummy {
        targets: RwLock::new(HashMap::new()),
    }
}

impl BlobBackend for Dummy {
    fn init(&mut self, _config: HashMap<String, String>) -> Result<()> {
        Ok(())
    }

    // Read a range of data from blob into the provided destination
    fn read(&self, _blobid: &str, buf: &mut Vec<u8>, _offset: u64, _count: usize) -> Result<usize> {
        Ok(buf.len())
    }

    // Write a range of data to blob from the provided source
    fn write(&self, _blobid: &str, buf: &[u8], _offset: u64) -> Result<usize> {
        Ok(buf.len())
    }

    fn close(&mut self) {
        self.targets.write().unwrap().clear()
    }
}
