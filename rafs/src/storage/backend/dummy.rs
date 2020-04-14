// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::fs::File;
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
    type Reader = File;

    fn init(&mut self, _config: HashMap<&str, &str>) -> Result<()> {
        Ok(())
    }

    // Read a range of data from blob into the provided destination
    fn read(&self, _blobid: &str, buf: &mut Vec<u8>, _offset: u64, _count: usize) -> Result<usize> {
        Ok(buf.len())
    }

    // Write a range of data to blob from the provided source
    fn write(&self, _blobid: &str, buf: &Vec<u8>, _offset: u64) -> Result<usize> {
        Ok(buf.len())
    }

    // Write data to blob from the provided source, the impl provided progress callback
    fn write_r(
        &self,
        _blobid: &str,
        _src: File,
        size: usize,
        _callback: fn((usize, usize)),
    ) -> Result<usize> {
        Ok(size)
    }

    fn close(&mut self) {
        self.targets.write().unwrap().clear()
    }
}
