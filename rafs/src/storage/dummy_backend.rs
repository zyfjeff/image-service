// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::ops::DerefMut;
use std::sync::{Arc, Mutex, RwLock};

use vm_memory::VolatileSlice;

use crate::storage::backend::BlobBackend;
use fuse::filesystem::{ZeroCopyReader, ZeroCopyWriter};
use vhost_rs::descriptor_utils::FileReadWriteVolatile;

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

impl FileReadWriteVolatile for DummyTarget {
    fn read_volatile(&mut self, slice: VolatileSlice) -> Result<usize> {
        Ok(slice.len())
    }

    fn write_volatile(&mut self, slice: VolatileSlice) -> Result<usize> {
        Ok(slice.len())
    }

    fn read_at_volatile(&mut self, slice: VolatileSlice, _offset: u64) -> Result<usize> {
        Ok(slice.len())
    }

    fn write_at_volatile(&mut self, slice: VolatileSlice, _offset: u64) -> Result<usize> {
        Ok(slice.len())
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
    fn init(&self, _config: HashMap<&str, &str>) -> Result<()> {
        Ok(())
    }

    fn add(&mut self, blobid: &str) -> Result<()> {
        match self.targets.read().unwrap().get(blobid) {
            Some(_) => Ok(()),
            _ => {
                self.targets.write().unwrap().insert(
                    blobid.to_owned(),
                    Arc::new(Mutex::new(DummyTarget::new(blobid))),
                );
                Ok(())
            }
        }
    }

    fn read_to<W: Write + ZeroCopyWriter>(
        &self,
        mut w: W,
        blobid: &str,
        count: usize,
        offset: u64,
    ) -> Result<usize> {
        let target = self
            .targets
            .read()
            .unwrap()
            .get(blobid)
            .map(Arc::clone)
            .ok_or(Error::from(ErrorKind::NotFound))?;

        let mut blob = target.lock().unwrap();
        w.write_from(&mut blob.deref_mut(), count, offset)
    }

    fn write_from<R: Read + ZeroCopyReader>(
        &self,
        mut r: R,
        blobid: &str,
        count: usize,
        offset: u64,
    ) -> Result<usize> {
        let target = self
            .targets
            .read()
            .unwrap()
            .get(blobid)
            .map(Arc::clone)
            .ok_or(Error::from(ErrorKind::NotFound))?;

        let mut blob = target.lock().unwrap();
        r.read_to(&mut blob.deref_mut(), count, offset)
    }

    fn delete(&mut self, blobid: &str) -> Result<()> {
        self.targets.write().unwrap().remove(blobid);
        Ok(())
    }

    fn close(&mut self) {
        self.targets.write().unwrap().clear()
    }
}
