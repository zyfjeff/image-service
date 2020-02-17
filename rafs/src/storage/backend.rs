// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::io::Result;

#[derive(Debug)]
pub enum BackendType {
    DummyBackendType,
}

impl Default for BackendType {
    fn default() -> Self {
        BackendType::DummyBackendType
    }
}

impl Copy for BackendType {}

impl Clone for BackendType {
    fn clone(&self) -> Self {
        *self
    }
}

// Rafs blob backend API
pub trait BlobBackend {
    // Initialize the blob backend
    // Each backend should define its own config type
    fn init(&mut self, config: HashMap<&str, &str>) -> Result<()>;

    // Read a range of data from blob into the provided slice
    fn read(&self, blobid: &str, buf: &mut Vec<u8>, offset: u64) -> Result<usize>;

    // Write a range of data to blob from the provided slice
    fn write(&self, blobid: &str, buf: &Vec<u8>, offset: u64) -> Result<usize>;

    // Close a backend
    fn close(&mut self);
}
