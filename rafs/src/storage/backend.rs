// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::io::{Read, Result, Write};

use fuse::filesystem::{ZeroCopyReader, ZeroCopyWriter};

// Rafs blob backend API. To be specific, each backend
// must properly implement read_at_volatile and write_at_volatile
// methods of FileReadWriteVolatile trait.
pub trait BlobBackend {
    // Initialize the blob backend
    // Each backend should define its own config type
    fn init(&self, config: HashMap<&str, &str>) -> Result<()>;

    // Add a blob to the backend
    fn add(&mut self, blobid: &str) -> Result<()>;

    // Read a range of data from blob into the provided writer
    fn read_to<W: Write + ZeroCopyWriter>(
        &self,
        w: W,
        blobid: &str,
        count: usize,
        offset: u64,
    ) -> Result<usize>;

    // Write a range of data to blob from the provided reader
    fn write_from<R: Read + ZeroCopyReader>(
        &self,
        r: R,
        blobid: &str,
        count: usize,
        offset: u64,
    ) -> Result<usize>;

    // Delete a blob
    fn delete(&mut self, blobid: &str) -> Result<()>;

    // Close a backend
    fn close(&mut self);
}
