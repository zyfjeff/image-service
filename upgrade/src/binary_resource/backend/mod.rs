// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

pub mod shared_memory;

use std::io::{Read, Result, Write};

pub trait Backend: Sync + Send {
    fn reset(&mut self) -> Result<()>;
    fn reader(&mut self) -> Result<&mut dyn Read>;
    fn writer(&mut self) -> Result<&mut dyn Write>;
    // This method will not be used in real scenarios, the Backend is
    // only responsible for read/write data, garage collection
    // for storage will be done on nydus control panel.
    fn destroy(&mut self) -> Result<()>;
}

#[derive(Hash, PartialEq, Eq)]
pub enum BackendType {
    SharedMemory,
}

impl Default for BackendType {
    fn default() -> Self {
        Self::SharedMemory
    }
}
