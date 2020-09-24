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
    fn destroy(&mut self) -> Result<()>;
}

#[derive(Hash, PartialEq, Eq)]
pub enum BackendType {
    SharedMemory,
}
