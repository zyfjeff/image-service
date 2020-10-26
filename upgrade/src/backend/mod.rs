// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

pub mod shared_memory;
pub mod unix_domain_socket;

use std::io::Result;
use std::os::unix::io::RawFd;

pub trait Backend: Sync + Send {
    fn save(&mut self, fds: &[RawFd], opaque: &[u8]) -> Result<usize>;
    fn restore(&mut self, fds: &mut Vec<RawFd>, opaque: &mut Vec<u8>) -> Result<(usize, usize)>;
    // This method will not be used in real scenarios, the Backend is
    // only responsible for read/write data, garage collection
    // for storage will be done on nydus control panel.
    fn destroy(&mut self) -> Result<()>;
}

#[derive(Hash, PartialEq, Eq)]
pub enum BackendType {
    SharedMemory,
    UdsBackend,
}

impl Default for BackendType {
    fn default() -> Self {
        Self::UdsBackend
    }
}
