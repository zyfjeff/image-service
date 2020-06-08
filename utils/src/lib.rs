// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "fusedev")]
#[macro_use]
extern crate log;
#[cfg(feature = "fusedev")]
pub mod fuse;
#[cfg(feature = "fusedev")]
pub use self::fuse::{FuseChannel, FuseSession};

pub mod compress;

pub fn log_level_to_verbosity(level: log::LevelFilter) -> usize {
    level as usize - 1
}

pub fn div_round_up(n: u64, d: u64) -> u64 {
    (n + d - 1) / d
}

/// A customized readahead function to ask kernel to fault in all pages
/// from offset to end. Call libc::readahead on every 128KB range because
/// otherwise readahead stops at kernel bdi readahead size which is 128KB
/// by default.
pub fn readahead(fd: libc::c_int, mut offset: u64, end: u64) {
    // Kernel default 128KB readahead size
    let count = 128 << 10;
    loop {
        if offset >= end {
            break;
        }
        unsafe { libc::readahead(fd, offset as i64, count) };
        offset += count as u64;
    }
}
