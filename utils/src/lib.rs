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

pub fn log_level_to_verbosity(level: log::LevelFilter) -> usize {
    level as usize - 1
}

pub fn div_round_up(n: u64, d: u64) -> u64 {
    (n + d - 1) / d
}
