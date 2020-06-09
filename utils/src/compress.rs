// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use lz4 as liblz4;
use std::borrow::Cow;
use std::convert::From;
use std::fmt;
use std::io::{Error, ErrorKind, Result};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Algorithm {
    None = 0,
    LZ4RatioDefault = 1,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "None" => Ok(Self::None),
            "LZ4RatioDefault" => Ok(Self::LZ4RatioDefault),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                "compression algorithm should be None or LZ4RatioDefault",
            )),
        }
    }
}

impl From<u8> for Algorithm {
    fn from(src: u8) -> Self {
        match src {
            1 => Self::LZ4RatioDefault,
            _ => Self::None,
        }
    }
}

impl Algorithm {
    pub fn is_none(&self) -> bool {
        self == &Self::None
    }
}

// compression format:
// 1. Default ratio
// 2. No prepend size

// For compatibility reason, we use liblz4 version to compress/decompress directly
// with data blocks so that we don't really care about lz4 header magic numbers like
// as being done with all these rust lz4 implementations
pub fn compress(src: &[u8], algorithm: Algorithm) -> Result<Cow<[u8]>> {
    match algorithm {
        Algorithm::None => Ok(Cow::Borrowed(src)),
        Algorithm::LZ4RatioDefault => {
            liblz4::block::compress(src, None, false).map(|r| Cow::Owned(r))
        }
    }
}

// Size must be provided otherwise the rust binding tries
// to guess the size as if it were prepended and fail
pub fn decompress(src: &[u8], blksize: u32) -> Result<Vec<u8>> {
    liblz4::block::decompress(src, Some(blksize as i32))
}
