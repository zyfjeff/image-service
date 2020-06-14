// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::convert::From;
use std::fmt;
use std::io::{Error, ErrorKind, Result};
use std::str::FromStr;

use lz4 as liblz4;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Algorithm {
    None = 0,
    LZ4Block = 1,
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
            "none" => Ok(Self::None),
            "lz4_block" => Ok(Self::LZ4Block),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                "compression algorithm should be none or lz4_block",
            )),
        }
    }
}

impl From<&u8> for Algorithm {
    fn from(src: &u8) -> Self {
        match *src {
            1 => Self::LZ4Block,
            _ => Self::None,
        }
    }
}

impl Algorithm {
    pub fn is_none(self) -> bool {
        self == Self::None
    }
}

// Algorithm::LZ4Block:
// 1. Default ratio
// 2. No prepend size

// For compatibility reason, we use liblz4 version to compress/decompress directly
// with data blocks so that we don't really care about lz4 header magic numbers like
// as being done with all these rust lz4 implementations
pub fn compress(src: &[u8], algorithm: Algorithm) -> Result<Cow<[u8]>> {
    match algorithm {
        Algorithm::None => Ok(Cow::Borrowed(src)),
        Algorithm::LZ4Block => liblz4::block::compress(src, None, false).map(Cow::Owned),
    }
}

pub fn decompress(src: &[u8], dst: &mut [u8]) -> Result<usize> {
    if dst.len() >= std::i32::MAX as usize {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "the destination buffer is big than i32::MAX.",
        ));
    }
    let size = dst.len() as i32;

    if unsafe { lz4_sys::LZ4_compressBound(size) } <= 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Given size parameter is too big",
        ));
    }

    let dec_bytes = unsafe {
        lz4_sys::LZ4_decompress_safe(
            src.as_ptr() as *const i8,
            dst.as_mut_ptr() as *mut i8,
            src.len() as i32,
            size,
        )
    };

    if dec_bytes < 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Decompression failed. Input invalid or too long?",
        ));
    }

    Ok(dec_bytes as usize)
}
