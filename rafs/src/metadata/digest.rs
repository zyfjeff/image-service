// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Structs for RAFS digest algorithm.

use std::fmt;
use std::fmt::Write;

use crate::metadata::layout::OndiskDigest;
use crate::metadata::RAFS_DIGEST_LENGTH;

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub struct RafsDigest {
    pub result: blake3::Hash,
}

impl RafsDigest {
    pub fn from_buf(buf: &[u8]) -> Self {
        Self {
            result: blake3::hash(buf),
        }
    }
    pub fn size(&self) -> usize {
        RAFS_DIGEST_LENGTH
    }
    pub fn hasher() -> blake3::Hasher {
        blake3::Hasher::new()
    }
    pub fn finalize(hasher: blake3::Hasher) -> Self {
        Self {
            result: hasher.finalize(),
        }
    }
}

impl Default for RafsDigest {
    fn default() -> Self {
        Self::from_buf(&[])
    }
}

impl Into<String> for RafsDigest {
    fn into(self) -> String {
        let mut ret = String::new();
        for c in self.result.as_bytes() {
            write!(ret, "{:02x}", c).unwrap();
        }
        ret
    }
}

impl From<OndiskDigest> for RafsDigest {
    fn from(digest: OndiskDigest) -> Self {
        RafsDigest {
            result: digest.data.into(),
        }
    }
}

impl AsRef<[u8]> for RafsDigest {
    fn as_ref(&self) -> &[u8] {
        self.result.as_bytes()
    }
}

impl fmt::Display for RafsDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.result.as_bytes() {
            write!(f, "{:02x}", c).unwrap()
        }
        Ok(())
    }
}
