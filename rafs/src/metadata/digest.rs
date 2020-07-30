// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Structs for RAFS digest algorithm.

use std::fmt;

use sha2::digest::Digest;
use sha2::Sha256;

use crate::metadata::RAFS_DIGEST_LENGTH;

type DigestData = [u8; RAFS_DIGEST_LENGTH];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    Blake3 = 0,
    Sha256 = 1,
}

pub trait DigestHasher {
    fn digest_update(&mut self, buf: &[u8]);
    fn digest_finalize(&mut self) -> RafsDigest;
}

impl DigestHasher for blake3::Hasher {
    fn digest_update(&mut self, buf: &[u8]) {
        self.update(buf);
    }
    fn digest_finalize(&mut self) -> RafsDigest {
        RafsDigest {
            data: self.clone().finalize().into(),
        }
    }
}

impl DigestHasher for Sha256 {
    fn digest_update(&mut self, buf: &[u8]) {
        self.update(buf);
    }
    fn digest_finalize(&mut self) -> RafsDigest {
        RafsDigest {
            data: self.clone().finalize().into(),
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub struct RafsDigest {
    pub data: DigestData,
}

impl RafsDigest {
    pub fn from_buf(buf: &[u8], algorithm: DigestAlgorithm) -> Self {
        let data: DigestData = match algorithm {
            DigestAlgorithm::Blake3 => blake3::hash(buf).into(),
            DigestAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(buf);
                hasher.finalize().into()
            }
        };

        RafsDigest { data }
    }
    pub fn hasher(algorithm: DigestAlgorithm) -> Box<dyn DigestHasher> {
        match algorithm {
            DigestAlgorithm::Blake3 => Box::new(blake3::Hasher::new()) as Box<dyn DigestHasher>,
            DigestAlgorithm::Sha256 => Box::new(Sha256::new()) as Box<dyn DigestHasher>,
        }
    }
    pub fn size(&self) -> usize {
        RAFS_DIGEST_LENGTH
    }
}

impl Default for RafsDigest {
    fn default() -> Self {
        Self {
            data: [0u8; RAFS_DIGEST_LENGTH],
        }
    }
}

impl From<DigestData> for RafsDigest {
    fn from(data: DigestData) -> Self {
        Self { data }
    }
}

impl AsRef<[u8]> for RafsDigest {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl fmt::Display for RafsDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in &self.data {
            write!(f, "{:02x}", c).unwrap()
        }
        Ok(())
    }
}

impl Into<String> for RafsDigest {
    fn into(self) -> String {
        format!("{}", self)
    }
}
