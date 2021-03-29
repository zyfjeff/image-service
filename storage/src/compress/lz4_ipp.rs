// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! An optimized lz4 compress()/decompress() based Intell IPP library.
//!
//! The IPP library only works on Intel processors, so we need to manual choose this implementation.

use std::io::{Error, ErrorKind, Result};

use lz4_sys::{LZ4_compressBound, LZ4_compress_default};

type IppStatus = std::os::raw::c_int;
const IPP_STATUS_NO_ERR: std::os::raw::c_int = 0;

#[link(name = "ippdc", kind = "static")]
extern "C" {
    pub fn ippsDecodeLZ4_8u(
        pSrc: *const u8,
        srcLen: ::std::os::raw::c_int,
        pDst: *mut u8,
        pDstLen: *mut ::std::os::raw::c_int,
    ) -> IppStatus;
}

pub(super) fn lz4_compress(src: &[u8]) -> Result<Vec<u8>> {
    // 0 iff src too large
    let compress_bound: i32 = unsafe { LZ4_compressBound(src.len() as i32) };

    if src.len() > (i32::max_value() as usize) || compress_bound <= 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Compression input data is too big.",
        ));
    }

    let mut dst_buf = Vec::with_capacity(compress_bound as usize);
    let dec_size = unsafe {
        LZ4_compress_default(
            src.as_ptr() as *const i8,
            dst_buf.as_mut_ptr() as *mut i8,
            src.len() as i32,
            compress_bound,
        )
    };
    if dec_size <= 0 {
        return Err(Error::new(ErrorKind::Other, "Compression failed"));
    }

    assert!(dec_size as usize <= dst_buf.capacity());
    unsafe { dst_buf.set_len(dec_size as usize) };

    Ok(dst_buf)
}

pub(super) fn lz4_decompress(src: &[u8], dst: &mut [u8]) -> Result<usize> {
    if dst.len() >= std::i32::MAX as usize {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "the destination buffer is big than i32::MAX.",
        ));
    }
    let mut size = dst.len() as i32;

    if unsafe { lz4_sys::LZ4_compressBound(size) } <= 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Given size parameter is too big",
        ));
    }

    let result = unsafe {
        ippsDecodeLZ4_8u(
            src.as_ptr() as *const u8,
            src.len() as i32,
            dst.as_mut_ptr() as *mut u8,
            &mut size as *mut i32,
        )
    };

    if result != IPP_STATUS_NO_ERR as i32 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Decompression failed. Input invalid or too long?",
        ));
    }

    Ok(size as usize)
}
