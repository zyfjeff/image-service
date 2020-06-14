// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::alloc::Layout;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::io::RawFd;

use libc::{c_int, c_void, off64_t, preadv64, size_t};
use vm_memory::{Bytes, VolatileSlice};

pub fn readv(fd: RawFd, bufs: &[VolatileSlice], offset: u64, max_size: usize) -> Result<usize> {
    let mut size: usize = 0;
    let iovecs: Vec<libc::iovec> = bufs
        .iter()
        .map(|s| {
            let len = if size + s.len() > max_size {
                max_size - size
            } else {
                s.len()
            };
            size += s.len();
            libc::iovec {
                iov_base: s.as_ptr() as *mut c_void,
                iov_len: len as size_t,
            }
        })
        .collect();

    if iovecs.is_empty() {
        return Ok(0);
    }

    loop {
        let ret = unsafe { preadv64(fd, &iovecs[0], iovecs.len() as c_int, offset as off64_t) };
        if ret >= 0 {
            return Ok(ret as usize);
        }

        let err = Error::last_os_error();
        // Retry if the IO is interrupted by signal.
        if err.kind() != ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

pub fn copyv(src: &[u8], dst: &[VolatileSlice], offset: u64, max_size: usize) -> Result<usize> {
    let mut offset = offset as usize;
    let mut size: usize = 0;

    for s in dst.iter() {
        let len = if size + s.len() > max_size {
            max_size - size
        } else {
            s.len()
        };
        s.write_slice(&src[offset..offset + len], 0).map_err(|_| {
            Error::new(
                std::io::ErrorKind::Other,
                "Decompression failed. Input invalid or too long?",
            )
        })?;
        offset += len;
        size += len;
    }

    Ok(size)
}

/// A customized readahead function to ask kernel to fault in all pages from offset to end.
///
/// Call libc::readahead on every 128KB range because otherwise readahead stops at kernel bdi
/// readahead size which is 128KB by default.
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

pub struct DataBuf {
    layout: Layout,
    size: usize,
    ptr: *mut u8,
}

impl DataBuf {
    pub fn alloc(size: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(size, 8).unwrap();
        let ptr = unsafe { std::alloc::alloc(layout) };

        DataBuf { size, ptr, layout }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size) }
    }
}

impl Drop for DataBuf {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                std::alloc::dealloc(self.ptr, self.layout);
            }
            self.ptr = std::ptr::null_mut();
        }
    }
}
