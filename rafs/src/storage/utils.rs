use std::io::{Error, Result};
use std::os::unix::io::RawFd;

use libc::{c_int, c_void, off64_t, preadv64, size_t};
use vm_memory::VolatileSlice;

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

    let ret = unsafe { preadv64(fd, &iovecs[0], iovecs.len() as c_int, offset as off64_t) };
    if ret >= 0 {
        Ok(ret as usize)
    } else {
        Err(Error::last_os_error())
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
        s.copy_from(&src[offset..offset + len]);
        offset += len;
        size += len;
    }

    Ok(size)
}
