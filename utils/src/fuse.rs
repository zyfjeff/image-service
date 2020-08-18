// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Deref;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use libc::{c_int, sysconf, _SC_PAGESIZE};
use nix::errno::Errno;
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::poll::{poll, PollFd, PollFlags};
use nix::unistd::{getgid, getuid, read};
use nix::Error as nixError;

use crate::error::*;

use fuse_rs::transport::{FuseBuf, Reader, Writer};

/// These follows definition from libfuse
const FUSE_KERN_BUF_SIZE: usize = 32;
const FUSE_HEADER_SIZE: usize = 0x1000;

const FUSE_DEVICE: &str = "/dev/fuse";
const FUSE_FSTYPE: &str = "fuse";

/// A fuse session representation
pub struct FuseSession {
    mountpoint: PathBuf,
    fsname: String,
    subtype: String,
    file: Option<File>,
    bufsize: usize,
}

impl FuseSession {
    /// create a new fuse session
    pub fn new(
        mountpoint: &Path,
        fsname: &str,
        subtype: &str,
        readonly: bool,
    ) -> io::Result<FuseSession> {
        let dest = mountpoint.canonicalize()?;
        if !dest.is_dir() {
            return Err(einval!(format!(
                "{} is not a directory",
                dest.to_str().unwrap()
            )));
        }
        let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOATIME;
        if readonly {
            flags |= MsFlags::MS_RDONLY;
        }
        let file = fuse_kern_mount(&dest, fsname, subtype, flags)?;
        Ok(FuseSession {
            mountpoint: dest,
            fsname: fsname.to_owned(),
            subtype: subtype.to_owned(),
            file: Some(file),
            bufsize: FUSE_KERN_BUF_SIZE * pagesize() + FUSE_HEADER_SIZE,
        })
    }

    /// destroy a fuse session
    pub fn umount(&mut self) -> io::Result<()> {
        if self.file.is_none() {
            return Ok(());
        }

        fuse_kern_umount(self.mountpoint.to_str().unwrap(), self.file.take().unwrap())
    }

    /// return the mountpoint
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// return the fsname
    pub fn fsname(&self) -> &str {
        &self.fsname
    }

    /// return the subtype
    pub fn subtype(&self) -> &str {
        &self.subtype
    }

    /// return the default buffer size
    pub fn bufsize(&self) -> usize {
        self.bufsize
    }

    /// create a new fuse message channel
    pub fn new_channel(&self) -> io::Result<FuseChannel> {
        if let Some(file) = &self.file {
            Ok(FuseChannel::new(file.as_raw_fd(), self.bufsize))
        } else {
            Err(einval!("invalid fuse session"))
        }
    }
}

impl Drop for FuseSession {
    fn drop(&mut self) {
        let _ = self.umount();
    }
}

pub struct FuseChannel {
    fd: c_int,
    bufsize: usize,
    // XXX: Ideally we should have write buffer as well
    // write_buf: Vec<u8>,
}

impl FuseChannel {
    fn new(fd: c_int, bufsize: usize) -> Self {
        FuseChannel { fd, bufsize }
    }

    pub fn get_reader<'b>(&self, buf: &'b mut Vec<u8>) -> io::Result<Option<Reader<'b>>> {
        loop {
            match read(self.fd, buf.as_mut_slice()) {
                Ok(len) => {
                    return Ok(Some(
                        Reader::new(FuseBuf::new(&mut buf[..len])).map_err(|e| eother!(e))?,
                    ));
                }
                Err(nixError::Sys(e)) => match e {
                    Errno::ENOENT => {
                        // ENOENT means the operation was interrupted, it's safe
                        // to restart
                        trace!("restart reading");
                        continue;
                    }
                    Errno::ENODEV => {
                        info!("fuse filesystem umounted");
                        return Ok(None);
                    }
                    e => {
                        warn! {"read fuse dev failed on fd {}: {}", self.fd, e};
                        return Err(io::Error::from_raw_os_error(e as i32));
                    }
                },
                Err(e) => {
                    return Err(eother!(e));
                }
            };
        }
    }

    pub fn get_writer(&self) -> io::Result<Writer> {
        Ok(Writer::new(self.fd, self.bufsize).unwrap())
    }
}

/// Safe wrapper for `sysconf(_SC_PAGESIZE)`.
#[inline(always)]
fn pagesize() -> usize {
    // Trivially safe
    unsafe { sysconf(_SC_PAGESIZE) as usize }
}

/// Mount a fuse file system
fn fuse_kern_mount(
    mountpoint: &Path,
    fsname: &str,
    subtype: &str,
    flags: MsFlags,
) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(false)
        .read(true)
        .write(true)
        .open(FUSE_DEVICE)?;
    let meta = mountpoint.metadata()?;
    let opts = format!(
        "default_permissions,allow_other,fd={},rootmode={:o},user_id={},group_id={}",
        file.as_raw_fd(),
        meta.permissions().mode() & libc::S_IFMT,
        getuid(),
        getgid(),
    );
    let mut fstype = String::from(FUSE_FSTYPE);
    if !subtype.is_empty() {
        fstype.push_str(".");
        fstype.push_str(subtype);
    }

    info!(
        "mount source {} dest {} with fstype {} opts {} fd {}",
        fsname,
        mountpoint.to_str().unwrap(),
        fstype,
        opts,
        file.as_raw_fd(),
    );
    mount(
        Some(fsname),
        mountpoint,
        Some(fstype.deref()),
        flags,
        Some(opts.deref()),
    )
    .map_err(|e| eother!(format!("mount failed: {:}", e)))?;
    Ok(file)
}

/// Umount a fuse file system
fn fuse_kern_umount(mountpoint: &str, file: File) -> io::Result<()> {
    let mut fds = [PollFd::new(file.as_raw_fd(), PollFlags::empty())];
    let res = poll(&mut fds, 0);

    // Drop to close fuse session fd, otherwise synchronous umount
    // can recurse into filesystem and deadlock.
    drop(file);

    if res.is_ok() {
        // POLLERR means the file system is already umounted,
        // or the connection was severed via /sys/fs/fuse/connections/NNN/abort
        if let Some(event) = fds[0].revents() {
            if event == PollFlags::POLLERR {
                return Ok(());
            }
        }
    }

    umount2(mountpoint, MntFlags::MNT_DETACH).map_err(|e| eother!(e))
}
