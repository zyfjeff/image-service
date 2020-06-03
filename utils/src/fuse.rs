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
use nix::unistd::{close, getgid, getuid, read};
use nix::Error as nixError;

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
    dev: File,
    bufsize: usize,
    exited: bool,
}

impl FuseSession {
    /// create a new fuse session
    pub fn new(mountpoint: &Path, fsname: &str, subtype: &str) -> io::Result<FuseSession> {
        let dest = mountpoint.canonicalize()?;
        if !dest.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a directory", dest.to_str().unwrap()),
            ));
        }
        let file = fuse_kern_mount(
            &dest,
            fsname,
            subtype,
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        )?;
        Ok(FuseSession {
            mountpoint: dest,
            fsname: fsname.to_owned(),
            subtype: subtype.to_owned(),
            dev: file,
            bufsize: FUSE_KERN_BUF_SIZE * pagesize() + FUSE_HEADER_SIZE,
            exited: false,
        })
    }

    /// destroy a fuse session
    pub fn umount(&mut self) -> io::Result<()> {
        if self.exited {
            return Ok(());
        }
        // Safe because no one else is accessing mnt, and fd closing
        // race is handled inside fuse_kern_umount
        fuse_kern_umount(self.mountpoint.to_str().unwrap(), self.dev.as_raw_fd())?;
        self.exited = true;
        Ok(())
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
    pub fn new_channel(&self) -> FuseChannel {
        FuseChannel::new(self.dev.as_raw_fd(), self.bufsize)
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
                        Reader::new(FuseBuf::new(&mut buf[..len]))
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
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
                    return Err(io::Error::new(io::ErrorKind::Other, e));
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
        "mount source {} dest {} with fstype {} opts {}",
        fsname,
        mountpoint.to_str().unwrap(),
        fstype,
        opts
    );
    mount(
        Some(fsname),
        mountpoint,
        Some(fstype.deref()),
        flags,
        Some(opts.deref()),
    )
    .map_err(|e| {
        error!("mount failed: {:}", e);
        io::Error::new(io::ErrorKind::Other, e)
    })?;
    Ok(file)
}

/// Umount a fuse file system
fn fuse_kern_umount(mountpoint: &str, fd: c_int) -> io::Result<()> {
    let pfd = PollFd::new(fd, PollFlags::empty());
    if poll(&mut [pfd], 0).is_err() {
        // POLLERR means the file system is already umounted,
        // or the connection was severed via /sys/fs/fuse/connections/NNN/abort
        if let Some(event) = pfd.revents() {
            if event == PollFlags::POLLERR {
                // always ensure fd is closed.
                let _ = close(fd);
                return Ok(());
            }
        }
    }
    // Need to close fd, otherwise synchronous umount
    // can recurse into filesystem and deadlock.
    let _ = close(fd);
    umount2(mountpoint, MntFlags::MNT_DETACH).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}
