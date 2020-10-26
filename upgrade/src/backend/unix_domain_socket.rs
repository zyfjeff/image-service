// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::io::Result;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use nydus_utils::{einval, last_error};
use sendfd::{RecvWithFd, SendWithFd};

use crate::backend::Backend;

// UdsBackend is responsible for sending fd to a remote server, or receiving fd
// from a remote server to save and restore fd via the unix domain socket (uds) server path.
// It is also allowed to carry opaque data when sending fd or receiving fd.
pub struct UdsBackend {
    uds_path: PathBuf,
}

impl UdsBackend {
    pub fn new(uds_path: PathBuf) -> Self {
        Self { uds_path }
    }
}

impl Backend for UdsBackend {
    fn save(&mut self, fds: &[RawFd], opaque: &[u8]) -> Result<usize> {
        if fds.is_empty() {
            return Err(einval!("fd haven't be added to resource"));
        }

        let stream = UnixStream::connect(&self.uds_path).map_err(|err| {
            error!("connect to {:?} failed: {:?}", &self.uds_path, err);
            err
        })?;
        stream
            .send_with_fd(opaque, &fds)
            .map_err(|e| last_error!(e))
    }

    fn restore(
        &mut self,
        mut fds: &mut Vec<RawFd>,
        mut opaque: &mut Vec<u8>,
    ) -> Result<(usize, usize)> {
        let stream = UnixStream::connect(&self.uds_path).map_err(|err| {
            error!("connect to {:?} failed: {:?}", &self.uds_path, err);
            err
        })?;

        let (opaque_size, fd_count) = stream
            .recv_with_fd(&mut opaque, &mut fds)
            .map_err(|e| last_error!(e))?;

        if fd_count < 1 {
            return Err(einval!("fd not found in sock stream"));
        }

        Ok((opaque_size, fd_count))
    }

    fn destroy(&mut self) -> Result<()> {
        Ok(())
    }
}
