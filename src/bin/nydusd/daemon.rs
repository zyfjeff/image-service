// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#[cfg(feature = "virtiofsd")]
use fuse_rs::transport::Error as FuseTransportError;
use fuse_rs::Error as VhostUserFsError;
use nydus_utils::einval;
use std::io::Result;
use std::{convert, error, fmt, io};

pub trait NydusDaemon {
    fn start(&mut self, cnt: u32) -> Result<()>;
    fn wait(&mut self) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    /// Invalid arguments provided.
    InvalidArguments(String),
    /// Invalid config provided
    InvalidConfig(String),
    /// Failed to handle event other than input event.
    HandleEventNotEpollIn,
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
    /// No memory configured.
    NoMemoryConfigured,
    /// Invalid Virtio descriptor chain.
    #[cfg(feature = "virtiofsd")]
    InvalidDescriptorChain(FuseTransportError),
    /// Processing queue failed.
    ProcessQueue(VhostUserFsError),
    /// Cannot create epoll context.
    Epoll(io::Error),
    /// Cannot clone event fd.
    EventFdClone(io::Error),
    /// Cannot spawn a new thread
    ThreadSpawn(io::Error),
    /// Failure to initialize file system
    FsInitFailure(io::Error),
    /// Daemon related error
    DaemonFailure(String),
    /// Wait daemon failure
    WaitDaemon,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidArguments(s) => write!(f, "Invalid argument: {}", s),
            Error::InvalidConfig(s) => write!(f, "Invalid config: {}", s),
            Error::DaemonFailure(s) => write!(f, "Daemon error: {}", s),
            _ => write!(f, "vhost_user_fs_error: {:?}", self),
        }
    }
}

impl error::Error for Error {}

impl convert::From<Error> for io::Error {
    fn from(e: Error) -> Self {
        einval!(e)
    }
}
