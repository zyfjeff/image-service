// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::fs::File;
use std::io::ErrorKind;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::{Read, Result, Write};
use std::os::unix::io::FromRawFd;

use nix::fcntl::OFlag;
use nix::sys::mman::{shm_open, shm_unlink};
use nix::sys::stat::Mode;

use super::Backend;
use nydus_utils::last_error;

pub struct SharedMemoryBackend {
    name: String,
    file: File,
}

impl SharedMemoryBackend {
    pub fn new(name: &str) -> Result<Self> {
        let fd = shm_open(
            name,
            OFlag::O_CREAT | OFlag::O_RDWR,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .map_err(|_| last_error!())?;

        let file = unsafe { File::from_raw_fd(fd) };

        Ok(Self {
            name: String::from(name),
            file,
        })
    }
}

impl Backend for SharedMemoryBackend {
    fn reset(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    fn reader(&mut self) -> Result<&mut dyn Read> {
        Ok(&mut self.file as &mut dyn Read)
    }

    fn writer(&mut self) -> Result<&mut dyn Write> {
        Ok(&mut self.file as &mut dyn Write)
    }

    fn destroy(&mut self) -> Result<()> {
        shm_unlink(self.name.as_str())
            .map_err(|_| last_error!())
            .or_else(|err| {
                if err.kind() == ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(err)
                }
            })
    }
}
