// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::io::Result;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use sendfd::{RecvWithFd, SendWithFd};
use snapshot::{Persist, Snapshot};
use versionize::Versionize;

use super::resource::{Resource, VersionMapGetter};
use nydus_utils::{einval, last_error};

pub struct FdResource {
    uds_path: PathBuf,
    fds: Vec<RawFd>,
}

impl FdResource {
    fn new(uds_path: PathBuf, fds: Vec<RawFd>) -> Self {
        Self { uds_path, fds }
    }

    fn send_fd(&mut self, opaque: &[u8]) -> Result<usize> {
        let stream = UnixStream::connect(&self.uds_path).map_err(|err| {
            error!("connect to {:?} failed: {:?}", &self.uds_path, err);
            err
        })?;
        stream
            .send_with_fd(&opaque, &self.fds)
            .map_err(|e| last_error!(e))
    }

    fn recv_fd(&mut self, mut fds: &mut [RawFd], mut opaque: &mut [u8]) -> Result<(usize, usize)> {
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
}

impl Resource for FdResource {
    fn save<'a, O, V, D>(&mut self, obj: &O) -> Result<()>
    where
        O: Persist<'a, State = V, Error = D>,
        V: Versionize + VersionMapGetter,
        D: std::fmt::Debug,
    {
        let vm = V::version_map();
        let latest_version = vm.latest_version();

        let mut snapshot = Snapshot::new(vm, latest_version);

        let state = obj.save();
        let mut opaque: Vec<u8> = Vec::new();

        snapshot
            .save_with_crc64(&mut opaque, &state)
            .map_err(|e| einval!(e))?;

        self.send_fd(opaque.as_slice())?;

        Ok(())
    }

    fn restore<'a, O, V, A, D>(&mut self, args: A) -> Result<O>
    where
        O: Persist<'a, State = V, ConstructorArgs = A, Error = D>,
        V: Versionize + VersionMapGetter,
        D: std::fmt::Debug,
    {
        let vm = V::version_map();

        // TODO: Is 8K buffer large enough?
        let mut opaque: Vec<u8> = vec![0u8; 8 << 10];
        let mut fds: Vec<RawFd> = vec![0; 8];

        let (opaque_size, fd_count) = self.recv_fd(fds.as_mut_slice(), &mut opaque)?;
        opaque.truncate(opaque_size);
        fds.truncate(fd_count);

        let restored = Snapshot::load_with_crc64(&mut opaque.as_slice(), vm).map_err(|e| {
            warn!("fd resource: failed to restore from uds server: {}", e);
            einval!(e)
        })?;

        self.fds = fds;

        O::restore(args, &restored).map_err(|e| einval!(e))
    }
}

#[cfg(test)]
pub mod tests {
    use sendfd::{RecvWithFd, SendWithFd};
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{Seek, SeekFrom};
    use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::thread;

    use vmm_sys_util::tempfile::TempFile;

    use crate::binary_resource::tests::{Test, TestArgs};
    use crate::resource::Resource;

    use super::FdResource;

    fn start_uds_server(path: PathBuf) {
        let mut received = false;
        let mut fds: Vec<RawFd> = vec![0; 1];
        let mut buf = vec![0u8; 4 << 10];

        let listener = UnixListener::bind(path).unwrap();

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if !received {
                        let (opaque_size, fds_count) = stream
                            .recv_with_fd(buf.as_mut_slice(), fds.as_mut_slice())
                            .unwrap();
                        assert_eq!(fds_count, 1);
                        buf.truncate(opaque_size);
                        fds.truncate(fds_count);
                        received = true;
                        continue;
                    }
                    stream.send_with_fd(&buf, &fds).unwrap();
                }
                Err(err) => {
                    panic!(err);
                }
            }
        }
    }

    #[test]
    fn test_fd_resource() {
        let opaque = Test {
            foo: HashMap::new(),
            bar: String::from("bar"),
            baz: 100,
        };

        // Start uds server for recv and reply fd + opaque
        let sock_file = TempFile::new().unwrap();
        let uds_path = sock_file.as_path().to_path_buf();
        let res_uds_path = uds_path.clone();
        // Just get a temp path for uds server creation
        drop(sock_file);

        thread::spawn(move || start_uds_server(uds_path));
        std::thread::sleep(std::time::Duration::from_millis(500));

        let seek_pos = 123;
        let temp_file = TempFile::new().unwrap();
        let fds = vec![temp_file.as_file().as_raw_fd()];
        temp_file.as_file().seek(SeekFrom::Start(seek_pos)).unwrap();

        // Save fd + opaque to uds server
        let mut fd_resource = FdResource::new(res_uds_path, fds);
        fd_resource.save(&opaque.clone()).unwrap();

        // Restore fd + opaque from uds server
        let restored: Test = fd_resource.restore(TestArgs { baz: 100 }).unwrap();

        // Check restored opaque
        let expected = opaque.clone();
        assert_eq!(restored, expected);

        // Check restored fd
        let mut temp_file = unsafe { File::from_raw_fd(fd_resource.fds[0]) };
        let expected = temp_file.seek(SeekFrom::Current(0)).unwrap();
        assert_eq!(seek_pos, expected);
    }
}
