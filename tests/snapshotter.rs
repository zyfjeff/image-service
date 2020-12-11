// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;

use sendfd::{RecvWithFd, SendWithFd};
use serde_json::json;
use serde_json::value::Value;

use nydus_utils::exec;

pub struct Snapshotter {
    work_dir: PathBuf,
}

impl Snapshotter {
    pub fn new(work_dir: PathBuf) -> Self {
        let mut received = false;
        let mut fds: Vec<RawFd> = vec![0; 1];
        let mut buf = vec![0u8; 4 << 10];

        let sock_path = work_dir.join("supervisor.sock");

        thread::spawn(move || {
            let listener = UnixListener::bind(sock_path).unwrap();
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
                        received = false;
                    }
                    Err(err) => {
                        panic!(err);
                    }
                }
            }
        });

        Self { work_dir }
    }

    fn request(
        &self,
        apisock: &PathBuf,
        method: &str,
        path: &str,
        body: Option<String>,
    ) -> Result<String> {
        let sock_path = self.work_dir.join(apisock);
        let mut curl = format!(
            "curl -X {} --unix-socket {:?} http:/localhost/api/v1{}",
            method, sock_path, path
        );
        if let Some(body) = body {
            curl = format!("{} -d '{}'", curl, body);
        }
        exec(curl.as_str(), true)
    }

    pub fn request_sendfd(&self, apisock: &PathBuf) {
        self.request(apisock, "PUT", "/daemon/fuse/sendfd", None)
            .unwrap();
    }

    pub fn get_status(&self, apisock: &PathBuf) -> String {
        let resp = self.request(apisock, "GET", "/daemon", None).unwrap();
        let info: Value = serde_json::from_str(&resp).unwrap();
        info["state"].as_str().unwrap().to_string()
    }

    pub fn kill_nydusd(&self, apisock: &PathBuf) {
        self.request(apisock, "PUT", "/daemon/exit", None).unwrap();
    }

    pub fn take_over(&self, apisock: &PathBuf) {
        self.request(apisock, "PUT", "/daemon/fuse/takeover", None)
            .unwrap();
    }

    pub fn mount(
        &self,
        apisock: &PathBuf,
        blobs_dir: &str,
        mount_point: &str,
        source_name: &str,
    ) -> String {
        let config = json!(
            {
                "device": {
                    "backend": {
                        "type": "localfs",
                        "config": {
                            "dir": self.work_dir.join(blobs_dir),
                        }
                    }
                },
                "mode": "direct"
            }
        );
        let mount_info = json!({
            "source": self.work_dir.join(source_name),
            "config": config.to_string(),
            "fs_type": "rafs",
        });
        let endpoint = format!("/mount?mountpoint={}", mount_point);
        self.request(
            apisock,
            "POST",
            endpoint.as_str(),
            Some(mount_info.to_string()),
        )
        .unwrap()
    }

    pub fn umount(&self, apisock: &PathBuf, mount_point: &str) -> String {
        let endpoint = format!("/mount?mountpoint={}", mount_point);
        self.request(apisock, "DELETE", endpoint.as_str(), None)
            .unwrap()
    }
}
