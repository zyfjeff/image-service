// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::io::{Result, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread::*;
use std::time;

use nydus_utils::einval;
use rafs::metadata::RafsMode;

const NYDUSD: &str = "./target-fusedev/debug/nydusd";

pub fn exec(cmd: &str) -> Result<()> {
    println!("exec `{}`", cmd);

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .env("RUST_BACKTRACE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let status = child.wait()?;

    let status = status.code().ok_or(einval!("exited with unknown status"))?;

    if status != 0 {
        return Err(einval!("exited with non-zero"));
    }

    Ok(())
}

pub struct Nydusd {
    work_dir: PathBuf,
    mount_path: PathBuf,
    bootstrap_file_name: String,
}

pub fn new(
    work_dir: &PathBuf,
    enable_cache: bool,
    rafs_mode: RafsMode,
    bootstrap_file_name: String,
) -> Result<Nydusd> {
    let mount_path = work_dir.join("mnt");
    fs::create_dir_all(mount_path.clone())?;

    let cache_path = work_dir.join("cache");
    fs::create_dir_all(cache_path.clone())?;

    let cache = format!(
        r###"
        ,"cache": {{
            "type": "blobcache",
            "config": {{
                "work_dir": {:?}
            }}
        }}
    "###,
        work_dir.join("cache")
    );

    let config = format!(
        r###"
        {{
            "device": {{
                "backend": {{
                    "type": "localfs",
                    "config": {{
                        "dir": {:?},
                        "readahead": true
                    }}
                }}
                {}
            }},
            "mode": "{}",
            "digest_validate": true,
            "iostats_files": true
        }}
        "###,
        work_dir.join("blobs"),
        if enable_cache { cache } else { String::new() },
        rafs_mode,
    );

    File::create(work_dir.join("config.json"))?.write_all(config.as_bytes())?;

    Ok(Nydusd {
        work_dir: work_dir.clone(),
        mount_path,
        bootstrap_file_name,
    })
}

impl Nydusd {
    pub fn start(&self) -> Result<()> {
        let work_dir = self.work_dir.clone();
        let mount_path = self.mount_path.clone();
        let bootstrap_file_name = self.bootstrap_file_name.clone();

        spawn(move || {
            exec(
                format!(
                    "{} --config {:?} --apisock {:?} --mountpoint {:?} --bootstrap {:?} --log-level trace",
                    NYDUSD,
                    work_dir.join("config.json"),
                    work_dir.join("api.sock"),
                    mount_path,
                    work_dir.join(bootstrap_file_name),
                )
                .as_str(),
            ).unwrap_or(());
        });

        sleep(time::Duration::from_secs(1));

        Ok(())
    }
    pub fn stop(&self) {
        exec(format!("umount {:?}", self.mount_path).as_str()).unwrap();
    }
}
