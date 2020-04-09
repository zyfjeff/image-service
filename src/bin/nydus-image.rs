// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use image_builder::builder;

#[macro_use(crate_version, crate_authors)]
extern crate clap;
extern crate stderrlog;

#[macro_use]
extern crate log;

use clap::{App, Arg, SubCommand};
use mktemp::Temp;
use uuid::Uuid;

use std::fs::File;
use std::io::{self, Result, Write};

use rafs::storage::backend::oss::OSS;

fn main() -> Result<()> {
    stderrlog::new()
        .quiet(false)
        .modules(vec![module_path!(), "image_builder"])
        .verbosity(log::LevelFilter::Info as usize)
        .timestamp(stderrlog::Timestamp::Second)
        .init()
        .unwrap();

    let cmd = App::new("nydus image builder")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Build image using nydus format.")
        .subcommand(
            SubCommand::with_name("create")
                .about("create image and upload blob to oss")
                .arg(
                    Arg::with_name("SOURCE")
                        .help("source directory")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("blob")
                        .long("blob")
                        .help("blob file path")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .help("bootstrap file path (required)")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("blob_id")
                        .long("blob_id")
                        .help("blob id (as object key in oss)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("parent_bootstrap")
                        .long("parent_bootstrap")
                        .help("bootstrap file path of parent (optional)")
                        .takes_value(true)
                        .required(false),
                )
                .arg(
                    Arg::with_name("oss_endpoint")
                        .long("oss_endpoint")
                        .help("oss endpoint (enable oss upload if specified)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("oss_access_key_id")
                        .long("oss_access_key_id")
                        .help("oss access key id")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("oss_access_key_secret")
                        .long("oss_access_key_secret")
                        .help("oss access key secret")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("oss_bucket_name")
                        .long("oss_bucket_name")
                        .help("oss bucket name")
                        .takes_value(true),
                ),
        )
        .get_matches();

    if let Some(matches) = cmd.subcommand_matches("create") {
        let source_path = matches.value_of("SOURCE").expect("SOURCE is required");
        let blob_path = matches.value_of("blob");
        let bootstrap_path = matches
            .value_of("bootstrap")
            .expect("bootstrap is required");

        let mut blob_id = Uuid::new_v4().to_string();
        if let Some(p_blob_id) = matches.value_of("blob_id") {
            blob_id = String::from(p_blob_id);
        }

        let temp_blob_file = Temp::new_file().unwrap();

        let real_blob_path;
        if blob_path.is_none() {
            real_blob_path = temp_blob_file.to_str().unwrap();
        } else {
            real_blob_path = blob_path.unwrap();
        }

        let mut parent_bootstrap = String::new();
        if let Some(_parent_bootstrap) = matches.value_of("parent_bootstrap") {
            parent_bootstrap = _parent_bootstrap.to_owned();
        }

        let mut ib = builder::Builder::new(
            source_path.to_owned(),
            real_blob_path.to_owned(),
            bootstrap_path.to_owned(),
            parent_bootstrap,
            blob_id.clone(),
        )?;
        ib.build()?;

        if let Some(oss_endpoint) = matches.value_of("oss_endpoint") {
            let oss_access_key_id = matches
                .value_of("oss_access_key_id")
                .expect("oss_access_key_id is required");
            let oss_access_key_secret = matches
                .value_of("oss_access_key_secret")
                .expect("oss_access_key_secret is required");
            let oss_bucket_name = matches
                .value_of("oss_bucket_name")
                .expect("oss_bucket_name is required");

            let oss = OSS::new(
                oss_endpoint,
                oss_access_key_id,
                oss_access_key_secret,
                oss_bucket_name,
            );

            let blob_file = File::open(real_blob_path)?;
            oss.put_object(blob_id.as_str(), blob_file, |(current, total)| {
                io::stdout().flush().unwrap();
                print!("\r");
                print!(
                    "OSS blob uploading: {}/{} bytes ({}%)",
                    current,
                    total,
                    current * 100 / total,
                );
            })?;

            print!("\r");
            io::stdout().flush().unwrap();
        }

        if blob_path.is_some() {
            info!(
                "build finished, blob id: {}, blob file: {}",
                blob_id.as_str(),
                real_blob_path
            );
        } else {
            info!("build finished, blob id: {}", blob_id.as_str());
        }
    }

    Ok(())
}
