// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use image_builder::builder;

#[macro_use(crate_version, crate_authors)]
extern crate clap;
extern crate stderrlog;

use clap::{App, Arg, SubCommand};
use uuid::Uuid;

use std::fs::File;
use std::io::Result;

use rafs::storage::oss_backend::OSS;

fn main() -> Result<()> {
    stderrlog::new()
        .quiet(false)
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
                    Arg::with_name("blob")
                        .long("blob")
                        .help("blob file path (required)")
                        .takes_value(true)
                        .min_values(1),
                )
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .help("bootstrap file path (required)")
                        .takes_value(true)
                        .min_values(1),
                )
                .arg(
                    Arg::with_name("blob_id")
                        .long("blob_id")
                        .help("blob id (as object key in oss)")
                        .takes_value(true)
                        .min_values(0),
                )
                .arg(
                    Arg::with_name("oss_endpoint")
                        .long("oss_endpoint")
                        .help("oss endpoint (enable oss upload if specified)")
                        .takes_value(true)
                        .min_values(0),
                )
                .arg(
                    Arg::with_name("oss_access_key_id")
                        .long("oss_access_key_id")
                        .help("oss access key id")
                        .takes_value(true)
                        .min_values(0),
                )
                .arg(
                    Arg::with_name("oss_access_key_secret")
                        .long("oss_access_key_secret")
                        .help("oss access key secret")
                        .takes_value(true)
                        .min_values(0),
                )
                .arg(
                    Arg::with_name("oss_bucket_name")
                        .long("oss_bucket_name")
                        .help("oss bucket name")
                        .takes_value(true)
                        .min_values(0),
                )
                .arg(
                    Arg::with_name("SOURCE")
                        .help("source directory")
                        .required(true)
                        .index(1),
                ),
        )
        .get_matches();

    if let Some(matches) = cmd.subcommand_matches("create") {
        let source_path = matches.value_of("SOURCE").expect("SOURCE is required");
        let blob_path = matches.value_of("blob").expect("blob is required");
        let bootstrap_path = matches
            .value_of("bootstrap")
            .expect("bootstrap is required");

        let mut blob_id = Uuid::new_v4().to_string();
        if let Some(p_blob_id) = matches.value_of("blob_id") {
            blob_id = String::from(p_blob_id);
        }

        let mut ib =
            builder::Builder::new(source_path, blob_path, bootstrap_path, blob_id.as_str())?;
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

            let blob_file = File::open(blob_path)?;
            oss.put_object(blob_id.as_str(), blob_file)?;
        }
    }

    Ok(())
}
