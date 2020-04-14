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

use std::fs::{File, OpenOptions};
use std::io::{self, Result, Write};
use std::os::linux::fs::MetadataExt;

use rafs::storage::backend::*;

fn upload_blob(
    backend: Box<dyn BlobBackendUploader<Reader = File>>,
    blob_id: &str,
    blob_path: &str,
) -> Result<()> {
    let blob_file = OpenOptions::new().read(true).write(false).open(blob_path)?;
    let size = blob_file.metadata()?.st_size() as usize;
    backend.upload(blob_id, blob_file, size, |(current, total)| {
        io::stdout().flush().unwrap();
        print!("\r");
        print!(
            "Backend blob uploading: {}/{} bytes ({}%)",
            current,
            total,
            current * 100 / total,
        );
    })?;

    print!("\r");
    io::stdout().flush().unwrap();

    Ok(())
}

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
                .about("dump image bootstrap and upload blob to storage backend")
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
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("blob_id")
                        .long("blob_id")
                        .help("blob id (as object key in backend)")
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
                    Arg::with_name("backend_type")
                        .long("backend_type")
                        .help("blob storage backend type (enable backend upload if specified)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("backend_config")
                        .long("backend_config")
                        .help("blob storage backend config")
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

        let mut blob_id = String::new();
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
        blob_id = ib.build()?;

        if let Some(backend_type) = matches.value_of("backend_type") {
            if let Some(backend_config) = matches.value_of("backend_config") {
                let config = BlobBackend::parse_config(backend_config);
                let blob_backend = BlobBackend::map_uploader_type(backend_type, config).unwrap();

                upload_blob(blob_backend, blob_id.as_str(), real_blob_path)?;
            }
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
