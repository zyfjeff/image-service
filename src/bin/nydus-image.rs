// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[macro_use(crate_version, crate_authors)]
extern crate clap;
extern crate stderrlog;

#[macro_use]
extern crate log;

const BLOB_ID_MAXIMUM_LENGTH: usize = 1024;

use clap::{App, Arg, SubCommand};
use mktemp::Temp;

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Error, ErrorKind, Result, Write};
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nydus_builder::builder;
use nydus_builder::node::Node;
use nydus_utils::{backtrace_enable, log_level_to_verbosity};
use rafs::storage::{backend, factory};

fn upload_blob(
    backend: Box<dyn backend::BlobBackendUploader<Reader = File>>,
    blob_id: &str,
    blob_path: &str,
) -> Result<()> {
    let blob_file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(blob_path)
        .map_err(|e| {
            error!("upload_blob open failed {:?}", e);
            e
        })?;
    let size = blob_file.metadata()?.st_size() as usize;
    backend
        .upload(blob_id, blob_file, size, |(current, total)| {
            io::stdout().flush().unwrap();
            print!("\r");
            print!(
                "Backend blob uploading: {}/{} bytes ({}%)",
                current,
                total,
                current * 100 / total,
            );
        })
        .map_err(|e| {
            error!("upload_blob backend.upload {:?}", e);
            e
        })?;

    print!("\r");
    io::stdout().flush().unwrap();

    Ok(())
}

/// Get readhead file paths line by line from stdin
fn get_readhead_files() -> Result<HashMap<PathBuf, Option<Node>>> {
    let stdin = io::stdin();
    let mut files = HashMap::new();

    loop {
        let mut file = String::new();
        let ret = stdin.read_line(&mut file);
        match ret {
            Ok(size) => {
                if size == 0 {
                    break;
                }
                let file_name = file.trim();
                if !file_name.is_empty() {
                    debug!("readhead file: {}", file_name);
                    files.insert(Path::new(file_name).to_path_buf(), None);
                }
            }
            Err(err) => {
                error!("Failed to parse readhead files: {}", err);
            }
        }
    }

    Ok(files)
}

fn build() -> Result<()> {
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
                        .help("blob id (as object id in backend)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("compressor")
                        .long("compressor")
                        .help("how blob will be compressed: none, lz4_block (default)")
                        .takes_value(true)
                        .required(false)
                        .default_value("lz4_block"),
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
                        .help("blob storage backend config (json)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("enable_readhead")
                        .long("enable_readhead")
                        .help("enable blob readhead optimiztion (read file list from stdin)"),
                ),
        )
        .arg(
            Arg::with_name("log_level")
                .long("log_level")
                .default_value("info")
                .help("Specify log level: trace, debug, info, warn, error")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .get_matches();

    let v = cmd
        .value_of("log_level")
        .unwrap()
        .parse()
        .unwrap_or(log::LevelFilter::Warn);

    stderrlog::new()
        .quiet(false)
        .modules(vec![module_path!(), "nydus_builder", "rafs"])
        .verbosity(log_level_to_verbosity(v))
        .timestamp(stderrlog::Timestamp::Second)
        .init()
        .unwrap();

    if let Some(matches) = cmd.subcommand_matches("create") {
        let source_path = matches.value_of("SOURCE").expect("SOURCE is required");
        let blob_path = matches.value_of("blob");
        let bootstrap_path = matches
            .value_of("bootstrap")
            .expect("bootstrap is required");

        let mut blob_id = String::new();
        if let Some(p_blob_id) = matches.value_of("blob_id") {
            blob_id = String::from(p_blob_id);
            if blob_id.len() > BLOB_ID_MAXIMUM_LENGTH {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("blob id is limited to length {}", BLOB_ID_MAXIMUM_LENGTH),
                ));
            }
        }

        let compressor = matches.value_of("compressor").unwrap_or_default().parse()?;

        let temp_blob_file = Temp::new_file().unwrap();

        let real_blob_path = if let Some(blob_path) = blob_path {
            blob_path
        } else {
            temp_blob_file.to_str().unwrap()
        };

        let mut parent_bootstrap = String::new();
        if let Some(_parent_bootstrap) = matches.value_of("parent_bootstrap") {
            parent_bootstrap = _parent_bootstrap.to_owned();
        }

        let readhead_files = if matches.is_present("enable_readhead") {
            get_readhead_files()?
        } else {
            HashMap::new()
        };

        let mut ib = builder::Builder::new(
            source_path.to_owned(),
            real_blob_path.to_owned(),
            bootstrap_path.to_owned(),
            parent_bootstrap,
            blob_id.clone(),
            compressor,
            readhead_files,
        )?;
        blob_id = ib.build()?;

        if let Some(backend_type) = matches.value_of("backend_type") {
            if let Some(backend_config) = matches.value_of("backend_config") {
                let config = factory::BackendConfig {
                    backend_type: backend_type.to_owned(),
                    backend_config: serde_json::from_str(backend_config).map_err(|e| {
                        error!("failed to parse backend_config json: {}", e);
                        e
                    })?,
                };
                let blob_backend = factory::new_uploader(&config).unwrap();
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

fn main() -> Result<()> {
    if backtrace_enable() {
        build().unwrap();
        return Ok(());
    }
    build().map_err(|err| {
        error!("Build image failed");
        err
    })
}
