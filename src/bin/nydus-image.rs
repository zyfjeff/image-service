// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use image_builder::builder;

#[macro_use(crate_version, crate_authors)]
extern crate clap;
use clap::{App, Arg};
use uuid::Uuid;

use std::io::Result;

fn main() -> Result<()> {
    let cmd_arguments = App::new("nydus image builder")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Build image using nydus format.")
        .arg(
            Arg::with_name("blob")
                .long("blob")
                .help("blob file path")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("bootstrap")
                .long("bootstrap")
                .help("bootstrap file path")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("SOURCE")
                .long("source")
                .help("source directory")
                .required(true)
                .index(1),
        )
        .get_matches();

    let source_path = cmd_arguments.value_of("SOURCE").unwrap();
    let blob_path = cmd_arguments.value_of("blob").unwrap();
    let bootstrap_path = cmd_arguments.value_of("bootstrap").unwrap();

    let blob_id = Uuid::new_v4().to_string();

    let mut ib = builder::Builder::new(source_path, blob_path, bootstrap_path, blob_id.as_str())?;
    ib.build()?;

    Ok(())
}
