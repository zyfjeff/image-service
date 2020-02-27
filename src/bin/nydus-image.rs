// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod image;

#[macro_use(crate_version, crate_authors)]
extern crate clap;
use clap::{App, Arg};

use std::io::Result;

fn main() -> Result<()> {
  let cmd_arguments = App::new("nydus image builder")
    .version(crate_version!())
    .author(crate_authors!())
    .about("Build image using nydus format.")
    .arg(
      Arg::with_name("SOURCE")
        .long("source")
        .help("source directory for image build")
        .required(true)
        .index(1),
    )
    .get_matches();

  let source_dir = cmd_arguments.value_of("SOURCE").unwrap();

  image::build(source_dir)?;

  Ok(())
}
