// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod dag;
use dag::Dag;

use std::io;

struct RafsSuper {
    s_magic: u32,
    s_version: u32,
    s_root: Dag,
}

struct RafsConfig {
    source: String,
}

pub struct Rafs {
    conf: RafsConfig,

    sb: RafsSuper,
}

impl Rafs {
    fn new(conf: RafsConfig) -> io::Result<Rafs> {
        Ok(Rafs {
            sb: RafsSuper {
                s_magic: 100,
                s_version: 1,
                s_root: Dag {},
            },
            conf: conf,
        })
    }

    fn mount(&self) -> io::Result<()> {
        Ok(())
    }

    fn umount(&self) -> io::Result<()> {
        Ok(())
    }
}
