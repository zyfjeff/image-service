// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[macro_use]
extern crate log;
extern crate serde;
#[macro_use]
extern crate serde_derive;

#[allow(dead_code, unused_variables)]
pub mod fs;
#[allow(dead_code)]
pub mod layout;
pub mod storage;

#[macro_use]
extern crate lazy_static;
#[allow(dead_code)]
pub mod io_stats;
