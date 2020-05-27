// Copyright 2020 Ant Financial. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be
// found in the LICENSE file.
//

#[macro_use]
extern crate log;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate micro_http;
extern crate vmm_sys_util;
#[macro_use]
extern crate lazy_static;

pub mod http;
pub mod http_endpoint;
