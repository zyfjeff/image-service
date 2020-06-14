// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::{Error, ErrorKind};

pub struct ReqErr {}

impl ReqErr {
    pub fn inv_input<E: std::fmt::Debug>(err: E) -> Error {
        Error::new(ErrorKind::InvalidInput, format!("{:?}", err))
    }
    pub fn inv_data<E: std::fmt::Debug>(err: E) -> Error {
        Error::new(ErrorKind::InvalidData, format!("{:?}", err))
    }
    pub fn other<E: std::fmt::Debug>(err: E) -> Error {
        Error::new(ErrorKind::Other, format!("{:?}", err))
    }
    pub fn broken_pipe<E: std::fmt::Debug>(err: E) -> Error {
        Error::new(ErrorKind::BrokenPipe, format!("{:?}", err))
    }
}
