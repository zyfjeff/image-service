// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fmt::Debug;

use backtrace::Backtrace;

#[macro_use]
extern crate log;

pub mod rafs;

macro_rules! make_debuggable {
    ($fn:ident, $code:expr) => {
        #[macro_export]
        macro_rules! $fn {
            () => {{
                $code
            }};
            ($err:expr) => {{
                $fn(&$err, file!(), line!());
                std::io::Error::new($code.kind(), format!("{:?}", $err))
            }};
        }
    };
}

macro_rules! define_macro {
    ($fn:ident, $code:ident) => {
        pub fn $fn(raw: impl Debug, file: &str, line: u32) {
            display(
                &std::io::Error::from_raw_os_error(libc::$code),
                raw,
                file,
                line,
            );
        }
        make_debuggable!($fn, std::io::Error::from_raw_os_error(libc::$code));
    };
}

fn display(err: &std::io::Error, raw: impl Debug, file: &str, line: u32) {
    error!(
        "Error:\n    kind: {:?}, error: {:?}\n    at {}:{}",
        err.kind(),
        raw,
        file,
        line
    );
    if cfg!(debug_assertions) {
        if let Ok(val) = env::var("RUST_BACKTRACE") {
            if val.trim() != "0" {
                error!("Stack:\n{:?}", Backtrace::new());
            }
        }
    }
}

pub fn last_error(raw: impl Debug, file: &str, line: u32) -> std::io::Error {
    let err = std::io::Error::last_os_error();
    display(&err, &raw, file, line);
    std::io::Error::new(err.kind(), format!("{:?}", raw))
}

make_debuggable!(last_error, std::io::Error::last_os_error());

define_macro!(einval, EINVAL);
define_macro!(enoent, ENOENT);
define_macro!(ebadf, EBADF);
define_macro!(eacces, EACCES);
define_macro!(enotdir, ENOTDIR);
define_macro!(eisdir, EISDIR);
define_macro!(ealready, EALREADY);
define_macro!(enosys, ENOSYS);
define_macro!(epipe, EPIPE);
define_macro!(eio, EIO);
