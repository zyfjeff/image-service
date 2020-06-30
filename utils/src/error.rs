// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fmt::Debug;

use backtrace::Backtrace;

/// Display line number, file path and backtrace when an error occurs
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

/// Define macro like `einval!()` or `einval!(err)`
macro_rules! define_macro {
    ($fn:ident, $err:expr) => {
        #[macro_export]
        macro_rules! $fn {
            () => {{
                $err
            }};
            ($raw:expr) => {{
                $fn(&$raw, file!(), line!());
                std::io::Error::new($err.kind(), format!("{:?}", $raw))
            }};
        }
    };
}

/// Define function and macro
macro_rules! make {
    ($fn:ident, $code:ident) => {
        /// Define function like `einval(...)`
        pub fn $fn(raw: impl Debug, file: &str, line: u32) {
            display(
                &std::io::Error::from_raw_os_error(libc::$code),
                raw,
                file,
                line,
            );
        }
        define_macro!($fn, std::io::Error::from_raw_os_error(libc::$code));
    };
}

/// Define macro `last_error!(...)`
pub fn last_error(raw: impl Debug, file: &str, line: u32) -> std::io::Error {
    let err = std::io::Error::last_os_error();
    display(&err, &raw, file, line);
    std::io::Error::new(err.kind(), format!("{:?}", raw))
}
define_macro!(last_error, std::io::Error::last_os_error());

// Add more error codes here if necessary
make!(einval, EINVAL);
make!(enoent, ENOENT);
make!(ebadf, EBADF);
make!(eacces, EACCES);
make!(enotdir, ENOTDIR);
make!(eisdir, EISDIR);
make!(ealready, EALREADY);
make!(enosys, ENOSYS);
make!(epipe, EPIPE);
make!(eio, EIO);
