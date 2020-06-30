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

/// Define function like `einval(...)` and
/// macro like `einval!()` or `einval!(err)` for custom error codes
macro_rules! define_error_macro {
    ($fn:ident, $err:expr) => {
        pub fn $fn(raw: impl Debug, file: &str, line: u32) -> std::io::Error {
            display(&$err, &raw, file, line);
            std::io::Error::new($err.kind(), format!("{:?}", raw))
        }
        #[macro_export]
        macro_rules! $fn {
            () => {
                $err
            };
            ($raw:expr) => {
                $fn(&$raw, file!(), line!())
            };
        }
    };
}

/// Define function and macro for libc error codes
macro_rules! define_libc_error_macro {
    ($fn:ident, $code:ident) => {
        define_error_macro!($fn, std::io::Error::from_raw_os_error(libc::$code));
    };
}

// Add more libc error macro here if necessary
define_libc_error_macro!(einval, EINVAL);
define_libc_error_macro!(enoent, ENOENT);
define_libc_error_macro!(ebadf, EBADF);
define_libc_error_macro!(eacces, EACCES);
define_libc_error_macro!(enotdir, ENOTDIR);
define_libc_error_macro!(eisdir, EISDIR);
define_libc_error_macro!(ealready, EALREADY);
define_libc_error_macro!(enosys, ENOSYS);
define_libc_error_macro!(epipe, EPIPE);
define_libc_error_macro!(eio, EIO);

// Define macro like `last_error!(...)`
// Add more custom error macro here if necessary
define_error_macro!(last_error, std::io::Error::last_os_error());
define_error_macro!(eother, std::io::Error::new(std::io::ErrorKind::Other, ""));
