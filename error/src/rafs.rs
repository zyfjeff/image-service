// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[macro_export]
macro_rules! rafs_decompress_failed {
    () => {{
        use nydus_error::eio;
        eio!("decompression failed")
    }};
}

#[macro_export]
macro_rules! rafs_invalid_superblock {
    () => {{
        use nydus_error::einval;
        einval!("invalid superblock")
    }};
}

#[macro_export]
macro_rules! rafs_is_not_directory {
    () => {{
        use nydus_error::enotdir;
        enotdir!("is not a directory")
    }};
}
