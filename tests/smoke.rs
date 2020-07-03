// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;

use vmm_sys_util::tempdir::TempDir;

mod builder;
mod nydusd;

use nydus_utils::eother;

fn test(enable_compress: bool, enable_cache: bool, rafs_mode: &str) -> Result<()> {
    let tmp_dir = TempDir::new().map_err(|e| eother!(e))?;
    let work_dir = tmp_dir.as_path().to_path_buf();

    let mut builder = builder::new(&work_dir);

    // create & build parent rootfs
    builder.make_parent()?;
    let build_ret = builder.build_parent(enable_compress)?;

    let nydusd = nydusd::new(&work_dir, enable_cache, rafs_mode.parse()?)?;
    nydusd.start()?;
    let mount_ret = builder.mount_check()?;
    assert_eq!(build_ret, mount_ret);

    // test blob cache recovery if enable cache
    if enable_cache {
        drop(nydusd);
        let nydusd = nydusd::new(&work_dir, enable_cache, rafs_mode.parse()?)?;
        nydusd.start()?;
        let mount_ret = builder.mount_check()?;
        assert_eq!(build_ret, mount_ret);
    }

    // create & build source rootfs based parent
    builder.make_source()?;
    builder.build_source()?;

    Ok(())
}

#[test]
fn run() -> Result<()> {
    test(true, true, "direct")?;
    test(false, false, "direct")?;
    test(true, false, "direct")?;
    test(false, true, "direct")?;

    test(true, true, "cached")?;
    test(false, false, "cached")?;
    test(true, false, "cached")?;
    test(false, true, "cached")
}
