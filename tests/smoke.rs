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

    {
        // Create & build lower rootfs
        builder.make_lower()?;
        builder.build_lower(enable_compress)?;

        // Mount lower rootfs and check
        let nydusd = nydusd::new(
            &work_dir,
            enable_cache,
            rafs_mode.parse()?,
            "bootstrap-lower".to_string(),
        )?;
        nydusd.start()?;
        builder.mount_check("lower")?;
        nydusd.stop();
    }

    // Mount upper rootfs and check
    {
        // Create & build upper rootfs based lower
        builder.make_upper()?;
        builder.build_upper(enable_compress)?;

        // Mount overlay rootfs and check
        let nydusd = nydusd::new(
            &work_dir,
            enable_cache,
            rafs_mode.parse()?,
            "bootstrap-overlay".to_string(),
        )?;
        nydusd.start()?;
        builder.mount_check("overlay")?;
        nydusd.stop();
    }

    // Test blob cache recovery if enable cache
    if enable_cache {
        let nydusd = nydusd::new(
            &work_dir,
            enable_cache,
            rafs_mode.parse()?,
            "bootstrap-overlay".to_string(),
        )?;
        nydusd.start()?;
        builder.mount_check("overlay")?;
        nydusd.stop();
    }

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
