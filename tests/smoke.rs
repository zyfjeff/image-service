// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate log;

mod builder;
mod nydusd;
mod snapshotter;

use std::io::Result;
use std::path::PathBuf;

use vmm_sys_util::tempdir::TempDir;

use nydus_utils::{eother, exec, setup_logging};
use snapshotter::Snapshotter;

const COMPAT_BOOTSTRAPS: [&str; 2] = [
    "blake3-lz4_block-non_repeatable",
    "sha256-nocompress-repeatable",
];

fn check_compact<'a>(work_dir: &'a PathBuf, bootstrap_name: &str, rafs_mode: &str) -> Result<()> {
    let nydusd = nydusd::new(
        work_dir,
        false,
        false,
        rafs_mode.parse()?,
        "api.sock".into(),
        true,
    )?;

    nydusd.start(Some(bootstrap_name), "mnt")?;
    let result_path = format!("repeatable/{}.result", bootstrap_name);
    nydusd.check(result_path.as_str(), "mnt")?;
    nydusd.umount("mnt");

    Ok(())
}

fn test(
    compressor: &str,
    enable_cache: bool,
    cache_compressed: bool,
    rafs_mode: &str,
    whiteout_spec: &str,
) -> Result<()> {
    // std::thread::sleep(std::time::Duration::from_secs(1000));

    info!(
        "\n\n==================== testing run: compressor={} enable_cache={} cache_compressed={} rafs_mode={}",
        compressor, enable_cache, cache_compressed, rafs_mode
    );

    // If the smoke test run in container based on overlayfs storage driver,
    // the test will failed because we can't call `mknod` to create char device file.
    // So please provide the env `TEST_WORKDIR_PREFIX` to specify a host path, allow
    // `mknod` to create char device file in the non-overlayfs filesystem.
    let tmp_dir_prefix =
        std::env::var("TEST_WORKDIR_PREFIX").expect("Please specify `TEST_WORKDIR_PREFIX` env");
    let tmp_dir = {
        let path = if tmp_dir_prefix.ends_with('/') {
            tmp_dir_prefix
        } else {
            format!("{}/", tmp_dir_prefix)
        };
        TempDir::new_with_prefix(path).map_err(|e| eother!(e))?
    };
    let work_dir = tmp_dir.as_path().to_path_buf();
    let lower_texture = "directory/lower.result".to_string();
    let overlay_texture = "directory/overlay.result".to_string();

    let mut builder = builder::new(&work_dir, whiteout_spec);

    {
        // Create & build lower rootfs
        builder.make_lower()?;
        builder.build_lower(compressor)?;

        // Mount lower rootfs and check
        let nydusd = nydusd::new(
            &work_dir,
            enable_cache,
            cache_compressed,
            rafs_mode.parse()?,
            "api.sock".into(),
            true,
        )?;
        nydusd.start(Some("bootstrap-lower"), "mnt")?;
        nydusd.check(&lower_texture, "mnt")?;
        nydusd.umount("mnt");
    }

    // Mount upper rootfs and check
    {
        // Create & build upper rootfs based lower
        builder.make_upper()?;
        builder.build_upper(compressor)?;

        // Mount overlay rootfs and check
        let nydusd = nydusd::new(
            &work_dir,
            enable_cache,
            cache_compressed,
            rafs_mode.parse()?,
            "api.sock".into(),
            true,
        )?;
        nydusd.start(Some("bootstrap-overlay"), "mnt")?;
        nydusd.check(&overlay_texture, "mnt")?;
        nydusd.umount("mnt");
    }

    // Test blob cache recovery if enable cache
    if enable_cache {
        let nydusd = nydusd::new(
            &work_dir,
            enable_cache,
            cache_compressed,
            rafs_mode.parse()?,
            "api.sock".into(),
            true,
        )?;
        nydusd.start(Some("bootstrap-overlay"), "mnt")?;
        nydusd.check(&overlay_texture, "mnt")?;
        nydusd.umount("mnt");
    }

    Ok(())
}

#[test]
fn integration_test_init() {
    setup_logging(None, log::LevelFilter::Trace).unwrap()
}

#[test]
fn integration_test_directory_1() -> Result<()> {
    test("lz4_block", true, false, "direct", "oci")
}

#[test]
fn integration_test_directory_2() -> Result<()> {
    test("lz4_block", false, false, "direct", "oci")
}

#[test]
fn integration_test_directory_3() -> Result<()> {
    test("gzip", false, false, "direct", "oci")
}

#[test]
fn integration_test_directory_4() -> Result<()> {
    test("none", true, false, "direct", "oci")
}

#[test]
fn integration_test_directory_5() -> Result<()> {
    test("gzip", true, true, "cached", "oci")
}

#[test]
fn integration_test_directory_6() -> Result<()> {
    test("none", false, true, "cached", "oci")
}

#[test]
fn integration_test_directory_7() -> Result<()> {
    test("lz4_block", false, true, "cached", "oci")
}

#[test]
fn integration_test_directory_8() -> Result<()> {
    test("lz4_block", true, true, "cached", "oci")
}

#[test]
fn integration_test_directory_9() -> Result<()> {
    test("lz4_block", true, false, "direct", "overlayfs")
}

#[test]
fn integration_test_compact() -> Result<()> {
    info!("\n\n==================== testing run: compact test");

    let tmp_dir = TempDir::new().map_err(|e| eother!(e))?;
    let work_dir = tmp_dir.as_path().to_path_buf();
    let _ = exec(
        format!("cp -a tests/texture/repeatable/* {:?}", work_dir).as_str(),
        false,
    )?;

    for mode in vec!["direct", "cached"].iter() {
        for bs in COMPAT_BOOTSTRAPS.iter() {
            check_compact(&work_dir, bs, mode)?;
        }
    }

    Ok(())
}

#[test]
fn integration_test_special_files() -> Result<()> {
    info!("\n\n==================== testing run: special file test");
    let tmp_dir = TempDir::new().map_err(|e| eother!(e))?;
    let work_dir = tmp_dir.as_path().to_path_buf();

    let mut builder = builder::new(&work_dir, "oci");

    builder.build_special_files()?;

    for mode in &["direct", "cached"] {
        let nydusd = nydusd::new(
            &work_dir,
            true,
            true,
            mode.parse()?,
            "api.sock".into(),
            false,
        )?;
        nydusd.start(Some("bootstrap-specialfiles"), "mnt")?;
        nydusd.check("specialfiles/result", "mnt")?;
        nydusd.umount("mnt");
    }

    Ok(())
}

#[test]
fn integration_test_stargz() -> Result<()> {
    info!("\n\n==================== testing run: stargz test");

    let tmp_dir = TempDir::new().map_err(|e| eother!(e))?;
    let work_dir = tmp_dir.as_path().to_path_buf();

    let _ = exec(
        format!("cp -a tests/texture/stargz/* {:?}", work_dir).as_str(),
        false,
    )?;

    let mut builder = builder::new(&work_dir, "oci");

    builder.build_stargz_lower()?;
    builder.build_stargz_upper()?;

    let nydusd = nydusd::new(
        &work_dir,
        true,
        true,
        "direct".parse()?,
        "api.sock".into(),
        false,
    )?;

    nydusd.start(Some("bootstrap-overlay"), "mnt")?;
    nydusd.check("directory/overlay.result", "mnt")?;
    nydusd.umount("mnt");

    Ok(())
}

#[test]
fn integration_test_hot_upgrade_with_fusedev() -> Result<()> {
    info!("\n\n==================== testing run: hot upgrade with fusedev");

    let tmp_dir = TempDir::new().map_err(|e| eother!(e))?;
    let work_dir = tmp_dir.as_path().to_path_buf();
    let _ = exec(
        format!("cp -a tests/texture/repeatable/* {:?}", work_dir).as_str(),
        false,
    )
    .unwrap();

    let old_nydusd = nydusd::new(
        &work_dir,
        false,
        false,
        "direct".parse()?,
        "api.sock".into(),
        true,
    )?;

    let new_nydusd = nydusd::new(
        &work_dir,
        false,
        false,
        "direct".parse()?,
        "new-api.sock".into(),
        true,
    )?;

    let snapshotter = Snapshotter::new(work_dir);

    // Start old nydusd to mount
    old_nydusd.start(Some(COMPAT_BOOTSTRAPS[0]), "mnt")?;

    // Old nydusd's state should be RUNNING
    assert_eq!(snapshotter.get_status(&old_nydusd.api_sock), "RUNNING");

    // Snapshotter receive fuse fd from old nydusd
    snapshotter.request_sendfd(&old_nydusd.api_sock);

    // Start new nydusd but don't mount
    new_nydusd.start_with_upgrade(Some(COMPAT_BOOTSTRAPS[0]), "mnt")?;

    // New nydusd's state should be INIT
    assert_eq!(snapshotter.get_status(&new_nydusd.api_sock), "INIT");

    // Snapshotter tells old nydusd to exit
    snapshotter.kill_nydusd(&old_nydusd.api_sock);

    // Snapshotter send fuse fd to new nydusd
    snapshotter.take_over(&new_nydusd.api_sock);

    // New nydusd's state should be RUNNING
    assert_eq!(snapshotter.get_status(&new_nydusd.api_sock), "RUNNING");

    // Snapshotter receive fuse fd from new nydusd
    snapshotter.request_sendfd(&new_nydusd.api_sock);

    // Check files in mount point
    let result_path = format!("repeatable/{}.result", COMPAT_BOOTSTRAPS[0]);
    new_nydusd.check(result_path.as_str(), "mnt")?;

    // Stop new nydusd
    new_nydusd.umount("mnt");

    Ok(())
}

#[test]
fn integration_test_hot_upgrade_with_rafs_mount() -> Result<()> {
    info!("\n\n==================== testing run: hot upgrade with rafs mount");

    let tmp_dir = TempDir::new().map_err(|e| eother!(e))?;
    let work_dir = tmp_dir.as_path().to_path_buf();
    let _ = exec(
        format!("cp -a tests/texture/repeatable/* {:?}", work_dir).as_str(),
        false,
    )
    .unwrap();

    let old_nydusd = nydusd::new(
        &work_dir,
        false,
        false,
        "direct".parse()?,
        "api.sock".into(),
        true,
    )?;

    let new_nydusd = nydusd::new(
        &work_dir,
        false,
        false,
        "direct".parse()?,
        "new-api.sock".into(),
        true,
    )?;

    let snapshotter = Snapshotter::new(work_dir);

    // Start old nydusd to mount
    old_nydusd.start(None, "mnt")?;

    // Add RAFS mountpoint
    snapshotter.mount(&old_nydusd.api_sock, "blobs", "/sub1", COMPAT_BOOTSTRAPS[0]);

    // Add RAFS mountpoint
    snapshotter.mount(&old_nydusd.api_sock, "blobs", "/sub2", COMPAT_BOOTSTRAPS[1]);

    // Old nydusd's state should be RUNNING
    assert_eq!(snapshotter.get_status(&old_nydusd.api_sock), "RUNNING");

    // Snapshotter receive fuse fd from old nydusd
    snapshotter.request_sendfd(&old_nydusd.api_sock);

    // Start new nydusd but don't mount
    new_nydusd.start_with_upgrade(None, "mnt")?;

    // New nydusd's state should be INIT
    assert_eq!(snapshotter.get_status(&new_nydusd.api_sock), "INIT");

    // Snapshotter tells old nydusd to exit
    snapshotter.kill_nydusd(&old_nydusd.api_sock);

    // Snapshotter send fuse fd to new nydusd
    snapshotter.take_over(&new_nydusd.api_sock);

    // New nydusd's state should be RUNNING
    assert_eq!(snapshotter.get_status(&new_nydusd.api_sock), "RUNNING");

    // Snapshotter receive fuse fd from new nydusd
    snapshotter.request_sendfd(&new_nydusd.api_sock);

    // Check files in mount point
    let result_path = format!("repeatable/{}.result", COMPAT_BOOTSTRAPS[0]);
    new_nydusd.check(result_path.as_str(), "mnt/sub1")?;

    let result_path = format!("repeatable/{}.result", COMPAT_BOOTSTRAPS[1]);
    new_nydusd.check(result_path.as_str(), "mnt/sub2")?;

    snapshotter.umount(&new_nydusd.api_sock, "/sub2");

    // Stop new nydusd
    new_nydusd.umount("mnt");

    Ok(())
}
