fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    if target_os != "linux" || target_env != "gnu" || target_arch != "x86_64" {
        return;
    }

    if std::env::var_os("CARGO_FEATURE_LZ4_IPP").is_some() {
        let topdir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

        println!("cargo:rustc-cfg=lz4_ipp_enabled");
        println!(
            "cargo:rustc-link-search=native={}/src/storage/compress",
            topdir
        );
        println!("cargo:rustc-link-lib=static=ippcore");
    }
}
