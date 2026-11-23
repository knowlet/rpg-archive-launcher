fn main() {
    println!("cargo:rerun-if-changed=native/fuse_bridge.c");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    if std::env::var_os("CARGO_FEATURE_FUSE").is_none() {
        return;
    }
    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target != "macos" && target != "linux" {
        panic!(
            "the optional fuse adapter currently supports macOS/macFUSE and Linux/libfuse2 only"
        );
    }
    let fuse = pkg_config::Config::new()
        .atleast_version("2.9")
        .probe("fuse")
        .expect("feature fuse needs libfuse2 development headers (Linux: libfuse-dev; macOS: install macFUSE, add /usr/local/lib/pkgconfig to PKG_CONFIG_PATH)");
    let mut build = cc::Build::new();
    build
        .file("native/fuse_bridge.c")
        .define("_FILE_OFFSET_BITS", "64")
        .flag_if_supported("-std=c11");
    if target == "linux" {
        build.define("_DEFAULT_SOURCE", None);
    }
    for path in fuse.include_paths {
        build.include(path);
    }
    for (name, value) in fuse.defines {
        build.define(&name, value.as_deref());
    }
    build.compile("rpg_fuse_bridge");
}
