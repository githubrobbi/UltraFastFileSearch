// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

// Build scripts run on the build host; the workspace's runtime
// `deny(expect_used)`/`deny(unwrap_used)` lints don't apply here.
#![allow(
    clippy::expect_used,
    reason = "build scripts may panic on build-host failure; workspace deny-expect targets runtime code"
)]

//! Build script for `uffs-vss-requestor`.
//!
//! Stamps the git-sha/commit-date/rustc/target/profile build-metadata
//! env vars `uffs_version::handle_version!` reads (matching every other
//! UFFS binary), then compiles `native/vss_shim.cpp` — the narrow VSS
//! requestor shim against the official Windows SDK's `vsbackup.h` (see
//! `docs/dev/architecture/uffs-vss-rust-cpp-shim-implementation-guide.md`)
//! — into a static library and links it into this crate's binary. The
//! native-shim compile is a no-op on every non-Windows build target.

fn main() {
    uffs_version::emit_build_env();
    println!("cargo:rerun-if-changed=native/vss_shim.cpp");
    println!("cargo:rerun-if-changed=native/vss_shim.h");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    cc::Build::new()
        .cpp(true)
        .file("native/vss_shim.cpp")
        .flag_if_supported("-EHsc")
        .warnings(false)
        .compile("uffs_vss_shim");

    println!("cargo:rustc-link-lib=dylib=vssapi");
    println!("cargo:rustc-link-lib=dylib=ole32");
}
