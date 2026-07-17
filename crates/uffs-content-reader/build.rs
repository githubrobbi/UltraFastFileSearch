// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

// Build scripts run on the build host, not the shipping binary's target, so the
// workspace `deny(expect_used)` / `deny(unwrap_used)` runtime lints do not
// apply here; panicking on a build-host failure (missing icon / no resource
// compiler) is the idiomatic shape for a build script.
#![allow(
    clippy::expect_used,
    reason = "build scripts may panic on build-host failure; workspace deny-expect targets runtime code"
)]

//! Build script for `uffs-content-reader`.
//!
//! Embeds Windows PE resources — the UFFS icon, version info (company, product,
//! description), and the shared `app.manifest` — into `uffs-content-reader.exe`
//! via [`winresource`](https://crates.io/crates/winresource), so the shipped
//! binary carries proper metadata instead of shipping bare. A bare binary is
//! both unbranded and a mild antivirus false-positive signal. MSVC-Windows
//! only; a no-op on every other build target. Mirrors `uffs-broker`'s build
//! script.

fn main() {
    uffs_version::emit_build_env();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../assets/brand/icons/uffs.ico");
    println!("cargo:rerun-if-changed=../../assets/brand/app.manifest");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        return;
    }

    let mut res = winresource::WindowsResource::new();
    res.set_icon("../../assets/brand/icons/uffs.ico")
        .set("ProductName", "UltraFastFileSearch")
        .set(
            "FileDescription",
            "UFFS Content Reader (privileged VSS snapshot content reader)",
        )
        .set("CompanyName", "SKY, LLC.")
        .set("LegalCopyright", "(c) 2025-2026 SKY, LLC. MPL-2.0.")
        .set("OriginalFilename", "uffs-content-reader.exe")
        .set_manifest_file("../../assets/brand/app.manifest");
    res.compile()
        .expect("winresource: failed to embed uffs-content-reader resources");
}
