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

//! Build script for `uffs-manifest-audit`.
//!
//! Embeds the UFFS icon + version info + shared `app.manifest` into
//! `uffs-manifest-audit.exe` via [`winresource`](https://crates.io/crates/winresource),
//! for branding consistency with the rest of the UFFS binary family.
//! MSVC-Windows only; a no-op on every other build target.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../../assets/brand/icons/uffs.ico");
    println!("cargo:rerun-if-changed=../../../assets/brand/app.manifest");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        return;
    }

    let mut res = winresource::WindowsResource::new();
    res.set_icon("../../../assets/brand/icons/uffs.ico")
        .set("ProductName", "UltraFastFileSearch")
        .set("FileDescription", "UFFS CI: manifest auditor")
        .set("CompanyName", "SKY, LLC.")
        .set("LegalCopyright", "(c) 2025-2026 SKY, LLC. MPL-2.0.")
        .set_manifest_file("../../../assets/brand/app.manifest");
    res.compile()
        .expect("winresource: failed to embed uffs-manifest-audit resources");
}
