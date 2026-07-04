// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

// Build scripts run on the build host, not the shipping binary's target, so
// the workspace `deny(unwrap_used)` / `deny(expect_used)` runtime lints do not
// apply here; best-effort error handling with sensible fallbacks is the
// idiomatic shape for a build script whose only "failure" is "git not present".
#![allow(
    clippy::expect_used,
    reason = "build scripts may panic on build-host failure; workspace deny-expect targets runtime code"
)]

//! Build script for `uffs-daemon`.
//!
//! Two jobs:
//!
//! 1. Emits `UFFS_GIT_SHA` — the short commit the daemon was built from, with a
//!    `-dirty` suffix when the working tree had uncommitted changes — so the
//!    startup log can stamp **which build** is running. A definitive build
//!    stamp in the daemon log is how a field log (or a WIN test-script) is tied
//!    back to the exact binary that produced it, closing the "ran the
//!    wrong/stale binary" trap. Read back via `option_env!("UFFS_GIT_SHA")` in
//!    `startup.rs`.
//! 2. On MSVC-Windows, embeds PE resources (UFFS icon, version info, shared
//!    `app.manifest`) into `uffsd.exe` via [`winresource`], so the shipped
//!    binary carries proper metadata instead of shipping bare — a bare binary
//!    is both unbranded and a mild antivirus false-positive signal.

fn main() {
    embed_windows_resources();

    // Stamp UFFS_GIT_SHA + build metadata (commit date, rustc, target, profile)
    // for the shared `uffs-version` macros — the same stamp every UFFS binary
    // uses. `startup.rs` still reads `option_env!("UFFS_GIT_SHA")` for its log
    // prelude; `--version` / `--version -v` read the full set.
    uffs_version::emit_build_env();
    println!("cargo:rerun-if-changed=build.rs");
}

/// Embed the UFFS icon, version info, and shared `app.manifest` into
/// `uffsd.exe` on MSVC-Windows; a no-op on every other build target.
fn embed_windows_resources() {
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
        .set("FileDescription", "UFFS daemon (resident index server)")
        .set("CompanyName", "SKY, LLC.")
        .set("LegalCopyright", "(c) 2025-2026 SKY, LLC. MPL-2.0.")
        .set("OriginalFilename", "uffsd.exe")
        .set_manifest_file("../../assets/brand/app.manifest");
    res.compile()
        .expect("winresource: failed to embed uffs-daemon resources");
}
