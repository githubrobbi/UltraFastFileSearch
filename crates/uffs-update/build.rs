// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

// Build scripts run on the build host, not the shipping binary; the workspace
// deny-expect lint exists for runtime code. `expect` with a readable message is
// the idiomatic shape for build-script error reporting.
#![allow(
    clippy::expect_used,
    reason = "build scripts may panic on build-host failure; workspace deny-expect exists for runtime code"
)]

//! Build script: embed `app.manifest` into `uffs-update.exe` on Windows MSVC.
//!
//! The manifest declares `asInvoker`, which is **required** to stop Windows'
//! Installer Detection heuristic from force-elevating this binary purely
//! because its name contains "update". Without it, `uffs.exe` (non-elevated)
//! cannot spawn `uffs-update.exe` — it fails with `ERROR_ELEVATION_REQUIRED`
//! (os error 740) — breaking every `uffs --update` operation on Windows. The
//! helper only rewrites files in the user's install dir; it never needs admin.
//!
//! The manifest is intentionally minimal (`trustInfo`-only): a richer earlier
//! version tripped `ERROR_SXS_CANT_GEN_ACTCTX` (os error 14001) so the binary
//! would not start at all. See `app.manifest` for the full rationale.
//!
//! Inert on non-Windows / non-MSVC targets (the helper ships windows-msvc).

fn main() {
    uffs_version::emit_build_env();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=../../assets/brand/icons/uffs.ico");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    if target_os == "windows" && target_env == "msvc" {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../../assets/brand/icons/uffs.ico")
            .set("ProductName", "UltraFastFileSearch")
            .set("FileDescription", "UFFS self-update helper")
            .set("CompanyName", "SKY, LLC.")
            .set("LegalCopyright", "(c) 2025-2026 SKY, LLC. MPL-2.0.")
            .set("OriginalFilename", "uffs-update.exe")
            .set_manifest_file("app.manifest");

        // Panic on failure is fine in a build script (host-only; the
        // workspace deny-unwrap lint targets runtime code).
        res.compile()
            .expect("winresource: failed to embed uffs-update manifest");
    }
}
