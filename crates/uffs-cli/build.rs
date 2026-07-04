// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

// Build scripts run on the build host, not on the shipping binary's target.
// The workspace `deny(expect_used)` / `deny(unwrap_used)` lints exist to keep
// runtime code panic-free; forcing Result propagation through a build script
// whose only failure modes are `link.exe not found` or `icon file missing`
// adds noise without adding safety.  `expect` with a readable message is the
// idiomatic shape for build-script error reporting.
#![allow(
    clippy::expect_used,
    reason = "build scripts may panic on build-host failure; workspace deny-expect exists for runtime code"
)]

//! Build script for `uffs-cli`.
//!
//! Emits MSVC `/DELAYLOAD` linker directives for DLLs that are imported
//! transitively but are **not** on the hot path of the thin CLI.  Delay-loading
//! means the DLL is not mapped into the process image table at launch; it is
//! only paged in if a function from it is actually called.  For a launcher
//! whose wall-clock budget is dominated by process creation and DLL loads,
//! this is a real win even for "cheap" system DLLs.
//!
//! # Hot-path DLLs (NEVER delay-load these)
//!
//! - `KERNEL32.dll`, `ntdll.dll`, `VCRUNTIME140.dll`, `api-ms-win-*` — core
//!   runtime, loaded before `main` runs.
//! - `advapi32.dll` — `LookupAccountNameW` / `OpenProcessToken` for deriving
//!   the named-pipe user-SID hash (called on every launch).
//! - `userenv.dll` — `GetUserProfileDirectoryW` via `dirs-next` for resolving
//!   the daemon socket / pipe location.
//! - `shell32.dll` — `SHGetKnownFolderPath` via `dirs-next` for config dir.
//! - `bcryptprimitives.dll` — `getrandom` is called before `main` by several
//!   deps (hashmap seed, etc.).
//!
//! # Safe delay-load candidates (imported but never called)
//!
//! - `combase.dll` — COM runtime.  The `windows` crate exposes COM bindings via
//!   the `Win32_System_Com` feature, but `uffs-cli` never calls
//!   `CoInitializeEx`, `CoTaskMemFree`, or any other COM entry point.  The
//!   import is pulled in by the dependency graph only.
//! - `oleaut32.dll` — OLE Automation (BSTR / VARIANT).  Same story: pulled
//!   transitively, never actually called from the CLI binary.
//!
//! If either of these turns out to be called after all, the delay-load stub
//! will resolve lazily on first call — it will NOT crash.  The cost is
//! simply a one-time per-DLL load at the call site instead of at process
//! start.  See `perf-phase2-measurement-plan.md` §2.4 for A/B results.
//!
//! # Windows resources (icon + app manifest)
//!
//! On the same MSVC gate, embeds Windows PE resources via the
//! [`winresource`](https://crates.io/crates/winresource) crate:
//!
//! - **Icon** from `../../assets/brand/icons/uffs.ico` — picked up by Explorer,
//!   the taskbar, and Alt-Tab.
//! - **`app.manifest`** declaring `asInvoker`, `PerMonitorV2` DPI awareness,
//!   and long-path support.
//!
//! **The CLI stays `asInvoker`.**  Elevation policy lives in
//! [`uffs_client::daemon_ctl::ElevationPolicy`] and
//! [`crate::main::format_elevation_help`], not the manifest.  Requiring
//! admin at the manifest level would pop UAC on every `uffs <pattern>`
//! invocation and defeat the v0.5.36 elevation refactor.  See
//! `docs/refactor/elevation-posture.md` for the full posture doc.
//!
//! # Environment
//!
//! Build-time env vars consumed by this script (registry:
//! `docs/architecture/code-quality/build_codegen_policy.md` §5.1, playbook
//! §1049-1056):
//!
//! | Name | Type | Default | Notes |
//! |---|---|---|---|
//! | `CARGO_CFG_TARGET_OS`  | `string` | (set by Cargo) | Gates the effectful block on `target_os == "windows"`. |
//! | `CARGO_CFG_TARGET_ENV` | `string` | (set by Cargo) | Gates the effectful block on `target_env == "msvc"` (vs `gnu`). |
//!
//! Both vars are auto-tracked by Cargo (no explicit
//! `cargo:rerun-if-env-changed=` needed); changes to either value invalidate
//! the build cache automatically.
//!
//! # Inputs / tools / platform
//!
//! - **Files read** (declared via `cargo:rerun-if-changed=`): `build.rs`
//!   (self), `app.manifest`, `../../assets/brand/icons/uffs.ico`.
//! - **Tools required**: MSVC `link.exe` + `delayimp.lib` (for `/DELAYLOAD`);
//!   [`winresource`] crate (for PE resource embedding).
//! - **Platform assumptions**: the effectful block is MSVC-Windows only; on
//!   macOS / Linux / MinGW build hosts the script emits only the three
//!   `cargo:rerun-if-changed=` hints (harmless no-ops).

fn main() {
    // Re-run when this file, the app manifest, or the icon change.  The
    // manifest and icon are embedded into the PE as resources on MSVC
    // targets; without these extra hints Cargo would reuse stale .rsrc
    // data on edits.  On non-Windows the three extra print! lines are
    // harmless no-ops (Cargo just watches files that happen to exist).
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=../../assets/brand/icons/uffs.ico");

    // Stamp UFFS_GIT_SHA + build metadata (commit date, rustc, target, profile)
    // that the shared `uffs-version` macros read, so `uffs --version` ties a
    // running binary to its exact build and `--version -v` prints the full
    // fingerprint. Same stamp across every UFFS binary.
    uffs_version::emit_build_env();

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    // MSVC-only: `/DELAYLOAD` is an MSVC link.exe feature and requires
    // `delayimp.lib` for the stub resolver.  MinGW / GNU toolchains use a
    // different mechanism that we do not attempt here.
    if target_os == "windows" && target_env == "msvc" {
        for dll in ["combase.dll", "oleaut32.dll"] {
            println!("cargo:rustc-link-arg-bins=/DELAYLOAD:{dll}");
        }
        // Stub resolver used by /DELAYLOAD.
        println!("cargo:rustc-link-arg-bins=delayimp.lib");

        // Embed the UFFS icon and `app.manifest` as Windows PE resources.
        // See the crate-level doc for why the manifest declares
        // `asInvoker` instead of `requireAdministrator`.
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../../assets/brand/icons/uffs.ico")
            .set("ProductName", "UltraFastFileSearch")
            .set("FileDescription", "UFFS — Ultra Fast File Search")
            .set("CompanyName", "SKY, LLC.")
            .set("LegalCopyright", "(c) 2025-2026 SKY, LLC. MPL-2.0.")
            .set("OriginalFilename", "uffs.exe")
            .set_manifest_file("app.manifest");

        // Panic on failure is acceptable here: build.rs runs on a build
        // host, and the workspace deny-unwrap lint applies to runtime
        // code (not build scripts).
        res.compile()
            .expect("winresource: failed to embed icon + manifest");
    }
}
