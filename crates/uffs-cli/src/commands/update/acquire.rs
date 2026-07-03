// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Phase C trigger: spawn the `uffs-update` helper to download + verify a
//! release into the staging dir.
//!
//! The HTTP/TLS stack lives in the separate `uffs-update` binary, so the
//! lean `uffs` CLI just locates it (next to `uffs`, else on `PATH`) and
//! shells out — keeping reqwest/rustls out of `uffs.exe`.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context as _, Result, bail};

use super::snapshot;

/// Default upstream repository for self-update artifacts.
pub(super) const DEFAULT_REPO: &str = "skyllc-ai/UltraFastFileSearch";

/// Platform file name of the helper binary.
const fn helper_file_name() -> &'static str {
    if cfg!(windows) {
        "uffs-update.exe"
    } else {
        "uffs-update"
    }
}

/// Locate the `uffs-update` helper — next to the running `uffs` first,
/// then on `PATH`.
pub(super) fn find_helper() -> Result<PathBuf> {
    let name = helper_file_name();
    if let Some(sibling) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(name)))
        .filter(|path| path.exists())
    {
        return Ok(sibling);
    }
    which::which(name)
        .with_context(|| format!("cannot find `{name}` — install it alongside `uffs`"))
}

/// Spawn the acquire helper against a written snapshot, for an optional
/// target version tag. The helper reads the snapshot to know the
/// installed subset and downloads each binary individually. `verbose`
/// forwards `--verbose` so the helper can show per-binary detail.
///
/// # Errors
///
/// Fails if the helper cannot be located or it exits non-zero.
pub(crate) fn spawn(
    snapshot_path: &std::path::Path,
    version: Option<&str>,
    verbose: bool,
) -> Result<()> {
    let helper = find_helper()?;
    let stage = snapshot::update_dir().join("stage");
    let mut command = Command::new(&helper);
    command
        .args(["acquire", "--repo", DEFAULT_REPO, "--snapshot"])
        .arg(snapshot_path)
        .arg("--stage")
        .arg(&stage);
    if let Some(tag) = version {
        command.args(["--version", tag]);
    }
    if verbose {
        command.arg("--verbose");
    }
    let status = command
        .status()
        .with_context(|| format!("spawning {}", helper.display()))?;
    if !status.success() {
        bail!("uffs-update acquire failed (exit {:?})", status.code());
    }
    Ok(())
}

/// Ask the helper for the latest release tag (`vX.Y.Z`) — a single
/// non-mutating release-metadata fetch, no download. Returns `None` if the
/// helper is missing or the lookup fails (e.g. offline); the caller then
/// can't assert "already up to date" and falls back accordingly.
pub(super) fn latest_version() -> Option<String> {
    let helper = find_helper().ok()?;
    let output = Command::new(&helper)
        .args(["check", "--repo", DEFAULT_REPO])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    // Strict parse: the helper is our own binary emitting ASCII `latest=`
    // lines; non-UTF-8 output means something is wrong -> treat as no answer.
    core::str::from_utf8(&output.stdout)
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("latest="))
        .map(|tag| tag.trim().to_owned())
        .filter(|tag| !tag.is_empty())
}
