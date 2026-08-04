// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Acquire (self-update Phase C) — **per-binary**, no archive.
//!
//! For each binary the install actually has, download that binary as an
//! individual release asset (`uffsd.exe`, `uffs.exe`, …) and verify its
//! SHA-256 against the release's `SHA256SUMS`, straight into the staging
//! dir — which is exactly the loose-binary layout the apply phase reads.
//!
//! Why per-binary, not a bundle zip: it needs **no in-process archive
//! crate** (zip/tar pull unaudited deps and, shelled, aren't on every
//! Windows), each binary is **individually** SHA- and (at apply time)
//! Authenticode-verifiable, and we only fetch the installed subset.
//!
//! Requires the release to publish per-binary assets + `SHA256SUMS` (a
//! release-pipeline follow-up; the code is ready for it).

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use uffs_fetch::{github, verify};

use crate::orchestrate::{asset_name, exe_name};

/// Inputs for one acquire run.
pub(crate) struct AcquirePlan {
    /// GitHub `owner/repo`.
    pub(crate) repo: String,
    /// Release tag (e.g. `v0.6.2`), or `None` for latest.
    pub(crate) tag: Option<String>,
    /// Directory to stage verified binaries into.
    pub(crate) stage: PathBuf,
    /// Checksums asset name.
    pub(crate) sums: String,
    /// Binary stems to fetch (e.g. `["uffs", "uffsd"]`).
    pub(crate) binaries: Vec<String>,
}

/// Download + SHA-verify every requested binary into the staging dir.
/// Returns the staged paths. Aborts (leaving nothing trusted) on a
/// missing asset, a missing checksum, or a SHA mismatch.
///
/// # Errors
///
/// Network/HTTP errors, missing assets/checksums, or hash mismatch.
pub(crate) fn run(plan: &AcquirePlan) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(&plan.stage)
        .with_context(|| format!("creating stage dir {}", plan.stage.display()))?;

    let release = github::fetch_release(crate::USER_AGENT, &plan.repo, plan.tag.as_deref())?;

    // Checksums first.
    let sums_url = release
        .asset(&plan.sums)
        .with_context(|| format!("release {} has no asset {}", release.tag_name, plan.sums))?
        .browser_download_url
        .clone();
    let sums_path = plan.stage.join(&plan.sums);
    github::download_to(
        crate::USER_AGENT,
        &sums_url,
        &sums_path,
        crate::MAX_ASSET_BYTES,
    )?;
    let sums_text = std::fs::read_to_string(&sums_path)
        .with_context(|| format!("reading {}", sums_path.display()))?;
    let sums = verify::parse_sha256sums(&sums_text);

    // Each binary as an individual asset. We download the platform-
    // suffixed release asset (`uffsd-windows-x64.exe`) but stage it under
    // the plain on-disk name (`uffsd.exe`) so the apply phase finds it.
    let mut staged = Vec::with_capacity(plan.binaries.len());
    for stem in &plan.binaries {
        let asset = asset_name(stem);
        let url = release
            .asset(&asset)
            .with_context(|| format!("release {} has no asset {asset}", release.tag_name))?
            .browser_download_url
            .clone();
        let dest = plan.stage.join(exe_name(stem));
        github::download_to(crate::USER_AGENT, &url, &dest, crate::MAX_ASSET_BYTES)?;

        let expected = verify::expected_hash(&sums, &asset)
            .with_context(|| format!("{asset} is not listed in {}", plan.sums))?;
        if !verify::verify_sha256(&dest, expected)? {
            let _ignore = std::fs::remove_file(&dest);
            bail!("SHA-256 mismatch for {asset} — download rejected, nothing staged");
        }
        // Downloads land 0644 — not executable. The apply-phase smoke test
        // runs the swapped-in binary (and it must run once installed), so a
        // staged binary that isn't +x makes apply fail with "smoke test failed"
        // on macOS/Linux. (No-op on Windows.)
        make_executable(&dest)?;
        staged.push(dest);
    }
    Ok(staged)
}

/// Mark a freshly-downloaded binary executable. Unix only; Windows ignores the
/// mode bits, so this is a no-op there.
#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut perms = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).with_context(|| format!("chmod +x {}", path.display()))
}

/// Non-Unix: executability is not governed by file mode.
#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "signature mirrors the Unix path so the `?` call site compiles on every target"
)]
const fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn make_executable_sets_the_exec_bits() {
        use std::os::unix::fs::PermissionsExt as _;

        use super::make_executable;

        // A freshly-written download lands 0644 (no exec bit) — the exact
        // state that made apply fail the smoke test on macOS/Linux.
        let path = std::env::temp_dir().join(format!("uffs-acq-{}", std::process::id()));
        std::fs::write(&path, b"#!/bin/sh\n").expect("write temp binary");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("seed 0644");
        assert_eq!(
            std::fs::metadata(&path).expect("stat").permissions().mode() & 0o111,
            0,
            "precondition: not executable"
        );

        make_executable(&path).expect("make_executable");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_ne!(
            mode & 0o100,
            0,
            "owner-execute bit must be set after the fix"
        );
        let _cleanup = std::fs::remove_file(&path);
    }
}
