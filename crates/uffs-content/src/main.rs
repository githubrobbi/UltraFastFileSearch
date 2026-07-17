// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! UFFS Content Service — unprivileged content-coordinator binary for
//! downstream consumers (e.g. Docenta).
//!
//! # Status
//!
//! Job intake, manifest construction, and protocol framing are
//! implemented (`uffs_content::job`), but only against the cross-platform
//! `std::fs`-based candidate/content sources, not real VSS snapshots yet.
//! This bin is still a thin `--version`-only entry point — it does not
//! yet parse a job spec off the command line and dispatch it. See
//! Docenta's `uffs-ingest-protocol-v2-vss.md` for the target contract
//! (the authoritative spec this tool is built against) and
//! `docs/dev/architecture/` (local-only) for the surrounding design
//! review.
//!
//! # Usage
//!
//! ```bash
//! uffs-content --version                        # Print version (also -V)
//! uffs-content --self-test-vss-playback <dir>    # Elevated smoke test: real VSS
//!                                                 # snapshot + real Reader playback
//! uffs-content --self-test-vss-query <root> <ext> # Elevated smoke test: real
//!                                                 # extension-filtered query against
//!                                                 # an existing directory, verified
//!                                                 # against a ground-truth disk walk
//! ```

// Reserved for the wire types the bin will emit once job intake is wired
// up as a real CLI entry point; not yet used from this thin bin.
// Dev-dependencies used by `uffs_content`'s tests, not by this bin.
// Used by `uffs_content::job::snapshot_client` (the real Snapshot
// Manager pipe client), not by this thin entry point directly.
#[cfg(windows)]
use anyhow as _;
#[cfg(test)]
use blake3 as _;
// Used by `uffs_content::run` (failure log + summary serialization), not
// by this thin entry point directly.
use serde as _;
use serde_json as _;
#[cfg(test)]
use tempfile as _;
// Used by `uffs_content::job::vss_orchestrator` (best-effort
// lease-release warnings), not by this thin entry point directly.
#[cfg(windows)]
use tracing as _;
#[cfg(windows)]
use uffs_broker_protocol as _;
// Used to spawn/query the ephemeral `uffsd` instance (not by this thin
// entry point directly).
#[cfg(windows)]
use uffs_client as _;
use uffs_content_protocol as _;
// Used by `uffs_content::job::reader_client`/`content_source::VssContentSource`,
// not by this thin entry point directly.
#[cfg(windows)]
use uffs_content_reader_protocol as _;
// Used by `uffs_content::job::workflow`, not by this thin entry point
// directly.
use uuid as _;

#[expect(
    clippy::print_stderr,
    reason = "scaffold only: no tracing subscriber exists yet, so this is the \
              only way the operator sees the status. Replace with `tracing::info!` \
              once job intake wires up a subscriber, matching uffsd/uffs-broker."
)]
fn main() {
    // `--version` / `-V` is handled here, before any job dispatch, so it
    // works on every platform and exits 0 — matches `uffs-broker` and
    // `uffsd` so the self-update version probe can parse it uniformly.
    uffs_version::handle_version!("uffs-content");

    let args: Vec<String> = std::env::args().collect();
    if let Some(test_dir) = self_test_vss_playback_dir(&args) {
        std::process::exit(run_self_test_vss_playback(&test_dir));
    }
    if let Some((root, extension)) = self_test_vss_query_args(&args) {
        std::process::exit(run_self_test_vss_query(&root, &extension));
    }

    if uffs_content::is_implemented() {
        eprintln!("uffs-content: ready.");
    } else {
        eprintln!("uffs-content: scaffold only, job intake is not yet implemented.");
    }
}

/// Return the directory argument following `--self-test-vss-playback`,
/// if present.
#[cfg(windows)]
fn self_test_vss_playback_dir(args: &[String]) -> Option<std::path::PathBuf> {
    let flag_index = args
        .iter()
        .position(|arg| arg == "--self-test-vss-playback")?;
    args.get(flag_index + 1).map(std::path::PathBuf::from)
}

/// Non-Windows stub: `--self-test-vss-playback` needs a real VSS
/// snapshot, which doesn't exist on this platform.
#[cfg(not(windows))]
const fn self_test_vss_playback_dir(_args: &[String]) -> Option<std::path::PathBuf> {
    None
}

/// Run [`uffs_content::job::self_test::self_test_vss_playback`] and
/// print a PASS/FAIL result — a manual, elevated smoke test proving the
/// real VSS-snapshot + privileged-Reader content pipeline works at
/// runtime on this machine. Returns the process exit code (`0` pass,
/// `1` fail).
#[cfg(windows)]
#[expect(
    clippy::print_stderr,
    reason = "one-shot CLI diagnostic invoked before any tracing subscriber exists"
)]
fn run_self_test_vss_playback(test_dir: &std::path::Path) -> i32 {
    match uffs_content::job::self_test::self_test_vss_playback(test_dir) {
        Ok(()) => {
            eprintln!(
                "PASS: VSS snapshot + Reader playback round trip succeeded ({})",
                test_dir.display()
            );
            0
        }
        Err(err) => {
            eprintln!("FAIL: {err:#}");
            1
        }
    }
}

/// Non-Windows stub, matching [`self_test_vss_playback_dir`] always
/// returning `None` there (so this is unreachable in practice, but kept
/// for a symmetrical `#[cfg]` shape).
#[cfg(not(windows))]
const fn run_self_test_vss_playback(_test_dir: &std::path::Path) -> i32 {
    1
}

/// Return the `(root, extension)` arguments following
/// `--self-test-vss-query`, if present.
#[cfg(windows)]
fn self_test_vss_query_args(args: &[String]) -> Option<(std::path::PathBuf, String)> {
    let flag_index = args.iter().position(|arg| arg == "--self-test-vss-query")?;
    let root = args.get(flag_index + 1).map(std::path::PathBuf::from)?;
    let extension = args.get(flag_index + 2).cloned()?;
    Some((root, extension))
}

/// Non-Windows stub: `--self-test-vss-query` needs a real VSS snapshot,
/// which doesn't exist on this platform.
#[cfg(not(windows))]
const fn self_test_vss_query_args(_args: &[String]) -> Option<(std::path::PathBuf, String)> {
    None
}

/// Run [`uffs_content::job::self_test::self_test_vss_query_metadata`] and
/// print a PASS/FAIL result. Returns the process exit code (`0` pass, `1`
/// fail).
#[cfg(windows)]
#[expect(
    clippy::print_stderr,
    reason = "one-shot CLI diagnostic invoked before any tracing subscriber exists"
)]
fn run_self_test_vss_query(root: &std::path::Path, extension: &str) -> i32 {
    match uffs_content::job::self_test::self_test_vss_query_metadata(root, extension) {
        Ok(()) => {
            eprintln!(
                "PASS: query metadata/content totals matched ground truth ({}, *.{extension})",
                root.display()
            );
            0
        }
        Err(err) => {
            eprintln!("FAIL: {err:#}");
            1
        }
    }
}

/// Non-Windows stub, matching [`self_test_vss_query_args`] always
/// returning `None` there (so this is unreachable in practice, but kept
/// for a symmetrical `#[cfg]` shape).
#[cfg(not(windows))]
const fn run_self_test_vss_query(_root: &std::path::Path, _extension: &str) -> i32 {
    1
}
