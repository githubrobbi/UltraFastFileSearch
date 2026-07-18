// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Real-VSS, real-Reader end-to-end playback test —
//! `uffs-ingest-implementation-plan.md` §9.4's real-VSS variant, and
//! §5.4's "real snapshot, real file, assert bytes match" live test.
//!
//! Thin wrapper: calls
//! [`uffs_content::job::self_test::self_test_vss_playback`] — the exact
//! same production function `uffs-content --self-test-vss-playback` and
//! `scripts/windows/content-reader-validation.rs` both exercise, so none
//! of the three ever drift apart (mirrors `uffs-broker`'s
//! `--self-test-vss` / `cargo test -p uffs-broker -- --ignored` /
//! `scripts/windows/vss-snapshot-validation.rs` trio).
//!
//! # Requirements to actually run this test
//!
//! - Windows, and this test process itself running elevated (VSS snapshot
//!   creation and the Reader's `OpenFileById` device-path open both require it
//!   — see `job::vss_orchestrator`'s and
//!   `uffs-content-reader/src/reader/logical.rs`'s doc comments for why
//!   elevation is a deliberate v1 choice, not yet Broker-mediated).
//! - `uffs-broker --install` already run once on the host (or the Broker's
//!   Snapshot Manager reachable some other way).
//! - `uffsd` and `uffs-content-reader` built and discoverable next to this test
//!   binary (both are spawned as child processes).
//!
//! None of that is available in this workspace's ordinary CI lanes, so
//! this is `#[ignore]` — run explicitly on a prepared Windows box with
//! `cargo test -p uffs-content --test e2e_real_vss_content_reader --
//! --ignored`.

#![cfg(test)]

// This crate's own dependencies (shared across every integration test
// binary in this crate), not used directly from this particular test
// module on every platform.
// These are Windows-only deps of `uffs-content` itself
// (`job::vss_orchestrator`/`ephemeral_daemon`/`reader_client`/
// `self_test`), reached transitively through `uffs_content::job::
// self_test::self_test_vss_playback` but not named directly by this
// thin test — same rationale as `src/main.rs`'s matching markers.
#[cfg(windows)]
use anyhow as _;
use blake3 as _;
// Used by `uffs_content::job::workflow`'s pipelined content reader, not
// by this thin test directly (its own real test body is windows-only,
// see below — but the dependency itself is unconditional).
use crossbeam_channel as _;
use serde as _;
use serde_json as _;
// Used only inside the `#[cfg(windows)] mod windows_tests` below — the
// real test body needs Windows, so these are otherwise
// visible-but-unused on every other platform.
#[cfg(not(windows))]
use tempfile as _;
#[cfg(windows)]
use tokio as _;
// Unconditional dependency of `uffs-content` (see that crate's
// `Cargo.toml`) — reached transitively on every platform, not named
// directly by this thin test on either.
use tracing as _;
#[cfg(windows)]
use tracing_subscriber as _;
#[cfg(windows)]
use uffs_broker_protocol as _;
#[cfg(windows)]
use uffs_client as _;
#[cfg(not(windows))]
use uffs_content as _;
use uffs_content_protocol as _;
#[cfg(windows)]
use uffs_content_reader_protocol as _;
#[cfg(windows)]
use uffs_mft as _;
#[cfg(windows)]
use uffs_security as _;
use uffs_version as _;
use uuid as _;

/// All real test code is Windows-only — see the module doc for why.
#[cfg(windows)]
mod windows_tests {
    /// Playback through the real VSS + Reader pipeline must reproduce a
    /// freshly created, uniquely-named sample file's content exactly.
    ///
    /// # Requirements
    /// See this file's module doc comment.
    #[test]
    #[ignore = "requires Windows, elevation, an installed uffs-broker, and \
                uffsd/uffs-content-reader built alongside the test binary"]
    fn real_vss_playback_matches_original_file_content() {
        let test_dir = tempfile::tempdir().expect("create test dir");
        uffs_content::job::self_test::self_test_vss_playback(test_dir.path())
            .expect("real VSS snapshot + Reader playback round trip must succeed");
    }

    /// An extension-filtered query against a real, pre-existing directory
    /// (an arbitrary number of real files, not a synthetic sample) must
    /// report metadata and streamed-content totals that exactly match an
    /// independent ground-truth filesystem walk.
    ///
    /// The root directory is necessarily machine-specific (a real drive
    /// with real files already on it), so it can't be hardcoded here —
    /// set `UFFS_CONTENT_QUERY_TEST_ROOT` (e.g. `G:\`) and, optionally,
    /// `UFFS_CONTENT_QUERY_TEST_EXT` (default `txt`).
    ///
    /// # Requirements
    /// See this file's module doc comment, plus `UFFS_CONTENT_QUERY_TEST_ROOT`
    /// above.
    #[test]
    #[ignore = "requires Windows, elevation, an installed uffs-broker, \
                uffsd/uffs-content-reader built alongside the test binary, and \
                UFFS_CONTENT_QUERY_TEST_ROOT set to a real directory"]
    fn real_vss_query_metadata_matches_ground_truth_disk_walk() {
        let root = std::env::var("UFFS_CONTENT_QUERY_TEST_ROOT")
            .expect("set UFFS_CONTENT_QUERY_TEST_ROOT to a real directory, e.g. G:\\");
        let extension =
            std::env::var("UFFS_CONTENT_QUERY_TEST_EXT").unwrap_or_else(|_| "txt".to_owned());
        uffs_content::job::self_test::self_test_vss_query_metadata(
            std::path::Path::new(&root),
            &extension,
        )
        .expect("real VSS query metadata/content totals must match ground truth");
    }
}
