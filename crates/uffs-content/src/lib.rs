// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

// `MetadataExt::file_index` (the Windows analogue of a Unix inode,
// used by `job::candidate_source::file_identity` for hard-link
// detection) is still gated behind this unstable std feature
// (rust-lang/rust#63010) with no stable alternative. Sound to rely on
// here: `rust-toolchain.toml` pins the exact same nightly across every
// environment (host, Windows, Linux) workspace-wide, not just for this
// crate, and `just toolchain-sync` re-validates every bump attempt
// against it before the pin moves.
#![cfg_attr(windows, feature(windows_by_handle))]

//! UFFS Content Service — library crate.
//!
//! `uffs-content` is the unprivileged content **coordinator**: read-mode
//! planning, candidate-manifest handling, and framed content streaming.
//! Any privileged VSS-snapshot/raw-extent capability is a narrow internal
//! helper this crate calls into (extending `uffs-broker`'s existing
//! pattern), never a whole-volume handle owned directly by this process.
//! See `docs/dev/architecture/uffs-content-stream-enterprise-design-review.md`
//! (local-only) for the rationale, and Docenta's
//! `uffs-ingest-protocol-v2-vss.md` for the settled manifest/frame
//! contract. The `[[bin]]` in this crate (`src/main.rs`) is a thin entry
//! point over this library, matching the `uffs-daemon` / `uffs_daemon`
//! split.
//!
//! # Status
//!
//! [`run`] (the ephemeral per-run manifest/failure-log/summary model) and
//! [`job`] (job intake, candidate enumeration, manifest construction, and
//! protocol framing) are real — but [`job`]'s [`job::candidate_source`]
//! and [`job::content_source`] backends are currently the cross-platform
//! `std::fs`-based stand-ins described in
//! `uffs-ingest-implementation-plan.md` §9.5, not the real VSS-snapshot
//! and privileged-Reader-backed ones (UFI.1/UFI.2). [`is_implemented`]
//! tracks the latter, not this crate's own workflow logic.

pub mod job;
pub mod run;

// `uffs_version::handle_version!` is invoked from `main.rs` only.
// Dev-dependency used by `tests/support/plain_walk.rs` (the independent
// oracle for the E2E dir-walk parity harness), not by this crate's own
// unit tests.
#[cfg(test)]
use blake3 as _;
use uffs_version as _;

/// Whether the production, VSS-snapshot-backed pipeline is wired up.
///
/// Returns `false` until [`job::candidate_source`] and
/// [`job::content_source`] have real Broker/Reader-backed implementations
/// (UFI.1/UFI.2) — the workflow itself ([`job::workflow::run_job`]) is
/// already real, just not yet running against NTFS.
#[must_use]
pub const fn is_implemented() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::is_implemented;

    #[test]
    fn scaffold_reports_not_implemented() {
        assert!(!is_implemented());
    }
}
