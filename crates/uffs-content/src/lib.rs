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
//! [`run`] (the ephemeral per-run manifest/failure-log/summary model),
//! [`job`] (job intake, candidate enumeration, manifest construction,
//! and protocol framing — both the cross-platform `std::fs`-based
//! stand-ins from `uffs-ingest-implementation-plan.md` §9.5 and the
//! real VSS-snapshot/privileged-Reader-backed production path,
//! `job::vss_job::run_vss_job`), and the two-pipe transport server
//! (`serve`, Windows-only) that lets an external consumer actually reach
//! that pipeline, are all real. [`is_implemented`] tracks the
//! VSS-backed pipeline's platform availability, not this crate's own
//! workflow logic.

extern crate alloc;

pub mod job;
pub mod run;
// Two-pipe (data + command) transport server: the real entry point an
// external consumer (e.g. Docenta) connects to. Windows-only — named
// pipes, and every job this serves is VSS-backed (`job::vss_job`,
// itself Windows-only).
#[cfg(windows)]
pub(crate) mod serve;

// `uffs_version::handle_version!` is invoked from `main.rs` only.
// Dev-dependency used by `tests/support/plain_walk.rs` (the independent
// oracle for the E2E dir-walk parity harness), not by this crate's own
// unit tests.
#[cfg(test)]
use blake3 as _;
// Installed by `main.rs::init_tracing()` (the bin target), not used
// directly by this library crate.
#[cfg(windows)]
use tracing_subscriber as _;
use uffs_version as _;

/// Whether the production, VSS-snapshot-backed pipeline is wired up.
///
/// `true` on Windows: [`job::candidate_source::VssCandidateSource`] and
/// [`job::content_source::VssContentSource`] are real, and
/// [`job::vss_job::run_vss_job`] has been validated end to end against
/// real hardware (real VSS snapshot, real ephemeral target-selection
/// daemon, real privileged Reader). `false` on every other platform —
/// VSS doesn't exist there, so this pipeline fundamentally can't run.
#[must_use]
#[cfg(windows)]
pub const fn is_implemented() -> bool {
    true
}

/// Non-Windows: see the Windows doc comment above for why this is
/// always `false` here, not a scaffold-vs-real distinction.
#[must_use]
#[cfg(not(windows))]
pub const fn is_implemented() -> bool {
    false
}

/// Run the two-pipe transport server for the process's whole lifetime.
///
/// The real entry point an external consumer (e.g. Docenta) connects
/// to. See the crate-private `serve` module's doc comment for the
/// wire-level design.
///
/// # Errors
/// Returns an error only if a pipe itself cannot be created at all.
#[cfg(windows)]
pub fn serve() -> anyhow::Result<()> {
    serve::run()
}

#[cfg(test)]
mod tests {
    use super::is_implemented;

    #[test]
    fn is_implemented_matches_platform_capability() {
        assert_eq!(is_implemented(), cfg!(windows));
    }
}
