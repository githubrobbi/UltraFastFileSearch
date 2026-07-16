// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

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
//! Job intake, VSS, MFT, and streaming logic are not implemented yet.
//! [`run`] (the ephemeral per-run manifest/failure-log/summary model) is
//! real.

pub mod run;

// Not yet wired into this library's logic — reserved for the manifest /
// frame types this crate will produce and consume once job intake lands.
// `uffs_version::handle_version!` is invoked from `main.rs` only.
use uffs_content_protocol as _;
use uffs_version as _;

/// Placeholder for the not-yet-implemented job entry point.
///
/// Returns `false` until job intake (job-spec parsing, VSS snapshot
/// creation, candidate evaluation, and streaming) is implemented.
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
