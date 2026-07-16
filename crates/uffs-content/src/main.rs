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
//! # Usage (planned)
//!
//! ```bash
//! uffs-content --version   # Print version (also -V)
//! ```

// Reserved for the wire types the bin will emit once job intake is wired
// up as a real CLI entry point; not yet used from this thin bin.
// Dev-dependencies used by `uffs_content`'s tests, not by this bin.
#[cfg(test)]
use blake3 as _;
// Used by `uffs_content::run` (failure log + summary serialization), not
// by this thin entry point directly.
use serde as _;
use serde_json as _;
#[cfg(test)]
use tempfile as _;
use uffs_content_protocol as _;
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

    if uffs_content::is_implemented() {
        eprintln!("uffs-content: ready.");
    } else {
        eprintln!("uffs-content: scaffold only, job intake is not yet implemented.");
    }
}
