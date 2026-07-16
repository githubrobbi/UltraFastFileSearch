// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! UFFS Content Service — unprivileged content-coordinator binary for
//! downstream consumers (e.g. Docenta).
//!
//! # Status
//!
//! Scaffold only. Job intake (structured JSON job spec), VSS snapshot
//! orchestration, candidate evaluation, and framed content streaming are
//! not yet implemented. See Docenta's `uffs-ingest-protocol-v2-vss.md` for
//! the target contract (the authoritative spec this tool is built
//! against) and `docs/dev/architecture/` (local-only) for the surrounding
//! design review.
//!
//! # Usage (planned)
//!
//! ```bash
//! uffs-content --version   # Print version (also -V)
//! ```

// Reserved for the wire types the bin will emit once job intake is wired
// up; not yet used from this thin entry point.
use uffs_content_protocol as _;

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
