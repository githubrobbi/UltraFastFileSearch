// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Job intake and execution: the real Coordinator workflow described in
//! `docs/dev/architecture/uffs-ingest-implementation-plan.md` §6.
//!
//! Built against swappable [`candidate_source::CandidateSource`] /
//! [`content_source::ContentSource`] backends so it can be exercised
//! today — via this crate's own
//! [`candidate_source::DirWalkCandidateSource`] /
//! [`content_source::FsContentSource`] — ahead of the real
//! Broker/Reader-backed implementations landing (UFI.1/UFI.2). This is
//! also what powers the plan's §9.5 "fast" end-to-end dir-walk parity
//! harness (`crates/uffs-content/tests/e2e_dir_walk_parity_fake_reader.rs`).

pub mod candidate_source;
pub mod content_source;
pub mod intake;
pub mod manifest_builder;
// In-memory per-job resume state (which candidates a reconnecting
// consumer still needs streamed). Cross-platform: pure logic, no VSS/
// pipe dependency of its own. `pub(crate)` so `crate::serve` (the
// two-pipe transport server, a sibling of this module) can reach it.
pub(crate) mod registry;
// Credit-based backpressure tracker (design-doc §13). Cross-platform:
// pure logic, no VSS/pipe dependency of its own. `pub(crate)` for the
// same reason as `registry`.
pub(crate) mod window;
// Coordinator-side client for the Broker's Snapshot Manager pipe — the
// real VSS lease backend `candidate_source`'s VSS-backed implementation
// calls into. Windows-only: no VSS, no Broker to talk to elsewhere,
// matching the `[target.'cfg(windows)'.dependencies]` scoping in
// Cargo.toml this module's own dependency (`uffs-broker-protocol`)
// requires.
#[cfg(windows)]
pub mod snapshot_client;
// Spawns/connects/tears down the ephemeral `uffsd` instance that
// answers target-selection queries against a leased VSS snapshot.
// Windows-only for the same reason as `snapshot_client`.
#[cfg(windows)]
pub mod ephemeral_daemon;
// Ties `snapshot_client` and `ephemeral_daemon` together: one lease per
// distinct drive, one combined daemon. Windows-only for the same reason
// as its two dependents.
#[cfg(windows)]
pub mod vss_orchestrator;
// Coordinator-side client for `uffs-content-reader-protocol` — spawns
// and talks to the privileged `uffs-content-reader` process
// `content_source::VssContentSource` reads through. Windows-only for
// the same reason as its siblings.
#[cfg(windows)]
pub mod reader_client;
pub mod workflow;
// End-to-end VSS-backed job execution — ties every piece above together
// into the real production entry point. Windows-only for the same
// reason as its dependencies.
#[cfg(windows)]
pub mod vss_job;
// Elevated smoke test: real VSS + real Reader playback, reused by the
// `--self-test-vss-playback` CLI flag and the `#[ignore]` cargo test.
// Windows-only for the same reason as `vss_job`.
#[cfg(windows)]
pub mod self_test;

#[cfg(test)]
mod tests;
