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
pub mod workflow;

#[cfg(test)]
mod tests;
