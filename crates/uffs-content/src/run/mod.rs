// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Ephemeral per-run bookkeeping.
//!
//! A run's state is intentionally **not** a transactional per-candidate
//! job database. Three artifacts on disk fully describe a run:
//!
//! 1. The immutable candidate manifest ([`uffs_content_protocol::manifest`]) —
//!    written once, before streaming starts, and never modified.
//! 2. An append-only JSONL failure log (`run-<id>.failures.jsonl`) — one
//!    [`FailureRecord`] line per non-success candidate, appended as candidates
//!    resolve. See [`FailureLogWriter`].
//! 3. A [`RunSummary`], atomically finalized only once every candidate has
//!    reached a terminal outcome (`run-<id>.summary.json`). See
//!    [`RunCounters::finalize`] and [`RunSummary::finalize_to_disk`].
//!
//! There is no durable per-candidate ledger, no lease/attempt history,
//! and no crash-recovery reconciliation: if the process or machine dies
//! before the summary is finalized, the run is simply incomplete — the
//! existence of a valid final summary file *is* the job-completion
//! marker. Re-running from a fresh VSS snapshot is the recovery path,
//! not resuming mid-job: Docenta's own content-hash deduplication makes
//! re-streaming already-ingested content on a rerun a no-op on the
//! consumer side, so restarting from zero wastes no meaningful work.

mod failure_log;
mod summary;

pub use failure_log::{FailureLogWriter, FailureOutcomeKind, FailureRecord};
pub use summary::{RunCounters, RunSummary, SummaryFinalizeError};

#[cfg(test)]
mod tests;
