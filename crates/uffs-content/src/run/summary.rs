// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! In-memory run counters + the atomically finalized run summary.

use std::fs::{self, File};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// In-memory tally of candidate outcomes as a run streams.
///
/// Never persisted mid-run — see the [`crate::run`] module docs for why
/// there is no durable per-candidate ledger. Only
/// [`RunCounters::finalize`] turns this into a [`RunSummary`], and only
/// once every candidate is accounted for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunCounters {
    /// Total candidates in the finalized manifest this run is streaming.
    pub candidate_count: u64,
    /// Candidates that succeeded.
    pub succeeded_count: u64,
    /// Candidates that failed retryably.
    pub failed_retryable_count: u64,
    /// Candidates that failed terminally.
    pub failed_terminal_count: u64,
    /// Candidates deferred to manual handling.
    pub deferred_manual_count: u64,
    /// Total logical bytes across all successful candidates.
    pub logical_bytes_succeeded: u64,
}

impl RunCounters {
    /// Start a fresh counter set for a run whose manifest has
    /// `candidate_count` candidates.
    #[must_use]
    pub const fn new(candidate_count: u64) -> Self {
        Self {
            candidate_count,
            succeeded_count: 0,
            failed_retryable_count: 0,
            failed_terminal_count: 0,
            deferred_manual_count: 0,
            logical_bytes_succeeded: 0,
        }
    }

    /// Record one succeeded candidate.
    pub const fn record_succeeded(&mut self, logical_size: u64) {
        self.succeeded_count += 1;
        self.logical_bytes_succeeded += logical_size;
    }

    /// Record one failed-retryable candidate.
    pub const fn record_failed_retryable(&mut self) {
        self.failed_retryable_count += 1;
    }

    /// Record one failed-terminal candidate.
    pub const fn record_failed_terminal(&mut self) {
        self.failed_terminal_count += 1;
    }

    /// Record one deferred-manual candidate.
    pub const fn record_deferred_manual(&mut self) {
        self.deferred_manual_count += 1;
    }

    /// Total candidates that have reached *any* terminal outcome so far.
    #[must_use]
    pub const fn resolved_count(&self) -> u64 {
        self.succeeded_count
            + self.failed_retryable_count
            + self.failed_terminal_count
            + self.deferred_manual_count
    }

    /// Whether every candidate in the manifest has a terminal outcome.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.resolved_count() == self.candidate_count
    }

    /// Turn these counters into a [`RunSummary`], failing if any
    /// candidate has not yet reached a terminal outcome.
    ///
    /// # Errors
    /// Returns [`SummaryFinalizeError::Incomplete`] if
    /// [`RunCounters::is_complete`] is false.
    pub fn finalize(
        self,
        run_id: String,
        started_at_unix_ms: i64,
        finished_at_unix_ms: i64,
    ) -> Result<RunSummary, SummaryFinalizeError> {
        if !self.is_complete() {
            return Err(SummaryFinalizeError::Incomplete {
                candidate_count: self.candidate_count,
                resolved_count: self.resolved_count(),
            });
        }
        Ok(RunSummary {
            run_id,
            started_at_unix_ms,
            finished_at_unix_ms,
            candidate_count: self.candidate_count,
            succeeded_count: self.succeeded_count,
            failed_retryable_count: self.failed_retryable_count,
            failed_terminal_count: self.failed_terminal_count,
            deferred_manual_count: self.deferred_manual_count,
            logical_bytes_succeeded: self.logical_bytes_succeeded,
        })
    }
}

/// Why [`RunCounters::finalize`] refused to produce a [`RunSummary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SummaryFinalizeError {
    /// Not every candidate has reached a terminal outcome yet.
    Incomplete {
        /// Candidates in the manifest.
        candidate_count: u64,
        /// Candidates that have resolved so far.
        resolved_count: u64,
    },
}

impl core::fmt::Display for SummaryFinalizeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Incomplete {
                candidate_count,
                resolved_count,
            } => write!(
                f,
                "cannot finalize run summary: {resolved_count} of {candidate_count} \
                 candidates have a terminal outcome"
            ),
        }
    }
}

impl core::error::Error for SummaryFinalizeError {}

/// The finalized, immutable record of one completed run.
///
/// The existence of a valid file at this summary's final path (no
/// `.partial` suffix) is the job-completion marker: if a run or the
/// machine crashes before [`RunSummary::finalize_to_disk`] renames the
/// `.partial` file into place, the run is incomplete, full stop. There is
/// no partial-completion state to reconcile — rerun the job from a new
/// VSS snapshot (see the [`crate::run`] module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSummary {
    /// Identifier for this run (matches the manifest's `job_id`, rendered
    /// as a string for JSON).
    pub run_id: String,
    /// When the run started, Unix milliseconds.
    pub started_at_unix_ms: i64,
    /// When the run finished (all candidates resolved), Unix
    /// milliseconds.
    pub finished_at_unix_ms: i64,
    /// Total candidates in the finalized manifest.
    pub candidate_count: u64,
    /// Candidates that succeeded.
    pub succeeded_count: u64,
    /// Candidates that failed retryably.
    pub failed_retryable_count: u64,
    /// Candidates that failed terminally.
    pub failed_terminal_count: u64,
    /// Candidates deferred to manual handling.
    pub deferred_manual_count: u64,
    /// Total logical bytes across all successful candidates.
    pub logical_bytes_succeeded: u64,
}

impl RunSummary {
    /// Atomically finalize this summary to `final_path`.
    ///
    /// Writes to a sibling `.partial` file first, `fsync`s it, then
    /// renames it into place — the rename is the atomic step a reader
    /// can rely on to never observe a half-written summary. `final_path`
    /// must not already exist (a run's summary is written exactly once).
    ///
    /// # Errors
    /// Returns an [`io::ErrorKind::AlreadyExists`] error if `final_path`
    /// already exists, and otherwise propagates the underlying
    /// [`io::Error`] from any filesystem step.
    pub fn finalize_to_disk(&self, final_path: &Path) -> io::Result<()> {
        if final_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("run summary already finalized at {}", final_path.display()),
            ));
        }
        let partial_path = partial_path_for(final_path);
        let json = serde_json::to_vec_pretty(self)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let mut partial_file = File::create(&partial_path)?;
        partial_file.write_all(&json)?;
        partial_file.sync_all()?;
        drop(partial_file);
        fs::rename(&partial_path, final_path)?;
        Ok(())
    }

    /// Read a previously finalized summary from `final_path`.
    ///
    /// Returns `Ok(None)` if no file exists there yet (i.e. the run has
    /// not completed) rather than an error — "not finalized" is an
    /// expected, common state, not a failure.
    ///
    /// # Errors
    /// Propagates I/O errors other than "not found", and wraps a JSON
    /// parse failure (for a file that exists but is not a valid summary)
    /// as an [`io::Error`].
    pub fn load_if_finalized(final_path: &Path) -> io::Result<Option<Self>> {
        match fs::read(final_path) {
            Ok(bytes) => {
                let summary = serde_json::from_slice(&bytes)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                Ok(Some(summary))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }
}

/// The `.partial` sibling path used during atomic finalization.
fn partial_path_for(final_path: &Path) -> PathBuf {
    let mut partial = final_path.as_os_str().to_owned();
    partial.push(".partial");
    PathBuf::from(partial)
}
