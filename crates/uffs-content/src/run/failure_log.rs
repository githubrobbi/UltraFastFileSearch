// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Append-only JSONL failure log: one record per non-success candidate.

use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::Path;

use serde::{Deserialize, Serialize};
use uffs_content_protocol::error::ErrorCode;
use uffs_content_protocol::frame::{FailedOutcome, FailureStage, RetryClass};

/// Discriminant for a [`FailureRecord`]'s outcome.
///
/// Mirrors the non-success half of
/// [`uffs_content_protocol::state::CandidateOutcome`] (excludes
/// `Succeeded` — a successful candidate is never written to this log,
/// only to the manifest and the content stream itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureOutcomeKind {
    /// May be retried in a later job attempt against a new snapshot.
    FailedRetryable,
    /// Will not succeed on retry.
    FailedTerminal,
    /// Deferred to manual or later handling.
    DeferredManual,
}

impl From<FailedOutcome> for FailureOutcomeKind {
    fn from(outcome: FailedOutcome) -> Self {
        match outcome {
            FailedOutcome::Retryable => Self::FailedRetryable,
            FailedOutcome::Terminal => Self::FailedTerminal,
        }
    }
}

/// One non-success candidate outcome, as persisted to the run's failure
/// log.
///
/// Serialized one JSON object per line (JSONL), appended as candidates
/// resolve — see [`FailureLogWriter`]. A candidate present in the
/// manifest but absent from both this log and the successful-content
/// stream simply hasn't resolved yet; a reader must not infer success
/// from mere absence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureRecord {
    /// Candidate this record terminates.
    pub candidate_id: u64,
    /// Which of the three non-success outcomes this is.
    pub outcome: FailureOutcomeKind,
    /// Which pipeline stage the failure occurred at. Absent for
    /// `DeferredManual` (a deferral isn't a failure at a stage).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub failure_stage: Option<String>,
    /// Stable machine-readable error/reason code
    /// ([`ErrorCode::as_str`]).
    pub error_code: String,
    /// Underlying OS error code, if applicable.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub os_error_code: Option<i64>,
    /// How this failure may be retried. Absent for `DeferredManual`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub retry_class: Option<String>,
    /// Bytes emitted before the failure (0 for a deferral, which never
    /// starts streaming a body).
    pub bytes_emitted_before_failure: u64,
    /// Human-readable diagnostic message.
    pub message: String,
}

impl FailureRecord {
    /// Build a record for a `FAILED_RETRYABLE`/`FAILED_TERMINAL` outcome.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "single call site, flat args mirroring FILE_FAILED's own field list"
    )]
    pub fn failed<S: Into<String>>(
        candidate_id: u64,
        outcome: FailedOutcome,
        failure_stage: FailureStage,
        error_code: ErrorCode,
        os_error_code: Option<i64>,
        retry_class: RetryClass,
        bytes_emitted_before_failure: u64,
        message: S,
    ) -> Self {
        Self {
            candidate_id,
            outcome: outcome.into(),
            failure_stage: Some(failure_stage_label(failure_stage).to_owned()),
            error_code: error_code.as_str().to_owned(),
            os_error_code,
            retry_class: Some(retry_class_label(retry_class).to_owned()),
            bytes_emitted_before_failure,
            message: message.into(),
        }
    }

    /// Build a record for a `DEFERRED_MANUAL` outcome.
    #[must_use]
    pub fn deferred<S: Into<String>>(
        candidate_id: u64,
        reason_code: ErrorCode,
        message: S,
    ) -> Self {
        Self {
            candidate_id,
            outcome: FailureOutcomeKind::DeferredManual,
            failure_stage: None,
            error_code: reason_code.as_str().to_owned(),
            os_error_code: None,
            retry_class: None,
            bytes_emitted_before_failure: 0,
            message: message.into(),
        }
    }

    /// Serialize this record as one JSON line (no trailing newline).
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails.
    pub fn to_json_line(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

/// Stable `snake_case` label for a [`FailureStage`], for JSON — kept local
/// to this log rather than added to the wire-protocol type, since the
/// binary wire codec (design-doc §5.4) and this auxiliary JSON log are
/// deliberately separate concerns.
const fn failure_stage_label(stage: FailureStage) -> &'static str {
    match stage {
        FailureStage::SnapshotCreate => "snapshot_create",
        FailureStage::SnapshotOpen => "snapshot_open",
        FailureStage::Enumeration => "enumeration",
        FailureStage::Identity => "identity",
        FailureStage::StreamResolution => "stream_resolution",
        FailureStage::RunlistValidation => "runlist_validation",
        FailureStage::Read => "read",
        FailureStage::Reconstruction => "reconstruction",
        FailureStage::Hash => "hash",
        FailureStage::Transport => "transport",
        FailureStage::ConsumerAck => "consumer_ack",
        FailureStage::Internal => "internal",
    }
}

/// Stable `snake_case` label for a [`RetryClass`], for JSON — see
/// [`failure_stage_label`] for why this lives here instead of on the
/// wire-protocol type.
const fn retry_class_label(class: RetryClass) -> &'static str {
    match class {
        RetryClass::RetrySameJob => "retry_same_job",
        RetryClass::RetryNewSnapshot => "retry_new_snapshot",
        RetryClass::RetryAfterResourceChange => "retry_after_resource_change",
        RetryClass::RetryWithManualHandler => "retry_with_manual_handler",
        RetryClass::RetryWithCredentialOrKey => "retry_with_credential_or_key",
        RetryClass::DoNotRetry => "do_not_retry",
    }
}

/// Append-only writer for a run's failure log.
///
/// Opens (or creates) the file in append mode and flushes after every
/// record, so a reader tailing the file mid-run always sees complete
/// lines — there is no cross-call buffering to lose on a crash.
#[derive(Debug)]
pub struct FailureLogWriter {
    /// The open file handle, in append mode.
    file: std::fs::File,
}

impl FailureLogWriter {
    /// Open (creating if absent) the failure log at `path` for
    /// appending.
    ///
    /// # Errors
    /// Propagates the underlying [`io::Error`] from opening the file.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file })
    }

    /// Append one record as a JSON line.
    ///
    /// # Errors
    /// Returns an error if serialization or the write/flush fails.
    pub fn append(&mut self, record: &FailureRecord) -> io::Result<()> {
        let line = record
            .to_json_line()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        writeln!(self.file, "{line}")?;
        self.file.flush()
    }
}
