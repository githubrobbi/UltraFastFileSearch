// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `JOB_END` payload (design-doc §12.10).

use super::{FrameError, JobStatus};
use crate::codec::{Digest, Reader, write_bytes_u16_prefixed, write_u64_le};

// ───────────────────────── JOB_END (§12.10) ─────────────────────────

/// `JOB_END` payload: the receiver verifies the completeness invariant
/// against these counts (design-doc §12.10, §2.2, §21.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobEnd {
    /// Total candidates in the finalized manifest.
    pub candidate_count: u64,
    /// Candidates with a `SUCCEEDED` outcome.
    pub succeeded_count: u64,
    /// Candidates with a `FAILED_RETRYABLE` outcome.
    pub failed_retryable_count: u64,
    /// Candidates with a `FAILED_TERMINAL` outcome.
    pub failed_terminal_count: u64,
    /// Candidates with a `DEFERRED_MANUAL` outcome.
    pub deferred_manual_count: u64,
    /// Successful candidates the consumer has durably acknowledged.
    pub acknowledged_success_count: u64,
    /// Total logical bytes across all successful candidates.
    pub logical_bytes_succeeded: u64,
    /// Identifier of the durable failure-bucket record set for this job.
    pub failure_bucket_id: Vec<u8>,
    /// Digest of the finalized candidate manifest (must match `JOB_BEGIN`).
    pub manifest_digest: Digest,
    /// Digest of the durable outcome ledger.
    pub outcome_ledger_digest: Digest,
    /// Terminal job status.
    pub job_status: JobStatus,
}

impl JobEnd {
    /// Encode this payload.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `job_status` is not one of the four terminal
    /// [`JobStatus`] variants a `JOB_END` frame may carry.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let job_status_byte = encode_terminal_job_status(self.job_status)?;
        let mut out = Vec::new();
        write_u64_le(&mut out, self.candidate_count);
        write_u64_le(&mut out, self.succeeded_count);
        write_u64_le(&mut out, self.failed_retryable_count);
        write_u64_le(&mut out, self.failed_terminal_count);
        write_u64_le(&mut out, self.deferred_manual_count);
        write_u64_le(&mut out, self.acknowledged_success_count);
        write_u64_le(&mut out, self.logical_bytes_succeeded);
        write_bytes_u16_prefixed(&mut out, &self.failure_bucket_id);
        out.extend_from_slice(&self.manifest_digest);
        out.extend_from_slice(&self.outcome_ledger_digest);
        out.push(job_status_byte);
        Ok(out)
    }

    /// Decode this payload.
    ///
    /// # Errors
    /// See [`FrameError`].
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, FrameError> {
        let candidate_count = reader.read_u64_le()?;
        let succeeded_count = reader.read_u64_le()?;
        let failed_retryable_count = reader.read_u64_le()?;
        let failed_terminal_count = reader.read_u64_le()?;
        let deferred_manual_count = reader.read_u64_le()?;
        let acknowledged_success_count = reader.read_u64_le()?;
        let logical_bytes_succeeded = reader.read_u64_le()?;
        let failure_bucket_id = reader
            .read_bytes_u16_prefixed("failure_bucket_id", crate::manifest::MAX_IDENTIFIER_BYTES)?;
        let manifest_digest: Digest = reader.read_array()?;
        let outcome_ledger_digest: Digest = reader.read_array()?;
        let job_status_byte = reader.read_u8()?;
        let job_status = decode_terminal_job_status(job_status_byte)?;
        Ok(Self {
            candidate_count,
            succeeded_count,
            failed_retryable_count,
            failed_terminal_count,
            deferred_manual_count,
            acknowledged_success_count,
            logical_bytes_succeeded,
            failure_bucket_id,
            manifest_digest,
            outcome_ledger_digest,
            job_status,
        })
    }
}

/// Encodes only the four terminal [`JobStatus`] variants a `JOB_END`
/// frame may legally carry — a non-terminal `JobState` reaching this
/// point would itself be a producer bug, not a wire concern.
const fn encode_terminal_job_status(status: JobStatus) -> Result<u8, FrameError> {
    match status {
        JobStatus::Completed => Ok(0),
        JobStatus::CompletedWithFailures => Ok(1),
        JobStatus::Cancelled => Ok(2),
        JobStatus::Aborted => Ok(3),
        JobStatus::Created
        | JobStatus::SnapshotCreating
        | JobStatus::SnapshotReady
        | JobStatus::Enumerating
        | JobStatus::ManifestFinalized
        | JobStatus::Streaming
        | JobStatus::Completing => Err(FrameError::UnknownDiscriminant {
            field: "job_status",
            value: 255,
        }),
    }
}

/// Decode a terminal [`JobStatus`] byte written by
/// [`encode_terminal_job_status`].
fn decode_terminal_job_status(byte: u8) -> Result<JobStatus, FrameError> {
    match byte {
        0 => Ok(JobStatus::Completed),
        1 => Ok(JobStatus::CompletedWithFailures),
        2 => Ok(JobStatus::Cancelled),
        3 => Ok(JobStatus::Aborted),
        other => Err(FrameError::UnknownDiscriminant {
            field: "job_status",
            value: u64::from(other),
        }),
    }
}
