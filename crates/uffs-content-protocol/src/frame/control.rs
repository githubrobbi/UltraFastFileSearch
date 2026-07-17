// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `PROGRESS`, `HEARTBEAT`, `JOB_CANCEL`, `WINDOW_UPDATE`, `JOB_RESUME`,
//! and `JOB_SUBMIT` payloads (design-doc §12.2, plus this crate's own
//! `JOB_RESUME`/`JOB_SUBMIT` additions — see [`super::FrameType`]'s doc
//! comment).

use super::{FrameError, read_message, write_message};
use crate::codec::{Reader, write_u64_le};

// ───────────────────────── PROGRESS / HEARTBEAT / control
// ─────────────────────────

/// `PROGRESS` payload (design-doc §20.1 job/throughput metrics). Field
/// set is this crate's own choice — the spec names the metric categories
/// but not a fixed wire layout for this frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Candidates discovered so far (manifest may still be enumerating).
    pub candidates_discovered: u64,
    /// Candidates that have reached a terminal outcome.
    pub candidates_completed: u64,
    /// Logical bytes successfully emitted so far.
    pub logical_bytes_emitted: u64,
    /// Total error count (failed + deferred) so far.
    pub error_count: u64,
}

impl Progress {
    /// Encode this payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.candidates_discovered);
        write_u64_le(&mut out, self.candidates_completed);
        write_u64_le(&mut out, self.logical_bytes_emitted);
        write_u64_le(&mut out, self.error_count);
        out
    }

    /// Decode this payload.
    ///
    /// # Errors
    /// See [`FrameError`].
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, FrameError> {
        Ok(Self {
            candidates_discovered: reader.read_u64_le()?,
            candidates_completed: reader.read_u64_le()?,
            logical_bytes_emitted: reader.read_u64_le()?,
            error_count: reader.read_u64_le()?,
        })
    }
}

/// `HEARTBEAT` payload.
///
/// Primarily exists so the frame envelope arriving at all proves
/// liveness (design-doc §12.2 "prevents an idle long-file operation from
/// looking dead"), but also carries a cheap resume marker — the
/// producer's own idea of the last candidate it completed — so a
/// reconnecting consumer (or the producer itself, after a transport blip
/// that didn't kill the process) has a recent, no-cost checkpoint
/// without needing a durable ledger. Superseded by the authoritative
/// `FILE_ACK`-driven state in `crate::job::registry` (UFFS-side, not
/// part of this wire crate) whenever the two disagree — this is a hint,
/// not a source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat {
    /// The most recent candidate id the producer finished streaming
    /// (`FILE_END`/`FILE_FAILED`/`FILE_DEFERRED` already sent for it), or
    /// `0` if none yet — `0` is never a real candidate id (candidate ids
    /// are 1-based; see `manifest_builder::index_to_candidate_id`'s own
    /// reserved-sentinel rationale).
    pub last_completed_candidate_id: u64,
}

impl Heartbeat {
    /// Encode this payload.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.last_completed_candidate_id);
        out
    }

    /// Decode this payload. A short/empty buffer (an old peer's empty
    /// `HEARTBEAT`) decodes as `last_completed_candidate_id: 0` rather
    /// than erroring — liveness-only heartbeats from a peer that
    /// predates this marker are still valid heartbeats.
    #[must_use]
    pub fn decode(reader: &mut Reader<'_>) -> Self {
        Self {
            last_completed_candidate_id: reader.read_u64_le().unwrap_or(0),
        }
    }
}

/// `JOB_RESUME` payload: empty.
///
/// Sent by a reconnecting consumer to resume the job named by this
/// frame's own `FrameEnvelope::job_id` — nothing else needs to travel in
/// the payload, since the envelope already identifies the job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobResume;

impl JobResume {
    /// Encode this payload (always empty).
    #[must_use]
    #[expect(
        clippy::unused_self,
        reason = "kept as an instance method for API uniformity with every \
                  other frame payload's encode(self/&self) -> Vec<u8> shape, \
                  even though this particular payload carries no fields"
    )]
    pub const fn encode(self) -> Vec<u8> {
        Vec::new()
    }

    /// Decode this payload (always succeeds; ignores any bytes present).
    #[must_use]
    pub const fn decode() -> Self {
        Self
    }
}

/// `JOB_SUBMIT` payload: a JSON-encoded job spec.
///
/// Deliberately opaque bytes rather than a structured wire layout this
/// crate parses field-by-field: the job spec is UFFS-side application
/// data (`uffs_content::job::intake::JobRequest`, outside this crate),
/// not part of the UFFS/Docenta content-stream contract itself. This
/// frame only needs to get those bytes from the consumer to the
/// producer intact; the envelope's own checksums already guard that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSubmit {
    /// The job spec, as UTF-8 JSON bytes.
    pub job_spec_json: Vec<u8>,
}

impl JobSubmit {
    /// Encode this payload (the JSON bytes verbatim).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.job_spec_json.clone()
    }

    /// Decode this payload: the entire frame payload is the JSON bytes,
    /// so this takes the raw payload directly rather than a [`Reader`]
    /// (there are no further sub-fields to walk).
    #[must_use]
    pub fn decode(payload: &[u8]) -> Self {
        Self {
            job_spec_json: payload.to_vec(),
        }
    }
}

/// `JOB_CANCEL` payload, sent by the consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobCancel {
    /// Human-readable cancellation reason.
    pub reason: String,
}

impl JobCancel {
    /// Encode this payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_message(&mut out, &self.reason);
        out
    }

    /// Decode this payload.
    ///
    /// # Errors
    /// See [`FrameError`].
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, FrameError> {
        Ok(Self {
            reason: read_message(reader)?,
        })
    }
}

/// `WINDOW_UPDATE` payload, sent by the consumer to grant additional
/// backpressure budget (design-doc §13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowUpdate {
    /// Additional bytes the producer may now have unacknowledged/in-flight.
    pub additional_window_bytes: u64,
}

impl WindowUpdate {
    /// Encode this payload.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.additional_window_bytes);
        out
    }

    /// Decode this payload.
    ///
    /// # Errors
    /// See [`FrameError`].
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, FrameError> {
        Ok(Self {
            additional_window_bytes: reader.read_u64_le()?,
        })
    }
}
