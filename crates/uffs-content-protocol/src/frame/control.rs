// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `PROGRESS`, `HEARTBEAT`, `JOB_CANCEL`, and `WINDOW_UPDATE` payloads
//! (design-doc §12.2).

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

/// `HEARTBEAT` payload: empty. Its purpose is solely the frame envelope
/// arriving at all (design-doc §12.2 "prevents an idle long-file
/// operation from looking dead").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat;

impl Heartbeat {
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
