// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `FILE_FAILED` payload (design-doc §12.7).

use core::str::FromStr as _;

use super::{
    FailureStage, FrameError, RetryClass, read_message, read_optional_i64, write_message,
    write_optional_i64,
};
use crate::codec::{Reader, write_bytes_u16_prefixed, write_u64_le};

// ───────────────────────── FILE_FAILED (§12.7) ─────────────────────────

/// `FILE_FAILED` outcome discriminant (design-doc §12.7): either of the
/// two failure [`crate::state::CandidateOutcome`] variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FailedOutcome {
    /// May be retried in a later job attempt.
    Retryable = 0,
    /// Will not succeed on retry.
    Terminal = 1,
}

impl FailedOutcome {
    /// Serialize to the wire byte.
    #[must_use]
    pub const fn encode(self) -> u8 {
        self as u8
    }

    /// Parse the wire byte.
    ///
    /// # Errors
    /// Returns the offending byte if unrecognized.
    pub const fn decode(byte: u8) -> Result<Self, u8> {
        match byte {
            0 => Ok(Self::Retryable),
            1 => Ok(Self::Terminal),
            other => Err(other),
        }
    }
}

/// `FILE_FAILED` payload. Contains no successful content object
/// (design-doc §12.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFailed {
    /// Candidate this terminates.
    pub candidate_id: u64,
    /// Retryable vs. terminal.
    pub outcome: FailedOutcome,
    /// Which stage the failure occurred at.
    pub failure_stage: FailureStage,
    /// Stable machine-readable error code.
    pub error_code: crate::error::ErrorCode,
    /// Underlying OS error code, if applicable.
    pub os_error_code: Option<i64>,
    /// How this failure may be retried.
    pub retry_class: RetryClass,
    /// Bytes emitted before the failure (consumer MUST discard them —
    /// design-doc §12.7).
    pub bytes_emitted_before_failure: u64,
    /// Human-readable diagnostic message.
    pub message: String,
}

impl FileFailed {
    /// Encode this payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.candidate_id);
        out.push(self.outcome.encode());
        out.push(self.failure_stage.encode());
        write_bytes_u16_prefixed(&mut out, self.error_code.as_str().as_bytes());
        write_optional_i64(&mut out, self.os_error_code);
        out.push(self.retry_class.encode());
        write_u64_le(&mut out, self.bytes_emitted_before_failure);
        write_message(&mut out, &self.message);
        out
    }

    /// Decode this payload.
    ///
    /// # Errors
    /// See [`FrameError`].
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, FrameError> {
        let candidate_id = reader.read_u64_le()?;
        let outcome_byte = reader.read_u8()?;
        let outcome = FailedOutcome::decode(outcome_byte).map_err(|byte| {
            FrameError::UnknownDiscriminant {
                field: "outcome",
                value: u64::from(byte),
            }
        })?;
        let stage_byte = reader.read_u8()?;
        let failure_stage =
            FailureStage::decode(stage_byte).map_err(|byte| FrameError::UnknownDiscriminant {
                field: "failure_stage",
                value: u64::from(byte),
            })?;
        let error_code_bytes = reader.read_bytes_u16_prefixed("error_code", 64)?;
        let error_code_str = String::from_utf8(error_code_bytes)
            .map_err(|_err| FrameError::InvalidUtf8("error_code"))?;
        let error_code = crate::error::ErrorCode::from_str(&error_code_str).map_err(|_err| {
            FrameError::UnknownDiscriminant {
                field: "error_code",
                value: 0,
            }
        })?;
        let os_error_code = read_optional_i64(reader)?;
        let retry_class_byte = reader.read_u8()?;
        let retry_class = RetryClass::decode(retry_class_byte).map_err(|byte| {
            FrameError::UnknownDiscriminant {
                field: "retry_class",
                value: u64::from(byte),
            }
        })?;
        let bytes_emitted_before_failure = reader.read_u64_le()?;
        let message = read_message(reader)?;
        Ok(Self {
            candidate_id,
            outcome,
            failure_stage,
            error_code,
            os_error_code,
            retry_class,
            bytes_emitted_before_failure,
            message,
        })
    }
}
