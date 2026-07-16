// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `FILE_DEFERRED` payload (design-doc §12.8).

use core::str::FromStr as _;

use super::{FrameError, read_message, write_message};
use crate::codec::{Reader, write_bytes_u16_prefixed, write_u64_le};

// ───────────────────────── FILE_DEFERRED (§12.8) ─────────────────────────

/// `FILE_DEFERRED` payload. No content body is considered successful
/// (design-doc §12.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDeferred {
    /// Candidate this terminates.
    pub candidate_id: u64,
    /// Stable machine-readable reason code (one of the `*_MANUAL`
    /// [`crate::error::ErrorCode`] variants).
    pub reason_code: crate::error::ErrorCode,
    /// Optional hint for which manual handler applies.
    pub manual_handler_hint: Option<String>,
    /// Human-readable diagnostic message.
    pub message: String,
}

impl FileDeferred {
    /// Encode this payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.candidate_id);
        write_bytes_u16_prefixed(&mut out, self.reason_code.as_str().as_bytes());
        match &self.manual_handler_hint {
            Some(hint) => {
                out.push(1);
                write_message(&mut out, hint);
            }
            None => out.push(0),
        }
        write_message(&mut out, &self.message);
        out
    }

    /// Decode this payload.
    ///
    /// # Errors
    /// See [`FrameError`].
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, FrameError> {
        let candidate_id = reader.read_u64_le()?;
        let reason_bytes = reader.read_bytes_u16_prefixed("reason_code", 64)?;
        let reason_str = String::from_utf8(reason_bytes)
            .map_err(|_err| FrameError::InvalidUtf8("reason_code"))?;
        let reason_code = crate::error::ErrorCode::from_str(&reason_str).map_err(|_err| {
            FrameError::UnknownDiscriminant {
                field: "reason_code",
                value: 0,
            }
        })?;
        let hint_present = reader.read_u8()?;
        let manual_handler_hint = if hint_present == 0 {
            None
        } else {
            Some(read_message(reader)?)
        };
        let message = read_message(reader)?;
        Ok(Self {
            candidate_id,
            reason_code,
            manual_handler_hint,
            message,
        })
    }
}
