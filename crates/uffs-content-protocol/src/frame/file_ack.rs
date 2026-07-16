// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `FILE_ACK` payload (design-doc §12.9).

use super::{ConsumerAckStatus, FrameError, read_message, write_message};
use crate::codec::{Digest, Reader, write_u64_le};

// ───────────────────────── FILE_ACK (§12.9) ─────────────────────────

/// `FILE_ACK` payload, sent by the consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAck {
    /// Candidate being acknowledged.
    pub candidate_id: u64,
    /// Digest the consumer computed for the received content, for
    /// `job_id + candidate_id + content_digest` idempotency (design-doc
    /// §9.4).
    pub content_digest: Digest,
    /// Whether the consumer accepted or rejected the file.
    pub consumer_status: ConsumerAckStatus,
    /// Consumer-side error code, if rejected.
    pub consumer_error_code: Option<String>,
}

impl FileAck {
    /// Encode this payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.candidate_id);
        out.extend_from_slice(&self.content_digest);
        out.push(self.consumer_status.encode());
        match &self.consumer_error_code {
            Some(code) => {
                out.push(1);
                write_message(&mut out, code);
            }
            None => out.push(0),
        }
        out
    }

    /// Decode this payload.
    ///
    /// # Errors
    /// See [`FrameError`].
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, FrameError> {
        let candidate_id = reader.read_u64_le()?;
        let content_digest: Digest = reader.read_array()?;
        let status_byte = reader.read_u8()?;
        let consumer_status = ConsumerAckStatus::decode(status_byte).map_err(|byte| {
            FrameError::UnknownDiscriminant {
                field: "consumer_status",
                value: u64::from(byte),
            }
        })?;
        let error_present = reader.read_u8()?;
        let consumer_error_code = if error_present == 0 {
            None
        } else {
            Some(read_message(reader)?)
        };
        Ok(Self {
            candidate_id,
            content_digest,
            consumer_status,
            consumer_error_code,
        })
    }
}
