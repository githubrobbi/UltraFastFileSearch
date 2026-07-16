// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `CONTENT_CHUNK` payload (design-doc §12.5).

use super::FrameError;
use crate::codec::{Reader, write_bytes_u32_prefixed, write_u64_le};

// ───────────────────────── CONTENT_CHUNK (§12.5) ─────────────────────────

/// `CONTENT_CHUNK` payload.
///
/// Rules (design-doc §12.5): chunks are bounded; `logical_offset` for one
/// file increases monotonically; `payload` is raw logical file bytes in
/// v2; no whole-file buffering is implied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentChunk {
    /// Candidate this chunk belongs to.
    pub candidate_id: u64,
    /// File-local chunk sequence number.
    pub chunk_sequence: u64,
    /// Logical byte offset of this chunk within the file.
    pub logical_offset: u64,
    /// Logical length of this chunk (matches `payload.len()`).
    pub logical_length: u64,
    /// Raw logical file bytes for this chunk.
    pub payload: Vec<u8>,
}

impl ContentChunk {
    /// Encode this payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.candidate_id);
        write_u64_le(&mut out, self.chunk_sequence);
        write_u64_le(&mut out, self.logical_offset);
        write_u64_le(&mut out, self.logical_length);
        write_bytes_u32_prefixed(&mut out, &self.payload);
        out
    }

    /// Decode this payload.
    ///
    /// `max_payload_bytes` bounds the chunk payload before allocation.
    ///
    /// # Errors
    /// See [`FrameError`].
    pub fn decode(reader: &mut Reader<'_>, max_payload_bytes: u32) -> Result<Self, FrameError> {
        let candidate_id = reader.read_u64_le()?;
        let chunk_sequence = reader.read_u64_le()?;
        let logical_offset = reader.read_u64_le()?;
        let logical_length = reader.read_u64_le()?;
        let payload = reader.read_bytes_u32_prefixed("chunk_payload", max_payload_bytes)?;
        Ok(Self {
            candidate_id,
            chunk_sequence,
            logical_offset,
            logical_length,
            payload,
        })
    }
}
