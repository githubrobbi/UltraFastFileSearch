// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `FILE_END` payload (design-doc §12.6).

use super::{FrameError, ReadMode};
use crate::codec::{Digest, Reader, write_u32_le, write_u64_le};

// ───────────────────────── FILE_END (§12.6) ─────────────────────────

/// `FILE_END` payload: a candidate is successful only after this frame
/// (design-doc §12.6).
///
/// `content_digest` is `None` exactly when `read_mode ==
/// ReadMode::MetadataOnly` — the candidate matched the job's query but
/// exceeded its content-delivery ceiling, so no bytes were read and
/// `chunk_count` is `0`. This is still a successful outcome: the
/// candidate is validated and present in the manifest, nothing failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEnd {
    /// Candidate this terminates.
    pub candidate_id: u64,
    /// Total logical bytes emitted. `0` when `content_digest` is `None`
    /// (the file's true size is already in `FILE_BEGIN.logical_size`).
    pub total_logical_bytes: u64,
    /// BLAKE3 digest over the exact emitted logical bytes, or `None` if
    /// no content was delivered (see field-level docs above).
    pub content_digest: Option<Digest>,
    /// Read mode actually used.
    pub read_mode: ReadMode,
    /// Number of `CONTENT_CHUNK` frames emitted for this file.
    pub chunk_count: u64,
    /// Elapsed time for this attempt, milliseconds.
    pub elapsed_ms: u64,
    /// Reserved warning bitfield; no bits defined in v2.
    pub warning_flags: u32,
}

impl FileEnd {
    /// Encode this payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.candidate_id);
        write_u64_le(&mut out, self.total_logical_bytes);
        match self.content_digest {
            Some(digest) => {
                out.push(1);
                out.extend_from_slice(&digest);
            }
            None => out.push(0),
        }
        out.push(self.read_mode.encode());
        write_u64_le(&mut out, self.chunk_count);
        write_u64_le(&mut out, self.elapsed_ms);
        write_u32_le(&mut out, self.warning_flags);
        out
    }

    /// Decode this payload.
    ///
    /// # Errors
    /// See [`FrameError`].
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, FrameError> {
        let candidate_id = reader.read_u64_le()?;
        let total_logical_bytes = reader.read_u64_le()?;
        let digest_present = reader.read_u8()?;
        let content_digest = if digest_present == 0 {
            None
        } else {
            let digest: Digest = reader.read_array()?;
            Some(digest)
        };
        let read_mode_byte = reader.read_u8()?;
        let read_mode =
            ReadMode::decode(read_mode_byte).map_err(|byte| FrameError::UnknownDiscriminant {
                field: "read_mode",
                value: u64::from(byte),
            })?;
        let chunk_count = reader.read_u64_le()?;
        let elapsed_ms = reader.read_u64_le()?;
        let warning_flags = reader.read_u32_le()?;
        Ok(Self {
            candidate_id,
            total_logical_bytes,
            content_digest,
            read_mode,
            chunk_count,
            elapsed_ms,
            warning_flags,
        })
    }
}
