// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `JOB_BEGIN` payload (design-doc §12.3).

use super::{
    ContentSemantics, DigestAlgorithm, FrameError, FrameOrdering, read_optional_u64,
    write_optional_u64,
};
use crate::codec::{
    Digest, Reader, write_bytes_u16_prefixed, write_i64_le, write_u32_le, write_u64_le,
};

// ───────────────────────── JOB_BEGIN (§12.3) ─────────────────────────

/// `JOB_BEGIN` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobBegin {
    /// Job identifier.
    pub job_id: [u8; 16],
    /// Source identifier.
    pub source_id: [u8; 16],
    /// Opaque VSS snapshot identifier.
    pub snapshot_id: Vec<u8>,
    /// Snapshot creation time, Unix milliseconds.
    pub snapshot_created_at: i64,
    /// Digest of the finalized candidate manifest.
    pub manifest_digest: Digest,
    /// Total candidates in the manifest.
    pub candidate_count: u64,
    /// Authorization model this job was authorized under.
    pub authorization_mode: crate::manifest::AuthorizationMode,
    /// Cross-file ordering contract (fixed `NONE` in v2).
    pub ordering: FrameOrdering,
    /// Content semantics (fixed `UNNAMED_LOGICAL_STREAM` in v2).
    pub content_semantics: ContentSemantics,
    /// Digest algorithm (fixed `BLAKE3` in v2).
    pub digest_algorithm: DigestAlgorithm,
    /// Negotiated maximum `CONTENT_CHUNK` payload size.
    pub max_chunk_bytes: u32,
    /// Content-delivery ceiling: candidates whose `logical_size` exceeds
    /// this are still enumerated in the manifest (for reap/metadata
    /// completeness) but their body is not streamed —
    /// `FILE_END.read_mode == ReadMode::MetadataOnly` for those
    /// candidates. `None` means no ceiling: every matched candidate gets
    /// its content delivered. This is independent of the query's own
    /// candidate-match filters (ext/date/etc.) — see
    /// [`super::ReadMode::MetadataOnly`].
    pub max_content_delivery_bytes: Option<u64>,
}

impl JobBegin {
    /// Encode this payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.job_id);
        out.extend_from_slice(&self.source_id);
        write_bytes_u16_prefixed(&mut out, &self.snapshot_id);
        write_i64_le(&mut out, self.snapshot_created_at);
        out.extend_from_slice(&self.manifest_digest);
        write_u64_le(&mut out, self.candidate_count);
        out.push(self.authorization_mode.encode());
        out.push(self.ordering.encode());
        out.push(self.content_semantics.encode());
        out.push(self.digest_algorithm.encode());
        write_u32_le(&mut out, self.max_chunk_bytes);
        write_optional_u64(&mut out, self.max_content_delivery_bytes);
        out
    }

    /// Decode this payload.
    ///
    /// # Errors
    /// See [`FrameError`].
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, FrameError> {
        let job_id: [u8; 16] = reader.read_array()?;
        let source_id: [u8; 16] = reader.read_array()?;
        let snapshot_id =
            reader.read_bytes_u16_prefixed("snapshot_id", crate::manifest::MAX_IDENTIFIER_BYTES)?;
        let snapshot_created_at = reader.read_i64_le()?;
        let manifest_digest: Digest = reader.read_array()?;
        let candidate_count = reader.read_u64_le()?;
        let auth_byte = reader.read_u8()?;
        let authorization_mode =
            crate::manifest::AuthorizationMode::decode(auth_byte).map_err(|byte| {
                FrameError::UnknownDiscriminant {
                    field: "authorization_mode",
                    value: u64::from(byte),
                }
            })?;
        let ordering_byte = reader.read_u8()?;
        let ordering = FrameOrdering::decode(ordering_byte).map_err(|byte| {
            FrameError::UnknownDiscriminant {
                field: "ordering",
                value: u64::from(byte),
            }
        })?;
        let semantics_byte = reader.read_u8()?;
        let content_semantics = ContentSemantics::decode(semantics_byte).map_err(|byte| {
            FrameError::UnknownDiscriminant {
                field: "content_semantics",
                value: u64::from(byte),
            }
        })?;
        let digest_algo_byte = reader.read_u8()?;
        let digest_algorithm = DigestAlgorithm::decode(digest_algo_byte).map_err(|byte| {
            FrameError::UnknownDiscriminant {
                field: "digest_algorithm",
                value: u64::from(byte),
            }
        })?;
        let max_chunk_bytes = reader.read_u32_le()?;
        let max_content_delivery_bytes = read_optional_u64(reader)?;
        Ok(Self {
            job_id,
            source_id,
            snapshot_id,
            snapshot_created_at,
            manifest_digest,
            candidate_count,
            authorization_mode,
            ordering,
            content_semantics,
            digest_algorithm,
            max_chunk_bytes,
            max_content_delivery_bytes,
        })
    }
}
