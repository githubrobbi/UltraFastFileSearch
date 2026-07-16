// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Builds a finalized candidate manifest from an enumerated candidate
//! list (design-doc §4.1 step 8: checksummed and finalized before any
//! candidate is processed).

use uffs_content_protocol::codec::Digest;
use uffs_content_protocol::manifest::{
    AuthorizationMode, CandidateFlags, CandidateRecord, ManifestError, ManifestHeader,
    ManifestTrailer,
};
use uffs_content_protocol::path_encoding::WindowsPath;

use super::candidate_source::CandidateEntry;

/// A finalized manifest: encoded bytes plus the metadata a job needs to
/// build its `JOB_BEGIN`/`JOB_END` frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltManifest {
    /// Header + record section + trailer, exactly as they appear on disk.
    pub bytes: Vec<u8>,
    /// BLAKE3 digest over the header + record section — the trailer's
    /// `manifest_digest`, and what `JOB_BEGIN.manifest_digest` repeats.
    pub manifest_digest: Digest,
    /// `candidate_id` assigned to each input entry, in the same order as
    /// the `entries` slice given to [`build_manifest`].
    pub candidate_ids: Vec<u64>,
}

/// Assigns sequential `candidate_id`s and builds a finalized manifest for
/// `entries`.
///
/// # Errors
/// Propagates [`ManifestError`] from encoding any header/record (only
/// possible for implausibly large fields — see
/// [`CandidateRecord::encode`]).
pub fn build_manifest(
    job_id: [u8; 16],
    source_id: [u8; 16],
    query_digest: Digest,
    entries: &[CandidateEntry],
) -> Result<BuiltManifest, ManifestError> {
    let mut record_bytes = Vec::new();
    let mut candidate_ids = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let candidate_id = index_to_candidate_id(index);
        candidate_ids.push(candidate_id);
        let record = CandidateRecord {
            candidate_id,
            file_reference: entry.file_reference,
            logical_size: entry.logical_size,
            valid_data_length: entry.logical_size,
            mtime_unix_ms: entry.mtime_unix_ms,
            candidate_flags: CandidateFlags::empty(),
            path: WindowsPath::from_str_lossless(&entry.relative_path.to_string_lossy()),
        };
        record_bytes.extend_from_slice(&record.encode()?);
    }

    let candidate_count = u64::try_from(entries.len()).unwrap_or(u64::MAX);
    let header = ManifestHeader {
        format_version: 2,
        job_id,
        source_id,
        volume_serial: 0,
        volume_guid: Vec::new(),
        snapshot_id: Vec::new(),
        snapshot_created_unix_ms: 0,
        query_digest,
        authorization_mode: AuthorizationMode::AdminExport,
        candidate_count,
        record_section_length: u64::try_from(record_bytes.len()).unwrap_or(u64::MAX),
    };

    let mut bytes = header.encode()?;
    bytes.extend_from_slice(&record_bytes);
    let manifest_digest = ManifestTrailer::compute_digest(&bytes);
    let trailer = ManifestTrailer {
        candidate_count_repeat: candidate_count,
        manifest_digest,
    };
    bytes.extend_from_slice(&trailer.encode());

    Ok(BuiltManifest {
        bytes,
        manifest_digest,
        candidate_ids,
    })
}

/// `candidate_id` assignment policy: sequential, 1-based (`0` is left
/// unused as a future not-a-candidate sentinel might want it).
fn index_to_candidate_id(index: usize) -> u64 {
    u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1)
}
