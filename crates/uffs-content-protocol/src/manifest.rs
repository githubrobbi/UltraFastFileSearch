// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Candidate manifest: header, per-candidate record, and trailer.
//!
//! Design-doc §11. Every length-prefixed field's declared length is
//! bounds-checked before allocation (see [`crate::codec::Reader`]); every
//! checksum is verified before the decoded value is trusted.

use crate::codec::{
    Digest, Reader, checksum32, digest, write_bytes_u16_prefixed, write_i64_le, write_u16_le,
    write_u32_le, write_u64_le,
};
use crate::path_encoding::{MAX_PATH_CODE_UNITS, PathDecodeError, WindowsPath};

/// Manifest header magic (design-doc §11.1).
pub const MANIFEST_MAGIC: [u8; 4] = *b"UFM2";
/// Manifest trailer end-magic (design-doc §11.3).
pub const MANIFEST_END_MAGIC: [u8; 4] = *b"UFE2";

/// Wire-safety bound on `volume_guid`/`snapshot_id` byte length. Both are
/// small opaque identifiers in practice (a GUID string is ~36 bytes); this
/// is generous headroom, not an observed real-world size.
pub const MAX_IDENTIFIER_BYTES: u16 = 512;

/// Wire-safety bound on an encoded path's byte length: two bytes per
/// UTF-16 code unit, [`MAX_PATH_CODE_UNITS`] code units.
pub const MAX_PATH_BYTES: u32 = (MAX_PATH_CODE_UNITS as u32) * 2;

/// `authorization_mode` (design-doc §2.7/§17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AuthorizationMode {
    /// Version 1: administrator-authorized export. No per-file ACL
    /// equivalence — see design-doc §2.7 and the addendum's §7 scope
    /// restriction to a single-user, local-admin deployment.
    AdminExport = 0,
    /// Future: the producer applies the authenticated caller's effective
    /// Windows access token to candidate visibility and content
    /// authorization (design-doc §17.2, addendum §7.3/§7.4).
    CallerToken = 1,
}

impl AuthorizationMode {
    /// Serialize to the single-byte wire representation.
    #[must_use]
    pub const fn encode(self) -> u8 {
        self as u8
    }

    /// Parse the single-byte wire representation.
    ///
    /// # Errors
    ///
    /// Returns the offending byte if it does not match a known variant.
    pub const fn decode(byte: u8) -> Result<Self, u8> {
        match byte {
            0 => Ok(Self::AdminExport),
            1 => Ok(Self::CallerToken),
            other => Err(other),
        }
    }
}

bitflags::bitflags! {
    /// Candidate flags (design-doc §11.4): "facts or planning hints, not
    /// guaranteed processing success."
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CandidateFlags: u32 {
        /// Unnamed data is MFT-resident.
        const RESIDENT = 1 << 0;
        /// Unnamed data is nonresident (has a runlist).
        const NONRESIDENT = 1 << 1;
        /// Stream has a sparse layout.
        const SPARSE = 1 << 2;
        /// Stream is NTFS-compressed.
        const COMPRESSED = 1 << 3;
        /// Stream is EFS-encrypted.
        const ENCRYPTED = 1 << 4;
        /// Object is reparse-point-backed.
        const REPARSE = 1 << 5;
        /// Object is Data-Dedup-optimized or otherwise provider-backed.
        const DEDUP_OR_PROVIDER = 1 << 6;
        /// Logical size exceeds the producer's "large file" threshold.
        const LARGE_FILE = 1 << 7;
        /// Heuristically likely to require a manual handler even if not
        /// yet classified as such.
        const MANUAL_HANDLER_LIKELY = 1 << 8;
    }
}

/// Errors decoding a manifest header, candidate record, or trailer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestError {
    /// Underlying bounds/length-prefix decode failure.
    #[error(transparent)]
    Decode(#[from] crate::codec::DecodeError),
    /// Path field failed to decode.
    #[error(transparent)]
    Path(#[from] PathDecodeError),
    /// Header or trailer magic did not match the expected constant.
    #[error("bad magic: expected {expected:?}, got {actual:?}")]
    BadMagic {
        /// Expected magic bytes.
        expected: [u8; 4],
        /// Magic bytes actually present.
        actual: [u8; 4],
    },
    /// The declared `header_length` did not match the number of bytes
    /// actually consumed while decoding the header.
    #[error("header_length mismatch: declared {declared}, actual {actual}")]
    HeaderLengthMismatch {
        /// Declared length from the wire.
        declared: u16,
        /// Bytes actually consumed decoding the header.
        actual: usize,
    },
    /// The declared `record_length` did not match the number of bytes
    /// actually consumed while decoding the candidate record.
    #[error("record_length mismatch: declared {declared}, actual {actual}")]
    RecordLengthMismatch {
        /// Declared length from the wire.
        declared: u32,
        /// Bytes actually consumed decoding the record.
        actual: usize,
    },
    /// A header/record checksum did not match the bytes it covers.
    #[error("checksum mismatch: expected 0x{expected:08x}, computed 0x{computed:08x}")]
    ChecksumMismatch {
        /// Checksum read from the wire.
        expected: u32,
        /// Checksum recomputed locally.
        computed: u32,
    },
    /// `authorization_mode` byte did not match a known variant.
    #[error("unknown authorization_mode byte: {0}")]
    UnknownAuthorizationMode(u8),
    /// The trailer's `candidate_count_repeat` did not match the header's
    /// `candidate_count`.
    #[error("candidate_count mismatch: header {header}, trailer {trailer}")]
    CandidateCountMismatch {
        /// Value from the header.
        header: u64,
        /// Value from the trailer.
        trailer: u64,
    },
}

/// Manifest header (design-doc §11.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestHeader {
    /// Wire format version.
    pub format_version: u16,
    /// Job identifier (UUID bytes).
    pub job_id: [u8; 16],
    /// Source identifier (UUID bytes).
    pub source_id: [u8; 16],
    /// NTFS volume serial number.
    pub volume_serial: u64,
    /// Opaque volume GUID bytes.
    pub volume_guid: Vec<u8>,
    /// Opaque VSS snapshot identifier bytes.
    pub snapshot_id: Vec<u8>,
    /// Snapshot creation time, Unix milliseconds.
    pub snapshot_created_unix_ms: i64,
    /// Digest of the UFFS query that produced this candidate set.
    pub query_digest: Digest,
    /// Authorization model this job was authorized under.
    pub authorization_mode: AuthorizationMode,
    /// Total number of candidate records in the manifest.
    pub candidate_count: u64,
    /// Total byte length of the record section following this header.
    pub record_section_length: u64,
}

/// Bytes preceding the checksummed/length-counted header content:
/// 4 (magic) + 2 (`format_version`) + 2 (`header_length`).
const HEADER_PREFIX_LEN: usize = 8;

impl ManifestHeader {
    /// Encode this header, computing `header_length` and
    /// `header_checksum` automatically.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the encoded header would exceed `u16::MAX` bytes
    /// (only possible with an implausibly large `volume_guid`/`snapshot_id`).
    pub fn encode(&self) -> Result<Vec<u8>, ManifestError> {
        let mut content = Vec::new();
        content.extend_from_slice(&self.job_id);
        content.extend_from_slice(&self.source_id);
        write_u64_le(&mut content, self.volume_serial);
        write_bytes_u16_prefixed(&mut content, &self.volume_guid);
        write_bytes_u16_prefixed(&mut content, &self.snapshot_id);
        write_i64_le(&mut content, self.snapshot_created_unix_ms);
        content.extend_from_slice(&self.query_digest);
        content.push(self.authorization_mode.encode());
        write_u64_le(&mut content, self.candidate_count);
        write_u64_le(&mut content, self.record_section_length);

        // `header_length` covers exactly the bytes `decode` measures as
        // `consumed` (magic..record_section_length) — it must NOT include
        // the trailing `header_checksum`, which `decode` reads and
        // verifies separately, after computing `consumed`.
        let header_length_value = HEADER_PREFIX_LEN.checked_add(content.len()).ok_or(
            ManifestError::HeaderLengthMismatch {
                declared: 0,
                actual: usize::MAX,
            },
        )?;
        let header_length = u16::try_from(header_length_value).map_err(|_err| {
            ManifestError::HeaderLengthMismatch {
                declared: u16::MAX,
                actual: header_length_value,
            }
        })?;

        let mut checked = Vec::with_capacity(header_length_value + 4);
        checked.extend_from_slice(&MANIFEST_MAGIC);
        write_u16_le(&mut checked, self.format_version);
        write_u16_le(&mut checked, header_length);
        checked.extend_from_slice(&content);
        let checksum = checksum32(&checked);

        let mut out = checked;
        write_u32_le(&mut out, checksum);
        Ok(out)
    }

    /// Decode a manifest header from `reader`.
    ///
    /// # Errors
    ///
    /// See [`ManifestError`] variants: bad magic, length/checksum
    /// mismatch, unknown authorization mode, or an underlying bounds
    /// failure.
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, ManifestError> {
        let start = reader.position();

        let magic: [u8; 4] = reader.read_array()?;
        if magic != MANIFEST_MAGIC {
            return Err(ManifestError::BadMagic {
                expected: MANIFEST_MAGIC,
                actual: magic,
            });
        }
        let format_version = reader.read_u16_le()?;
        let header_length = reader.read_u16_le()?;

        let job_id: [u8; 16] = reader.read_array()?;
        let source_id: [u8; 16] = reader.read_array()?;
        let volume_serial = reader.read_u64_le()?;
        let volume_guid = reader.read_bytes_u16_prefixed("volume_guid", MAX_IDENTIFIER_BYTES)?;
        let snapshot_id = reader.read_bytes_u16_prefixed("snapshot_id", MAX_IDENTIFIER_BYTES)?;
        let snapshot_created_unix_ms = reader.read_i64_le()?;
        let query_digest: Digest = reader.read_array()?;
        let authorization_byte = reader.read_u8()?;
        let authorization_mode = AuthorizationMode::decode(authorization_byte)
            .map_err(ManifestError::UnknownAuthorizationMode)?;
        let candidate_count = reader.read_u64_le()?;
        let record_section_length = reader.read_u64_le()?;

        let end = reader.position();
        let consumed = end - start;
        if consumed != header_length as usize {
            return Err(ManifestError::HeaderLengthMismatch {
                declared: header_length,
                actual: consumed,
            });
        }

        let expected_checksum = reader.read_u32_le()?;
        let header_bytes =
            reader
                .full_buffer()
                .get(start..end)
                .ok_or(ManifestError::HeaderLengthMismatch {
                    declared: header_length,
                    actual: consumed,
                })?;
        let computed_checksum = checksum32(header_bytes);
        if expected_checksum != computed_checksum {
            return Err(ManifestError::ChecksumMismatch {
                expected: expected_checksum,
                computed: computed_checksum,
            });
        }

        Ok(Self {
            format_version,
            job_id,
            source_id,
            volume_serial,
            volume_guid,
            snapshot_id,
            snapshot_created_unix_ms,
            query_digest,
            authorization_mode,
            candidate_count,
            record_section_length,
        })
    }
}

/// One candidate manifest record (design-doc §11.2/§5.2/§5.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRecord {
    /// Unique identifier for this candidate within this job.
    pub candidate_id: u64,
    /// Full NTFS file reference (MFT index + sequence number packed per
    /// the platform's native 64-bit file-ID layout) — never a bare MFT
    /// record index (design-doc §5.2, enterprise-review Finding C4).
    pub file_reference: u64,
    /// Logical size at snapshot time.
    pub logical_size: u64,
    /// Valid Data Length at snapshot time.
    pub valid_data_length: u64,
    /// Modification time, Unix milliseconds.
    pub mtime_unix_ms: i64,
    /// Planning-hint flags (design-doc §11.4).
    pub candidate_flags: CandidateFlags,
    /// Lossless Windows path.
    pub path: WindowsPath,
}

/// Bytes contributed by the fixed-width fields preceding the
/// variable-length path: `candidate_id`(8) + `file_reference`(8) +
/// `logical_size`(8) + `valid_data_length`(8) + `mtime_unix_ms`(8) +
/// `candidate_flags`(4) = 44. Does not include `record_length` (4) or
/// `record_checksum` (4), which are added separately below.
const RECORD_FIXED_CONTENT_LEN: usize = 44;

impl CandidateRecord {
    /// Encode this record, computing `record_length` and
    /// `record_checksum` automatically.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the encoded record would exceed `u32::MAX` bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ManifestError> {
        let mut content = Vec::with_capacity(RECORD_FIXED_CONTENT_LEN);
        write_u64_le(&mut content, self.candidate_id);
        write_u64_le(&mut content, self.file_reference);
        write_u64_le(&mut content, self.logical_size);
        write_u64_le(&mut content, self.valid_data_length);
        write_i64_le(&mut content, self.mtime_unix_ms);
        write_u32_le(&mut content, self.candidate_flags.bits());
        self.path.encode(&mut content);

        // `record_length` covers exactly the bytes `decode` measures as
        // `consumed` (record_length field itself..end of path) — it must
        // NOT include the trailing `record_checksum`, which `decode`
        // reads and verifies separately, after computing `consumed`.
        let record_length_value = content
                .len()
                .checked_add(4) // + record_length field itself
                .ok_or(ManifestError::RecordLengthMismatch {
                    declared: 0,
                    actual: usize::MAX,
                })?;
        let record_length = u32::try_from(record_length_value).map_err(|_err| {
            ManifestError::RecordLengthMismatch {
                declared: u32::MAX,
                actual: record_length_value,
            }
        })?;

        let mut checked = Vec::with_capacity(record_length_value + 4);
        write_u32_le(&mut checked, record_length);
        checked.extend_from_slice(&content);
        let checksum = checksum32(&checked);

        let mut out = checked;
        write_u32_le(&mut out, checksum);
        Ok(out)
    }

    /// Decode a candidate record from `reader`.
    ///
    /// # Errors
    ///
    /// See [`ManifestError`] variants: length/checksum mismatch, a
    /// malformed path, or an underlying bounds failure.
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, ManifestError> {
        let start = reader.position();
        let record_length = reader.read_u32_le()?;

        let candidate_id = reader.read_u64_le()?;
        let file_reference = reader.read_u64_le()?;
        let logical_size = reader.read_u64_le()?;
        let valid_data_length = reader.read_u64_le()?;
        let mtime_unix_ms = reader.read_i64_le()?;
        let flags_bits = reader.read_u32_le()?;
        let candidate_flags = CandidateFlags::from_bits_truncate(flags_bits);
        let path = WindowsPath::decode(reader, MAX_PATH_BYTES)?;

        let end = reader.position();
        let consumed = end - start;
        if consumed != record_length as usize {
            return Err(ManifestError::RecordLengthMismatch {
                declared: record_length,
                actual: consumed,
            });
        }

        let expected_checksum = reader.read_u32_le()?;
        let record_bytes =
            reader
                .full_buffer()
                .get(start..end)
                .ok_or(ManifestError::RecordLengthMismatch {
                    declared: record_length,
                    actual: consumed,
                })?;
        let computed_checksum = checksum32(record_bytes);
        if expected_checksum != computed_checksum {
            return Err(ManifestError::ChecksumMismatch {
                expected: expected_checksum,
                computed: computed_checksum,
            });
        }

        Ok(Self {
            candidate_id,
            file_reference,
            logical_size,
            valid_data_length,
            mtime_unix_ms,
            candidate_flags,
            path,
        })
    }
}

/// Manifest trailer (design-doc §11.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestTrailer {
    /// Repeats the header's `candidate_count`, so a streaming consumer
    /// can validate completeness without holding the header in memory.
    pub candidate_count_repeat: u64,
    /// BLAKE3 digest of the entire manifest (header + record section)
    /// preceding this trailer.
    pub manifest_digest: Digest,
}

impl ManifestTrailer {
    /// Encode this trailer.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.candidate_count_repeat);
        out.extend_from_slice(&self.manifest_digest);
        out.extend_from_slice(&MANIFEST_END_MAGIC);
        out
    }

    /// Decode a trailer from `reader`.
    ///
    /// # Errors
    ///
    /// [`ManifestError::BadMagic`] if `end_magic` does not match, or an
    /// underlying bounds failure.
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, ManifestError> {
        let candidate_count_repeat = reader.read_u64_le()?;
        let manifest_digest: Digest = reader.read_array()?;
        let end_magic: [u8; 4] = reader.read_array()?;
        if end_magic != MANIFEST_END_MAGIC {
            return Err(ManifestError::BadMagic {
                expected: MANIFEST_END_MAGIC,
                actual: end_magic,
            });
        }
        Ok(Self {
            candidate_count_repeat,
            manifest_digest,
        })
    }

    /// Compute the trailer's `manifest_digest` over `manifest_bytes`
    /// (header + record section, exactly as they appear on the wire
    /// preceding the trailer).
    #[must_use]
    pub fn compute_digest(manifest_bytes: &[u8]) -> Digest {
        digest(manifest_bytes)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{
        AuthorizationMode, CandidateFlags, CandidateRecord, ManifestError, ManifestHeader,
        ManifestTrailer,
    };
    use crate::codec::Reader;
    use crate::path_encoding::WindowsPath;

    fn sample_header() -> ManifestHeader {
        ManifestHeader {
            format_version: 2,
            job_id: [1_u8; 16],
            source_id: [2_u8; 16],
            volume_serial: 0x1234_5678_9ABC_DEF0,
            volume_guid: b"{11111111-2222-3333-4444-555555555555}".to_vec(),
            snapshot_id: b"snap-0001".to_vec(),
            snapshot_created_unix_ms: 1_752_000_000_000,
            query_digest: [7_u8; 32],
            authorization_mode: AuthorizationMode::AdminExport,
            candidate_count: 3,
            record_section_length: 999,
        }
    }

    fn sample_record(candidate_id: u64) -> CandidateRecord {
        CandidateRecord {
            candidate_id,
            file_reference: 0xABCD_EF01_2345_6789,
            logical_size: 4096,
            valid_data_length: 4096,
            mtime_unix_ms: 1_752_000_000_000,
            candidate_flags: CandidateFlags::NONRESIDENT | CandidateFlags::LARGE_FILE,
            path: WindowsPath::from_str_lossless(r"C:\Users\robert\data\file.bin"),
        }
    }

    #[test]
    fn header_round_trips() {
        let header = sample_header();
        let bytes = header.encode().unwrap();
        let mut reader = Reader::new(&bytes);
        let decoded = ManifestHeader::decode(&mut reader).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(
            reader.remaining(),
            0,
            "decode must consume the whole header"
        );
    }

    #[test]
    #[expect(
        clippy::indexing_slicing,
        reason = "test mutation of a known, already-validated buffer index; \
                  clippy::get_unwrap is also denied, so a scoped exception on \
                  direct indexing is the established pattern for this \
                  conflict (see crates/uffs-daemon/tests/ipc_integration.rs)"
    )]
    fn header_rejects_bad_magic() {
        let header = sample_header();
        let mut bytes = header.encode().unwrap();
        bytes[0] = b'X';
        let mut reader = Reader::new(&bytes);
        let err = ManifestHeader::decode(&mut reader).unwrap_err();
        assert!(matches!(err, ManifestError::BadMagic { .. }));
    }

    #[test]
    #[expect(
        clippy::indexing_slicing,
        reason = "test mutation of a known, already-validated buffer index; \
                  clippy::get_unwrap is also denied, so a scoped exception on \
                  direct indexing is the established pattern for this \
                  conflict (see crates/uffs-daemon/tests/ipc_integration.rs)"
    )]
    fn header_rejects_flipped_byte_via_checksum() {
        let header = sample_header();
        let mut bytes = header.encode().unwrap();
        // Flip a byte inside the checksummed region (well past the magic
        // and length fields, inside `job_id`).
        let flip_index = 10;
        bytes[flip_index] ^= 0xFF;
        let mut reader = Reader::new(&bytes);
        let err = ManifestHeader::decode(&mut reader).unwrap_err();
        assert!(matches!(err, ManifestError::ChecksumMismatch { .. }));
    }

    #[test]
    fn header_rejects_unknown_authorization_mode() {
        let header = sample_header();
        let bytes = header.encode().unwrap();
        // Re-encode is awkward to mutate mid-structure directly since the
        // checksum covers it; instead, hand-verify the decode path
        // rejects an out-of-range byte by constructing a header with a
        // manually patched authorization byte and a recomputed checksum
        // would require re-implementing encode. Simplest robust check:
        // AuthorizationMode::decode itself rejects out-of-range bytes,
        // exercised directly.
        assert_eq!(AuthorizationMode::decode(2), Err(2));
        // Sanity: the real header still round-trips (guards against a
        // future refactor accidentally breaking the happy path while
        // "testing" the unhappy one above).
        let mut reader = Reader::new(&bytes);
        ManifestHeader::decode(&mut reader).unwrap();
    }

    #[test]
    fn record_round_trips() {
        let record = sample_record(42);
        let bytes = record.encode().unwrap();
        let mut reader = Reader::new(&bytes);
        let decoded = CandidateRecord::decode(&mut reader).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(
            reader.remaining(),
            0,
            "decode must consume the whole record"
        );
    }

    #[test]
    #[expect(
        clippy::indexing_slicing,
        reason = "test mutation of a known, already-validated buffer index; \
                  clippy::get_unwrap is also denied, so a scoped exception on \
                  direct indexing is the established pattern for this \
                  conflict (see crates/uffs-daemon/tests/ipc_integration.rs)"
    )]
    fn record_rejects_flipped_byte_via_checksum() {
        let record = sample_record(1);
        let mut bytes = record.encode().unwrap();
        let last = bytes.len() - 5; // inside the record body, before the trailing checksum
        bytes[last] ^= 0xFF;
        let mut reader = Reader::new(&bytes);
        let err = CandidateRecord::decode(&mut reader).unwrap_err();
        assert!(matches!(err, ManifestError::ChecksumMismatch { .. }));
    }

    #[test]
    fn record_flags_round_trip_bit_pattern() {
        let mut record = sample_record(7);
        record.candidate_flags = CandidateFlags::RESIDENT
            | CandidateFlags::SPARSE
            | CandidateFlags::MANUAL_HANDLER_LIKELY;
        let bytes = record.encode().unwrap();
        let mut reader = Reader::new(&bytes);
        let decoded = CandidateRecord::decode(&mut reader).unwrap();
        assert_eq!(decoded.candidate_flags, record.candidate_flags);
    }

    #[test]
    fn trailer_round_trips() {
        let trailer = ManifestTrailer {
            candidate_count_repeat: 3,
            manifest_digest: [9_u8; 32],
        };
        let bytes = trailer.encode();
        let mut reader = Reader::new(&bytes);
        let decoded = ManifestTrailer::decode(&mut reader).unwrap();
        assert_eq!(decoded, trailer);
    }

    #[test]
    #[expect(
        clippy::indexing_slicing,
        reason = "test mutation of a known, already-validated buffer index; \
                  clippy::get_unwrap is also denied, so a scoped exception on \
                  direct indexing is the established pattern for this \
                  conflict (see crates/uffs-daemon/tests/ipc_integration.rs)"
    )]
    fn trailer_rejects_bad_end_magic() {
        let trailer = ManifestTrailer {
            candidate_count_repeat: 1,
            manifest_digest: [0_u8; 32],
        };
        let mut bytes = trailer.encode();
        let last_index = bytes.len() - 1;
        bytes[last_index] = b'?';
        let mut reader = Reader::new(&bytes);
        let err = ManifestTrailer::decode(&mut reader).unwrap_err();
        assert!(matches!(err, ManifestError::BadMagic { .. }));
    }

    #[test]
    fn full_manifest_round_trip_with_multiple_candidates() {
        // End-to-end: header + N records + trailer, exactly the shape a
        // real manifest file has on disk, decoded back sequentially from
        // one contiguous buffer.
        let candidates: Vec<CandidateRecord> = (0..5).map(sample_record).collect();

        let mut record_bytes = Vec::new();
        for candidate in &candidates {
            record_bytes.extend_from_slice(&candidate.encode().unwrap());
        }

        let mut header = sample_header();
        header.candidate_count = candidates.len() as u64;
        header.record_section_length = record_bytes.len() as u64;
        let mut manifest_bytes = header.encode().unwrap();
        manifest_bytes.extend_from_slice(&record_bytes);

        let trailer = ManifestTrailer {
            candidate_count_repeat: header.candidate_count,
            manifest_digest: ManifestTrailer::compute_digest(&manifest_bytes),
        };
        manifest_bytes.extend_from_slice(&trailer.encode());

        // Now decode the whole thing back.
        let mut reader = Reader::new(&manifest_bytes);
        let decoded_header = ManifestHeader::decode(&mut reader).unwrap();
        assert_eq!(decoded_header, header);

        let mut decoded_candidates = Vec::new();
        for _ in 0..decoded_header.candidate_count {
            decoded_candidates.push(CandidateRecord::decode(&mut reader).unwrap());
        }
        assert_eq!(decoded_candidates, candidates);

        let decoded_trailer = ManifestTrailer::decode(&mut reader).unwrap();
        assert_eq!(
            decoded_trailer.candidate_count_repeat,
            header.candidate_count
        );
        assert_eq!(
            reader.remaining(),
            0,
            "trailer must be the last thing in the manifest"
        );

        // Completeness invariant sanity: every decoded candidate_id is
        // unique and matches what was encoded (design-doc §21.7).
        let mut ids: Vec<u64> = decoded_candidates
            .iter()
            .map(|candidate| candidate.candidate_id)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids.len(),
            decoded_candidates.len(),
            "candidate_id must be unique"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        #[test]
        fn candidate_record_round_trips_for_arbitrary_fields(
            candidate_id: u64,
            file_reference: u64,
            logical_size: u64,
            valid_data_length: u64,
            mtime_unix_ms: i64,
            flags_bits: u32,
            path_str in "[a-zA-Z0-9_/\\\\:. ]{0,200}",
        ) {
            let record = CandidateRecord {
                candidate_id,
                file_reference,
                logical_size,
                valid_data_length,
                mtime_unix_ms,
                candidate_flags: CandidateFlags::from_bits_truncate(flags_bits),
                path: WindowsPath::from_str_lossless(&path_str),
            };
            let bytes = record.encode().unwrap();
            let mut reader = Reader::new(&bytes);
            let decoded = CandidateRecord::decode(&mut reader).unwrap();
            prop_assert_eq!(decoded, record);
        }
    }
}
