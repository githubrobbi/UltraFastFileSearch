// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Stable, machine-readable error taxonomy (design-doc §16).

/// Stable, machine-readable protocol/content error code.
///
/// Every variant maps to exactly one `SCREAMING_SNAKE_CASE` stable string
/// via [`ErrorCode::as_str`] — this is the wire-visible form, and it's
/// what a non-Rust consumer implementing the spec from the Markdown
/// document alone would match on. [`ErrorCode::as_str`] and the
/// [`FromStr`](core::str::FromStr) impl round-trip for every variant;
/// this is asserted by an exhaustive test in this module specifically so
/// a future contributor cannot silently rename a code in one language and
/// not the other (that exact risk is called out in
/// `uffs-ingest-implementation-plan.md` §2.2).
///
/// `#[non_exhaustive]`: a future protocol revision adding a code is an
/// additive, non-breaking change for consumers whose `match` has a
/// wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    // ── Snapshot lifecycle ──────────────────────────────────────────
    /// VSS snapshot creation failed.
    SnapshotCreateFailed,
    /// VSS snapshot device could not be opened.
    SnapshotOpenFailed,
    /// The snapshot became unavailable after candidates began processing.
    SnapshotLost,
    /// Copy-on-write storage backing the snapshot was exhausted.
    SnapshotStorageExhausted,

    // ── Manifest / identity ─────────────────────────────────────────
    /// The manifest failed structural or checksum validation.
    ManifestCorrupt,
    /// A referenced `candidate_id` does not exist in the finalized manifest.
    CandidateIdInvalid,
    /// The object opened at read time does not match the manifest identity.
    IdentityMismatch,
    /// The full file reference's sequence number indicates the MFT record
    /// was reused since manifest finalization.
    FileReferenceReused,
    /// The candidate's path could not be resolved/opened.
    PathUnresolvable,

    // ── Stream resolution ───────────────────────────────────────────
    /// The requested stream (unnamed `$DATA`) was not found on the object.
    StreamNotFound,
    /// The stream's on-disk layout is not one this version supports.
    StreamLayoutUnsupported,
    /// The object's attribute-list layout is not one this version supports.
    AttributeListUnsupported,
    /// The nonresident data run list failed validation.
    RunlistCorrupt,
    /// A resolved extent falls outside validated volume bounds.
    ExtentOutOfBounds,
    /// The EOF/valid-data-length relationship failed validation.
    VdlEofInvalid,

    // ── Deferred-to-manual reasons ───────────────────────────────────
    /// Candidate is NTFS-compressed; deferred to manual handling.
    CompressedManual,
    /// Candidate is EFS-encrypted; deferred to manual handling.
    EncryptedManual,
    /// Candidate has an unsupported sparse layout; deferred to manual handling.
    SparseManual,
    /// Candidate is reparse-point-backed; deferred to manual handling.
    ReparseManual,
    /// Candidate is Data-Dedup-optimized or otherwise provider-backed;
    /// deferred to manual handling.
    DedupProviderManual,
    /// Candidate is a cloud placeholder; deferred to manual handling.
    CloudPlaceholderManual,
    /// Candidate has other special semantics not yet supported; deferred
    /// to manual handling.
    SpecialSemanticsManual,

    // ── Read / integrity ─────────────────────────────────────────────
    /// A transient I/O error occurred while reading.
    ReadIoTransient,
    /// A permanent I/O error occurred while reading.
    ReadIoPermanent,
    /// A read returned fewer bytes than the validated plan required.
    ReadShort,
    /// Incremental hashing failed internally.
    HashFailed,
    /// The final digest did not match the expected/reported value.
    DigestMismatch,

    // ── Transport / job ───────────────────────────────────────────────
    /// The consumer disconnected before the operation completed.
    ConsumerDisconnected,
    /// The consumer explicitly rejected a delivered frame (e.g. digest
    /// mismatch on its side).
    ConsumerRejected,
    /// A protocol-level violation occurred (version skew, invalid frame
    /// sequence, etc.) distinct from a single frame's bytes being corrupt.
    ///
    /// Wire string is `PROTOCOL_ERROR` (design-doc §16 literal token);
    /// the variant is named `ProtocolViolation` to avoid colliding with
    /// this crate's [`crate::codec::DecodeError`] naming.
    ProtocolViolation,
    /// A frame failed header/payload checksum validation.
    FrameCorrupt,
    /// The job was cancelled.
    JobCancelled,
    /// A configured resource limit (byte/file/time/memory/concurrency)
    /// was reached.
    ResourceLimit,
    /// An internal error occurred that does not fit another category.
    InternalError,
}

impl ErrorCode {
    /// The stable `SCREAMING_SNAKE_CASE` wire string for this code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SnapshotCreateFailed => "SNAPSHOT_CREATE_FAILED",
            Self::SnapshotOpenFailed => "SNAPSHOT_OPEN_FAILED",
            Self::SnapshotLost => "SNAPSHOT_LOST",
            Self::SnapshotStorageExhausted => "SNAPSHOT_STORAGE_EXHAUSTED",
            Self::ManifestCorrupt => "MANIFEST_CORRUPT",
            Self::CandidateIdInvalid => "CANDIDATE_ID_INVALID",
            Self::IdentityMismatch => "IDENTITY_MISMATCH",
            Self::FileReferenceReused => "FILE_REFERENCE_REUSED",
            Self::PathUnresolvable => "PATH_UNRESOLVABLE",
            Self::StreamNotFound => "STREAM_NOT_FOUND",
            Self::StreamLayoutUnsupported => "STREAM_LAYOUT_UNSUPPORTED",
            Self::AttributeListUnsupported => "ATTRIBUTE_LIST_UNSUPPORTED",
            Self::RunlistCorrupt => "RUNLIST_CORRUPT",
            Self::ExtentOutOfBounds => "EXTENT_OUT_OF_BOUNDS",
            Self::VdlEofInvalid => "VDL_EOF_INVALID",
            Self::CompressedManual => "COMPRESSED_MANUAL",
            Self::EncryptedManual => "ENCRYPTED_MANUAL",
            Self::SparseManual => "SPARSE_MANUAL",
            Self::ReparseManual => "REPARSE_MANUAL",
            Self::DedupProviderManual => "DEDUP_PROVIDER_MANUAL",
            Self::CloudPlaceholderManual => "CLOUD_PLACEHOLDER_MANUAL",
            Self::SpecialSemanticsManual => "SPECIAL_SEMANTICS_MANUAL",
            Self::ReadIoTransient => "READ_IO_TRANSIENT",
            Self::ReadIoPermanent => "READ_IO_PERMANENT",
            Self::ReadShort => "READ_SHORT",
            Self::HashFailed => "HASH_FAILED",
            Self::DigestMismatch => "DIGEST_MISMATCH",
            Self::ConsumerDisconnected => "CONSUMER_DISCONNECTED",
            Self::ConsumerRejected => "CONSUMER_REJECTED",
            Self::ProtocolViolation => "PROTOCOL_ERROR",
            Self::FrameCorrupt => "FRAME_CORRUPT",
            Self::JobCancelled => "JOB_CANCELLED",
            Self::ResourceLimit => "RESOURCE_LIMIT",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }

    /// All variants, for exhaustive round-trip testing.
    #[cfg(test)]
    const ALL: &'static [Self] = &[
        Self::SnapshotCreateFailed,
        Self::SnapshotOpenFailed,
        Self::SnapshotLost,
        Self::SnapshotStorageExhausted,
        Self::ManifestCorrupt,
        Self::CandidateIdInvalid,
        Self::IdentityMismatch,
        Self::FileReferenceReused,
        Self::PathUnresolvable,
        Self::StreamNotFound,
        Self::StreamLayoutUnsupported,
        Self::AttributeListUnsupported,
        Self::RunlistCorrupt,
        Self::ExtentOutOfBounds,
        Self::VdlEofInvalid,
        Self::CompressedManual,
        Self::EncryptedManual,
        Self::SparseManual,
        Self::ReparseManual,
        Self::DedupProviderManual,
        Self::CloudPlaceholderManual,
        Self::SpecialSemanticsManual,
        Self::ReadIoTransient,
        Self::ReadIoPermanent,
        Self::ReadShort,
        Self::HashFailed,
        Self::DigestMismatch,
        Self::ConsumerDisconnected,
        Self::ConsumerRejected,
        Self::ProtocolViolation,
        Self::FrameCorrupt,
        Self::JobCancelled,
        Self::ResourceLimit,
        Self::InternalError,
    ];
}

/// Error returned by [`ErrorCode`]'s [`FromStr`](core::str::FromStr) impl
/// when the input does not match any known stable wire string.
///
/// A caller that needs to tolerate codes from a newer producer build
/// should treat this as "unrecognized/future code," not a hard protocol
/// error — that's this crate's forward-compatibility stance for
/// `#[non_exhaustive]` enums in general.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized ErrorCode wire string")]
pub struct UnknownErrorCode;

impl core::str::FromStr for ErrorCode {
    type Err = UnknownErrorCode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "SNAPSHOT_CREATE_FAILED" => Self::SnapshotCreateFailed,
            "SNAPSHOT_OPEN_FAILED" => Self::SnapshotOpenFailed,
            "SNAPSHOT_LOST" => Self::SnapshotLost,
            "SNAPSHOT_STORAGE_EXHAUSTED" => Self::SnapshotStorageExhausted,
            "MANIFEST_CORRUPT" => Self::ManifestCorrupt,
            "CANDIDATE_ID_INVALID" => Self::CandidateIdInvalid,
            "IDENTITY_MISMATCH" => Self::IdentityMismatch,
            "FILE_REFERENCE_REUSED" => Self::FileReferenceReused,
            "PATH_UNRESOLVABLE" => Self::PathUnresolvable,
            "STREAM_NOT_FOUND" => Self::StreamNotFound,
            "STREAM_LAYOUT_UNSUPPORTED" => Self::StreamLayoutUnsupported,
            "ATTRIBUTE_LIST_UNSUPPORTED" => Self::AttributeListUnsupported,
            "RUNLIST_CORRUPT" => Self::RunlistCorrupt,
            "EXTENT_OUT_OF_BOUNDS" => Self::ExtentOutOfBounds,
            "VDL_EOF_INVALID" => Self::VdlEofInvalid,
            "COMPRESSED_MANUAL" => Self::CompressedManual,
            "ENCRYPTED_MANUAL" => Self::EncryptedManual,
            "SPARSE_MANUAL" => Self::SparseManual,
            "REPARSE_MANUAL" => Self::ReparseManual,
            "DEDUP_PROVIDER_MANUAL" => Self::DedupProviderManual,
            "CLOUD_PLACEHOLDER_MANUAL" => Self::CloudPlaceholderManual,
            "SPECIAL_SEMANTICS_MANUAL" => Self::SpecialSemanticsManual,
            "READ_IO_TRANSIENT" => Self::ReadIoTransient,
            "READ_IO_PERMANENT" => Self::ReadIoPermanent,
            "READ_SHORT" => Self::ReadShort,
            "HASH_FAILED" => Self::HashFailed,
            "DIGEST_MISMATCH" => Self::DigestMismatch,
            "CONSUMER_DISCONNECTED" => Self::ConsumerDisconnected,
            "CONSUMER_REJECTED" => Self::ConsumerRejected,
            "PROTOCOL_ERROR" => Self::ProtocolViolation,
            "FRAME_CORRUPT" => Self::FrameCorrupt,
            "JOB_CANCELLED" => Self::JobCancelled,
            "RESOURCE_LIMIT" => Self::ResourceLimit,
            "INTERNAL_ERROR" => Self::InternalError,
            _ => return Err(UnknownErrorCode),
        })
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr as _;

    use super::ErrorCode;

    #[test]
    fn every_variant_round_trips_through_as_str_and_from_str() {
        for &code in ErrorCode::ALL {
            let wire_str = code.as_str();
            let parsed = ErrorCode::from_str(wire_str)
                .unwrap_or_else(|_| panic!("as_str() output {wire_str:?} must parse back"));
            assert_eq!(parsed, code, "round-trip mismatch for {wire_str:?}");
        }
    }

    #[test]
    fn every_variant_has_a_distinct_wire_string() {
        let mut seen = std::collections::HashSet::new();
        for &code in ErrorCode::ALL {
            assert!(
                seen.insert(code.as_str()),
                "duplicate wire string: {:?}",
                code.as_str()
            );
        }
    }

    #[test]
    fn every_wire_string_is_screaming_snake_case() {
        for &code in ErrorCode::ALL {
            let wire_str = code.as_str();
            assert!(
                wire_str
                    .chars()
                    .all(|ch| ch.is_ascii_uppercase() || ch == '_' || ch.is_ascii_digit()),
                "{wire_str:?} is not SCREAMING_SNAKE_CASE"
            );
        }
    }

    #[test]
    fn from_str_rejects_unknown_code() {
        ErrorCode::from_str("NOT_A_REAL_CODE").unwrap_err();
        ErrorCode::from_str("").unwrap_err();
        ErrorCode::from_str("snapshot_lost").unwrap_err(); // wrong case
    }
}
