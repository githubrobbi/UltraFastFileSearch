// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit tests for [`super`] (`frame`) and all twelve payload submodules.

use super::{
    ConsumerAckStatus, ContentChunk, ContentSemantics, DigestAlgorithm, FailedOutcome,
    FailureStage, FileAck, FileBegin, FileDeferred, FileEnd, FileFailed, FrameEnvelope, FrameError,
    FrameOrdering, FrameType, Heartbeat, JobBegin, JobCancel, JobEnd, JobResume, JobStatus,
    JobSubmit, PROTOCOL_VERSION, Progress, ReadMode, RetryClass, WindowUpdate,
};
use crate::codec::Reader;
use crate::error::ErrorCode;
use crate::manifest::AuthorizationMode;
use crate::path_encoding::WindowsPath;

fn sample_envelope(frame_type: FrameType, frame_sequence: u64) -> FrameEnvelope {
    FrameEnvelope {
        protocol_version: PROTOCOL_VERSION,
        frame_type,
        flags: 0,
        job_id: [3_u8; 16],
        frame_sequence,
    }
}

#[test]
fn envelope_round_trips_with_payload() {
    let envelope = sample_envelope(FrameType::Heartbeat, 7);
    let payload = b"hello frame payload";
    let bytes = envelope.encode(payload);
    let mut reader = Reader::new(&bytes);
    let (decoded_envelope, decoded_payload) =
        FrameEnvelope::decode(&mut reader, 1_000_000).unwrap();
    assert_eq!(decoded_envelope, envelope);
    assert_eq!(decoded_payload, payload);
    assert_eq!(reader.remaining(), 0);
}

#[test]
fn envelope_round_trips_with_empty_payload() {
    let envelope = sample_envelope(FrameType::JobCancel, 1);
    let bytes = envelope.encode(&[]);
    let mut reader = Reader::new(&bytes);
    let (decoded_envelope, decoded_payload) =
        FrameEnvelope::decode(&mut reader, 1_000_000).unwrap();
    assert_eq!(decoded_envelope, envelope);
    assert!(decoded_payload.is_empty());
}

#[test]
#[expect(
    clippy::indexing_slicing,
    reason = "test mutation of a known, already-validated buffer index; \
              clippy::get_unwrap is also denied, so a scoped exception on \
              direct indexing is the established pattern for this \
              conflict (see crates/uffs-daemon/tests/ipc_integration.rs)"
)]
fn envelope_rejects_bad_magic() {
    let envelope = sample_envelope(FrameType::Heartbeat, 1);
    let mut bytes = envelope.encode(&[]);
    bytes[0] = b'Z';
    let mut reader = Reader::new(&bytes);
    let err = FrameEnvelope::decode(&mut reader, 1_000_000).unwrap_err();
    assert!(matches!(err, FrameError::BadMagic(_)));
}

#[test]
#[expect(
    clippy::indexing_slicing,
    reason = "test mutation of a known, already-validated buffer index; \
              clippy::get_unwrap is also denied, so a scoped exception on \
              direct indexing is the established pattern for this \
              conflict (see crates/uffs-daemon/tests/ipc_integration.rs)"
)]
fn envelope_rejects_flipped_header_byte_via_checksum() {
    let envelope = sample_envelope(FrameType::Heartbeat, 1);
    let mut bytes = envelope.encode(&[]);
    // job_id lives inside the checksummed header region.
    bytes[20] ^= 0xFF;
    let mut reader = Reader::new(&bytes);
    let err = FrameEnvelope::decode(&mut reader, 1_000_000).unwrap_err();
    assert!(matches!(err, FrameError::HeaderChecksumMismatch { .. }));
}

#[test]
#[expect(
    clippy::indexing_slicing,
    reason = "test mutation of a known, already-validated buffer index; \
              clippy::get_unwrap is also denied, so a scoped exception on \
              direct indexing is the established pattern for this \
              conflict (see crates/uffs-daemon/tests/ipc_integration.rs)"
)]
fn envelope_rejects_flipped_payload_byte_via_checksum() {
    let envelope = sample_envelope(FrameType::Heartbeat, 1);
    let mut bytes = envelope.encode(b"payload bytes here");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let mut reader = Reader::new(&bytes);
    let err = FrameEnvelope::decode(&mut reader, 1_000_000).unwrap_err();
    assert!(matches!(err, FrameError::PayloadChecksumMismatch { .. }));
}

#[test]
fn envelope_rejects_payload_exceeding_max_before_allocation() {
    let envelope = sample_envelope(FrameType::ContentChunk, 1);
    let bytes = envelope.encode(&[1, 2, 3, 4, 5]);
    let mut reader = Reader::new(&bytes);
    let err = FrameEnvelope::decode(&mut reader, 2).unwrap_err();
    assert!(matches!(err, FrameError::PayloadTooLarge {
        declared: 5,
        max: 2
    }));
}

#[test]
#[expect(
    clippy::indexing_slicing,
    reason = "test mutation of a known, already-validated buffer range; \
              clippy::get_unwrap is also denied, so a scoped exception on \
              direct indexing is the established pattern for this \
              conflict (see crates/uffs-daemon/tests/ipc_integration.rs)"
)]
fn envelope_rejects_unknown_frame_type() {
    // Hand-craft an envelope with frame_type = 999 by encoding a
    // valid one then patching the frame_type field bytes directly
    // (offset 6-7: magic(4) + protocol_version(2)).
    let envelope = sample_envelope(FrameType::Heartbeat, 1);
    let mut bytes = envelope.encode(&[]);
    bytes[6..8].copy_from_slice(&999_u16.to_le_bytes());
    let mut reader = Reader::new(&bytes);
    let err = FrameEnvelope::decode(&mut reader, 1_000_000).unwrap_err();
    assert!(matches!(err, FrameError::UnknownFrameType(999)));
}

#[test]
#[expect(
    clippy::indexing_slicing,
    reason = "test mutation of a known, already-validated buffer range; \
              clippy::get_unwrap is also denied, so a scoped exception on \
              direct indexing is the established pattern for this \
              conflict (see crates/uffs-daemon/tests/ipc_integration.rs)"
)]
fn envelope_rejects_mismatched_protocol_version() {
    // Patch the protocol_version field bytes directly (offset 4-5:
    // magic(4), before frame_type at offset 6-7) rather than constructing
    // an envelope with the "wrong" version, since `FrameEnvelope` only
    // has one field for it and this crate defines what "right" means.
    let envelope = sample_envelope(FrameType::Heartbeat, 1);
    let mut bytes = envelope.encode(&[]);
    bytes[4..6].copy_from_slice(&99_u16.to_le_bytes());
    let mut reader = Reader::new(&bytes);
    let err = FrameEnvelope::decode(&mut reader, 1_000_000).unwrap_err();
    assert!(matches!(err, FrameError::ProtocolVersionMismatch {
        expected: PROTOCOL_VERSION,
        actual: 99
    }));
}

#[test]
fn frame_type_round_trips_all_variants() {
    for value in 1_u16..=14 {
        let frame_type = FrameType::decode(value).unwrap();
        assert_eq!(frame_type.encode(), value);
    }
    assert_eq!(FrameType::decode(0), Err(0));
    assert_eq!(FrameType::decode(15), Err(15));
}

fn sample_job_begin() -> JobBegin {
    JobBegin {
        job_id: [1_u8; 16],
        source_id: [2_u8; 16],
        snapshot_id: b"snap-1".to_vec(),
        snapshot_created_at: 1_752_000_000_000,
        manifest_digest: [4_u8; 32],
        candidate_count: 10,
        authorization_mode: AuthorizationMode::AdminExport,
        ordering: FrameOrdering::None,
        content_semantics: ContentSemantics::UnnamedLogicalStream,
        digest_algorithm: DigestAlgorithm::Blake3,
        max_chunk_bytes: 65536,
        max_content_delivery_bytes: Some(64 * 1024 * 1024),
    }
}

#[test]
fn job_begin_round_trips() {
    let payload = sample_job_begin();
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = JobBegin::decode(&mut reader).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(reader.remaining(), 0);
}

#[test]
fn job_begin_round_trips_with_no_delivery_ceiling() {
    let mut payload = sample_job_begin();
    payload.max_content_delivery_bytes = None;
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = JobBegin::decode(&mut reader).unwrap();
    assert_eq!(decoded.max_content_delivery_bytes, None);
}

fn sample_file_begin() -> FileBegin {
    FileBegin {
        candidate_id: 42,
        file_reference: 0xABCD_EF01,
        path: WindowsPath::from_str_lossless(r"C:\data\report.txt"),
        logical_size: 2048,
        mtime: 1_752_000_000_000,
        read_mode: ReadMode::LogicalSnapshot,
        attempt_number: 1,
        content_object_id: None,
    }
}

#[test]
fn file_begin_round_trips() {
    let payload = sample_file_begin();
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = FileBegin::decode(&mut reader).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(reader.remaining(), 0);
}

#[test]
fn file_begin_round_trips_with_content_object_id() {
    let mut payload = sample_file_begin();
    payload.content_object_id = Some(999);
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = FileBegin::decode(&mut reader).unwrap();
    assert_eq!(decoded.content_object_id, Some(999));
}

#[test]
fn content_chunk_round_trips() {
    let payload = ContentChunk {
        candidate_id: 1,
        chunk_sequence: 0,
        logical_offset: 0,
        logical_length: 4,
        payload: vec![1, 2, 3, 4],
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = ContentChunk::decode(&mut reader, 1024).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn content_chunk_rejects_payload_over_max_before_allocation() {
    let payload = ContentChunk {
        candidate_id: 1,
        chunk_sequence: 0,
        logical_offset: 0,
        logical_length: 4,
        payload: vec![1, 2, 3, 4],
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let err = ContentChunk::decode(&mut reader, 2).unwrap_err();
    assert!(matches!(err, FrameError::Decode(_)));
}

#[test]
fn file_end_round_trips_with_delivered_content() {
    let payload = FileEnd {
        candidate_id: 1,
        total_logical_bytes: 4096,
        content_digest: Some([5_u8; 32]),
        read_mode: ReadMode::LogicalSnapshot,
        chunk_count: 1,
        elapsed_ms: 12,
        warning_flags: 0,
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = FileEnd::decode(&mut reader).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(reader.remaining(), 0);
}

#[test]
fn file_end_round_trips_metadata_only_with_no_digest() {
    // The content-delivery-ceiling case (design-doc addendum
    // discussion): candidate matched and validated, but its body
    // exceeded the job's delivery ceiling, so nothing was read.
    let payload = FileEnd {
        candidate_id: 2,
        total_logical_bytes: 0,
        content_digest: None,
        read_mode: ReadMode::MetadataOnly,
        chunk_count: 0,
        elapsed_ms: 1,
        warning_flags: 0,
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = FileEnd::decode(&mut reader).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(decoded.content_digest, None);
    assert_eq!(decoded.read_mode, ReadMode::MetadataOnly);
}

#[test]
fn read_mode_round_trips_all_variants_including_metadata_only() {
    for value in 0_u8..=3 {
        let mode = ReadMode::decode(value).unwrap();
        assert_eq!(mode.encode(), value);
    }
    assert_eq!(ReadMode::decode(4), Err(4));
}

#[test]
fn file_failed_round_trips() {
    let payload = FileFailed {
        candidate_id: 3,
        outcome: FailedOutcome::Retryable,
        failure_stage: FailureStage::Read,
        error_code: ErrorCode::ReadIoTransient,
        os_error_code: Some(-5),
        retry_class: RetryClass::RetrySameJob,
        bytes_emitted_before_failure: 100,
        message: "transient read error".to_owned(),
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = FileFailed::decode(&mut reader).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(reader.remaining(), 0);
}

#[test]
fn file_failed_round_trips_without_os_error_code() {
    let payload = FileFailed {
        candidate_id: 4,
        outcome: FailedOutcome::Terminal,
        failure_stage: FailureStage::Identity,
        error_code: ErrorCode::IdentityMismatch,
        os_error_code: None,
        retry_class: RetryClass::DoNotRetry,
        bytes_emitted_before_failure: 0,
        message: String::new(),
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = FileFailed::decode(&mut reader).unwrap();
    assert_eq!(decoded.os_error_code, None);
    assert_eq!(decoded.message, "");
}

#[test]
fn file_deferred_round_trips_with_hint() {
    let payload = FileDeferred {
        candidate_id: 5,
        reason_code: ErrorCode::CompressedManual,
        manual_handler_hint: Some("ntfs-compressed-handler".to_owned()),
        message: "NTFS compression not yet supported".to_owned(),
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = FileDeferred::decode(&mut reader).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn file_deferred_round_trips_without_hint() {
    let payload = FileDeferred {
        candidate_id: 6,
        reason_code: ErrorCode::SpecialSemanticsManual,
        manual_handler_hint: None,
        message: String::new(),
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = FileDeferred::decode(&mut reader).unwrap();
    assert_eq!(decoded.manual_handler_hint, None);
}

#[test]
fn file_ack_round_trips_accepted() {
    let payload = FileAck {
        candidate_id: 7,
        content_digest: [6_u8; 32],
        consumer_status: ConsumerAckStatus::Accepted,
        consumer_error_code: None,
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = FileAck::decode(&mut reader).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn file_ack_round_trips_rejected_with_error_code() {
    let payload = FileAck {
        candidate_id: 8,
        content_digest: [7_u8; 32],
        consumer_status: ConsumerAckStatus::Rejected,
        consumer_error_code: Some("DIGEST_MISMATCH_LOCAL".to_owned()),
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = FileAck::decode(&mut reader).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn job_end_round_trips_for_every_terminal_status() {
    for job_status in [
        JobStatus::Completed,
        JobStatus::CompletedWithFailures,
        JobStatus::Cancelled,
        JobStatus::Aborted,
    ] {
        let payload = JobEnd {
            candidate_count: 10,
            succeeded_count: 8,
            failed_retryable_count: 1,
            failed_terminal_count: 1,
            deferred_manual_count: 0,
            acknowledged_success_count: 8,
            logical_bytes_succeeded: 4096,
            failure_bucket_id: b"bucket-1".to_vec(),
            manifest_digest: [8_u8; 32],
            outcome_ledger_digest: [9_u8; 32],
            job_status,
        };
        let bytes = payload.encode().unwrap();
        let mut reader = Reader::new(&bytes);
        let decoded = JobEnd::decode(&mut reader).unwrap();
        assert_eq!(decoded, payload, "round-trip failed for {job_status:?}");
    }
}

#[test]
fn job_end_rejects_non_terminal_job_status_at_encode_time() {
    let payload = JobEnd {
        candidate_count: 1,
        succeeded_count: 0,
        failed_retryable_count: 0,
        failed_terminal_count: 0,
        deferred_manual_count: 0,
        acknowledged_success_count: 0,
        logical_bytes_succeeded: 0,
        failure_bucket_id: vec![],
        manifest_digest: [0_u8; 32],
        outcome_ledger_digest: [0_u8; 32],
        job_status: JobStatus::Streaming, // not a legal JOB_END status
    };
    let err = payload.encode().unwrap_err();
    assert!(matches!(err, FrameError::UnknownDiscriminant {
        field: "job_status",
        ..
    }));
}

#[test]
fn job_end_completeness_invariant_matches_sample_data() {
    // Anchors design-doc §2.2/§21.7: candidate_count must equal the
    // sum of the four outcome buckets. This test doesn't enforce the
    // invariant in the wire format itself (that's the Coordinator's
    // job) — it documents the expectation against a concrete example.
    let succeeded = 8_u64;
    let failed_retryable = 1_u64;
    let failed_terminal = 1_u64;
    let deferred_manual = 0_u64;
    let candidate_count = 10_u64;
    assert_eq!(
        candidate_count,
        succeeded + failed_retryable + failed_terminal + deferred_manual
    );
}

#[test]
fn progress_round_trips() {
    let payload = Progress {
        candidates_discovered: 100,
        candidates_completed: 42,
        logical_bytes_emitted: 1_000_000,
        error_count: 2,
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = Progress::decode(&mut reader).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn heartbeat_round_trips_the_progress_marker() {
    let payload = Heartbeat {
        last_completed_candidate_id: 42,
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = Heartbeat::decode(&mut reader);
    assert_eq!(decoded, payload);
}

#[test]
fn heartbeat_with_no_progress_yet_uses_the_zero_sentinel() {
    let payload = Heartbeat {
        last_completed_candidate_id: 0,
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = Heartbeat::decode(&mut reader);
    assert_eq!(decoded, payload);
}

#[test]
fn heartbeat_decodes_an_old_peers_empty_payload_as_the_zero_sentinel() {
    let decoded = Heartbeat::decode(&mut Reader::new(&[]));
    assert_eq!(decoded, Heartbeat {
        last_completed_candidate_id: 0
    });
}

#[test]
fn job_resume_encodes_to_empty_bytes() {
    let payload = JobResume;
    assert!(payload.encode().is_empty());
    let decoded = JobResume::decode();
    assert_eq!(decoded, JobResume);
}

#[test]
fn job_submit_round_trips_arbitrary_json_bytes() {
    let payload = JobSubmit {
        job_spec_json: br#"{"source_id":"s","root":"C:\\","query":"*.txt"}"#.to_vec(),
    };
    let bytes = payload.encode();
    let decoded = JobSubmit::decode(&bytes);
    assert_eq!(decoded, payload);
}

#[test]
fn job_submit_decodes_empty_payload_as_empty_json_bytes() {
    let decoded = JobSubmit::decode(&[]);
    assert_eq!(decoded, JobSubmit {
        job_spec_json: Vec::new()
    });
}

#[test]
fn job_cancel_round_trips() {
    let payload = JobCancel {
        reason: "user requested cancellation".to_owned(),
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = JobCancel::decode(&mut reader).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn window_update_round_trips() {
    let payload = WindowUpdate {
        additional_window_bytes: 1_048_576,
    };
    let bytes = payload.encode();
    let mut reader = Reader::new(&bytes);
    let decoded = WindowUpdate::decode(&mut reader).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn full_frame_round_trip_job_begin_inside_envelope() {
    // End-to-end: a real JobBegin payload framed by a real envelope,
    // exactly the shape that crosses the wire to Docenta.
    let job_begin = sample_job_begin();
    let payload_bytes = job_begin.encode();
    let envelope = sample_envelope(FrameType::JobBegin, 0);
    let frame_bytes = envelope.encode(&payload_bytes);

    let mut reader = Reader::new(&frame_bytes);
    let (decoded_envelope, decoded_payload) =
        FrameEnvelope::decode(&mut reader, 1_000_000).unwrap();
    assert_eq!(decoded_envelope.frame_type, FrameType::JobBegin);

    let mut payload_reader = Reader::new(&decoded_payload);
    let decoded_job_begin = JobBegin::decode(&mut payload_reader).unwrap();
    assert_eq!(decoded_job_begin, job_begin);
}
