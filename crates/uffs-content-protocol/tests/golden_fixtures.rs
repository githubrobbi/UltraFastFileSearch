// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Golden fixture conformance tests (design-doc §21.6, addendum §5.5).
//!
//! Each fixture under `tests/fixtures/*.bin` is a **frozen** wire-format
//! sample, committed to the repository. These tests decode the frozen
//! bytes and assert the expected values — they do not regenerate the
//! bytes from the current encoder on every run. That distinction is the
//! entire point: if a future change to `encode()`/`decode()` silently
//! drifts the wire format, a test that regenerated its own expected
//! bytes each time would never catch it, because it would just compare
//! the new (wrong) output against itself. Comparing against frozen bytes
//! is what makes this a *regression* guard rather than a tautology.
//!
//! This is also the cross-language contract surface: per addendum §5.5,
//! "a future implementation in another language is supported only after
//! passing the same conformance corpus" — these files are that corpus's
//! first slice.
//!
//! To regenerate a fixture deliberately (a real, intentional wire-format
//! version bump — not a routine change), run:
//! `UFFS_REGENERATE_FIXTURES=1 cargo test -p uffs-content-protocol --test
//! golden_fixtures -- --ignored --nocapture` then inspect the diff before
//! committing it.

// These are `uffs-content-protocol`'s own dependencies, not this test
// binary's — an integration test is a separate compilation unit, so it
// sees them as unused unless a marker import says otherwise. See
// `crates/uffs-daemon/src/lib.rs`'s `use uffs_version as _;` for the same
// pattern.
use bitflags as _;
use blake3 as _;
use proptest as _;
use thiserror as _;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use uffs_content_protocol::codec::Reader;
    use uffs_content_protocol::error::ErrorCode;
    use uffs_content_protocol::frame::{
        ContentChunk, ContentSemantics, DigestAlgorithm, FailedOutcome, FailureStage, FileBegin,
        FileEnd, FileFailed, FrameEnvelope, FrameError, FrameOrdering, FrameType, JobBegin, JobEnd,
        JobStatus, ReadMode, RetryClass,
    };
    use uffs_content_protocol::manifest::{
        AuthorizationMode, CandidateFlags, CandidateRecord, ManifestHeader, ManifestTrailer,
    };
    use uffs_content_protocol::path_encoding::WindowsPath;

    fn fixture_path(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    fn load_fixture(name: &str) -> Vec<u8> {
        fs::read(fixture_path(name)).unwrap_or_else(|err| {
            panic!(
                "missing golden fixture {name}: {err}. Run with \
                 UFFS_REGENERATE_FIXTURES=1 --ignored first."
            )
        })
    }

    /// Writes `bytes` to the fixture path only when explicitly requested
    /// via `UFFS_REGENERATE_FIXTURES=1`. Every call site that uses this
    /// is `#[ignore]`d so a normal `cargo test` run never touches the
    /// fixture files.
    fn regenerate_fixture(name: &str, bytes: &[u8]) {
        assert!(
            std::env::var("UFFS_REGENERATE_FIXTURES").as_deref() == Ok("1"),
            "refusing to write fixture {name}: set UFFS_REGENERATE_FIXTURES=1 to confirm this \
             is an intentional wire-format change"
        );
        fs::write(fixture_path(name), bytes).unwrap_or_else(|err| panic!("writing {name}: {err}"));
    }

    fn sample_manifest_header() -> ManifestHeader {
        ManifestHeader {
            format_version: 2,
            job_id: [0x11_u8; 16],
            source_id: [0x22_u8; 16],
            volume_serial: 0x0102_0304_0506_0708,
            volume_guid: b"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}".to_vec(),
            snapshot_id: b"vss-snapshot-0001".to_vec(),
            snapshot_created_unix_ms: 1_752_000_000_000,
            query_digest: [0x33_u8; 32],
            authorization_mode: AuthorizationMode::AdminExport,
            candidate_count: 3,
            record_section_length: 999,
        }
    }

    fn sample_candidate_record() -> CandidateRecord {
        CandidateRecord {
            candidate_id: 12345,
            file_reference: 0xABCD_EF01_2345_6789,
            logical_size: 4_194_304,
            valid_data_length: 4_194_304,
            mtime_unix_ms: 1_752_000_000_000,
            candidate_flags: CandidateFlags::NONRESIDENT | CandidateFlags::LARGE_FILE,
            path: WindowsPath::from_str_lossless(r"C:\Users\robert\Documents\report-final.docx"),
        }
    }

    const fn sample_manifest_trailer() -> ManifestTrailer {
        ManifestTrailer {
            candidate_count_repeat: 3,
            manifest_digest: [0x44_u8; 32],
        }
    }

    fn sample_job_begin_frame() -> (FrameEnvelope, JobBegin) {
        let envelope = FrameEnvelope {
            protocol_version: 2,
            frame_type: FrameType::JobBegin,
            flags: 0,
            job_id: [0x11_u8; 16],
            frame_sequence: 0,
        };
        let payload = JobBegin {
            job_id: [0x11_u8; 16],
            source_id: [0x22_u8; 16],
            snapshot_id: b"vss-snapshot-0001".to_vec(),
            snapshot_created_at: 1_752_000_000_000,
            manifest_digest: [0x55_u8; 32],
            candidate_count: 3,
            authorization_mode: AuthorizationMode::AdminExport,
            ordering: FrameOrdering::None,
            content_semantics: ContentSemantics::UnnamedLogicalStream,
            digest_algorithm: DigestAlgorithm::Blake3,
            max_chunk_bytes: 1_048_576,
            max_content_delivery_bytes: Some(64 * 1024 * 1024),
        };
        (envelope, payload)
    }

    const fn sample_file_end_success() -> FileEnd {
        FileEnd {
            candidate_id: 12345,
            total_logical_bytes: 4_194_304,
            content_digest: Some([0x66_u8; 32]),
            read_mode: ReadMode::LogicalSnapshot,
            chunk_count: 64,
            elapsed_ms: 250,
            warning_flags: 0,
        }
    }

    const fn sample_file_end_metadata_only() -> FileEnd {
        FileEnd {
            candidate_id: 99999,
            total_logical_bytes: 0,
            content_digest: None,
            read_mode: ReadMode::MetadataOnly,
            chunk_count: 0,
            elapsed_ms: 1,
            warning_flags: 0,
        }
    }

    fn sample_file_failed() -> FileFailed {
        FileFailed {
            candidate_id: 777,
            outcome: FailedOutcome::Retryable,
            failure_stage: FailureStage::Read,
            error_code: ErrorCode::ReadIoTransient,
            os_error_code: Some(-5),
            retry_class: RetryClass::RetrySameJob,
            bytes_emitted_before_failure: 0,
            message: "transient I/O error reading extent".to_owned(),
        }
    }

    fn sample_job_end() -> JobEnd {
        JobEnd {
            candidate_count: 10,
            succeeded_count: 7,
            failed_retryable_count: 1,
            failed_terminal_count: 1,
            deferred_manual_count: 1,
            acknowledged_success_count: 7,
            logical_bytes_succeeded: 100_000_000,
            failure_bucket_id: b"job-0001-failures".to_vec(),
            manifest_digest: [0x77_u8; 32],
            outcome_ledger_digest: [0x88_u8; 32],
            job_status: JobStatus::CompletedWithFailures,
        }
    }

    // ───────────────────────── manifest header ─────────────────────────

    #[test]
    #[ignore = "writes a golden fixture; run with UFFS_REGENERATE_FIXTURES=1 --ignored"]
    fn regenerate_manifest_header_fixture() {
        let bytes = sample_manifest_header().encode().unwrap();
        regenerate_fixture("manifest_header_basic.bin", &bytes);
    }

    #[test]
    fn manifest_header_fixture_decodes_to_expected_values() {
        let bytes = load_fixture("manifest_header_basic.bin");
        let mut reader = Reader::new(&bytes);
        let decoded = ManifestHeader::decode(&mut reader).unwrap();
        assert_eq!(decoded, sample_manifest_header());
        // Also guards encode-side drift: re-encoding the decoded value
        // must reproduce the exact frozen bytes.
        assert_eq!(decoded.encode().unwrap(), bytes);
    }

    // ───────────────────────── candidate record ─────────────────────────

    #[test]
    #[ignore = "writes a golden fixture; run with UFFS_REGENERATE_FIXTURES=1 --ignored"]
    fn regenerate_candidate_record_fixture() {
        let bytes = sample_candidate_record().encode().unwrap();
        regenerate_fixture("candidate_record_basic.bin", &bytes);
    }

    #[test]
    fn candidate_record_fixture_decodes_to_expected_values() {
        let bytes = load_fixture("candidate_record_basic.bin");
        let mut reader = Reader::new(&bytes);
        let decoded = CandidateRecord::decode(&mut reader).unwrap();
        assert_eq!(decoded, sample_candidate_record());
        assert_eq!(decoded.encode().unwrap(), bytes);
    }

    // ───────────────────────── manifest trailer ─────────────────────────

    #[test]
    #[ignore = "writes a golden fixture; run with UFFS_REGENERATE_FIXTURES=1 --ignored"]
    fn regenerate_manifest_trailer_fixture() {
        let bytes = sample_manifest_trailer().encode();
        regenerate_fixture("manifest_trailer_basic.bin", &bytes);
    }

    #[test]
    fn manifest_trailer_fixture_decodes_to_expected_values() {
        let bytes = load_fixture("manifest_trailer_basic.bin");
        let mut reader = Reader::new(&bytes);
        let decoded = ManifestTrailer::decode(&mut reader).unwrap();
        assert_eq!(decoded, sample_manifest_trailer());
        assert_eq!(decoded.encode(), bytes);
    }

    // ───────────────────────── frames: JOB_BEGIN ─────────────────────────

    #[test]
    #[ignore = "writes a golden fixture; run with UFFS_REGENERATE_FIXTURES=1 --ignored"]
    fn regenerate_frame_job_begin_fixture() {
        let (envelope, payload) = sample_job_begin_frame();
        let bytes = envelope.encode(&payload.encode());
        regenerate_fixture("frame_job_begin.bin", &bytes);
    }

    #[test]
    fn frame_job_begin_fixture_decodes_to_expected_values() {
        let bytes = load_fixture("frame_job_begin.bin");
        let mut reader = Reader::new(&bytes);
        let (decoded_envelope, decoded_payload_bytes) =
            FrameEnvelope::decode(&mut reader, 1_000_000).unwrap();
        let (expected_envelope, expected_payload) = sample_job_begin_frame();
        assert_eq!(decoded_envelope, expected_envelope);
        let mut payload_reader = Reader::new(&decoded_payload_bytes);
        let decoded_payload = JobBegin::decode(&mut payload_reader).unwrap();
        assert_eq!(decoded_payload, expected_payload);
    }

    // ───────────────────────── frames: FILE_END (success)
    // ─────────────────────────

    #[test]
    #[ignore = "writes a golden fixture; run with UFFS_REGENERATE_FIXTURES=1 --ignored"]
    fn regenerate_frame_file_end_success_fixture() {
        let payload = sample_file_end_success();
        let envelope = FrameEnvelope {
            protocol_version: 2,
            frame_type: FrameType::FileEnd,
            flags: 0,
            job_id: [0x11_u8; 16],
            frame_sequence: 10,
        };
        let bytes = envelope.encode(&payload.encode());
        regenerate_fixture("frame_file_end_success.bin", &bytes);
    }

    #[test]
    fn frame_file_end_success_fixture_decodes_to_expected_values() {
        let bytes = load_fixture("frame_file_end_success.bin");
        let mut reader = Reader::new(&bytes);
        let (envelope, payload_bytes) = FrameEnvelope::decode(&mut reader, 1_000_000).unwrap();
        assert_eq!(envelope.frame_type, FrameType::FileEnd);
        let mut payload_reader = Reader::new(&payload_bytes);
        let decoded = FileEnd::decode(&mut payload_reader).unwrap();
        assert_eq!(decoded, sample_file_end_success());
        assert!(decoded.content_digest.is_some());
    }

    // ───────────────────────── frames: FILE_END (metadata-only)
    // ─────────────────────────

    #[test]
    #[ignore = "writes a golden fixture; run with UFFS_REGENERATE_FIXTURES=1 --ignored"]
    fn regenerate_frame_file_end_metadata_only_fixture() {
        let payload = sample_file_end_metadata_only();
        let envelope = FrameEnvelope {
            protocol_version: 2,
            frame_type: FrameType::FileEnd,
            flags: 0,
            job_id: [0x11_u8; 16],
            frame_sequence: 11,
        };
        let bytes = envelope.encode(&payload.encode());
        regenerate_fixture("frame_file_end_metadata_only.bin", &bytes);
    }

    #[test]
    fn frame_file_end_metadata_only_fixture_decodes_to_expected_values() {
        // This is the content-delivery-ceiling fixture: a candidate that
        // matched the job's query but exceeded the delivery ceiling, so
        // it has no content body — see frame::ReadMode::MetadataOnly.
        let bytes = load_fixture("frame_file_end_metadata_only.bin");
        let mut reader = Reader::new(&bytes);
        let (_envelope, payload_bytes) = FrameEnvelope::decode(&mut reader, 1_000_000).unwrap();
        let mut payload_reader = Reader::new(&payload_bytes);
        let decoded = FileEnd::decode(&mut payload_reader).unwrap();
        assert_eq!(decoded, sample_file_end_metadata_only());
        assert_eq!(decoded.content_digest, None);
        assert_eq!(decoded.read_mode, ReadMode::MetadataOnly);
        assert_eq!(decoded.chunk_count, 0);
    }

    // ───────────────────────── frames: FILE_FAILED ─────────────────────────

    #[test]
    #[ignore = "writes a golden fixture; run with UFFS_REGENERATE_FIXTURES=1 --ignored"]
    fn regenerate_frame_file_failed_fixture() {
        let payload = sample_file_failed();
        let envelope = FrameEnvelope {
            protocol_version: 2,
            frame_type: FrameType::FileFailed,
            flags: 0,
            job_id: [0x11_u8; 16],
            frame_sequence: 12,
        };
        let bytes = envelope.encode(&payload.encode());
        regenerate_fixture("frame_file_failed.bin", &bytes);
    }

    #[test]
    fn frame_file_failed_fixture_decodes_to_expected_values() {
        let bytes = load_fixture("frame_file_failed.bin");
        let mut reader = Reader::new(&bytes);
        let (_envelope, payload_bytes) = FrameEnvelope::decode(&mut reader, 1_000_000).unwrap();
        let mut payload_reader = Reader::new(&payload_bytes);
        let decoded = FileFailed::decode(&mut payload_reader).unwrap();
        assert_eq!(decoded, sample_file_failed());
    }

    // ───────────────────────── frames: JOB_END ─────────────────────────

    #[test]
    #[ignore = "writes a golden fixture; run with UFFS_REGENERATE_FIXTURES=1 --ignored"]
    fn regenerate_frame_job_end_fixture() {
        let payload = sample_job_end();
        let envelope = FrameEnvelope {
            protocol_version: 2,
            frame_type: FrameType::JobEnd,
            flags: 0,
            job_id: [0x11_u8; 16],
            frame_sequence: 999,
        };
        let bytes = envelope.encode(&payload.encode().unwrap());
        regenerate_fixture("frame_job_end.bin", &bytes);
    }

    #[test]
    fn frame_job_end_fixture_decodes_to_expected_values() {
        let bytes = load_fixture("frame_job_end.bin");
        let mut reader = Reader::new(&bytes);
        let (_envelope, payload_bytes) = FrameEnvelope::decode(&mut reader, 1_000_000).unwrap();
        let mut payload_reader = Reader::new(&payload_bytes);
        let decoded = JobEnd::decode(&mut payload_reader).unwrap();
        assert_eq!(decoded, sample_job_end());
        // Completeness invariant sanity (design-doc §2.2/§21.7).
        assert_eq!(
            decoded.candidate_count,
            decoded.succeeded_count
                + decoded.failed_retryable_count
                + decoded.failed_terminal_count
                + decoded.deferred_manual_count
        );
    }

    // ───────────────────────── job stream (full sequence)
    // ─────────────────────────
    //
    // A recorded frame stream for one representative job, end to end:
    // JOB_BEGIN, then FILE_BEGIN/[CONTENT_CHUNK]*/FILE_END per candidate,
    // then JOB_END — no framing beyond each frame's own envelope, exactly
    // as a consumer sees it over the wire. This is the "replay fixture"
    // a consumer without a Windows/VSS host (e.g. Docenta) can decode
    // against to validate their own decoder end to end, not just against
    // one frame type in isolation. Candidate 1 is an ordinary two-chunk
    // success; candidate 2 exceeds `JOB_BEGIN.max_content_delivery_bytes`
    // and is reported `ReadMode::MetadataOnly`, so this stream also
    // covers that still-recent wire shape in full sequence context.

    const JOB_STREAM_JOB_ID: [u8; 16] = [0xAA_u8; 16];

    const fn job_stream_content() -> &'static [u8] {
        b"hello world"
    }

    fn sample_job_stream_job_begin() -> JobBegin {
        JobBegin {
            job_id: JOB_STREAM_JOB_ID,
            source_id: [0xBB_u8; 16],
            snapshot_id: b"vss-snapshot-job-stream-0001".to_vec(),
            snapshot_created_at: 1_752_100_000_000,
            manifest_digest: [0xCC_u8; 32],
            candidate_count: 2,
            authorization_mode: AuthorizationMode::AdminExport,
            ordering: FrameOrdering::None,
            content_semantics: ContentSemantics::UnnamedLogicalStream,
            digest_algorithm: DigestAlgorithm::Blake3,
            max_chunk_bytes: 1_048_576,
            max_content_delivery_bytes: Some(1024),
        }
    }

    fn sample_job_stream_file_begin_1() -> FileBegin {
        FileBegin {
            candidate_id: 1,
            file_reference: 0x1000_0000_0000_0001,
            path: WindowsPath::from_str_lossless(r"C:\Users\robert\Documents\report.docx"),
            logical_size: 11,
            mtime: 1_752_100_000_000,
            read_mode: ReadMode::LogicalSnapshot,
            attempt_number: 1,
            content_object_id: None,
        }
    }

    fn sample_job_stream_chunk_1a() -> ContentChunk {
        ContentChunk {
            candidate_id: 1,
            chunk_sequence: 0,
            logical_offset: 0,
            logical_length: 6,
            payload: b"hello ".to_vec(),
        }
    }

    fn sample_job_stream_chunk_1b() -> ContentChunk {
        ContentChunk {
            candidate_id: 1,
            chunk_sequence: 1,
            logical_offset: 6,
            logical_length: 5,
            payload: b"world".to_vec(),
        }
    }

    fn sample_job_stream_file_end_1() -> FileEnd {
        FileEnd {
            candidate_id: 1,
            total_logical_bytes: 11,
            content_digest: Some(*blake3::hash(job_stream_content()).as_bytes()),
            read_mode: ReadMode::LogicalSnapshot,
            chunk_count: 2,
            elapsed_ms: 3,
            warning_flags: 0,
        }
    }

    fn sample_job_stream_file_begin_2() -> FileBegin {
        FileBegin {
            candidate_id: 2,
            file_reference: 0x1000_0000_0000_0002,
            path: WindowsPath::from_str_lossless(r"C:\Data\bigfile.bin"),
            logical_size: 10_737_418_240,
            mtime: 1_752_100_000_000,
            read_mode: ReadMode::MetadataOnly,
            attempt_number: 1,
            content_object_id: None,
        }
    }

    const fn sample_job_stream_file_end_2() -> FileEnd {
        FileEnd {
            candidate_id: 2,
            total_logical_bytes: 0,
            content_digest: None,
            read_mode: ReadMode::MetadataOnly,
            chunk_count: 0,
            elapsed_ms: 0,
            warning_flags: 0,
        }
    }

    fn sample_job_stream_job_end() -> JobEnd {
        JobEnd {
            candidate_count: 2,
            succeeded_count: 2,
            failed_retryable_count: 0,
            failed_terminal_count: 0,
            deferred_manual_count: 0,
            acknowledged_success_count: 0,
            logical_bytes_succeeded: 11,
            failure_bucket_id: b"job-stream-0001-failures".to_vec(),
            manifest_digest: [0xCC_u8; 32],
            outcome_ledger_digest: [0xDD_u8; 32],
            job_status: JobStatus::Completed,
        }
    }

    /// Wraps `payload` in a `FrameEnvelope` for the job-stream fixture,
    /// assigning `frame_sequence` in emission order.
    fn job_stream_envelope(frame_type: FrameType, frame_sequence: u64, payload: &[u8]) -> Vec<u8> {
        FrameEnvelope {
            protocol_version: 2,
            frame_type,
            flags: 0,
            job_id: JOB_STREAM_JOB_ID,
            frame_sequence,
        }
        .encode(payload)
    }

    /// Builds the full, ordered byte stream: `JOB_BEGIN`, candidate 1's
    /// `FILE_BEGIN`/two `CONTENT_CHUNK`s/`FILE_END`, candidate 2's
    /// `FILE_BEGIN`/`FILE_END` (metadata-only), then `JOB_END`.
    fn build_job_stream_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(job_stream_envelope(
            FrameType::JobBegin,
            0,
            &sample_job_stream_job_begin().encode(),
        ));
        out.extend(job_stream_envelope(
            FrameType::FileBegin,
            1,
            &sample_job_stream_file_begin_1().encode(),
        ));
        out.extend(job_stream_envelope(
            FrameType::ContentChunk,
            2,
            &sample_job_stream_chunk_1a().encode(),
        ));
        out.extend(job_stream_envelope(
            FrameType::ContentChunk,
            3,
            &sample_job_stream_chunk_1b().encode(),
        ));
        out.extend(job_stream_envelope(
            FrameType::FileEnd,
            4,
            &sample_job_stream_file_end_1().encode(),
        ));
        out.extend(job_stream_envelope(
            FrameType::FileBegin,
            5,
            &sample_job_stream_file_begin_2().encode(),
        ));
        out.extend(job_stream_envelope(
            FrameType::FileEnd,
            6,
            &sample_job_stream_file_end_2().encode(),
        ));
        out.extend(job_stream_envelope(
            FrameType::JobEnd,
            7,
            &sample_job_stream_job_end()
                .encode()
                .unwrap_or_else(|err| panic!("sample_job_stream_job_end must encode: {err}")),
        ));
        out
    }

    #[test]
    #[ignore = "writes a golden fixture; run with UFFS_REGENERATE_FIXTURES=1 --ignored"]
    fn regenerate_job_stream_fixture() {
        regenerate_fixture("job_stream_two_candidates.bin", &build_job_stream_bytes());
    }

    #[test]
    fn job_stream_fixture_decodes_to_expected_full_sequence() {
        let bytes = load_fixture("job_stream_two_candidates.bin");
        let mut reader = Reader::new(&bytes);

        let mut decoded_types = Vec::new();
        let mut total_chunk_bytes = Vec::new();
        let mut file_ends = Vec::new();
        while reader.remaining() > 0 {
            let (envelope, payload) = FrameEnvelope::decode(&mut reader, 1_000_000).unwrap();
            assert_eq!(envelope.job_id, JOB_STREAM_JOB_ID);
            decoded_types.push(envelope.frame_type);

            let mut payload_reader = Reader::new(&payload);
            match envelope.frame_type {
                FrameType::JobBegin => {
                    assert_eq!(
                        JobBegin::decode(&mut payload_reader).unwrap(),
                        sample_job_stream_job_begin()
                    );
                }
                FrameType::ContentChunk => {
                    let chunk = ContentChunk::decode(&mut payload_reader, 1_000_000).unwrap();
                    if chunk.candidate_id == 1 {
                        total_chunk_bytes.extend(chunk.payload);
                    }
                }
                FrameType::FileEnd => {
                    file_ends.push(FileEnd::decode(&mut payload_reader).unwrap());
                }
                FrameType::JobEnd => {
                    assert_eq!(
                        JobEnd::decode(&mut payload_reader).unwrap(),
                        sample_job_stream_job_end()
                    );
                }
                FrameType::FileBegin => {
                    // Decoded via the per-candidate assertions below.
                }
                other @ (FrameType::FileFailed
                | FrameType::FileDeferred
                | FrameType::FileAck
                | FrameType::Progress
                | FrameType::Heartbeat
                | FrameType::JobCancel
                | FrameType::WindowUpdate
                | FrameType::JobResume
                | FrameType::JobSubmit) => {
                    panic!("unexpected frame type in job stream: {other:?}")
                }
            }
        }

        assert_eq!(decoded_types, vec![
            FrameType::JobBegin,
            FrameType::FileBegin,
            FrameType::ContentChunk,
            FrameType::ContentChunk,
            FrameType::FileEnd,
            FrameType::FileBegin,
            FrameType::FileEnd,
            FrameType::JobEnd,
        ]);

        // Candidate 1: chunks reassemble to the exact original content,
        // and the digest FILE_END reports matches an independent BLAKE3
        // recomputation over those reassembled bytes.
        assert_eq!(total_chunk_bytes, job_stream_content());
        assert_eq!(file_ends.len(), 2);
        let candidate_1_end = file_ends
            .iter()
            .find(|end| end.candidate_id == 1)
            .expect("candidate 1's FILE_END must be present");
        assert_eq!(candidate_1_end, &sample_job_stream_file_end_1());
        assert_eq!(
            candidate_1_end.content_digest,
            Some(*blake3::hash(&total_chunk_bytes).as_bytes())
        );

        // Candidate 2: over the delivery ceiling, so metadata-only —
        // matches ReadMode::MetadataOnly's own doc comment (design-doc's
        // two-tier delivery-ceiling model).
        let candidate_2_end = file_ends
            .iter()
            .find(|end| end.candidate_id == 2)
            .expect("candidate 2's FILE_END must be present");
        assert_eq!(candidate_2_end, &sample_job_stream_file_end_2());
        assert_eq!(candidate_2_end.content_digest, None);
        assert_eq!(candidate_2_end.chunk_count, 0);
    }

    // ───────────────────────── invalid fixtures (must be rejected)
    // ─────────────────────────

    #[test]
    #[ignore = "writes a golden fixture; run with UFFS_REGENERATE_FIXTURES=1 --ignored"]
    fn regenerate_corrupt_checksum_fixture() {
        let (envelope, payload) = sample_job_begin_frame();
        let mut bytes = envelope.encode(&payload.encode());
        let last = bytes.len() - 1;
        if let Some(byte) = bytes.get_mut(last) {
            *byte ^= 0xFF;
        }
        regenerate_fixture("frame_corrupt_checksum.bin", &bytes);
    }

    #[test]
    fn corrupt_checksum_fixture_is_rejected() {
        let bytes = load_fixture("frame_corrupt_checksum.bin");
        let mut reader = Reader::new(&bytes);
        let err = FrameEnvelope::decode(&mut reader, 1_000_000).unwrap_err();
        assert!(matches!(err, FrameError::PayloadChecksumMismatch { .. }));
    }

    #[test]
    #[ignore = "writes a golden fixture; run with UFFS_REGENERATE_FIXTURES=1 --ignored"]
    fn regenerate_truncated_frame_fixture() {
        let (envelope, payload) = sample_job_begin_frame();
        let bytes = envelope.encode(&payload.encode());
        // Truncate to just past the fixed header, before any checksum or
        // payload bytes are fully present.
        let truncated = bytes.get(0..30).unwrap_or(&bytes).to_vec();
        regenerate_fixture("frame_truncated.bin", &truncated);
    }

    #[test]
    fn truncated_frame_fixture_is_rejected() {
        let bytes = load_fixture("frame_truncated.bin");
        let mut reader = Reader::new(&bytes);
        let err = FrameEnvelope::decode(&mut reader, 1_000_000).unwrap_err();
        assert!(matches!(err, FrameError::Decode(_)));
    }
}
