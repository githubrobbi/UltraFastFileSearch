// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit tests for job intake, candidate/content sources, manifest
//! building, and the end-to-end workflow. The full directory-walk
//! parity check against an independent oracle lives in
//! `crates/uffs-content/tests/e2e_dir_walk_parity_fake_reader.rs` — these
//! tests instead cover this module's own internals in isolation.

use std::fs;

use uffs_content_protocol::codec::Reader;
use uffs_content_protocol::frame::{FrameEnvelope, FrameType};
use uffs_content_protocol::manifest::{CandidateRecord, ManifestHeader, ManifestTrailer};

use super::candidate_source::{CandidateSource as _, DirWalkCandidateSource};
use super::content_source::{ContentSource as _, FsContentSource};
use super::intake::JobRequest;
use super::manifest_builder::build_manifest;
use super::workflow::{ReadConcurrency, run_job};

#[test]
fn dir_walk_candidate_source_enumerates_files_not_directories() {
    let dir = tempfile::tempdir().expect("create temp dir");
    fs::create_dir_all(dir.path().join("nested")).expect("create nested dir");
    fs::write(dir.path().join("a.txt"), b"a").expect("write a.txt");
    fs::write(dir.path().join("nested/b.txt"), b"bb").expect("write nested/b.txt");

    let entries = DirWalkCandidateSource
        .enumerate(dir.path())
        .expect("enumerate must succeed");

    let mut relative_paths: Vec<_> = entries
        .iter()
        .map(|entry| entry.relative_path.clone())
        .collect();
    relative_paths.sort();
    assert_eq!(relative_paths, vec![
        std::path::PathBuf::from("a.txt"),
        std::path::PathBuf::from("nested/b.txt"),
    ]);
}

#[test]
fn dir_walk_candidate_source_gives_hard_links_the_same_file_reference() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let original = dir.path().join("original.txt");
    let linked = dir.path().join("linked.txt");
    fs::write(&original, b"shared content").expect("write original");
    fs::hard_link(&original, &linked).expect("create hard link");

    let entries = DirWalkCandidateSource
        .enumerate(dir.path())
        .expect("enumerate must succeed");
    assert_eq!(entries.len(), 2);

    let mut file_references: Vec<u64> = entries.iter().map(|entry| entry.file_reference).collect();
    file_references.sort_unstable();
    let [first, second] = file_references.as_slice() else {
        panic!("expected exactly two entries");
    };
    assert_eq!(
        first, second,
        "two directory entries for the same inode must share file_reference"
    );
}

#[test]
fn fs_content_source_reads_bounded_ranges_and_reports_eof() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("data.bin");
    fs::write(&path, b"0123456789").expect("write data.bin");

    let entries = DirWalkCandidateSource
        .enumerate(dir.path())
        .expect("enumerate must succeed");
    let entry = entries.first().expect("one entry expected");

    let first_half = FsContentSource
        .read_at(entry, 0, 0, 5)
        .expect("read first half");
    assert_eq!(first_half, b"01234");

    let second_half = FsContentSource
        .read_at(entry, 0, 5, 5)
        .expect("read second half");
    assert_eq!(second_half, b"56789");

    let past_eof = FsContentSource
        .read_at(entry, 0, 10, 5)
        .expect("read past EOF must not error");
    assert!(past_eof.is_empty(), "read at EOF must return no bytes");
}

#[test]
fn build_manifest_round_trips_through_the_wire_codec() {
    let dir = tempfile::tempdir().expect("create temp dir");
    fs::write(dir.path().join("one.txt"), b"one").expect("write one.txt");
    fs::write(dir.path().join("two.txt"), b"two!!").expect("write two.txt");
    let entries = DirWalkCandidateSource
        .enumerate(dir.path())
        .expect("enumerate must succeed");

    let built = build_manifest([1_u8; 16], [2_u8; 16], [3_u8; 32], &entries)
        .expect("build_manifest must succeed");
    assert_eq!(built.candidate_ids.len(), entries.len());

    let mut reader = Reader::new(&built.bytes);
    let header = ManifestHeader::decode(&mut reader).expect("decode header");
    assert_eq!(header.candidate_count, entries.len() as u64);

    let mut decoded_records = Vec::new();
    for _ in 0..header.candidate_count {
        decoded_records.push(CandidateRecord::decode(&mut reader).expect("decode record"));
    }
    let trailer = ManifestTrailer::decode(&mut reader).expect("decode trailer");
    assert_eq!(reader.remaining(), 0, "trailer must be the last thing");
    assert_eq!(trailer.manifest_digest, built.manifest_digest);

    let mut decoded_ids: Vec<u64> = decoded_records
        .iter()
        .map(|record| record.candidate_id)
        .collect();
    decoded_ids.sort_unstable();
    let mut expected_ids = built.candidate_ids.clone();
    expected_ids.sort_unstable();
    assert_eq!(decoded_ids, expected_ids);
}

#[test]
fn run_job_produces_a_well_formed_frame_sequence_with_no_failures() {
    let source_dir = tempfile::tempdir().expect("create source temp dir");
    fs::write(source_dir.path().join("hello.txt"), b"hello world").expect("write hello.txt");
    fs::create_dir_all(source_dir.path().join("sub")).expect("create sub dir");
    fs::write(source_dir.path().join("sub/empty.txt"), b"").expect("write empty.txt");

    let run_dir = tempfile::tempdir().expect("create run temp dir");
    let request = JobRequest {
        source_id: "test-source".to_owned(),
        roots: vec![source_dir.path().to_path_buf()],
        query: "*".to_owned(),
        ..Default::default()
    };

    let mut frames = Vec::new();
    let outcome = run_job(
        &request,
        &DirWalkCandidateSource,
        &FsContentSource,
        run_dir.path(),
        // >1 so this test also exercises the concurrent-read batching
        // path (`read_candidate_batch`), not just the fully-sequential
        // (`concurrency == 1`) case.
        &ReadConcurrency::flat(4),
        |frame| {
            frames.push(frame);
            Ok(())
        },
    )
    .expect("run_job must succeed");

    assert_eq!(outcome.run_summary.candidate_count, 2);
    assert_eq!(outcome.run_summary.succeeded_count, 2);
    assert_eq!(outcome.run_summary.failed_retryable_count, 0);
    assert_eq!(outcome.run_summary.failed_terminal_count, 0);
    assert_eq!(outcome.run_summary.deferred_manual_count, 0);
    assert_eq!(outcome.run_summary.logical_bytes_succeeded, 11);

    // Decode every emitted frame and assert the expected type sequence:
    // JOB_BEGIN, then (FILE_BEGIN, [CONTENT_CHUNK]*, FILE_END) per
    // candidate, then JOB_END.
    let mut decoded_types = Vec::new();
    for frame_bytes in &frames {
        let mut reader = Reader::new(frame_bytes);
        let (envelope, _payload) =
            FrameEnvelope::decode(&mut reader, u64::MAX).expect("decode frame envelope");
        assert_eq!(envelope.job_id, outcome.job_id);
        decoded_types.push(envelope.frame_type);
    }

    assert_eq!(decoded_types.first(), Some(&FrameType::JobBegin));
    assert_eq!(decoded_types.last(), Some(&FrameType::JobEnd));
    let file_end_count = decoded_types
        .iter()
        .filter(|frame_type| **frame_type == FrameType::FileEnd)
        .count();
    assert_eq!(file_end_count, 2, "both candidates must reach FILE_END");
}
