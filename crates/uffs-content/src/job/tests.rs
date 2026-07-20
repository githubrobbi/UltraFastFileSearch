// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit tests for job intake, candidate/content sources, manifest
//! building, and the end-to-end workflow. The full directory-walk
//! parity check against an independent oracle lives in
//! `crates/uffs-content/tests/e2e_dir_walk_parity_fake_reader.rs` — these
//! tests instead cover this module's own internals in isolation.

use alloc::sync::Arc;
use core::time::Duration;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use uffs_content_protocol::codec::Reader;
use uffs_content_protocol::frame::{
    ContentChunk, FileBegin, FileEnd, FrameEnvelope, FrameType, ReadMode,
};
use uffs_content_protocol::manifest::{CandidateRecord, ManifestHeader, ManifestTrailer};

use super::candidate_source::{CandidateEntry, CandidateSource, DirWalkCandidateSource};
use super::content_source::{ContentSource, FsContentSource, ReadSession};
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
        PathBuf::from("a.txt"),
        PathBuf::from("nested/b.txt"),
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

    let mut session = FsContentSource
        .begin_read(entry, 0)
        .expect("begin_read must succeed");

    let first_half = session.read_at(0, 5).expect("read first half");
    assert_eq!(first_half, b"01234");

    let second_half = session.read_at(5, 5).expect("read second half");
    assert_eq!(second_half, b"56789");

    let past_eof = session
        .read_at(10, 5)
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
        // >1 so this test also exercises the sliding-window concurrent-
        // read path (`read_lease_run_pipelined`), not just the fully-
        // sequential (`concurrency == 1`) case.
        &ReadConcurrency::flat(4),
        &[],
        0,
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

#[test]
fn a_run_larger_than_the_credit_window_still_completes_correctly() {
    let source_dir = tempfile::tempdir().expect("create source temp dir");
    // concurrency 2 -> credit_window = 2 * 4 = 8 (see pipeline::
    // read_lease_run_pipelined), so a run of 40 files forces the feeder
    // to actually exhaust and wait on credits several times over, not
    // just exercise the never-full-window happy path every other test
    // in this file takes.
    let file_count: u64 = 40;
    for index in 0..file_count {
        fs::write(
            source_dir.path().join(format!("file_{index:03}.txt")),
            format!("content for file {index}").into_bytes(),
        )
        .expect("write fixture file");
    }

    let run_dir = tempfile::tempdir().expect("create run temp dir");
    let request = JobRequest {
        source_id: "credit-window-source".to_owned(),
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
        &ReadConcurrency::flat(2),
        &[],
        0,
        |frame| {
            frames.push(frame);
            Ok(())
        },
    )
    .expect("run_job must succeed");

    assert_eq!(outcome.run_summary.candidate_count, file_count);
    assert_eq!(outcome.run_summary.succeeded_count, file_count);
    assert_eq!(outcome.run_summary.failed_retryable_count, 0);
    assert_eq!(outcome.run_summary.failed_terminal_count, 0);

    // FILE_END frames must appear in strict, gapless candidate_id order
    // -- confirms the credit-window backpressure never disturbs the
    // pipeline's strict-order emission guarantee, even when the feeder
    // is repeatedly forced to block waiting for a credit.
    let mut file_end_candidate_ids = Vec::new();
    for frame_bytes in &frames {
        let mut reader = Reader::new(frame_bytes);
        let (envelope, payload) =
            FrameEnvelope::decode(&mut reader, u64::MAX).expect("decode frame envelope");
        if envelope.frame_type == FrameType::FileEnd {
            let mut payload_reader = Reader::new(&payload);
            let file_end = FileEnd::decode(&mut payload_reader).expect("decode file end");
            file_end_candidate_ids.push(file_end.candidate_id);
        }
    }
    let expected_ids: Vec<u64> = (1..=file_count).collect();
    assert_eq!(
        file_end_candidate_ids, expected_ids,
        "FILE_END frames must appear in strict candidate_id order even when the run exceeds \
         the credit window"
    );
}

#[test]
fn candidates_over_the_delivery_ceiling_are_reported_metadata_only() {
    let source_dir = tempfile::tempdir().expect("create source temp dir");
    fs::write(source_dir.path().join("small.txt"), b"tiny").expect("write small.txt");
    fs::write(source_dir.path().join("big.bin"), vec![0_u8; 64]).expect("write big.bin");

    let run_dir = tempfile::tempdir().expect("create run temp dir");
    let request = JobRequest {
        source_id: "ceiling-source".to_owned(),
        roots: vec![source_dir.path().to_path_buf()],
        query: "*".to_owned(),
        max_content_delivery_bytes: Some(10),
        ..Default::default()
    };

    let mut frames = Vec::new();
    let outcome = run_job(
        &request,
        &DirWalkCandidateSource,
        &FsContentSource,
        run_dir.path(),
        &ReadConcurrency::flat(2),
        &[],
        0,
        |frame| {
            frames.push(frame);
            Ok(())
        },
    )
    .expect("run_job must succeed");

    assert_eq!(outcome.run_summary.candidate_count, 2);
    assert_eq!(outcome.run_summary.succeeded_count, 2);

    let mut file_ends = Vec::new();
    for frame_bytes in &frames {
        let mut reader = Reader::new(frame_bytes);
        let (envelope, payload) =
            FrameEnvelope::decode(&mut reader, u64::MAX).expect("decode frame envelope");
        if envelope.frame_type == FrameType::FileEnd {
            let mut payload_reader = Reader::new(&payload);
            file_ends.push(FileEnd::decode(&mut payload_reader).expect("decode file end"));
        }
    }
    assert_eq!(file_ends.len(), 2);

    let big_end = file_ends
        .iter()
        .find(|end| end.total_logical_bytes == 0)
        .expect("big file's FILE_END must report zero delivered bytes");
    assert_eq!(big_end.read_mode, ReadMode::MetadataOnly);
    assert!(big_end.content_digest.is_none());
    assert_eq!(big_end.chunk_count, 0);

    let small_end = file_ends
        .iter()
        .find(|end| end.total_logical_bytes == 4)
        .expect("small file's FILE_END must report its actual byte count");
    assert_eq!(small_end.read_mode, ReadMode::LogicalSnapshot);
    assert!(small_end.content_digest.is_some());
}

/// Test-only [`CandidateSource`] that fabricates a fixed small candidate
/// set per root, tagging each with a `snapshot_lease_id` parsed from the
/// root itself (`"lease:<id>"`) — lets a single test drive multiple
/// concurrent lease runs without touching the filesystem or a real VSS
/// snapshot.
struct MultiLeaseCandidateSource {
    /// Candidates to synthesize per lease.
    per_lease: usize,
}

impl CandidateSource for MultiLeaseCandidateSource {
    fn enumerate(&self, root: &Path) -> std::io::Result<Vec<CandidateEntry>> {
        let root_str = root.to_string_lossy();
        let lease_id: u64 = root_str
            .strip_prefix("lease:")
            .and_then(|suffix| suffix.parse().ok())
            .unwrap_or(0);
        Ok((0..self.per_lease)
            .map(|i| {
                let name = format!("file-{lease_id}-{i}.txt");
                CandidateEntry {
                    relative_path: PathBuf::from(&name),
                    absolute_path: PathBuf::from(&name),
                    logical_size: 4,
                    mtime_unix_ms: 0,
                    file_reference: lease_id * 1000 + i as u64,
                    snapshot_lease_id: lease_id,
                }
            })
            .collect())
    }
}

/// Asserts that at least two of `intervals` overlap in wall-clock time —
/// direct proof that two of the recorded operations actually ran at the
/// same time, rather than inferring concurrency from a coarse
/// elapsed-time-vs-threshold check. A fixed millisecond threshold is
/// only ever true *relative to how fast the test machine happens to be
/// that run*; on a loaded/throttled CI runner, `thread::sleep(100ms)`
/// itself can take several hundred milliseconds of wall-clock time
/// (real GitHub-hosted-Windows-runner behavior, not hypothetical — see
/// the `concurrent_lease_runs_...` test's git history), which pushes
/// *both* the sequential and concurrent paths past any fixed absolute
/// threshold and produces a false failure. Two intervals overlapping is
/// true or false independent of how slow the machine is: it only asks
/// whether two things happened during the same stretch of time.
fn assert_any_two_intervals_overlap(intervals: &[(Instant, Instant)], what: &str) {
    for (i, &(a_start, a_end)) in intervals.iter().enumerate() {
        for &(b_start, b_end) in intervals.get(i + 1..).unwrap_or_default() {
            if a_start < b_end && b_start < a_end {
                return;
            }
        }
    }
    panic!("no two {what} intervals overlap in wall-clock time: {intervals:?}");
}

/// Test-only [`ContentSource`] whose every candidate read sleeps
/// `per_candidate_delay` before returning a fixed 4-byte payload —
/// simulates real per-candidate I/O latency without touching a real
/// disk. Records each read's (start, end) so a test can prove two
/// lease runs' reads genuinely overlapped in wall-clock time (see
/// [`assert_any_two_intervals_overlap`]) rather than inferring it from
/// an elapsed-time-vs-threshold check.
struct SlowContentSource {
    /// How long each candidate's one real read takes.
    per_candidate_delay: Duration,
    /// (start, end) of every `read_at` call across every thread. `Arc`
    /// (not a borrow of `&self`) because `ContentSource::begin_read`
    /// returns a `'static` `Box<dyn ReadSession>`.
    intervals: Arc<Mutex<Vec<(Instant, Instant)>>>,
}

impl SlowContentSource {
    fn new(per_candidate_delay: Duration) -> Self {
        Self {
            per_candidate_delay,
            intervals: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl ContentSource for SlowContentSource {
    fn begin_read(
        &self,
        _candidate: &CandidateEntry,
        _candidate_id: u64,
    ) -> std::io::Result<Box<dyn ReadSession>> {
        Ok(Box::new(SlowReadSession {
            delay: self.per_candidate_delay,
            served: false,
            intervals: Arc::clone(&self.intervals),
        }))
    }
}

/// [`SlowContentSource`]'s session: sleeps once, returns 4 bytes, then
/// signals EOF on every subsequent call.
struct SlowReadSession {
    /// How long the one real read takes.
    delay: Duration,
    /// Whether the 4-byte payload has already been served.
    served: bool,
    /// Shared back-reference to record this read's (start, end) into.
    intervals: Arc<Mutex<Vec<(Instant, Instant)>>>,
}

impl ReadSession for SlowReadSession {
    fn read_at(&mut self, _offset: u64, _max_len: u32) -> std::io::Result<Vec<u8>> {
        let start = Instant::now();
        std::thread::sleep(self.delay);
        let end = Instant::now();
        self.intervals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((start, end));
        if self.served {
            return Ok(Vec::new());
        }
        self.served = true;
        Ok(b"data".to_vec())
    }
}

/// Multiple lease runs (drives) must run concurrently, not one fully
/// finishing before the next starts — real-hardware benchmarking found
/// a slow HDD-backed lease holding up every other drive's candidates,
/// including a fast SSD-backed lease sitting idle in queue, even though
/// they share no connection pool or physical device. Proves this two
/// ways: wall-clock time must reflect the *slowest single lease*, not
/// the *sum* of every lease's time, and the emitted frame stream must
/// never let one candidate's frame group be split apart by another's —
/// the one atomicity guarantee concurrent lease runs must still uphold
/// (see `workflow`'s "Concurrent reads, concurrent drives, atomic
/// per-candidate emission" doc section).
#[test]
fn concurrent_lease_runs_actually_overlap_and_never_interleave_a_candidates_frames() {
    const CANDIDATES_PER_LEASE: usize = 3;
    const PER_CANDIDATE_DELAY: Duration = Duration::from_millis(100);

    let run_dir = tempfile::tempdir().expect("create run temp dir");
    let request = JobRequest {
        source_id: "test-source".to_owned(),
        roots: vec![PathBuf::from("lease:1"), PathBuf::from("lease:2")],
        query: "*".to_owned(),
        ..Default::default()
    };

    let candidate_source = MultiLeaseCandidateSource {
        per_lease: CANDIDATES_PER_LEASE,
    };
    let content_source = SlowContentSource::new(PER_CANDIDATE_DELAY);

    let mut frames = Vec::new();
    let outcome = run_job(
        &request,
        &candidate_source,
        &content_source,
        run_dir.path(),
        &ReadConcurrency::flat(1),
        &[],
        0,
        |frame| {
            frames.push(frame);
            Ok(())
        },
    )
    .expect("run_job must succeed");

    let total_candidates = 2 * CANDIDATES_PER_LEASE;
    assert_eq!(outcome.run_summary.candidate_count, total_candidates as u64);
    assert_eq!(outcome.run_summary.succeeded_count, total_candidates as u64);
    assert_eq!(outcome.run_summary.failed_retryable_count, 0);

    // Direct proof of concurrency: two different leases' reads must
    // genuinely overlap in wall-clock time (each lease runs its
    // CANDIDATES_PER_LEASE reads sequentially within itself, at
    // concurrency = 1, so an overlap can only come from two *different*
    // leases' single-connection reads proceeding at the same time).
    let intervals = content_source
        .intervals
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_any_two_intervals_overlap(&intervals, "lease-run read_at");

    // Correctness: decode every frame in emission order and confirm no
    // candidate's frame group (FILE_BEGIN..FILE_END) is ever split apart
    // by another candidate's frames -- the one atomicity guarantee that
    // must hold regardless of how many lease runs execute concurrently.
    let mut open_candidate: Option<u64> = None;
    for frame_bytes in &frames {
        let mut reader = Reader::new(frame_bytes);
        let Ok((envelope, payload)) = FrameEnvelope::decode(&mut reader, u64::MAX) else {
            panic!("every emitted frame must decode");
        };
        match envelope.frame_type {
            FrameType::FileBegin => {
                assert_eq!(
                    open_candidate, None,
                    "a new FILE_BEGIN must never arrive while another candidate is still open"
                );
                let file_begin = FileBegin::decode(&mut Reader::new(&payload))
                    .expect("decode FILE_BEGIN payload");
                open_candidate = Some(file_begin.candidate_id);
            }
            FrameType::ContentChunk => {
                let chunk = ContentChunk::decode(&mut Reader::new(&payload), u32::MAX)
                    .expect("decode CONTENT_CHUNK payload");
                assert_eq!(
                    open_candidate,
                    Some(chunk.candidate_id),
                    "a CONTENT_CHUNK must belong to the currently-open candidate"
                );
            }
            FrameType::FileEnd => {
                let file_end =
                    FileEnd::decode(&mut Reader::new(&payload)).expect("decode FILE_END payload");
                assert_eq!(
                    open_candidate,
                    Some(file_end.candidate_id),
                    "FILE_END must close the currently-open candidate"
                );
                open_candidate = None;
            }
            FrameType::JobBegin | FrameType::JobEnd => {}
            other @ (FrameType::FileFailed
            | FrameType::FileDeferred
            | FrameType::FileAck
            | FrameType::Progress
            | FrameType::Heartbeat
            | FrameType::JobCancel
            | FrameType::WindowUpdate
            | FrameType::JobResume
            | FrameType::JobSubmit) => {
                panic!("unexpected frame type in this test's stream: {other:?}")
            }
        }
    }
    assert_eq!(
        open_candidate, None,
        "every candidate must be closed by the end of the stream"
    );
}

/// Test-only [`CandidateSource`] whose every `enumerate` call sleeps
/// `per_root_delay` before returning one fixed candidate for `root` —
/// simulates real per-root search latency (a synchronous round trip to
/// the daemon) without touching a real daemon. Records each call's
/// (start, end) so a test can prove two roots' enumeration genuinely
/// overlapped in wall-clock time (see
/// [`assert_any_two_intervals_overlap`]) rather than inferring it from
/// an elapsed-time-vs-threshold check.
struct SlowEnumerateCandidateSource {
    /// How long each root's `enumerate` call takes.
    per_root_delay: Duration,
    /// (start, end) of every `enumerate` call across every thread.
    intervals: Mutex<Vec<(Instant, Instant)>>,
}

impl SlowEnumerateCandidateSource {
    fn new(per_root_delay: Duration) -> Self {
        Self {
            per_root_delay,
            intervals: Mutex::new(Vec::new()),
        }
    }
}

impl CandidateSource for SlowEnumerateCandidateSource {
    fn enumerate(&self, root: &Path) -> std::io::Result<Vec<CandidateEntry>> {
        let start = Instant::now();
        std::thread::sleep(self.per_root_delay);
        let end = Instant::now();
        self.intervals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((start, end));
        let root_str = root.to_string_lossy();
        let root_index: u64 = root_str
            .strip_prefix("root:")
            .and_then(|suffix| suffix.parse().ok())
            .unwrap_or(0);
        let name = format!("file-{root_index}.txt");
        Ok(vec![CandidateEntry {
            relative_path: PathBuf::from(&name),
            absolute_path: PathBuf::from(&name),
            logical_size: 4,
            mtime_unix_ms: 0,
            file_reference: root_index,
            snapshot_lease_id: 0,
        }])
    }
}

/// Enumerating multiple roots must run concurrently, not one root's
/// whole search-and-collect cycle blocking the next — real-hardware
/// benchmarking found a two-drive job's enumeration costing ~15s + ~13s
/// back to back (~28s total) even though each root's `enumerate` call
/// opens its own independent connection to the daemon and shares no
/// mutable state with any other call (see
/// `workflow::enumerate_all_roots_concurrently`'s own doc comment).
#[test]
fn root_enumeration_actually_overlaps_across_roots() {
    const ROOT_COUNT: usize = 4;
    const PER_ROOT_DELAY: Duration = Duration::from_millis(100);

    let run_dir = tempfile::tempdir().expect("create run temp dir");
    let roots: Vec<PathBuf> = (0..ROOT_COUNT)
        .map(|i| PathBuf::from(format!("root:{i}")))
        .collect();
    let request = JobRequest {
        source_id: "test-source".to_owned(),
        roots,
        query: "*".to_owned(),
        ..Default::default()
    };

    let candidate_source = SlowEnumerateCandidateSource::new(PER_ROOT_DELAY);
    let content_source = SlowContentSource::new(Duration::ZERO);

    let outcome = run_job(
        &request,
        &candidate_source,
        &content_source,
        run_dir.path(),
        &ReadConcurrency::flat(1),
        &[],
        0,
        |_frame| Ok(()),
    )
    .expect("run_job must succeed");

    assert_eq!(outcome.run_summary.candidate_count, ROOT_COUNT as u64);
    assert_eq!(outcome.run_summary.succeeded_count, ROOT_COUNT as u64);
    assert_eq!(outcome.run_summary.failed_retryable_count, 0);

    // Direct proof of concurrency: two different roots' `enumerate`
    // calls must genuinely overlap in wall-clock time.
    let intervals = candidate_source
        .intervals
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_any_two_intervals_overlap(&intervals, "root enumeration");
}
