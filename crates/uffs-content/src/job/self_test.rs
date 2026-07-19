// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Elevated smoke test: real VSS snapshot + real privileged Reader,
//! creating a unique sample file and proving playback through
//! [`super::vss_job::run_vss_job`] reproduces its content exactly.
//!
//! Mirrors `uffs-broker`'s own `--self-test-vss` design
//! (`crates/uffs-broker/src/broker.rs`/`broker/snapshot_manager/
//! vss_self_test.rs`): the round-trip logic lives once, here, in
//! production code — reused by both the `--self-test-vss-playback` CLI
//! flag (`main.rs`) and `cargo test -p uffs-content -- --ignored`
//! (`tests/e2e_real_vss_content_reader.rs`), so none of the three ever
//! drift apart.

use std::path::Path;

use anyhow::{Context as _, Result};
use uffs_content_protocol::codec::Reader as WireReader;
use uffs_content_protocol::frame::{ContentChunk, FileEnd, FrameEnvelope, FrameType};
use uffs_content_protocol::manifest::{CandidateRecord, ManifestHeader};

use super::intake::JobRequest;
use super::vss_job::run_vss_job;

/// Run the real create-snapshot -> select-target -> read-content round trip.
///
/// Uses a freshly created, uniquely-named sample file under `test_dir`,
/// and verifies the streamed bytes exactly match what was written.
///
/// # Errors
/// Returns an error if the sample file can't be created, `run_vss_job`
/// fails, the job doesn't find exactly the one sample file, or the
/// played-back content doesn't match what was written.
pub fn self_test_vss_playback(test_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(test_dir)
        .with_context(|| format!("failed to create test dir {}", test_dir.display()))?;

    let unique_name = format!(
        "uffs-content-self-test-{}.txt",
        uuid::Uuid::new_v4().simple()
    );
    let content =
        b"UFFS content-reader self-test: real VSS snapshot + real Reader playback.\n".as_slice();
    let sample_path = test_dir.join(&unique_name);
    std::fs::write(&sample_path, content)
        .with_context(|| format!("failed to write sample file {}", sample_path.display()))?;

    let run_dir = test_dir.join("run");
    std::fs::create_dir_all(&run_dir)
        .with_context(|| format!("failed to create run dir {}", run_dir.display()))?;

    let request = JobRequest {
        source_id: "uffs-content-self-test".to_owned(),
        roots: vec![test_dir.to_path_buf()],
        query: unique_name,
        ..Default::default()
    };

    let mut frames = Vec::new();
    let outcome = run_vss_job(&request, &run_dir, |frame| {
        frames.push(frame);
        Ok(())
    })
    .context("run_vss_job failed")?;

    anyhow::ensure!(
        outcome.run_summary.candidate_count == 1,
        "expected exactly 1 candidate (the unique sample file), found {}",
        outcome.run_summary.candidate_count
    );
    anyhow::ensure!(
        outcome.run_summary.succeeded_count == 1,
        "expected the sample file to succeed, got {} succeeded / {} failed-retryable / {} \
         failed-terminal / {} deferred",
        outcome.run_summary.succeeded_count,
        outcome.run_summary.failed_retryable_count,
        outcome.run_summary.failed_terminal_count,
        outcome.run_summary.deferred_manual_count
    );

    let played_back = decode_single_file_content(&outcome.manifest_bytes, &frames)
        .context("failed to decode the job's own manifest/frame output")?;
    anyhow::ensure!(
        played_back == content,
        "playback content does not match the original sample file (got {} bytes, expected {})",
        played_back.len(),
        content.len()
    );

    Ok(())
}

/// Run a real, extension-filtered query against an existing directory and
/// verify the pipeline's reported metadata/content totals against ground
/// truth.
///
/// Runs against a real drive with real files already on it — not a
/// synthetic sample. Unlike [`self_test_vss_playback`] (one synthetic
/// file, content-only),
/// this validates the pipeline against however many real files of
/// `extension` already exist under `root`: every candidate must succeed,
/// the candidate count must match the ground-truth walk's file count, the
/// manifest's own `logical_size` fields must sum to the ground-truth
/// total, and the bytes actually streamed over `CONTENT_CHUNK` frames
/// must also sum to that same total. Ground truth comes from
/// `walk_tolerating_denied` — a permissive `std::fs` walker reading the
/// **live** volume rather than the job's VSS snapshot; on a quiescent
/// drive the two are expected to match exactly.
///
/// # Errors
/// Returns an error if the ground-truth walk finds no matching files,
/// `run_vss_job` fails, any candidate doesn't succeed, or any of the
/// three totals (candidate count, manifest metadata bytes, streamed
/// content bytes) disagrees with ground truth.
pub fn self_test_vss_query_metadata(root: &Path, extension: &str) -> Result<()> {
    let (ground_truth_count, ground_truth_bytes, skipped_dirs, ground_truth_paths) =
        ground_truth_extension_totals(root, extension);
    if !skipped_dirs.is_empty() {
        tracing::warn!(
            skipped_count = skipped_dirs.len(),
            skipped = ?skipped_dirs,
            "ground-truth walk skipped {} inaccessible director{} (e.g. OS-reserved \
             folders) — the real MFT-based query engine reads these regardless, so a \
             mismatch caused by this is a ground-truth walker limitation, not a pipeline bug",
            skipped_dirs.len(),
            if skipped_dirs.len() == 1 { "y" } else { "ies" }
        );
    }
    anyhow::ensure!(
        ground_truth_count > 0,
        "no *.{extension} files found under {} — nothing to validate",
        root.display()
    );

    let run_dir = std::env::temp_dir().join(format!(
        "uffs-content-query-metadata-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&run_dir)
        .with_context(|| format!("failed to create run dir {}", run_dir.display()))?;

    let request = JobRequest {
        source_id: "uffs-content-self-test-query".to_owned(),
        roots: vec![root.to_path_buf()],
        query: "*".to_owned(),
        ext: Some(extension.to_owned()),
        ..Default::default()
    };

    let mut frames = Vec::new();
    let outcome = run_vss_job(&request, &run_dir, |frame| {
        frames.push(frame);
        Ok(())
    })
    .context("run_vss_job failed")?;

    if outcome.run_summary.candidate_count != ground_truth_count {
        let pipeline_paths = decode_candidate_paths(&outcome.manifest_bytes, root)
            .context("failed to decode candidate paths for mismatch diagnostics")?;
        anyhow::bail!(
            "candidate count mismatch: pipeline found {}, ground-truth disk walk found {}\n\
             (path, pipeline_count, ground_truth_count) for every differing path:\n{:#?}",
            outcome.run_summary.candidate_count,
            ground_truth_count,
            count_mismatches(&pipeline_paths, &ground_truth_paths),
        );
    }
    anyhow::ensure!(
        outcome.run_summary.succeeded_count == outcome.run_summary.candidate_count,
        "not every candidate succeeded: {} of {} (failed-retryable={}, failed-terminal={}, \
         deferred={})",
        outcome.run_summary.succeeded_count,
        outcome.run_summary.candidate_count,
        outcome.run_summary.failed_retryable_count,
        outcome.run_summary.failed_terminal_count,
        outcome.run_summary.deferred_manual_count
    );

    let summary = summarize_query_outcome(&outcome.manifest_bytes, &frames)
        .context("failed to decode the job's own manifest/frame output")?;
    anyhow::ensure!(
        summary.metadata_total_bytes == ground_truth_bytes,
        "manifest metadata size total mismatch: pipeline reported {} bytes, ground-truth {} bytes",
        summary.metadata_total_bytes,
        ground_truth_bytes
    );
    anyhow::ensure!(
        summary.content_total_bytes == ground_truth_bytes,
        "streamed content byte total mismatch: pipeline streamed {} bytes, ground-truth {} bytes",
        summary.content_total_bytes,
        ground_truth_bytes
    );

    Ok(())
}

/// One [`self_test_reader_benchmark`] run's measured results.
#[derive(Debug, Clone, Copy)]
pub struct ReaderBenchmarkReport {
    /// Total candidates the manifest committed to.
    pub candidate_count: u64,
    /// Candidates that reached a successful terminal outcome.
    pub succeeded_count: u64,
    /// Sum of every `CONTENT_CHUNK.payload.len()` actually streamed.
    pub content_bytes: u64,
    /// Wall-clock time from job start to the first `CONTENT_CHUNK` frame:
    /// VSS lease + ephemeral daemon spawn + enumeration + manifest
    /// finalization, milliseconds.
    pub enumeration_ms: u128,
    /// Wall-clock time from the first `CONTENT_CHUNK` frame to the job
    /// finishing — the number this benchmark exists to measure,
    /// milliseconds.
    pub content_read_ms: u128,
    /// `content_bytes` / `content_read_ms`, in MiB/s. `0.0` if
    /// `content_read_ms` is `0` (nothing to divide by — e.g. a job with
    /// no content-bearing candidates).
    pub throughput_mib_per_sec: f64,
}

/// Run a real VSS-backed job against `roots` (empty = every local NTFS
/// drive — see [`super::vss_job::run_vss_job`]) evaluating `query`, and
/// report content-read wall-clock time and throughput.
///
/// This is the baseline-measurement tool for judging Reader-parallelism
/// work (see the local-only content-engine architecture doc): it
/// deliberately isolates the *content-read phase* from VSS-lease/
/// ephemeral-daemon/enumeration overhead by using `emit_frame` itself as
/// the observation point — the moment the first `CONTENT_CHUNK` frame
/// arrives marks the enumeration/content-read phase boundary — rather
/// than adding timing instrumentation to `run_job`/`workflow` itself.
///
/// # Errors
/// Returns an error if the run directory can't be created or
/// `run_vss_job` fails.
pub fn self_test_reader_benchmark(
    roots: &[std::path::PathBuf],
    query: &str,
) -> Result<ReaderBenchmarkReport> {
    let run_dir = std::env::temp_dir().join(format!(
        "uffs-content-reader-benchmark-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&run_dir)
        .with_context(|| format!("failed to create run dir {}", run_dir.display()))?;

    let request = JobRequest {
        source_id: "uffs-content-reader-benchmark".to_owned(),
        roots: roots.to_vec(),
        query: query.to_owned(),
        ..Default::default()
    };

    let start = std::time::Instant::now();
    let mut first_content_chunk_at: Option<std::time::Instant> = None;
    let mut content_bytes: u64 = 0;

    let outcome = run_vss_job(&request, &run_dir, |frame_bytes| {
        let mut reader = WireReader::new(&frame_bytes);
        if let Ok((envelope, payload)) = FrameEnvelope::decode(&mut reader, u64::MAX)
            && envelope.frame_type == FrameType::ContentChunk
        {
            first_content_chunk_at.get_or_insert_with(std::time::Instant::now);
            let mut payload_reader = WireReader::new(&payload);
            if let Ok(chunk) = ContentChunk::decode(&mut payload_reader, u32::MAX) {
                content_bytes += u64::try_from(chunk.payload.len()).unwrap_or(u64::MAX);
            }
        }
        Ok(())
    })
    .context("run_vss_job failed")?;

    let end = std::time::Instant::now();
    let content_start = first_content_chunk_at.unwrap_or(end);
    let enumeration_ms = content_start.duration_since(start).as_millis();
    let content_read_ms = end.duration_since(content_start).as_millis();
    #[expect(
        clippy::cast_precision_loss,
        reason = "diagnostic-only throughput number for a benchmark report, not a value \
                  anything downstream computes against — losing precision above 2^53 bytes \
                  (8+ petabytes) or milliseconds is not a real concern here"
    )]
    #[expect(
        clippy::float_arithmetic,
        reason = "diagnostic-only throughput ratio for a benchmark report — same precision \
                  posture as uffs-daemon's own EMA rate arithmetic (drive_stats.rs)"
    )]
    let throughput_mib_per_sec = if content_read_ms > 0 {
        (content_bytes as f64 / (1_024.0_f64 * 1_024.0_f64))
            / (content_read_ms as f64 / 1_000.0_f64)
    } else {
        0.0_f64
    };

    Ok(ReaderBenchmarkReport {
        candidate_count: outcome.run_summary.candidate_count,
        succeeded_count: outcome.run_summary.succeeded_count,
        content_bytes,
        enumeration_ms,
        content_read_ms,
        throughput_mib_per_sec,
    })
}

/// Independent ground truth for [`self_test_vss_query_metadata`]: walk
/// `root` live via `std::fs` (bypassing VSS/the daemon entirely) and sum
/// the size of every regular file whose extension case-insensitively
/// matches `extension`.
///
/// Deliberately **not** [`super::candidate_source::DirWalkCandidateSource`]
/// (used elsewhere in this crate for synthetic test fixtures, where an
/// access-denied error is itself a bug worth failing loud on): a real,
/// pre-existing drive
/// routinely has OS-reserved, ACL-locked directories (`System Volume
/// Information`, `$RECYCLE.BIN`) that plain `std::fs::read_dir` can't
/// enter but that the real MFT-based query engine reads regardless (it
/// never goes through filesystem permission checks). This walker treats
/// a directory it can't enter as "skip, not fail" and reports how many
/// were skipped, so a real discrepancy is still visible rather than
/// silently swallowed.
///
/// Returns `(matching_file_count, total_logical_bytes, skipped_dirs,
/// matching_paths)`.
fn ground_truth_extension_totals(
    root: &Path,
    extension: &str,
) -> (u64, u64, Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
    let mut count: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut skipped_dirs = Vec::new();
    let mut matching_paths = Vec::new();
    walk_tolerating_denied(
        root,
        extension,
        &mut count,
        &mut total_bytes,
        &mut skipped_dirs,
        &mut matching_paths,
    );
    (count, total_bytes, skipped_dirs, matching_paths)
}

/// Recursive worker for [`ground_truth_extension_totals`]. A directory
/// that can't be listed (permission denied, or any other `read_dir`
/// error) is appended to `skipped_dirs` and skipped, rather than
/// propagated — see that function's doc comment for why.
fn walk_tolerating_denied(
    dir: &Path,
    extension: &str,
    count: &mut u64,
    total_bytes: &mut u64,
    skipped_dirs: &mut Vec<std::path::PathBuf>,
    matching_paths: &mut Vec<std::path::PathBuf>,
) {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        skipped_dirs.push(dir.to_path_buf());
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.is_dir() {
            walk_tolerating_denied(
                &path,
                extension,
                count,
                total_bytes,
                skipped_dirs,
                matching_paths,
            );
        } else if metadata.is_file() {
            let matches = path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case(extension));
            if matches {
                *count += 1;
                *total_bytes += metadata.len();
                matching_paths.push(path);
            }
        }
    }
}

/// Decode every `CandidateRecord::path` out of a manifest, re-joined onto
/// `root` for the candidate-count-mismatch diagnostic in
/// [`self_test_vss_query_metadata`].
///
/// `CandidateRecord::path` is root-relative by design (see
/// `CandidateEntry::relative_path`'s doc comment), while the ground-truth
/// walker's paths are absolute — rejoining here puts both sides in the
/// same representation so the diff isn't swamped by a spurious
/// "every path differs" noise from the root prefix alone.
fn decode_candidate_paths(manifest_bytes: &[u8], root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut manifest_reader = WireReader::new(manifest_bytes);
    let header = ManifestHeader::decode(&mut manifest_reader)
        .map_err(|err| anyhow::anyhow!("decode manifest header: {err}"))?;
    let mut paths = Vec::with_capacity(usize::try_from(header.candidate_count).unwrap_or(0));
    for _ in 0..header.candidate_count {
        let record = CandidateRecord::decode(&mut manifest_reader)
            .map_err(|err| anyhow::anyhow!("decode candidate record: {err}"))?;
        paths.push(root.join(record.path.display_lossy()));
    }
    Ok(paths)
}

/// For every path whose occurrence count differs between `left` and
/// `right`, `(path, left_count, right_count)` — for the candidate-count-
/// mismatch diagnostic in [`self_test_vss_query_metadata`]. Counts a path
/// appearing twice in one side but once in the other (a literal duplicate
/// row), not just paths missing entirely from one side, since that's
/// exactly the shape a merge/dedup bug would produce.
fn count_mismatches(
    left: &[std::path::PathBuf],
    right: &[std::path::PathBuf],
) -> Vec<(std::path::PathBuf, usize, usize)> {
    let mut counts: alloc::collections::BTreeMap<&Path, (usize, usize)> =
        alloc::collections::BTreeMap::new();
    for path in left {
        counts.entry(path.as_path()).or_default().0 += 1;
    }
    for path in right {
        counts.entry(path.as_path()).or_default().1 += 1;
    }
    counts
        .into_iter()
        .filter(|(_, (left_count, right_count))| left_count != right_count)
        .map(|(path, (left_count, right_count))| (path.to_path_buf(), left_count, right_count))
        .collect()
}

/// Aggregate totals decoded from a job's own manifest + frame output, for
/// [`self_test_vss_query_metadata`].
struct QueryOutcomeSummary {
    /// Sum of every `CandidateRecord::logical_size` in the manifest.
    metadata_total_bytes: u64,
    /// Sum of every `CONTENT_CHUNK.payload.len()` actually streamed.
    content_total_bytes: u64,
}

/// Decode a manifest describing `header.candidate_count` candidates plus
/// their frame stream, returning both the manifest's own metadata-size
/// total and the total bytes actually streamed over `CONTENT_CHUNK`
/// frames — the two independent numbers [`self_test_vss_query_metadata`]
/// cross-checks against ground truth.
///
/// Deliberately duplicated from [`decode_single_file_content`] rather than
/// generalizing that one: this decoder sums across an arbitrary number of
/// candidates and never buffers content bytes, while that one is scoped
/// to exactly one candidate and returns its buffered content — different
/// enough shapes that a shared abstraction would obscure both.
fn summarize_query_outcome(
    manifest_bytes: &[u8],
    frames: &[Vec<u8>],
) -> Result<QueryOutcomeSummary> {
    let mut manifest_reader = WireReader::new(manifest_bytes);
    let header = ManifestHeader::decode(&mut manifest_reader)
        .map_err(|err| anyhow::anyhow!("decode manifest header: {err}"))?;

    let mut metadata_total_bytes: u64 = 0;
    for _ in 0..header.candidate_count {
        let record = CandidateRecord::decode(&mut manifest_reader)
            .map_err(|err| anyhow::anyhow!("decode candidate record: {err}"))?;
        metadata_total_bytes += record.logical_size;
    }

    let mut content_total_bytes: u64 = 0;
    for frame_bytes in frames {
        let mut frame_reader = WireReader::new(frame_bytes);
        let (envelope, payload) = FrameEnvelope::decode(&mut frame_reader, u64::MAX)
            .map_err(|err| anyhow::anyhow!("decode frame envelope: {err}"))?;
        if envelope.frame_type != FrameType::ContentChunk {
            continue;
        }
        let mut payload_reader = WireReader::new(&payload);
        let chunk = ContentChunk::decode(&mut payload_reader, u32::MAX)
            .map_err(|err| anyhow::anyhow!("decode CONTENT_CHUNK: {err}"))?;
        content_total_bytes += chunk.payload.len() as u64;
    }

    Ok(QueryOutcomeSummary {
        metadata_total_bytes,
        content_total_bytes,
    })
}

/// Decode a manifest + frame stream that is known to describe exactly
/// one candidate, returning the bytes its `CONTENT_CHUNK` frames
/// carried.
///
/// A narrow, self-test-only decoder — see
/// `tests/support/test_consumer.rs` for the fuller, general-purpose
/// version the parity harness uses; duplicated here (not shared)
/// because this one is production code (compiled into the shipped
/// binary), matching `uffs-content-reader-protocol`'s own "small,
/// independent duplicate" precedent for the same reason.
fn decode_single_file_content(manifest_bytes: &[u8], frames: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut manifest_reader = WireReader::new(manifest_bytes);
    let header = ManifestHeader::decode(&mut manifest_reader)
        .map_err(|err| anyhow::anyhow!("decode manifest header: {err}"))?;
    anyhow::ensure!(
        header.candidate_count == 1,
        "expected exactly 1 candidate in the manifest, found {}",
        header.candidate_count
    );

    let mut buffered = Vec::new();
    let mut saw_file_end = false;
    for frame_bytes in frames {
        let mut frame_reader = WireReader::new(frame_bytes);
        let (envelope, payload) = FrameEnvelope::decode(&mut frame_reader, u64::MAX)
            .map_err(|err| anyhow::anyhow!("decode frame envelope: {err}"))?;
        let mut payload_reader = WireReader::new(&payload);
        match envelope.frame_type {
            FrameType::ContentChunk => {
                let chunk = ContentChunk::decode(&mut payload_reader, u32::MAX)
                    .map_err(|err| anyhow::anyhow!("decode CONTENT_CHUNK: {err}"))?;
                buffered.extend_from_slice(&chunk.payload);
            }
            FrameType::FileEnd => {
                FileEnd::decode(&mut payload_reader)
                    .map_err(|err| anyhow::anyhow!("decode FILE_END: {err}"))?;
                saw_file_end = true;
            }
            FrameType::FileFailed | FrameType::FileDeferred => {
                anyhow::bail!("candidate did not succeed (saw {:?})", envelope.frame_type);
            }
            FrameType::JobBegin
            | FrameType::FileBegin
            | FrameType::FileAck
            | FrameType::Progress
            | FrameType::Heartbeat
            | FrameType::JobEnd
            | FrameType::JobCancel
            | FrameType::WindowUpdate
            | FrameType::JobResume
            | FrameType::JobSubmit => {}
        }
    }
    anyhow::ensure!(
        saw_file_end,
        "never saw a FILE_END frame for the sample file"
    );

    Ok(buffered)
}
