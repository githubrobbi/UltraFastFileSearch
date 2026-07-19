// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Per-candidate, per-lease-run content emission — split out of
//! `workflow` itself purely to stay under this workspace's file-size
//! policy (mirroring `workflow`'s own existing `pipeline` split for the
//! same reason); every item here is still conceptually part of
//! `run_job`'s single content-reading step, just extracted so that one
//! file doesn't hold both the top-level job orchestration and the
//! concurrency machinery beneath it.
//!
//! See `super`'s "Concurrent reads, concurrent drives, atomic
//! per-candidate emission" doc section for why [`EmitState`]'s mutex
//! exists and what atomicity it's protecting.

use std::io;

use uffs_content_protocol::error::ErrorCode;
use uffs_content_protocol::frame::{
    FailedOutcome, FailureStage, FileBegin, FileEnd, FileFailed, FrameType, ReadMode, RetryClass,
};
use uffs_content_protocol::path_encoding::WindowsPath;

use super::pipeline::{CandidateContent, lease_runs, read_lease_run_pipelined};
use super::{DEFAULT_MAX_CHUNK_BYTES, ReadConcurrency, encode_frame};
use crate::job::candidate_source::CandidateEntry;
use crate::job::content_source::ContentSource;
use crate::run::{FailureLogWriter, FailureRecord, RunCounters};

/// Read and emit every candidate's content, one [`read_lease_run_pipelined`]
/// call per contiguous [`lease_runs`] group. Extracted from
/// `super::run_job` itself so that function stays under the workspace's
/// `too_many_lines` budget — every parameter here is `run_job`'s own
/// local state, threaded through unchanged.
///
/// # Errors
/// Propagates the first error from enumerating a lease run's content or
/// from `emit_frame` itself, exactly as `run_job`'s own doc comment
/// describes.
#[expect(
    clippy::too_many_arguments,
    reason = "the alternative is a bespoke context struct bundling counters/failure_log/ \
              frame_sequence/emit_frame purely to satisfy this lint, for a private helper \
              extracted from run_job with exactly one call site; not worth the indirection"
)]
#[expect(
    clippy::significant_drop_tightening,
    reason = "the lock IS the intended critical section, per lease-run closure below: it must \
              stay held for one candidate's whole emission (assembling + writing its frames, \
              updating counters/failure_log/frame_sequence together), not something to shrink \
              -- that's exactly what keeps two drives' candidates from interleaving on the wire"
)]
pub(super) fn read_and_emit_all_candidates<F>(
    candidates: &[(&CandidateEntry, u64)],
    read_concurrency: &ReadConcurrency,
    content_source: &dyn ContentSource,
    max_content_delivery_bytes: Option<u64>,
    job_id: [u8; 16],
    counters: &mut RunCounters,
    failure_log: &mut FailureLogWriter,
    frame_sequence: &mut u64,
    emit_frame: &mut F,
) -> io::Result<()>
where
    F: FnMut(Vec<u8>) -> io::Result<()> + Send,
{
    let total_candidates = candidates.len();
    let run_started_at = std::time::Instant::now();
    let emit_state = std::sync::Mutex::new(EmitState {
        counters,
        failure_log,
        frame_sequence,
        emit_frame,
        emitted_count: 0,
        last_progress_log_at: run_started_at,
        last_progress_log_bytes: 0,
    });

    let runs = lease_runs(candidates);
    let results: Vec<io::Result<()>> = std::thread::scope(|scope| {
        let handles: Vec<_> = runs
            .iter()
            .map(|run| {
                let emit_state_ref = &emit_state;
                scope.spawn(move || {
                    let Some(&(first_entry, _)) = run.first() else {
                        return Ok(());
                    };
                    let concurrency = read_concurrency.for_lease(first_entry.snapshot_lease_id);
                    read_lease_run_pipelined(
                        run,
                        concurrency,
                        content_source,
                        DEFAULT_MAX_CHUNK_BYTES,
                        max_content_delivery_bytes,
                        |index, read_result| {
                            let Some(&(entry, candidate_id)) = run.get(index) else {
                                return Ok(());
                            };
                            let mut guard = emit_state_ref
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            // Explicit reborrow: the guard's `DerefMut` hides
                            // field disjointness from the borrow checker, so
                            // every subsequent access goes through this plain
                            // `&mut EmitState` instead of `guard` directly.
                            let state = &mut *guard;
                            let result = emit_candidate(
                                entry,
                                candidate_id,
                                read_result,
                                state.counters,
                                state.failure_log,
                                job_id,
                                state.frame_sequence,
                                state.emit_frame,
                            );
                            state.emitted_count += 1;
                            log_progress_if_due(
                                state.emitted_count,
                                total_candidates,
                                state.counters,
                                run_started_at,
                                &mut state.last_progress_log_at,
                                &mut state.last_progress_log_bytes,
                            );
                            result
                        },
                    )
                })
            })
            .collect();

        handles
            .into_iter()
            .map(|handle| {
                handle.join().unwrap_or_else(|panic_payload| {
                    Err(io::Error::other(format!(
                        "lease-run thread panicked: {panic_payload:?}"
                    )))
                })
            })
            .collect()
    });

    for result in results {
        result?;
    }
    Ok(())
}

/// Bundles everything one candidate's emission touches — `counters`,
/// `failure_log`, `frame_sequence`, the `emit_frame` callback itself,
/// and the progress-heartbeat state — behind one lock, so concurrently-
/// running lease runs (drives) never interleave two candidates' frame
/// groups on the wire; see `super`'s "Concurrent reads, concurrent
/// drives, atomic per-candidate emission" doc section for why that's
/// exactly the atomicity the protocol requires, no more and no less.
struct EmitState<'a, F> {
    /// Run-wide success/failure/byte counters, updated once per emitted
    /// candidate.
    counters: &'a mut RunCounters,
    /// Append-only failure-record log, written to on a failed candidate.
    failure_log: &'a mut FailureLogWriter,
    /// Next frame's sequence number, advanced by every frame this
    /// candidate emits.
    frame_sequence: &'a mut u64,
    /// The caller-supplied frame sink.
    emit_frame: &'a mut F,
    /// Candidates emitted so far, across every lease run combined.
    emitted_count: usize,
    /// Wall-clock time of the last progress heartbeat.
    last_progress_log_at: std::time::Instant,
    /// `counters.logical_bytes_succeeded` as of the last heartbeat.
    last_progress_log_bytes: u64,
}

/// How often [`read_and_emit_all_candidates`] logs a progress heartbeat,
/// at minimum — never less often than this many wall-clock seconds
/// apart, regardless of candidate count or throughput. Chosen so a job
/// that's silently grinding for a long time (whether genuinely slow or
/// stuck on one candidate — see `pipeline::read_one_candidate`'s own
/// per-candidate stall warning) is never silent for more than about this
/// long between updates.
const PROGRESS_LOG_MIN_INTERVAL: core::time::Duration = core::time::Duration::from_secs(10);

/// Also log a heartbeat every this many candidates, even if
/// [`PROGRESS_LOG_MIN_INTERVAL`] hasn't elapsed — keeps a very fast run
/// (thousands of tiny files) from having its own progress signal
/// throttled down to nothing.
const PROGRESS_LOG_CANDIDATE_STRIDE: usize = 1000;

/// Log an `INFO`-level progress line if either [`PROGRESS_LOG_MIN_INTERVAL`]
/// has elapsed since the last one or `emitted_count` just crossed a
/// [`PROGRESS_LOG_CANDIDATE_STRIDE`] boundary — see `super`'s "Concurrent
/// reads, concurrent drives, atomic per-candidate emission" doc section
/// for why total silence during content reading was a real problem this
/// closes.
///
/// Also reports `mib_per_sec_since_last_heartbeat` and
/// `mib_per_sec_since_job_start`: `logical_bytes_succeeded` only
/// advances as candidates are actually *emitted* — i.e. bytes handed to
/// `emit_frame`, the real wire write in `--serve` mode — so both figures
/// are a direct measurement of consumer-facing pipe throughput, not an
/// internal per-connection or per-drive read rate. Scan
/// `mib_per_sec_since_last_heartbeat` across a run's log for min/max;
/// the last line's `mib_per_sec_since_job_start` is the run's overall
/// average.
#[expect(
    clippy::cast_precision_loss,
    reason = "diagnostic-only throughput figures for a log line, not computed against further \
              — same posture as uffs-content's own benchmark report (self_test.rs)"
)]
#[expect(
    clippy::float_arithmetic,
    reason = "diagnostic-only throughput ratios for a log line, matching self_test.rs's \
              existing benchmark-report precedent"
)]
fn log_progress_if_due(
    emitted_count: usize,
    total_candidates: usize,
    counters: &RunCounters,
    run_started_at: std::time::Instant,
    last_progress_log_at: &mut std::time::Instant,
    last_progress_log_bytes: &mut u64,
) {
    let due_by_time = last_progress_log_at.elapsed() >= PROGRESS_LOG_MIN_INTERVAL;
    let due_by_count = emitted_count.is_multiple_of(PROGRESS_LOG_CANDIDATE_STRIDE)
        || emitted_count == total_candidates;
    if !due_by_time && !due_by_count {
        return;
    }
    let interval_secs = last_progress_log_at.elapsed().as_secs_f64();
    let interval_bytes = counters
        .logical_bytes_succeeded
        .saturating_sub(*last_progress_log_bytes);
    let mib_per_sec_since_last_heartbeat = if interval_secs > 0.0_f64 {
        (interval_bytes as f64 / (1_024.0_f64 * 1_024.0_f64)) / interval_secs
    } else {
        0.0_f64
    };
    let overall_secs = run_started_at.elapsed().as_secs_f64();
    let mib_per_sec_since_job_start = if overall_secs > 0.0_f64 {
        (counters.logical_bytes_succeeded as f64 / (1_024.0_f64 * 1_024.0_f64)) / overall_secs
    } else {
        0.0_f64
    };

    *last_progress_log_at = std::time::Instant::now();
    *last_progress_log_bytes = counters.logical_bytes_succeeded;
    tracing::info!(
        emitted_count,
        total_candidates,
        succeeded = counters.succeeded_count,
        failed_retryable = counters.failed_retryable_count,
        failed_terminal = counters.failed_terminal_count,
        logical_bytes_succeeded = counters.logical_bytes_succeeded,
        mib_per_sec_since_last_heartbeat,
        mib_per_sec_since_job_start,
        "job: content read progress"
    );
}

/// Emit one already-read candidate's `FILE_BEGIN`, its `CONTENT_CHUNK`s,
/// and its terminal frame (`FILE_END`/`FILE_FAILED`), in that order, on
/// the caller's own thread — see `super`'s "Concurrent reads, concurrent
/// drives, atomic per-candidate emission" doc section for the atomicity
/// this step is part of. Updates `counters` and appends to `failure_log`
/// for a non-success outcome.
#[expect(
    clippy::too_many_arguments,
    reason = "the alternative is a bespoke context struct bundling job_id/frame_sequence/ \
              emit_frame purely to satisfy this lint, for a private helper with exactly one \
              call site; not worth the indirection"
)]
fn emit_candidate(
    entry: &CandidateEntry,
    candidate_id: u64,
    content: CandidateContent,
    counters: &mut RunCounters,
    failure_log: &mut FailureLogWriter,
    job_id: [u8; 16],
    frame_sequence: &mut u64,
    emit_frame: &mut dyn FnMut(Vec<u8>) -> io::Result<()>,
) -> io::Result<()> {
    let path = WindowsPath::from_str_lossless(&entry.relative_path.to_string_lossy());

    let file_begin = FileBegin {
        candidate_id,
        file_reference: entry.file_reference,
        path,
        logical_size: entry.logical_size,
        mtime: entry.mtime_unix_ms,
        read_mode: content.read_mode,
        attempt_number: 1,
        content_object_id: None,
    };
    emit_frame(encode_frame(
        job_id,
        frame_sequence,
        FrameType::FileBegin,
        &file_begin.encode(),
    ))?;

    let chunk_count = super::len_as_u64(content.chunks.len());
    for chunk in &content.chunks {
        emit_frame(encode_frame(
            job_id,
            frame_sequence,
            FrameType::ContentChunk,
            &chunk.encode(),
        ))?;
    }

    let read_mode = content.read_mode;
    match content.read_error {
        None => {
            // A metadata-only candidate never had real bytes read (see
            // `pipeline::read_one_candidate`'s doc comment), so its
            // digest is meaningless — report `None`, matching the wire
            // contract `ReadMode::MetadataOnly`'s own doc comment
            // documents (design-doc's two-tier delivery-ceiling model).
            let content_digest = if read_mode == ReadMode::MetadataOnly {
                None
            } else {
                Some(content.digest)
            };
            let file_end = FileEnd {
                candidate_id,
                total_logical_bytes: content.total_read,
                content_digest,
                read_mode,
                chunk_count,
                elapsed_ms: 0,
                warning_flags: 0,
            };
            emit_frame(encode_frame(
                job_id,
                frame_sequence,
                FrameType::FileEnd,
                &file_end.encode(),
            ))?;
            counters.record_succeeded(content.total_read);
        }
        Some(err) => {
            let os_error_code = err.raw_os_error().map(i64::from);
            let message = err.to_string();
            let file_failed = FileFailed {
                candidate_id,
                outcome: FailedOutcome::Retryable,
                failure_stage: FailureStage::Read,
                error_code: ErrorCode::ReadIoTransient,
                os_error_code,
                retry_class: RetryClass::RetryNewSnapshot,
                bytes_emitted_before_failure: content.total_read,
                message: message.clone(),
            };
            emit_frame(encode_frame(
                job_id,
                frame_sequence,
                FrameType::FileFailed,
                &file_failed.encode(),
            ))?;
            counters.record_failed_retryable();
            failure_log.append(&FailureRecord::failed(
                candidate_id,
                FailedOutcome::Retryable,
                FailureStage::Read,
                ErrorCode::ReadIoTransient,
                os_error_code,
                RetryClass::RetryNewSnapshot,
                content.total_read,
                message,
            ))?;
        }
    }

    Ok(())
}
