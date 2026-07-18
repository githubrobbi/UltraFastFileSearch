// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Drives one job end to end: enumerate candidates, finalize the
//! manifest, stream framed content, and finalize the run summary.
//!
//! This is the real Coordinator workflow — only the
//! [`CandidateSource`]/[`ContentSource`] it's given are swappable; see
//! those traits' docs for what "swappable" means today (a real vs. fake
//! backing).
//!
//! # Concurrent reads, sequential emission
//!
//! Candidates are read through a bounded pipeline, one per contiguous
//! `snapshot_lease_id` run (see `lease_runs`), sized by that lease's
//! own [`ReadConcurrency`] — routed to that drive's own connection pool
//! by `reader_client::ContentReader` (see that module's doc comment).
//! `read_lease_run_pipelined` is a genuine sliding window, not a
//! fixed-size batch that waits for its slowest member before starting
//! the next one: as soon as any of the `concurrency` worker threads
//! finishes a candidate, it immediately claims the next not-yet-started
//! one from the same run, regardless of whether earlier candidates are
//! still in flight. This matters in practice — a real-hardware run
//! mixing a handful of multi-gigabyte files into tens of thousands of
//! tiny ones showed the earlier fixed-batch design stalling *every*
//! connection in a batch for as long as its one large straggler took,
//! since the next batch could never start until the current one's
//! `std::thread::scope` join completed. The sliding window instead keeps
//! the other `concurrency - 1` connections working through subsequent
//! candidates for the whole time the straggler is still streaming.
//!
//! Despite the out-of-order reads, frames are still *emitted* strictly
//! in original candidate order, on the caller's own thread, exactly
//! matching the fully-sequential emission order this function has always
//! produced: `read_lease_run_pipelined`'s coordinator loop buffers an
//! out-of-order completion in a small reorder map and only calls the
//! caller's `on_ready` once every earlier candidate in the run has
//! already been handed back. `emit_frame`/`frame_sequence`/`counters`/
//! `failure_log` are therefore still only ever touched from one thread;
//! no synchronization was added to any of them, and downstream consumers
//! of the frame stream (`crate::serve::stream::Grouped`) see exactly the
//! same per-candidate-contiguous ordering as the fully-sequential (every
//! lease at concurrency `1`) case.
//!
//! The reorder map's size — and therefore how far the sliding window can
//! run ahead of a straggler — is self-bounding to a small constant
//! multiple of `concurrency`, never the run's total length: candidates
//! are dispatched to workers through an input channel bounded to
//! `concurrency` slots, and completed results flow back through an
//! output channel of the same bound, so a worker that finishes early
//! blocks on its next claim (or its result send) once the pipeline is
//! full, rather than racing arbitrarily far ahead and buffering the rest
//! of the job's content in memory behind one slow file.
//!
//! A run never spans two different `snapshot_lease_id`s — candidates
//! are collected one root/drive at a time (see `run_job`'s enumeration
//! loop), so they already arrive grouped contiguously by drive, and
//! `lease_runs` splits at each lease boundary rather than letting one
//! drive's run absorb another's candidates under the wrong concurrency
//! setting. This is what makes an HDD-backed lease's concurrency-`1`
//! setting actually mean "read every candidate strictly one at a time,
//! in the order they were enumerated" — the same order the MFT (and
//! therefore, roughly, on-disk position) produced them in — rather than
//! being diluted by whatever other drives happen to be in the same job.
//!
//! # Why `emit_frame` is a callback, not a returned `Vec`
//!
//! Earlier revisions of this function collected every emitted frame into
//! one `Vec<Vec<u8>>` and returned it once the whole job finished — for a
//! job matching many/large files, that meant peak memory proportional to
//! the job's *entire* logical content, held before a single byte reached
//! any consumer. Emitting each frame through a caller-supplied callback as
//! soon as it's produced removes that ceiling: a caller that wants the old
//! all-in-memory behavior (this crate's own tests, `self_test`) can still
//! collect into a `Vec` via a trivial closure, while the real production
//! caller (`crate::serve::stream`) forwards frames onto a bounded channel
//! and paces them out under backpressure, so memory stays bounded near the
//! send-window size rather than the job size — see that module's own doc
//! comment for the consumer side of this.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use uffs_content_protocol::codec::{Digest, digest};
use uffs_content_protocol::error::ErrorCode;
use uffs_content_protocol::frame::{
    ContentSemantics, DigestAlgorithm, FailedOutcome, FailureStage, FileBegin, FileEnd, FileFailed,
    FrameEnvelope, FrameOrdering, FrameType, JobBegin, JobEnd, JobStatus, PROTOCOL_VERSION,
    ReadMode, RetryClass,
};
use uffs_content_protocol::manifest::AuthorizationMode;
use uffs_content_protocol::path_encoding::WindowsPath;

use self::pipeline::{CandidateContent, lease_runs, read_lease_run_pipelined};
use super::candidate_source::{CandidateEntry, CandidateSource};
use super::content_source::ContentSource;
use super::intake::JobRequest;
use super::manifest_builder::build_manifest;

mod pipeline;
use crate::run::{FailureLogWriter, FailureRecord, RunCounters, RunSummary};

/// One `CONTENT_CHUNK`'s maximum payload size for a job run.
///
/// Deliberately small so even modest fixture files exercise multiple
/// chunks — production tuning of this value is a UFI.2 scheduler
/// concern, not something this workflow needs to get "right" yet.
pub const DEFAULT_MAX_CHUNK_BYTES: u32 = 64 * 1024;

/// Per-drive (per `snapshot_lease_id`) content-read concurrency.
///
/// An HDD-backed lease should read its candidates one at a time, in the
/// order [`CandidateSource::enumerate`] returned them: candidates come
/// off the MFT roughly in on-disk order, so reading them strictly in
/// sequence approximates sequential disk access; racing several
/// concurrent reads against the same spinning disk instead scatters its
/// head across every in-flight read's location — pure seek-time waste.
/// An NVMe/SSD-backed lease has no seek penalty to protect and benefits
/// from many candidates in flight at once (see `reader_client`'s
/// `ConnectionPool`, which is what actually backs this concurrency on
/// the wire — this type only controls how many threads
/// [`run_job`] fans a given lease's reads out to).
///
/// `snapshot_lease_id == 0` (never a real Broker-assigned lease id — see
/// [`CandidateEntry::snapshot_lease_id`]) always falls through to
/// `default`, which is what the cross-platform fake/test harness (no
/// drive-type concept at all) relies on via [`Self::flat`].
#[derive(Debug, Clone)]
pub struct ReadConcurrency {
    /// Concurrency overrides, keyed by `snapshot_lease_id`.
    per_lease: HashMap<u64, usize>,
    /// Concurrency for any lease not present in `per_lease`.
    default: usize,
}

impl ReadConcurrency {
    /// A single flat concurrency for every lease — for callers with no
    /// per-drive concurrency to report (the cross-platform fake/test
    /// harness). `1` gives the fully-sequential, deterministic-order
    /// behavior some tests rely on.
    #[must_use]
    pub fn flat(concurrency: usize) -> Self {
        Self {
            per_lease: HashMap::new(),
            default: concurrency.max(1),
        }
    }

    /// Start from `default` (used for any lease [`Self::set`] hasn't
    /// overridden) with no per-lease overrides yet.
    #[must_use]
    pub fn new(default: usize) -> Self {
        Self {
            per_lease: HashMap::new(),
            default: default.max(1),
        }
    }

    /// Override `lease_id`'s own concurrency.
    pub fn set(&mut self, lease_id: u64, concurrency: usize) {
        self.per_lease.insert(lease_id, concurrency.max(1));
    }

    /// The concurrency to use for a candidate from `lease_id`.
    fn for_lease(&self, lease_id: u64) -> usize {
        self.per_lease
            .get(&lease_id)
            .copied()
            .unwrap_or(self.default)
    }
}

/// Everything one completed job produced, aside from the frames
/// themselves (see the module doc for why those are emitted through a
/// callback instead of collected here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobOutcome {
    /// Job identifier assigned to this run.
    pub job_id: [u8; 16],
    /// The finalized manifest's encoded bytes.
    pub manifest_bytes: Vec<u8>,
    /// The finalized run summary.
    pub run_summary: RunSummary,
}

/// Run one job: enumerate every one of `request.roots` via
/// `candidate_source`.
///
/// Finalize a manifest, stream every candidate's content via
/// `content_source`, and finalize the run's summary/failure log under
/// `run_dir`.
///
/// Every encoded frame (`JOB_BEGIN`, then per-candidate frames, then
/// `JOB_END`) is passed to `emit_frame` in emission order as soon as it
/// exists — see the module doc comment.
///
/// `read_concurrency` is how many candidates are read concurrently per
/// batch, per drive (see the module doc's "Concurrent reads, sequential
/// emission" section and [`ReadConcurrency`]'s own doc comment for why
/// this varies by drive rather than being one flat number). Pass
/// [`ReadConcurrency::flat`] for the fully-sequential, deterministic-
/// order behavior tests rely on, or a per-lease-tuned one built from
/// each leased drive's actual `uffs_mft::platform::DriveType` (see
/// `super::vss_job::run_vss_job`, the real caller) — this function has
/// no way to know drive types itself, since drive leasing happens in
/// the caller.
///
/// # Errors
/// Returns an [`io::Error`] for any filesystem failure enumerating
/// candidates, writing the failure log, or finalizing the summary, or
/// propagated from `emit_frame` itself (e.g. a downstream transport
/// failure). A per-candidate content-read failure is *not* an error
/// return — it's recorded as a `FAILED_RETRYABLE` outcome for that
/// candidate instead (a [`FileFailed`] frame plus a [`FailureRecord`]).
#[expect(
    clippy::too_many_arguments,
    reason = "snapshot_id/snapshot_created_at are real VSS provenance the caller (run_vss_job) \
              already holds from its lease response; the fake/test callers pass empty/zero. \
              Bundling them into a struct purely to satisfy this lint would add indirection \
              for two fields that always travel together and change meaning together."
)]
pub fn run_job<F>(
    request: &JobRequest,
    candidate_source: &dyn CandidateSource,
    content_source: &dyn ContentSource,
    run_dir: &Path,
    read_concurrency: &ReadConcurrency,
    snapshot_id: &[u8],
    snapshot_created_at: i64,
    mut emit_frame: F,
) -> io::Result<JobOutcome>
where
    F: FnMut(Vec<u8>) -> io::Result<()>,
{
    let job_id = *uuid::Uuid::new_v4().as_bytes();
    let source_id = source_id_bytes(&request.source_id);
    // No query filtering is wired up yet (see `JobRequest` docs) — every
    // job is equivalent to a `"*"` query, so its digest is fixed.
    let query_digest = digest(b"*");

    tracing::info!(
        job_id = %uuid::Uuid::from_bytes(job_id),
        root_count = request.roots.len(),
        "job: starting candidate enumeration"
    );
    let mut entries = Vec::new();
    for root in &request.roots {
        entries.extend(candidate_source.enumerate(root)?);
    }
    let candidate_count = len_as_u64(entries.len());
    tracing::info!(
        candidate_count,
        "job: enumeration complete, building manifest"
    );

    let built = build_manifest(job_id, source_id, query_digest, &entries)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;

    let mut frame_sequence: u64 = 0;

    let job_begin = JobBegin {
        job_id,
        source_id,
        snapshot_id: snapshot_id.to_vec(),
        snapshot_created_at,
        manifest_digest: built.manifest_digest,
        candidate_count,
        authorization_mode: AuthorizationMode::AdminExport,
        ordering: FrameOrdering::None,
        content_semantics: ContentSemantics::UnnamedLogicalStream,
        digest_algorithm: DigestAlgorithm::Blake3,
        max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
        max_content_delivery_bytes: request.max_content_delivery_bytes,
    };
    emit_frame(encode_frame(
        job_id,
        &mut frame_sequence,
        FrameType::JobBegin,
        &job_begin.encode(),
    ))?;

    let mut counters = RunCounters::new(candidate_count);
    let run_id = uuid::Uuid::from_bytes(job_id).to_string();
    let failures_path = run_dir.join(format!("run-{run_id}.failures.jsonl"));
    let mut failure_log = FailureLogWriter::open(&failures_path)?;

    let candidates: Vec<(&CandidateEntry, u64)> = entries
        .iter()
        .zip(built.candidate_ids.iter().copied())
        .collect();
    read_and_emit_all_candidates(
        &candidates,
        read_concurrency,
        content_source,
        request.max_content_delivery_bytes,
        job_id,
        &mut counters,
        &mut failure_log,
        &mut frame_sequence,
        &mut emit_frame,
    )?;
    drop(failure_log);

    tracing::info!(
        succeeded = counters.succeeded_count,
        failed_retryable = counters.failed_retryable_count,
        failed_terminal = counters.failed_terminal_count,
        deferred_manual = counters.deferred_manual_count,
        "job: content reads complete, finalizing"
    );
    emit_job_end(
        &counters,
        built.manifest_digest,
        candidate_count,
        &failures_path,
        job_id,
        &mut frame_sequence,
        &mut emit_frame,
    )?;

    let now_ms = unix_ms_now();
    let summary_path = run_dir.join(format!("run-{run_id}.summary.json"));
    let run_summary = counters
        .finalize(run_id, now_ms, now_ms)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    run_summary.finalize_to_disk(&summary_path)?;

    Ok(JobOutcome {
        job_id,
        manifest_bytes: built.bytes,
        run_summary,
    })
}

/// Read and emit every candidate's content, one [`read_lease_run_pipelined`]
/// call per contiguous [`lease_runs`] group. Extracted from [`run_job`]
/// itself so that function stays under the workspace's `too_many_lines`
/// budget — every parameter here is `run_job`'s own local state, threaded
/// through unchanged.
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
fn read_and_emit_all_candidates<F>(
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
    F: FnMut(Vec<u8>) -> io::Result<()>,
{
    for run in lease_runs(candidates) {
        let Some(&(first_entry, _)) = run.first() else {
            continue;
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
                emit_candidate(
                    entry,
                    candidate_id,
                    read_result,
                    counters,
                    failure_log,
                    job_id,
                    frame_sequence,
                    emit_frame,
                )
            },
        )?;
    }
    Ok(())
}

/// Wrap `payload` in a `FrameEnvelope` for `job_id`, assigning and
/// advancing the next `frame_sequence`.
fn encode_frame(
    job_id: [u8; 16],
    frame_sequence: &mut u64,
    frame_type: FrameType,
    payload: &[u8],
) -> Vec<u8> {
    let envelope = FrameEnvelope {
        protocol_version: PROTOCOL_VERSION,
        frame_type,
        flags: 0,
        job_id,
        frame_sequence: *frame_sequence,
    };
    *frame_sequence += 1;
    envelope.encode(payload)
}

/// Build and emit `JOB_END`: `job_status` is derived from `counters`,
/// `failure_bucket_id`/`outcome_ledger_digest` from the failure log file
/// at `failures_path`.
fn emit_job_end(
    counters: &RunCounters,
    manifest_digest: Digest,
    candidate_count: u64,
    failures_path: &Path,
    job_id: [u8; 16],
    frame_sequence: &mut u64,
    emit_frame: &mut dyn FnMut(Vec<u8>) -> io::Result<()>,
) -> io::Result<()> {
    let job_status = if counters.failed_retryable_count == 0
        && counters.failed_terminal_count == 0
        && counters.deferred_manual_count == 0
    {
        JobStatus::Completed
    } else {
        JobStatus::CompletedWithFailures
    };

    let failure_log_bytes = std::fs::read(failures_path).unwrap_or_default();
    let failure_bucket_id = failures_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned().into_bytes())
        .unwrap_or_default();
    let job_end = JobEnd {
        candidate_count,
        succeeded_count: counters.succeeded_count,
        failed_retryable_count: counters.failed_retryable_count,
        failed_terminal_count: counters.failed_terminal_count,
        deferred_manual_count: counters.deferred_manual_count,
        // No FILE_ACK loop is modeled by this fake-reader harness yet
        // (UFI.2 scheduler work) — every success is treated as
        // immediately acknowledged.
        acknowledged_success_count: counters.succeeded_count,
        logical_bytes_succeeded: counters.logical_bytes_succeeded,
        failure_bucket_id,
        manifest_digest,
        outcome_ledger_digest: digest(&failure_log_bytes),
        job_status,
    };
    let job_end_bytes = job_end
        .encode()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    emit_frame(encode_frame(
        job_id,
        frame_sequence,
        FrameType::JobEnd,
        &job_end_bytes,
    ))
}

/// Emit one already-read candidate's `FILE_BEGIN`, its `CONTENT_CHUNK`s,
/// and its terminal frame (`FILE_END`/`FILE_FAILED`), in that order, on
/// the caller's own thread — see the module doc's "Concurrent reads,
/// sequential emission" section for why this step is never
/// parallelized. Updates `counters` and appends to `failure_log` for a
/// non-success outcome.
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

    let chunk_count = len_as_u64(content.chunks.len());
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

/// Deterministically derives a manifest `source_id` from an arbitrary
/// caller-supplied string, truncating a BLAKE3 digest to 16 bytes (this
/// avoids requiring the `uuid` crate's `v5` feature workspace-wide for
/// what both docs and every existing user only ever treat as an opaque
/// 16-byte identifier).
fn source_id_bytes(source_id: &str) -> [u8; 16] {
    let full: Digest = digest(source_id.as_bytes());
    let mut out = [0_u8; 16];
    if let Some(prefix) = full.get(..16) {
        out.copy_from_slice(prefix);
    }
    out
}

/// Converts a byte length to `u64`, saturating instead of panicking (this
/// crate never handles files anywhere near `u64::MAX` bytes long, so
/// saturation is unobservable in practice and keeps every call site
/// infallible).
fn len_as_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Current wall-clock time, Unix milliseconds, saturating to `0` if the
/// clock is somehow set before the epoch.
fn unix_ms_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}
