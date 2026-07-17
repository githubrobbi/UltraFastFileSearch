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

use std::io;
use std::path::Path;

use uffs_content_protocol::codec::{Digest, IncrementalDigest, digest};
use uffs_content_protocol::error::ErrorCode;
use uffs_content_protocol::frame::{
    ContentChunk, ContentSemantics, DigestAlgorithm, FailedOutcome, FailureStage, FileBegin,
    FileEnd, FileFailed, FrameEnvelope, FrameOrdering, FrameType, JobBegin, JobEnd, JobStatus,
    ReadMode, RetryClass,
};
use uffs_content_protocol::manifest::AuthorizationMode;
use uffs_content_protocol::path_encoding::WindowsPath;

use super::candidate_source::{CandidateEntry, CandidateSource};
use super::content_source::ContentSource;
use super::intake::JobRequest;
use super::manifest_builder::build_manifest;
use crate::run::{FailureLogWriter, FailureRecord, RunCounters, RunSummary};

/// One `CONTENT_CHUNK`'s maximum payload size for a job run.
///
/// Deliberately small so even modest fixture files exercise multiple
/// chunks — production tuning of this value is a UFI.2 scheduler
/// concern, not something this workflow needs to get "right" yet.
pub const DEFAULT_MAX_CHUNK_BYTES: u32 = 64 * 1024;

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
/// # Errors
/// Returns an [`io::Error`] for any filesystem failure enumerating
/// candidates, writing the failure log, or finalizing the summary, or
/// propagated from `emit_frame` itself (e.g. a downstream transport
/// failure). A per-candidate content-read failure is *not* an error
/// return — it's recorded as a `FAILED_RETRYABLE` outcome for that
/// candidate instead (a [`FileFailed`] frame plus a [`FailureRecord`]).
pub fn run_job<F>(
    request: &JobRequest,
    candidate_source: &dyn CandidateSource,
    content_source: &dyn ContentSource,
    run_dir: &Path,
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

    let mut entries = Vec::new();
    for root in &request.roots {
        entries.extend(candidate_source.enumerate(root)?);
    }
    let candidate_count = len_as_u64(entries.len());

    let built = build_manifest(job_id, source_id, query_digest, &entries)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;

    let mut frame_sequence: u64 = 0;

    let job_begin = JobBegin {
        job_id,
        source_id,
        snapshot_id: Vec::new(),
        snapshot_created_at: 0,
        manifest_digest: built.manifest_digest,
        candidate_count,
        authorization_mode: AuthorizationMode::AdminExport,
        ordering: FrameOrdering::None,
        content_semantics: ContentSemantics::UnnamedLogicalStream,
        digest_algorithm: DigestAlgorithm::Blake3,
        max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
        max_content_delivery_bytes: None,
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

    for (entry, &candidate_id) in entries.iter().zip(&built.candidate_ids) {
        stream_one_candidate(
            entry,
            candidate_id,
            content_source,
            DEFAULT_MAX_CHUNK_BYTES,
            &mut counters,
            &mut failure_log,
            job_id,
            &mut frame_sequence,
            &mut emit_frame,
        )?;
    }
    drop(failure_log);

    let job_status = if counters.failed_retryable_count == 0
        && counters.failed_terminal_count == 0
        && counters.deferred_manual_count == 0
    {
        JobStatus::Completed
    } else {
        JobStatus::CompletedWithFailures
    };

    let failure_log_bytes = std::fs::read(&failures_path).unwrap_or_default();
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
        manifest_digest: built.manifest_digest,
        outcome_ledger_digest: digest(&failure_log_bytes),
        job_status,
    };
    let job_end_bytes = job_end
        .encode()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    emit_frame(encode_frame(
        job_id,
        &mut frame_sequence,
        FrameType::JobEnd,
        &job_end_bytes,
    ))?;

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

/// Wrap `payload` in a `FrameEnvelope` for `job_id`, assigning and
/// advancing the next `frame_sequence`.
fn encode_frame(
    job_id: [u8; 16],
    frame_sequence: &mut u64,
    frame_type: FrameType,
    payload: &[u8],
) -> Vec<u8> {
    let envelope = FrameEnvelope {
        protocol_version: 2,
        frame_type,
        flags: 0,
        job_id,
        frame_sequence: *frame_sequence,
    };
    *frame_sequence += 1;
    envelope.encode(payload)
}

/// Streams one candidate's content, emitting `FILE_BEGIN`, zero or more
/// `CONTENT_CHUNK`s, and exactly one of `FILE_END`/`FILE_FAILED` through
/// `emit_frame` as each is produced — never buffering more than one
/// chunk's worth of this candidate's content at a time. Updates
/// `counters` and appends to `failure_log` for a non-success outcome.
#[expect(
    clippy::too_many_arguments,
    reason = "the alternative is a bespoke context struct bundling job_id/frame_sequence/ \
              emit_frame purely to satisfy this lint, for a private helper with exactly one \
              call site; not worth the indirection"
)]
fn stream_one_candidate(
    entry: &CandidateEntry,
    candidate_id: u64,
    content_source: &dyn ContentSource,
    max_chunk_bytes: u32,
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
        read_mode: ReadMode::LogicalSnapshot,
        attempt_number: 1,
        content_object_id: None,
    };
    emit_frame(encode_frame(
        job_id,
        frame_sequence,
        FrameType::FileBegin,
        &file_begin.encode(),
    ))?;

    let (chunk_count, total_read, content_digest, read_error) = stream_content_chunks(
        entry,
        candidate_id,
        content_source,
        max_chunk_bytes,
        job_id,
        frame_sequence,
        emit_frame,
    )?;

    match read_error {
        None => {
            let file_end = FileEnd {
                candidate_id,
                total_logical_bytes: total_read,
                content_digest: Some(content_digest),
                read_mode: ReadMode::LogicalSnapshot,
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
            counters.record_succeeded(total_read);
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
                bytes_emitted_before_failure: total_read,
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
                total_read,
                message,
            ))?;
        }
    }

    Ok(())
}

/// Read and emit every `CONTENT_CHUNK` frame for one candidate, in
/// order, up to `entry.logical_size` or the first read error — never
/// buffering more than one chunk's worth of content at a time (the
/// running digest is incremental; see [`IncrementalDigest`]).
///
/// Returns `(chunk_count, total_read, digest, read_error)`; `read_error`
/// is `Some` only if a read failed partway, letting the caller decide
/// the candidate's terminal outcome.
fn stream_content_chunks(
    entry: &CandidateEntry,
    candidate_id: u64,
    content_source: &dyn ContentSource,
    max_chunk_bytes: u32,
    job_id: [u8; 16],
    frame_sequence: &mut u64,
    emit_frame: &mut dyn FnMut(Vec<u8>) -> io::Result<()>,
) -> io::Result<(u64, u64, Digest, Option<io::Error>)> {
    let mut hasher = IncrementalDigest::new();
    let mut offset = 0_u64;
    let mut chunk_sequence = 0_u64;
    let mut total_read = 0_u64;
    let mut read_error = None;

    while offset < entry.logical_size {
        match content_source.read_at(entry, candidate_id, offset, max_chunk_bytes) {
            Ok(bytes) if bytes.is_empty() => break,
            Ok(bytes) => {
                let read_len = len_as_u64(bytes.len());
                hasher.update(&bytes);
                total_read += read_len;
                let chunk = ContentChunk {
                    candidate_id,
                    chunk_sequence,
                    logical_offset: offset,
                    logical_length: read_len,
                    payload: bytes,
                };
                emit_frame(encode_frame(
                    job_id,
                    frame_sequence,
                    FrameType::ContentChunk,
                    &chunk.encode(),
                ))?;
                offset += read_len;
                chunk_sequence += 1;
            }
            Err(err) => {
                read_error = Some(err);
                break;
            }
        }
    }
    Ok((chunk_sequence, total_read, hasher.finalize(), read_error))
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
