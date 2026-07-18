// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Bounded sliding-window content-read pipeline — the concurrent-read
//! machinery behind [`super::run_job`], split into its own file so
//! `workflow.rs` itself stays under the workspace's file-size policy.
//! See that module's doc comment ("Concurrent reads, sequential
//! emission") for the full design rationale; everything here is
//! mechanism, not policy.

use std::collections::HashMap;
use std::io;

use crossbeam_channel::{Receiver, Sender};
use uffs_content_protocol::codec::{Digest, IncrementalDigest};
use uffs_content_protocol::frame::{ContentChunk, ReadMode};

use crate::job::candidate_source::CandidateEntry;
use crate::job::content_source::ContentSource;

/// Split `candidates` into contiguous same-`snapshot_lease_id` runs for
/// [`read_lease_run_pipelined`] — unlike a fixed batch size, a run is
/// never capped: its own concurrency (looked up once, from its first
/// candidate) instead bounds how many of its worker threads run at
/// once, not how many candidates it may contain. See the parent
/// module's "Concurrent reads, sequential emission" doc section for why
/// staying within one lease per run matters.
///
/// Candidates already arrive grouped contiguously by lease (`run_job`'s
/// enumeration loop appends one root/drive at a time), so a single
/// linear scan suffices — no need to look ahead past the current run.
pub(super) fn lease_runs<'entries>(
    candidates: &'entries [(&'entries CandidateEntry, u64)],
) -> Vec<&'entries [(&'entries CandidateEntry, u64)]> {
    let mut runs = Vec::new();
    let mut start = 0_usize;
    while start < candidates.len() {
        let Some((first_entry, _)) = candidates.get(start) else {
            break;
        };
        let lease_id = first_entry.snapshot_lease_id;
        let Some(tail) = candidates.get(start..) else {
            break;
        };
        let end = tail
            .iter()
            .position(|(entry, _)| entry.snapshot_lease_id != lease_id)
            .map_or(candidates.len(), |offset| start + offset);
        let Some(run) = candidates.get(start..end) else {
            break;
        };
        runs.push(run);
        start = end;
    }
    runs
}

/// One candidate's content, fully read into memory by
/// [`read_lease_run_pipelined`]/[`read_one_candidate`] and consumed by
/// the parent module's `emit_candidate`. Bounded to exactly one
/// candidate's content per instance — never a whole run or job — since
/// the pipeline's own bounded channels cap how many of these exist in
/// memory at once (see the parent module doc's "Concurrent reads,
/// sequential emission" section).
pub(super) struct CandidateContent {
    /// Every `CONTENT_CHUNK` this candidate's content produced, in order.
    /// Empty when `read_mode == MetadataOnly`.
    pub(super) chunks: Vec<ContentChunk>,
    /// Sum of every chunk's payload length. `0` when `read_mode ==
    /// MetadataOnly`.
    pub(super) total_read: u64,
    /// BLAKE3 digest over every chunk's payload, in order. Only
    /// meaningful when `read_mode != MetadataOnly` — the parent module's
    /// `emit_candidate` reports `content_digest: None` on `FILE_END` for
    /// a metadata-only candidate regardless of this value.
    pub(super) digest: Digest,
    /// Set only if a read failed partway through; `None` means every
    /// byte up to `entry.logical_size` was read successfully (or the
    /// read was skipped entirely because `read_mode == MetadataOnly`).
    pub(super) read_error: Option<io::Error>,
    /// Whether this candidate's body was actually streamed
    /// (`LogicalSnapshot`) or skipped because `entry.logical_size`
    /// exceeded the job's `max_content_delivery_bytes` ceiling
    /// (`MetadataOnly`) — see [`read_one_candidate`]'s doc comment.
    pub(super) read_mode: ReadMode,
}

/// Read every candidate in `run` through a bounded sliding-window
/// pipeline of `concurrency` worker threads, invoking `on_ready(index,
/// content)` — `index` into `run` — strictly in order as each
/// candidate's turn comes up, regardless of the order its read actually
/// completed in. See the parent module doc's "Concurrent reads,
/// sequential emission" section for the full rationale and the
/// memory-boundedness argument; in short: this is a genuine sliding
/// window (a worker immediately claims the next unclaimed candidate the
/// moment it finishes its current one), not a fixed-size batch that
/// waits for its slowest member before admitting more work.
///
/// Three threads-of-control cooperate, all joined via `std::thread::scope`
/// before this function returns:
/// - one **feeder** thread sends candidate indices `0..run.len()`, in order,
///   into a bounded input channel (capacity `concurrency`) — its `send` blocks
///   once that many are unclaimed, which is what keeps a fast run of tiny
///   candidates from letting workers race arbitrarily far ahead of a slow one;
/// - `concurrency` **worker** threads each loop: claim the next index from the
///   input channel, read that candidate, then push `(index, content)` to a
///   bounded output channel (same capacity) — blocking there, not just on the
///   next input claim, if results are piling up faster than they can be
///   consumed;
/// - this function's own body (the **coordinator**, running on the caller's
///   thread inside the `scope` — not a spawned thread) drains the output
///   channel into a small reorder map and calls `on_ready` for `0, 1, 2, ...`
///   in turn as each becomes available.
///
/// If `on_ready` itself returns an error (e.g. a downstream transport
/// failure), the coordinator stops calling it but keeps draining the
/// output channel to completion anyway — never stopping early and
/// leaving a worker or the feeder blocked on a channel nobody is
/// servicing anymore — and returns that first error once every
/// candidate has actually been read (wasting the now-moot remaining
/// reads in that rare case, in exchange for a pipeline that can never
/// deadlock on early termination).
///
/// # Errors
/// Returns the first error `on_ready` produced, if any.
pub(super) fn read_lease_run_pipelined(
    run: &[(&CandidateEntry, u64)],
    concurrency: usize,
    content_source: &dyn ContentSource,
    max_chunk_bytes: u32,
    max_content_delivery_bytes: Option<u64>,
    mut on_ready: impl FnMut(usize, CandidateContent) -> io::Result<()>,
) -> io::Result<()> {
    if run.is_empty() {
        return Ok(());
    }
    let worker_count = concurrency.max(1).min(run.len());

    let (input_tx, input_rx): (Sender<usize>, Receiver<usize>) =
        crossbeam_channel::bounded(worker_count);
    let (output_tx, output_rx): (Sender<IndexedContent>, Receiver<IndexedContent>) =
        crossbeam_channel::bounded(worker_count);

    std::thread::scope(|scope| {
        scope.spawn(move || {
            for index in 0..run.len() {
                if input_tx.send(index).is_err() {
                    break;
                }
            }
            // Dropping input_tx here (end of scope) closes the channel
            // once every index has been sent, so workers' `recv` loops
            // end cleanly instead of blocking forever.
        });

        for _ in 0..worker_count {
            let worker_input_rx = input_rx.clone();
            let worker_output_tx = output_tx.clone();
            scope.spawn(move || {
                while let Ok(index) = worker_input_rx.recv() {
                    let Some(&(entry, candidate_id)) = run.get(index) else {
                        continue;
                    };
                    let content = read_one_candidate_catch_panic(
                        entry,
                        candidate_id,
                        content_source,
                        max_chunk_bytes,
                        max_content_delivery_bytes,
                    );
                    if worker_output_tx.send((index, content)).is_err() {
                        break;
                    }
                }
            });
        }
        // This scope's own sender handle; every worker holds its own
        // clone, so the channel only truly closes once all of them
        // finish.
        drop(output_tx);

        drain_pipelined_output(run.len(), &output_rx, &mut on_ready)
    })
}

/// One worker's completed read, tagged with its index into the
/// enclosing [`read_lease_run_pipelined`] call's `run` slice.
type IndexedContent = (usize, CandidateContent);

/// The coordinator half of [`read_lease_run_pipelined`]: drain
/// `output_rx` into a reorder map and call `on_ready` for
/// `0..total_candidates` in turn as each becomes available. Extracted
/// so `read_lease_run_pipelined` itself stays under the workspace's
/// `too_many_lines` budget.
///
/// # Errors
/// Returns the first error `on_ready` produced, after draining every
/// remaining result (see [`read_lease_run_pipelined`]'s doc comment for
/// why finishing the drain, rather than stopping early, is what keeps
/// this deadlock-free).
fn drain_pipelined_output(
    total_candidates: usize,
    output_rx: &Receiver<IndexedContent>,
    on_ready: &mut dyn FnMut(usize, CandidateContent) -> io::Result<()>,
) -> io::Result<()> {
    let mut next_expected = 0_usize;
    let mut pending: HashMap<usize, CandidateContent> = HashMap::new();
    let mut first_error: Option<io::Error> = None;
    while next_expected < total_candidates {
        if let Some(content) = pending.remove(&next_expected) {
            if first_error.is_none()
                && let Err(err) = on_ready(next_expected, content)
            {
                first_error = Some(err);
            }
            next_expected += 1;
            continue;
        }
        match output_rx.recv() {
            Ok((index, content)) => {
                pending.insert(index, content);
            }
            // Every worker finished without ever producing
            // `next_expected` — unreachable in practice (the feeder
            // sends every index in `0..run.len()` and every worker
            // processes whatever it claims), but fail safe rather than
            // spin.
            Err(_) => break,
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// [`read_one_candidate`], guarded against a panic partway through:
/// `content_source` is a `&dyn ContentSource` trait object this crate
/// doesn't control every implementation of (see that trait's own doc
/// comment), so a third-party impl panicking must not take down this
/// candidate's entire worker thread — and, transitively, every other
/// candidate's read still in flight on this same `thread::scope` (a
/// spawned thread's panic propagates when the scope joins it). A caught
/// panic is reported the same way an `io::Error` from a normal read
/// failure is: as a retryable `FILE_FAILED`, via `read_error`.
///
/// Mirrors the panic-to-`read_error` conversion the earlier fixed-batch
/// design got for free from `JoinHandle::join()` returning `Err` on a
/// panicked thread — this pipeline's workers are fire-and-forget
/// (`scope.spawn` without a retained handle), so that safety net has to
/// be reintroduced explicitly here instead.
fn read_one_candidate_catch_panic(
    entry: &CandidateEntry,
    candidate_id: u64,
    content_source: &dyn ContentSource,
    max_chunk_bytes: u32,
    max_content_delivery_bytes: Option<u64>,
) -> CandidateContent {
    let outcome = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
        read_one_candidate(
            entry,
            candidate_id,
            content_source,
            max_chunk_bytes,
            max_content_delivery_bytes,
        )
    }));
    outcome.unwrap_or_else(|panic_payload| CandidateContent {
        chunks: Vec::new(),
        total_read: 0,
        digest: IncrementalDigest::new().finalize(),
        read_error: Some(io::Error::other(format!(
            "content-read thread panicked: {panic_payload:?}"
        ))),
        read_mode: ReadMode::LogicalSnapshot,
    })
}

/// Read one candidate's content into memory, up to `entry.logical_size`
/// or the first read error — or, if `entry.logical_size` exceeds
/// `max_content_delivery_bytes`, skip the read entirely and report
/// `read_mode: MetadataOnly` with no bytes read at all. This is the only
/// place the delivery ceiling is enforced; the query filters
/// (`ext`/`min_size`/etc.) that decide which files become candidates at
/// all are evaluated earlier, by the daemon — this is a second,
/// independent gate on an already-matched candidate's body.
///
/// Never touches `emit_frame`/`frame_sequence`/`counters`/`failure_log`
/// — those stay single-threaded, touched only by the parent module's
/// `emit_candidate` afterward.
fn read_one_candidate(
    entry: &CandidateEntry,
    candidate_id: u64,
    content_source: &dyn ContentSource,
    max_chunk_bytes: u32,
    max_content_delivery_bytes: Option<u64>,
) -> CandidateContent {
    if max_content_delivery_bytes.is_some_and(|ceiling| entry.logical_size > ceiling) {
        return CandidateContent {
            chunks: Vec::new(),
            total_read: 0,
            digest: IncrementalDigest::new().finalize(),
            read_error: None,
            read_mode: ReadMode::MetadataOnly,
        };
    }

    let mut hasher = IncrementalDigest::new();
    let mut offset = 0_u64;
    let mut chunk_sequence = 0_u64;
    let mut total_read = 0_u64;
    let mut chunks = Vec::new();
    let mut read_error = None;

    while offset < entry.logical_size {
        match content_source.read_at(entry, candidate_id, offset, max_chunk_bytes) {
            Ok(bytes) if bytes.is_empty() => break,
            Ok(bytes) => {
                let read_len = super::len_as_u64(bytes.len());
                hasher.update(&bytes);
                total_read += read_len;
                chunks.push(ContentChunk {
                    candidate_id,
                    chunk_sequence,
                    logical_offset: offset,
                    logical_length: read_len,
                    payload: bytes,
                });
                offset += read_len;
                chunk_sequence += 1;
            }
            Err(err) => {
                tracing::warn!(
                    candidate_id,
                    path = %entry.relative_path.display(),
                    offset,
                    error = %err,
                    "content read failed"
                );
                read_error = Some(err);
                break;
            }
        }
    }

    CandidateContent {
        chunks,
        total_read,
        digest: hasher.finalize(),
        read_error,
        read_mode: ReadMode::LogicalSnapshot,
    }
}
