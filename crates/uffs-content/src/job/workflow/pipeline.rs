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

/// A declared `logical_size` above this is almost certainly corrupted
/// MFT metadata, not a genuine file — used only to log a warning early
/// (see [`read_one_candidate`]), never to reject or cap the read itself,
/// since a real use case (e.g. a VM image or disk image export) can
/// legitimately exceed this.
const IMPLAUSIBLE_LOGICAL_SIZE_BYTES: u64 = 1024 * 1024 * 1024 * 1024; // 1 TiB

/// A declared `logical_size` at or above this is worth announcing
/// *before* reading it (see [`read_one_candidate`]) — real hardware has
/// shown large/fragmented files reading dramatically slower toward
/// their end than a small-file baseline would predict, without any
/// single candidate ever crossing [`STALL_WARNING_INTERVAL`] on its own.
/// Logging every such candidate up front means a run's throughput dip
/// can always be attributed to a named file, not just inferred after
/// the fact from progress-heartbeat arithmetic.
const NOTABLY_LARGE_LOGICAL_SIZE_BYTES: u64 = 50 * 1024 * 1024; // 50 MiB

/// How often [`read_one_candidate`] re-warns about a single candidate
/// still being read, once it's been in progress this long. Shorter than
/// might seem necessary on purpose: real hardware has shown a single
/// large/fragmented file's read throughput can collapse well before 30s
/// of elapsed time on that one candidate, so a shorter interval catches
/// a slow candidate sooner without waiting for it to look fully stuck.
const STALL_WARNING_INTERVAL: core::time::Duration = core::time::Duration::from_secs(10);

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
/// A fourth, bounded **credit** channel keeps the whole pipeline's memory
/// bounded regardless of run length: the feeder must claim one credit
/// before sending each index, and the coordinator returns exactly one
/// credit every time an index resolves (whether `on_ready` was actually
/// called for it or not — see below). Without this, a single slow
/// candidate holding up `next_expected` would not stop the *other*
/// workers from reading every remaining candidate in the run to
/// completion and piling the results into the reorder map unbounded —
/// real hardware has shown this: one multi-GB candidate stalling
/// emission while workers kept finishing (and fully buffering) tens of
/// thousands of others behind it, well past what "a small constant
/// multiple of concurrency" should ever allow. The credit window is
/// generous relative to `concurrency` (workers should rarely feel it on
/// an ordinary run) but always finite.
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
    // How many candidates may be claimed-but-not-yet-emitted at once —
    // see this function's own doc comment on the credit channel. A
    // small multiple of worker_count gives workers slack to keep moving
    // even while a handful of candidates ahead of the emission cursor
    // are still being read, without letting the whole remainder of a
    // huge run pile into memory behind one straggler.
    let credit_window = worker_count.saturating_mul(4);

    let (input_tx, input_rx): (Sender<usize>, Receiver<usize>) =
        crossbeam_channel::bounded(worker_count);
    let (output_tx, output_rx): (Sender<IndexedContent>, Receiver<IndexedContent>) =
        crossbeam_channel::bounded(worker_count);
    let (credit_tx, credit_rx): (Sender<()>, Receiver<()>) =
        crossbeam_channel::bounded(credit_window);
    for _ in 0..credit_window {
        // Never blocks: capacity is exactly credit_window and this sends
        // exactly that many, once, before any thread below starts.
        let _prefilled = credit_tx.try_send(()).ok();
    }

    std::thread::scope(|scope| {
        scope.spawn(move || {
            for index in 0..run.len() {
                if credit_rx.recv().is_err() {
                    break;
                }
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

        drain_pipelined_output(run.len(), &output_rx, &credit_tx, &mut on_ready)
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
/// Returns one credit to `credit_tx` every time an index resolves —
/// whether `on_ready` was actually called for it or not (see this
/// function's own error-handling branch below) — so the feeder in
/// [`read_lease_run_pipelined`] never blocks waiting for a credit that a
/// resolved-but-unemitted index should have released. This is the other
/// half of that function's credit-window backpressure; see its doc
/// comment for why the window exists at all.
///
/// # Errors
/// Returns the first error `on_ready` produced, after draining every
/// remaining result (see [`read_lease_run_pipelined`]'s doc comment for
/// why finishing the drain, rather than stopping early, is what keeps
/// this deadlock-free).
fn drain_pipelined_output(
    total_candidates: usize,
    output_rx: &Receiver<IndexedContent>,
    credit_tx: &Sender<()>,
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
            // Best-effort: a disconnected credit channel just means the
            // feeder already exited (e.g. it hit a send error on
            // input_tx and gave up), not something this coordinator
            // needs to react to.
            let _credit_returned = credit_tx.send(()).ok();
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
    log_candidate_size_if_notable(entry, candidate_id);

    let mut session = match content_source.begin_read(entry, candidate_id) {
        Ok(session) => session,
        Err(err) => {
            tracing::warn!(
                candidate_id,
                path = %entry.relative_path.display(),
                error = %err,
                "content read: failed to begin read session"
            );
            return CandidateContent {
                chunks: Vec::new(),
                total_read: 0,
                digest: IncrementalDigest::new().finalize(),
                read_error: Some(err),
                read_mode: ReadMode::LogicalSnapshot,
            };
        }
    };

    let mut hasher = IncrementalDigest::new();
    let mut offset = 0_u64;
    let mut chunk_sequence = 0_u64;
    let mut total_read = 0_u64;
    let mut chunks = Vec::new();
    let mut read_error = None;
    let read_started_at = std::time::Instant::now();
    let mut last_stall_warning_at = read_started_at;

    while offset < entry.logical_size {
        warn_if_candidate_read_is_stalling(
            entry,
            candidate_id,
            total_read,
            read_started_at,
            &mut last_stall_warning_at,
        );
        match session.read_at(offset, max_chunk_bytes) {
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
    // `session` drops here, returning its pinned connection (if still
    // framing-aligned) to the pool.

    CandidateContent {
        chunks,
        total_read,
        digest: hasher.finalize(),
        read_error,
        read_mode: ReadMode::LogicalSnapshot,
    }
}

/// Logs a warning if `entry.logical_size` is implausibly large (likely
/// corrupted MFT metadata), or an informational note if it's merely
/// notably large (a real, sizeable file worth naming up front) —
/// extracted from [`read_one_candidate`] purely to keep that function's
/// cognitive complexity down; see [`IMPLAUSIBLE_LOGICAL_SIZE_BYTES`] and
/// [`NOTABLY_LARGE_LOGICAL_SIZE_BYTES`]'s own doc comments for why both
/// exist.
fn log_candidate_size_if_notable(entry: &CandidateEntry, candidate_id: u64) {
    if entry.logical_size > IMPLAUSIBLE_LOGICAL_SIZE_BYTES {
        tracing::warn!(
            candidate_id,
            path = %entry.relative_path.display(),
            declared_logical_size = entry.logical_size,
            "content read: candidate's declared logical_size is implausibly large -- this \
             usually means corrupted/stale MFT metadata for this file (e.g. a reused FRS or a \
             race with the file being resized around snapshot time), not a genuinely huge file; \
             the read below is bounded by this declared size regardless, so a corrupted value \
             here can make one candidate consume a very long time and a lot of memory"
        );
    } else if entry.logical_size >= NOTABLY_LARGE_LOGICAL_SIZE_BYTES {
        // Announced up front, before any bytes are read, so a later
        // throughput dip can always be traced back to a named candidate
        // instead of only inferred from progress-heartbeat arithmetic
        // after the fact -- real hardware has shown a large/fragmented
        // file's read slow down well before it individually crosses
        // STALL_WARNING_INTERVAL.
        tracing::info!(
            candidate_id,
            path = %entry.relative_path.display(),
            declared_logical_size = entry.logical_size,
            "content read: about to read a notably large candidate"
        );
    }
}

/// Logs a warning if this candidate's read has been running for at
/// least [`STALL_WARNING_INTERVAL`] and hasn't already warned within the
/// last [`STALL_WARNING_INTERVAL`] — extracted from
/// [`read_one_candidate`]'s read loop purely to keep that function's
/// cognitive complexity down; see its own doc comment for why this
/// exists (a corrupted `logical_size` or a stuck reader-side round trip
/// must be visible in the log, not silent for an hour).
fn warn_if_candidate_read_is_stalling(
    entry: &CandidateEntry,
    candidate_id: u64,
    total_read: u64,
    read_started_at: std::time::Instant,
    last_stall_warning_at: &mut std::time::Instant,
) {
    if read_started_at.elapsed() < STALL_WARNING_INTERVAL
        || last_stall_warning_at.elapsed() < STALL_WARNING_INTERVAL
    {
        return;
    }
    *last_stall_warning_at = std::time::Instant::now();
    tracing::warn!(
        candidate_id,
        path = %entry.relative_path.display(),
        declared_logical_size = entry.logical_size,
        total_read,
        elapsed_secs = read_started_at.elapsed().as_secs(),
        "content read: this candidate is taking unusually long -- still in progress, not \
         necessarily hung, but if this repeats every ~30s indefinitely for the same \
         candidate_id, suspect corrupted logical_size (see the warning above, if any) or a \
         stuck reader-side round trip"
    );
}
