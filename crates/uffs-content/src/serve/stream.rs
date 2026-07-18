// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Per-job streaming task: owns the data-pipe connection for exactly
//! one job, groups its frames by candidate (file-boundary resume — see
//! design-doc §6.5/§9.4), and paces emission through a
//! [`crate::job::window::WindowTracker`].
//!
//! # Why the accept loop lives *with* the job, not as a separate
//! always-on server
//!
//! A data-pipe disconnect mid-candidate must not corrupt the stream: the
//! only correct move is to stop, wait for a fresh connection, and
//! restart that candidate from its `FILE_BEGIN` (never send a partial
//! candidate split across two connections). Owning the accept loop here
//! means "waiting for a (re)connection" and "waiting for send-window
//! budget" are the same kind of pause, handled by the same loop, instead
//! of needing a separate always-on data-pipe server to coordinate with
//! whichever job happens to be active.
//!
//! # Incremental production, not whole-job materialization
//!
//! [`crate::job::vss_job::run_vss_job`] runs on a dedicated blocking
//! thread and emits each encoded frame through a bounded channel
//! ([`FRAME_CHANNEL_CAPACITY`]) as soon as it exists, instead of
//! returning the whole job's frames in one `Vec` — see that function's
//! (and `workflow::run_job`'s) own doc comments for why. This task is
//! the consumer side of that channel: it classifies each arriving frame
//! into [`Grouped`], sends a candidate's group once the send-window
//! admits it, and evicts a candidate's buffered frames the moment a
//! `FILE_ACK` confirms it's no longer needed for a resend. Combined with
//! the channel's own small bounded capacity, peak memory stays close to
//! the send-window size (a small, fixed budget) rather than growing with
//! the job's total content — never the whole job at once.
//!
//! # v1 simplifications, documented rather than silent
//!
//! - Window size is a fixed default, not negotiated per job — see
//!   [`DEFAULT_WINDOW_BYTES`].

use alloc::sync::Arc;
use std::collections::HashMap;
use std::path::PathBuf;

use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::mpsc;
use uffs_content_protocol::DATA_PIPE_NAME;
use uffs_content_protocol::frame::{FrameEnvelope, FrameType, JobBegin};

use super::{ActiveJob, ControlSignal, ServerState, pipe_io};
use crate::job::intake::JobRequest;
use crate::job::vss_job::run_vss_job;
use crate::job::window::WindowTracker;

/// Default per-job send-window budget (design-doc §13.1
/// `max_unacknowledged_bytes`). Not yet negotiated per job with the
/// consumer (`JOB_SUBMIT`'s payload is just the job spec JSON today) —
/// a fixed, generous default until per-job negotiation is worth adding.
const DEFAULT_WINDOW_BYTES: u64 = 16 * 1024 * 1024;

/// How many produced-but-not-yet-classified frames the bounded channel
/// between the blocking producer thread and this streaming task may
/// hold before the producer blocks on send. This is what keeps the
/// producer from running arbitrarily far ahead of a stalled consumer —
/// worst case, a full channel holds this many maximum-size frames
/// (~64 KiB each at the default chunk size), a few MiB, nowhere near an
/// entire job's content.
const FRAME_CHANNEL_CAPACITY: usize = 32;

/// Spawn the streaming task for a freshly submitted job.
///
/// The producer, not the consumer, assigns the real `job_id`:
/// [`run_vss_job`] already generates a fresh one internally, matching
/// every other call site in this crate, and there is no reason to plumb
/// an externally-chosen id through that already-real,
/// already-validated-on-hardware function just to satisfy a wire
/// nicety. The consumer learns the real `job_id` from `JOB_BEGIN`, the
/// first frame on the data pipe.
pub(super) fn spawn(state: Arc<ServerState>, request: JobRequest, run_dir: PathBuf) {
    tokio::spawn(async move {
        if let Err(err) = run(&state, request, &run_dir).await {
            tracing::error!(error = %err, "job streaming task failed");
        }
    });
}

/// Async body of [`spawn`].
async fn run(
    state: &Arc<ServerState>,
    request: JobRequest,
    run_dir: &std::path::Path,
) -> anyhow::Result<()> {
    let (frame_tx, mut frame_rx) = mpsc::channel::<Vec<u8>>(FRAME_CHANNEL_CAPACITY);
    let run_dir_owned = run_dir.to_path_buf();
    let job_task = tokio::task::spawn_blocking(move || {
        run_vss_job(&request, &run_dir_owned, move |frame| {
            frame_tx.blocking_send(frame).map_err(|_err| {
                std::io::Error::other("streaming task's frame receiver was dropped")
            })
        })
    });

    // JOB_BEGIN is always the first frame `run_job` emits — receive
    // (and classify) frames until it arrives, so `job_id` and
    // `candidate_count` are known before anything else happens.
    let mut grouped = Grouped::default();
    while grouped.job_begin.is_none() {
        match frame_rx.recv().await {
            Some(bytes) => grouped.classify_one_frame(bytes),
            None => break,
        }
    }
    let Some(job_begin_bytes) = grouped.job_begin.clone() else {
        return Err(surface_job_task_error(
            job_task.await,
            "producer finished without emitting JOB_BEGIN",
        ));
    };
    let (job_id, candidate_count) = decode_job_begin(&job_begin_bytes)?;

    let candidate_ids: Vec<u64> = (1..=candidate_count).collect();
    state.registry.register(job_id, candidate_ids);

    let (control_tx, mut control_rx) = mpsc::channel(32);
    set_active(state, Some(ActiveJob { job_id, control_tx }));

    let mut window = WindowTracker::new(DEFAULT_WINDOW_BYTES);
    let mut frame_rx_closed = false;

    serve_data_pipe(
        state,
        job_id,
        &job_begin_bytes,
        &mut grouped,
        &mut frame_rx,
        &mut frame_rx_closed,
        &mut control_rx,
        &mut window,
    )
    .await;
    set_active(state, None);
    state.registry.remove(job_id);

    match job_task.await {
        Ok(Ok(_outcome)) => Ok(()),
        Ok(Err(err)) => Err(err),
        Err(err) => Err(anyhow::anyhow!("streaming task panicked: {err}")),
    }
}

/// Turn the blocking job task's already-resolved result into the real
/// error that made it finish without ever emitting `JOB_BEGIN`, falling
/// back to `fallback` only if the task itself reports success (a
/// producer bug: finishing cleanly without emitting the one frame every
/// job must start with).
fn surface_job_task_error(
    job_task_result: Result<
        anyhow::Result<crate::job::workflow::JobOutcome>,
        tokio::task::JoinError,
    >,
    fallback: &str,
) -> anyhow::Error {
    match job_task_result {
        Ok(Ok(_outcome)) => anyhow::anyhow!("{fallback}"),
        Ok(Err(err)) => err,
        Err(err) => anyhow::anyhow!("streaming task panicked: {err}"),
    }
}

/// Decode a `JOB_BEGIN` frame's envelope + payload, returning
/// `(job_id, candidate_count)`.
fn decode_job_begin(frame_bytes: &[u8]) -> anyhow::Result<([u8; 16], u64)> {
    let mut reader = uffs_content_protocol::codec::Reader::new(frame_bytes);
    let (envelope, payload) = FrameEnvelope::decode(&mut reader, u64::MAX)
        .map_err(|err| anyhow::anyhow!("failed to decode JOB_BEGIN envelope: {err}"))?;
    let mut payload_reader = uffs_content_protocol::codec::Reader::new(&payload);
    let job_begin = JobBegin::decode(&mut payload_reader)
        .map_err(|err| anyhow::anyhow!("failed to decode JOB_BEGIN payload: {err}"))?;
    Ok((envelope.job_id, job_begin.candidate_count))
}

/// Outer accept loop: (re)connect the data pipe and stream `job_id`'s
/// frames over it until the job completes or is terminated. Reconnects
/// transparently on a write failure — the only way a partial candidate
/// mid-connection gets resolved is a fresh connection restarting that
/// candidate from its `FILE_BEGIN` (see the module doc's "why the accept
/// loop lives with the job" section).
#[expect(
    clippy::too_many_arguments,
    reason = "every parameter is per-job state that must persist across every reconnect on \
              this job's data pipe; bundling into a context struct would only move the \
              sprawl, since `stream_over_connection`'s own `wait_for_progress` needs several \
              of these as genuinely disjoint borrows inside a `tokio::select!` (a shared \
              context struct would force one exclusive borrow there instead)"
)]
async fn serve_data_pipe(
    state: &Arc<ServerState>,
    job_id: [u8; 16],
    job_begin: &[u8],
    grouped: &mut Grouped,
    frame_rx: &mut mpsc::Receiver<Vec<u8>>,
    frame_rx_closed: &mut bool,
    control_rx: &mut mpsc::Receiver<ControlSignal>,
    window: &mut WindowTracker,
) {
    let mut first_instance = true;
    loop {
        let mut pipe = pipe_io::accept_connection(DATA_PIPE_NAME, &mut first_instance).await;
        tracing::info!(job_id = %pipe_io::hex_job_id(job_id), "consumer connected on data pipe");

        if pipe_io::write_one_message(&mut pipe, job_begin)
            .await
            .is_err()
        {
            continue;
        }

        match stream_over_connection(
            &mut pipe,
            state,
            job_id,
            grouped,
            frame_rx,
            frame_rx_closed,
            control_rx,
            window,
        )
        .await
        {
            ConnectionOutcome::Reconnect => {}
            ConnectionOutcome::JobComplete | ConnectionOutcome::Terminated => return,
        }
    }
}

/// What ended one data-pipe connection's streaming loop.
enum ConnectionOutcome {
    /// Every candidate was acked and `JOB_END` was sent (best-effort).
    JobComplete,
    /// The consumer cancelled, the control channel died, or the producer
    /// ended without ever completing the manifest it committed to —
    /// nothing further to send or wait for.
    Terminated,
    /// The connection dropped mid-stream; the caller should accept a
    /// fresh one and resume from wherever the registry says is pending.
    Reconnect,
}

/// Stream `job_id`'s not-yet-acked candidates over `pipe` until it
/// completes, is terminated, or the connection itself fails.
#[expect(
    clippy::too_many_arguments,
    reason = "see `serve_data_pipe`'s own reason"
)]
async fn stream_over_connection(
    pipe: &mut NamedPipeServer,
    state: &Arc<ServerState>,
    job_id: [u8; 16],
    grouped: &mut Grouped,
    frame_rx: &mut mpsc::Receiver<Vec<u8>>,
    frame_rx_closed: &mut bool,
    control_rx: &mut mpsc::Receiver<ControlSignal>,
    window: &mut WindowTracker,
) -> ConnectionOutcome {
    loop {
        if state.registry.is_complete(job_id) == Some(true) {
            return send_job_end_once_complete(
                pipe,
                state,
                job_id,
                grouped,
                frame_rx,
                frame_rx_closed,
                control_rx,
                window,
            )
            .await;
        }

        let candidate_id = match next_pending_candidate_ready_to_send(
            state,
            job_id,
            grouped,
            frame_rx,
            frame_rx_closed,
            control_rx,
            window,
        )
        .await
        {
            Ok(id) => id,
            Err(outcome) => return outcome,
        };

        let Some(group) = grouped.by_candidate.get(&candidate_id) else {
            // Evicted between being selected and being sent — only
            // reachable if it was acked without ever being sent, which
            // `next_pending_candidate_ready_to_send` never allows; fail
            // safe rather than loop forever on it.
            tracing::warn!(
                candidate_id,
                "candidate group vanished before it could be sent"
            );
            state.registry.ack(job_id, candidate_id);
            continue;
        };
        let group_bytes: u64 = group.iter().map(|frame| frame.len() as u64).sum();
        if send_group(pipe, group).await.is_err() {
            tracing::info!(
                job_id = %pipe_io::hex_job_id(job_id),
                "data pipe write failed; waiting for reconnect"
            );
            return ConnectionOutcome::Reconnect;
        }
        window.record_sent(group_bytes);
    }
}

/// Every candidate is acked (the caller already checked
/// `registry.is_complete`) — wait for `JOB_END` itself to have arrived
/// from the producer (it is always the last frame emitted, but the
/// channel may not have delivered it yet) and send it.
#[expect(
    clippy::too_many_arguments,
    reason = "see `serve_data_pipe`'s own reason"
)]
async fn send_job_end_once_complete(
    pipe: &mut NamedPipeServer,
    state: &Arc<ServerState>,
    job_id: [u8; 16],
    grouped: &mut Grouped,
    frame_rx: &mut mpsc::Receiver<Vec<u8>>,
    frame_rx_closed: &mut bool,
    control_rx: &mut mpsc::Receiver<ControlSignal>,
    window: &mut WindowTracker,
) -> ConnectionOutcome {
    while grouped.job_end.is_none() {
        if let Err(outcome) = wait_for_progress(
            frame_rx,
            frame_rx_closed,
            control_rx,
            state,
            job_id,
            window,
            grouped,
        )
        .await
        {
            return outcome;
        }
        if *frame_rx_closed && grouped.job_end.is_none() {
            tracing::error!(
                job_id = %pipe_io::hex_job_id(job_id),
                "producer finished without ever emitting JOB_END"
            );
            return ConnectionOutcome::Terminated;
        }
    }
    let job_end = grouped.job_end.clone().unwrap_or_default();
    if let Err(err) = pipe_io::write_one_message(pipe, &job_end).await {
        tracing::warn!(error = %err, job_id = %pipe_io::hex_job_id(job_id), "failed to send JOB_END");
    }
    ConnectionOutcome::JobComplete
}

/// Find the next not-yet-acked candidate whose complete frame group has
/// both been produced and fits the current send window, waiting on
/// production and/or control signals for as long as neither condition
/// holds yet.
async fn next_pending_candidate_ready_to_send(
    state: &Arc<ServerState>,
    job_id: [u8; 16],
    grouped: &mut Grouped,
    frame_rx: &mut mpsc::Receiver<Vec<u8>>,
    frame_rx_closed: &mut bool,
    control_rx: &mut mpsc::Receiver<ControlSignal>,
    window: &mut WindowTracker,
) -> Result<u64, ConnectionOutcome> {
    loop {
        let Some(candidate_id) = state
            .registry
            .pending(job_id)
            .and_then(|pending| pending.into_iter().next())
        else {
            // Nothing left to send this connection (a resume race, or
            // every candidate already sent) — wait for an ack that
            // completes the job, or a cancel, before re-checking.
            wait_for_progress(
                frame_rx,
                frame_rx_closed,
                control_rx,
                state,
                job_id,
                window,
                grouped,
            )
            .await?;
            continue;
        };
        if !grouped.by_candidate.contains_key(&candidate_id) {
            // Not produced yet — wait for more frames to arrive.
            wait_for_progress(
                frame_rx,
                frame_rx_closed,
                control_rx,
                state,
                job_id,
                window,
                grouped,
            )
            .await?;
            if *frame_rx_closed && !grouped.by_candidate.contains_key(&candidate_id) {
                // The producer is done and never produced this
                // candidate's frames at all — a producer-side bug
                // (every registered candidate id came from the same
                // manifest `run_job` itself built), not something to
                // spin on forever.
                tracing::error!(
                    candidate_id,
                    job_id = %pipe_io::hex_job_id(job_id),
                    "producer finished without ever producing this candidate's frames"
                );
                return Err(ConnectionOutcome::Terminated);
            }
            continue;
        }
        let group_bytes: u64 = grouped.by_candidate.get(&candidate_id).map_or(0, |group| {
            group.iter().map(|frame| frame.len() as u64).sum()
        });
        while !window.can_admit(group_bytes) {
            wait_for_progress(
                frame_rx,
                frame_rx_closed,
                control_rx,
                state,
                job_id,
                window,
                grouped,
            )
            .await?;
        }
        return Ok(candidate_id);
    }
}

/// Wait for either the next frame from the producer (classifying it into
/// `grouped`) or the next control signal (applying it), whichever
/// arrives first. Once the producer channel has closed, stops selecting
/// on it — a closed [`mpsc::Receiver`] resolves immediately on every
/// poll, which would otherwise starve the control-signal branch in a
/// tight loop — and only waits on `control_rx` from then on.
async fn wait_for_progress(
    frame_rx: &mut mpsc::Receiver<Vec<u8>>,
    frame_rx_closed: &mut bool,
    control_rx: &mut mpsc::Receiver<ControlSignal>,
    state: &Arc<ServerState>,
    job_id: [u8; 16],
    window: &mut WindowTracker,
    grouped: &mut Grouped,
) -> Result<(), ConnectionOutcome> {
    if *frame_rx_closed {
        return match apply_next_signal(control_rx, state, job_id, window, grouped).await {
            SignalOutcome::Applied => Ok(()),
            SignalOutcome::Cancelled | SignalOutcome::ControlChannelClosed => {
                Err(ConnectionOutcome::Terminated)
            }
        };
    }
    tokio::select! {
        frame = frame_rx.recv() => {
            match frame {
                Some(bytes) => grouped.classify_one_frame(bytes),
                None => *frame_rx_closed = true,
            }
            Ok(())
        }
        signal = apply_next_signal(control_rx, state, job_id, window, grouped) => {
            match signal {
                SignalOutcome::Applied => Ok(()),
                SignalOutcome::Cancelled | SignalOutcome::ControlChannelClosed => {
                    Err(ConnectionOutcome::Terminated)
                }
            }
        }
    }
}

/// What happened when [`apply_next_signal`] waited for and applied one
/// [`ControlSignal`].
enum SignalOutcome {
    /// A `WindowGrant` or `FileAcked` signal was applied; the caller
    /// should re-check its own loop condition (window budget, pending
    /// candidates) since state just changed.
    Applied,
    /// The consumer sent `JOB_CANCEL`.
    Cancelled,
    /// The control channel closed — the command pipe's dispatcher (and
    /// with it, this job's only path to further acks/cancellation) is
    /// gone.
    ControlChannelClosed,
}

/// Block until one [`ControlSignal`] arrives and apply it: a
/// `WindowGrant` raises `window`'s ceiling, a `FileAcked` updates the
/// registry and evicts that candidate's buffered frames from `grouped`
/// (they're never needed again — an ack is a promise the consumer never
/// needs a resend), a `Cancel` is reported (not applied here — the
/// caller owns job teardown).
async fn apply_next_signal(
    control_rx: &mut mpsc::Receiver<ControlSignal>,
    state: &Arc<ServerState>,
    job_id: [u8; 16],
    window: &mut WindowTracker,
    grouped: &mut Grouped,
) -> SignalOutcome {
    let Some(signal) = control_rx.recv().await else {
        return SignalOutcome::ControlChannelClosed;
    };
    match signal {
        ControlSignal::WindowGrant(additional_bytes) => {
            window.grant(additional_bytes);
            SignalOutcome::Applied
        }
        ControlSignal::FileAcked(candidate_id) => {
            state.registry.ack(job_id, candidate_id);
            grouped.by_candidate.remove(&candidate_id);
            SignalOutcome::Applied
        }
        ControlSignal::Cancel(reason) => {
            tracing::info!(job_id = %pipe_io::hex_job_id(job_id), reason, "job cancelled by consumer");
            SignalOutcome::Cancelled
        }
    }
}

/// Write every frame in one candidate's group, in order.
async fn send_group(pipe: &mut NamedPipeServer, group: &[Vec<u8>]) -> anyhow::Result<()> {
    for frame in group {
        pipe_io::write_one_message(pipe, frame).await?;
    }
    Ok(())
}

/// Incrementally accumulated frame buckets: the leading `JOB_BEGIN`, each
/// not-yet-acked candidate's frames received so far (or complete, in
/// manifest order), and the trailing `JOB_END` — built one frame at a
/// time via [`Grouped::classify_one_frame`] as frames arrive from the
/// producer, rather than all at once from a prebuilt slice (see the
/// module doc comment).
#[derive(Default)]
struct Grouped {
    /// The job's `JOB_BEGIN` frame, once received.
    job_begin: Option<Vec<u8>>,
    /// Every other not-yet-evicted frame, bucketed by the `candidate_id`
    /// it belongs to, in arrival (= manifest emission) order. A
    /// candidate's entry is removed once `FILE_ACK` confirms it's no
    /// longer needed for a resend (see [`apply_next_signal`]).
    by_candidate: HashMap<u64, Vec<Vec<u8>>>,
    /// The job's `JOB_END` frame, once received (always the last frame
    /// the producer emits).
    job_end: Option<Vec<u8>>,
    /// Which candidate a non-`FILE_BEGIN` frame belongs to — carried
    /// across calls to [`Self::classify_one_frame`], mirroring the local
    /// `current` variable a whole-slice classifier would keep instead.
    current_candidate: Option<u64>,
}

impl Grouped {
    /// Classify one already-decoded-length frame into this job's
    /// buckets, exactly matching `run_job`'s own emission order
    /// (`JOB_BEGIN` first, `JOB_END` last, every per-candidate frame
    /// group in between starting with `FILE_BEGIN`).
    fn classify_one_frame(&mut self, frame_bytes: Vec<u8>) {
        let mut reader = uffs_content_protocol::codec::Reader::new(&frame_bytes);
        let Ok((envelope, payload)) = FrameEnvelope::decode(&mut reader, u64::MAX) else {
            return;
        };
        match envelope.frame_type {
            FrameType::JobBegin => self.job_begin = Some(frame_bytes),
            FrameType::JobEnd => self.job_end = Some(frame_bytes),
            FrameType::FileBegin => {
                let mut payload_reader = uffs_content_protocol::codec::Reader::new(&payload);
                if let Ok(file_begin) =
                    uffs_content_protocol::frame::FileBegin::decode(&mut payload_reader)
                {
                    self.current_candidate = Some(file_begin.candidate_id);
                    self.by_candidate
                        .entry(file_begin.candidate_id)
                        .or_default()
                        .push(frame_bytes);
                }
            }
            FrameType::ContentChunk
            | FrameType::FileEnd
            | FrameType::FileFailed
            | FrameType::FileDeferred
            | FrameType::FileAck
            | FrameType::Progress
            | FrameType::Heartbeat
            | FrameType::JobCancel
            | FrameType::WindowUpdate
            | FrameType::JobResume
            | FrameType::JobSubmit => {
                if let Some(candidate_id) = self.current_candidate {
                    self.by_candidate
                        .entry(candidate_id)
                        .or_default()
                        .push(frame_bytes);
                }
            }
        }
    }
}

/// Set (or clear) the server's single active-job slot.
fn set_active(state: &Arc<ServerState>, active: Option<ActiveJob>) {
    let mut slot = state
        .active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = active;
}

#[cfg(test)]
mod tests {
    use uffs_content_protocol::frame::{
        FileBegin, FrameEnvelope, FrameType, JobBegin, PROTOCOL_VERSION, ReadMode,
    };
    use uffs_content_protocol::manifest::AuthorizationMode;
    use uffs_content_protocol::path_encoding::WindowsPath;

    use super::Grouped;

    const JOB_ID: [u8; 16] = [7; 16];

    fn encode(frame_sequence: u64, frame_type: FrameType, payload: &[u8]) -> Vec<u8> {
        FrameEnvelope {
            protocol_version: PROTOCOL_VERSION,
            frame_type,
            flags: 0,
            job_id: JOB_ID,
            frame_sequence,
        }
        .encode(payload)
    }

    fn file_begin_frame(sequence: u64, candidate_id: u64) -> Vec<u8> {
        let file_begin = FileBegin {
            candidate_id,
            file_reference: candidate_id,
            path: WindowsPath::from_str_lossless("file.bin"),
            logical_size: 0,
            mtime: 0,
            read_mode: ReadMode::LogicalSnapshot,
            attempt_number: 1,
            content_object_id: None,
        };
        encode(sequence, FrameType::FileBegin, &file_begin.encode())
    }

    #[test]
    fn classify_one_frame_buckets_job_begin_and_job_end_separately() {
        let mut grouped = Grouped::default();
        let job_begin = JobBegin {
            job_id: JOB_ID,
            source_id: [0; 16],
            snapshot_id: Vec::new(),
            snapshot_created_at: 0,
            manifest_digest: [0; 32],
            candidate_count: 0,
            authorization_mode: AuthorizationMode::AdminExport,
            ordering: uffs_content_protocol::frame::FrameOrdering::None,
            content_semantics: uffs_content_protocol::frame::ContentSemantics::UnnamedLogicalStream,
            digest_algorithm: uffs_content_protocol::frame::DigestAlgorithm::Blake3,
            max_chunk_bytes: 65536,
            max_content_delivery_bytes: None,
        };
        let job_begin_bytes = encode(0, FrameType::JobBegin, &job_begin.encode());
        grouped.classify_one_frame(job_begin_bytes.clone());
        assert_eq!(grouped.job_begin, Some(job_begin_bytes));
        assert!(grouped.by_candidate.is_empty());
        assert_eq!(grouped.job_end, None);
    }

    #[test]
    fn classify_one_frame_groups_frames_under_the_most_recent_file_begin() {
        let mut grouped = Grouped::default();
        let begin_1 = file_begin_frame(0, 1);
        let chunk_1 = encode(1, FrameType::ContentChunk, b"chunk-for-candidate-1");
        let begin_2 = file_begin_frame(2, 2);
        let chunk_2 = encode(3, FrameType::ContentChunk, b"chunk-for-candidate-2");

        for frame in [
            begin_1.clone(),
            chunk_1.clone(),
            begin_2.clone(),
            chunk_2.clone(),
        ] {
            grouped.classify_one_frame(frame);
        }

        assert_eq!(grouped.by_candidate.get(&1), Some(&vec![begin_1, chunk_1]));
        assert_eq!(grouped.by_candidate.get(&2), Some(&vec![begin_2, chunk_2]));
    }

    #[test]
    fn classify_one_frame_ignores_undecodable_bytes() {
        let mut grouped = Grouped::default();
        grouped.classify_one_frame(b"not a valid frame".to_vec());
        assert_eq!(grouped.job_begin, None);
        assert!(grouped.by_candidate.is_empty());
        assert_eq!(grouped.job_end, None);
    }
}
