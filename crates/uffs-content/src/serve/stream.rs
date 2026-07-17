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
//! # v1 simplifications, documented rather than silent
//!
//! - No incremental production: [`crate::job::vss_job::run_vss_job`] already
//!   builds the whole job's frames synchronously before this task starts pacing
//!   them out. A future revision that streams while reading would let a very
//!   large job start delivering bytes sooner, but does not change the
//!   resume/backpressure contract this module implements.
//! - Window size is a fixed default, not negotiated per job — see
//!   [`DEFAULT_WINDOW_BYTES`].

use alloc::sync::Arc;
use std::collections::HashMap;
use std::path::PathBuf;

use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::mpsc;
use uffs_content_protocol::DATA_PIPE_NAME;
use uffs_content_protocol::frame::{FrameEnvelope, FrameType};

use super::{ActiveJob, ControlSignal, ServerState, pipe_io};
use crate::job::intake::JobRequest;
use crate::job::vss_job::run_vss_job;
use crate::job::window::WindowTracker;

/// Default per-job send-window budget (design-doc §13.1
/// `max_unacknowledged_bytes`). Not yet negotiated per job with the
/// consumer (`JOB_SUBMIT`'s payload is just the job spec JSON today) —
/// a fixed, generous default until per-job negotiation is worth adding.
const DEFAULT_WINDOW_BYTES: u64 = 16 * 1024 * 1024;

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
    let run_dir_owned = run_dir.to_path_buf();
    let outcome = tokio::task::spawn_blocking(move || run_vss_job(&request, &run_dir_owned))
        .await
        .map_err(|err| anyhow::anyhow!("streaming task panicked: {err}"))??;

    let job_id = outcome.job_id;
    let candidate_ids: Vec<u64> = (1..=outcome.run_summary.candidate_count).collect();
    state.registry.register(job_id, candidate_ids);

    let (control_tx, mut control_rx) = mpsc::channel(32);
    set_active(state, Some(ActiveJob { job_id, control_tx }));

    let grouped = group_frames_by_candidate(&outcome.frames);
    let mut window = WindowTracker::new(DEFAULT_WINDOW_BYTES);

    serve_data_pipe(state, job_id, &grouped, &mut control_rx, &mut window).await;
    set_active(state, None);
    state.registry.remove(job_id);
    Ok(())
}

/// Outer accept loop: (re)connect the data pipe and stream `job_id`'s
/// frames over it until the job completes or is terminated. Reconnects
/// transparently on a write failure — the only way a partial candidate
/// mid-connection gets resolved is a fresh connection restarting that
/// candidate from its `FILE_BEGIN` (see the module doc's "why the accept
/// loop lives with the job" section).
async fn serve_data_pipe(
    state: &Arc<ServerState>,
    job_id: [u8; 16],
    grouped: &Grouped,
    control_rx: &mut mpsc::Receiver<ControlSignal>,
    window: &mut WindowTracker,
) {
    let mut first_instance = true;
    loop {
        let mut pipe = pipe_io::accept_connection(DATA_PIPE_NAME, &mut first_instance).await;
        tracing::info!(job_id = %pipe_io::hex_job_id(job_id), "consumer connected on data pipe");

        if pipe_io::write_one_message(&mut pipe, &grouped.job_begin)
            .await
            .is_err()
        {
            continue;
        }

        match stream_over_connection(&mut pipe, state, job_id, grouped, control_rx, window).await {
            ConnectionOutcome::Reconnect => {}
            ConnectionOutcome::JobComplete | ConnectionOutcome::Terminated => return,
        }
    }
}

/// What ended one data-pipe connection's streaming loop.
enum ConnectionOutcome {
    /// Every candidate was acked and `JOB_END` was sent (best-effort).
    JobComplete,
    /// The consumer cancelled, or the control channel died — nothing
    /// further to send or wait for.
    Terminated,
    /// The connection dropped mid-stream; the caller should accept a
    /// fresh one and resume from wherever the registry says is pending.
    Reconnect,
}

/// Stream `job_id`'s not-yet-acked candidates over `pipe` until it
/// completes, is terminated, or the connection itself fails.
async fn stream_over_connection(
    pipe: &mut NamedPipeServer,
    state: &Arc<ServerState>,
    job_id: [u8; 16],
    grouped: &Grouped,
    control_rx: &mut mpsc::Receiver<ControlSignal>,
    window: &mut WindowTracker,
) -> ConnectionOutcome {
    loop {
        if state.registry.is_complete(job_id) == Some(true) {
            if let Err(err) = pipe_io::write_one_message(pipe, &grouped.job_end).await {
                tracing::warn!(error = %err, job_id = %pipe_io::hex_job_id(job_id), "failed to send JOB_END");
            }
            return ConnectionOutcome::JobComplete;
        }
        let (group, group_bytes) =
            match next_group_to_send(state, job_id, grouped, control_rx, window).await {
                Ok(pair) => pair,
                Err(outcome) => return outcome,
            };
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

/// Pick the next not-yet-acked candidate's frame group, waiting on
/// window budget and control signals (`WINDOW_UPDATE`/`FILE_ACK`) for as
/// long as nothing is ready to send yet.
async fn next_group_to_send<'grouped>(
    state: &Arc<ServerState>,
    job_id: [u8; 16],
    grouped: &'grouped Grouped,
    control_rx: &mut mpsc::Receiver<ControlSignal>,
    window: &mut WindowTracker,
) -> Result<(&'grouped [Vec<u8>], u64), ConnectionOutcome> {
    loop {
        let Some(candidate_id) = state
            .registry
            .pending(job_id)
            .and_then(|pending| pending.into_iter().next())
        else {
            // Nothing left to send this connection (a resume race, or
            // every candidate already sent) — wait for an ack that
            // completes the job, or a cancel, before re-checking.
            wait_for_progress(control_rx, state, job_id, window).await?;
            continue;
        };
        let Some(group) = grouped.by_candidate.get(&candidate_id) else {
            // A candidate id the manifest never actually produced frames
            // for (shouldn't happen — every registered id comes from the
            // same manifest — but fail safe rather than looping forever
            // on it).
            tracing::warn!(candidate_id, "no frame group for pending candidate id");
            state.registry.ack(job_id, candidate_id);
            continue;
        };
        let group_bytes: u64 = group.iter().map(|frame| frame.len() as u64).sum();
        while !window.can_admit(group_bytes) {
            wait_for_progress(control_rx, state, job_id, window).await?;
        }
        return Ok((group, group_bytes));
    }
}

/// Wait for and apply one control signal, collapsing the two "streaming
/// cannot continue" cases ([`SignalOutcome::Cancelled`] and
/// [`SignalOutcome::ControlChannelClosed`]) into a single `Err` the
/// caller propagates via `?`/`return`.
async fn wait_for_progress(
    control_rx: &mut mpsc::Receiver<ControlSignal>,
    state: &Arc<ServerState>,
    job_id: [u8; 16],
    window: &mut WindowTracker,
) -> Result<(), ConnectionOutcome> {
    match apply_next_signal(control_rx, state, job_id, window).await {
        SignalOutcome::Applied => Ok(()),
        SignalOutcome::Cancelled | SignalOutcome::ControlChannelClosed => {
            Err(ConnectionOutcome::Terminated)
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
/// registry, a `Cancel` is reported (not applied here — the caller owns
/// job teardown).
async fn apply_next_signal(
    control_rx: &mut mpsc::Receiver<ControlSignal>,
    state: &Arc<ServerState>,
    job_id: [u8; 16],
    window: &mut WindowTracker,
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
            SignalOutcome::Applied
        }
        ControlSignal::Cancel(reason) => {
            tracing::info!(job_id = %pipe_io::hex_job_id(job_id), reason, "job cancelled by consumer");
            SignalOutcome::Cancelled
        }
    }
}

/// Group `frames` into the leading `JOB_BEGIN`, one frame list per
/// candidate (in manifest order), and the trailing `JOB_END` —
/// `run_job`'s own emission order (`push_frame(FrameType::JobBegin, ..)`
/// first, `push_frame(FrameType::JobEnd, ..)` last, every per-candidate
/// frame group in between starting with `FILE_BEGIN`) makes this a
/// single linear pass.
struct Grouped {
    /// The job's `JOB_BEGIN` frame, ready to send as-is.
    job_begin: Vec<u8>,
    /// Every other frame, bucketed by the `candidate_id` it belongs to,
    /// in manifest emission order.
    by_candidate: HashMap<u64, Vec<Vec<u8>>>,
    /// The job's `JOB_END` frame, ready to send as-is.
    job_end: Vec<u8>,
}

/// Split `frames` (one job's complete, already-produced frame list) into
/// [`Grouped`]'s three buckets: the leading `JOB_BEGIN`, one frame group
/// per candidate, and the trailing `JOB_END`.
fn group_frames_by_candidate(frames: &[Vec<u8>]) -> Grouped {
    let mut by_candidate: HashMap<u64, Vec<Vec<u8>>> = HashMap::new();
    let mut job_begin = Vec::new();
    let mut job_end = Vec::new();
    let mut current: Option<u64> = None;

    for frame_bytes in frames {
        let mut reader = uffs_content_protocol::codec::Reader::new(frame_bytes);
        let Ok((envelope, payload)) = FrameEnvelope::decode(&mut reader, u64::MAX) else {
            continue;
        };
        match envelope.frame_type {
            FrameType::JobBegin => job_begin.clone_from(frame_bytes),
            FrameType::JobEnd => job_end.clone_from(frame_bytes),
            FrameType::FileBegin => {
                let mut payload_reader = uffs_content_protocol::codec::Reader::new(&payload);
                if let Ok(file_begin) =
                    uffs_content_protocol::frame::FileBegin::decode(&mut payload_reader)
                {
                    current = Some(file_begin.candidate_id);
                    by_candidate
                        .entry(file_begin.candidate_id)
                        .or_default()
                        .push(frame_bytes.clone());
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
                if let Some(candidate_id) = current {
                    by_candidate
                        .entry(candidate_id)
                        .or_default()
                        .push(frame_bytes.clone());
                }
            }
        }
    }

    Grouped {
        job_begin,
        by_candidate,
        job_end,
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
