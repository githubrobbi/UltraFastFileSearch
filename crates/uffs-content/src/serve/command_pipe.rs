// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Command pipe: job submission/resume and every control frame
//! (`WINDOW_UPDATE`/`FILE_ACK`/`JOB_CANCEL` in, `PROGRESS`/`HEARTBEAT`
//! out — the latter two not wired up yet, see the module doc's v1 gaps).
//!
//! Unlike [`super::stream`]'s data pipe (job-owned, exits once the job
//! completes), this pipe is server-lifetime: it loops accepting
//! connections for as long as the process runs, since it must remain
//! reachable across job boundaries — a `JOB_SUBMIT` for the *next* job
//! has to land somewhere even after the previous job's data pipe has
//! long since torn down.

use alloc::sync::Arc;

use tokio::net::windows::named_pipe::NamedPipeServer;
use uffs_content_protocol::COMMAND_PIPE_NAME;
use uffs_content_protocol::codec::Reader as WireReader;
use uffs_content_protocol::frame::{
    FileAck, FrameEnvelope, FrameType, JobCancel, JobSubmit, WindowUpdate,
};

use super::{ControlSignal, ServerState, stream};
use crate::job::intake::JobRequest;

/// Run the command pipe server for the process's whole lifetime.
///
/// # Errors
/// Returns an error only if the pipe itself cannot be created at all.
#[expect(
    clippy::infinite_loop,
    reason = "server-lifetime accept loop: exits only via process shutdown, matching \
              uffs-broker's own sweep-expired-leases loop"
)]
pub(super) async fn serve(state: Arc<ServerState>) -> anyhow::Result<()> {
    let mut first_instance = true;
    loop {
        let mut pipe =
            super::pipe_io::accept_connection(COMMAND_PIPE_NAME, &mut first_instance).await;
        tracing::info!("consumer connected on command pipe");
        serve_connection(&state, &mut pipe).await;
    }
}

/// Read and dispatch messages from one connected command-pipe client
/// until it disconnects or sends something malformed.
async fn serve_connection(state: &Arc<ServerState>, pipe: &mut NamedPipeServer) {
    loop {
        match super::pipe_io::read_one_message(pipe).await {
            Ok(Some(message)) => dispatch(state, &message).await,
            Ok(None) => {
                tracing::info!("consumer disconnected from command pipe");
                return;
            }
            Err(err) => {
                tracing::warn!(error = %err, "malformed command-pipe message; closing connection");
                return;
            }
        }
    }
}

/// Decode one framed message and dispatch it to the right handler.
async fn dispatch(state: &Arc<ServerState>, message: &[u8]) {
    let mut reader = WireReader::new(message);
    let (envelope, payload) = match FrameEnvelope::decode(&mut reader, u64::MAX) {
        Ok(decoded) => decoded,
        Err(err) => {
            tracing::warn!(error = %err, "failed to decode command-pipe frame envelope");
            return;
        }
    };

    match envelope.frame_type {
        FrameType::JobSubmit => handle_job_submit(state, &JobSubmit::decode(&payload)),
        FrameType::JobResume => handle_job_resume(state, envelope.job_id),
        FrameType::WindowUpdate => handle_window_update(state, envelope.job_id, &payload).await,
        FrameType::FileAck => handle_file_ack(state, envelope.job_id, &payload).await,
        FrameType::JobCancel => handle_job_cancel(state, envelope.job_id, &payload).await,
        producer_to_consumer @ (FrameType::JobBegin
        | FrameType::FileBegin
        | FrameType::ContentChunk
        | FrameType::FileEnd
        | FrameType::FileFailed
        | FrameType::FileDeferred
        | FrameType::Progress
        | FrameType::Heartbeat
        | FrameType::JobEnd) => {
            tracing::warn!(
                ?producer_to_consumer,
                "producer-to-consumer frame type on command pipe; ignoring"
            );
        }
    }
}

/// `JOB_SUBMIT`: start a new job, unless one is already active (v1's
/// documented one-job-at-a-time scope — see the crate module doc).
fn handle_job_submit(state: &Arc<ServerState>, submit: &JobSubmit) {
    {
        let active = state
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active.is_some() {
            tracing::warn!(
                "JOB_SUBMIT rejected: a job is already active (v1 serves one at a time)"
            );
            return;
        }
    }
    let request: JobRequest = match serde_json::from_slice(&submit.job_spec_json) {
        Ok(request) => request,
        Err(err) => {
            tracing::warn!(error = %err, "JOB_SUBMIT payload did not decode as a JobRequest");
            return;
        }
    };
    let run_dir = std::env::temp_dir().join(format!(
        "uffs-content-serve-{}",
        uuid::Uuid::new_v4().simple()
    ));
    if let Err(err) = std::fs::create_dir_all(&run_dir) {
        tracing::warn!(error = %err, path = %run_dir.display(), "failed to create job run dir");
        return;
    }
    stream::spawn(Arc::clone(state), request, run_dir);
}

/// `JOB_RESUME`: a reconnecting consumer naming a job it wants to keep
/// receiving. Nothing to *do* here beyond logging — the job's own data-
/// pipe accept loop ([`super::stream`]) is already waiting for exactly
/// this reconnection, and picks it up on its own the moment the
/// consumer opens a new data-pipe connection. If `job_id` doesn't match
/// (or there is no) active job, this producer process doesn't have that
/// job anymore (it crashed/restarted since) — the already-decided
/// fallback in `crate::run`'s own doc comment applies: the consumer
/// starts a fresh `JOB_SUBMIT` with a new VSS snapshot.
fn handle_job_resume(state: &Arc<ServerState>, job_id: [u8; 16]) {
    let active = state
        .active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match &*active {
        Some(job) if job.job_id == job_id => {
            tracing::info!(job_id = %super::pipe_io::hex_job_id(job_id), "JOB_RESUME acknowledged (data pipe reconnect expected)");
        }
        _ => {
            tracing::warn!(job_id = %super::pipe_io::hex_job_id(job_id), "JOB_RESUME for an unknown/no-longer-active job");
        }
    }
}

/// `WINDOW_UPDATE`: forward to the job's streaming task.
async fn handle_window_update(state: &Arc<ServerState>, job_id: [u8; 16], payload: &[u8]) {
    let mut reader = WireReader::new(payload);
    let Ok(update) = WindowUpdate::decode(&mut reader) else {
        tracing::warn!("failed to decode WINDOW_UPDATE payload");
        return;
    };
    send_signal(
        state,
        job_id,
        ControlSignal::WindowGrant(update.additional_window_bytes),
    )
    .await;
}

/// `FILE_ACK`: forward accepted acks to the job's streaming task. A
/// rejected ack (digest mismatch on the consumer's side) is logged, not
/// forwarded — the candidate stays pending and will be retransmitted,
/// matching design-doc §12.9's "a digest mismatch is REJECTED" and
/// §9.4's retransmit-on-non-ack contract.
async fn handle_file_ack(state: &Arc<ServerState>, job_id: [u8; 16], payload: &[u8]) {
    let mut reader = WireReader::new(payload);
    let Ok(ack) = FileAck::decode(&mut reader) else {
        tracing::warn!("failed to decode FILE_ACK payload");
        return;
    };
    if ack.consumer_status == uffs_content_protocol::frame::ConsumerAckStatus::Rejected {
        tracing::warn!(
            candidate_id = ack.candidate_id,
            error_code = ?ack.consumer_error_code,
            "consumer rejected candidate; leaving it pending for retransmission"
        );
        return;
    }
    send_signal(state, job_id, ControlSignal::FileAcked(ack.candidate_id)).await;
}

/// `JOB_CANCEL`: forward to the job's streaming task.
async fn handle_job_cancel(state: &Arc<ServerState>, job_id: [u8; 16], payload: &[u8]) {
    let mut reader = WireReader::new(payload);
    let reason =
        JobCancel::decode(&mut reader).map_or_else(|_| String::new(), |cancel| cancel.reason);
    send_signal(state, job_id, ControlSignal::Cancel(reason)).await;
}

/// Send `signal` to `job_id`'s streaming task, if it is the currently
/// active job. Logs and drops the signal otherwise (a control frame for
/// a job this producer process doesn't know about — already resolved,
/// or from a stale/mistaken consumer).
async fn send_signal(state: &Arc<ServerState>, job_id: [u8; 16], signal: ControlSignal) {
    let control_tx = {
        let active = state
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*active {
            Some(job) if job.job_id == job_id => job.control_tx.clone(),
            _ => {
                tracing::warn!(job_id = %super::pipe_io::hex_job_id(job_id), "control signal for an unknown/no-longer-active job");
                return;
            }
        }
    };
    if control_tx.send(signal).await.is_err() {
        tracing::warn!(job_id = %super::pipe_io::hex_job_id(job_id), "job's control channel closed; signal dropped");
    }
}
