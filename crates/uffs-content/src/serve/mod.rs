// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

#![cfg(windows)]

//! Two-pipe transport server: the real entry point an external consumer
//! (e.g. Docenta) connects to.
//!
//! Two named pipes, per the design conversation this implements:
//!
//! - [`uffs_content_protocol::DATA_PIPE_NAME`] — the content stream itself
//!   (`JOB_BEGIN`/`FILE_BEGIN`/`CONTENT_CHUNK`/.../`JOB_END`), producer to
//!   consumer, paced by a [`crate::job::window::WindowTracker`]. Owned by the
//!   job's own streaming task ([`stream`]) — see that module's doc comment for
//!   why "accept loop lives with the job, not as a separate always-on server"
//!   is what makes reconnect-and-resume correct.
//! - [`uffs_content_protocol::COMMAND_PIPE_NAME`] — job submission/resume,
//!   `WINDOW_UPDATE`/`FILE_ACK`/`JOB_CANCEL` (consumer to producer), and
//!   `PROGRESS`/`HEARTBEAT` (producer to consumer). Always low-volume, so it
//!   stays responsive no matter how backed up the data pipe is.
//!
//! # v1 scope: one job at a time
//!
//! This server serves exactly one active job at a time —
//! [`ServerState::active`] is a single slot, not a map. A second
//! `JOB_SUBMIT` while a job is already running is rejected. This is a
//! deliberate, documented scope cut (not a design ceiling): concurrent
//! multi-job serving would need the data pipe to demultiplex frames by
//! `job_id` (today one connection carries exactly one job's stream) and
//! the command pipe to route control signals to the right job's task
//! instead of "the" active job. Revisit if a real multi-job requirement
//! shows up.

mod command_pipe;
mod pipe_io;
mod stream;

use alloc::sync::Arc;
use std::sync::Mutex;

use tokio::sync::mpsc;

use crate::job::registry::JobRegistry;

/// A signal the command pipe delivers to the active job's streaming task
/// ([`stream::spawn`]).
pub(crate) enum ControlSignal {
    /// `WINDOW_UPDATE`: raise the send budget by this many bytes.
    WindowGrant(u64),
    /// `FILE_ACK`: candidate id the consumer has durably accepted.
    FileAcked(u64),
    /// `JOB_CANCEL`: stop streaming. The `String` is a diagnostic reason
    /// only.
    Cancel(String),
}

/// Handle to the currently-active job, from the command pipe's point of
/// view.
struct ActiveJob {
    /// The producer-assigned id for this job (see [`stream::spawn`]'s doc
    /// comment for why the producer, not the consumer, assigns it).
    job_id: [u8; 16],
    /// Delivers [`ControlSignal`]s to the streaming task.
    control_tx: mpsc::Sender<ControlSignal>,
}

/// Server-wide shared state, held behind an `Arc` by both the command
/// pipe and every job's streaming task.
struct ServerState {
    /// Resume state for whichever job is (or was) active.
    registry: Arc<JobRegistry>,
    /// The single active job's control handle, if a job is running. See
    /// the module doc for why this is one slot, not a map, in v1.
    active: Mutex<Option<ActiveJob>>,
}

/// Run the command pipe server for the process's whole lifetime. Each
/// `JOB_SUBMIT` spawns a job-owned data-pipe streaming task
/// ([`stream::spawn`]) alongside it.
///
/// # Errors
/// Returns an error only if the command pipe itself cannot be created at
/// all.
pub(crate) fn run() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve())
}

/// Async body of [`run`].
async fn serve() -> anyhow::Result<()> {
    let state = Arc::new(ServerState {
        registry: Arc::new(JobRegistry::new()),
        active: Mutex::new(None),
    });
    command_pipe::serve(state).await
}
