// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! End-to-end VSS-backed job execution — the real production path.
//!
//! Ties every piece built for UFI.1/UFI.2 together: lease the drive(s)
//! a job's root touches, spin up the ephemeral target-selection daemon,
//! enumerate candidates against it, spawn the privileged content Reader,
//! stream content through [`super::workflow::run_job`], and tear
//! everything down — in the right order (content Reader/leases outlive
//! candidate enumeration; see
//! [`super::vss_orchestrator::EphemeralJobResources`] for why daemon and leases
//! are bundled into one teardown step).
//!
//! Windows-only: every piece this wires together already is.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context as _, Result};

use super::candidate_source::VssCandidateSource;
use super::content_source::VssContentSource;
use super::intake::JobRequest;
use super::reader_client::ContentReader;
use super::vss_orchestrator;
use super::workflow::{JobOutcome, run_job};

/// Run `request` end to end against a real VSS snapshot.
///
/// Every encoded frame is passed to `emit_frame` as soon as it's
/// produced — see [`run_job`]'s own doc comment for why this is a
/// callback rather than a returned `Vec`.
///
/// # Errors
/// Returns an error if any VSS lease, ephemeral daemon spawn, or
/// content Reader spawn step fails, or if the underlying `run_job` call
/// fails. Every resource successfully acquired before a failure is
/// released best-effort before returning.
pub fn run_vss_job<F>(request: &JobRequest, run_dir: &Path, emit_frame: F) -> Result<JobOutcome>
where
    F: FnMut(Vec<u8>) -> std::io::Result<()>,
{
    let job_id = *uuid::Uuid::new_v4().as_bytes();
    let ephemeral_id = uuid::Uuid::new_v4().simple().to_string();

    let resources = vss_orchestrator::prepare_ephemeral_daemon_for_roots(
        job_id,
        &[request.root.as_path()],
        &ephemeral_id,
    )
    .context("failed to lease VSS snapshot(s) and spawn the target-selection daemon")?;

    let drive_to_lease: HashMap<char, u64> = resources
        .leases
        .iter()
        .map(|lease| (lease.drive_letter, lease.lease_id))
        .collect();
    let candidate_source = VssCandidateSource::new(request, &resources.daemon, drive_to_lease);

    let devices_for_reader: Vec<(String, u64)> = resources
        .leases
        .iter()
        .map(|lease| (lease.device_path.clone(), lease.lease_id))
        .collect();
    let content_reader = ContentReader::spawn(job_id, &devices_for_reader)
        .context("failed to spawn the content reader")?;
    let content_source = VssContentSource::new(content_reader);

    let result = run_job(
        request,
        &candidate_source,
        &content_source,
        run_dir,
        emit_frame,
    )
    .context("run_job failed");

    // Drop the candidate source first (releases its borrow of
    // `resources.daemon`, which `resources.teardown()` below needs to
    // consume by value), then tear down the Reader and the
    // daemon/leases explicitly so a failed teardown is observable
    // rather than silently swallowed by `Drop`.
    drop(candidate_source);
    if let Err(err) = content_source.shutdown() {
        tracing::warn!(error = %err, "failed to fully tear down content reader");
    }
    if let Err(err) = resources.teardown() {
        tracing::warn!(error = %err, "failed to fully tear down VSS job resources");
    }

    result
}
