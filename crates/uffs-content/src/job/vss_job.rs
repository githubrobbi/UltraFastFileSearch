// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! End-to-end VSS-backed job execution — the real production path.
//!
//! Ties every piece built for UFI.1/UFI.2 together: lease the drive(s)
//! a job's root touches, spin up the ephemeral target-selection daemon,
//! enumerate candidates against it, spawn the privileged content Reader,
//! stream content through [`super::workflow::run_job`], and tear
//! everything down — in the right order (content Reader/leases outlive
//! candidate enumeration; see `EphemeralJobResources`
//! ([`super::vss_orchestrator`]) for why daemon and leases
//! are bundled into one teardown step).
//!
//! Windows-only: every piece this wires together already is.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

use super::candidate_source::VssCandidateSource;
use super::content_source::VssContentSource;
use super::intake::JobRequest;
use super::reader_client::{CONNECTIONS_PER_DRIVE, ContentReader};
use super::vss_orchestrator;
use super::workflow::{JobOutcome, ReadConcurrency, run_job};

/// Run `request` end to end against a real VSS snapshot.
///
/// Every encoded frame is passed to `emit_frame` as soon as it's
/// produced — see [`run_job`]'s own doc comment for why this is a
/// callback rather than a returned `Vec`.
///
/// `request.roots` is used as given if non-empty; if empty, this job
/// defaults to every local NTFS drive (`uffs_mft::detect_ntfs_drives`) —
/// the same auto-discovery `uffsd` itself falls back to when started
/// with no `--drive` flag.
///
/// # Errors
/// Returns an error if root resolution finds no local NTFS drives to
/// default to, any VSS lease, ephemeral daemon spawn, or content Reader
/// spawn step fails, or if the underlying `run_job` call fails. Every
/// resource successfully acquired before a failure is released
/// best-effort before returning.
pub fn run_vss_job<F>(request: &JobRequest, run_dir: &Path, emit_frame: F) -> Result<JobOutcome>
where
    F: FnMut(Vec<u8>) -> std::io::Result<()> + Send,
{
    let job_id = *uuid::Uuid::new_v4().as_bytes();
    let ephemeral_id = uuid::Uuid::new_v4().simple().to_string();

    let roots = resolve_roots(request)?;
    let root_paths: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();

    let resources =
        vss_orchestrator::prepare_ephemeral_daemon_for_roots(job_id, &root_paths, &ephemeral_id)
            .context("failed to lease VSS snapshot(s) and spawn the target-selection daemon")?;

    let drive_to_lease: HashMap<char, u64> = resources
        .leases
        .iter()
        .map(|lease| (lease.drive_letter, lease.lease_id))
        .collect();
    // The resolved (never-empty) root list is what `run_job`'s own
    // enumeration loop must iterate, not whatever `request.roots`
    // originally said (which may have been empty, relying on the
    // default-to-all-drives resolution above).
    let mut resolved_request = request.clone();
    resolved_request.roots = roots;
    let candidate_source =
        VssCandidateSource::new(&resolved_request, &resources.daemon, drive_to_lease);

    // Per-drive read concurrency: an HDD gets exactly one connection
    // (read its candidates strictly one at a time, in the order they
    // were enumerated — approximating sequential disk access instead of
    // seek-thrashing between concurrent reads on a spinning disk), an
    // NVMe/SSD gets `CONNECTIONS_PER_DRIVE` (no seek penalty to protect,
    // and it benefits from many reads in flight). See
    // `reader_client::CONNECTIONS_PER_DRIVE` and
    // `workflow::ReadConcurrency`'s doc comments for both sides of this.
    let mut devices_for_reader: Vec<(String, u64, usize)> =
        Vec::with_capacity(resources.leases.len());
    let mut read_concurrency = ReadConcurrency::new(1);
    for lease in &resources.leases {
        let connections = drive_read_connections(lease.drive_letter);
        tracing::info!(
            drive = %lease.drive_letter,
            connections,
            "content read: per-drive connection count"
        );
        read_concurrency.set(lease.lease_id, connections);
        devices_for_reader.push((lease.device_path.clone(), lease.lease_id, connections));
    }

    let content_reader = ContentReader::spawn(job_id, &devices_for_reader)
        .context("failed to spawn the content reader")?;
    let content_source = VssContentSource::new(content_reader);

    // JOB_BEGIN carries only one job-level snapshot_id/snapshot_created_at
    // pair (see `JobBegin`'s own doc comment), so a multi-drive job's
    // provenance is necessarily a representative one, not one per drive.
    // The first leased drive is as good a choice as any: every lease for
    // a job is taken back-to-back at job start (see
    // `vss_orchestrator::prepare_ephemeral_daemon_for_roots`), so their
    // snapshot_created_at values differ by at most the lease loop's own
    // wall-clock time, not something a consumer's temporal-memory use case
    // would notice.
    let (snapshot_id, snapshot_created_at) = resources
        .leases
        .first()
        .map(|lease| (lease.snapshot_id.clone(), lease.snapshot_created_at_unix_ms))
        .unwrap_or_default();

    let result = run_job(
        &resolved_request,
        &candidate_source,
        &content_source,
        run_dir,
        &read_concurrency,
        &snapshot_id,
        snapshot_created_at,
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

/// How many concurrent content-read connections `drive_letter`'s lease
/// should get: [`CONNECTIONS_PER_DRIVE`] for a high-performance medium
/// (NVMe/SSD — no seek penalty, benefits from many reads in flight), or
/// exactly `1` for anything else (HDD, removable, virtual, or a type
/// that couldn't be determined) — see [`CONNECTIONS_PER_DRIVE`]'s doc
/// comment for why concurrency `1` is the correct choice for a
/// seek-bound medium, not just a conservative fallback.
fn drive_read_connections(drive_letter: char) -> usize {
    let Ok(letter) = uffs_mft::platform::DriveLetter::parse(drive_letter) else {
        // Unreachable in practice: `drive_letter` came from a lease VSS
        // already accepted for this exact letter. Fall back to the safe
        // (sequential) choice rather than panicking.
        return 1;
    };
    if uffs_mft::platform::detect_drive_type(letter).is_high_performance() {
        CONNECTIONS_PER_DRIVE
    } else {
        1
    }
}

/// Resolve `request.roots`: as given if non-empty, else one root per
/// local NTFS drive on this machine — the consumer's "search everything"
/// default, matching `uffsd`'s own no-`--drive`-flag fallback
/// (`uffs_mft::detect_ntfs_drives`).
///
/// # Errors
/// Returns an error if `request.roots` is empty and no local NTFS drive
/// is found to default to.
fn resolve_roots(request: &JobRequest) -> Result<Vec<PathBuf>> {
    if !request.roots.is_empty() {
        return Ok(request.roots.clone());
    }
    let drives = uffs_mft::detect_ntfs_drives();
    anyhow::ensure!(
        !drives.is_empty(),
        "no roots given and no local NTFS drive found to default to"
    );
    Ok(drives
        .into_iter()
        .map(|letter| PathBuf::from(format!("{}:\\", letter.as_char())))
        .collect())
}
