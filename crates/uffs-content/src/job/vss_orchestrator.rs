// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Ties [`super::snapshot_client`] and [`super::ephemeral_daemon`] together.
//!
//! Leases one VSS snapshot per distinct drive a job's roots touch, then
//! spawns a single ephemeral `uffsd` instance covering all of them — per
//! the user's direct design decision: "create a VSS for each drive
//! (multiple) ... then when all done have the UFFS-content tool spin up
//! one instance of the daemon covering all the VSS MFT copies."

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context as _, Result};
use uffs_broker_protocol::snapshot_manager::{SnapshotManagerErrorCode, VolumeIdentity};

use super::ephemeral_daemon::EphemeralDaemon;
use super::snapshot_client::{self, BrokerRejectedCreate};

/// `VSS_E_VOLUME_NOT_SUPPORTED` — VSS permanently refuses to snapshot
/// this volume (observed in practice on removable/USB media). Distinct
/// from `uffs-vss-requestor`'s `RETRYABLE_HRESULTS`: this is
/// deliberately *not* in that list, and a job should skip the drive
/// rather than fail outright, since it will never become supported by
/// retrying.
const VSS_E_VOLUME_NOT_SUPPORTED: i32 = 0x8004_230C_u32.cast_signed();

/// Default VSS snapshot lease lifetime.
///
/// Generous relative to a single ingest job's expected wall-clock time;
/// revisit once real job-duration telemetry exists (no policy schema
/// for this yet — see [`DEFAULT_POLICY_ID`]).
const DEFAULT_LEASE_LIFETIME_SECS: u64 = 3600;

/// Placeholder policy id — the Broker's authorization-policy schema
/// doesn't exist yet; every lease request uses this until it does.
const DEFAULT_POLICY_ID: u32 = 0;

/// One leased drive: the snapshot device path, the drive letter it was
/// leased from, and the lease id — everything a caller needs to build
/// either the daemon's `--device <path>=<letter>` args or the Reader's
/// `--device <path>=<lease_id>` args, or to correlate a query result
/// row's drive letter back to the lease that produced it.
pub(crate) struct LeasedDrive {
    /// VSS snapshot device path (e.g.
    /// `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`).
    pub(crate) device_path: String,
    /// Drive letter the snapshot was taken from.
    pub(crate) drive_letter: char,
    /// This drive's lease id.
    pub(crate) lease_id: u64,
    /// Opaque VSS snapshot identifier, as reported by the Broker at
    /// lease time. Carried through to `JOB_BEGIN.snapshot_id` (see
    /// `super::vss_job::run_vss_job`) — one drive's worth of real
    /// snapshot provenance, since the wire protocol has only one
    /// job-level `snapshot_id`/`snapshot_created_at` pair even though a
    /// job may lease several drives.
    pub(crate) snapshot_id: Vec<u8>,
    /// This drive's snapshot creation time, Unix milliseconds.
    pub(crate) snapshot_created_at_unix_ms: i64,
}

/// Every live resource this orchestration step produced.
///
/// The daemon and the leases have different intended lifetimes: the
/// daemon is only needed for target-selection queries (`enumerate`) and
/// can be torn down as soon as that's done, while the leases must stay
/// alive for the whole job (content reading happens against the same
/// snapshots afterward). This struct bundles both anyway and tears them
/// down together via [`Self::teardown`] — a v1 simplification (the
/// daemon's memory stays resident through content-reading unnecessarily)
/// documented here rather than silently accepted; revisit if daemon
/// memory footprint during long content-reading phases matters in
/// practice.
pub(crate) struct EphemeralJobResources {
    /// The running ephemeral daemon covering every leased drive.
    pub(crate) daemon: EphemeralDaemon,
    /// Every drive this job leased, in lease order.
    pub(crate) leases: Vec<LeasedDrive>,
}

impl EphemeralJobResources {
    /// Tear down the daemon, then release every lease. Daemon teardown
    /// runs first — releasing a lease out from under a still-running
    /// daemon would pull the volume out from under its loaded index.
    /// Lease release is best-effort per-lease (a single failed release
    /// is logged, not fatal — see [`release_all_leases`]).
    ///
    /// # Errors
    /// Returns an error if the daemon couldn't be killed. Lease-release
    /// failures are logged, not propagated.
    pub(crate) fn teardown(self) -> Result<()> {
        self.daemon.shutdown()?;
        let lease_ids: Vec<u64> = self.leases.iter().map(|lease| lease.lease_id).collect();
        release_all_leases(&lease_ids);
        Ok(())
    }
}

/// Lease one VSS snapshot per distinct drive letter across `roots`,
/// then spawn one combined ephemeral daemon covering all of them.
///
/// Drive letters are read directly off each root path's own prefix
/// (`drive_letter_from_path`) — never inferred from the MFT: the
/// Coordinator already knows which drive it's snapshotting, per the
/// user's explicit correction during design.
///
/// A drive VSS permanently refuses to snapshot (`VSS_E_VOLUME_NOT_SUPPORTED`
/// — seen in practice on removable/USB media) is skipped, not fatal: it is
/// warn-logged and left out of the returned leases/daemon devices, so the
/// rest of a multi-drive "all drives" job still completes. Any other lease
/// failure still aborts the whole job.
///
/// # Errors
/// Returns an error if any root has no drive-letter prefix, a lease
/// request fails for a reason other than `VSS_E_VOLUME_NOT_SUPPORTED`,
/// or the ephemeral daemon fails to spawn or become ready. On error,
/// any leases already taken out are released best-effort before
/// returning.
pub(crate) fn prepare_ephemeral_daemon_for_roots(
    job_id: [u8; 16],
    roots: &[&Path],
    ephemeral_id: &str,
) -> Result<EphemeralJobResources> {
    let mut leases: Vec<LeasedDrive> = Vec::new();
    let mut seen_letters = HashSet::new();

    for root in roots {
        let letter = drive_letter_from_path(root)
            .with_context(|| format!("job root {} has no drive-letter prefix", root.display()))?;
        if !seen_letters.insert(letter) {
            continue; // already leased this drive for an earlier root
        }

        match lease_one_drive(job_id, letter) {
            Ok(Some(lease)) => leases.push(lease),
            Ok(None) => {} // VSS_E_VOLUME_NOT_SUPPORTED — skip, already warn-logged
            Err(err) => {
                release_all_leases(&lease_ids(&leases));
                return Err(err);
            }
        }
    }

    let devices: Vec<(String, char)> = leases
        .iter()
        .map(|lease| (lease.device_path.clone(), lease.drive_letter))
        .collect();

    tracing::info!(drive_count = devices.len(), "spawning ephemeral daemon");
    match EphemeralDaemon::spawn(ephemeral_id, &devices) {
        Ok(daemon) => {
            tracing::info!("ephemeral daemon ready");
            Ok(EphemeralJobResources { daemon, leases })
        }
        Err(err) => {
            tracing::warn!(error = %err, "ephemeral daemon spawn failed");
            release_all_leases(&lease_ids(&leases));
            Err(err)
        }
    }
}

/// Lease a VSS snapshot for drive `letter`, split out of
/// [`prepare_ephemeral_daemon_for_roots`]'s loop to keep that function's
/// cognitive complexity down.
///
/// `Ok(None)` means VSS specifically reported
/// `VSS_E_VOLUME_NOT_SUPPORTED` for this volume — skip it, not fatal
/// (already warn-logged here) — see the caller's doc comment.
///
/// # Errors
/// Returns any other lease failure reason.
fn lease_one_drive(job_id: [u8; 16], letter: char) -> Result<Option<LeasedDrive>> {
    tracing::info!(drive = %letter, "leasing VSS snapshot");
    let requested_root = utf16le_bytes(&format!("{letter}:\\"));
    let lease_result = snapshot_client::create_lease(
        job_id,
        VolumeIdentity {
            // Presently inert: the Broker's real `create_snapshot` path
            // derives the volume to snapshot from `requested_root`, not
            // this struct (confirmed via direct source read) — populate
            // a real serial/GUID once the Broker actually validates
            // against it.
            volume_serial: 0,
            volume_guid: Vec::new(),
        },
        requested_root,
        DEFAULT_LEASE_LIFETIME_SECS,
        DEFAULT_POLICY_ID,
    );

    let lease = match lease_result {
        Ok(lease) => lease,
        Err(err) if is_volume_not_supported(&err) => {
            tracing::warn!(
                drive = %letter,
                "skipping drive: VSS does not support snapshotting this volume \
                 (VSS_E_VOLUME_NOT_SUPPORTED — typically removable/USB media)"
            );
            return Ok(None);
        }
        Err(err) => {
            return Err(err.context(format!("failed to lease a VSS snapshot for drive {letter}")));
        }
    };
    tracing::info!(
        drive = %letter,
        lease_id = lease.snapshot_lease_id,
        device = %lease.snapshot_device_identity,
        "VSS snapshot leased"
    );
    Ok(Some(LeasedDrive {
        device_path: lease.snapshot_device_identity,
        drive_letter: letter,
        lease_id: lease.snapshot_lease_id,
        snapshot_id: lease.snapshot_id,
        snapshot_created_at_unix_ms: lease.snapshot_created_at_unix_ms,
    }))
}

/// Whether `err` is a [`BrokerRejectedCreate`] specifically reporting
/// `VSS_E_VOLUME_NOT_SUPPORTED` for a snapshot-creation failure — the
/// one lease-failure reason a multi-drive job should skip past rather
/// than abort on (see [`prepare_ephemeral_daemon_for_roots`]'s doc
/// comment).
fn is_volume_not_supported(err: &anyhow::Error) -> bool {
    err.downcast_ref::<BrokerRejectedCreate>()
        .is_some_and(|rejected| {
            rejected.code == SnapshotManagerErrorCode::SnapshotCreateFailed
                && rejected.hresult == Some(VSS_E_VOLUME_NOT_SUPPORTED)
        })
}

/// Extract just the lease ids from `leases`, for [`release_all_leases`].
fn lease_ids(leases: &[LeasedDrive]) -> Vec<u64> {
    leases.iter().map(|lease| lease.lease_id).collect()
}

/// Release every lease in `lease_ids`. Best-effort: a single failed
/// release is warn-logged, not propagated — teardown must proceed even
/// if one lease is already gone or the Broker is unreachable.
fn release_all_leases(lease_ids: &[u64]) {
    for &lease_id in lease_ids {
        if let Err(err) = snapshot_client::release_lease(lease_id) {
            tracing::warn!(lease_id, error = %err, "failed to release VSS snapshot lease");
        }
    }
}

/// Extract the drive letter a Windows path is rooted on (e.g.
/// `C:\Users\x` -> `'C'`).
///
/// Cheap and purely syntactic: reads the path's own `Prefix` component.
/// Never touches the filesystem or the MFT — the whole point is that
/// the Coordinator already knows which drive it's snapshotting from the
/// job's own root path.
fn drive_letter_from_path(path: &Path) -> Option<char> {
    use std::path::{Component, Prefix};

    let Component::Prefix(prefix) = path.components().next()? else {
        return None;
    };
    let (Prefix::Disk(byte) | Prefix::VerbatimDisk(byte)) = prefix.kind() else {
        return None;
    };
    Some(byte.to_ascii_uppercase() as char)
}

/// Encode `text` as raw UTF-16LE bytes (no null terminator) — the wire
/// format [`snapshot_client::create_lease`]'s `requested_root` expects,
/// mirroring the Broker's own `utf16le_bytes` helper
/// (`crates/uffs-broker/src/broker/snapshot_manager/vss_helper.rs`,
/// `pub(crate)` there so not reusable directly from this crate).
fn utf16le_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
