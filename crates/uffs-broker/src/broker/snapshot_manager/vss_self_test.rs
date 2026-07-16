// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Real, runnable, elevated end-to-end proof that the whole VSS
//! snapshot pipeline (native shim → `uffs-vss-requestor` helper process
//! → [`WindowsVssProvider`] lease/session bookkeeping → Job Object
//! cleanup) actually works at runtime, not just compiles and links.
//!
//! Split out of `vss_helper.rs` purely to stay under the workspace's
//! 800-LOC file-size policy once this self-test's tracing
//! instrumentation pushed that file over the limit — this module has no
//! independent design rationale beyond that split.
//!
//! Backs `uffs-broker --self-test-vss <dir>` (see `broker::run`) and
//! this module's own `#[ignore]`d test, both calling
//! [`self_test_round_trip`] directly so the CLI path and the test path
//! can never drift apart.

use std::path::Path;

use uffs_broker_protocol::snapshot_manager::VolumeIdentity;

use super::vss_helper::{WindowsVssProvider, utf16le_bytes};
use crate::snapshot_lease::{SnapshotHandle, VssProvider as _};

/// Content written to, and verified against, the marker file
/// [`self_test_round_trip`] snapshots.
const SELF_TEST_MARKER_CONTENT: &[u8] = b"uffs-broker --self-test-vss marker";

/// Creates a marker file under `test_dir`, snapshots that file's volume,
/// reads the marker back through the resulting snapshot device path,
/// verifies the content matches, then deletes the snapshot and the
/// marker file.
///
/// `test_dir` must be an absolute, plain (non `\\?\`-prefixed) path —
/// e.g. `C:\Users\me\AppData\Local\Temp\uffs-vss-self-test` — since its
/// drive root is passed directly to `IVssBackupComponents::
/// AddToSnapshotSet`, which expects that exact form.
///
/// # Errors
/// Returns an error if the deliberately-invalid-volume `Failed`-path
/// check doesn't behave as expected (see
/// [`self_test_invalid_volume_reports_failure`]), if `test_dir` can't
/// be created, has no root component, the marker file can't be
/// written, snapshot creation fails, the marker can't be read back
/// from the snapshot device path, its content doesn't match, or
/// snapshot deletion fails.
pub(crate) fn self_test_round_trip(test_dir: &Path) -> anyhow::Result<()> {
    tracing::info!(test_dir = %test_dir.display(), "self-test: starting VSS round trip");

    self_test_invalid_volume_reports_failure()?;

    std::fs::create_dir_all(test_dir)
        .map_err(|err| anyhow::anyhow!("failed to create {}: {err}", test_dir.display()))?;
    // `Path::ancestors()` walks from the path itself up to the root, so
    // the last ancestor is the drive root (e.g. `C:\`) — exactly the
    // form `AddToSnapshotSet` requires.
    let drive_root = test_dir
        .ancestors()
        .last()
        .ok_or_else(|| anyhow::anyhow!("{} has no root component", test_dir.display()))?
        .to_path_buf();

    let marker_path = test_dir.join("uffs-vss-self-test-marker.txt");
    std::fs::write(&marker_path, SELF_TEST_MARKER_CONTENT)
        .map_err(|err| anyhow::anyhow!("failed to write {}: {err}", marker_path.display()))?;
    tracing::info!(
        marker = %marker_path.display(),
        drive_root = %drive_root.display(),
        "self-test: wrote marker file"
    );

    let test_result = run_self_test_round_trip(&marker_path, &drive_root);

    if let Err(err) = std::fs::remove_file(&marker_path) {
        tracing::warn!(
            error = %err,
            path = %marker_path.display(),
            "self-test: failed to remove marker file"
        );
    }
    test_result
}

/// Prove the `Failed` wire event actually works: pass an unmistakably
/// invalid volume path to `create_snapshot` and confirm the helper
/// reports failure (rather than hanging, crashing, or somehow
/// succeeding) and the Broker surfaces it as a diagnosable error.
/// `Failed` is the one wire event `Ready`/`Pong`/`Released` didn't
/// already prove works, and unlike those three it has a real production
/// trigger (any actual VSS creation failure — disk full, service down,
/// a bad volume), so it's worth covering even though nothing else in
/// this self-test exercises it.
///
/// Spawns its own throwaway `uffs-vss-requestor` helper — a fresh
/// [`WindowsVssProvider`], unrelated to the main round trip's snapshot —
/// since this only needs to prove the failure-reporting path.
///
/// # Errors
/// Returns an error if `create_snapshot` unexpectedly *succeeds* for an
/// obviously-invalid volume path (which would itself be a bug worth
/// knowing about, not silently ignoring).
fn self_test_invalid_volume_reports_failure() -> anyhow::Result<()> {
    tracing::info!("self-test: verifying the Failed event path with a deliberately invalid volume");
    let provider = WindowsVssProvider::new();
    let volume = VolumeIdentity {
        volume_serial: 0,
        volume_guid: Vec::new(),
    };
    let bogus_root = utf16le_bytes("not-a-real-volume-path");

    match provider.create_snapshot(&volume, &bogus_root) {
        Ok(handle) => {
            // Unexpected success: clean up so a bug here doesn't also
            // leak a real snapshot, then fail loudly -- an obviously
            // invalid path succeeding is itself the actual problem.
            if let Err(err) = provider.delete_snapshot(&handle.snapshot_id) {
                tracing::warn!(
                    error = %err,
                    "self-test: failed to clean up the unexpectedly-created snapshot"
                );
            }
            anyhow::bail!(
                "expected create_snapshot to fail for an invalid volume path, but it succeeded"
            );
        }
        Err(err) => {
            tracing::info!(error = %err, "self-test: Failed event correctly reported");
            Ok(())
        }
    }
}

/// Create the real snapshot, verify `marker_path` round-trips through
/// it, and delete it — the body of [`self_test_round_trip`], split out
/// so the marker-file cleanup above always runs regardless of outcome.
fn run_self_test_round_trip(marker_path: &Path, drive_root: &Path) -> anyhow::Result<()> {
    let provider = WindowsVssProvider::new();
    let volume = VolumeIdentity {
        volume_serial: 0,
        volume_guid: Vec::new(),
    };
    let requested_root = utf16le_bytes(&drive_root.to_string_lossy());

    let handle = provider
        .create_snapshot(&volume, &requested_root)
        .map_err(|err| anyhow::anyhow!("create_snapshot failed: {err}"))?;

    tracing::info!("self-test: verifying marker round-trips through the snapshot device path");
    let verify_result = verify_marker_round_trip(marker_path, drive_root, &handle);
    if verify_result.is_ok() {
        tracing::info!("self-test: marker verified");
    }

    let ping_result = ping_lease_and_log(&provider, &handle.snapshot_id);

    if let Err(err) = provider.delete_snapshot(&handle.snapshot_id) {
        tracing::warn!(error = %err, "self-test: delete_snapshot failed");
        if verify_result.is_ok() && ping_result.is_ok() {
            return Err(anyhow::anyhow!("delete_snapshot failed: {err}"));
        }
    }
    verify_result.and(ping_result)
}

/// Real, wire-level proof the Ping/Pong path works — `Ping` has no
/// production caller yet, so this is the only place it's ever
/// exercised. Split out of [`run_self_test_round_trip`] to keep that
/// function's cognitive complexity down.
///
/// Failure here doesn't abort the round trip (Release still needs to
/// run to clean up the snapshot either way), but does turn the overall
/// self-test result into an error so a regression can't hide behind an
/// otherwise-green create/delete run.
fn ping_lease_and_log(provider: &WindowsVssProvider, snapshot_id: &[u8]) -> anyhow::Result<()> {
    let ping_result = provider
        .ping_lease(snapshot_id)
        .map_err(|err| anyhow::anyhow!("ping_lease failed: {err}"));
    if let Err(err) = &ping_result {
        tracing::warn!(error = %err, "self-test: ping_lease failed");
    }
    ping_result
}

/// Read `marker_path` back through `handle`'s snapshot device path and
/// confirm it matches [`SELF_TEST_MARKER_CONTENT`].
fn verify_marker_round_trip(
    marker_path: &Path,
    drive_root: &Path,
    handle: &SnapshotHandle,
) -> anyhow::Result<()> {
    if handle.device_identity.is_empty() {
        anyhow::bail!("helper reported no snapshot device path");
    }
    let relative_path = marker_path.strip_prefix(drive_root).map_err(|err| {
        anyhow::anyhow!(
            "{} is not under {}: {err}",
            marker_path.display(),
            drive_root.display()
        )
    })?;
    let snapshot_path = Path::new(&handle.device_identity).join(relative_path);

    let read_back = std::fs::read(&snapshot_path)
        .map_err(|err| anyhow::anyhow!("failed to read {}: {err}", snapshot_path.display()))?;
    if read_back != SELF_TEST_MARKER_CONTENT {
        anyhow::bail!(
            "content mismatch: snapshot read back {} bytes, expected {} bytes matching the marker",
            read_back.len(),
            SELF_TEST_MARKER_CONTENT.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Real, runnable, elevated end-to-end proof that the whole VSS
    /// pipeline actually works at runtime, not just compiles and links.
    /// Everything built for the Snapshot Manager across Phases 4-6 of
    /// `uffs-ingest-implementation-plan.md` had, until this test, never
    /// been executed. Delegates directly to [`super::self_test_round_trip`]
    /// — the exact same function `uffs-broker --self-test-vss` runs —
    /// so this test and the CLI path can never drift apart.
    ///
    /// Requires a real Windows host, Administrator elevation (creating a
    /// `VSS_CTX_FILE_SHARE_BACKUP` snapshot needs it, and reading a
    /// shadow-copy device path back needs it too), and
    /// `uffs-vss-requestor.exe` already built in the same profile
    /// directory `super::vss_helper::helper_exe_path` searches (it
    /// cannot be a Cargo dependency of any kind — see that function's
    /// doc comment — so nothing builds it automatically here): run
    /// `cargo build -p uffs-vss-requestor` once, then run this test
    /// elevated with `cargo test -p uffs-broker -- --ignored`.
    #[test]
    #[ignore = "requires a real Windows host, Administrator elevation, and live VSS"]
    fn create_read_delete_snapshot_round_trip() {
        let test_dir = std::env::temp_dir().join("uffs-vss-self-test");
        super::self_test_round_trip(&test_dir).expect("VSS round trip self-test failed");
    }
}
