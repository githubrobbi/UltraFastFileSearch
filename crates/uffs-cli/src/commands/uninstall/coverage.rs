// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Windows deep-sweep drive coverage for `uffs --uninstall`.
//!
//! The deep sweep searches the daemon's live index for stray family files, so
//! it is only as complete as the set of drives the daemon has loaded. Before
//! the sweep we make sure the daemon covers every NTFS drive; if it does not,
//! we reload it cleanly — **kill then start** — by calling the exact same
//! handlers the CLI dispatches for `uffs --daemon kill` / `uffs --daemon start`
//! ([`daemon_mgmt::daemon`]), in-process.
//!
//! Calling those handlers directly is the whole point: the daemon is then
//! spawned as a **direct child of this process**, identical to a shell
//! `uffs --daemon start`. An earlier attempt shelled out to
//! `uffs.exe --daemon start` as a subprocess, which made the daemon a
//! *grandchild* and intermittently hung its drive load (stuck at `5/7`).
//! Re-using the handler avoids that entirely.
//!
//! Windows-only: off Windows UFFS indexes offline MFT captures, not the live
//! filesystem, so there is no live drive coverage to ensure.

#![cfg(windows)]

use core::time::Duration;
use std::time::Instant;

use uffs_client::connect_sync::UffsClientSync;
use uffs_mft::platform::{DriveLetter, detect_ntfs_drives};

use crate::args::DaemonAction;
use crate::commands::daemon_mgmt;

/// How long to wait for the daemon to fully exit after `kill` before starting a
/// fresh one (a lingering pipe would make `start` see "already running" and
/// skip the reload).
const SHUTDOWN_WAIT: Duration = Duration::from_secs(15);

/// Poll interval while waiting for shutdown.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Ensure the daemon covers every NTFS drive before the deep sweep. No-op when
/// coverage is already complete; otherwise reload the daemon (kill + start)
/// via the real CLI handlers. Best-effort: any failure just means the sweep
/// covers whatever is currently loaded.
pub(crate) fn ensure_drive_coverage() {
    let all = detect_ntfs_drives();
    if all.is_empty() {
        return;
    }
    let managed = current_managed_drives();
    let missing: Vec<DriveLetter> = all
        .iter()
        .filter(|drive| !managed.contains(drive))
        .copied()
        .collect();
    if missing.is_empty() {
        // The daemon already covers every system drive — proceed silently.
        return;
    }
    reload_daemon_for_coverage(&all, &missing);
}

/// The drive letters the daemon currently manages (any tier). Empty when the
/// daemon is not running or did not answer.
fn current_managed_drives() -> Vec<DriveLetter> {
    UffsClientSync::connect_raw()
        .map_or_else(|_| Vec::new(), |mut client| managed_letters(&mut client))
}

/// Read the managed drive letters from `status_drives` (every row, regardless
/// of tier). Any RPC error yields an empty list (best-effort).
fn managed_letters(client: &mut UffsClientSync) -> Vec<DriveLetter> {
    client.status_drives().map_or_else(
        |_| Vec::new(),
        |resp| resp.drives.into_iter().map(|row| row.letter).collect(),
    )
}

/// Reload the daemon so it covers every drive: `kill`, wait for it to exit,
/// then `start`. Both steps go through [`daemon_mgmt::daemon`] — the exact
/// handlers `uffs --daemon kill` / `uffs --daemon start` use — so the daemon is
/// spawned in-process as a direct child (see module docs).
fn reload_daemon_for_coverage(all: &[DriveLetter], missing: &[DriveLetter]) {
    print_reload_intro(missing, all.len());

    if let Err(err) = daemon_mgmt::daemon(&DaemonAction::Kill) {
        print_reload_failed("kill the daemon", &err);
        return;
    }
    wait_until_daemon_down();

    // `daemon start` blocks until the daemon is Ready (every drive loaded), so
    // on success coverage is complete.
    if let Err(err) = daemon_mgmt::daemon(&start_action()) {
        print_reload_failed("start the daemon", &err);
        return;
    }

    let managed = current_managed_drives();
    let covered = all.iter().filter(|drive| managed.contains(drive)).count();
    if covered < all.len() {
        print_partial_coverage_notice(covered, all.len());
    }
}

/// The [`DaemonAction::Start`] a bare `uffs --daemon start` produces: auto-
/// discover every NTFS drive, use the cache, default logging, no UAC prompt.
fn start_action() -> DaemonAction {
    DaemonAction::Start {
        mft_file: Vec::new(),
        data_dir: None,
        drives: Vec::new(),
        no_cache: false,
        log_level: "info".to_owned(),
        log_file: None,
        elevate: false,
    }
}

/// Poll until the daemon is no longer reachable (fully shut down) or
/// [`SHUTDOWN_WAIT`] elapses.
fn wait_until_daemon_down() {
    let deadline = Instant::now() + SHUTDOWN_WAIT;
    while Instant::now() < deadline {
        if UffsClientSync::connect_raw().is_err() {
            return;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Announce the kill+start because coverage is incomplete.
#[expect(clippy::print_stdout, reason = "CLI progress output")]
fn print_reload_intro(missing: &[DriveLetter], total: usize) {
    let list = missing
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "\nDaemon is not indexing every drive (missing {list}; {covered} of {total} covered).\n\
         Reloading it (kill + start) for a complete deep sweep:",
        covered = total.saturating_sub(missing.len()),
    );
}

/// Note that the reload could not complete; the sweep continues best-effort.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_reload_failed(what: &str, err: &anyhow::Error) {
    println!("  could not {what}: {err}. Continuing the deep sweep with whatever is loaded.");
}

/// Note that the daemon covers only some drives after the reload.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_partial_coverage_notice(covered: usize, total: usize) {
    println!("  daemon covers {covered} of {total} drive(s); the deep sweep will scan those.");
}
