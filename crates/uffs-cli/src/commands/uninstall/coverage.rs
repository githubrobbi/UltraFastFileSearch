// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Windows deep-sweep drive coverage for `uffs --uninstall`.
//!
//! The deep sweep searches the daemon's live index for stray family files. It
//! is only as complete as the set of drives the daemon has loaded, so before
//! the sweep we check coverage — but we deliberately do **not** start or
//! restart the daemon ourselves.
//!
//! Why not: a standalone `uffs --daemon start` loads every NTFS drive in a few
//! seconds, but spawning that same command as a **child of the uninstall
//! process** intermittently hangs the drive load (two drives never finish —
//! observed a daemon stuck at `5/7` with zero progress across 15 s). Rather
//! than chase that spawn-context bug, we treat daemon startup as the user's
//! job: if the daemon already covers every drive we proceed silently; if a
//! daemon is up but still loading we wait briefly; otherwise we tell the user
//! to run `uffs --daemon start` and proceed best-effort with whatever is
//! loaded.
//!
//! Windows-only: off Windows UFFS indexes offline MFT captures, not the live
//! filesystem, so there is no live drive coverage to ensure.

#![cfg(windows)]

use core::time::Duration;
use std::time::Instant;

use uffs_client::connect_sync::UffsClientSync;
use uffs_mft::platform::{DriveLetter, detect_ntfs_drives};

/// Short wait for a daemon that is up but still loading drives to catch up
/// before the sweep proceeds. Bounded on purpose — we never block the uninstall
/// on a slow or stuck load; we proceed best-effort when it elapses.
const BRIEF_WAIT: Duration = Duration::from_secs(60);

/// Poll interval while waiting for a mid-load daemon to settle.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Ensure — best-effort — that the daemon covers every NTFS drive before the
/// deep sweep, without ever starting the daemon in-process (see module docs).
pub(crate) fn ensure_drive_coverage() {
    let all = detect_ntfs_drives();
    if all.is_empty() {
        return;
    }
    // Common case: a warm daemon already covers every drive — proceed silently.
    if covered_count(&all) == all.len() {
        return;
    }
    // Coverage is incomplete. If no daemon is reachable, there is nothing to
    // wait for — tell the user and continue with a limited sweep.
    if UffsClientSync::connect_raw().is_err() {
        print_no_daemon_notice();
        return;
    }
    // A daemon is up but not yet covering every drive — it may just be
    // mid-load. Wait briefly for it to catch up, then proceed with whatever is
    // loaded.
    let covered = wait_briefly_for_coverage(&all);
    if covered < all.len() {
        print_partial_coverage_notice(covered, all.len());
    }
}

/// How many of `all` the daemon currently manages (any tier).
fn covered_count(all: &[DriveLetter]) -> usize {
    let managed = current_managed_drives();
    all.iter().filter(|drive| managed.contains(drive)).count()
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

/// Poll until the daemon covers every drive in `all`, or [`BRIEF_WAIT`]
/// elapses. Prints progress so a mid-load wait never looks like a hang. Returns
/// the final covered count.
fn wait_briefly_for_coverage(all: &[DriveLetter]) -> usize {
    print_wait_intro(all.len());
    let deadline = Instant::now() + BRIEF_WAIT;
    let mut last_covered = usize::MAX;
    loop {
        let covered = covered_count(all);
        if covered != last_covered {
            print_coverage_progress(covered, all.len());
            last_covered = covered;
        }
        if covered == all.len() || Instant::now() >= deadline {
            return covered;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Announce a brief wait for a mid-load daemon.
#[expect(clippy::print_stdout, reason = "CLI progress output")]
fn print_wait_intro(total: usize) {
    println!("\nWaiting for the daemon to finish loading all {total} drive(s) for the deep sweep:");
}

/// Print drive-coverage progress while the daemon finishes loading.
#[expect(clippy::print_stdout, reason = "CLI progress output")]
fn print_coverage_progress(covered: usize, total: usize) {
    println!("  indexing for the sweep: {covered}/{total} drives ready...");
}

/// No daemon is running: the sweep cannot scan the live index. Tell the user
/// how to enable a complete sweep; the uninstall continues regardless.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_no_daemon_notice() {
    println!(
        "\nNo index daemon is running, so the deep sweep can only cover what is already loaded.\n\
         For a complete sweep, run `uffs --daemon start` and re-run the uninstall. Continuing..."
    );
}

/// The daemon covers only some drives after the brief wait. Note it and how to
/// get full coverage; the uninstall continues with a partial sweep.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_partial_coverage_notice(covered: usize, total: usize) {
    println!(
        "\nDaemon covers {covered} of {total} drive(s); the deep sweep will scan those.\n\
         For full coverage, run `uffs --daemon start` and re-run the uninstall. Continuing..."
    );
}
