// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Windows deep-sweep drive coverage for `uffs --uninstall`.
//!
//! The deep sweep searches the daemon's live index for stray family files, so
//! it is only as complete as the set of drives the daemon has loaded. Before
//! the sweep we make sure the daemon covers every NTFS drive; if it does not,
//! we reload it cleanly — **kill then start** — by calling the exact same
//! handlers the CLI dispatches for `uffs --daemon kill` / `uffs --daemon
//! start`, in-process (the daemon spawns as a direct child, identical to a
//! shell start; an earlier subprocess relaunch made it a grandchild and was
//! abandoned).
//!
//! Two narration modes: **loud** (`-v` sequential runs — everything prints
//! live, including the daemon handlers' own lines) and **quiet** (the default
//! background gather — the daemon handlers are silenced via
//! [`daemon_mgmt::daemon_quiet`] and the narration is *deferred*: collected as
//! note strings the caller prints with the final presentation, so nothing ever
//! garbles the interactive prompt on the main thread).
//!
//! Best-effort throughout: any failure leaves coverage as-is and the sweep
//! proceeds against whatever is currently loaded.

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

/// Whether the daemon already covers every NTFS drive — a cheap RPC check used
/// by the sweep-elevation decision *before* the gather starts (a daemon with
/// full coverage needs no reload, elevated or not).
pub(crate) fn coverage_complete() -> bool {
    let all = detect_ntfs_drives();
    if all.is_empty() {
        return true;
    }
    // A version-mismatched daemon (old uffsd serving a newer CLI) must be
    // reloaded before the sweep: its results are only as trustworthy as its
    // own code (cf. issue #510, where a mismatched daemon served sweep rows
    // whose paths resolved to the bare drive root).
    if daemon_version_mismatch().is_some() {
        return false;
    }
    let managed = current_managed_drives();
    all.iter().all(|drive| managed.contains(drive))
}

/// `Some(daemon_version)` when a daemon answers with a version different from
/// this CLI's; `None` when it matches or no daemon answers (nothing to judge).
fn daemon_version_mismatch() -> Option<String> {
    let mut client = UffsClientSync::connect_raw().ok()?;
    let status = client.status().ok()?;
    (status.version != env!("CARGO_PKG_VERSION")).then_some(status.version)
}

/// Ensure the daemon covers every NTFS drive before the deep sweep. No-op when
/// coverage is already complete; otherwise reload the daemon (kill + start)
/// via the real CLI handlers — with `elevate_daemon` the start requests a UAC
/// prompt (the user opted in at the sweep gate: without the Access Broker a
/// daemon can only read the MFT elevated). Returns the deferred narration
/// notes (always empty in loud mode, where everything printed live).
/// Best-effort: any failure just means the sweep covers whatever is loaded.
pub(crate) fn ensure_drive_coverage(quiet: bool, elevate_daemon: bool) -> Vec<String> {
    let mut notes: Vec<String> = Vec::new();
    let all = detect_ntfs_drives();
    if all.is_empty() {
        return notes;
    }
    let managed = current_managed_drives();
    let missing: Vec<DriveLetter> = all
        .iter()
        .filter(|drive| !managed.contains(drive))
        .copied()
        .collect();
    let stale = daemon_version_mismatch();
    if missing.is_empty() && stale.is_none() {
        // Full coverage from a version-matched daemon — nothing to do.
        return notes;
    }
    reload_daemon_for_coverage(
        &all,
        &missing,
        stale.as_deref(),
        quiet,
        elevate_daemon,
        &mut notes,
    );
    notes
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
/// then `start` (blocks until Ready = every drive loaded). Both steps go
/// through the real CLI handlers — silenced ones in quiet mode.
fn reload_daemon_for_coverage(
    all: &[DriveLetter],
    missing: &[DriveLetter],
    stale_version: Option<&str>,
    quiet: bool,
    elevate_daemon: bool,
    notes: &mut Vec<String>,
) {
    // Human reason for the reload: missing drives, a stale daemon, or both.
    let reason = match (stale_version, missing.is_empty()) {
        (Some(theirs), true) => format!(
            "it was running v{theirs}, not this CLI's v{}",
            env!("CARGO_PKG_VERSION")
        ),
        (Some(theirs), false) => format!(
            "it was running v{theirs}, not this CLI's v{}, and was missing {}",
            env!("CARGO_PKG_VERSION"),
            missing
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        (None, _) => format!(
            "it was missing {}",
            missing
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let list = reason.as_str();
    // Loud mode announces the attempt live; quiet mode stays silent until the
    // OUTCOME is known — a pre-declared "reloaded" note would contradict a later
    // start failure (e.g. a declined UAC prompt), which is exactly what the user
    // saw. The truthful note is pushed only once `start` actually succeeds.
    if !quiet {
        emit(
            quiet,
            notes,
            format!(
                "\nThe daemon needs a reload before the deep sweep ({list}).\n\
                 Reloading it (stop + start):"
            ),
        );
    }

    // Stop the running daemon COOPERATIVELY (an IPC shutdown it honors
    // regardless of its own elevation — the same-user pipe), NOT the
    // policy-gated `daemon kill`, which a non-elevated shell cannot use on an
    // elevated daemon (the loud failure the user hit). Only if the daemon cannot
    // be stopped at all do we fall back to scanning what is already indexed.
    if !stop_running_daemon(quiet) {
        emit(
            quiet,
            notes,
            "\nNote: could not stop the running daemon.\n\
               The deep sweep will scan the drives already indexed."
                .to_owned(),
        );
        return;
    }

    if let Err(err) = start_daemon_for_coverage(quiet, elevate_daemon) {
        emit(quiet, notes, start_failure_note(elevate_daemon, &err));
        return;
    }

    // Success: the daemon is back with full coverage, so the note is truthful.
    if quiet {
        notes.push(format!(
            "\nNote: the index daemon was restarted for the deep sweep ({list})."
        ));
    }

    let managed = current_managed_drives();
    let covered = all.iter().filter(|drive| managed.contains(drive)).count();
    if covered < all.len() {
        emit(
            quiet,
            notes,
            format!(
                "  daemon covers {covered} of {total} drive(s); the deep sweep will scan those.",
                total = all.len(),
            ),
        );
    }
}

/// A coherent note for a failed coverage start — the elevated no-broker case
/// names the likely cause (a declined UAC prompt) so the message does not read
/// as a bug. Never claims the daemon "was reloaded" (it was not).
fn start_failure_note(elevate_daemon: bool, err: &anyhow::Error) -> String {
    if elevate_daemon {
        format!(
            "\nNote: the elevated index daemon a full deep sweep needs could not be\n\
             started (the UAC prompt was likely declined: {err}).\n\
             The deep sweep will scan the drives already indexed."
        )
    } else {
        format!(
            "\nNote: the index daemon could not be started ({err}).\n\
             The deep sweep will scan the drives already indexed."
        )
    }
}

/// Dispatch `action` through the CLI handlers — the silenced variant in quiet
/// mode so background work never prints over the interactive prompt.
fn run_handler(quiet: bool, action: &DaemonAction) -> anyhow::Result<()> {
    if quiet {
        daemon_mgmt::daemon_quiet(action)
    } else {
        daemon_mgmt::daemon(action)
    }
}

/// Start the (possibly elevated) daemon for the reload. A cold cache can take
/// ~90 s to load; in loud mode animate a spinner over the *quiet* start (the
/// raw "connect attempt N/20" chatter reads as a hang), so the spinner owns the
/// line. Quiet mode stays silent — its narration is deferred as a note by the
/// caller.
fn start_daemon_for_coverage(quiet: bool, elevate_daemon: bool) -> anyhow::Result<()> {
    if quiet {
        return daemon_mgmt::daemon_quiet(&start_action(elevate_daemon));
    }
    crate::commands::spinner::spinner_while(
        "starting the index daemon (a cold cache can take up to ~90 s)",
        || daemon_mgmt::daemon_quiet(&start_action(elevate_daemon)),
    )
}

/// Route one narration line: printed live in loud mode, deferred as a note in
/// quiet mode (the caller prints notes with the final presentation).
#[expect(clippy::print_stdout, reason = "CLI progress output (loud mode only)")]
fn emit(quiet: bool, notes: &mut Vec<String>, line: String) {
    if quiet {
        notes.push(line);
    } else {
        println!("{line}");
    }
}

/// The [`DaemonAction::Start`] a bare `uffs --daemon start` produces: auto-
/// discover every NTFS drive, use the cache, default logging. `elevate`
/// requests the UAC prompt (`--daemon start --elevate`) for the no-broker
/// sweep path the user opted into.
fn start_action(elevate: bool) -> DaemonAction {
    DaemonAction::Start {
        mft_file: Vec::new(),
        data_dir: None,
        drives: Vec::new(),
        no_cache: false,
        log_level: "info".to_owned(),
        log_file: None,
        elevate,
    }
}

/// Stop the running daemon for the reload. Tries the **cooperative** IPC
/// shutdown first — the daemon exits itself on the RPC regardless of its own
/// elevation (the pipe is same-user), so it works from a non-elevated shell,
/// unlike the policy-gated `daemon kill`. Falls back to the gated kill only if
/// the daemon ignores the shutdown (works for a non-elevated / broker daemon;
/// needs Administrator for an elevated one). Returns whether the daemon is
/// actually down afterward.
fn stop_running_daemon(quiet: bool) -> bool {
    if UffsClientSync::connect_raw().is_ok_and(|mut client| client.shutdown().is_ok()) {
        wait_until_daemon_down();
    }
    if daemon_is_down() {
        return true;
    }
    // The daemon ignored the cooperative shutdown (or its pipe was unreachable
    // yet the process lives) — try the gated kill, then re-check.
    if run_handler(quiet, &DaemonAction::Kill).is_ok() {
        wait_until_daemon_down();
    }
    daemon_is_down()
}

/// Whether the daemon's IPC endpoint is no longer reachable (fully shut down).
fn daemon_is_down() -> bool {
    UffsClientSync::connect_raw().is_err()
}

/// Poll until the daemon is no longer reachable (fully shut down) or
/// [`SHUTDOWN_WAIT`] elapses.
fn wait_until_daemon_down() {
    let deadline = Instant::now() + SHUTDOWN_WAIT;
    while Instant::now() < deadline {
        if daemon_is_down() {
            return;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}
