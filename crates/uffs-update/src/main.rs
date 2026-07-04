// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `uffs-update` — the self-update **acquire** helper binary.
//!
//! A separate binary from `uffs` so the HTTP/TLS stack (reqwest + rustls)
//! never bloats the lean CLI. `uffs --update` spawns this for the
//! download/verify step only; detect + snapshot stay in `uffs-cli`.
//!
//! ```text
//! uffs-update acquire --snapshot <path> --stage <dir>
//!                     [--repo <owner/name>] [--version <tag>] [--sums <asset>]
//! ```

mod acquire;
mod apply;
mod doctor;
mod github;
mod journal;
mod orchestrate;
mod plan;
mod proc;
mod quiesce;
mod recover;
mod restore;
mod verify;

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::acquire::AcquirePlan;

/// Entry point. Prints a clean `Error: …` chain (no Rust backtrace) and exits
/// non-zero on any failure — a usage slip like `uffs-update --doctor` should
/// read like advice, not a crash. Mirrors `uffs`'s `main` error rendering.
#[expect(clippy::print_stderr, reason = "top-level CLI error output")]
fn main() {
    if let Err(err) = run() {
        for (idx, cause) in err.chain().enumerate() {
            if idx == 0 {
                eprintln!("Error: {cause}");
            } else {
                eprintln!("  Caused by: {cause}");
            }
        }
        std::process::exit(1);
    }
}

/// Dispatch the subcommand. Returns a non-zero exit (via [`main`]) on failure.
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("acquire") => run_acquire(args.get(1..).unwrap_or_default()),
        Some("apply") => run_apply(args.get(1..).unwrap_or_default()),
        Some("recover") => run_recover(args.get(1..).unwrap_or_default()),
        Some("doctor") => run_doctor(args.get(1..).unwrap_or_default()),
        Some("check") => run_check(args.get(1..).unwrap_or_default()),
        Some("--version" | "-V") => {
            print_version();
            Ok(())
        }
        Some("--help" | "-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            bail!(
                "unknown subcommand `{other}` (try `acquire` / `apply` / `recover` / `doctor` / `check`)"
            )
        }
    }
}

/// Reclaim a prior self-replacement's leftover `.bak` (§19.7, R4) from the
/// running orchestrator's own directory — but **only** when no update is
/// in-flight (`update_dir/journal.json` absent), since a live journal means
/// recovery owns those backups. Best-effort; never fails the caller.
fn sweep_self_backups_if_idle(update_dir: &Path) {
    if update_dir.join("journal.json").exists() {
        return; // recovery owns the .bak files — do not touch
    }
    if let Some(self_dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    {
        let _swept = apply::sweep_stale_backups(&self_dir);
    }
}

/// Parse the `apply` flags and run the full journal-driven flow:
/// quiesce → backup/swap/smoke → commit → restore → prune. On any
/// pre-commit failure the binaries are rolled back **and** the stopped
/// services are restarted (INV-1: never leave a service down).
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn run_apply(args: &[String]) -> Result<()> {
    let snapshot_path = PathBuf::from(required(flag(args, "--snapshot"), "--snapshot <path>")?);
    let stage = PathBuf::from(required(flag(args, "--stage"), "--stage <dir>")?);
    let update_dir = stage
        .parent()
        .map_or_else(|| stage.clone(), Path::to_path_buf);

    // R4: reclaim any prior self-replacement's leftover `.bak` before we
    // begin (no live journal yet for this run).
    sweep_self_backups_if_idle(&update_dir);

    let mut snapshot = plan::Snapshot::load(&snapshot_path)?;

    // A non-elevated apply skips the Access Broker ONLY when it is a *running*
    // LocalSystem service: we can neither stop (to unlock its `.exe`) nor
    // restart it without admin. Drop it from this run — update everything else;
    // the running broker keeps serving (its wire protocol is back-compatible)
    // and catches up on the next elevated update. When the broker is NOT running
    // (not installed, or just a hand-placed `uffs-broker.exe` file), there is no
    // service to stop and the binary is swapped in place like any other — so do
    // not skip it and do not print the "left running" note. `is_elevated()` is
    // `false` off Windows, but the snapshot has no broker there, so this is a
    // no-op away from Windows.
    // Read this BEFORE drop_broker strips the broker entries: when the broker
    // lives in a WinGet-delegated root, the caller's `winget upgrade` refreshes
    // its `.exe` and cycles the service, so it is not left at the old version.
    let broker_delegated = snapshot.broker_in_winget_root();
    // Components whose image is in a WinGet-delegated root: the caller
    // (uffs-cli) stops them up front and its `resume` relaunches them on the
    // new binary, so if restore can't restart them here it is NOT a fault.
    let winget_delegated = snapshot.winget_delegated_components();
    let skipped_broker = if !uffs_winsvc::is_elevated() && snapshot.broker_is_running() {
        snapshot.drop_broker()
    } else {
        None
    };

    let backup_dir = update_dir.join(format!("backup-{}", std::process::id()));
    let journal_path = update_dir.join("journal.json");
    let mut journal = orchestrate::journal_from_snapshot(journal_path, &snapshot, backup_dir);
    // Record the snapshot so Phase H can restore service state on recovery.
    journal.snapshot_ref = Some(snapshot_path.display().to_string());
    journal.transition(journal::UpdateState::Acquired, "apply.acquired")?;

    // R3 (§19.6): WinGet roots are delegated, not swapped — tell the user
    // so a winget-managed install is never silently left at the old version.
    if !journal.delegated_winget.is_empty() {
        println!(
            "note: {} WinGet-managed root(s) are delegated — run `winget upgrade` to update them:\n  {}",
            journal.delegated_winget.len(),
            journal.delegated_winget.join("\n  ")
        );
    }

    // Pre-flight BEFORE touching any service: prove every staged binary
    // is present and every target dir is writable. A failure here is
    // zero-downtime — nothing is quiesced or swapped yet (§19, Phase D).
    if let Err(err) = orchestrate::preflight(&journal, &stage) {
        journal.transition(journal::UpdateState::Aborted, "preflight.failed")?;
        journal.archive();
        return Err(err);
    }
    journal.transition(journal::UpdateState::PreflightOk, "preflight.ok")?;

    // Stop the resident services so their files unlock.
    quiesce::quiesce(&mut journal, &snapshot)?;

    // Swap + smoke + commit; on failure the binaries are already rolled
    // back — now restart the services we stopped (INV-1) and abort.
    if let Err(err) = orchestrate::apply_all(&mut journal, &stage, |target| {
        apply::smoke_ok(target, orchestrate::SMOKE_ARG)
    }) {
        let failed = restore::restore(&snapshot);
        journal.transition(
            journal::UpdateState::Aborted,
            &format!("apply.aborted; restart_failed=[{}]", failed.join(", ")),
        )?;
        journal.archive();
        return Err(err);
    }

    // Committed: relaunch services into the new binaries.
    let failed = restore::restore(&snapshot);
    journal.transition(journal::UpdateState::Restored, "restore.done")?;
    // Split the failures: a component in a WinGet-delegated root was stopped by
    // the caller and is relaunched by its `resume` on the new binary, so it is
    // not a fault here — only genuinely-ours components warrant the warning.
    let (delegated_down, genuine_failed): (Vec<String>, Vec<String>) = failed
        .into_iter()
        .partition(|component| winget_delegated.contains(component));
    if !genuine_failed.is_empty() {
        #[expect(clippy::print_stderr, reason = "CLI user-facing warning")]
        {
            eprintln!(
                "warning: components failed to restart: [{}]",
                genuine_failed.join(", ")
            );
        }
    }
    if !delegated_down.is_empty() {
        println!(
            "note: {} left stopped here — the winget package update relaunches \
             it on the new binary.",
            delegated_down.join(", ")
        );
    }

    orchestrate::prune_all(&journal);
    journal.transition(journal::UpdateState::Done, "apply.done")?;
    journal.archive();
    println!("Applied + committed → {}", journal.to_version);
    // Only warn when nothing else will refresh the broker. If it lives in a
    // WinGet-delegated root, the caller's `winget upgrade` + service cycle
    // brings it to the new version, so this hint would contradict reality.
    if let Some(broker_version) = skipped_broker
        && !broker_delegated
    {
        println!(
            "note: the Access Broker (uffs-broker {broker_version}) was left running \
             and NOT updated — refreshing the LocalSystem broker service needs \
             elevation. The running broker stays compatible; for a full refresh \
             (incl. the broker), run once from an elevated shell:\n    uffs --update"
        );
    }
    Ok(())
}

/// Parse the `recover` flags and run Phase H against a journal.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn run_recover(args: &[String]) -> Result<()> {
    let journal_path = PathBuf::from(required(flag(args, "--journal"), "--journal <path>")?);
    let message = match recover::recover(&journal_path)? {
        recover::Recovery::NothingToDo => "nothing to do",
        recover::Recovery::InProgress => "another update is in progress (owner alive)",
        recover::Recovery::RolledForward => "interrupted update resumed → completed",
        recover::Recovery::RolledBack => "interrupted update rolled back to the previous version",
    };
    println!("recover: {message}");
    Ok(())
}

/// Default upstream repository for self-update artifacts.
const DEFAULT_REPO: &str = "skyllc-ai/UltraFastFileSearch";

/// Parse the `doctor` flags and run the end-to-end health check. Exits
/// non-zero when a hard failure is found so it composes in scripts/CI.
fn run_doctor(args: &[String]) -> Result<()> {
    let opts = doctor::DoctorOpts {
        snapshot: flag(args, "--snapshot").map(PathBuf::from),
        stage: flag(args, "--stage").map(PathBuf::from),
        repo: flag(args, "--repo").unwrap_or_else(|| DEFAULT_REPO.to_owned()),
        tag: flag(args, "--version"),
        repair: has_flag(args, "--repair"),
        offline: has_flag(args, "--offline"),
        verbose: has_flag(args, "--verbose") || has_flag(args, "-v"),
    };
    if doctor::run(&opts) {
        Ok(())
    } else {
        bail!("doctor found one or more failures")
    }
}

/// Resolve the latest (or `--version`-requested) release tag and print
/// `latest=<tag>` for the CLI to compare against the installed version.
/// Non-mutating, no download — a single release-metadata fetch so the
/// ordinary-user `uffs --update` can short-circuit when already current.
#[expect(
    clippy::print_stdout,
    reason = "machine-readable line consumed by the CLI"
)]
fn run_check(args: &[String]) -> Result<()> {
    let repo = flag(args, "--repo").unwrap_or_else(|| DEFAULT_REPO.to_owned());
    let release = github::fetch_release(&repo, flag(args, "--version").as_deref())?;
    println!("latest={}", release.tag_name);
    Ok(())
}

/// Print the helper version.
#[expect(clippy::print_stdout, reason = "intentional version output")]
fn print_version() {
    println!("uffs-update {}", env!("CARGO_PKG_VERSION"));
}

/// Parse the `acquire` flags and download + verify the installed-subset
/// binaries from the snapshot.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn run_acquire(args: &[String]) -> Result<()> {
    let snapshot_path = PathBuf::from(required(flag(args, "--snapshot"), "--snapshot <path>")?);
    let stage = PathBuf::from(required(flag(args, "--stage"), "--stage <dir>")?);

    // R4: a fresh acquire is the natural moment to reclaim a prior
    // self-replacement's leftover `.bak` (the prior process has long
    // exited), gated on no in-flight journal.
    if let Some(update_dir) = stage.parent() {
        sweep_self_backups_if_idle(update_dir);
    }

    let snapshot = plan::Snapshot::load(&snapshot_path)?;

    // The installed subset across every unmanaged root, deduplicated.
    let binaries = snapshot.installed_binaries();
    if binaries.is_empty() {
        bail!("no unmanaged binaries to acquire (WinGet roots are delegated to winget)");
    }

    let plan = AcquirePlan {
        repo: flag(args, "--repo").unwrap_or_else(|| DEFAULT_REPO.to_owned()),
        tag: flag(args, "--version"),
        stage: stage.clone(),
        sums: flag(args, "--sums").unwrap_or_else(|| "SHA256SUMS".to_owned()),
        binaries,
    };
    let staged = acquire::run(&plan)?;
    println!(
        "Acquired + verified {} binaries into {}",
        staged.len(),
        stage.display()
    );
    Ok(())
}

/// Return the value following `name` in `args` (`--name value`).
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|idx| args.get(idx + 1))
        .cloned()
}

/// `true` if the bare flag `name` is present.
fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

/// Turn a missing required flag into a clear error.
fn required(value: Option<String>, what: &str) -> Result<String> {
    value.ok_or_else(|| anyhow::anyhow!("missing required {what}"))
}

/// Print usage to stdout.
#[expect(clippy::print_stdout, reason = "intentional help output")]
fn print_usage() {
    println!(
        "uffs-update — self-update acquire + apply + recover + doctor + check helper\n\n\
         USAGE:\n\
         \x20 uffs-update acquire --snapshot <path> --stage <dir> \\\n\
         \x20                     [--repo <owner/name>] [--version <tag>] [--sums <asset>]\n\
         \x20 uffs-update apply   --snapshot <path> --stage <dir>\n\
         \x20 uffs-update recover --journal <path>\n\
         \x20 uffs-update doctor  [--snapshot <path>] [--stage <dir>] \\\n\
         \x20                     [--repo <owner/name>] [--version <tag>] [--repair]\n\
         \x20                     [--offline] [--verbose]\n\
         \x20 uffs-update check   [--repo <owner/name>] [--version <tag>]\n\n\
         check:   prints `latest=<tag>` (the latest release) for the CLI to\n\
         compare against the installed version. Non-mutating, no download.\n\
         acquire: per the snapshot's installed subset, downloads each binary\n\
         as an individual release asset + SHA256SUMS, SHA-256-verifies each,\n\
         and leaves them staged. It does not replace anything (apply phase).\n\
         doctor:  end-to-end health check of the update flow; `--repair`\n\
         resumes/rolls-back an interrupted update, sweeps stale backups, and\n\
         restarts any stopped service. Exits non-zero on a hard failure.\n"
    );
}
