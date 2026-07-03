// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `WinGet` upgrade orchestration for `uffs --update` (task: the "update flow,
//! winget-delegating").
//!
//! `winget upgrade` on a portable/zip package is an uninstall + reinstall, so
//! it fails with `remove_all: Access is denied` whenever a UFFS process runs
//! FROM the package dir (reproduced live on v0.6.20: the daemon and the broker
//! service both ran from the winget root). The old behavior — printing "run
//! `winget upgrade` yourself" — therefore dead-ended for exactly the users it
//! addressed.
//!
//! This module makes `uffs --update` orchestrate the whole thing:
//!
//! 1. Stop the daemon if its image lives under the winget root (shutdown RPC —
//!    no privileges needed, works on an elevated daemon too).
//! 2. Cycle the broker service around the upgrade when ITS image lives under
//!    the root: directly when already elevated, otherwise through ONE UAC
//!    prompt — a persistent elevated helper (`--update broker-cycle-helper`)
//!    stops the service, waits for a release file, restarts the service.
//! 3. Run `winget upgrade` — winget's own verb on winget's own turf. If the
//!    running `uffs.exe` is itself inside the package, the upgrade is deferred
//!    to right after this process exits (detached `cmd`, mirroring the
//!    uninstall's deferred delegation) and the release file is written by the
//!    deferred script, so the broker still restarts after the upgrade.
//! 4. Restart the daemon (it auto-starts on the next search anyway; a direct
//!    restart just closes the gap).
//!
//! Windows-only in substance: off Windows there are no winget roots and
//! [`orchestrate`] is a no-op.

use anyhow::Result;

use super::model::DetectionReport;

/// The `WinGet` package id UFFS publishes under (same id the uninstall
/// delegation uses). Only the Windows implementation consumes it.
#[cfg(windows)]
pub(crate) const WINGET_PACKAGE_ID: &str = "SkyLLC.UFFS";

/// Run the winget leg of an update: orchestrate `winget upgrade` for a
/// winget-managed root, working around the locked-image failures a bare
/// `winget upgrade` hits. No-op when the report has no winget root.
///
/// # Errors
///
/// Best-effort by design: individual failures are narrated and degrade to
/// printed instructions; only setup-level failures (e.g. spawning the UAC
/// helper machinery) propagate.
#[cfg(windows)]
pub(crate) fn orchestrate(report: &DetectionReport, latest: &str) -> Result<()> {
    windows_impl::orchestrate(report, latest)
}

/// Non-Windows: winget does not exist and detection never yields a winget
/// root, so there is nothing to orchestrate.
#[cfg(not(windows))]
#[expect(
    clippy::unnecessary_wraps,
    clippy::missing_const_for_fn,
    reason = "signature mirrors the Windows implementation, which is fallible"
)]
pub(crate) fn orchestrate(_report: &DetectionReport, _latest: &str) -> Result<()> {
    Ok(())
}

/// Elevated persistent helper behind `uffs --update broker-cycle-helper
/// <release-file>`: stop the broker service, wait (bounded) for the release
/// file to appear, start the service again, exit. Spawned via a single UAC
/// prompt by [`orchestrate`]; never part of the interactive flow.
///
/// # Errors
///
/// Fails when not elevated, or when the service stop/start fails.
#[cfg(windows)]
pub(crate) fn run_broker_cycle_helper(release_file: &str) -> Result<()> {
    windows_impl::run_broker_cycle_helper(release_file)
}

/// Non-Windows stub for the helper entry point (the action token is accepted
/// on every platform; there is no service to cycle off Windows).
#[cfg(not(windows))]
pub(crate) fn run_broker_cycle_helper(_release_file: &str) -> Result<()> {
    anyhow::bail!("broker-cycle-helper is Windows-only (there is no broker service here)")
}

#[cfg(windows)]
/// The real Windows implementation (see the module docs above); split so the
/// cross-platform facade stays free of Win32-only imports.
mod windows_impl {
    use core::time::Duration;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::Instant;

    use anyhow::{Context as _, Result, bail};

    use super::WINGET_PACKAGE_ID;
    use crate::commands::update::model::{Channel, DetectionReport, InstallRoot, Scope};
    use crate::commands::update::strip_verbatim_prefix;

    /// How long the elevated helper waits for the release file before
    /// restarting the service anyway (an abandoned upgrade must not leave the
    /// broker down forever).
    const RELEASE_WAIT: Duration = Duration::from_secs(600);

    /// How long the orchestrator waits for the helper to get the service
    /// stopped before giving up on the winget leg.
    const STOP_WAIT: Duration = Duration::from_secs(60);

    /// Poll interval for both waits.
    const POLL: Duration = Duration::from_millis(500);

    /// See [`super::orchestrate`].
    #[expect(clippy::print_stdout, reason = "CLI user-facing narration")]
    pub(super) fn orchestrate(report: &DetectionReport, latest: &str) -> Result<()> {
        let Some(root) = winget_root(report) else {
            return Ok(());
        };
        if root_is_current(root, latest) {
            return Ok(());
        }

        // winget refuses to touch a USER-scope package from an elevated
        // session (its scope-safety; reproduced live). Nothing to orchestrate
        // — hand the user the one command that works.
        if matches!(root.scope, Scope::User) && uffs_mft::is_elevated() {
            println!(
                "\nThe winget package updates from a NORMAL (non-admin) terminal — winget\n\
                 refuses user-scope changes in elevated sessions. Run there:\n\
                 \x20   uffs --update"
            );
            return Ok(());
        }

        let root_dir = strip_verbatim_prefix(root.dir.clone());
        println!("\nUpdating the winget package \u{2192} {latest} (via winget) \u{2026}");

        // 1. Daemon out of the way (only when its image is inside the package; the
        //    shutdown RPC needs no privileges and stops elevated daemons).
        let daemon_stopped = stop_daemon_if_under(&root_dir, report);

        // 2. Broker service cycled around the upgrade when it runs from the package (a
        //    running service locks its own image, which is exactly the `remove_all:
        //    Access is denied` a bare `winget upgrade` hits).
        let broker_cycle = cycle_broker_if_under(&root_dir, report)?;

        // 3. The upgrade itself — deferred past process exit when this very uffs.exe is
        //    part of the package being replaced.
        let self_inside = std::env::current_exe()
            .map(strip_verbatim_prefix)
            .is_ok_and(|exe| exe.starts_with(&root_dir));
        if self_inside {
            schedule_deferred_upgrade(root.scope, broker_cycle.as_ref())?;
            println!(
                "\nwinget finishes the update once this process exits (the running uffs.exe\n\
                 is part of the winget package). The daemon restarts on the next search."
            );
            return Ok(());
        }

        let upgraded = run_winget_upgrade(root.scope);
        if let Some(cycle) = &broker_cycle {
            cycle.release();
        }
        match upgraded {
            Ok(()) => println!("\u{2713} winget package updated to {latest}."),
            Err(err) => println!(
                "\u{26a0} winget upgrade did not complete ({err:#}).\n\
                 \x20  Re-run `uffs --update`, or `winget upgrade {WINGET_PACKAGE_ID}` directly."
            ),
        }

        // 4. Bring the daemon back if we took it down (best-effort — it also
        //    auto-starts on the next search).
        if daemon_stopped {
            restart_daemon();
        }
        Ok(())
    }

    /// The first winget-managed root in the report, if any.
    fn winget_root(report: &DetectionReport) -> Option<&InstallRoot> {
        report
            .roots
            .iter()
            .find(|root| matches!(root.channel, Channel::WinGet))
    }

    /// Whether every version-parseable binary in the winget root already
    /// matches `latest` (nothing for winget to do).
    fn root_is_current(root: &InstallRoot, latest: &str) -> bool {
        let want = latest.strip_prefix('v').unwrap_or(latest);
        let versions: Vec<&str> = root
            .binaries
            .iter()
            .filter_map(|bin| bin.version.as_deref())
            .collect();
        !versions.is_empty() && versions.iter().all(|have| *have == want)
    }

    /// Stop the daemon iff its image path lies under `root_dir`. Returns
    /// whether a stop was performed.
    fn stop_daemon_if_under(root_dir: &Path, report: &DetectionReport) -> bool {
        let daemon_inside = report.running.iter().any(|proc| {
            proc.component.label() == "daemon"
                && proc
                    .image_path
                    .clone()
                    .map(strip_verbatim_prefix)
                    .is_some_and(|img| img.starts_with(root_dir))
        });
        if !daemon_inside {
            return false;
        }
        // Graceful shutdown RPC first (no privileges; works on an elevated
        // daemon), then the kill handler as fallback.
        let stopped = uffs_client::connect_sync::UffsClientSync::connect_raw()
            .is_ok_and(|mut client| client.shutdown().is_ok());
        if !stopped {
            let _killed: Result<()> =
                crate::commands::daemon_mgmt::daemon_quiet(&crate::args::DaemonAction::Kill);
        }
        // Give the image a beat to unlock (IPC down lags the loader).
        std::thread::sleep(Duration::from_millis(750));
        true
    }

    /// Best-effort daemon restart after the upgrade (`--daemon start` handler,
    /// silenced). Auto-start on the next search covers any failure.
    fn restart_daemon() {
        let _started: Result<()> =
            crate::commands::daemon_mgmt::daemon_quiet(&crate::args::DaemonAction::Start {
                mft_file: Vec::new(),
                data_dir: None,
                drives: Vec::new(),
                no_cache: false,
                log_level: "info".to_owned(),
                log_file: None,
                elevate: false,
            });
    }

    /// A broker service cycle in flight: the service is stopped, and writing
    /// the release file lets the elevated helper (or the elevated path's
    /// deferred logic) start it again.
    pub(super) struct BrokerCycle {
        /// Path of the release file the waiting side polls for.
        release_file: PathBuf,
        /// `true` when THIS process is elevated and owns the restart directly
        /// (no helper was spawned).
        direct: bool,
    }

    impl BrokerCycle {
        /// Signal that the upgrade is done: restart directly (elevated path)
        /// or release the waiting helper by writing the file.
        #[expect(clippy::print_stdout, reason = "CLI user-facing narration")]
        pub(super) fn release(&self) {
            if self.direct {
                if let Err(err) = uffs_winsvc::start(uffs_broker_protocol::SERVICE_NAME) {
                    println!("\u{26a0} could not restart the broker service ({err:#}).");
                }
                return;
            }
            // The helper restarts the service the moment this file exists.
            let _released: Result<(), std::io::Error> = std::fs::write(&self.release_file, b"done");
        }

        /// The release-file path (for embedding into a deferred script).
        pub(super) fn release_file(&self) -> &Path {
            &self.release_file
        }
    }

    /// If the broker service's image lives under `root_dir`, stop it for the
    /// upgrade and arrange its restart: directly when elevated, else through
    /// the one-UAC persistent helper. `Ok(None)` when the broker is not
    /// involved; `Err` aborts the winget leg (the upgrade would just fail).
    #[expect(clippy::print_stdout, reason = "CLI user-facing narration")]
    fn cycle_broker_if_under(
        root_dir: &Path,
        report: &DetectionReport,
    ) -> Result<Option<BrokerCycle>> {
        let service = uffs_broker_protocol::SERVICE_NAME;
        if !uffs_winsvc::is_installed(service) {
            return Ok(None);
        }
        let broker_inside = report.running.iter().any(|proc| {
            proc.component.label() == "broker"
                && proc
                    .image_path
                    .clone()
                    .map(strip_verbatim_prefix)
                    .is_some_and(|img| img.starts_with(root_dir))
        });
        if !broker_inside {
            return Ok(None);
        }

        let release_file =
            std::env::temp_dir().join(format!("uffs-broker-cycle-{}.release", std::process::id()));
        // Stale file from a crashed prior run would release the helper
        // instantly — clear it first.
        let _removed: Result<(), std::io::Error> = std::fs::remove_file(&release_file);

        if uffs_mft::is_elevated() {
            println!("  stopping the broker service for the upgrade\u{2026}");
            uffs_winsvc::stop(service).context("stopping the broker service")?;
            return Ok(Some(BrokerCycle {
                release_file,
                direct: true,
            }));
        }

        // One UAC prompt: the elevated helper stops the service, waits for the
        // release file, restarts the service.
        println!(
            "  the broker service runs from the winget package — cycling it around the\n\
             \x20 upgrade (Windows shows one UAC prompt)\u{2026}"
        );
        spawn_broker_cycle_helper(&release_file)?;
        let deadline = Instant::now() + STOP_WAIT;
        while uffs_winsvc::status(service) != uffs_winsvc::ServiceState::Stopped {
            if Instant::now() >= deadline {
                // Unblock the helper (it would otherwise restart the service
                // only after its own timeout) and give the user the way out.
                let _released: Result<(), std::io::Error> = std::fs::write(&release_file, b"abort");
                bail!(
                    "the broker service did not stop (UAC declined?) — run `uffs --update` \
                     from an Administrator terminal, or stop the service and retry"
                );
            }
            std::thread::sleep(POLL);
        }
        Ok(Some(BrokerCycle {
            release_file,
            direct: false,
        }))
    }

    /// Spawn this same `uffs.exe` elevated (single UAC prompt) in the hidden
    /// `--update broker-cycle-helper <release-file>` mode. `PowerShell`
    /// `Start-Process -Verb RunAs` mirrors the uninstall's service helper.
    fn spawn_broker_cycle_helper(release_file: &Path) -> Result<()> {
        let raw_exe = std::env::current_exe().context("locating uffs.exe for the UAC helper")?;
        let exe = strip_verbatim_prefix(raw_exe);
        let exe_escaped = exe.display().to_string().replace('\'', "''");
        let file_escaped = release_file.display().to_string().replace('\'', "''");
        let script = format!(
            "Start-Process -FilePath '{exe_escaped}' \
             -ArgumentList '--update','broker-cycle-helper','{file_escaped}' \
             -Verb RunAs -WindowStyle Hidden"
        );
        let status = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("spawning the elevated broker-cycle helper")?;
        if !status.success() {
            bail!("could not launch the elevated broker-cycle helper (UAC declined?)");
        }
        Ok(())
    }

    /// See [`super::run_broker_cycle_helper`].
    pub(super) fn run_broker_cycle_helper(release_file: &str) -> Result<()> {
        if !uffs_mft::is_elevated() {
            bail!(
                "broker-cycle-helper must run elevated (it is spawned via a UAC prompt by \
                 `uffs --update`)"
            );
        }
        let service = uffs_broker_protocol::SERVICE_NAME;
        uffs_winsvc::stop(service).context("stopping the broker service")?;
        // Wait for the orchestrator (or its deferred script) to finish the
        // upgrade; a bounded wait so an abandoned run cannot leave the broker
        // down forever.
        let release = Path::new(release_file);
        let deadline = Instant::now() + RELEASE_WAIT;
        while !release.exists() && Instant::now() < deadline {
            std::thread::sleep(POLL);
        }
        let _removed: Result<(), std::io::Error> = std::fs::remove_file(release);
        uffs_winsvc::start(service).context("restarting the broker service")
    }

    /// Run `winget upgrade` for the package, scope-aware, silent.
    fn run_winget_upgrade(scope: Scope) -> Result<()> {
        let mut command = Command::new("winget");
        command.args([
            "upgrade",
            "--id",
            WINGET_PACKAGE_ID,
            "--silent",
            "--accept-source-agreements",
        ]);
        match scope {
            Scope::Machine => {
                command.args(["--scope", "machine"]);
            }
            Scope::User => {
                command.args(["--scope", "user"]);
            }
            Scope::Unknown => {}
        }
        let status = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("spawning winget upgrade")?;
        if status.success() {
            Ok(())
        } else {
            bail!("winget upgrade exited with {status}")
        }
    }

    /// Defer the upgrade past process exit (the running uffs.exe is part of
    /// the package): a detached `cmd` waits ~2s, runs `winget upgrade`, and —
    /// when a broker cycle is in flight — writes the release file so the
    /// elevated helper restarts the service after the upgrade.
    fn schedule_deferred_upgrade(scope: Scope, cycle: Option<&BrokerCycle>) -> Result<()> {
        use std::os::windows::process::CommandExt as _;

        let scope_arg = match scope {
            Scope::Machine => " --scope machine",
            Scope::User => " --scope user",
            Scope::Unknown => "",
        };
        let release_leg = cycle.map_or_else(String::new, |in_flight| {
            format!(" & echo done > \"{}\"", in_flight.release_file().display())
        });
        let script = format!(
            "ping 127.0.0.1 -n 3 >nul & winget upgrade --id {WINGET_PACKAGE_ID} --silent \
             --accept-source-agreements{scope_arg}{release_leg} & rem deferred winget upgrade"
        );
        // `raw_arg`, NOT `args`: std's default Windows quoting mangles the
        // `/c` payload for cmd.exe (same lesson as the uninstall self-delete).
        Command::new("cmd")
            .raw_arg("/c")
            .raw_arg(&script)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("scheduling the deferred winget upgrade")?;
        Ok(())
    }
}
