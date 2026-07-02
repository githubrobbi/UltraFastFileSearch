// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Live [`Effects`] for `uffs --uninstall` (tasks U-41/U-42): the real
//! filesystem / process / service side effects, kept apart from the executor
//! ([`super::remove`]) so the orchestration stays testable against a fake.
//!
//! Deletions are **idempotent** (an absent target is a success). Process stop,
//! service removal, and `winget` delegation shell out (`kill`/`taskkill`,
//! `sc`, `winget`) rather than via `libc`, so this crate stays `unsafe`-free.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};

use super::remove::Effects;
use crate::commands::update::model::Scope;

/// The production effects implementation. Carries the running self-binaries so
/// they can be skipped in place — the OS locks a running image, so deleting it
/// directly fails; [`schedule_self_delete`] removes them after this process
/// exits instead.
pub(crate) struct SystemEffects {
    /// Absolute paths of the running self-binaries to skip in-place deletes.
    self_paths: Vec<PathBuf>,
    /// Windows: the user chose "elevate at removal time" at the elevation gate,
    /// so admin-only service removal is routed through a one-shot elevated
    /// helper (a single UAC prompt) instead of failing non-elevated. Stored but
    /// never read off Windows (no broker service exists there).
    #[cfg_attr(
        not(windows),
        expect(
            dead_code,
            reason = "read only by the Windows UAC service-removal routing"
        )
    )]
    elevate_via_uac: bool,
}

impl SystemEffects {
    /// Construct the live effects sink, told which running self-binaries to
    /// skip in-place (they are deferred to [`schedule_self_delete`]) and
    /// whether admin-only service removal goes through the Windows UAC helper
    /// (`elevate_via_uac`; meaningless off Windows).
    pub(crate) const fn new(self_paths: Vec<PathBuf>, elevate_via_uac: bool) -> Self {
        Self {
            self_paths,
            elevate_via_uac,
        }
    }

    /// Whether `path` is one of the running self-binaries (case-insensitive,
    /// matching the verbatim-stripped form the plan carries).
    fn is_self(&self, path: &Path) -> bool {
        let target = path.to_string_lossy();
        self.self_paths
            .iter()
            .any(|self_path| self_path.to_string_lossy().eq_ignore_ascii_case(&target))
    }
}

impl Effects for SystemEffects {
    fn stop_process(&mut self, component: &str, pid: u32) -> Result<()> {
        // The daemon's analyzed pid can go stale before execution (the deep
        // sweep's coverage reload restarts it), so stop the CURRENT daemon:
        // graceful shutdown RPC first — it needs no OS privileges, so it also
        // stops an ELEVATED daemon (the no-broker sweep's UAC start) that
        // taskkill could not touch — then the `uffs --daemon kill` handler
        // (pid-file/socket discovery), then the recorded pid as a last resort.
        // Finally wait for the process to actually exit so its image is
        // unlocked before the runtime binaries are deleted.
        if component == "daemon" {
            let stopped = uffs_client::connect_sync::UffsClientSync::connect_raw()
                .is_ok_and(|mut client| client.shutdown().is_ok());
            if !stopped
                && crate::commands::daemon_mgmt::daemon_quiet(&crate::args::DaemonAction::Kill)
                    .is_err()
            {
                terminate_pid(pid)?;
            }
            wait_daemon_down();
            return Ok(());
        }
        terminate_pid(pid)
    }

    fn remove_service(&mut self, service: &str) -> Result<()> {
        // Non-elevated with the gate's "elevate at removal time" choice: run
        // the removal in a one-shot elevated helper (this is where the single
        // UAC prompt appears). Elevated runs remove the service in-process.
        #[cfg(windows)]
        if self.elevate_via_uac && !uffs_mft::is_elevated() {
            return remove_service_via_uac(service);
        }
        remove_windows_service(service)
    }

    fn delete_binaries(&mut self, dir: &Path, stems: &[String]) -> Result<()> {
        // Best-effort across the whole set: one locked file must never trap
        // the remaining deletions (the original failure mode: a lingering
        // uffsd.exe aborted the loop and left 21 other binaries in place).
        let failed: Vec<PathBuf> = stems
            .iter()
            .map(|stem| dir.join(exe_file_name(stem)))
            // A running self-binary can't be deleted in place — defer it.
            .filter(|path| !self.is_self(path))
            .filter(|path| remove_file_if_present(path).is_err())
            .collect();
        if failed.is_empty() {
            return Ok(());
        }
        // A just-stopped process can hold its image for a beat after the kill
        // returns; give it one settle-and-retry pass before reporting.
        std::thread::sleep(core::time::Duration::from_millis(750));
        let mut errors: Vec<String> = Vec::new();
        for path in failed {
            if let Err(err) = remove_file_if_present(&path) {
                errors.push(format!("{}: {err}", path.display()));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!(
                "could not remove {} of {} file(s): {}",
                errors.len(),
                stems.len(),
                errors.join("; ")
            )
        }
    }

    fn delegate_winget(&mut self, package_id: &str, scope: Scope) -> Result<()> {
        winget_uninstall(package_id, scope)
    }

    #[cfg(windows)]
    fn delete_file(&mut self, path: &Path) -> Result<()> {
        // A running self-binary can't be deleted in place — defer it.
        if self.is_self(path) {
            return Ok(());
        }
        remove_file_if_present(path).with_context(|| format!("removing {}", path.display()))
    }

    fn remove_dir(&mut self, path: &Path) -> Result<()> {
        remove_dir_if_present(path).with_context(|| format!("removing {}", path.display()))
    }

    fn remove_path_entry(&mut self, dir: &Path) -> Result<()> {
        remove_path_entry_impl(dir)
    }
}

/// Windows: remove `dir` from the persisted user + machine PATH (the registry),
/// each guarded so a write (and thus elevation) only happens when that scope
/// actually contains the entry. `[Environment]::SetEnvironmentVariable`
/// broadcasts `WM_SETTINGCHANGE` so open shells pick up the change.
#[cfg(windows)]
fn remove_path_entry_impl(dir: &Path) -> Result<()> {
    let dir_str = dir.display().to_string();
    let escaped = dir_str.replace('\'', "''");
    let script = format!(
        "$d='{escaped}'; foreach($t in 'User','Machine'){{ \
         $p=[Environment]::GetEnvironmentVariable('Path',$t); \
         if($p){{ $new=($p -split ';' | Where-Object {{ $_ -and ($_ -ne $d) }}) -join ';'; \
         if($new -ne $p){{ [Environment]::SetEnvironmentVariable('Path',$new,$t) }} }} }}"
    );
    run_quiet(
        Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]),
        &format!("removing {dir_str} from PATH"),
    )
}

/// Unix: the shell owns PATH (rc files), so editing it automatically is unsafe.
/// Write a manual-cleanup hint to stderr instead (genuinely fallible, so no
/// `unnecessary_wraps`). Only reached for a dir we vetted as UFFS-dedicated, so
/// removing its PATH line is safe — a shared bin dir never gets here.
#[cfg(not(windows))]
fn remove_path_entry_impl(dir: &Path) -> Result<()> {
    use std::io::Write as _;

    writeln!(
        std::io::stderr(),
        "  note: {} was a UFFS-only directory; if you added it to your shell PATH \
         (~/.profile or ~/.zshrc), you can remove that line now",
        dir.display()
    )
    .context("writing PATH cleanup hint")
}

/// Delete the running self-binaries (`uffs.exe` + `uffs-update.exe`) that
/// cannot delete themselves in place.
///
/// Windows: a process cannot delete its own running image, so spawn a detached
/// `cmd` that waits for this process to exit, then deletes each path (the
/// classic self-delete; no FFI needed). Unix: a running binary can be unlinked
/// directly, so just remove them.
#[cfg(windows)]
pub(crate) fn schedule_self_delete(paths: &[PathBuf]) -> Result<()> {
    use std::os::windows::process::CommandExt as _;

    if paths.is_empty() {
        return Ok(());
    }
    let deletes: Vec<String> = paths
        .iter()
        .map(|path| format!("del /f /q \"{}\"", path.display()))
        .collect();
    // `ping` is a portable ~2s sleep; by then this process has exited and the
    // images are unlocked.
    let script = format!(
        "ping 127.0.0.1 -n 3 >nul & {} & rem self-delete",
        deletes.join(" & ")
    );
    // `raw_arg`, NOT `args`: std's default Windows quoting wraps the script in
    // quotes and backslash-escapes the inner `del "path"` quotes — an escaping
    // scheme cmd.exe does not understand, so the deferred delete silently never
    // deleted anything. The raw form hands cmd the `/c` payload verbatim.
    Command::new("cmd")
        .raw_arg("/c")
        .raw_arg(&script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("scheduling self-delete")?;
    Ok(())
}

/// Unix variant (see the Windows declaration): a running binary can be unlinked
/// directly, so remove each now.
#[cfg(not(windows))]
pub(crate) fn schedule_self_delete(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        remove_file_if_present(path).with_context(|| format!("removing {}", path.display()))?;
    }
    Ok(())
}

/// The on-disk file name for a binary stem (`uffsd` -> `uffsd.exe` on Windows).
pub(crate) fn exe_file_name(stem: &str) -> String {
    #[cfg(windows)]
    {
        format!("{stem}.exe")
    }
    #[cfg(not(windows))]
    {
        stem.to_owned()
    }
}

/// Remove a file; an already-absent target is success (idempotent). A real
/// failure (permission, sharing violation) is propagated.
fn remove_file_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(_) if confirmed_absent(path) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Recursively remove a directory; an already-absent target is success
/// (idempotent). A real failure is propagated.
fn remove_dir_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(_) if confirmed_absent(path) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Whether `path` is *confirmed* not to exist. `try_exists` returns `Ok(false)`
/// only when the absence is certain; an `Err` (e.g. permission denied on the
/// parent) is treated as "still present", so a genuine failure is not masked.
fn confirmed_absent(path: &Path) -> bool {
    path.try_exists().is_ok_and(|exists| !exists)
}

/// Run `command` with stdio suppressed; map a non-zero exit to an error.
fn run_quiet(command: &mut Command, what: &str) -> Result<()> {
    let status = command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("spawning {what}"))?;
    if status.success() {
        Ok(())
    } else {
        bail!("{what} exited with {status}");
    }
}

/// Poll until the daemon is no longer reachable over IPC (up to 10s), then
/// give the OS a short beat to release the process image. Bounded — a wedged
/// teardown degrades to the delete-side retry, never a hang.
fn wait_daemon_down() {
    let deadline = std::time::Instant::now() + core::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if uffs_client::connect_sync::UffsClientSync::connect_raw().is_err() {
            break;
        }
        std::thread::sleep(core::time::Duration::from_millis(250));
    }
    // IPC down != image released; the loader lock lags the socket teardown.
    std::thread::sleep(core::time::Duration::from_millis(500));
}

/// Stop a process by pid (`taskkill` on Windows, `kill` on Unix).
fn terminate_pid(pid: u32) -> Result<()> {
    let pid_str = pid.to_string();
    run_quiet(&mut stop_command(&pid_str), &format!("stop of pid {pid}"))
}

/// Windows: build the `taskkill` command for `pid_str`.
#[cfg(windows)]
fn stop_command(pid_str: &str) -> Command {
    let mut command = Command::new("taskkill");
    command.args(["/PID", pid_str, "/T", "/F"]);
    command
}

/// Unix: build the `kill` command for `pid_str`.
#[cfg(not(windows))]
fn stop_command(pid_str: &str) -> Command {
    let mut command = Command::new("kill");
    command.arg(pid_str);
    command
}

/// Stop + delete the broker Windows service. No-op off Windows (where no such
/// service exists, so the plan never produces this item). `pub(crate)` so the
/// hidden `--remove-service-helper` mode (the elevated UAC child) can call the
/// exact same removal.
#[cfg(windows)]
pub(crate) fn remove_windows_service(service: &str) -> Result<()> {
    // Best-effort stop first; an already-stopped service is fine to delete, so
    // proceed whether or not the stop succeeded.
    match uffs_winsvc::stop(service) {
        Ok(()) | Err(_) => {}
    }
    run_quiet(
        Command::new("sc").args(["delete", service]),
        &format!("sc delete {service}"),
    )
}

/// Non-Windows: there is no broker service, so removal is not applicable. The
/// plan never produces this item off Windows, so this is never reached; if it
/// somehow were, erroring is the honest outcome.
#[cfg(not(windows))]
pub(crate) fn remove_windows_service(service: &str) -> Result<()> {
    bail!("cannot remove service {service}: the broker is Windows-only")
}

/// Marker exit code the `PowerShell` launcher script returns when elevation was
/// not obtained (the UAC prompt was declined, or `Start-Process -Verb RunAs`
/// failed) — distinguishable from the helper's own success (0) / failure (1).
#[cfg(windows)]
const UAC_NOT_GRANTED_EXIT: i32 = 223;

/// Remove `service` through a one-shot **elevated helper**: relaunch this same
/// `uffs.exe` via `Start-Process -Verb RunAs` (the single UAC prompt) with the
/// hidden `--uninstall --remove-service-helper <service>` mode, wait for it,
/// and map its exit code. A declined UAC prompt degrades gracefully into an
/// error that names the skipped service and the elevated re-run hint — the
/// executor records it and the rest of the uninstall continues.
///
/// `PowerShell` (not raw `ShellExecuteExW`) keeps this crate `unsafe`-free and
/// matches the module's shell-out design; `-Wait -PassThru` provides the exit
/// code, and the `catch` arm turns "UAC declined" into
/// [`UAC_NOT_GRANTED_EXIT`].
#[cfg(windows)]
fn remove_service_via_uac(service: &str) -> Result<()> {
    let raw_exe = std::env::current_exe().context("locating uffs.exe for the elevated helper")?;
    let exe = crate::commands::update::strip_verbatim_prefix(raw_exe);
    let exe_escaped = exe.display().to_string().replace('\'', "''");
    let service_escaped = service.replace('\'', "''");
    let script = format!(
        "try {{ \
           $p = Start-Process -FilePath '{exe_escaped}' \
                -ArgumentList '--uninstall','--remove-service-helper','{service_escaped}' \
                -Verb RunAs -Wait -PassThru -WindowStyle Hidden; \
           exit $p.ExitCode \
         }} catch {{ exit {UAC_NOT_GRANTED_EXIT} }}"
    );
    let status = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("spawning the elevated service-removal helper")?;
    match status.code() {
        Some(0) => {
            // Trust but verify: the helper said OK, confirm the service is gone.
            if uffs_winsvc::is_installed(service) {
                bail!("elevated helper reported success but service {service} is still installed");
            }
            Ok(())
        }
        // Typed so the executor recognises the decline and LEAVES the broker
        // (service + its locked binary) as a clean outcome, instead of the raw
        // Access-denied that deleting the still-running broker's image produces.
        Some(UAC_NOT_GRANTED_EXIT) => Err(super::remove::ElevationDeclined.into()),
        other => bail!(
            "elevated service-removal helper failed (exit {other:?}) — {service} may still \
             be installed"
        ),
    }
}

/// Delegate removal of a `WinGet`-managed root to `winget uninstall`.
fn winget_uninstall(package_id: &str, scope: Scope) -> Result<()> {
    let mut command = Command::new("winget");
    command.args([
        "uninstall",
        "--id",
        package_id,
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
    run_quiet(&mut command, &format!("winget uninstall {package_id}"))
}

#[cfg(test)]
mod tests {
    use super::{Effects as _, SystemEffects, exe_file_name};

    /// Exercise the live deletion path on throwaway temp files (U-112): real
    /// `SystemEffects`, real files, no UFFS install touched.
    #[test]
    fn delete_binaries_and_dir_remove_real_files_idempotently() {
        let base = std::env::temp_dir().join(format!(
            "uffs-uninstall-effects-{}-{}",
            std::process::id(),
            "u112"
        ));
        std::fs::create_dir_all(&base).unwrap();
        let stems = vec!["uffs".to_owned(), "uffsd".to_owned()];
        for stem in &stems {
            std::fs::write(base.join(exe_file_name(stem)), b"binary").unwrap();
        }

        // The second stem is treated as the running self-binary — it must be
        // skipped (left for the deferred self-delete), not removed in place.
        let self_path = base.join(exe_file_name("uffsd"));
        let mut effects = SystemEffects::new(vec![self_path.clone()], false);
        effects.delete_binaries(&base, &stems).unwrap();
        assert!(
            !base.join(exe_file_name("uffs")).exists(),
            "non-self binary removed"
        );
        assert!(self_path.exists(), "running self-binary skipped (deferred)");
        // ...and is idempotent on already-absent files.
        effects.delete_binaries(&base, &stems).unwrap();

        // remove_dir clears the tree, idempotently.
        effects.remove_dir(&base).unwrap();
        assert!(!base.exists());
        effects.remove_dir(&base).unwrap();
    }
}
