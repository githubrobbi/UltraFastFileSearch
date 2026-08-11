// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `uffs --daemon resident` — make the daemon permanently resident.
//!
//! The daemon's go-to-sleep ladder (Hot → Warm → Parked → Cold) frees
//! memory beautifully, but its final rung — the idle auto-retire —
//! removes `uffsd` from the process list entirely, so the next search
//! pays the full daemon-restart cost. This command flips that trade:
//! a **resident** daemon runs with `--no-retire` (never exits on
//! idle; the tiering ladder still shrinks it to a few MB when unused)
//! and is registered as a **per-user login item** so it is already
//! warm before the first search of the day.
//!
//! Per platform the login item is:
//!
//! - **Windows** — an `HKCU\…\Run` registry value (never needs Administrator; a
//!   non-elevated resident daemon reads the MFT through the Access Broker, so
//!   the zero-UAC story is preserved).
//! - **macOS** — a launchd `LaunchAgent` (`launchctl bootstrap`,
//!   `KeepAlive.SuccessfulExit = false`: crash → relaunch, clean `uffs --daemon
//!   stop` → stays stopped).
//! - **Linux** — a systemd *user* unit (`systemctl --user enable`,
//!   `Restart=on-failure`).
//!
//! `on` installs the item and starts the daemon right away when none
//! is running; `off` removes it; `status` reports both halves. When a
//! daemon is already running, `on` leaves it untouched (its idle
//! timeout keeps ruling until it retires or is stopped) and the
//! resident configuration takes over from the next start.
//!
//! `on` also writes the **auto-spawn marker** (`resident.args`, next
//! to the daemon PID file). Every implicit daemon auto-spawn merges
//! the marker's argv (caller flags win — see
//! `uffs_client::daemon_resident::merge_resident_args`), so the next
//! search after a crash or a manual stop revives the daemon
//! *resident* — this is what closes the Windows gap where the Run key
//! alone cannot restart a crashed daemon mid-session.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use uffs_client::connect_sync::UffsClientSync;
use uffs_client::daemon_ctl::find_daemon_exe;
use uffs_mft::platform::DriveLetter;

use crate::args::ResidentMode;

/// `uffs --daemon resident <on|off|status>` entry point.
///
/// # Errors
///
/// Fails when the daemon binary cannot be located, the platform login
/// item cannot be written/removed, or the immediate start fails.
pub(crate) fn resident(
    mode: ResidentMode,
    mft_files: &[PathBuf],
    data_dir: Option<&Path>,
    drives: &[DriveLetter],
) -> Result<()> {
    match mode {
        ResidentMode::On => resident_on(mft_files, data_dir, drives),
        ResidentMode::Off => resident_off(),
        ResidentMode::Status => {
            resident_status();
            Ok(())
        }
    }
}

// ── on ──────────────────────────────────────────────────────────────

/// Install the login item and start the resident daemon when possible.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn resident_on(
    mft_files: &[PathBuf],
    data_dir: Option<&Path>,
    drives: &[DriveLetter],
) -> Result<()> {
    if !cfg!(windows) && mft_files.is_empty() && data_dir.is_none() {
        anyhow::bail!(
            "No MFT data sources specified.\n\
             The resident daemon needs data to serve at login:\n\
             \x20 uffs --daemon resident on --data-dir <path>\n\
             \x20 uffs --daemon resident on --mft-file <path>"
        );
    }
    let exe = resolve_daemon_exe()?;
    let argv = daemon_argv(mft_files, data_dir, drives);
    platform::turn_on(&exe, &argv)?;
    write_marker(&argv)?;
    println!(
        "\nUFFS is now resident: uffsd starts at login with --no-retire\n\
         (never exits on idle; memory tiering still parks unused drives),\n\
         and every auto-started daemon inherits the resident lifetime.\n\
         Undo with: uffs --daemon resident off"
    );
    Ok(())
}

/// Write the resident marker (`resident.args`) so implicit auto-spawns
/// — the next search after a crash or a manual stop — revive the
/// daemon with the same resident argv the login item uses (merged in
/// `uffs_client::daemon_resident`; caller flags win).
fn write_marker(argv: &[String]) -> Result<()> {
    let path = uffs_client::daemon_ctl::resident_args_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut content = argv.join("\n");
    content.push('\n');
    std::fs::write(&path, content).with_context(|| format!("writing {}", path.display()))
}

/// Resolve the daemon binary to an absolute, existing path — a login
/// item must not depend on the login shell's `PATH`.
fn resolve_daemon_exe() -> Result<PathBuf> {
    let exe = find_daemon_exe();
    if exe.is_absolute() && exe.exists() {
        return Ok(exe);
    }
    // `find_daemon_exe` fell back to a bare name: resolve it on PATH.
    which::which(&exe).with_context(|| {
        format!(
            "Cannot locate the daemon binary ({}).\n\
             Install uffsd next to uffs, or add it to PATH.",
            exe.display()
        )
    })
}

/// Build the resident daemon's argv (after the program): `--no-retire`,
/// the forwarded data sources, and an absolute `--log-file` (a
/// login-started process has no useful working directory to drop a
/// relative log into).
///
/// Rendered lossily to `String` — the login-item formats (registry
/// value, plist, unit file) are text, so a non-UTF-8 path cannot be
/// represented in them anyway.
fn daemon_argv(
    mft_files: &[PathBuf],
    data_dir: Option<&Path>,
    drives: &[DriveLetter],
) -> Vec<String> {
    let mut argv = vec![String::from("--no-retire")];
    if let Some(dir) = data_dir {
        argv.push(String::from("--data-dir"));
        argv.push(dir.to_string_lossy().into_owned());
    }
    for mft in mft_files {
        argv.push(String::from("--mft-file"));
        argv.push(mft.to_string_lossy().into_owned());
    }
    for letter in drives {
        argv.push(String::from("--drive"));
        argv.push(letter.to_string());
    }
    let log_dir = uffs_security::log_dir::log_dir();
    // Best effort — uffsd's appender creates the directory again.
    let _ensure = std::fs::create_dir_all(&log_dir);
    argv.push(String::from("--log-file"));
    argv.push(log_dir.join("uffsd.log").to_string_lossy().into_owned());
    argv
}

/// Start the daemon through the normal client auto-start path (broker
/// aware, elevation-refusing) and wait until it is ready. Windows
/// only — the Run key has no "start now" verb of its own (launchd and
/// systemd start their job as part of activation).
#[cfg(windows)]
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn spawn_now(argv: &[String]) -> Result<()> {
    let spawn_args: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    println!("Starting resident daemon...");
    let mut client = UffsClientSync::connect_with_args(&spawn_args)
        .with_context(|| "Failed to start the resident daemon")?;
    client
        .await_ready(core::time::Duration::from_mins(2))
        .with_context(|| "Daemon did not become ready in time")?;
    println!("Resident daemon started and ready.");
    Ok(())
}

/// True when a daemon is already reachable on the per-user endpoint.
fn daemon_running() -> bool {
    UffsClientSync::connect_raw().is_ok()
}

// ── off ─────────────────────────────────────────────────────────────

/// Remove the login item and the auto-spawn marker.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn resident_off() -> Result<()> {
    platform::turn_off()?;
    // Auto-spawns fall back to the default idle-retire lifetime.
    let _absent = std::fs::remove_file(uffs_client::daemon_ctl::resident_args_path());
    if daemon_running() {
        println!(
            "A daemon is still running; it is unaffected.\n\
             Stop it with: uffs --daemon stop"
        );
    }
    Ok(())
}

// ── status ──────────────────────────────────────────────────────────

/// Report the login-item and daemon state.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn resident_status() {
    match platform::installed_at() {
        Some(artifact) => println!("Login item:  installed ({artifact})"),
        None => println!("Login item:  not installed"),
    }
    if uffs_client::daemon_ctl::resident_args_path().exists() {
        println!("Auto-spawn:  resident (revived daemons keep --no-retire)");
    } else {
        println!("Auto-spawn:  default (idle retire)");
    }
    if daemon_running() {
        println!("Daemon:      running (details: uffs --daemon status)");
    } else {
        println!("Daemon:      not running");
    }
}

// ── shared plumbing ─────────────────────────────────────────────────

/// Run one system tool to completion, mapping a non-zero exit into an
/// error carrying the tool's stderr.
fn run_tool(program: &str, args: &[&str]) -> Result<std::process::Output> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    if output.status.success() {
        Ok(output)
    } else {
        anyhow::bail!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}

// ── macOS: launchd LaunchAgent ──────────────────────────────────────

/// macOS backend: launchd `LaunchAgent` in `~/Library/LaunchAgents`.
#[cfg(target_os = "macos")]
mod platform {
    use anyhow::{Context as _, Result};

    use super::{daemon_running, run_tool};

    /// launchd label — also the plist file stem.
    const LABEL: &str = "com.skyllc.uffs.daemon";

    /// Path of the `LaunchAgent` plist.
    fn plist_path() -> Result<std::path::PathBuf> {
        let home = std::env::var_os("HOME").context("HOME is not set")?;
        Ok(std::path::PathBuf::from(home)
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist")))
    }

    /// The current user's launchd GUI domain (`gui/<uid>`).
    fn gui_domain() -> Result<String> {
        let output = run_tool("id", &["-u"])?;
        Ok(format!(
            "gui/{}",
            String::from_utf8_lossy(&output.stdout).trim()
        ))
    }

    /// Minimal XML escaping for plist string values.
    fn xml_escape(raw: &str) -> String {
        raw.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    /// Render the `LaunchAgent` plist. `KeepAlive.SuccessfulExit=false`
    /// relaunches a crashed daemon but honors a clean shutdown;
    /// `ThrottleInterval` keeps a pathological respawn loop tame.
    fn launch_agent_plist(exe: &str, argv: &[String], stderr_log: &str) -> String {
        use core::fmt::Write as _;
        let mut arguments = String::new();
        for arg in core::iter::once(exe).chain(argv.iter().map(String::as_str)) {
            // Writing into a String is infallible.
            let _infallible = writeln!(arguments, "        <string>{}</string>", xml_escape(arg));
        }
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{arguments}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>30</integer>
    <key>StandardErrorPath</key>
    <string>{}</string>
</dict>
</plist>
"#,
            xml_escape(stderr_log)
        )
    }

    /// Write the plist and bootstrap it (which also starts the daemon)
    /// unless one is already running.
    #[expect(clippy::print_stdout, reason = "CLI user-facing output")]
    pub(super) fn turn_on(exe: &std::path::Path, argv: &[String]) -> Result<()> {
        let plist = plist_path()?;
        if let Some(parent) = plist.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let stderr_log = uffs_security::log_dir::log_dir().join("uffsd.launchd.err.log");
        std::fs::write(
            &plist,
            launch_agent_plist(&exe.to_string_lossy(), argv, &stderr_log.to_string_lossy()),
        )
        .with_context(|| format!("writing {}", plist.display()))?;
        println!("Login item installed: {}", plist.display());

        if daemon_running() {
            println!(
                "A daemon is already running; leaving it untouched.\n\
                 The resident (launchd-managed) daemon takes over at next login,\n\
                 or right away after: uffs --daemon stop && uffs --daemon resident on"
            );
            return Ok(());
        }
        let domain = gui_domain()?;
        // A previous registration may linger — clear it, then load.
        let _bootout = std::process::Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{LABEL}")])
            .output();
        run_tool("launchctl", &[
            "bootstrap",
            &domain,
            &plist.to_string_lossy(),
        ])?;
        println!("Resident daemon started (launchd-managed).");
        Ok(())
    }

    /// Boot the agent out (stops a launchd-managed daemon) and delete
    /// the plist.
    #[expect(clippy::print_stdout, reason = "CLI user-facing output")]
    pub(super) fn turn_off() -> Result<()> {
        let plist = plist_path()?;
        if let Ok(domain) = gui_domain() {
            // Ignore failure — the agent may simply not be loaded.
            let _bootout = std::process::Command::new("launchctl")
                .args(["bootout", &format!("{domain}/{LABEL}")])
                .output();
        }
        if plist.exists() {
            std::fs::remove_file(&plist)
                .with_context(|| format!("removing {}", plist.display()))?;
            println!("Login item removed: {}", plist.display());
        } else {
            println!("No login item installed.");
        }
        Ok(())
    }

    /// The install artifact, when present.
    pub(super) fn installed_at() -> Option<String> {
        let plist = plist_path().ok()?;
        plist.exists().then(|| plist.display().to_string())
    }

    #[cfg(test)]
    mod tests {
        use super::{launch_agent_plist, xml_escape};

        /// The plist carries the label, the full argv in order, and the
        /// crash-only `KeepAlive` policy.
        #[test]
        fn plist_renders_label_argv_and_keepalive() {
            let rendered = launch_agent_plist(
                "/opt/uffs/uffsd",
                &[
                    String::from("--no-retire"),
                    String::from("--data-dir"),
                    String::from("/Users/me/uffs data"),
                ],
                "/tmp/err.log",
            );
            assert!(rendered.contains("<string>com.skyllc.uffs.daemon</string>"));
            assert!(rendered.contains("<string>/opt/uffs/uffsd</string>"));
            assert!(rendered.contains("<string>--no-retire</string>"));
            assert!(rendered.contains("<string>/Users/me/uffs data</string>"));
            assert!(rendered.contains("<key>SuccessfulExit</key>\n        <false/>"));
            assert!(rendered.contains("<key>RunAtLoad</key>\n    <true/>"));
        }

        /// Paths with XML-special characters survive escaping.
        #[test]
        fn xml_special_characters_are_escaped() {
            assert_eq!(xml_escape("a&b<c>d"), "a&amp;b&lt;c&gt;d");
        }
    }
}

// ── Windows: HKCU Run key ───────────────────────────────────────────

/// Windows backend: per-user `HKCU\…\Run` registry value.
#[cfg(windows)]
mod platform {
    use anyhow::Result;

    use super::{daemon_running, run_tool, spawn_now};

    /// Registry path of the per-user Run key.
    const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

    /// Value name of the UFFS login item under [`RUN_KEY`].
    const RUN_VALUE: &str = "UFFSDaemon";

    /// Render the Run-key command line: the exe always quoted, each
    /// argument quoted when it contains whitespace.
    fn run_command_line(exe: &str, argv: &[String]) -> String {
        let mut parts = vec![format!("\"{exe}\"")];
        for arg in argv {
            if arg.contains(char::is_whitespace) {
                parts.push(format!("\"{arg}\""));
            } else {
                parts.push(arg.clone());
            }
        }
        parts.join(" ")
    }

    /// Write the Run value (no Administrator needed — HKCU is the
    /// user's own hive; a non-elevated resident daemon reads the MFT
    /// via the Access Broker) and start the daemon when none runs.
    #[expect(clippy::print_stdout, reason = "CLI user-facing output")]
    pub(super) fn turn_on(exe: &std::path::Path, argv: &[String]) -> Result<()> {
        let line = run_command_line(&exe.to_string_lossy(), argv);
        run_tool("reg", &[
            "add", RUN_KEY, "/v", RUN_VALUE, "/t", "REG_SZ", "/d", &line, "/f",
        ])?;
        println!("Login item installed: {RUN_KEY}\\{RUN_VALUE}");
        if daemon_running() {
            println!(
                "A daemon is already running; leaving it untouched.\n\
                 The resident configuration takes over at next login,\n\
                 or right away after: uffs --daemon stop && uffs --daemon resident on"
            );
            return Ok(());
        }
        spawn_now(argv)
    }

    /// Delete the Run value (absent value is not an error).
    #[expect(clippy::print_stdout, reason = "CLI user-facing output")]
    pub(super) fn turn_off() -> Result<()> {
        if installed_at().is_none() {
            println!("No login item installed.");
            return Ok(());
        }
        run_tool("reg", &["delete", RUN_KEY, "/v", RUN_VALUE, "/f"])?;
        println!("Login item removed: {RUN_KEY}\\{RUN_VALUE}");
        Ok(())
    }

    /// The install artifact, when present.
    pub(super) fn installed_at() -> Option<String> {
        let query = std::process::Command::new("reg")
            .args(["query", RUN_KEY, "/v", RUN_VALUE])
            .output()
            .ok()?;
        query
            .status
            .success()
            .then(|| format!("{RUN_KEY}\\{RUN_VALUE}"))
    }

    #[cfg(test)]
    mod tests {
        use super::run_command_line;

        /// The exe is always quoted; args are quoted only when they
        /// contain whitespace (Run-key command-line convention).
        #[test]
        fn run_command_line_quotes_exe_and_spaced_args() {
            let line = run_command_line(r"C:\Program Files\UFFS\uffsd.exe", &[
                String::from("--no-retire"),
                String::from("--log-file"),
                String::from(r"C:\Users\Me\App Data\uffsd.log"),
            ]);
            assert_eq!(
                line,
                r#""C:\Program Files\UFFS\uffsd.exe" --no-retire --log-file "C:\Users\Me\App Data\uffsd.log""#
            );
        }
    }
}

// ── Linux (and other unix): systemd user unit ───────────────────────

/// Linux / other-unix backend: systemd user unit.
#[cfg(all(unix, not(target_os = "macos")))]
mod platform {
    use anyhow::{Context as _, Result};

    use super::{daemon_running, run_tool};

    /// systemd user-unit file name.
    const UNIT: &str = "uffs-daemon.service";

    /// Path of the user unit file.
    fn unit_path() -> Result<std::path::PathBuf> {
        let base = std::env::var_os("XDG_CONFIG_HOME").map_or_else(
            || std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".config")),
            |xdg| Some(std::path::PathBuf::from(xdg)),
        );
        Ok(base
            .context("neither XDG_CONFIG_HOME nor HOME is set")?
            .join("systemd/user")
            .join(UNIT))
    }

    /// Render the unit. `Restart=on-failure` relaunches a crashed
    /// daemon but honors a clean `uffs --daemon stop`.
    fn systemd_unit(exe: &str, argv: &[String]) -> String {
        let exec = core::iter::once(exe)
            .chain(argv.iter().map(String::as_str))
            .map(|token| format!("\"{token}\""))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "[Unit]\n\
             Description=UFFS resident search daemon\n\n\
             [Service]\n\
             ExecStart={exec}\n\
             Restart=on-failure\n\
             RestartSec=10\n\n\
             [Install]\n\
             WantedBy=default.target\n"
        )
    }

    /// Write + enable the unit; start it when no daemon runs.
    #[expect(clippy::print_stdout, reason = "CLI user-facing output")]
    pub(super) fn turn_on(exe: &std::path::Path, argv: &[String]) -> Result<()> {
        let unit = unit_path()?;
        if let Some(parent) = unit.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&unit, systemd_unit(&exe.to_string_lossy(), argv))
            .with_context(|| format!("writing {}", unit.display()))?;
        run_tool("systemctl", &["--user", "daemon-reload"])?;
        run_tool("systemctl", &["--user", "enable", UNIT])?;
        println!("Login item installed: {}", unit.display());
        if daemon_running() {
            println!(
                "A daemon is already running; leaving it untouched.\n\
                 The resident (systemd-managed) daemon takes over at next login,\n\
                 or right away after: uffs --daemon stop && uffs --daemon resident on"
            );
            return Ok(());
        }
        run_tool("systemctl", &["--user", "start", UNIT])?;
        println!("Resident daemon started (systemd-managed).");
        Ok(())
    }

    /// Disable + delete the unit (a still-running instance is left
    /// alone; the caller prints the stop hint).
    #[expect(clippy::print_stdout, reason = "CLI user-facing output")]
    pub(super) fn turn_off() -> Result<()> {
        let unit = unit_path()?;
        if !unit.exists() {
            println!("No login item installed.");
            return Ok(());
        }
        // Ignore failure — the unit may not be enabled.
        let _disable = std::process::Command::new("systemctl")
            .args(["--user", "disable", UNIT])
            .output();
        std::fs::remove_file(&unit).with_context(|| format!("removing {}", unit.display()))?;
        let _reload = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .output();
        println!("Login item removed: {}", unit.display());
        Ok(())
    }

    /// The install artifact, when present.
    pub(super) fn installed_at() -> Option<String> {
        let unit = unit_path().ok()?;
        unit.exists().then(|| unit.display().to_string())
    }

    #[cfg(test)]
    mod tests {
        use super::systemd_unit;

        /// The unit quotes every `ExecStart` token and carries the
        /// crash-only restart policy.
        #[test]
        fn unit_renders_execstart_and_restart_policy() {
            let unit = systemd_unit("/opt/uffs/uffsd", &[
                String::from("--no-retire"),
                String::from("--data-dir"),
                String::from("/data dir"),
            ]);
            assert!(unit.contains(
                "ExecStart=\"/opt/uffs/uffsd\" \"--no-retire\" \"--data-dir\" \"/data dir\""
            ));
            assert!(unit.contains("Restart=on-failure"));
            assert!(unit.contains("WantedBy=default.target"));
        }
    }
}

// ── Fallback: unsupported platforms ─────────────────────────────────

/// Fallback backend: residency is unsupported.
#[cfg(not(any(windows, unix)))]
mod platform {
    use anyhow::Result;

    /// Residency is not supported on this platform.
    pub(super) fn turn_on(_exe: &std::path::Path, _argv: &[String]) -> Result<()> {
        anyhow::bail!("resident mode is not supported on this platform")
    }

    /// Residency is not supported on this platform.
    pub(super) fn turn_off() -> Result<()> {
        anyhow::bail!("resident mode is not supported on this platform")
    }

    /// Residency is not supported on this platform.
    pub(super) fn installed_at() -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::daemon_argv;

    /// The resident argv always leads with `--no-retire`, forwards the
    /// data sources, and ends with an absolute `--log-file`.
    #[test]
    fn argv_carries_no_retire_sources_and_log_file() {
        let argv = daemon_argv(
            &[std::path::PathBuf::from("/mft/c.bin")],
            Some(std::path::Path::new("/data")),
            &[],
        );
        assert_eq!(argv.first().map(String::as_str), Some("--no-retire"));
        let joined = argv.join(" ");
        assert!(joined.contains("--data-dir /data"));
        assert!(joined.contains("--mft-file /mft/c.bin"));
        let log_flag = argv
            .iter()
            .position(|arg| arg == "--log-file")
            .expect("--log-file present");
        let log_path = argv.get(log_flag + 1).expect("log path follows flag");
        assert!(
            std::path::Path::new(log_path).is_absolute(),
            "log path must be absolute for a login-started process: {log_path}"
        );
        assert!(log_path.ends_with("uffsd.log"));
    }
}
