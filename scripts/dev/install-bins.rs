#!/usr/bin/env rust-script
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.
//!
//! install-bins.rs — build the workspace and install **every** binary it
//! produces to `~/bin`.
//!
//! The binary list is not hardcoded: after building, the same build is
//! re-run with `--message-format=json` (instant from cache) and every
//! `compiler-artifact` message's `executable` path is installed. A new
//! `[[bin]]` anywhere in the workspace is picked up automatically.
//!
//! Called by `just use-local` as
//! `rust-script scripts/dev/install-bins.rs`. A rust-script on purpose:
//!
//! - a just shebang recipe dies on Windows (just hands bash a raw
//!   `C:\...` temp path whose backslashes bash eats, exit 127);
//! - a plain `bash script.sh` line dies too when `bash` on PATH resolves
//!   to WSL's `System32\bash.exe`, which has no cargo ("cargo: command
//!   not found").
//!
//! rust-script runs identically under just's unix shell and its
//! powershell windows-shell, and spawns `cargo` from the real PATH.
//!
//! Usage:
//!   rust-script scripts/dev/install-bins.rs

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn main() {
    let build_args: &[&str] = &["build", "--release", "--workspace"];

    eprintln!("📦 Build (release) + install UFFS binaries to ~/bin");
    eprintln!("========================================================");

    // Note whether a daemon was serving BEFORE we tear it down, so the
    // install can put it back afterwards (see `restart_daemon`).  Probing
    // after `stop_running_services` would of course always say "no".
    let daemon_was_running = daemon_is_running();
    let mcp_was_running = mcp_is_running();
    let watchdog_was_running = watchdog_is_running();

    // Stop the running daemon + MCP first (best effort), mirroring the
    // previous [unix] bash recipe: the old binaries release their file
    // locks (Windows can't overwrite a running .exe at all) and no stale
    // in-memory index shadows the freshly installed build.
    stop_running_services();

    eprintln!();
    eprintln!("🔨 cargo {}", build_args.join(" "));

    // ONE build, both outputs: cargo always prints its human status
    // ("Compiling…", "Finished") and rendered diagnostics on stderr,
    // while `--message-format=json-render-diagnostics` puts one JSON
    // message per artifact on stdout — so the operator keeps the live
    // progress AND we capture the authoritative binary list from the
    // same run. (The previous two-pass design re-ran the build with
    // `--message-format=json` to "walk the cache for free"; on Windows,
    // AV/sync tools touching fresh artifacts between the passes
    // invalidated fingerprints and turned the 'free' pass into a full
    // second compile — observed on winbox 2026-08-23.)
    let started = Instant::now();
    let executables = match build_workspace_capturing_executables(build_args) {
        Ok(paths) => {
            eprintln!("  → Built in {}s", started.elapsed().as_secs());
            paths
        }
        Err(message) => {
            eprintln!("❌ {message}");
            std::process::exit(1);
        }
    };
    if executables.is_empty() {
        eprintln!("❌ cargo reported no workspace binaries to install");
        std::process::exit(1);
    }

    let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let Ok(home) = std::env::var(home_var) else {
        eprintln!("❌ {home_var} is not set — nowhere to install to");
        std::process::exit(1);
    };
    let bin_dir = PathBuf::from(&home).join("bin");
    if let Err(err) = std::fs::create_dir_all(&bin_dir) {
        eprintln!("❌ cannot create {}: {err}", bin_dir.display());
        std::process::exit(1);
    }

    let mut installed = 0_u32;
    let mut skipped = 0_u32;
    let mut unchanged = 0_u32;
    eprintln!();
    // Clear sidecars left by earlier rename-swaps whose old process has
    // since exited.  Ones still held stay put and are swept next time.
    sweep_sidecars(&bin_dir);

    eprintln!("📦 Installing {} binaries to {}", executables.len(), bin_dir.display());
    for src in &executables {
        let Some(file_name) = src.file_name() else {
            continue;
        };
        let dest = bin_dir.join(file_name);
        let name = file_name.to_string_lossy();
        if !src.is_file() {
            eprintln!("  ⚠️  {name:<28} not found at {} (skipping)", src.display());
            skipped += 1;
            continue;
        }
        // Identical to what is already installed?  Don't touch it.
        //
        // This matters most for `uffs-broker.exe`: it runs as a LocalSystem
        // Windows service, so its image is locked and the copy fails with
        // `os error 32` — which used to fail the whole recipe even when the
        // binary had not changed at all.  The broker's sources move rarely
        // (byte-identical across v0.6.30..v0.6.31), so the common case is a
        // needless copy of an unchanged file.
        if files_identical(src, &dest) {
            eprintln!("  ⏭️  {name:<28} unchanged");
            unchanged += 1;
            continue;
        }
        // Changed AND currently locked by the running service: stop it,
        // copy, restart.  The broker exposes native SCM control for exactly
        // this (`--stop` waits for STOPPED, `--start` waits for RUNNING and
        // for the pipe to actually serve), which is the same quiesce/restore
        // dance `uffs --update` performs.
        let broker_guard = if is_broker(&name) {
            BrokerGuard::stop_for_replace(&dest)
        } else {
            BrokerGuard::inactive()
        };
        // Remove first so the copy gets a fresh inode — overwrites in place
        // share the inode, which lets macOS re-use a path-cached Launch
        // Services deny verdict against an earlier broken copy.
        if dest.is_dir() {
            let _ = std::fs::remove_dir_all(&dest);
        }
        // A running image cannot be deleted on Windows — but it can be
        // renamed, which frees the path without touching the live
        // process. That is how a binary gets replaced under a running
        // stdio supervisor: it notices its image changed and hot-swaps
        // its worker, so the AI host's session never drops.
        if dest.exists() && std::fs::remove_file(&dest).is_err() {
            if rename_aside(&dest).is_none() {
                eprintln!("  ❌ {name:<28} in use and could not be moved aside");
                skipped += 1;
                continue;
            }
        }
        match std::fs::copy(src, &dest) {
            Ok(bytes) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    let _ = std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(0o755),
                    );
                }
                eprintln!("  ✅ {name:<28} {:.1} MB", bytes as f64 / 1_048_576.0);
                installed += 1;
            }
            Err(err) => {
                eprintln!("  ❌ {name:<28} copy failed: {err}");
                skipped += 1;
            }
        }
        broker_guard.restart();
    }

    eprintln!();
    if unchanged > 0 {
        eprintln!("✅ Installed {installed} binaries ({unchanged} unchanged, {skipped} skipped)");
    } else {
        eprintln!("✅ Installed {installed} binaries ({skipped} skipped)");
    }
    let on_path = std::env::var("PATH")
        .map(|path| std::env::split_paths(&path).any(|entry| entry == bin_dir))
        .unwrap_or(false);
    if !on_path {
        eprintln!("⚠️  {} is not on PATH", bin_dir.display());
    }
    // Put back what we took down.  Deliberately BEFORE the `skipped`
    // exit: a partially-failed install is exactly the case where leaving
    // the machine daemon-less hurts most.
    if daemon_was_running {
        restart_daemon(&bin_dir);
    }
    if mcp_was_running {
        restart_mcp(&bin_dir);
    }
    // Restart the supervisor LAST: it must not respawn services while
    // they are mid-restart above, or it races the install.
    if watchdog_was_running {
        restart_watchdog(&bin_dir);
    }
    if skipped > 0 {
        std::process::exit(1);
    }
}

/// Move a locked binary aside so a fresh one can take its canonical
/// path, returning where it went.
///
/// Windows refuses to delete or overwrite a running image but happily
/// **renames** it: the running process keeps its handle to the old
/// inode while the path is freed. That is the whole mechanism behind
/// the zero-downtime upgrade the MCP stdio supervisor implements — it
/// watches its own image path and hot-swaps its worker when the bytes
/// there change, so a rename-swap upgrades a live agent session
/// without dropping the host's connection.
///
/// Before this existed the installer took the blunt route and
/// force-killed every `uffsmcp.exe` by image name to unlock the file,
/// which killed the stdio supervisors belonging to interactive agent
/// sessions — the exact failure the supervisor was written to prevent,
/// and a plausible source of "the MCP call was accepted and then
/// vanished" reports.
///
/// Returns `None` when even the rename fails, which means the caller
/// must skip that binary rather than corrupt the install.
fn rename_aside(dest: &std::path::Path) -> Option<std::path::PathBuf> {
    for attempt in 0..64_u32 {
        let sidecar = dest.with_extension(format!("old{attempt}"));
        if sidecar.exists() {
            // A previous run's sidecar still held by a live process.
            continue;
        }
        if std::fs::rename(dest, &sidecar).is_ok() {
            return Some(sidecar);
        }
    }
    None
}

/// Delete leftover `*.oldN` sidecars from previous rename-swaps.
///
/// A sidecar stays on disk while the old process still has it open;
/// once that process exits the file is deletable, so every later
/// install sweeps them. Failures are ignored — a sidecar still in use
/// simply waits for the next run.
fn sweep_sidecars(bin_dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(bin_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_sidecar = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.starts_with("old") && ext[3..].chars().all(|c| c.is_ascii_digit()));
        if is_sidecar {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// PID of a service reported by `uffs --status --json`, if it is running.
///
/// Used to scope teardown kills to the process we actually mean.
/// Killing `uffsmcp.exe` by image name also kills every stdio
/// supervisor an AI host has spawned; those are other people's
/// sessions, not ours to end.
fn service_pid(key: &str) -> Option<u32> {
    let out = Command::new("uffs")
        .args(["--status", "--json"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let section = text.split(&format!("\"{key}\":")).nth(1)?;
    // Sections are small objects; the first `"pid":` after the key is
    // that service's own.
    let after = section.split("\"pid\":").nth(1)?;
    after
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}

/// Force-kill one PID (last-resort backstop after a graceful stop).
fn kill_pid(pid: u32) {
    let _ = if cfg!(windows) {
        Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    } else {
        Command::new("kill")
            .args(["-9", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    };
}

/// True when `src` and `dest` are byte-identical, so the copy can be
/// skipped entirely.  Compares length first (cheap, rejects almost every
/// changed binary) and only then the contents.  A missing or unreadable
/// `dest` is "not identical", so the normal copy path runs.
fn files_identical(src: &std::path::Path, dest: &std::path::Path) -> bool {
    let (Ok(src_meta), Ok(dest_meta)) = (src.metadata(), dest.metadata()) else {
        return false;
    };
    if src_meta.len() != dest_meta.len() {
        return false;
    }
    match (std::fs::read(src), std::fs::read(dest)) {
        (Ok(lhs), Ok(rhs)) => lhs == rhs,
        _ => false,
    }
}

/// Is this the Access Broker binary (the one that runs as a service and
/// therefore holds its own image open)?
fn is_broker(name: &str) -> bool {
    let stem = name.strip_suffix(".exe").unwrap_or(name);
    stem == "uffs-broker"
}

/// Stops the broker service around a replace, and restarts it afterwards.
///
/// `stop_for_replace` is a no-op unless the service is actually running,
/// so a developer box without the broker installed sees no behaviour
/// change.  Restart is best-effort and never fails the install: leaving
/// the new binary in place with the service down is recoverable
/// (`uffs-broker --start`), and is reported loudly.
struct BrokerGuard {
    /// Path of the installed broker binary, when we stopped its service.
    stopped: Option<std::path::PathBuf>,
}

impl BrokerGuard {
    /// A guard that does nothing (non-broker binaries).
    const fn inactive() -> Self {
        Self { stopped: None }
    }

    /// Stop the broker service so its image can be overwritten.
    fn stop_for_replace(installed: &std::path::Path) -> Self {
        if !installed.is_file() {
            return Self::inactive();
        }
        eprintln!("  ⏸️  uffs-broker                 stopping service to replace it");
        let stopped = std::process::Command::new(installed)
            .arg("--stop")
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if stopped {
            Self { stopped: Some(installed.to_path_buf()) }
        } else {
            // Not installed as a service, already stopped, or not
            // elevated — the copy below will report the real error.
            Self::inactive()
        }
    }

    /// Restart the service if this guard stopped it.
    fn restart(self) {
        let Some(path) = self.stopped else {
            return;
        };
        let started = std::process::Command::new(&path)
            .arg("--start")
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if started {
            eprintln!("  ▶️  uffs-broker                 service restarted");
        } else {
            eprintln!(
                "  ⚠️  uffs-broker                 service did NOT restart — run: {} --start",
                path.display()
            );
        }
    }
}

/// Is the service reported under `key` running right now?
///
/// Read from `uffs --status --json`, which reports every service under
/// its own key (`daemon`, `mcp_http`, …). Scanning the *human* status
/// text instead is a trap this script fell into twice: `--mcp status`
/// also prints a `Daemon:  not running` line, so a stopped daemon made
/// a healthy gateway read as stopped, and `◐ loading (3/7 drives)`
/// contains neither `running` nor `not running`, so a daemon busy
/// reading the MFT read as absent and was never restarted.
///
/// Any failure to run the probe (no `uffs` on PATH yet on a first
/// install) reads as "not running", which is the safe answer: we then
/// leave things alone rather than start something the user never had.
fn service_running(key: &str) -> bool {
    let Ok(out) = Command::new("uffs").args(["--status", "--json"]).output() else {
        return false;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    // Sections are emitted in sorted key order and each carries its own
    // `running` flag, so the first flag *after* the key we asked for is
    // that key's own — no JSON parser needed in a rust-script.
    text.split(&format!("\"{key}\":"))
        .nth(1)
        .and_then(|section| section.split("\"running\":").nth(1))
        .map(|flag| flag.trim_start().starts_with("true"))
        .unwrap_or(false)
}

/// Was a daemon serving before we tore everything down?
fn daemon_is_running() -> bool {
    service_running("daemon")
}

/// Restart the daemon we deliberately stopped, using the freshly
/// installed binary.
///
/// `use-local` kills the daemon + MCP so their images can be replaced,
/// but until now never brought them back — so a routine dev install
/// silently left the machine without a daemon, which is exactly the
/// promise `uffs --daemon resident` makes and breaks. Restoring it here
/// keeps the invariant "use-local leaves the machine as it found it".
///
/// The restart goes through the normal `--daemon start` path, so the
/// resident marker (`resident.args`) is merged in by the client's
/// auto-spawn — a daemon that was resident comes back resident, with
/// `--no-retire`, rather than as a plain ephemeral one.
fn restart_daemon(bin_dir: &std::path::Path) {
    let exe = bin_dir.join(if cfg!(windows) { "uffs.exe" } else { "uffs" });
    if !exe.is_file() {
        return;
    }
    eprintln!();
    eprintln!("🔄 Restarting the daemon (it was running before the install)...");
    let ok = Command::new(&exe)
        .args(["--daemon", "start"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if ok {
        eprintln!("✅ Daemon restarted.");
    } else {
        eprintln!(
            "⚠️  Daemon did NOT restart — run: {} --daemon start",
            exe.display()
        );
    }
}

/// Is a watchdog supervising right now?
fn watchdog_is_running() -> bool {
    if cfg!(windows) {
        Command::new("tasklist")
            .args(["/FI", "IMAGENAME eq uffs-watchdog.exe", "/NH"])
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("uffs-watchdog.exe"))
            .unwrap_or(false)
    } else {
        Command::new("pgrep")
            .args(["-x", "uffs-watchdog"])
            .output()
            .map(|out| !out.stdout.is_empty())
            .unwrap_or(false)
    }
}

/// Restart the supervisor we stopped, using the new binary.
fn restart_watchdog(bin_dir: &std::path::Path) {
    let exe = bin_dir.join(if cfg!(windows) { "uffs-watchdog.exe" } else { "uffs-watchdog" });
    if !exe.is_file() {
        return;
    }
    let spawned = Command::new(&exe)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_ok();
    if spawned {
        eprintln!("✅ Watchdog restarted.");
    } else {
        eprintln!("⚠️  Watchdog did NOT restart — run: {}", exe.display());
    }
}

/// Was the MCP HTTP gateway serving before the teardown?
fn mcp_is_running() -> bool {
    service_running("mcp_http")
}

/// Restart the MCP HTTP gateway we stopped, using the new binary.
fn restart_mcp(bin_dir: &std::path::Path) {
    let exe = bin_dir.join(if cfg!(windows) { "uffs.exe" } else { "uffs" });
    if !exe.is_file() {
        return;
    }
    eprintln!();
    eprintln!("🔄 Restarting the MCP server (it was running before the install)...");
    let ok = Command::new(&exe)
        .args(["--mcp", "start"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if ok {
        eprintln!("✅ MCP server restarted.");
    } else {
        eprintln!(
            "⚠️  MCP server did NOT restart — run: {} --mcp start",
            exe.display()
        );
    }
}

/// Best-effort shutdown of the resident daemon + MCP before installing.
///
/// `uffs --daemon kill` is given 10 seconds (a wedged daemon must not
/// hang the install), then any survivors are hard-killed by image name —
/// `pkill -x` on Unix, `taskkill /IM … /F` on Windows. Every step is
/// best-effort: on a machine with nothing running (or no `uffs` on PATH
/// yet), all of this silently no-ops.
fn stop_running_services() {
    eprintln!();
    eprintln!("🔪 Stopping daemon + MCP (best effort)...");
    // Capture PIDs before the graceful stops clear the PID files, so the
    // force-kill backstops below can target exactly these processes.
    let daemon_pid = service_pid("daemon");
    if let Ok(mut child) = Command::new("uffs")
        .args(["--daemon", "kill"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                _ => {
                    let _ = child.kill();
                    break;
                }
            }
        }
    }
    // Ask the MCP gateway to stop cleanly.  Capture its PID first: if it
    // ignores the request we force-kill THAT process and nothing else.
    //
    // This used to be `taskkill /IM uffsmcp.exe /F`, which killed every
    // `uffsmcp` on the box — including the stdio supervisors that AI
    // hosts spawn for interactive agent sessions.  Those belong to
    // other people's sessions; ending them mid-request produces exactly
    // the "call accepted, then silently lost, never returns" signature
    // that got reported against the MCP bridge.  Binary replacement no
    // longer needs the kill either: `rename_aside` frees the path
    // without touching the running process, which is the zero-downtime
    // upgrade path the supervisor already implements.
    let gateway_pid = service_pid("mcp_http");
    let _ = Command::new("uffs")
        .args(["--mcp", "stop"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    // Nested rather than a `let`-chain: rust-script compiles this file
    // on its default edition, where `if let … && …` is not available.
    if let Some(pid) = gateway_pid {
        if mcp_is_running() {
            kill_pid(pid);
        }
    }
    // The watchdog is stopped FIRST: if it kept running while we tear
    // the daemon down, it would dutifully restart it mid-install — the
    // supervisor fighting the installer. It is restarted at the end.
    for name in ["uffs-watchdog"] {
        let _ = if cfg!(windows) {
            Command::new("taskkill")
                .args(["/IM", &format!("{name}.exe"), "/F"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        } else {
            Command::new("pkill")
                .args(["-x", name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        };
    }
    // The daemon: `uffs --daemon kill` above already targets the PID in
    // the PID file and cleans up after itself.  This is the backstop for
    // the case where that failed, still scoped to the one PID the daemon
    // reports rather than every `uffsd` image on the box.
    //
    // `uffsmcp` is deliberately absent from any image-name kill: see the
    // gateway block above.  Stdio supervisors owned by AI hosts survive
    // an install now, and `rename_aside` replaces their binary underneath
    // them so they hot-swap instead of dying.
    if let Some(pid) = daemon_pid {
        if daemon_is_running() {
            kill_pid(pid);
        }
    }
}

/// Run the workspace build ONCE, streaming cargo's human status/
/// diagnostics to the operator (stderr, untouched) while collecting
/// every built binary's absolute path from the JSON artifact messages
/// on stdout (`compiler-artifact` records with a non-null
/// `"executable"`; libraries carry `"executable":null` and are
/// skipped). This is the authoritative "what did we build" list: no
/// name guessing, no `.exe` handling, no missed target when a new
/// `[[bin]]` is added — and no second cargo invocation for external
/// file-touchers (AV, sync clients) to invalidate.
fn build_workspace_capturing_executables(build_args: &[&str]) -> Result<Vec<PathBuf>, String> {
    let mut args: Vec<&str> = build_args.to_vec();
    args.push("--message-format=json-render-diagnostics");
    let mut child = Command::new("cargo")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| format!("failed to launch cargo: {err}"))?;

    // Drain stdout WHILE the build runs — the JSON stream is emitted
    // per-artifact, and an undrained pipe would deadlock the build once
    // the OS buffer fills.
    let mut text = String::new();
    if let Some(stdout) = child.stdout.take() {
        let mut reader = stdout;
        use std::io::Read;
        if let Err(err) = reader.read_to_string(&mut text) {
            // Keep going to reap the child; report the real failure below.
            eprintln!("⚠️  could not read cargo's artifact stream: {err}");
        }
    }
    let status = child
        .wait()
        .map_err(|err| format!("failed to wait for cargo: {err}"))?;
    if !status.success() {
        return Err(format!("build failed with {status:?}"));
    }

    let mut paths = Vec::new();
    for line in text.lines() {
        if let Some(exe) = json_executable(line) {
            paths.push(PathBuf::from(exe));
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// The non-null `"executable"` path from one cargo JSON message line, if
/// present. `"executable":null` (a library artifact) yields `None`.
fn json_executable(line: &str) -> Option<String> {
    let key = "\"executable\":";
    let after = &line[line.find(key)? + key.len()..];
    // Value is either `null` or `"<escaped path>"`.
    let rest = after.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(unescape_json_path(&rest[..end]))
}

/// Undo JSON string escaping in a path (`\\` → `\`, `\/` → `/`).
fn unescape_json_path(escaped: &str) -> String {
    let mut out = String::with_capacity(escaped.len());
    let mut chars = escaped.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('/') => out.push('/'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}
