// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Live-process & service discovery for the daemon / broker / MCP
//! anchors (Phase A.1 of the self-update design).
//!
//! **No PowerShell.** Sources, by reliability:
//!
//! - **Command line:** the component's own persisted launch state (the daemon
//!   writes `daemon.state.json` next to its PID file). This is more trustworthy
//!   than scraping another process's command line — and needs no `Win32`/PEB
//!   hack.
//! - **Image path + pid enumeration:** native Win32 via
//!   `uffs_mft::platform::process` on Windows; `/proc` + `pgrep` on Unix.
//! - **Broker service:** `sc.exe qc/queryex` (documented, not EDR-noisy).
//!
//! Everything is best-effort: a failed probe yields `None`.

use std::path::PathBuf;

/// Launch facts for a component — from its persisted state where
/// available, else derived natively.
#[derive(Debug, Clone, Default)]
pub(crate) struct LaunchState {
    /// Full path to the running image, if known.
    pub(crate) image_path: Option<PathBuf>,
    /// Exact launch command line (image + all switches), if known.
    pub(crate) command_line: Option<String>,
    /// Reported version, if known.
    pub(crate) version: Option<String>,
}

/// Broker-service facts surfaced from `sc.exe`: `(registered binPath,
/// running pid if started)`. A plain tuple so there is no Windows-only
/// type to go dead off-Windows.
pub(crate) type BrokerService = (PathBuf, Option<u32>);

/// The daemon's lifecycle directory (`%LOCALAPPDATA%\uffs` on Windows),
/// mirroring `uffs_daemon::startup` so the file paths match exactly.
pub(crate) fn lifecycle_dir() -> PathBuf {
    dirs_next::data_local_dir().map_or_else(|| PathBuf::from("/tmp/uffs"), |base| base.join("uffs"))
}

/// Read the daemon PID from `<lifecycle_dir>/daemon.pid`, if present.
pub(crate) fn daemon_pid_from_file() -> Option<u32> {
    let text = std::fs::read_to_string(lifecycle_dir().join("daemon.pid")).ok()?;
    text.trim().parse::<u32>().ok()
}

/// Read the daemon's persisted launch state (`daemon.state.json`), which
/// the daemon writes next to its PID file at startup. Returns
/// `(pid, launch_state)`.
pub(crate) fn daemon_launch_state() -> Option<(u32, LaunchState)> {
    let text = std::fs::read_to_string(lifecycle_dir().join("daemon.state.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let pid = u32::try_from(value.get("pid")?.as_u64()?).ok()?;
    Some((pid, launch_state_from_json(&value)))
}

/// Extract a [`LaunchState`] from the daemon-state JSON object.
fn launch_state_from_json(value: &serde_json::Value) -> LaunchState {
    let string_field = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|text| !text.is_empty())
            .map(ToOwned::to_owned)
    };
    LaunchState {
        image_path: string_field("image_path").map(PathBuf::from),
        command_line: string_field("command_line"),
        version: string_field("version"),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Image path + pid enumeration — native, per platform.
// ─────────────────────────────────────────────────────────────────────

/// Native image path for a pid (Win32 `QueryFullProcessImageNameW`).
#[cfg(windows)]
pub(crate) fn image_path(pid: u32) -> Option<PathBuf> {
    uffs_mft::platform::process::process_image_path(pid)
}

/// Image path for a pid via `/proc` then `ps`.
#[cfg(unix)]
pub(crate) fn image_path(pid: u32) -> Option<PathBuf> {
    unix_image_path(pid)
}

/// Best-effort command line for a pid. **Windows returns `None`** — the
/// command line comes from persisted launch state, never OS scraping.
#[cfg(windows)]
pub(crate) const fn command_line(_pid: u32) -> Option<String> {
    None
}

/// Command line for a pid via `/proc` then `ps` (Unix).
#[cfg(unix)]
pub(crate) fn command_line(pid: u32) -> Option<String> {
    unix_cmdline(pid)
}

/// Find pids by image stem (native Win32 process snapshot).
#[cfg(windows)]
pub(crate) fn find_pids_by_name(stem: &str) -> Vec<u32> {
    uffs_mft::platform::process::pids_by_image_name(&format!("{stem}.exe"))
}

/// Find pids by exact process name via `pgrep -x`.
#[cfg(unix)]
pub(crate) fn find_pids_by_name(stem: &str) -> Vec<u32> {
    std::process::Command::new("pgrep")
        .args(["-x", stem])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| {
            // AUDIT-OK(bytes): pgrep emits one ASCII pid per line; a lossy
            // decode cannot fabricate digits (U+FFFD fails `parse::<u32>`),
            // it can only drop a line — best-effort by design.
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|line| line.trim().parse::<u32>().ok())
                .collect()
        })
        .unwrap_or_default()
}

// ─────────────────────────────────────────────────────────────────────
// Broker service (Windows `sc.exe`).
// ─────────────────────────────────────────────────────────────────────

/// The broker service's registered binary path + running pid, via
/// `sc.exe`. `None` when the service is not installed.
///
/// This is config *discovery* (the registered `BINARY_PATH_NAME`), distinct
/// from the state control consolidated in `uffs-winsvc`; the service name
/// is the shared `uffs_broker_protocol::SERVICE_NAME`. Migrating the binPath
/// read to native `QueryServiceConfigW` is a future follow-up.
#[cfg(windows)]
pub(crate) fn broker_service() -> Option<BrokerService> {
    let service = uffs_broker_protocol::SERVICE_NAME;
    let qc = sc_output(&["qc", service])?;
    let bin_path = qc
        .lines()
        .find_map(|line| line.trim().strip_prefix("BINARY_PATH_NAME").map(str::trim))
        .and_then(|rest| rest.strip_prefix(':').map(str::trim))
        .map(PathBuf::from)?;
    let pid = sc_output(&["queryex", service]).and_then(|queryex| {
        queryex.lines().find_map(|line| {
            line.trim()
                .strip_prefix("PID")
                .and_then(|rest| rest.trim().strip_prefix(':'))
                .and_then(|num| num.trim().parse::<u32>().ok())
                .filter(|parsed| *parsed != 0)
        })
    });
    Some((bin_path, pid))
}

/// Non-Windows: there is no broker service.
#[cfg(not(windows))]
pub(crate) const fn broker_service() -> Option<BrokerService> {
    None
}

/// Run `sc.exe <args>` and return trimmed stdout on success.
#[cfg(windows)]
fn sc_output(args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("sc.exe")
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // AUDIT-OK(bytes): Windows console tools emit OEM/ANSI-codepage bytes, so
    // a strict UTF-8 parse would fail on any localized system; the text is a
    // best-effort display/substring probe, and lossy can only fail a match.
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    (!text.trim().is_empty()).then_some(text)
}

// ─────────────────────────────────────────────────────────────────────
// Unix helpers (macOS / Linux).
// ─────────────────────────────────────────────────────────────────────

/// Best-effort command line for a unix pid (`/proc` then `ps`).
#[cfg(unix)]
fn unix_cmdline(pid: u32) -> Option<String> {
    if let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) {
        // `/proc/<pid>/cmdline` is NUL-separated.
        let joined = raw
            .split(|byte| *byte == 0)
            .filter(|seg| !seg.is_empty())
            // AUDIT-OK(bytes): kernel cmdline segments are OS-arbitrary bytes
            // with no encoding guarantee; best-effort display/probe text.
            .map(|seg| String::from_utf8_lossy(seg).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        if !joined.is_empty() {
            return Some(joined);
        }
    }
    ps_field(pid, "args=")
}

/// Best-effort image path for a unix pid (`/proc/<pid>/exe` then `ps comm=`).
#[cfg(unix)]
fn unix_image_path(pid: u32) -> Option<PathBuf> {
    if let Ok(target) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        return Some(target);
    }
    ps_field(pid, "comm=").map(PathBuf::from)
}

/// Run `ps -p <pid> -o <field>` and return the trimmed single-line value.
#[cfg(unix)]
fn ps_field(pid: u32, field: &str) -> Option<String> {
    let out = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", field])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // AUDIT-OK(bytes): `ps` field bytes have no encoding guarantee (they echo
    // the process's own argv); best-effort display/probe text.
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (!text.is_empty()).then_some(text)
}
