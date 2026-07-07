// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `uffs --status` — combined daemon + broker + MCP status in one view.
//!
//! Four sections, each with a health glyph and (in `-v`) expanded detail:
//! - **Daemon**: PID, uptime, drives, queries; `-v` adds build / broker mode,
//!   live-update loops, memory, and paths.
//! - **Access Broker**: SCM state, PID, pipe-serving (native, locale-proof);
//!   `-v` adds the broker binary path + uptime + stale-binary check.
//! - **MCP HTTP Gateway**: PID, transport, health, sessions, tool calls.
//! - **MCP Stdio Sessions**: active `uffs --mcp run` processes (one per AI
//!   host).
//!
//! `--json` emits the machine-readable superset of all four sections.

#[cfg(feature = "mcp-http-probe")]
use anyhow::{Context as _, Result};
use uffs_client::connect_sync::UffsClientSync;
use uffs_client::protocol::response::{DriveInfo, ShardTier, StatsResponse, StatusResponse};
use uffs_statusfmt::{Glyph, Palette, field, header, section, status_row};

use crate::commands::daemon_status::health;

/// Short pipe-probe budget for the status line (ms).
const BROKER_PIPE_PROBE_MS: u32 = 1_000;

/// One mebibyte, for the `bytes → MB` display conversions.
const MIB: u64 = 1024 * 1024;

/// `uffs --status [-v] [--json]` — show combined system status.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn system_status(verbose: bool, json: bool) {
    let daemon = gather_daemon();
    if json {
        render_json(daemon.as_ref());
        return;
    }
    let palette = Palette::detect();
    println!("{}", header(palette, "UFFS System Status"));
    println!();
    print_daemon_section(palette, verbose, daemon.as_ref());
    println!();
    print_broker_section(palette, verbose);
    println!();
    print_mcp_http_section(palette, verbose);
    println!();
    print_mcp_stdio_section(palette);
}

/// Daemon state gathered once, shared by the human and JSON renderers.
struct DaemonSnapshot {
    /// `status` RPC payload (phase, pid, uptime, new operator fields).
    status: StatusResponse,
    /// Loaded drives from the `drives` RPC (empty when none / unavailable).
    drives: Vec<DriveInfo>,
    /// `stats` RPC payload (performance counters), when the daemon supports it.
    perf: Option<StatsResponse>,
}

/// Connect to the daemon and snapshot status + drives + stats, or `None` when
/// the daemon is not running / not responding.
fn gather_daemon() -> Option<DaemonSnapshot> {
    let mut client = UffsClientSync::connect_raw().ok()?;
    let status = client.status().ok()?;
    let drives = client
        .drives()
        .ok()
        .map_or_else(Vec::new, |resp| resp.drives);
    let perf = client.stats().ok();
    Some(DaemonSnapshot {
        status,
        drives,
        perf,
    })
}

// ── JSON ────────────────────────────────────────────────────────────────────

/// Emit the machine-readable superset of every section under stable keys.
#[expect(clippy::print_stdout, reason = "CLI --json output")]
fn render_json(daemon: Option<&DaemonSnapshot>) {
    let doc = serde_json::json!({
        "daemon": daemon_json(daemon),
        "broker": broker_json(),
        "mcp_http": mcp_http_json(),
        "mcp_stdio": mcp_stdio_json(),
    });
    match serde_json::to_string_pretty(&doc) {
        Ok(text) => println!("{text}"),
        Err(err) => println!("{{\"error\":\"{err}\"}}"),
    }
}

/// JSON for the daemon section (status + drives + stats, or `running:false`).
fn daemon_json(daemon: Option<&DaemonSnapshot>) -> serde_json::Value {
    daemon.map_or_else(
        || serde_json::json!({ "running": false }),
        |snap| {
            serde_json::json!({
                "running": true,
                "status": snap.status,
                "drives": snap.drives,
                "stats": snap.perf,
            })
        },
    )
}

// ── Daemon (human) ───────────────────────────────────────────────────────────

/// Print the daemon section: glyph headline + core fields, plus `-v` detail.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_daemon_section(palette: Palette, verbose: bool, daemon: Option<&DaemonSnapshot>) {
    println!("{}", section(palette, "Daemon"));
    let Some(snap) = daemon else {
        println!("{}", status_row(palette, Glyph::Down, "not running", ""));
        let pid_path = uffs_client::daemon_ctl::pid_file_path();
        if pid_path.exists() {
            println!(
                "  {}",
                palette.dim(&format!("(stale PID file at {})", pid_path.display()))
            );
        }
        return;
    };

    let (glyph, state) = health(&snap.status.status);
    let stale_tag = if binary_is_newer_than(snap.status.uptime_secs) {
        format!("  {}", palette.yellow("\u{26a0} stale binary"))
    } else {
        String::new()
    };
    println!(
        "{}",
        status_row(
            palette,
            glyph,
            &state,
            &format!("PID {}{stale_tag}", snap.status.pid)
        )
    );

    let width = 11;
    println!(
        "{}",
        field(
            palette,
            "Version",
            &crate::commands::version_summary(&snap.status.version),
            width
        )
    );
    println!(
        "{}",
        field(palette, "Uptime", &fmt_secs(snap.status.uptime_secs), width)
    );
    print_daemon_drives(palette, &snap.drives, width);
    if let Some(perf) = snap.perf.as_ref() {
        print_daemon_queries(palette, perf, width);
    }
    if verbose {
        print_daemon_verbose(palette, &snap.status);
    }
}

/// Compact one-line drive summary (count · records · tier split).
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_daemon_drives(palette: Palette, drives: &[DriveInfo], width: usize) {
    if drives.is_empty() {
        println!("{}", field(palette, "Drives", "(none loaded)", width));
        return;
    }
    let records: usize = drives.iter().map(|dr| dr.records).sum();
    let parked = drives
        .iter()
        .filter(|dr| matches!(dr.tier, Some(ShardTier::Parked)))
        .count();
    let cold = drives
        .iter()
        .filter(|dr| matches!(dr.tier, Some(ShardTier::Cold)))
        .count();
    let active = drives.len().saturating_sub(parked).saturating_sub(cold);
    let value = format!(
        "{} loaded \u{b7} {} records ({active} active / {parked} parked / {cold} cold)",
        drives.len(),
        uffs_client::format::format_number_commas(records as u64),
    );
    println!("{}", field(palette, "Drives", &value, width));
}

/// Compact one-line query-rate summary.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_daemon_queries(palette: Palette, stats: &StatsResponse, width: usize) {
    if stats.total_queries == 0 {
        println!("{}", field(palette, "Queries", "0", width));
        return;
    }
    let avg =
        core::time::Duration::from_micros(uffs_client::format::f64_to_u64(stats.avg_query_time_us));
    let value = format!(
        "{} (avg {}, {:.1}/s)",
        stats.total_queries,
        uffs_client::format::format_duration(avg),
        stats.queries_per_second,
    );
    println!("{}", field(palette, "Queries", &value, width));
}

/// `-v` daemon detail: build / broker mode, live-update, memory, paths.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_daemon_verbose(palette: Palette, status: &StatusResponse) {
    let width = 11;
    if !status.git_sha.is_empty() {
        println!("{}", field(palette, "Commit", &status.git_sha, width));
    }
    let mode = if status.elevated {
        "yes (direct elevated reads)"
    } else if status.reading_via_broker {
        "no (via Access Broker, zero-UAC)"
    } else {
        "no"
    };
    println!("{}", field(palette, "Elevated", mode, width));
    if let Some(info) = status.live_update {
        let value = if info.active_loops > 0 {
            format!("{} journal loop(s) running", info.active_loops)
        } else {
            "inactive".to_owned()
        };
        println!("{}", field(palette, "Live upd", &value, width));
    }
    if let Some(rss) = status.rss_bytes {
        let heap = status
            .index_heap_bytes
            .map_or_else(String::new, |bytes| format!(" (index {} MB)", bytes / MIB));
        println!(
            "{}",
            field(
                palette,
                "Memory",
                &format!("{} MB RSS{heap}", rss / MIB),
                width
            )
        );
    }
    if let Some(paths) = status.paths.as_ref()
        && !paths.data_dir.is_empty()
    {
        println!("{}", field(palette, "Data dir", &paths.data_dir, width));
    }
}

// ── Access Broker (human) ────────────────────────────────────────────────────

/// Print the Access Broker section. The broker is Windows-only (it vends
/// elevated NTFS volume handles); off Windows the section says "not applicable"
/// rather than advertising an install that does nothing.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_broker_section(palette: Palette, verbose: bool) {
    use uffs_broker_protocol::{PIPE_NAME, SERVICE_NAME};

    println!("{}", section(palette, "Access Broker"));
    if !cfg!(windows) {
        println!(
            "{}",
            status_row(
                palette,
                Glyph::Off,
                "not applicable",
                "Windows-only component"
            )
        );
        return;
    }
    let info = uffs_winsvc::query(SERVICE_NAME);
    if !info.state.is_installed() {
        println!("{}", status_row(palette, Glyph::Off, "not installed", ""));
        println!(
            "  {}",
            palette.dim("Install: uffs-broker --install  (one-time; removes UAC prompts)")
        );
        return;
    }
    let (glyph, running) = if info.state.is_running() {
        (Glyph::Up, true)
    } else {
        (Glyph::Down, false)
    };
    let detail = info
        .pid
        .map_or_else(String::new, |pid| format!("PID {pid}"));
    println!(
        "{}",
        status_row(palette, glyph, info.state.label(), &detail)
    );

    let serving = running && uffs_winsvc::pipe_serving(PIPE_NAME, BROKER_PIPE_PROBE_MS);
    println!(
        "{}",
        field(
            palette,
            "Pipe",
            if serving { "serving" } else { "not serving" },
            9
        )
    );
    print_broker_detail(palette, verbose, info.pid);
}

/// `-v` broker detail (non-Windows): the broker does not exist here.
#[cfg(not(windows))]
const fn print_broker_detail(_palette: Palette, _verbose: bool, _pid: Option<u32>) {}

/// `-v` broker detail (Windows): binary path + uptime + stale-binary check.
#[cfg(windows)]
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_broker_detail(palette: Palette, verbose: bool, pid: Option<u32>) {
    if !verbose {
        return;
    }
    let Some(broker_pid) = pid else {
        return;
    };
    let width = 9;
    if let Some(path) = uffs_mft::platform::process::process_image_path(broker_pid) {
        println!(
            "{}",
            field(palette, "Binary", &path.display().to_string(), width)
        );
        if let Some(created) = uffs_mft::platform::process::process_creation_time(broker_pid) {
            if let Ok(uptime) = std::time::SystemTime::now().duration_since(created) {
                println!(
                    "{}",
                    field(
                        palette,
                        "Uptime",
                        &uffs_client::format::format_duration(uptime),
                        width
                    )
                );
            }
            let stale = std::fs::metadata(&path)
                .ok()
                .and_then(|meta| meta.modified().ok())
                .is_some_and(|mtime| created < mtime);
            if stale {
                println!(
                    "  {}",
                    palette.yellow("\u{26a0} broker binary is newer than the running process")
                );
            }
        }
    }
}

/// JSON for the broker section (Windows).
#[cfg(windows)]
fn broker_json() -> serde_json::Value {
    use uffs_broker_protocol::{PIPE_NAME, SERVICE_NAME};
    let info = uffs_winsvc::query(SERVICE_NAME);
    if !info.state.is_installed() {
        return serde_json::json!({ "applicable": true, "installed": false });
    }
    let running = info.state.is_running();
    let serving = running && uffs_winsvc::pipe_serving(PIPE_NAME, BROKER_PIPE_PROBE_MS);
    let binary = info
        .pid
        .and_then(uffs_mft::platform::process::process_image_path)
        .map(|path| path.display().to_string());
    serde_json::json!({
        "applicable": true,
        "installed": true,
        "state": info.state.label(),
        "running": running,
        "pid": info.pid,
        "pipe_serving": serving,
        "binary": binary,
    })
}

/// JSON for the broker section (non-Windows: the broker does not exist).
#[cfg(not(windows))]
fn broker_json() -> serde_json::Value {
    serde_json::json!({ "applicable": false })
}

// ── MCP HTTP Gateway ─────────────────────────────────────────────────────────

/// Print the MCP HTTP gateway section.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_mcp_http_section(palette: Palette, verbose: bool) {
    println!("{}", section(palette, "MCP HTTP Gateway"));
    let info = match uffs_client::mcp_pid::parse_mcp_pid_file_full() {
        Some(info) if info.http_addr().is_some() => info,
        _ => {
            println!("{}", status_row(palette, Glyph::Down, "not running", ""));
            return;
        }
    };
    if uffs_client::mcp_pid::is_mcp_server_running().is_none() {
        println!(
            "{}",
            status_row(
                palette,
                Glyph::Down,
                "not running",
                &format!("stale PID {}", info.pid)
            )
        );
        return;
    }
    let uptime_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |dur| dur.as_secs().saturating_sub(info.start_ts));
    let gw_stale = mcp_started_before_binary(info.start_ts);
    let stale = if gw_stale {
        format!("  {}", palette.yellow("\u{26a0} stale binary"))
    } else {
        String::new()
    };
    println!(
        "{}",
        status_row(
            palette,
            Glyph::Up,
            "running",
            &format!("PID {}{stale}", info.pid)
        )
    );
    println!("{}", field(palette, "Uptime", &fmt_secs(uptime_secs), 11));
    if let Some((bind, port)) = info.http_addr() {
        print_mcp_http_endpoint(palette, verbose, bind, port);
    }
    if gw_stale {
        println!(
            "  {}",
            palette.dim("Run `uffs --mcp reload` to restart with the current binary.")
        );
    }
}

/// Print the endpoint + (feature-gated) health/stats for the HTTP gateway.
#[cfg(feature = "mcp-http-probe")]
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_mcp_http_endpoint(palette: Palette, _verbose: bool, bind: &str, port: u16) {
    let width = 11;
    println!(
        "{}",
        field(
            palette,
            "Endpoint",
            &format!("http://{bind}:{port}/mcp"),
            width
        )
    );
    match http_get_json(bind, port, "/status") {
        Ok(json) => {
            println!("{}", field(palette, "Health", "\u{2713} ok", width));
            if let Some(stats) = json.get("mcp_stats") {
                print_mcp_stats(palette, stats);
            }
        }
        Err(err) => {
            println!(
                "{}",
                field(
                    palette,
                    "Health",
                    &palette.red(&format!("unreachable ({err})")),
                    width
                )
            );
        }
    }
}

/// Print the endpoint for the HTTP gateway (probe feature disabled).
#[cfg(not(feature = "mcp-http-probe"))]
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_mcp_http_endpoint(palette: Palette, _verbose: bool, bind: &str, port: u16) {
    let width = 11;
    println!(
        "{}",
        field(
            palette,
            "Endpoint",
            &format!("http://{bind}:{port}/mcp"),
            width
        )
    );
    println!(
        "  {}",
        palette.dim("(health probe disabled — rebuild with `--features mcp-http-probe`)")
    );
}

/// Display MCP stats from the `/status` JSON response.
#[cfg(feature = "mcp-http-probe")]
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_mcp_stats(palette: Palette, stats: &serde_json::Value) {
    let width = 11;
    let sessions = stats["active_sessions"].as_u64().unwrap_or(0);
    let total_sessions = stats["total_sessions"].as_u64().unwrap_or(0);
    let tool_calls = stats["tool_calls"].as_u64().unwrap_or(0);
    let tool_errors = stats["tool_errors"].as_u64().unwrap_or(0);
    println!(
        "{}",
        field(
            palette,
            "Sessions",
            &format!("{sessions} active / {total_sessions} total"),
            width
        )
    );
    println!(
        "{}",
        field(
            palette,
            "Tool calls",
            &format!("{tool_calls} ({tool_errors} errors)"),
            width
        )
    );
}

/// JSON for the MCP HTTP gateway section.
fn mcp_http_json() -> serde_json::Value {
    let info = match uffs_client::mcp_pid::parse_mcp_pid_file_full() {
        Some(info) if info.http_addr().is_some() => info,
        _ => return serde_json::json!({ "running": false }),
    };
    let running = uffs_client::mcp_pid::is_mcp_server_running().is_some();
    let endpoint = info
        .http_addr()
        .map(|(bind, port)| format!("http://{bind}:{port}/mcp"));
    serde_json::json!({
        "running": running,
        "pid": info.pid,
        "endpoint": endpoint,
    })
}

mod process_scan;
use process_scan::{mcp_stdio_json, print_mcp_stdio_section};

// ── small shared helpers ─────────────────────────────────────────────────────

/// Format a whole-second duration for display.
fn fmt_secs(secs: u64) -> String {
    uffs_client::format::format_duration(core::time::Duration::from_secs(secs))
}

/// Was the on-disk CLI binary modified after a process that has been up for
/// `uptime_secs` started? A `true` means the process is running a stale binary.
fn binary_is_newer_than(uptime_secs: u64) -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::metadata(path).ok())
        .and_then(|meta| meta.modified().ok())
        .is_some_and(|bin_mtime| {
            let started =
                std::time::SystemTime::now() - core::time::Duration::from_secs(uptime_secs);
            started < bin_mtime
        })
}

/// Did the MCP gateway (started at unix `start_ts`) predate the current binary?
fn mcp_started_before_binary(start_ts: u64) -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::metadata(path).ok())
        .and_then(|meta| meta.modified().ok())
        .is_some_and(|bin_mtime| {
            let started = std::time::UNIX_EPOCH + core::time::Duration::from_secs(start_ts);
            started < bin_mtime
        })
}

/// HTTP GET returning parsed JSON body (blocking).
#[cfg(feature = "mcp-http-probe")]
fn http_get_json(bind: &str, port: u16, path: &str) -> Result<serde_json::Value> {
    use std::io::{Read as _, Write as _};

    let addr = format!("{bind}:{port}");
    let mut stream =
        std::net::TcpStream::connect(&addr).with_context(|| format!("connect to {addr}"))?;
    _ = stream.set_read_timeout(Some(core::time::Duration::from_secs(5)));

    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    // AUDIT-OK(bytes): HTTP probe response body split for display only, not a
    // trust/targeting decision. (WI-4.3 follow-up)
    let text = String::from_utf8_lossy(&response);
    let body = text
        .split_once("\r\n\r\n")
        .map_or("", |(_, resp_body)| resp_body.trim());
    serde_json::from_str(body).with_context(|| format!("bad JSON from {path}: {body}"))
}
