// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `uffs --daemon status` — the read-only daemon status display.
//!
//! One unified view with three levels of detail:
//! * **short** (default) — health glyph, version, uptime, drives, query rate.
//! * **long** (`-v` / `--verbose`) — adds build fingerprint, elevation / broker
//!   mode, live-update loops, memory tiers, filesystem paths, the full
//!   per-drive memory breakdown, and performance counters (the former `--daemon
//!   stats`, now folded in here).
//! * **`--json`** — the machine-readable superset (status + drives + stats),
//!   for scripts and dashboards.
//!
//! Split out of `daemon_mgmt.rs` (which keeps the dispatch, elevation gate,
//! and the mutating start/stop/kill/restart handlers) so the pure rendering
//! concern lives beside its siblings `daemon_load.rs` / `daemon_tiering.rs`.

use anyhow::{Context as _, Result};
use uffs_client::connect_sync::UffsClientSync;
use uffs_client::daemon_ctl::pid_file_path;
use uffs_client::protocol::response::{
    DaemonStatus, DriveInfo, DriveMemoryInfo, ShardTier, StatsResponse, StatusResponse,
};
use uffs_statusfmt::{Glyph, Palette, field, header, section, status_row};

/// One mebibyte, for the `bytes → MB` display conversions.
const MIB: u64 = 1024 * 1024;

/// `uffs --daemon status [-v] [--json]` — show daemon status, PID, drives, and
/// (in long / JSON form) performance counters.
///
/// # Errors
///
/// Returns an error only if the daemon is reachable but a follow-up RPC
/// (`drives`) fails; a daemon that is simply not running renders the graceful
/// "not running" view and returns `Ok`.
pub(crate) fn daemon_status(verbose: bool, json: bool) -> Result<()> {
    let Ok(mut client) = UffsClientSync::connect_raw() else {
        return render_not_running(json);
    };
    let Ok(status) = client.status() else {
        return render_not_running(json);
    };
    let drives = client.drives().with_context(|| "Failed to query drives")?;
    // Performance counters are best-effort: an older daemon or a transient
    // error should not sink the whole status view.
    let perf = client.stats().ok();

    if json {
        return render_json(&status, &drives.drives, perf.as_ref());
    }
    render_human(
        Palette::detect(),
        verbose,
        &status,
        &drives.drives,
        perf.as_ref(),
    );
    Ok(())
}

/// Emit the machine-readable superset: daemon status + loaded drives + (when
/// available) performance counters, all under stable top-level keys.
#[expect(clippy::print_stdout, reason = "CLI --json output")]
fn render_json(
    status: &StatusResponse,
    drives: &[DriveInfo],
    perf: Option<&StatsResponse>,
) -> Result<()> {
    let doc = serde_json::json!({
        "running": true,
        "status": status,
        "drives": drives,
        "stats": perf,
    });
    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(())
}

/// Render the human-facing daemon status (short or long) with `palette` colour.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn render_human(
    palette: Palette,
    verbose: bool,
    status: &StatusResponse,
    drives: &[DriveInfo],
    perf: Option<&StatsResponse>,
) {
    println!("{}", header(palette, "UFFS Daemon"));
    let (glyph, state) = health(&status.status);
    let stale_tag = if binary_is_newer_than(status.uptime_secs) {
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
            &format!("PID {}{stale_tag}", status.pid),
        )
    );

    // Core block — always shown.
    let width = 11;
    println!(
        "{}",
        field(
            palette,
            "Version",
            &crate::commands::version_summary(&status.version),
            width
        )
    );
    println!(
        "{}",
        field(palette, "Uptime", &fmt_secs(status.uptime_secs), width)
    );
    print_drive_headline(palette, drives, width);
    if let Some(counters) = perf {
        print_query_headline(palette, counters, width);
    }

    if verbose {
        print_build_block(palette, status);
        print_live_update_block(palette, status);
        print_memory_block(palette, status);
        print_paths_block(palette, status);
        if let Some(counters) = perf {
            print_performance_block(palette, counters);
        }
        print_drive_detail_block(palette, drives, &status.drive_memory);
    }
}

/// Map the daemon's lifecycle phase to a health [`Glyph`] and a display label.
///
/// Shared with the combined `uffs --status` view so both surfaces agree on the
/// daemon's glyph and phase wording.
pub(crate) fn health(status: &DaemonStatus) -> (Glyph, String) {
    match status {
        DaemonStatus::Ready => (Glyph::Up, "running".to_owned()),
        DaemonStatus::Loading {
            drives_loaded,
            drives_total,
        } => (
            Glyph::Warn,
            format!("loading ({drives_loaded}/{drives_total} drives)"),
        ),
        DaemonStatus::Refreshing { drives } => {
            let list: String = drives
                .iter()
                .map(|letter| format!("{letter}:"))
                .collect::<Vec<_>>()
                .join(", ");
            (Glyph::Warn, format!("refreshing ({list})"))
        }
    }
}

/// One-line drive summary for the core block.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_drive_headline(palette: Palette, drives: &[DriveInfo], width: usize) {
    if drives.is_empty() {
        println!("{}", field(palette, "Drives", "(none loaded)", width));
        return;
    }
    let records: usize = drives.iter().map(|dr| dr.records).sum();
    let value = format!(
        "{} loaded \u{b7} {} records",
        drives.len(),
        uffs_client::format::format_number_commas(records as u64)
    );
    println!("{}", field(palette, "Drives", &value, width));
}

/// One-line query-rate summary for the core block.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_query_headline(palette: Palette, perf: &StatsResponse, width: usize) {
    if perf.total_queries == 0 {
        println!("{}", field(palette, "Queries", "0", width));
        return;
    }
    let avg =
        core::time::Duration::from_micros(uffs_client::format::f64_to_u64(perf.avg_query_time_us));
    let value = format!(
        "{} (avg {}, {:.1}/s)",
        perf.total_queries,
        uffs_client::format::format_duration(avg),
        perf.queries_per_second,
    );
    println!("{}", field(palette, "Queries", &value, width));
}

/// Verbose `── Build ──` section: commit + elevation / broker mode.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_build_block(palette: Palette, status: &StatusResponse) {
    let width = 9;
    println!("{}", section(palette, "Build"));
    let commit = if status.git_sha.is_empty() {
        "unknown"
    } else {
        status.git_sha.as_str()
    };
    println!("{}", field(palette, "Commit", commit, width));
    let mode = if status.elevated {
        "yes (direct elevated reads)".to_owned()
    } else if status.reading_via_broker {
        "no (reading via Access Broker, zero-UAC)".to_owned()
    } else {
        "no".to_owned()
    };
    println!("{}", field(palette, "Elevated", &mode, width));
}

/// Verbose `── Live update ──` section: USN journal loop liveness.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_live_update_block(palette: Palette, status: &StatusResponse) {
    println!("{}", section(palette, "Live update"));
    let value = match status.live_update {
        Some(info) if info.active_loops > 0 => {
            format!("{} journal loop(s) running", info.active_loops)
        }
        _ => "inactive (offline source or non-Windows)".to_owned(),
    };
    println!("{}", field(palette, "Journal", &value, 9));
}

/// Verbose `── Memory ──` section: logical heap, allocator-committed, RSS.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_memory_block(palette: Palette, status: &StatusResponse) {
    if status.index_heap_bytes.is_none()
        && status.mimalloc_committed_bytes.is_none()
        && status.rss_bytes.is_none()
    {
        return;
    }
    let width = 11;
    println!("{}", section(palette, "Memory"));
    if let Some(heap) = status.index_heap_bytes {
        println!(
            "{}",
            field(palette, "Index heap", &format!("{} MB", heap / MIB), width)
        );
    }
    if let Some(committed) = status.mimalloc_committed_bytes {
        println!(
            "{}",
            field(
                palette,
                "Mimalloc",
                &format!("{} MB committed", committed / MIB),
                width
            )
        );
    }
    if let Some(rss) = status.rss_bytes {
        println!(
            "{}",
            field(palette, "RSS", &format!("{} MB", rss / MIB), width)
        );
    }
}

/// Verbose `── Paths ──` section: where the daemon keeps data, socket, logs.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_paths_block(palette: Palette, status: &StatusResponse) {
    let Some(paths) = status.paths.as_ref() else {
        return;
    };
    let width = 8;
    println!("{}", section(palette, "Paths"));
    if !paths.data_dir.is_empty() {
        println!("{}", field(palette, "Data", &paths.data_dir, width));
    }
    if !paths.socket.is_empty() {
        println!("{}", field(palette, "Socket", &paths.socket, width));
    }
    if !paths.log_dir.is_empty() {
        println!("{}", field(palette, "Logs", &paths.log_dir, width));
    }
}

/// Verbose `── Performance ──` section: the former `--daemon stats`, folded in.
///
/// Field labels are kept stable (`Total records:`, `Queries served:`,
/// `Avg query time:`, `Agg cache:`, …) because the live-Windows benchmark /
/// validation harnesses scrape them by name.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_performance_block(palette: Palette, perf: &StatsResponse) {
    let width = 17;
    let fmt = uffs_client::format::format_duration;
    println!("{}", section(palette, "Performance"));
    println!(
        "{}",
        field(
            palette,
            "Startup duration",
            &fmt(core::time::Duration::from_millis(perf.startup_duration_ms)),
            width
        )
    );
    println!(
        "{}",
        field(
            palette,
            "Total records",
            &uffs_client::format::format_number_commas(perf.total_records as u64),
            width
        )
    );
    println!(
        "{}",
        field(
            palette,
            "Queries served",
            &perf.total_queries.to_string(),
            width
        )
    );
    if perf.total_queries > 0 {
        let avg = core::time::Duration::from_micros(uffs_client::format::f64_to_u64(
            perf.avg_query_time_us,
        ));
        println!("{}", field(palette, "Avg query time", &fmt(avg), width));
        println!(
            "{}",
            field(
                palette,
                "Total query time",
                &fmt(core::time::Duration::from_micros(perf.total_query_time_us)),
                width
            )
        );
    }
    println!(
        "{}",
        field(
            palette,
            "Queries/second",
            &format!("{:.2}", perf.queries_per_second),
            width
        )
    );
    let lookups = perf.agg_cache_hits.saturating_add(perf.agg_cache_misses);
    let hit_rate = hit_rate_percent(perf.agg_cache_hits, lookups);
    println!(
        "{}",
        field(
            palette,
            "Agg cache",
            &format!(
                "{} hits / {} misses ({hit_rate:.1}% hit-rate, {} entries)",
                perf.agg_cache_hits, perf.agg_cache_misses, perf.agg_cache_entries
            ),
            width
        )
    );
}

/// Verbose `── Drives ──` section: full per-drive tier + memory breakdown.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_drive_detail_block(palette: Palette, drives: &[DriveInfo], memory: &[DriveMemoryInfo]) {
    println!("{}", section(palette, "Drives"));
    if drives.is_empty() {
        println!("  {}", palette.dim("(none loaded)"));
        return;
    }
    for dr in drives {
        print_drive_line(palette, dr, memory);
    }
}

/// Render one detailed drive row, tier-aware, with a colour-coded glyph.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_drive_line(palette: Palette, dr: &DriveInfo, memory: &[DriveMemoryInfo]) {
    let glyph = tier_glyph(dr.tier).render(palette);
    let letter = palette.bold(&format!("{}:", dr.letter));
    match dr.tier {
        Some(ShardTier::Warm | ShardTier::Hot) | None => {
            let records = uffs_client::format::format_number_commas(dr.records as u64);
            match memory.iter().find(|dm| dm.drive == dr.letter) {
                Some(dm) => {
                    let mb = |bytes: u64| bytes / MIB;
                    println!(
                        "  {glyph} {letter} {records:>12} records ({}) \u{b7} {} MB  [rec={} names={} tri={} ch={} ext={}]",
                        dr.source,
                        mb(dm.heap_bytes),
                        mb(dm.records_bytes),
                        mb(dm.names_bytes),
                        mb(dm.trigram_bytes),
                        mb(dm.children_bytes),
                        mb(dm.ext_index_bytes),
                    );
                }
                None => {
                    println!("  {glyph} {letter} {records:>12} records ({})", dr.source);
                }
            }
        }
        Some(ShardTier::Parked) => {
            println!(
                "  {glyph} {letter} {}",
                palette.dim("bloom + trie resident; body released")
            );
        }
        Some(ShardTier::Cold) => {
            println!(
                "  {glyph} {letter} {}",
                palette.dim("encrypted cache only; nothing in RAM")
            );
        }
        Some(ShardTier::Evicting | ShardTier::Unknown) => {
            println!("  {glyph} {letter} ({})", dr.source);
        }
    }
}

/// Map a shard tier to the shared health glyph: Hot/Warm are up, Parked is
/// transitional, Cold/Evicting/Unknown are down/off.
const fn tier_glyph(tier: Option<ShardTier>) -> Glyph {
    match tier {
        Some(ShardTier::Hot | ShardTier::Warm) | None => Glyph::Up,
        Some(ShardTier::Parked) => Glyph::Warn,
        Some(ShardTier::Cold | ShardTier::Evicting) => Glyph::Down,
        Some(ShardTier::Unknown) => Glyph::Off,
    }
}

/// Render the graceful "daemon not running" view (human or JSON).
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn render_not_running(json: bool) -> Result<()> {
    if json {
        let doc = serde_json::json!({ "running": false });
        println!("{}", serde_json::to_string_pretty(&doc)?);
        return Ok(());
    }
    let palette = Palette::detect();
    println!(
        "{}",
        status_row(palette, Glyph::Down, "Daemon", "not running")
    );
    let pid_path = pid_file_path();
    if pid_path.exists() {
        // A PID file with no reachable daemon is usually stale — but not always.
        // On Windows `is_pid_alive` confirms the PID is a live *uffsd* (a
        // recycled PID owned by an unrelated process reads as not-alive), so a
        // live result here means a real daemon holds the PID yet the IPC
        // endpoint did not answer: it is still loading, or it is wedged. Say so
        // rather than mislabeling a live daemon "stale".
        let note = match uffs_client::daemon_ctl::parse_pid_file(&pid_path) {
            Some((pid, ..)) if uffs_client::daemon_ctl::is_pid_alive(pid) => format!(
                "(daemon process is alive at PID {pid} but not answering on IPC — it may \
                 still be loading, or it is wedged; run `uffs --daemon restart` to clear it)"
            ),
            _ => format!("(stale PID file at {})", pid_path.display()),
        };
        println!("  {}", palette.dim(&note));
    }
    Ok(())
}

/// Print the "not running" message for sibling read-only commands.
///
/// Visible to `daemon_tiering.rs` so the graceful "daemon down" rendering
/// stays consistent across every read-only daemon command. Mutating commands
/// (`hibernate` / `preload` / `forget`) deliberately stay on the bail-with-
/// error path because the operator should know their mutation didn't run.
pub(crate) fn print_not_running() {
    // Human view only; callers that want JSON go through `daemon_status`.
    let _ignored = render_not_running(false);
}

/// Format a whole-second duration for display.
fn fmt_secs(secs: u64) -> String {
    uffs_client::format::format_duration(core::time::Duration::from_secs(secs))
}

/// Was the on-disk CLI binary modified *after* the daemon started? A `true`
/// means the running daemon is older than the installed binary (stale).
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

/// Aggregate-cache hit-rate as a percentage; `0.0` when there were no lookups
/// (avoids a divide-by-zero on cold daemons). Rendered with `{:.1}` so the
/// cast's precision loss is invisible.
#[expect(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    reason = "telemetry hit-rate percent; rendered with `{:.1}` so precision loss is invisible"
)]
fn hit_rate_percent(hits: u64, lookups: u64) -> f64 {
    if lookups == 0 {
        return 0.0_f64;
    }
    (hits as f64 / lookups as f64) * 100.0_f64
}
