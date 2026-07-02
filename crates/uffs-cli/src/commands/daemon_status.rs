// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `uffs --daemon status` / `uffs --daemon stats` — the read-only daemon
//! status and performance displays.
//!
//! Split out of `daemon_mgmt.rs` (which keeps the dispatch, elevation gate,
//! and the mutating start/stop/kill/restart handlers) so the pure rendering
//! concern lives beside its siblings `daemon_load.rs` / `daemon_tiering.rs`.

use anyhow::{Context as _, Result};
use uffs_client::connect_sync::UffsClientSync;
use uffs_client::daemon_ctl::pid_file_path;
use uffs_client::protocol::response::{DaemonStatus, DriveInfo, ShardTier};

/// `uffs --daemon status` — show daemon status, PID, loaded drives.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn daemon_status() -> Result<()> {
    let Ok(mut client) = UffsClientSync::connect_raw() else {
        print_not_running();
        return Ok(());
    };

    let Ok(status) = client.status() else {
        print_not_running();
        return Ok(());
    };

    let uptime = core::time::Duration::from_secs(status.uptime_secs);
    println!(
        "Version:       {}",
        crate::commands::version_summary(&status.version)
    );
    println!("Daemon PID:    {}", status.pid);
    println!(
        "Uptime:        {}",
        uffs_client::format::format_duration(uptime)
    );
    match &status.status {
        DaemonStatus::Loading {
            drives_loaded,
            drives_total,
        } => {
            println!("Status:        Loading ({drives_loaded}/{drives_total} drives)");
        }
        DaemonStatus::Ready => {
            println!("Status:        Ready");
        }
        DaemonStatus::Refreshing { drives } => {
            let drive_list: String = drives
                .iter()
                .map(|letter| format!("{letter}:"))
                .collect::<Vec<_>>()
                .join(", ");
            println!("Status:        Refreshing ({drive_list})");
        }
    }
    println!("Connections:   {}", status.connections);

    // Memory info.  Three numbers, in increasing order of "what the OS
    // sees": logical heap (sum of per-drive `heap_size_bytes`), then
    // mimalloc's committed pages, then the OS-reported RSS.  All three
    // come from the same `status` payload so they are consistent.
    if let Some(heap) = status.index_heap_bytes {
        println!("Index heap:    {} MB", heap / (1024 * 1024));
    }
    if let Some(committed) = status.mimalloc_committed_bytes {
        println!(
            "Mimalloc:      {} MB (committed)",
            committed / (1024 * 1024)
        );
    }
    if let Some(rss) = status.rss_bytes {
        println!("RSS:           {} MB", rss / (1024 * 1024));
    }

    // Also show loaded drives.  The `drives` RPC returns every shard
    // in the registry — Warm/Hot with their full memory breakdown,
    // Parked/Cold with just the tier marker (no body in RAM).  Empty
    // registry still renders `(none loaded)` so cold-boot detection in
    // external scripts (api-validation, mcp-validation) keeps working.
    let drives = client.drives().with_context(|| "Failed to query drives")?;
    if drives.drives.is_empty() {
        println!("Drives:        (none loaded)");
    } else {
        println!("Drives:");
        for dr in &drives.drives {
            print_drive_line(dr, &status.drive_memory);
        }
    }
    Ok(())
}

/// Render one row of the `Drives:` block in `daemon status`.
///
/// Format depends on the shard's tier (per Phase 5 task 5.11):
/// * Warm/Hot — full breakdown (records count, source, memory rec= / names= /
///   tri= / ch= / ext=).
/// * Parked  — `[Parked]` marker + bloom + trie kept resident note.
/// * Cold    — `[Cold]` marker only (no body, no filters).
/// * Other   — fall back to the legacy single-line format so the formatter
///   never panics on a state we haven't taught it about.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_drive_line(
    dr: &DriveInfo,
    drive_memory: &[uffs_client::protocol::response::DriveMemoryInfo],
) {
    let tier_marker = tier_marker(dr.tier);
    match dr.tier {
        Some(ShardTier::Warm | ShardTier::Hot) | None => {
            let mem = drive_memory.iter().find(|dm| dm.drive == dr.letter);
            if let Some(dm) = mem {
                let mb = |bytes: u64| bytes / (1024 * 1024);
                println!(
                    "  {} {}: — {:>10} records ({}) — {} MB  [rec={} names={} tri={} ch={} ext={}]",
                    tier_marker,
                    dr.letter,
                    uffs_client::format::format_number_commas(dr.records as u64),
                    dr.source,
                    mb(dm.heap_bytes),
                    mb(dm.records_bytes),
                    mb(dm.names_bytes),
                    mb(dm.trigram_bytes),
                    mb(dm.children_bytes),
                    mb(dm.ext_index_bytes),
                );
            } else {
                println!(
                    "  {} {}: — {:>10} records ({})",
                    tier_marker,
                    dr.letter,
                    uffs_client::format::format_number_commas(dr.records as u64),
                    dr.source
                );
            }
        }
        Some(ShardTier::Parked) => {
            println!(
                "  {} {}: — bloom + trie kept resident; body released",
                tier_marker, dr.letter
            );
        }
        Some(ShardTier::Cold) => {
            println!(
                "  {} {}: — encrypted cache only; nothing in RAM",
                tier_marker, dr.letter
            );
        }
        Some(ShardTier::Evicting | ShardTier::Unknown) => {
            println!("  {} {}: — ({})", tier_marker, dr.letter, dr.source);
        }
    }
}

/// Format the bracket-style tier marker for `daemon status`'s drive
/// list.  An 8-character right-padded label so the per-drive lines
/// align in the operator's terminal.
const fn tier_marker(tier: Option<ShardTier>) -> &'static str {
    match tier {
        Some(ShardTier::Hot) => "[Hot]   ",
        Some(ShardTier::Warm) => "[Warm]  ",
        Some(ShardTier::Parked) => "[Parked]",
        Some(ShardTier::Cold) => "[Cold]  ",
        Some(ShardTier::Evicting) => "[Evict] ",
        Some(ShardTier::Unknown) => "[?]     ",
        None => "        ",
    }
}

/// Print the "not running" message with optional stale-PID hint.
///
/// Visible to sibling command modules (`daemon_tiering.rs`) so the
/// graceful "daemon down" rendering stays consistent across every
/// read-only daemon command — the operator sees the **same** stdout
/// shape from `uffs --daemon status` and `uffs --daemon status_drives`
/// when the daemon happens to be down.  Mutating commands
/// (`hibernate` / `preload` / `forget`) deliberately stay on the
/// bail-with-error path because the operator should know their
/// requested mutation didn't run.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_not_running() {
    println!("Daemon is not running.");
    let pid_path = pid_file_path();
    if pid_path.exists() {
        println!("  (stale PID file exists at {})", pid_path.display());
    }
}

/// `uffs --daemon stats` — show performance metrics.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn daemon_stats() -> Result<()> {
    if let Ok(mut client) = UffsClientSync::connect_raw() {
        let stats = client
            .stats()
            .with_context(|| "Failed to query daemon stats")?;

        let fmt = uffs_client::format::format_duration;
        let uptime = core::time::Duration::from_secs(stats.uptime_secs);
        let startup = core::time::Duration::from_millis(stats.startup_duration_ms);
        let avg_query = core::time::Duration::from_micros(uffs_client::format::f64_to_u64(
            stats.avg_query_time_us,
        ));
        let total_query = core::time::Duration::from_micros(stats.total_query_time_us);

        println!("═══ Daemon Performance Stats ═══");
        println!(
            "Version:           {}",
            crate::commands::version_summary(&stats.version)
        );
        println!("Uptime:            {}", fmt(uptime));
        println!("Startup duration:  {}", fmt(startup));
        println!(
            "Total records:     {}",
            uffs_client::format::format_number_commas(stats.total_records as u64)
        );
        println!("Queries served:    {}", stats.total_queries);
        if stats.total_queries > 0 {
            println!("Avg query time:    {}", fmt(avg_query));
            println!("Total query time:  {}", fmt(total_query));
        }
        println!("Queries/second:    {:.2}", stats.queries_per_second);

        // Aggregate cache observability.  Hit-rate is computed on
        // demand to avoid a division-by-zero for cold daemons.
        let lookups = stats.agg_cache_hits.saturating_add(stats.agg_cache_misses);
        let hit_rate = compute_hit_rate_percent(stats.agg_cache_hits, lookups);
        println!(
            "Agg cache:         {} hits / {} misses ({:.1}% hit-rate, {} entries)",
            stats.agg_cache_hits, stats.agg_cache_misses, hit_rate, stats.agg_cache_entries,
        );
    } else {
        println!("Daemon is not running.");
    }
    Ok(())
}

/// Compute aggregate-cache hit-rate as a percentage for daemon status display.
///
/// Returns `0.0` when no lookups have occurred, avoiding a division by
/// zero on cold daemons.  The `cast_precision_loss` expect is justified
/// for telemetry display: well over `2^53` cache lookups would be
/// required to lose a single bit of precision, and the output is
/// rendered with `{:.1}` so single-bit differences are invisible.
#[expect(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    reason = "telemetry hit-rate percent; rendered with `{:.1}` so precision loss is invisible"
)]
fn compute_hit_rate_percent(hits: u64, lookups: u64) -> f64 {
    if lookups == 0 {
        return 0.0_f64;
    }
    (hits as f64 / lookups as f64) * 100.0_f64
}
