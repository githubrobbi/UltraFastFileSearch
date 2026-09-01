// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

// CLI aggregate formatter: tabular output with terse loop vars, println for
// user-facing output, and controlled precision casts for display.
#![allow(
    clippy::min_ident_chars,
    clippy::print_stdout,
    clippy::redundant_pub_crate,
    clippy::default_numeric_fallback,
    clippy::collapsible_if,
    reason = "CLI display code: terse loop vars, stdout output"
)]

//! Aggregate command implementation.
//!
//! Runs aggregate analytics via the daemon and prints results.

use std::io::Write;

use anyhow::Result;
use uffs_client::protocol::AggregateResultWire;

use super::search::run_search;
use super::{format_number, format_size};
use crate::args;

/// Handle `uffs --agg|agg <preset> [--format ...] [--data-dir ...]`.
///
/// # Errors
///
/// Returns an error when no preset is given or when the synthesised
/// aggregate search fails.
pub(crate) fn run_aggregate(args: &[String]) -> Result<()> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        args::print_aggregate_help();
        return Ok(());
    }
    // Extract the preset (first positional arg).
    let preset = args
        .iter()
        .find(|arg| !arg.starts_with('-'))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Usage: uffs --agg <PRESET>\n\
                 Available presets: overview, by_type, by_extension, by_drive, by_size, by_age, count"
            )
        })?;

    // Synthesise search args: `* --agg <preset> --limit 0 [remaining flags]`.
    let mut synth_args = vec![
        "*".to_owned(),
        "--agg".to_owned(),
        preset.clone(),
        "--limit".to_owned(),
        "0".to_owned(),
    ];
    // Default to table format for `uffs --agg` unless user specifies --format.
    let has_format = args.iter().any(|arg| arg == "--format" || arg == "-f");
    if !has_format {
        synth_args.extend(["--format".to_owned(), "table".to_owned()]);
    }
    // Forward all flags (skip the preset positional).
    for arg in args {
        if arg == preset {
            continue;
        }
        synth_args.push(arg.clone());
    }
    run_search(&synth_args)
}

/// Print aggregate results in a human-readable table format.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub(crate) fn print_table_results(results: &[AggregateResultWire]) -> Result<()> {
    let mut stdout = std::io::stdout().lock();

    for result in results {
        let label = result.label.as_deref().unwrap_or(&result.kind);

        writeln!(stdout, "\n=== {label} ===")?;

        match result.kind.as_str() {
            "count" => {
                if let Some(value) = result.value {
                    writeln!(stdout, "  Total: {}", format_number(value))?;
                }
            }
            "stats" => {
                if let Some(stats) = &result.stats {
                    writeln!(stdout, "  Count:  {}", format_number(stats.count))?;
                    writeln!(stdout, "  Sum:    {}", format_size(stats.sum))?;
                    writeln!(stdout, "  Min:    {}", format_size(stats.min))?;
                    writeln!(stdout, "  Max:    {}", format_size(stats.max))?;
                    writeln!(
                        stdout,
                        "  Avg:    {}",
                        format_size(uffs_client::format::f64_to_u64(stats.avg))
                    )?;
                    if stats.waste_bytes > 0 {
                        writeln!(
                            stdout,
                            "  Waste:  {} ({:.1}%)",
                            format_size(stats.waste_bytes),
                            stats.waste_pct
                        )?;
                    }
                }
            }
            "buckets" | "rollup" => {
                if result.buckets.is_empty() {
                    writeln!(stdout, "  (no data)")?;
                } else {
                    print_table_buckets(&mut stdout, result)?;
                }
            }
            "duplicates" => {
                if result.buckets.is_empty() {
                    writeln!(stdout, "  (no data)")?;
                } else {
                    print_duplicate_table(&mut stdout, result)?;
                }
            }
            "missing" | "distinct" => {
                if let Some(value) = result.value {
                    writeln!(stdout, "  {}: {}", result.kind, format_number(value))?;
                }
            }
            _ => {
                writeln!(stdout, "  (unknown result kind: {})", result.kind)?;
            }
        }
    }

    writeln!(stdout)?;
    Ok(())
}

/// Print aggregate results in CSV/TSV format.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub(crate) fn print_csv_results(results: &[AggregateResultWire], tsv: bool) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    let sep = if tsv { '\t' } else { ',' };

    for result in results {
        let label = result.label.as_deref().unwrap_or(&result.kind);

        match result.kind.as_str() {
            "count" => {
                writeln!(stdout, "# {label}")?;
                writeln!(stdout, "count")?;
                if let Some(v) = result.value {
                    writeln!(stdout, "{v}")?;
                }
            }
            "stats" => {
                if let Some(stats) = &result.stats {
                    writeln!(stdout, "# {label}")?;
                    writeln!(
                        stdout,
                        "count{sep}sum{sep}min{sep}max{sep}avg{sep}waste_bytes{sep}waste_pct"
                    )?;
                    writeln!(
                        stdout,
                        "{}{sep}{}{sep}{}{sep}{}{sep}{:.2}{sep}{}{sep}{:.2}",
                        stats.count,
                        stats.sum,
                        stats.min,
                        stats.max,
                        stats.avg,
                        stats.waste_bytes,
                        stats.waste_pct
                    )?;
                }
            }
            "buckets" | "rollup" => {
                writeln!(stdout, "# {label}")?;
                print_csv_buckets(&mut stdout, result, sep)?;
            }
            "duplicates" => {
                writeln!(stdout, "# {label}")?;
                print_csv_duplicates(&mut stdout, result, sep)?;
            }
            "missing" | "distinct" => {
                writeln!(stdout, "# {label}")?;
                writeln!(stdout, "value")?;
                if let Some(v) = result.value {
                    writeln!(stdout, "{v}")?;
                }
            }
            _ => {}
        }
        writeln!(stdout)?;
    }

    Ok(())
}

/// Render bucket rows (terms, rollup, duplicates) in table format.
fn print_table_buckets(stdout: &mut impl Write, result: &AggregateResultWire) -> Result<()> {
    writeln!(
        stdout,
        "  {:<30} {:>12} {:>14} {:>8} {:>8}",
        "Key", "Count", "Total Size", "Count%", "Size%"
    )?;
    writeln!(
        stdout,
        "  {:-<30} {:-<12} {:-<14} {:-<8} {:-<8}",
        "", "", "", "", ""
    )?;
    for row in &result.buckets {
        let share_c = row.share_count.unwrap_or(0.0);
        let share_b = row.share_bytes.unwrap_or(0.0);
        writeln!(
            stdout,
            "  {:<30} {:>12} {:>14} {:>7.1}% {:>7.1}%",
            row.key,
            format_number(row.count),
            format_size(row.total_bytes),
            share_c,
            share_b
        )?;
        // Sample rows (top-hits).
        for sr in &row.sample_rows {
            let name = sr.fields.get("name").map_or("?", |s| s.as_str());
            let size = sr
                .fields
                .get("size")
                .and_then(|s| s.parse::<u64>().ok())
                .map_or_else(String::new, |n| format!(" ({})", format_size(n)));
            let modified = sr
                .fields
                .get("modified")
                .map_or(String::new(), |s| format!(" mod:{s}"));
            writeln!(stdout, "    → {name}{size}{modified}")?;
        }
        // Nested sub-aggregation buckets.
        for sub in &row.sub_buckets {
            let sc = sub.share_count.unwrap_or(0.0);
            let sb = sub.share_bytes.unwrap_or(0.0);
            writeln!(
                stdout,
                "    ├─ {:<26} {:>12} {:>14} {:>7.1}% {:>7.1}%",
                sub.key,
                format_number(sub.count),
                format_size(sub.total_bytes),
                sc,
                sb
            )?;
        }
    }
    if let Some(other) = result.other_count {
        if other > 0 {
            writeln!(
                stdout,
                "  ... and {} more groups ({} records)",
                result
                    .total_groups
                    .unwrap_or(0)
                    .saturating_sub(result.buckets.len()),
                format_number(other)
            )?;
        }
    }
    if result.values_complete == Some(false) {
        writeln!(stdout, "  [truncated — not all values shown]")?;
    }
    if let Some(cursor) = &result.next_cursor {
        writeln!(stdout, "  [next page: --agg-cursor {cursor}]")?;
    }
    Ok(())
}

/// Print dedicated duplicate-group table.
///
/// Shows a summary header with total groups/files/reclaimable, then a
/// table with human-readable keys, copies, file size, reclaimable bytes,
/// and verified status.  Sample rows are rendered as indented `→` lines
/// showing member file paths.
fn print_duplicate_table(stdout: &mut impl Write, result: &AggregateResultWire) -> Result<()> {
    // ── Summary header ──────────────────────────────────────────────
    if let Some(stats) = &result.stats {
        let groups = result.total_groups.unwrap_or(result.buckets.len());
        writeln!(
            stdout,
            "  Groups: {}  Files: {}  Reclaimable: {}",
            format_number(groups as u64), // usize→u64 lossless on 64-bit
            format_number(stats.count),
            format_size(stats.waste_bytes),
        )?;
        writeln!(stdout)?;
    }

    // ── Column header ───────────────────────────────────────────────
    writeln!(
        stdout,
        "  {:<40} {:>8} {:>12} {:>14} {:>5}",
        "Name", "Copies", "File Size", "Reclaimable", "  ✓"
    )?;
    writeln!(
        stdout,
        "  {:-<40} {:-<8} {:-<12} {:-<14} {:-<5}",
        "", "", "", "", ""
    )?;

    for row in &result.buckets {
        let reclaimable = row.total_allocated.unwrap_or(0);
        let file_size = uffs_client::format::f64_to_u64(row.avg_size.unwrap_or(0.0));
        let verified_mark = if row.verified { " ✓" } else { "" };

        writeln!(
            stdout,
            "  {:<40} {:>8} {:>12} {:>14} {:>5}",
            truncate_str(&row.key, 40),
            format_number(row.count),
            format_size(file_size),
            format_size(reclaimable),
            verified_mark,
        )?;

        // Sample rows: show member file locations.
        for sr in &row.sample_rows {
            let name = sr.fields.get("name").map_or("?", |s| s.as_str());
            let path = sr
                .fields
                .get("path")
                .map_or(String::new(), |s| format!(" {s}"));
            let size = sr
                .fields
                .get("size")
                .and_then(|s| s.parse::<u64>().ok())
                .map_or_else(String::new, |n| format!(" ({})", format_size(n)));
            writeln!(stdout, "    → {name}{size}{path}")?;
        }
    }

    // ── Overflow ────────────────────────────────────────────────────
    if let Some(total) = result.total_groups {
        let shown = result.buckets.len();
        if total > shown {
            writeln!(
                stdout,
                "  ... and {} more groups",
                format_number((total - shown) as u64), // usize→u64 lossless on 64-bit
            )?;
        }
    }

    Ok(())
}

/// Truncate a string to `max` chars, appending `…` if truncated.
fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let truncated: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{truncated}…")
    }
}

/// Render bucket rows in CSV/TSV format.
fn print_csv_buckets(
    stdout: &mut impl Write,
    result: &AggregateResultWire,
    sep: char,
) -> Result<()> {
    let has_samples = result.buckets.iter().any(|r| !r.sample_rows.is_empty());
    let has_drill = result.buckets.iter().any(|r| !r.drilldown.is_empty());

    write!(
        stdout,
        "key{sep}count{sep}total_bytes{sep}total_allocated{sep}avg_size{sep}share_count{sep}share_bytes"
    )?;
    if has_samples {
        write!(stdout, "{sep}samples")?;
    }
    if has_drill {
        write!(stdout, "{sep}drilldown")?;
    }
    writeln!(stdout)?;

    for row in &result.buckets {
        write!(
            stdout,
            "{}{sep}{}{sep}{}{sep}{}{sep}{:.2}{sep}{:.2}{sep}{:.2}",
            row.key,
            row.count,
            row.total_bytes,
            row.total_allocated.unwrap_or(0),
            row.avg_size.unwrap_or(0.0),
            row.share_count.unwrap_or(0.0),
            row.share_bytes.unwrap_or(0.0),
        )?;
        if has_samples {
            let json = serde_json::to_string(&row.sample_rows).unwrap_or_else(|_| "[]".to_owned());
            write!(stdout, "{sep}{json}")?;
        }
        if has_drill {
            let json = serde_json::to_string(&row.drilldown).unwrap_or_else(|_| "[]".to_owned());
            write!(stdout, "{sep}{json}")?;
        }
        writeln!(stdout)?;
        // Nested sub-aggregation rows prefixed with parent key.
        for sub in &row.sub_buckets {
            writeln!(
                stdout,
                "{}/{}{sep}{}{sep}{}{sep}{}{sep}{:.2}{sep}{:.2}{sep}{:.2}",
                row.key,
                sub.key,
                sub.count,
                sub.total_bytes,
                sub.total_allocated.unwrap_or(0),
                sub.avg_size.unwrap_or(0.0),
                sub.share_count.unwrap_or(0.0),
                sub.share_bytes.unwrap_or(0.0),
            )?;
        }
    }
    // CSV metadata comments.
    if let Some(other) = result.other_count {
        if other > 0 {
            writeln!(stdout, "# other_count={other}")?;
        }
    }
    if result.values_complete == Some(false) {
        writeln!(stdout, "# values_complete=false")?;
    }
    if let Some(cursor) = &result.next_cursor {
        writeln!(stdout, "# next_cursor={cursor}")?;
    }
    Ok(())
}

/// Render duplicate groups in CSV/TSV format with dedicated columns.
fn print_csv_duplicates(
    stdout: &mut impl Write,
    result: &AggregateResultWire,
    sep: char,
) -> Result<()> {
    let has_samples = result.buckets.iter().any(|r| !r.sample_rows.is_empty());

    // Summary metadata.
    if let Some(stats) = &result.stats {
        writeln!(
            stdout,
            "# total_groups={} total_files={} total_reclaimable={}",
            result.total_groups.unwrap_or(result.buckets.len()),
            stats.count,
            stats.waste_bytes,
        )?;
    }

    // Header row.
    write!(
        stdout,
        "key{sep}copies{sep}file_size{sep}total_bytes{sep}reclaimable{sep}verified"
    )?;
    if has_samples {
        write!(stdout, "{sep}samples")?;
    }
    writeln!(stdout)?;

    for row in &result.buckets {
        let reclaimable = row.total_allocated.unwrap_or(0);
        let file_size = uffs_client::format::f64_to_u64(row.avg_size.unwrap_or(0.0));
        write!(
            stdout,
            "{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}",
            row.key, row.count, file_size, row.total_bytes, reclaimable, row.verified,
        )?;
        if has_samples {
            let json = serde_json::to_string(&row.sample_rows).unwrap_or_else(|_| "[]".to_owned());
            write!(stdout, "{sep}{json}")?;
        }
        writeln!(stdout)?;
    }

    // Overflow metadata.
    if let Some(total) = result.total_groups {
        let shown = result.buckets.len();
        if total > shown {
            writeln!(stdout, "# remaining_groups={}", total - shown)?;
        }
    }

    Ok(())
}

// ── Raw Value wrappers (thin-client path) ──────────────────────────────

/// Print aggregate results from raw JSON values in table format.
///
/// Deserializes each `Value` into `AggregateResultWire` on-the-fly,
/// then delegates to [`print_table_results`].
///
/// # Errors
///
/// Returns an error if deserialization or output fails.
pub(crate) fn print_table_results_raw(raw: &[serde_json::Value]) -> Result<()> {
    let typed: Vec<AggregateResultWire> = raw
        .iter()
        .filter_map(|val| serde_json::from_value(val.clone()).ok())
        .collect();
    print_table_results(&typed)
}

/// Print aggregate results from raw JSON values in CSV/TSV format.
///
/// # Errors
///
/// Returns an error if deserialization or output fails.
pub(crate) fn print_csv_results_raw(raw: &[serde_json::Value], tsv: bool) -> Result<()> {
    let typed: Vec<AggregateResultWire> = raw
        .iter()
        .filter_map(|val| serde_json::from_value(val.clone()).ok())
        .collect();
    print_csv_results(&typed, tsv)
}
