// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `verify` command — canonical parity comparison of two MFT CSV exports.
//!
//! Cross-platform: compares two CSVs written by `uffs-mft load` (e.g.
//! Rust-on-Windows vs Rust-on-macOS, or Rust vs a C++ golden). Rows are
//! projected onto key columns matched by header *name*, so column order may
//! differ; duplicates are compared as a multiset. Exits non-zero on any
//! divergence, so it drops into scripts.
#![expect(
    clippy::print_stdout,
    reason = "intentional user-facing CLI parity report"
)]

use std::io::BufRead as _;
use std::path::Path;

use anyhow::{Context as _, Result};
use uffs_mft::parity::{self, ParityReport};

/// Stream one CSV into canonical row keys. When `columns` is empty the file's
/// own header is used as the comparison column set (returned so the second file
/// can be projected onto the same columns).
fn stream_keys(path: &Path, columns: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut lines = std::io::BufReader::new(file).lines();

    let header_line = lines
        .next()
        .with_context(|| format!("{} is empty (no CSV header)", path.display()))?
        .with_context(|| format!("reading header of {}", path.display()))?;
    let header = parity::split_csv_line(&header_line);
    let wanted: Vec<String> = if columns.is_empty() {
        header.clone()
    } else {
        columns.to_vec()
    };
    let indices = parity::header_indices(&header, &wanted)?;

    let mut keys: Vec<String> = Vec::new();
    for line_result in lines {
        let line = line_result.with_context(|| format!("reading {}", path.display()))?;
        if line.is_empty() {
            continue;
        }
        let fields = parity::split_csv_line(&line);
        keys.push(parity::row_key(&fields, &indices));
    }
    Ok((wanted, keys))
}

/// Render a key (control-separated components) for display.
fn show_key(key: &str) -> String {
    key.replace('\u{1}', " | ")
}

/// Print the parity report; returns whether the sides matched.
fn print_report(left: &Path, right: &Path, wanted: &[String], report: &ParityReport) {
    println!("═══ UFFS verify — MFT parity ═══");
    println!("  A: {}  ({} rows)", left.display(), report.a_rows);
    println!("  B: {}  ({} rows)", right.display(), report.b_rows);
    println!("  Columns compared: {}", wanted.join(", "));
    println!("  Common rows: {}", report.common);
    println!("  Only in A:   {}", report.only_a_total);
    println!("  Only in B:   {}", report.only_b_total);

    for (label, sample) in [("A", &report.only_a), ("B", &report.only_b)] {
        for key in sample {
            println!("    only {label}: {}", show_key(key));
        }
    }

    if report.matched() {
        println!("  ✅ MATCH — the two exports are identical over the compared columns.");
    } else {
        println!("  ❌ MISMATCH — see divergent rows above.");
    }
}

/// Compare two MFT CSV exports and report parity.
///
/// # Errors
///
/// Returns an error if either file cannot be read, a requested column is
/// missing, or the two exports diverge (so the process exits non-zero).
pub(crate) fn cmd_verify(left: &Path, right: &Path, columns: &[String]) -> Result<()> {
    // The first file establishes the comparison columns when none were given.
    let (wanted, left_keys) = stream_keys(left, columns)?;
    let (_, right_keys) = stream_keys(right, &wanted)?;
    let report = parity::compare_keys(left_keys, right_keys);
    print_report(left, right, &wanted, &report);
    if report.matched() {
        Ok(())
    } else {
        anyhow::bail!(
            "parity mismatch: {} row(s) only in A, {} only in B",
            report.only_a_total,
            report.only_b_total
        )
    }
}
