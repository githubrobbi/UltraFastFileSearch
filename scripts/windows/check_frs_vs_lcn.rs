#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! serde_json = "1.0"
//! rand = "0.8"
//! ```
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Checks whether ascending NTFS file-reference (FRS) order correlates
//! with ascending on-disk physical location, for a sample of files.
//!
//! Step 1 of the "does reading candidates in ascending FRS order actually
//! give us near-sequential physical disk access" investigation. Rust
//! replacement for the original `check_frs_vs_lcn.ps1` (same logic).
//!
//! Reads `uffs --format json` output (path + file_reference per line),
//! samples a subset, and runs `fsutil file queryextents` on each sampled
//! file to find its first extent's starting LCN (logical cluster number
//! -- i.e. where it actually sits on the volume). Reports the Spearman
//! rank correlation between FRS order and LCN order: a strong positive
//! correlation means ascending-FRS read order is a good proxy for
//! physical order (sorting reads by FRS should meaningfully cut seeks);
//! a weak/no correlation means it won't help -- the files are physically
//! scattered independent of allocation order.
//!
//! # Usage
//! ```text
//! uffs.exe "*.txt" --drive D --format json > d_files.jsonl
//! rust-script scripts/windows/check_frs_vs_lcn.rs d_files.jsonl [sample_size]
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::{env, fs};

use rand::seq::SliceRandom;

/// Low 48 bits are the FRS (MFT record number); high 16 bits are the
/// sequence number (slot-reuse generation) -- mirrors
/// `CompactRecord::pack_file_reference` in `uffs-core`.
const FRS_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

struct Sample {
    path: String,
    frs: u64,
}

struct Resolved {
    path: String,
    frs: u64,
    lcn: u64,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let Some(json_path) = args.get(1) else {
        eprintln!(
            "usage: check_frs_vs_lcn.rs <json_path> [sample_size=500]\n\
             \n\
             json_path must be `uffs --format json` output (one JSON object per line, \
             with a `path` and nonzero `file_reference` field)."
        );
        std::process::exit(2);
    };
    let sample_size: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);

    println!("Reading {json_path} ...");
    let content = fs::read_to_string(json_path).unwrap_or_else(|err| {
        eprintln!("failed to read {json_path}: {err}");
        std::process::exit(1);
    });

    let rows: Vec<Sample> = content
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|value| {
            let path = value.get("path")?.as_str()?.to_owned();
            let file_reference = value.get("file_reference")?.as_u64()?;
            if file_reference == 0 {
                return None;
            }
            Some(Sample {
                path,
                frs: file_reference & FRS_MASK,
            })
        })
        .collect();

    println!("Loaded {} rows with a nonzero file_reference.", rows.len());
    if rows.is_empty() {
        eprintln!(
            "No usable rows -- check that json_path came from 'uffs ... --format json' \
             (needs the file_reference field)."
        );
        std::process::exit(1);
    }

    let mut rng = rand::thread_rng();
    let take = sample_size.min(rows.len());
    let mut indices: Vec<usize> = (0..rows.len()).collect();
    indices.shuffle(&mut rng);
    indices.truncate(take);

    println!("Sampling {take} files; querying extents (this hits the filesystem once per file)...");

    let mut resolved = Vec::with_capacity(take);
    let mut unresolved = 0_usize;
    for (i, &idx) in indices.iter().enumerate() {
        if (i + 1) % 50 == 0 {
            println!("  ... {} / {take}", i + 1);
        }
        let row = &rows[idx];
        match query_first_lcn(&row.path) {
            Some(lcn) => resolved.push(Resolved {
                path: row.path.clone(),
                frs: row.frs,
                lcn,
            }),
            None => unresolved += 1,
        }
    }

    println!();
    println!(
        "Got extents for {} / {take} sampled files ({unresolved} unresolved -- deleted/locked/\
         resident-no-extent files are skipped).",
        resolved.len()
    );

    if resolved.len() < 10 {
        eprintln!("Too few resolvable extents to compute a meaningful correlation.");
        std::process::exit(1);
    }

    let spearman = spearman_correlation(&resolved);

    println!();
    println!("=== Result ===");
    println!("Sampled files with resolvable extents: {}", resolved.len());
    println!("Spearman correlation (FRS order vs. physical LCN order): {spearman:.3}");
    println!();
    if spearman > 0.7 {
        println!(
            "Strong positive correlation -- ascending FRS order is a good proxy for physical \
             order on this volume. Sorting reads by FRS should meaningfully reduce seeks."
        );
    } else if spearman > 0.3 {
        println!(
            "Weak-to-moderate correlation -- FRS-sorted reads might help somewhat but won't \
             eliminate seeking; this volume has likely been reorganized/fragmented since these \
             files were created."
        );
    } else {
        println!(
            "Little to no correlation -- FRS order will NOT meaningfully help; the files are \
             physically scattered independent of allocation order (heavy fragmentation, moves, \
             or FRS-slot reuse)."
        );
    }

    let out_csv = default_output_csv(json_path);
    write_csv(&out_csv, &resolved);
    println!();
    println!(
        "Full sample written to {} for inspection/plotting.",
        out_csv.display()
    );
}

/// Run `fsutil file queryextents` and pull out the first `Lcn` value it
/// prints -- tolerant of hex (`0x...`) or decimal, and of the label's
/// exact wording/case, since this has drifted across Windows versions.
fn query_first_lcn(path: &str) -> Option<u64> {
    let output = Command::new("fsutil")
        .args(["file", "queryextents", path])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(idx) = lower.find("lcn") {
            let after = line.get(idx + 3..)?;
            let after = after.trim_start_matches([':', ' ', '\t']);
            if let Some(hex) = after
                .strip_prefix("0x")
                .or_else(|| after.strip_prefix("0X"))
            {
                let digits: String = hex.chars().take_while(char::is_ascii_hexdigit).collect();
                if let Ok(value) = u64::from_str_radix(&digits, 16) {
                    return Some(value);
                }
            } else {
                let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
                if let Ok(value) = digits.parse::<u64>() {
                    return Some(value);
                }
            }
        }
    }
    None
}

/// Spearman rank correlation between FRS order and LCN order across
/// `resolved` -- ranks both columns independently, then Pearson-
/// correlates the ranks via the standard tied-rank-free shortcut
/// formula (valid when ranks are a permutation of `0..n`, i.e. no
/// duplicate FRS/LCN collisions -- close enough for this sample size).
fn spearman_correlation(resolved: &[Resolved]) -> f64 {
    let mut by_frs: Vec<usize> = (0..resolved.len()).collect();
    by_frs.sort_by_key(|&i| resolved[i].frs);
    let mut frs_rank: HashMap<usize, usize> = HashMap::new();
    for (rank, &i) in by_frs.iter().enumerate() {
        frs_rank.insert(i, rank);
    }

    let mut by_lcn: Vec<usize> = (0..resolved.len()).collect();
    by_lcn.sort_by_key(|&i| resolved[i].lcn);
    let mut lcn_rank: HashMap<usize, usize> = HashMap::new();
    for (rank, &i) in by_lcn.iter().enumerate() {
        lcn_rank.insert(i, rank);
    }

    let n = resolved.len() as f64;
    let sum_d_sq: f64 = (0..resolved.len())
        .map(|i| {
            let d = frs_rank[&i] as f64 - lcn_rank[&i] as f64;
            d * d
        })
        .sum();

    1.0 - (6.0 * sum_d_sq) / (n * (n * n - 1.0))
}

/// Default CSV output path: alongside `json_path`, falling back to the
/// current directory when `json_path` has no parent component (e.g. a
/// bare filename like `d_files.jsonl`).
fn default_output_csv(json_path: &str) -> std::path::PathBuf {
    let parent = Path::new(json_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty());
    parent
        .unwrap_or_else(|| Path::new("."))
        .join("frs_vs_lcn_sample.csv")
}

fn write_csv(path: &Path, resolved: &[Resolved]) {
    let mut out = String::from("Path,Frs,Lcn\n");
    for row in resolved {
        // Paths can contain commas/quotes -- quote and escape per RFC 4180.
        let escaped_path = row.path.replace('"', "\"\"");
        out.push_str(&format!("\"{escaped_path}\",{},{}\n", row.frs, row.lcn));
    }
    if let Err(err) = fs::write(path, out) {
        eprintln!("failed to write {}: {err}", path.display());
    }
}
