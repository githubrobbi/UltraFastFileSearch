#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! serde_json = "1.0"
//! rand = "0.8"
//! ```
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Checks whether ascending NTFS file-reference (FRS) order correlates
//! with ascending on-disk physical location, for a sample of files --
//! and how much read-order headroom is actually on the table.
//!
//! Step 1 of the "does reading candidates in ascending FRS order actually
//! give us near-sequential physical disk access" investigation. Rust
//! replacement for the original `check_frs_vs_lcn.ps1` (same logic, plus
//! the natural-vs-FRS-vs-oracle seek-distance comparison below).
//!
//! Reads `uffs --format json` output (path + file_reference per line),
//! samples a subset, and runs `fsutil file queryextents` on each sampled
//! file to find its first extent's starting LCN (logical cluster number
//! -- i.e. where it actually sits on the volume). Reports two things:
//!
//! 1. The Spearman rank correlation between FRS order and LCN order: a strong
//!    positive correlation means ascending-FRS read order is a good proxy for
//!    physical order; weak/no correlation means it won't help -- the files are
//!    physically scattered independent of allocation order.
//! 2. The total seek distance (sum of `|Δ LCN|` between consecutive reads)
//!    under three orderings of the same sample: the order the search response
//!    actually returned them in ("natural" -- what the read pipeline processes
//!    today), ascending-FRS order, and the oracle (true ascending-LCN order --
//!    the unbeatable lower bound). This turns "FRS correlates weakly/moderately
//!    with LCN" into a concrete number: how much of the *achievable* seek
//!    reduction does cheap FRS-sorting actually capture, versus what only a
//!    real LCN-resolution pass (querying physical location up front) could get.
//!
//! Two sampling modes are supported (3rd arg):
//! - `random` (default): a true uniform random draw across every row in the
//!   file -- answers "does global FRS order track global LCN order."
//! - `block`: `sample_size` *consecutive* rows (in search-response order)
//!   starting at a given or random offset -- answers a different question: are
//!   candidates *as the pipeline's bounded sliding window would actually
//!   encounter them together* physically clustered. This is the more
//!   operationally relevant test, since the read pipeline only ever has a
//!   handful of candidates in flight at once, not the freedom to globally
//!   reorder the whole run.
//!
//! # Usage
//! ```text
//! uffs.exe "*.txt" --drive D --format json > d_files.jsonl
//! rust-script scripts/windows/check_frs_vs_lcn.rs d_files.jsonl [sample_size] [random|block] [offset]
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::{env, fs};

use rand::Rng;
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
    /// Position in `rows` -- i.e. the order the search response actually
    /// returned this file in, which is what the read pipeline processes
    /// today (see `candidate_source.rs`: candidates keep the search
    /// response's row order).
    natural_index: usize,
    frs: u64,
    lcn: u64,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let Some(json_path) = args.get(1) else {
        eprintln!(
            "usage: check_frs_vs_lcn.rs <json_path> [sample_size=500] [random|block] [offset]\n\
             \n\
             json_path must be `uffs --format json` output (one JSON object per line, \
             with a `path` and nonzero `file_reference` field)."
        );
        std::process::exit(2);
    };
    let sample_size: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
    let mode = args.get(3).map(String::as_str).unwrap_or("random");
    let fixed_offset: Option<usize> = args.get(4).and_then(|s| s.parse().ok());

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
    let indices: Vec<usize> = match mode {
        "block" => {
            let max_start = rows.len().saturating_sub(take);
            let start = fixed_offset
                .unwrap_or_else(|| rng.gen_range(0..=max_start))
                .min(max_start);
            let total = rows.len();
            println!(
                "Block-sampling {take} consecutive rows starting at natural index {start} \
                 (of {total} total)."
            );
            (start..start + take).collect()
        }
        _ => {
            let mut shuffled: Vec<usize> = (0..rows.len()).collect();
            shuffled.shuffle(&mut rng);
            shuffled.truncate(take);
            shuffled
        }
    };

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
                natural_index: idx,
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

    print_seek_distance_comparison(&resolved);

    let out_csv = default_output_csv(json_path);
    write_csv(&out_csv, &resolved);
    println!();
    println!(
        "Full sample written to {} for inspection/plotting.",
        out_csv.display()
    );
}

/// Sum of `|Δ LCN|` between consecutive entries of `ordered` -- a proxy
/// for total head movement (in clusters) touring this sample once in
/// the given order.
fn total_seek_distance(ordered: &[&Resolved]) -> u64 {
    ordered
        .windows(2)
        .map(|pair| pair[0].lcn.abs_diff(pair[1].lcn))
        .sum()
}

/// Prints the natural-vs-FRS-vs-oracle seek-distance comparison: how
/// much of the seek reduction that's actually achievable (natural ->
/// oracle) does cheap ascending-FRS sorting capture on its own.
fn print_seek_distance_comparison(resolved: &[Resolved]) {
    let mut by_natural: Vec<&Resolved> = resolved.iter().collect();
    by_natural.sort_by_key(|r| r.natural_index);

    let mut by_frs: Vec<&Resolved> = resolved.iter().collect();
    by_frs.sort_by_key(|r| r.frs);

    // The oracle: true ascending-LCN order. For a strictly ascending
    // sequence, sum of |Δ| collapses to (max - min) -- the unbeatable
    // lower bound for touring every point once.
    let mut by_lcn: Vec<&Resolved> = resolved.iter().collect();
    by_lcn.sort_by_key(|r| r.lcn);

    let natural_total = total_seek_distance(&by_natural);
    let frs_total = total_seek_distance(&by_frs);
    let oracle_total = total_seek_distance(&by_lcn);

    let bytes_per_cluster = resolved
        .first()
        .and_then(|r| drive_root(&r.path))
        .and_then(|root| query_bytes_per_cluster(&root));

    println!();
    println!(
        "=== Total seek distance (sum of |Δ LCN| touring the sample once; lower is better) ==="
    );
    print_distance_line(
        "Natural (search-response) order",
        natural_total,
        bytes_per_cluster,
    );
    print_distance_line("Ascending-FRS order", frs_total, bytes_per_cluster);
    print_distance_line(
        "Oracle: true ascending-LCN order",
        oracle_total,
        bytes_per_cluster,
    );
    println!();

    let achievable = natural_total.saturating_sub(oracle_total);
    if achievable == 0 {
        println!(
            "Natural order already matches the oracle on this sample -- no seek-distance headroom to capture."
        );
        return;
    }
    let frs_captured = natural_total.saturating_sub(frs_total);
    let capture_pct = 100.0 * frs_captured as f64 / achievable as f64;
    println!(
        "Ascending-FRS order captures {capture_pct:.1}% of the max possible seek-distance \
         reduction (natural -> oracle) on this sample. The remaining {:.1}% is only reachable \
         by actually resolving true LCN per candidate before ordering reads.",
        100.0 - capture_pct
    );
}

fn print_distance_line(label: &str, clusters: u64, bytes_per_cluster: Option<u64>) {
    match bytes_per_cluster {
        Some(bpc) => {
            let mib = (clusters as f64 * bpc as f64) / (1024.0 * 1024.0);
            println!("{label}: {clusters} clusters (~{mib:.1} MiB of head travel)");
        }
        None => println!(
            "{label}: {clusters} clusters (bytes/cluster unknown -- couldn't convert to MiB)"
        ),
    }
}

/// Extracts `"D:"` from a path like `"D:\Dropbox\..."`, for the
/// `fsutil fsinfo ntfsinfo` call below. `None` for anything that doesn't
/// look like a drive-letter-rooted Windows path.
fn drive_root(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        Some(format!("{}:", &path[0..1]))
    } else {
        None
    }
}

/// Runs `fsutil fsinfo ntfsinfo <drive_root>` and pulls out "Bytes Per
/// Cluster" so seek-distance numbers can be shown in MiB, not just raw
/// cluster counts. Best-effort: `None` if the command or parse fails,
/// callers fall back to reporting clusters only.
fn query_bytes_per_cluster(drive_root: &str) -> Option<u64> {
    let output = Command::new("fsutil")
        .args(["fsinfo", "ntfsinfo", drive_root])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if !line.to_ascii_lowercase().contains("bytes per cluster") {
            continue;
        }
        // Only look at what follows the last ':' on this line -- the
        // label itself never contains digits, but scoping to the value
        // side avoids picking up stray digits from anywhere else on the
        // line if the format has more on it than expected.
        let Some(colon) = line.rfind(':') else {
            continue;
        };
        let after = line[colon + 1..].trim();
        let parsed = if let Some(hex) = after
            .strip_prefix("0x")
            .or_else(|| after.strip_prefix("0X"))
        {
            u64::from_str_radix(hex.trim(), 16).ok()
        } else {
            after
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .ok()
        };
        // NTFS cluster sizes are always a power of two in [512 B, 2 MiB].
        // Reject anything else as a parse failure rather than silently
        // reporting a nonsense MiB conversion downstream.
        if let Some(value) = parsed {
            if (512..=2 * 1024 * 1024).contains(&value) && value.is_power_of_two() {
                return Some(value);
            }
        }
    }
    None
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
    let mut out = String::from("Path,NaturalIndex,Frs,Lcn\n");
    for row in resolved {
        // Paths can contain commas/quotes -- quote and escape per RFC 4180.
        let escaped_path = row.path.replace('"', "\"\"");
        out.push_str(&format!(
            "\"{escaped_path}\",{},{},{}\n",
            row.natural_index, row.frs, row.lcn
        ));
    }
    if let Err(err) = fs::write(path, out) {
        eprintln!("failed to write {}: {err}", path.display());
    }
}
