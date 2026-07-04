// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Deep comparison of UFFS reference-output vs Rust outputs using Polars.
//!
//! This is a development/debugging tool for comparing the reference output and
//! Rust UFFS outputs. It identifies structural differences, missing records,
//! and attribute mismatches.
//!
//! # Usage
//!
//! ```bash
//! uffs-analyze-diff <baseline.txt> <rust.txt>
//! ```
//!
//! # Output
//!
//! The tool prints analysis results to stdout, including:
//! - Column comparison between the reference output and Rust output
//! - Path matching statistics
//! - Missing path analysis by drive and parent directory
//! - Pattern analysis for system files and unknown paths

#![expect(
    unused_crate_dependencies,
    reason = "standalone binary doesn't use all crate dependencies"
)]
#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::use_debug,
    reason = "diagnostic tool — stdout/stderr/debug output is intentional"
)]
#![expect(
    clippy::float_arithmetic,
    clippy::default_numeric_fallback,
    reason = "percentage calculations and statistics use floating-point"
)]
#![expect(
    clippy::too_many_lines,
    reason = "sequential analysis script — splitting main would reduce clarity"
)]
#![expect(
    clippy::shadow_reuse,
    reason = "idiomatic DataFrame transformation pipeline"
)]
#![expect(
    clippy::string_slice,
    clippy::indexing_slicing,
    reason = "slicing on normalized ASCII paths is safe and bounds-checked"
)]
#![expect(
    clippy::min_ident_chars,
    reason = "short names are conventional in data analysis code"
)]
#![expect(
    clippy::single_call_fn,
    reason = "functions factored for readability in this analysis tool"
)]

use core::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::env;
use std::path::Path;

use anyhow::{Context as _, Result};
use uffs_polars::{
    Column, CsvReadOptions, DataFrame, IntoSeries as _, SerReader as _, StringChunked,
};

/// Loads a CSV file into a Polars `DataFrame`.
///
/// # Arguments
///
/// * `path` - Path to the CSV file
/// * `name` - Display name for logging (e.g., "reference" or "Rust")
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
fn load_csv(path: &Path, name: &str) -> Result<DataFrame> {
    println!("Loading {name}: {}", path.display());
    let df = CsvReadOptions::default()
        .with_has_header(true)
        .with_infer_schema_length(Some(10000))
        .with_ignore_errors(true) // Skip malformed rows
        .map_parse_options(|opts| opts.with_truncate_ragged_lines(true))
        .try_into_reader_with_file_path(Some(path.into()))?
        .finish()
        .with_context(|| format!("Failed to read CSV: {}", path.display()))?;
    println!("  Loaded {} rows, {} columns", df.height(), df.width());
    println!("  Columns: {:?}", df.get_column_names());
    Ok(df)
}

/// Normalizes paths in a `DataFrame` by converting to lowercase and replacing
/// backslashes.
///
/// Adds a new column `path_norm` with the normalized paths.
///
/// # Errors
///
/// Returns an error if the "Path" column doesn't exist or isn't a string type.
fn normalize_paths(input_df: &DataFrame) -> Result<DataFrame> {
    let path_col = input_df.column("Path")?.str()?;
    let normalized: StringChunked = path_col
        .iter()
        .map(|opt: Option<&str>| opt.map(|val| val.to_lowercase().replace('\\', "/")))
        .collect();

    let mut result_df = input_df.clone();
    let col = Column::new("path_norm".into(), normalized.into_series());
    result_df.with_column(col)?;
    Ok(result_df)
}

/// Extracts the parent directory from a normalized path.
///
/// Returns the path up to and including the last `/`.
fn extract_parent(path: &str) -> Option<&str> {
    path.rfind('/').map(|idx| &path[..=idx])
}

/// Extracts the drive letter from a normalized path.
///
/// Returns the first character if it's an ASCII alphabetic character.
fn extract_drive(path: &str) -> Option<char> {
    path.chars().next().filter(char::is_ascii_alphabetic)
}

/// Checks if a path is an Alternate Data Stream (ADS).
///
/// ADS paths contain a `:` after the drive letter, e.g.:
/// `f:/path/file.txt:Zone.Identifier`
fn is_ads_path(path: &str) -> bool {
    // Skip the drive letter portion (e.g., "f:/")
    // ADS has a colon AFTER the drive letter colon
    if path.len() > 2 {
        // Find colon after "X:/" prefix
        path[2..].contains(':')
    } else {
        false
    }
}

/// Extracts the ADS stream name from a path.
///
/// Returns the stream name portion after the last `:` (excluding drive letter).
fn extract_ads_name(path: &str) -> Option<&str> {
    if path.len() > 2 {
        path[2..].rfind(':').map(|idx| &path[2 + idx + 1..])
    } else {
        None
    }
}

/// Entry point for the UFFS diff analysis tool.
///
/// Compares the reference output and Rust output to identify differences in:
/// - Column schemas
/// - Path matching
/// - Missing files by drive and parent directory
/// - System file patterns
///
/// # Errors
///
/// Returns an error if input files cannot be read or parsed.
fn main() -> Result<()> {
    uffs_version::handle_version!("uffs-analyze-diff");
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: uffs-analyze-diff <reference.txt> <rust.txt>");
        std::process::exit(1);
    }

    let reference_path = Path::new(&args[1]);
    let rust_path = Path::new(&args[2]);

    println!("{}", "=".repeat(70));
    println!("UFFS Deep Comparison Analysis (Rust)");
    println!("{}", "=".repeat(70));

    // Load data
    let reference = load_csv(reference_path, "reference")?;
    let rust = load_csv(rust_path, "Rust")?;

    println!("\n{}", "=".repeat(70));
    println!("STEP 1: Column Comparison");
    println!("{}", "=".repeat(70));

    let reference_cols: HashSet<_> = reference.get_column_names().into_iter().collect();
    let rust_cols: HashSet<_> = rust.get_column_names().into_iter().collect();

    let only_reference: Vec<_> = reference_cols.difference(&rust_cols).collect();
    let only_rust: Vec<_> = rust_cols.difference(&reference_cols).collect();
    let common: Vec<_> = reference_cols.intersection(&rust_cols).collect();

    println!(
        "Reference columns ({}): {:?}",
        reference_cols.len(),
        reference.get_column_names()
    );
    println!(
        "Rust columns ({}): {:?}",
        rust_cols.len(),
        rust.get_column_names()
    );
    println!("Only in reference: {only_reference:?}");
    println!("Only in Rust: {only_rust:?}");
    println!("Common columns ({}): {:?}", common.len(), common);

    println!("\n{}", "=".repeat(70));
    println!("STEP 2: Path Analysis");
    println!("{}", "=".repeat(70));

    // Normalize paths
    let reference = normalize_paths(&reference)?;
    let rust = normalize_paths(&rust)?;

    // Sample paths
    println!("\nSample reference paths:");
    println!("{:?}", reference.column("path_norm")?.head(Some(5)));
    println!("\nSample Rust paths:");
    println!("{:?}", rust.column("path_norm")?.head(Some(5)));

    println!("\n{}", "=".repeat(70));
    println!("STEP 3: Build Path Sets");
    println!("{}", "=".repeat(70));

    // Extract paths into sets
    let reference_paths: HashSet<String> = reference
        .column("path_norm")?
        .str()?
        .iter()
        .filter_map(|opt_str: Option<&str>| opt_str.map(String::from))
        .collect();

    let rust_paths: HashSet<String> = rust
        .column("path_norm")?
        .str()?
        .iter()
        .filter_map(|opt_str: Option<&str>| opt_str.map(String::from))
        .collect();

    println!("Reference unique paths: {:?}", reference_paths.len());
    println!("Rust unique paths: {:?}", rust_paths.len());

    let common_paths: HashSet<_> = reference_paths.intersection(&rust_paths).collect();
    let reference_only: Vec<_> = reference_paths.difference(&rust_paths).collect();
    let rust_only: Vec<_> = rust_paths.difference(&reference_paths).collect();

    println!("Exact matches: {:?}", common_paths.len());
    println!("Reference only: {:?}", reference_only.len());
    println!("Rust only: {:?}", rust_only.len());

    let match_rate = 100.0 * uffs_mft::usize_to_f64(common_paths.len())
        / uffs_mft::usize_to_f64(reference_paths.len());
    println!("Match rate: {match_rate:.2}%");

    println!("\n{}", "=".repeat(70));
    println!("STEP 4: Analyze Missing Paths");
    println!("{}", "=".repeat(70));

    // Sample missing paths
    println!("\nSample paths in the reference output but NOT in Rust (first 20):");
    for (idx, path) in reference_only.iter().take(20).enumerate() {
        println!("  {}: {path}", idx + 1);
    }

    if !rust_only.is_empty() {
        println!("\nSample paths in Rust but NOT in the reference output (first 20):");
        for (idx, path) in rust_only.iter().take(20).enumerate() {
            println!("  {}: {path}", idx + 1);
        }
    }

    // Analyze by drive
    println!("\nMissing paths by drive:");
    let mut drive_counts: HashMap<char, usize> = HashMap::new();
    for path in &reference_only {
        if let Some(drive) = extract_drive(path) {
            *drive_counts.entry(drive).or_insert(0) += 1;
        }
    }
    let mut drives: Vec<_> = drive_counts.iter().collect();
    drives.sort_by_key(|(_, cnt)| Reverse(*cnt));
    for (drive, count) in drives {
        println!("  {drive}: {count}");
    }

    println!("\n{}", "=".repeat(70));
    println!("STEP 5: Parent Directory Analysis");
    println!("{}", "=".repeat(70));

    // Check which parent directories are missing
    let reference_parents: HashSet<String> = reference_paths
        .iter()
        .filter_map(|path| extract_parent(path).map(String::from))
        .collect();
    let rust_parents: HashSet<String> = rust_paths
        .iter()
        .filter_map(|path| extract_parent(path).map(String::from))
        .collect();

    let missing_parents: Vec<_> = reference_parents.difference(&rust_parents).collect();
    println!(
        "Parent dirs in reference output but not Rust: {:?}",
        missing_parents.len()
    );

    // Top missing parent directories by frequency
    let mut parent_freq: HashMap<&str, usize> = HashMap::new();
    for path in &reference_only {
        if let Some(parent) = extract_parent(path) {
            *parent_freq.entry(parent).or_insert(0) += 1;
        }
    }
    let mut parents: Vec<_> = parent_freq.iter().collect();
    parents.sort_by_key(|(_, cnt)| Reverse(*cnt));

    println!("\nTop 20 parent directories with most missing files:");
    for (parent, count) in parents.iter().take(20) {
        println!("  {count:>6} files missing in: {parent}");
    }

    println!("\n{}", "=".repeat(70));
    println!("STEP 6: Pattern Analysis in Missing Paths");
    println!("{}", "=".repeat(70));

    // Check for $-prefixed (system) files
    let system_files_count = reference_only
        .iter()
        .filter(|path| {
            path.split('/')
                .next_back()
                .is_some_and(|name| name.starts_with('$'))
        })
        .count();
    println!("Missing $-prefixed (system) files: {system_files_count}");

    // Check for <unknown> in Rust paths
    let unknown_paths: Vec<_> = rust_paths
        .iter()
        .filter(|path| path.contains("<unknown>"))
        .collect();
    println!("Rust paths with '<unknown>': {}", unknown_paths.len());
    if !unknown_paths.is_empty() {
        println!("  Sample:");
        for path in unknown_paths.iter().take(10) {
            println!("    {path}");
        }
    }

    // Check for very short paths (root-level issues)
    let reference_short_count = reference_paths
        .iter()
        .filter(|path| path.len() < 10)
        .count();
    let rust_short_count = rust_paths.iter().filter(|path| path.len() < 10).count();
    println!("\nReference paths < 10 chars: {reference_short_count}");
    println!("Rust paths < 10 chars: {rust_short_count}");

    // Check for paths with "." as filename (directory entries)
    let reference_dot_count = reference_paths
        .iter()
        .filter(|path| path.ends_with("/."))
        .count();
    let rust_dot_count = rust_paths
        .iter()
        .filter(|path| path.ends_with("/."))
        .count();
    println!("\nReference paths ending with '/.' (dir entries): {reference_dot_count}");
    println!("Rust paths ending with '/.' (dir entries): {rust_dot_count}");

    println!("\n{}", "=".repeat(70));
    println!("STEP 7: Alternate Data Streams (ADS) Analysis");
    println!("{}", "=".repeat(70));

    // Count ADS entries in each set
    let reference_ads_count = reference_paths.iter().filter(|p| is_ads_path(p)).count();
    let rust_ads_count = rust_paths.iter().filter(|p| is_ads_path(p)).count();
    let reference_only_ads_count = reference_only.iter().filter(|p| is_ads_path(p)).count();
    let rust_only_ads_count = rust_only.iter().filter(|p| is_ads_path(p)).count();

    println!("ADS entries in reference output: {reference_ads_count}");
    println!("ADS entries in Rust: {rust_ads_count}");
    println!("ADS entries only in reference output: {reference_only_ads_count}");
    println!("ADS entries in Rust only (extra): {rust_only_ads_count}");

    // Sample ADS entries
    if reference_ads_count > 0 {
        println!("\nSample ADS entries from the reference output (first 10):");
        for (idx, path) in reference_paths
            .iter()
            .filter(|p| is_ads_path(p))
            .take(10)
            .enumerate()
        {
            println!("  {}: {path}", idx + 1);
        }
    }

    // Analyze ADS stream names
    let mut ads_name_freq: HashMap<&str, usize> = HashMap::new();
    for path in reference_paths.iter().filter(|p| is_ads_path(p)) {
        if let Some(name) = extract_ads_name(path) {
            *ads_name_freq.entry(name).or_insert(0) += 1;
        }
    }
    if !ads_name_freq.is_empty() {
        let mut ads_names: Vec<_> = ads_name_freq.iter().collect();
        ads_names.sort_by_key(|(_, cnt)| Reverse(*cnt));
        println!("\nTop 10 ADS stream names in the reference output:");
        for (name, count) in ads_names.iter().take(10) {
            println!("  {count:>8}: {name}");
        }
    }

    println!("\n{}", "=".repeat(70));
    println!("STEP 8: Comparison EXCLUDING ADS");
    println!("{}", "=".repeat(70));

    // Filter out ADS entries for a "base files only" comparison
    let reference_no_ads: HashSet<_> = reference_paths.iter().filter(|p| !is_ads_path(p)).collect();
    let rust_no_ads: HashSet<_> = rust_paths.iter().filter(|p| !is_ads_path(p)).collect();

    let common_no_ads: HashSet<_> = reference_no_ads.intersection(&rust_no_ads).collect();
    let reference_only_no_ads: Vec<_> = reference_no_ads.difference(&rust_no_ads).collect();
    let rust_only_no_ads: Vec<_> = rust_no_ads.difference(&reference_no_ads).collect();

    let match_rate_no_ads = if reference_no_ads.is_empty() {
        0.0
    } else {
        100.0 * uffs_mft::usize_to_f64(common_no_ads.len())
            / uffs_mft::usize_to_f64(reference_no_ads.len())
    };

    println!("\nExcluding ADS entries:");
    println!("  Reference base files: {}", reference_no_ads.len());
    println!("  Rust base files: {}", rust_no_ads.len());
    println!("  Exact matches: {}", common_no_ads.len());
    println!(
        "  Reference only (missing from Rust): {}",
        reference_only_no_ads.len()
    );
    println!("  Rust only (extra): {}", rust_only_no_ads.len());
    println!("  Match rate (no ADS): {match_rate_no_ads:.2}%");

    if !reference_only_no_ads.is_empty() {
        println!("\nSample base files in the reference output but NOT in Rust (first 20):");
        for (idx, path) in reference_only_no_ads.iter().take(20).enumerate() {
            println!("  {}: {path}", idx + 1);
        }
    }

    if !rust_only_no_ads.is_empty() {
        println!("\nSample base files in Rust but NOT in the reference output (first 20):");
        for (idx, path) in rust_only_no_ads.iter().take(20).enumerate() {
            println!("  {}: {path}", idx + 1);
        }
    }

    println!("\n{}", "=".repeat(70));
    println!("SUMMARY & ROOT CAUSE HYPOTHESIS");
    println!("{}", "=".repeat(70));

    let missing_pct = 100.0 * uffs_mft::usize_to_f64(reference_only.len())
        / uffs_mft::usize_to_f64(reference_paths.len());
    let missing_no_ads_pct = if reference_no_ads.is_empty() {
        0.0
    } else {
        100.0 * uffs_mft::usize_to_f64(reference_only_no_ads.len())
            / uffs_mft::usize_to_f64(reference_no_ads.len())
    };

    println!("\nAnalysis Complete (ALL paths):");
    println!(
        "  - Reference output found {} unique paths",
        reference_paths.len()
    );
    println!("  - Rust found {} unique paths", rust_paths.len());
    println!(
        "  - Missing from Rust: {} ({missing_pct:.1}%)",
        reference_only.len(),
    );
    println!("  - Extra in Rust: {}", rust_only.len());
    println!("  - Match rate: {match_rate:.2}%");

    println!("\nAnalysis Complete (EXCLUDING ADS):");
    println!("  - Reference base files: {}", reference_no_ads.len());
    println!("  - Rust base files: {}", rust_no_ads.len());
    println!(
        "  - Missing from Rust: {} ({missing_no_ads_pct:.1}%)",
        reference_only_no_ads.len(),
    );
    println!("  - Extra in Rust: {}", rust_only_no_ads.len());
    println!("  - Match rate (no ADS): {match_rate_no_ads:.2}%");

    println!("\nLikely Issues:");
    // ADS counts are small enough that `i64::try_from` is infallible in
    // practice; the saturating fallback is unreachable.
    let ref_i64 = i64::try_from(reference_ads_count).unwrap_or(i64::MAX);
    let rust_i64 = i64::try_from(rust_ads_count).unwrap_or(i64::MAX);
    let ads_diff = ref_i64 - rust_i64;
    println!(
        "  1. ADS entries: {reference_ads_count} in reference output, {rust_ads_count} in Rust (diff: {ads_diff})"
    );
    println!(
        "  2. <unknown> paths: {} paths have unresolved parents",
        unknown_paths.len()
    );
    println!(
        "  3. Missing parent dirs: {} parent directories not in Rust",
        missing_parents.len()
    );
    println!("  4. System files ($): {system_files_count} $-prefixed files missing");
    println!(
        "  5. Directory entries (.): reference output has {reference_dot_count}, Rust has {rust_dot_count}"
    );

    Ok(())
}
