// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Analyze parent/child coverage in an MFT Parquet file.
//!
//! This is an offline analysis tool that operates purely on a Parquet export
//! (e.g. `f_mft.parquet`). It is cross-platform and does **not** require
//! direct NTFS access.
//!
//! It focuses on one key question:
//!   *Which `parent_frs` values referenced by children do **not** have a
//!   corresponding directory row in the dataset?*
//!
//! This helps explain why the path resolver later needs to inject
//! `<dir:XXXXXX>` placeholders.
//!
//! # Usage
//!
//! ```bash
//! uffs-analyze-mft-parents docs/trial_runs/f_mft.parquet
//! ```

#![expect(
    unused_crate_dependencies,
    reason = "shared Cargo.toml dependencies not used by all binaries"
)]
#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "diagnostic tool — stdout/stderr output is intentional"
)]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Reverse;
use std::collections::HashSet;
use std::env;
use std::path::Path;

use anyhow::{Context as _, Result};
use uffs_polars::{BooleanChunked, DataFrame, SerReader as _, UInt64Chunked};

fn main() -> Result<()> {
    uffs_version::handle_version!("uffs-analyze-mft-parents");
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: uffs-analyze-mft-parents <mft.parquet>");
        std::process::exit(1);
    }

    let parquet_path = args.get(1).map(String::as_str).ok_or_else(|| {
        anyhow::anyhow!("Expected <mft.parquet> path argument to be present after length check")
    })?;
    let path = Path::new(parquet_path);

    println!("{}", "=".repeat(70));
    println!("MFT Parent Coverage Analysis");
    println!("{}", "=".repeat(70));
    println!("Input Parquet: {}", path.display());

    let df = load_parquet(path)?;

    println!("\nRows: {}", df.height());
    println!("Cols: {}", df.width());

    let column_names: Vec<String> = df
        .get_column_names()
        .into_iter()
        .map(uffs_polars::PlSmallStr::to_string)
        .collect();
    println!("Columns: {}", column_names.join(", "));

    analyze_parents(&df)?;

    Ok(())
}

/// Load an MFT Parquet file into a [`DataFrame`].
#[expect(
    clippy::single_call_fn,
    reason = "intentionally separate for clarity and focused error context"
)]
fn load_parquet(path: &Path) -> Result<DataFrame> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open Parquet file: {}", path.display()))?;

    uffs_polars::ParquetReader::new(file)
        .finish()
        .with_context(|| format!("Failed to read Parquet data from {}", path.display()))
}

/// Analyze parent/child coverage and print summary statistics.
#[expect(
    clippy::single_call_fn,
    reason = "encapsulates analysis pipeline for readability"
)]
fn analyze_parents(df: &DataFrame) -> Result<()> {
    // Basic schema validation
    for required_column in &["frs", "parent_frs"] {
        if !df
            .get_column_names()
            .iter()
            .any(|name| name == required_column)
        {
            anyhow::bail!("Required column '{required_column}' missing from DataFrame");
        }
    }

    let frs_col: &UInt64Chunked = df
        .column("frs")?
        .u64()
        .context("Column 'frs' is not UInt64")?;

    let parent_col: &UInt64Chunked = df
        .column("parent_frs")?
        .u64()
        .context("Column 'parent_frs' is not UInt64")?;

    let is_dir_col: Option<&BooleanChunked> = df
        .column("is_directory")
        .ok()
        .and_then(|directory_column| directory_column.bool().ok());

    println!("\nDistinct FRS / parent_frs / dirs:");

    let mut frs_set = HashSet::with_capacity(frs_col.len());
    for frs_value in frs_col.iter().flatten() {
        frs_set.insert(frs_value);
    }

    let mut parent_set = BTreeSet::new();
    for parent_value in parent_col.iter().flatten() {
        // Skip root/sentinel parents (0) if present
        if parent_value != 0 {
            parent_set.insert(parent_value);
        }
    }

    let mut dir_set = HashSet::new();
    if let Some(is_directory_series) = is_dir_col {
        for (idx, is_directory_opt) in is_directory_series.iter().enumerate() {
            if is_directory_opt == Some(true)
                && let Some(frs) = frs_col.get(idx)
            {
                dir_set.insert(frs);
            }
        }
    } else {
        // Fallback: treat all FRS as potential directory candidates
        dir_set.extend(frs_set.iter().copied());
    }

    println!("  Distinct FRS count: {}", frs_set.len());
    println!(
        "  Distinct parent_frs count (non-zero): {}",
        parent_set.len()
    );
    println!("  Distinct directory FRS count: {}", dir_set.len());

    // Parents that are referenced but do not have a directory row
    let mut missing_parents = BTreeSet::new();
    for parent_value in &parent_set {
        if !dir_set.contains(parent_value) {
            missing_parents.insert(*parent_value);
        }
    }

    println!(
        "\nMissing parent FRS count (referenced, but no directory row): {}",
        missing_parents.len()
    );

    // Further classify missing parents: do they exist as any row at all?
    let mut missing_but_present_as_frs: u64 = 0;
    let mut missing_and_absent_completely: u64 = 0;
    for parent_value in &missing_parents {
        if frs_set.contains(parent_value) {
            missing_but_present_as_frs += 1;
        } else {
            missing_and_absent_completely += 1;
        }
    }

    println!(
        "  Of these, parents that DO have at least one row (non-directory row): {missing_but_present_as_frs}"
    );
    println!("  Parents that have NO row at all in the DataFrame: {missing_and_absent_completely}");

    // Convert back to a sorted Vec<u64> for downstream analysis/printing.
    let missing_parents_vec: Vec<u64> = missing_parents.into_iter().collect();
    print_missing_parent_details(&missing_parents_vec, parent_col);

    Ok(())
}

/// Print detailed statistics about missing parents, including bucketed counts
/// and the most-referenced missing parents.
#[expect(
    clippy::single_call_fn,
    reason = "factored out of analyze_parents for readability"
)]
fn print_missing_parent_details(missing_parents: &[u64], parent_col: &UInt64Chunked) {
    if missing_parents.is_empty() {
        println!("No missing parents detected.\n");
        return;
    }

    let min_frs = missing_parents.first().copied().unwrap_or(0);
    let max_frs = missing_parents.last().copied().unwrap_or(0);
    println!("Missing parents FRS range: {min_frs} .. {max_frs}");

    // Compute child counts for missing parents
    let missing_set: HashSet<u64> = missing_parents.iter().copied().collect();
    let mut child_counts: BTreeMap<u64, u64> = BTreeMap::new();

    for parent_value in parent_col.iter().flatten() {
        if missing_set.contains(&parent_value) {
            *child_counts.entry(parent_value).or_insert(0) += 1;
        }
    }

    let mut child_vec: Vec<(u64, u64)> = child_counts.into_iter().collect();
    child_vec.sort_by_key(|&(_parent_frs, count)| Reverse(count));

    println!("\nTop 20 missing parents by child_count:");
    for (idx, (parent_frs, count)) in child_vec.iter().take(20).enumerate() {
        println!(
            "  {index:2}. parent_frs={parent_frs}  children={children}",
            index = idx + 1,
            parent_frs = parent_frs,
            children = count,
        );
    }

    // Coarse bucketing by FRS range to see clustering.
    let bucket_size: u64 = 100_000;
    let mut buckets: BTreeMap<u64, u64> = BTreeMap::new();
    for &parent_frs in missing_parents {
        let bucket = parent_frs / bucket_size;
        *buckets.entry(bucket).or_insert(0) += 1;
    }

    println!("\nMissing parents by FRS bucket (bucket_size={bucket_size}):");
    for (bucket, count) in buckets.iter().take(20) {
        println!(
            "  bucket {bucket:>6} (FRS {start_frs:>10} .. {end_frs:>10}): {parent_count:>6} parents",
            bucket = bucket,
            start_frs = bucket * bucket_size,
            end_frs = (bucket + 1) * bucket_size - 1,
            parent_count = count,
        );
    }
}
