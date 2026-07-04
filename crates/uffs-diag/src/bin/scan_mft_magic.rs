// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Scan magic values across all records in a raw MFT snapshot.
//!
//! Offline, cross-platform tool operating on `uffs-mft`'s raw MFT format
//! (`*.raw` produced by `uffs-mft save`). For each record, we inspect the
//! `MultiSectorHeader.magic` and classify it as FILE/RCRD/INDX/zero/other.
//! We then aggregate counts by FRS bucket to locate where valid FILE records
//! stop and other data (e.g. RCRD/zeros) begin.

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

use alloc::collections::BTreeMap;
use std::env;
use std::path::Path;

use anyhow::{Context as _, Result};
use uffs_mft::raw::{LoadRawOptions, load_raw_mft};

/// Local copy of the NTFS multi-sector header so this tool can run on
/// non-Windows targets (the real `ntfs` module is `cfg(windows)`).
///
/// This matches the layout in `crates/uffs-mft/src/ntfs.rs` and is used only
/// for inspecting the update-sequence (USA) header at the start of each
/// record.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MultiSectorHeader {
    /// 4-byte magic value at the start of the record (e.g. `FILE`, `RCRD`).
    magic: u32,
    /// Byte offset to the update sequence array (USA) from the start
    /// of the record.
    usa_offset: u16,
    /// Number of USA entries (including the update sequence number).
    usa_count: u16,
}

/// Parses the leading multi-sector header from a raw MFT record.
#[expect(
    clippy::single_call_fn,
    reason = "magic scanning keeps the header decode in one focused helper"
)]
fn parse_multi_sector_header(data: &[u8]) -> Option<MultiSectorHeader> {
    Some(MultiSectorHeader {
        magic: u32::from_le_bytes(data.get(0..4)?.try_into().ok()?),
        usa_offset: u16::from_le_bytes(data.get(4..6)?.try_into().ok()?),
        usa_count: u16::from_le_bytes(data.get(6..8)?.try_into().ok()?),
    })
}

/// Classify the 4-byte NTFS magic as one of the known record types.
#[expect(
    clippy::single_call_fn,
    reason = "focused helper mirroring core NTFS magic classification"
)]
const fn classify_magic(magic: u32) -> &'static str {
    match magic {
        // "FILE" in little-endian (matches FILE_RECORD_MAGIC in ntfs.rs)
        0x454C_4946 => "FILE",
        0x4452_4352 => "RCRD",
        0x5844_4E49 => "INDX",
        0x0000_0000 => "ZERO",
        _ => "OTHER",
    }
}

/// Aggregate counts of record magic classifications for a single FRS bucket.
///
/// Kept at module scope to avoid Clippy's items-after-statements lint while
/// still grouping bucket-related state.
#[derive(Default, Clone, Copy)]
struct BucketCounts {
    /// Count of records whose magic classified as "FILE".
    file: u64,
    /// Count of records whose magic classified as "RCRD".
    rcrd: u64,
    /// Count of records whose magic classified as "INDX".
    indx: u64,
    /// Count of records whose magic classified as all-zero.
    zero: u64,
    /// Count of records whose magic fell into the fallback "OTHER" bucket.
    other: u64,
}

fn main() -> Result<()> {
    uffs_version::handle_version!("uffs-scan-mft-magic");
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: uffs-scan-mft-magic <mft.raw> [bucket_size]");
        std::process::exit(1);
    }

    let raw_path = args.get(1).map(String::as_str).ok_or_else(|| {
        anyhow::anyhow!("Expected <mft.raw> path argument to be present after length check")
    })?;
    let bucket_size: u64 = if args.len() >= 3 {
        args.get(2)
            .map(String::as_str)
            .unwrap_or_default()
            .parse::<u64>()
            .context("Failed to parse bucket_size as u64")?
    } else {
        100_000
    };

    let path = Path::new(raw_path);
    let raw = load_raw_mft(path, &LoadRawOptions::default())
        .with_context(|| format!("Failed to load raw MFT from {}", path.display()))?;

    println!(
        "Loaded raw MFT: {} records, record_size={} bytes",
        raw.header.record_count, raw.header.record_size
    );
    println!("Bucket size: {bucket_size} records");

    let mut buckets: BTreeMap<u64, BucketCounts> = BTreeMap::new();

    let total_records = raw.header.record_count;

    println!("Scanning records...");

    // Use a local constant rather than an inner `use` item to avoid
    // clippy::items-after-statements while keeping the code readable.
    let header_size = size_of::<MultiSectorHeader>();

    for frs in 0..total_records {
        if let Some(data) = raw.get_record(frs) {
            if data.len() < header_size {
                continue;
            }

            let Some(header) = parse_multi_sector_header(data) else {
                continue;
            };
            let magic = header.magic;
            let class = classify_magic(magic);

            let bucket = frs / bucket_size;
            let entry = buckets.entry(bucket).or_default();
            match class {
                "FILE" => entry.file += 1,
                "RCRD" => entry.rcrd += 1,
                "INDX" => entry.indx += 1,
                "ZERO" => entry.zero += 1,
                _ => entry.other += 1,
            }
        }
    }

    println!("\nMagic distribution by FRS bucket:");
    println!("bucket  FRS_start   FRS_end     FILE      RCRD      INDX      ZERO     OTHER");

    for (bucket, counts) in buckets {
        let start_frs = bucket * bucket_size;
        let end_frs = (bucket + 1).saturating_mul(bucket_size).saturating_sub(1);
        println!(
            "{bucket:6} {start_frs:10} {end_frs:10} {file:10} {rcrd:10} {indx:10} {zero:10} {other:10}",
            bucket = bucket,
            start_frs = start_frs,
            end_frs = end_frs,
            file = counts.file,
            rcrd = counts.rcrd,
            indx = counts.indx,
            zero = counts.zero,
            other = counts.other,
        );
    }

    Ok(())
}
