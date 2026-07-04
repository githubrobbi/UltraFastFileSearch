// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Verify IOCP capture contains identical data to raw MFT.
//!
//! Compares an IOCP capture file against a reference raw MFT file by:
//! 1. Loading both files
//! 2. Sorting IOCP chunks by FRS to get sequential order
//! 3. Computing SHA256 of both uncompressed data streams
//! 4. Reporting match/mismatch
//!
//! # Usage
//! ```text
//! uffs-verify-iocp-capture <iocp_file.iocp> <reference.raw|.bin>
//! ```

// Diagnostic binary: relaxed lints for user-facing output and one-time verification
#![expect(
    unused_crate_dependencies,
    reason = "shared Cargo.toml dependencies not used by all binaries"
)]
#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "diagnostic tool — stdout/stderr output is intentional"
)]
#![expect(
    clippy::single_call_fn,
    reason = "diagnostic tool — separate functions for clarity and error handling"
)]
#![expect(
    clippy::float_arithmetic,
    clippy::default_numeric_fallback,
    reason = "diagnostic tool — progress percentages and GB size displays are approximate"
)]
#![expect(
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    reason = "diagnostic tool — flush() errors are safely ignored"
)]
#![expect(
    clippy::indexing_slicing,
    reason = "diagnostic tool — args indexing is guarded by length check"
)]

use std::env;
use std::io::Write as _;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context as _, Result};
use sha2::{Digest as _, Sha256};
use uffs_mft::raw::{LoadRawOptions, load_raw_mft};
use uffs_mft::raw_iocp::load_iocp_capture;

/// Chunk size for progress updates during hashing (256 MB).
const HASH_CHUNK_SIZE: usize = 256 * 1024 * 1024;

/// Conversion factor from bytes to GiB.
const BYTES_TO_GIB: f64 = 1024.0 * 1024.0 * 1024.0;

fn main() -> Result<()> {
    uffs_version::handle_version!("uffs-verify-iocp-capture");
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <iocp_file.iocp> <reference.raw|.bin>", args[0]);
        eprintln!();
        eprintln!("Verifies IOCP capture contains identical data to raw MFT.");
        eprintln!();
        eprintln!("TIP: Build with --release for 10-50x faster hashing!");
        std::process::exit(1);
    }

    let iocp_path = Path::new(&args[1]);
    let ref_path = Path::new(&args[2]);

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║         IOCP Capture Verification Tool                       ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Load and process IOCP capture
    println!("📂 Loading IOCP capture: {}", iocp_path.display());
    let iocp_start = Instant::now();
    let iocp_data = load_and_hash_iocp(iocp_path)?;
    println!(
        "\n   ✓ Loaded in {:.2}s: {} records, {:.2} GB",
        iocp_start.elapsed().as_secs_f64(),
        iocp_data.record_count,
        uffs_mft::usize_to_f64(iocp_data.data_size) / BYTES_TO_GIB
    );
    println!("   SHA256: {}", iocp_data.hash);
    println!();

    // Load and process reference MFT
    println!("📂 Loading reference MFT: {}", ref_path.display());
    let ref_start = Instant::now();
    let ref_data = load_and_hash_raw(ref_path)?;
    println!(
        "\n   ✓ Loaded in {:.2}s: {} records, {:.2} GB",
        ref_start.elapsed().as_secs_f64(),
        ref_data.record_count,
        uffs_mft::usize_to_f64(ref_data.data_size) / BYTES_TO_GIB
    );
    println!("   SHA256: {}", ref_data.hash);
    println!();

    // Compare
    println!("🔍 Comparing...");
    let records_match = iocp_data.record_count == ref_data.record_count;
    let size_match = iocp_data.data_size == ref_data.data_size;
    let hash_match = iocp_data.hash == ref_data.hash;

    println!("╔══════════════════════════════════════════════════════════════╗");
    if records_match && size_match && hash_match {
        println!("║  ✅ VERIFICATION PASSED - Data is identical                  ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
    } else {
        println!("║  ❌ VERIFICATION FAILED - Data differs                       ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        if !records_match {
            println!(
                "   Records: IOCP={}, Reference={}",
                iocp_data.record_count, ref_data.record_count
            );
        }
        if !size_match {
            println!(
                "   Size: IOCP={}, Reference={}",
                iocp_data.data_size, ref_data.data_size
            );
        }
        if !hash_match {
            println!("   Hash mismatch!");
        }
        std::process::exit(1);
    }

    Ok(())
}

/// Result of loading and hashing a data source.
struct HashResult {
    /// Number of MFT records.
    record_count: u64,
    /// Total data size in bytes.
    data_size: usize,
    /// Hex-encoded SHA256 hash.
    hash: String,
}

/// Loads an IOCP capture file, reassembles in FRS order, and computes SHA256.
fn load_and_hash_iocp(path: &Path) -> Result<HashResult> {
    print!("   Reading & decompressing...");
    let _ = std::io::stdout().flush();

    let capture = load_iocp_capture(path).context("Failed to load IOCP capture")?;

    let record_size = capture.record_size();
    let total_records = capture.header.total_records;
    let total_size = uffs_mft::frs_to_usize(total_records * u64::from(record_size));

    println!(
        " {} chunks, {:.2} GB uncompressed",
        capture.chunks.len(),
        uffs_mft::usize_to_f64(total_size) / BYTES_TO_GIB
    );

    // Allocate buffer and reassemble in FRS order
    print!("   Reassembling chunks in FRS order...");
    let _ = std::io::stdout().flush();

    let mut data = vec![0_u8; total_size];

    // Sort chunks by start_frs
    let mut chunks: Vec<_> = capture.iter_chunks().collect();
    chunks.sort_by_key(|(chunk, _)| chunk.start_frs);

    // Copy each chunk to correct position
    for (chunk, chunk_data) in chunks {
        let start_offset = uffs_mft::frs_to_usize(chunk.start_frs * u64::from(record_size));
        let end_offset = start_offset + chunk_data.len();
        data[start_offset..end_offset].copy_from_slice(chunk_data);
    }
    println!(" done");

    // Compute SHA256 with progress
    let hash = compute_sha256_with_progress(&data, "IOCP");

    Ok(HashResult {
        record_count: total_records,
        data_size: total_size,
        hash,
    })
}

/// Loads a raw MFT file and computes SHA256.
fn load_and_hash_raw(path: &Path) -> Result<HashResult> {
    print!("   Reading file...");
    let _ = std::io::stdout().flush();

    let raw = load_raw_mft(path, &LoadRawOptions {
        header_only: false,
        volume_letter: None,
        forensic: false,
    })
    .context("Failed to load raw MFT")?;

    println!(
        " done ({:.2} GB)",
        uffs_mft::usize_to_f64(raw.data.len()) / BYTES_TO_GIB
    );

    let hash = compute_sha256_with_progress(&raw.data, "RAW ");

    Ok(HashResult {
        record_count: raw.header.record_count,
        data_size: raw.data.len(),
        hash,
    })
}

/// Computes SHA256 of data with progress indicator.
fn compute_sha256_with_progress(data: &[u8], label: &str) -> String {
    let mut hasher = Sha256::new();
    let total = data.len();
    let mut processed = 0_usize;

    print!("   Hashing {label}: ");
    let _ = std::io::stdout().flush();

    for chunk in data.chunks(HASH_CHUNK_SIZE) {
        hasher.update(chunk);
        processed = processed.saturating_add(chunk.len());
        let pct = (uffs_mft::usize_to_f64(processed) / uffs_mft::usize_to_f64(total)) * 100.0;
        print!("\r   Hashing {label}: {pct:.0}%");
        let _ = std::io::stdout().flush();
    }

    let result = hasher.finalize();
    hex::encode(result)
}
