// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Compare two raw MFT files record-by-record.
//!
//! This tool streams through two UFFS-MFT format files and compares them
//! record-by-record without loading the entire files into memory.
//!
//! # Usage
//!
//! ```text
//! uffs-compare-raw-mft <file_a> <file_b>
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
#![expect(
    clippy::arithmetic_side_effects,
    reason = "diagnostic tool arithmetic on known-valid data"
)]

use std::env;
use std::fs::File;
use std::io::{BufReader, Read as _};
use std::path::Path;
use std::time::Instant;

use anyhow::{Context as _, Result, bail};

/// Header size in bytes (matches `uffs_mft::raw`).
const HEADER_SIZE: usize = 64;

/// Maximum number of sample diffs to collect for display.
const MAX_SAMPLES: usize = 20;

/// Magic bytes for raw MFT file format.
const MAGIC: &[u8; 8] = b"UFFS-MFT";

/// Flag: data is zstd compressed.
const FLAG_COMPRESSED: u32 = 0x0001;

/// Parsed header from a raw MFT file.
#[derive(Debug)]
struct RawMftHeader {
    /// Format version number.
    version: u32,
    /// Flags (e.g., compression).
    flags: u32,
    /// Size of each MFT record in bytes.
    record_size: u32,
    /// Total number of records in the file.
    record_count: u64,
    /// Original uncompressed size in bytes.
    original_size: u64,
    /// Compressed size in bytes (if compressed).
    #[expect(dead_code, reason = "parsed from binary format but not yet used")]
    compressed_size: u64,
}

impl RawMftHeader {
    /// Parse header from raw bytes.
    #[expect(
        clippy::single_call_fn,
        reason = "factored for clarity in comparison tool"
    )]
    fn from_bytes(buf: &[u8; HEADER_SIZE]) -> Result<Self> {
        if &buf[0..8] != MAGIC {
            bail!("Invalid magic bytes");
        }
        let version = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let flags = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let record_size = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let record_count = u64::from_le_bytes([
            buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27],
        ]);
        let original_size = u64::from_le_bytes([
            buf[28], buf[29], buf[30], buf[31], buf[32], buf[33], buf[34], buf[35],
        ]);
        let compressed_size = u64::from_le_bytes([
            buf[36], buf[37], buf[38], buf[39], buf[40], buf[41], buf[42], buf[43],
        ]);
        Ok(Self {
            version,
            flags,
            record_size,
            record_count,
            original_size,
            compressed_size,
        })
    }

    /// Check if the file is compressed.
    const fn is_compressed(&self) -> bool {
        self.flags & FLAG_COMPRESSED != 0
    }
}

/// Read and parse the header from a raw MFT file.
fn read_header<P: AsRef<Path>>(path: P) -> Result<(RawMftHeader, BufReader<File>)> {
    let file = File::open(path.as_ref())
        .with_context(|| format!("Failed to open {}", path.as_ref().display()))?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file); // 1MB buffer
    let mut header_buf = [0_u8; HEADER_SIZE];
    reader.read_exact(&mut header_buf)?;
    let header = RawMftHeader::from_bytes(&header_buf)?;
    Ok((header, reader))
}

#[expect(
    clippy::float_arithmetic,
    clippy::too_many_lines,
    reason = "diagnostic CLI main: sequential parse-args → read-headers → validate → \
              compare-loop → report pipeline; splitting would scatter the linear flow"
)]
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: uffs-compare-raw-mft <file_a> <file_b>");
        std::process::exit(1);
    }

    let Some(path_a) = args.get(1) else {
        bail!("Missing first file argument");
    };
    let Some(path_b) = args.get(2) else {
        bail!("Missing second file argument");
    };

    println!("=== Raw MFT Comparison ===");
    println!("File A: {path_a}");
    println!("File B: {path_b}");
    println!();

    // Read headers
    let (header_a, mut reader_a) = read_header(path_a)?;
    let (header_b, mut reader_b) = read_header(path_b)?;

    println!(
        "Header A: version={}, flags={}, record_size={}, record_count={}, original_size={}",
        header_a.version,
        header_a.flags,
        header_a.record_size,
        header_a.record_count,
        header_a.original_size
    );
    println!(
        "Header B: version={}, flags={}, record_size={}, record_count={}, original_size={}",
        header_b.version,
        header_b.flags,
        header_b.record_size,
        header_b.record_count,
        header_b.original_size
    );
    println!();

    // Validate geometry matches
    if header_a.record_size != header_b.record_size {
        bail!(
            "Record size mismatch: {} vs {}",
            header_a.record_size,
            header_b.record_size
        );
    }
    if header_a.record_count != header_b.record_count {
        bail!(
            "Record count mismatch: {} vs {}",
            header_a.record_count,
            header_b.record_count
        );
    }

    // Check for compression (not supported in streaming mode)
    if header_a.is_compressed() || header_b.is_compressed() {
        bail!("Compressed files not supported - decompress first");
    }

    let record_size = uffs_mft::u32_as_usize(header_a.record_size);
    let record_count = header_a.record_count;
    let total_bytes = record_count * u64::from(header_a.record_size);

    println!(
        "Comparing {record_count} records of {record_size} bytes each ({:.2} GiB)...",
        uffs_mft::u64_to_f64(total_bytes) / 1_024.0_f64 / 1_024.0_f64 / 1_024.0_f64
    );
    println!();

    // Allocate buffers for one record each
    let mut buf_a = vec![0_u8; record_size];
    let mut buf_b = vec![0_u8; record_size];

    let mut same_records: u64 = 0;
    let mut diff_records: u64 = 0;
    let mut diff_bytes_total: u64 = 0;
    let mut sample_diffs: Vec<(u64, usize)> = Vec::new(); // (frs, diff_byte_count)

    let start = Instant::now();
    let progress_interval = 1_000_000_u64; // Report every 1M records

    for frs in 0..record_count {
        // Progress reporting
        if frs > 0 && frs % progress_interval == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let rate = uffs_mft::u64_to_f64(frs) / elapsed;
            let eta = uffs_mft::u64_to_f64(record_count - frs) / rate;
            println!(
                "  Progress: {frs} / {record_count} records ({:.1}%), {rate:.0} rec/s, ETA {eta:.0}s",
                uffs_mft::u64_to_f64(frs) / uffs_mft::u64_to_f64(record_count) * 100.0_f64,
            );
        }

        // Read records
        reader_a
            .read_exact(&mut buf_a)
            .with_context(|| format!("EOF reading record {frs} from A"))?;
        reader_b
            .read_exact(&mut buf_b)
            .with_context(|| format!("EOF reading record {frs} from B"))?;

        if buf_a == buf_b {
            same_records += 1;
        } else {
            diff_records += 1;
            // Count differing bytes
            let diff_bytes: usize = buf_a
                .iter()
                .zip(buf_b.iter())
                .filter(|(byte_a, byte_b)| byte_a != byte_b)
                .count();
            diff_bytes_total += diff_bytes as u64; // usize→u64 lossless on 64-bit
            if sample_diffs.len() < MAX_SAMPLES {
                sample_diffs.push((frs, diff_bytes));
            }
        }
    }

    let elapsed = start.elapsed();
    println!();
    println!("=== Comparison Complete ===");
    println!("Time: {:.2}s", elapsed.as_secs_f64());
    println!();
    println!("Total records:  {record_count}");
    println!("Same records:   {same_records}");
    println!(
        "Diff records:   {diff_records} ({:.6}%)",
        uffs_mft::u64_to_f64(diff_records) / uffs_mft::u64_to_f64(record_count) * 100.0_f64
    );
    println!("Total differing bytes: {diff_bytes_total}");
    if total_bytes > 0 {
        println!(
            "Fraction of differing bytes: {:.9}",
            uffs_mft::u64_to_f64(diff_bytes_total) / uffs_mft::u64_to_f64(total_bytes)
        );
    }
    println!();

    if sample_diffs.is_empty() {
        println!("Files are IDENTICAL!");
    } else {
        println!(
            "First {} differing records (FRS, differing_bytes_in_record):",
            sample_diffs.len()
        );
        for (frs, diff_bytes) in &sample_diffs {
            println!("  FRS {frs}: {diff_bytes} bytes differ");
        }
    }

    Ok(())
}
