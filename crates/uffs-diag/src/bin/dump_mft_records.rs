// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Dump raw MFT records from a `.raw` snapshot for specific FRS values.
//!
//! Offline, cross-platform tool operating on `uffs-mft`'s raw MFT format
//! (`*.raw` produced by `uffs-mft save`). This lets us inspect header flags
//! and basic structure for selected records to verify parse correctness.
//!
//! Usage:
//! ```text
//!   uffs-dump-mft-records <raw_path> <frs1> [frs2] ...
//!   uffs-dump-mft-records --test-merge <raw_path> <base_frs> <ext_frs>
//! ```

#![expect(
    unused_crate_dependencies,
    reason = "standalone binary doesn't use all crate dependencies"
)]
#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "diagnostic tool — stdout/stderr output is intentional"
)]

use std::env;
use std::path::Path;

use anyhow::{Context as _, Result};
use uffs_mft::parse::{MftRecordMerger, ParseResult, parse_record_full};
use uffs_mft::raw::{LoadRawOptions, load_raw_mft};
// This binary intentionally pulls in uffs_polars via the uffs-diag crate
// dependency set so that offline diagnostics can share the same Polars
// facade version as the main CLI, even though this specific tool does not
// use it directly.
use uffs_polars as _;

/// Local copy of `MultiSectorHeader` layout so this tool can run on
/// non-Windows targets (the real `ntfs` module is `cfg(windows)`).
/// This matches the definition in `crates/uffs-mft/src/ntfs.rs`.
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

/// Header at the start of every NTFS file record segment.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct FileRecordSegmentHeader {
    /// NTFS multi-sector (USA) header at the start of the record.
    multi_sector_header: MultiSectorHeader,
    /// Log file sequence number (LSN) for this record.
    log_file_sequence_number: i64,
    /// Per-record sequence number used for stale handle detection.
    sequence_number: u16,
    /// Number of hard links (directory entries) pointing at this record.
    link_count: u16,
    /// Byte offset from the start of the record to the first attribute.
    first_attribute_offset: u16,
    /// Bitflags describing record state (in-use, directory, etc.).
    flags: u16,
    /// Number of bytes in use within this record.
    bytes_in_use: u32,
    /// Total bytes allocated for this record.
    bytes_allocated: u32,
    /// File reference of the base record if this is an extension record.
    base_file_record_segment: u64,
    /// Next attribute identifier to be assigned.
    next_attribute_number: u16,
    /// Reserved field in the on-disk layout.
    reserved: u16,
    /// Lower 32 bits of the file reference number.
    segment_number_lower: u32,
}

impl FileRecordSegmentHeader {
    /// Returns `true` if the record is currently marked as in-use.
    const fn is_in_use(&self) -> bool {
        (self.flags & 0x0001) != 0
    }

    /// Returns `true` if the record represents a directory.
    const fn is_directory(&self) -> bool {
        (self.flags & 0x0002) != 0
    }

    /// Returns `true` if this record is a base record (not an extension).
    const fn is_base_record(&self) -> bool {
        self.base_file_record_segment == 0
    }
}

/// Reads a little-endian `u16` from `data` at `offset`.
fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

/// Reads a little-endian `u32` from `data` at `offset`.
fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// Reads a little-endian `u64` from `data` at `offset`.
fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// Reads a little-endian `i64` from `data` at `offset`.
fn read_i64_le(data: &[u8], offset: usize) -> Option<i64> {
    Some(i64::from_le_bytes(
        data.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// Parses the leading bytes of a record into a local file record segment
/// header copy.
fn parse_file_record_segment_header(data: &[u8]) -> Option<FileRecordSegmentHeader> {
    Some(FileRecordSegmentHeader {
        multi_sector_header: MultiSectorHeader {
            magic: read_u32_le(data, 0)?,
            usa_offset: read_u16_le(data, 4)?,
            usa_count: read_u16_le(data, 6)?,
        },
        log_file_sequence_number: read_i64_le(data, 8)?,
        sequence_number: read_u16_le(data, 16)?,
        link_count: read_u16_le(data, 18)?,
        first_attribute_offset: read_u16_le(data, 20)?,
        flags: read_u16_le(data, 22)?,
        bytes_in_use: read_u32_le(data, 24)?,
        bytes_allocated: read_u32_le(data, 28)?,
        base_file_record_segment: read_u64_le(data, 32)?,
        next_attribute_number: read_u16_le(data, 40)?,
        reserved: read_u16_le(data, 42)?,
        segment_number_lower: read_u32_le(data, 44)?,
    })
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: uffs-dump-mft-records <mft.raw> <frs1> [frs2 frs3 ...]\n       uffs-dump-mft-records --test-merge <mft.raw> <base_frs> <ext_frs>"
        );
        std::process::exit(1);
    }

    // Check for --test-merge mode
    if args.get(1).map(String::as_str) == Some("--test-merge") {
        if args.len() < 5 {
            eprintln!("Usage: uffs-dump-mft-records --test-merge <mft.raw> <base_frs> <ext_frs>");
            std::process::exit(1);
        }
        let raw_path = args
            .get(2)
            .map(String::as_str)
            .ok_or_else(|| anyhow::anyhow!("Expected <mft.raw> path argument"))?;
        let base_frs: u64 = args
            .get(3)
            .ok_or_else(|| anyhow::anyhow!("Expected base_frs"))?
            .parse()?;
        let ext_frs: u64 = args
            .get(4)
            .ok_or_else(|| anyhow::anyhow!("Expected ext_frs"))?
            .parse()?;
        return test_merge(raw_path, base_frs, ext_frs);
    }

    let raw_path = args.get(1).map(String::as_str).ok_or_else(|| {
        anyhow::anyhow!("Expected <mft.raw> path argument to be present after length check")
    })?;
    let frs_values: Vec<u64> = args
        .get(2..)
        .ok_or_else(|| anyhow::anyhow!("Expected at least one FRS argument after <mft.raw>"))?
        .iter()
        .map(|arg| arg.parse::<u64>())
        .collect::<core::result::Result<_, _>>()
        .context("Failed to parse FRS arguments as u64")?;

    let path = Path::new(raw_path);
    let raw = load_raw_mft(path, &LoadRawOptions::default())
        .with_context(|| format!("Failed to load raw MFT from {}", path.display()))?;

    println!(
        "Loaded raw MFT: {} records, record_size={} bytes",
        raw.header.record_count, raw.header.record_size
    );

    for frs_value in frs_values {
        println!("\n============================================================");
        println!("FRS {frs_value}");
        println!("============================================================");

        match raw.get_record(frs_value) {
            Some(data) => dump_record(frs_value, data),
            None => {
                println!(
                    "Record out of range (max FRS = {})",
                    raw.header.record_count.saturating_sub(1)
                );
            }
        }
    }

    Ok(())
}

/// Test the merge functionality for a specific base/extension record pair.
#[expect(
    clippy::use_debug,
    reason = "diagnostic tool — Debug output is intentional for inspection"
)]
#[expect(
    clippy::too_many_lines,
    reason = "sequential diagnostic dump — splitting would reduce clarity"
)]
fn test_merge(raw_path: &str, base_frs: u64, ext_frs: u64) -> Result<()> {
    let path = Path::new(raw_path);
    let raw = load_raw_mft(path, &LoadRawOptions::default())
        .with_context(|| format!("Failed to load raw MFT from {}", path.display()))?;

    println!(
        "Loaded raw MFT: {} records, record_size={} bytes",
        raw.header.record_count, raw.header.record_size
    );

    // Parse base record
    println!("\n=== Parsing FRS {base_frs} (base record) ===");
    if let Some(data) = raw.get_record(base_frs) {
        match parse_record_full(data, base_frs) {
            ParseResult::Base(record) => {
                println!("  Result: Base record");
                println!("  name: {:?}", record.name);
                println!("  parent_frs: {}", record.parent_frs);
                println!("  size: {}", record.size);
                println!("  allocated_size: {}", record.allocated_size);
                println!("  is_directory: {}", record.is_directory);
                println!("  names.len(): {}", record.names.len());
                for (idx, name) in record.names.iter().enumerate() {
                    println!(
                        "    names[{idx}]: {:?} (parent={}, ns={})",
                        name.name, name.parent_frs, name.namespace
                    );
                }
                println!("  streams.len(): {}", record.streams.len());
                for (idx, stream) in record.streams.iter().enumerate() {
                    println!(
                        "    streams[{idx}]: {:?} (size={}, allocated={})",
                        stream.name, stream.size, stream.allocated_size
                    );
                }
            }
            ParseResult::Extension(ext) => {
                println!("  Result: Extension record (base_frs={})", ext.base_frs);
                println!("  names.len(): {}", ext.names.len());
            }
            ParseResult::Skip => {
                println!("  Result: Skip");
            }
        }
    } else {
        println!("  Record not found");
    }

    // Parse extension record
    println!("\n=== Parsing FRS {ext_frs} (extension record) ===");
    if let Some(data) = raw.get_record(ext_frs) {
        match parse_record_full(data, ext_frs) {
            ParseResult::Base(record) => {
                println!("  Result: Base record");
                println!("  name: {:?}", record.name);
                println!("  names.len(): {}", record.names.len());
            }
            ParseResult::Extension(ext) => {
                println!("  Result: Extension record (base_frs={})", ext.base_frs);
                println!("  names.len(): {}", ext.names.len());
                for (idx, name) in ext.names.iter().enumerate() {
                    println!(
                        "    names[{idx}]: {:?} (parent={}, ns={})",
                        name.name, name.parent_frs, name.namespace
                    );
                }
            }
            ParseResult::Skip => {
                println!("  Result: Skip");
            }
        }
    } else {
        println!("  Record not found");
    }

    // Test the record_merger with all records
    println!("\n=== Testing MftRecordMerger ===");
    let num_records = uffs_mft::frs_to_usize(raw.header.record_count);
    let mut record_merger = MftRecordMerger::with_capacity(num_records);

    for frs in 0..num_records {
        if let Some(data) = raw.get_record(frs as u64) {
            // usize→u64 lossless on 64-bit
            let result = parse_record_full(data, frs as u64); // usize→u64 lossless on 64-bit
            record_merger.add_result(result);
        }
    }

    println!("  base_count: {}", record_merger.base_count());
    println!("  extension_count: {}", record_merger.extension_count());

    // Merge and check the base record
    let merged_records = record_merger.merge();
    println!("  merged.len(): {}", merged_records.len());

    // Find the base record in merged results.  `base_frs` is the
    // CLI-parsed `u64`; lift to the typed `Frs` for the equality check.
    let base_frs_typed = uffs_mft::Frs::new(base_frs);
    if let Some(record) = merged_records.iter().find(|rec| rec.frs == base_frs_typed) {
        println!("\n=== FRS {base_frs} after merge ===");
        println!("  name: {:?}", record.name);
        println!("  parent_frs: {}", record.parent_frs);
        println!("  size: {}", record.size);
        println!("  allocated_size: {}", record.allocated_size);
        println!("  is_directory: {}", record.is_directory);
        println!("  names.len(): {}", record.names.len());
        for (idx, name) in record.names.iter().enumerate() {
            println!(
                "    names[{idx}]: {:?} (parent={}, ns={})",
                name.name, name.parent_frs, name.namespace
            );
        }
        println!("  streams.len(): {}", record.streams.len());
        for (idx, stream) in record.streams.iter().enumerate() {
            println!(
                "    streams[{idx}]: {:?} (size={}, allocated={})",
                stream.name, stream.size, stream.allocated_size
            );
        }
    } else {
        println!("\n=== FRS {base_frs} NOT FOUND in merged results ===");
    }

    // Now build the MftIndex and check the record
    println!("\n=== Building MftIndex from merged records ===");
    let index = uffs_mft::index::MftIndex::from_parsed_records(
        uffs_mft::platform::DriveLetter::D,
        merged_records,
    );
    println!("  records.len(): {}", index.records.len());
    println!("  children.len(): {}", index.children_count());

    // Find the record in the index. Lift the CLI-parsed raw `u64` to
    // a typed `Frs` at the typed-API boundary.
    if let Some(record) = index.find(uffs_mft::Frs::new(base_frs)) {
        println!("\n=== FRS {base_frs} in MftIndex ===");
        println!("  frs: {}", record.frs);
        println!("  name: {:?}", index.get_name(record.first_name.name));
        println!("  parent_frs: {}", record.first_name.parent_frs);
        println!("  is_directory: {}", record.is_directory());
        println!("  name_count: {}", record.name_count);
        println!("  stream_count: {}", record.stream_count);
        println!("  first_stream.size: {}", record.first_stream.size.length);
        println!(
            "  first_stream.next_entry: {}",
            record.first_stream.next_entry
        );
        println!("  descendants: {}", record.descendants);
        println!("  treesize: {}", record.treesize);
        println!("  tree_allocated: {}", record.tree_allocated);
        println!("  first_child: {}", record.first_child);

        // Check children by iterating through the children list
        let mut child_count = 0_u32;
        let mut child_entry_idx = record.first_child;
        while child_entry_idx != uffs_mft::index::NO_ENTRY {
            if let Some(child_entry) = index.children.get(uffs_mft::u32_as_usize(child_entry_idx)) {
                child_count += 1_u32;
                if child_count <= 5_u32 {
                    println!(
                        "    child[{}]: frs={}, name_index={}",
                        child_count - 1_u32,
                        child_entry.child_frs,
                        child_entry.name_index
                    );
                }
                child_entry_idx = child_entry.next_entry;
            } else {
                break;
            }
        }
        println!("  total children: {child_count}");

        // Check streams by iterating through the streams list
        let mut stream_count = 0_u32;
        let mut stream_entry_idx = record.first_stream.next_entry;
        while stream_entry_idx != uffs_mft::index::NO_ENTRY {
            if let Some(stream_entry) = index.streams.get(uffs_mft::u32_as_usize(stream_entry_idx))
            {
                stream_count += 1_u32;
                println!(
                    "    stream[{}]: {:?} (size={})",
                    stream_count,
                    index.get_name(stream_entry.name),
                    stream_entry.size.length
                );
                stream_entry_idx = stream_entry.next_entry;
            } else {
                break;
            }
        }
        println!("  total additional streams: {stream_count}");
    } else {
        println!("\n=== FRS {base_frs} NOT FOUND in MftIndex ===");
    }

    Ok(())
}
/// Number of bytes from the start of each record to include in the diagnostic
/// hex dump. This keeps output manageable while still showing header-adjacent
/// data for manual inspection.
const DUMP_BYTES: usize = 256;

/// Dump a single raw MFT record's header and a small hex preview.
fn dump_record(frs: u64, data: &[u8]) {
    use core::mem::size_of;

    println!("Record {frs}: {} bytes", data.len());

    if data.len() < size_of::<FileRecordSegmentHeader>() {
        println!("  Record too small for FileRecordSegmentHeader");
        return;
    }

    let Some(header) = parse_file_record_segment_header(data) else {
        println!("  Failed to decode FileRecordSegmentHeader");
        return;
    };

    // Copy out of the packed struct fields to avoid unaligned references.
    let ms = header.multi_sector_header;
    let magic = ms.magic;
    let usa_offset = ms.usa_offset;
    let usa_count = ms.usa_count;

    let sequence_number = header.sequence_number;
    let link_count = header.link_count;
    let first_attribute_offset = header.first_attribute_offset;
    let flags = header.flags;
    let bytes_in_use = header.bytes_in_use;
    let bytes_allocated = header.bytes_allocated;
    let base_file_record_segment = header.base_file_record_segment;

    println!("MultiSectorHeader:");
    println!("  magic      = 0x{magic:08X}");
    println!("  usa_offset = {usa_offset}");
    println!("  usa_count  = {usa_count}");

    println!("FileRecordSegmentHeader:");
    println!("  sequence_number        = {sequence_number}");
    println!("  link_count             = {link_count}");
    println!("  first_attribute_offset = {first_attribute_offset}");
    println!("  flags                  = 0x{flags:04X}");
    println!("    is_in_use            = {}", header.is_in_use());
    println!("    is_directory         = {}", header.is_directory());
    println!("  bytes_in_use           = {bytes_in_use}");
    println!("  bytes_allocated        = {bytes_allocated}");
    println!("  base_file_record_seg   = 0x{base_file_record_segment:016X}");
    println!("  is_base_record         = {}", header.is_base_record());

    // Quick hex dump of the first part of the record for manual inspection.
    let dump_len = core::cmp::min(DUMP_BYTES, data.len());
    let Some(slice) = data.get(..dump_len) else {
        println!("\nNo bytes available to dump (record shorter than header)");
        return;
    };

    println!("\nFirst {dump_len} bytes (hex):");
    for (index, chunk) in slice.chunks(16).enumerate() {
        print!("  {offset:04X}: ", offset = index * 16);
        for byte in chunk {
            print!("{byte:02X} ");
        }
        println!();
    }
}
