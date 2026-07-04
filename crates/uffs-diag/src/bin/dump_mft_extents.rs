// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Dump $MFT extents (VCN, `cluster_count`, LCN) for a given NTFS volume.
//!
//! Windows-only diagnostic helper that uses the same
//! `VolumeHandle::get_mft_extents` pipeline as the main uffs-mft reader. This
//! lets us compare our view of the $MFT layout against tools like `ntfsinfo` or
//! `fsutil file queryextents`.
//!
//! # Usage
//!
//! ```powershell
//! uffs-dump-mft-extents F
//! ```
//!
//! (Pass the drive letter without a colon.)

#![expect(
    unused_crate_dependencies,
    reason = "standalone binary doesn't use all crate dependencies"
)]
// print_stderr is needed on all platforms for the error messages
#![expect(
    clippy::print_stderr,
    reason = "diagnostic tool uses stderr for errors"
)]
// print_stdout is only used on Windows
#![cfg_attr(
    windows,
    expect(clippy::print_stdout, reason = "Windows diagnostic output")
)]

// This binary is Windows-only in terms of real functionality, but is compiled
// on all targets so the workspace stays consistent. We cfg-gate Windows-only
// types and imports to keep non-Windows builds happy.

#[cfg(windows)]
use std::env;

#[cfg(windows)]
use anyhow::{Context as _, Result};
#[cfg(windows)]
use uffs_mft::{MftExtent, VolumeHandle};

fn main() -> std::process::ExitCode {
    uffs_version::handle_version!("uffs-dump-mft-extents");
    #[cfg(windows)]
    {
        if let Err(error) = real_main() {
            eprintln!("uffs-dump-mft-extents failed: {error:#}");
            return std::process::ExitCode::from(1);
        }
        std::process::ExitCode::SUCCESS
    }

    #[cfg(not(windows))]
    {
        eprintln!("uffs-dump-mft-extents is only supported on Windows targets.");
        std::process::ExitCode::from(1)
    }
}

/// Windows entry point — argument parsing, volume open, extent dump.
///
/// Returns `Err` whenever a usage / handle / Win32 step fails so the
/// outer `main` can render the error and yield a non-zero exit code.
#[cfg(windows)]
fn real_main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let drive_arg = args.get(1).cloned().ok_or_else(|| {
        eprintln!("Usage: uffs-dump-mft-extents <drive_letter>");
        eprintln!("Example: uffs-dump-mft-extents F");
        anyhow::anyhow!("missing <drive_letter> argument")
    })?;
    if args.len() != 2 {
        anyhow::bail!(
            "expected exactly one <drive_letter> argument, got {}",
            args.len() - 1
        );
    }

    let mut chars = drive_arg.chars();
    let drive_input = chars
        .next()
        .context("Drive letter argument must not be empty")?;

    // `DriveLetter::parse` enforces ASCII-letter validation and
    // canonicalises to uppercase, replacing the previous hand-rolled
    // `is_ascii_alphabetic` + `to_ascii_uppercase` pair.
    let drive = uffs_mft::platform::DriveLetter::parse(drive_input)
        .with_context(|| format!("Drive letter must be A-Z, got: {drive_input}"))?;

    println!("===============================================");
    println!("Dumping $MFT extents for volume {drive}:");
    println!("===============================================");

    let handle = VolumeHandle::open(drive)
        .with_context(|| format!("Failed to open NTFS volume {drive}:"))?;

    let volume_data = handle.volume_data();
    println!("Volume data:");
    println!(
        "  bytes_per_sector            = {}",
        volume_data.bytes_per_sector
    );
    println!(
        "  bytes_per_cluster           = {}",
        volume_data.bytes_per_cluster
    );
    println!(
        "  bytes_per_file_record_seg   = {}",
        volume_data.bytes_per_file_record_segment
    );
    println!(
        "  clusters_per_file_record    = {}",
        volume_data.clusters_per_file_record_segment
    );
    println!(
        "  mft_valid_data_length (B)   = {}",
        volume_data.mft_valid_data_length
    );
    println!(
        "  mft_start_lcn               = {}",
        volume_data.mft_start_lcn
    );
    println!(
        "  mft2_start_lcn              = {}",
        volume_data.mft2_start_lcn
    );
    println!(
        "  mft_zone_start              = {}",
        volume_data.mft_zone_start
    );
    println!(
        "  mft_zone_end                = {}",
        volume_data.mft_zone_end
    );

    let extents = handle
        .get_mft_extents()
        .with_context(|| format!("Failed to get $MFT extents for drive {drive}"))?;

    if extents.is_empty() {
        println!("No extents returned (fallback to single-run extent may have occurred).");
        return Ok(());
    }

    println!("\nMFT extents (VCN, clusters, LCN):");
    println!(" idx      VCN      clusters           LCN         byte_offset        byte_size");

    let bytes_per_cluster = volume_data.bytes_per_cluster;
    let mut total_clusters: u64 = 0;

    for (idx, extent) in extents.iter().enumerate() {
        print_extent(idx, extent, bytes_per_cluster);
        total_clusters = total_clusters.saturating_add(extent.cluster_count);
    }

    let total_bytes = total_clusters.saturating_mul(u64::from(bytes_per_cluster));
    let record_size = u64::from(volume_data.bytes_per_file_record_segment);
    let approx_records = total_bytes.checked_div(record_size).unwrap_or(0);

    println!("\nSummary:");
    println!("  extent_count      = {}", extents.len());
    println!("  total_clusters    = {total_clusters}");
    println!("  total_bytes       = {total_bytes}");
    println!("  approx_records    = {approx_records} (total_bytes / record_size)");

    Ok(())
}

/// Pretty-print one [`MftExtent`] row including its derived byte
/// offset / size, mirroring the table header printed by `real_main`.
#[cfg(windows)]
fn print_extent(idx: usize, extent: &MftExtent, bytes_per_cluster: u32) {
    let byte_offset = extent.byte_offset(bytes_per_cluster);
    let byte_size = extent.byte_size(bytes_per_cluster);

    println!(
        "{idx:4} {vcn:10} {clusters:10} {lcn:14} {byte_offset:14} {byte_size:14}",
        idx = idx,
        vcn = extent.vcn,
        clusters = extent.cluster_count,
        lcn = extent.lcn,
        byte_offset = byte_offset,
        byte_size = byte_size,
    );
}
