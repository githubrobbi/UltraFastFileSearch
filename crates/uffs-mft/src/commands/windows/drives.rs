// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `drives` command handler — NTFS drive discovery and per-drive summary.
//!
//! Prints every NTFS volume with its label, capacity, free space, and `$MFT`
//! statistics, as a human table or machine JSON (consumed by the benchmark
//! report).  The lint exemptions below capture the CLI-specific display
//! patterns; library code never inherits them.
#![expect(
    clippy::print_stdout,
    reason = "intentional user-facing CLI drive listing output"
)]
#![expect(
    clippy::float_arithmetic,
    clippy::default_numeric_fallback,
    reason = "byte/percent calculations convert integer counters into f64 for human-readable display"
)]
#![expect(
    clippy::min_ident_chars,
    reason = "short closure identifiers aid readability in CLI driver code"
)]

use anyhow::{Context as _, Result};
use uffs_mft::u64_to_f64;

use crate::cli::OutputFormat;
use crate::display::{format_bytes, format_number_commas, truncate_string};

/// Per-drive summary used by [`cmd_drives`] to lay out the per-drive table.
#[cfg(windows)]
struct DriveInfo {
    /// Drive letter (e.g. `C`, `D`).
    letter: uffs_mft::platform::DriveLetter,
    /// `true` when this drive hosts the running OS.
    is_boot: bool,
    /// Volume label as reported by `GetVolumeInformationW`.
    label: String,
    /// Human-readable drive type (`SSD`, `HDD`, `NVMe`, ...).
    drive_type: String,
    /// Total volume capacity in bytes.
    total_size: u64,
    /// Free space in bytes (per Win32 disk-free-space query).
    free_space: u64,
    /// Used space in bytes (`total_size - free_space`).
    used_space: u64,
    /// Used capacity percentage in `[0.0, 100.0]`.
    used_pct: f64,
    /// Size of the `$MFT` file in bytes.
    mft_size: u64,
    /// Number of allocated MFT records on this volume.
    mft_records: u64,
}

/// `drives` CLI command — list every NTFS drive on this system with its
/// label, size, free space, and `$MFT` statistics.
#[cfg(windows)]
pub(crate) async fn cmd_drives(format: OutputFormat) -> Result<()> {
    use tracing::debug;

    debug!("🔍 Detecting NTFS drives...");

    let drive_infos = collect_drive_infos();

    if drive_infos.is_empty() {
        debug!("❌ No NTFS drives found");
        if matches!(format, OutputFormat::Json) {
            println!("[]");
        } else {
            println!("No NTFS drives found.");
        }
        return Ok(());
    }

    debug!(
        count = drive_infos.len(),
        "✅ Found {} NTFS drive(s)",
        drive_infos.len()
    );

    // JSON consumers (e.g. the benchmark report) get the machine form and
    // skip the human table entirely.
    if matches!(format, OutputFormat::Json) {
        return print_drives_json(&drive_infos);
    }

    print_drives_table(&drive_infos);
    Ok(())
}

/// Build the per-drive table rows: the non-privileged physical summary from
/// [`uffs_mft::platform::physical_drives`] (type, label, capacity, used,
/// free) augmented with `$MFT` geometry.
///
/// The `$MFT` columns need an opened volume handle (Administrator or the
/// Access Broker), so they are best-effort — a drive whose handle cannot be
/// opened still lists its physical facts and reports zero MFT stats, rather
/// than being dropped from the table.
#[cfg(windows)]
fn collect_drive_infos() -> Vec<DriveInfo> {
    use tracing::debug;
    use uffs_mft::platform::{VolumeHandle, physical_drives};

    physical_drives()
        .into_iter()
        .map(|drive| {
            let (mft_size, mft_records) =
                VolumeHandle::open(drive.letter)
                    .ok()
                    .map_or((0, 0), |handle| {
                        let vol_data = handle.volume_data();
                        let size = vol_data.mft_valid_data_length;
                        let records = size / u64::from(vol_data.bytes_per_file_record_segment);
                        (size, records)
                    });

            debug!(
                drive = %drive.letter,
                label = %drive.label,
                drive_type = drive.type_label(),
                total_size = drive.total_bytes,
                free_space = drive.free_bytes,
                mft_records,
                "📁 Drive details"
            );

            // Read the borrow-dependent fields before moving `drive.label`
            // into the struct (avoids a partial-move of `drive`).
            let drive_type = drive.type_label().to_owned();
            let used_pct = drive.used_pct();
            DriveInfo {
                letter: drive.letter,
                is_boot: drive.is_boot,
                label: drive.label,
                drive_type,
                total_size: drive.total_bytes,
                free_space: drive.free_bytes,
                used_space: drive.used_bytes,
                used_pct,
                mft_size,
                mft_records,
            }
        })
        .collect()
}

/// Print the human-readable drives summary table with a totals row.
#[cfg(windows)]
fn print_drives_table(drive_infos: &[DriveInfo]) {
    // Print table header
    println!();
    println!(
        "═══════════════════════════════════════════════════════════════════════════════════════════════════"
    );
    println!("                                    NTFS DRIVES SUMMARY");
    println!(
        "═══════════════════════════════════════════════════════════════════════════════════════════════════"
    );
    println!();
    println!(
        "{:<6} {:<16} {:<5} {:>10} {:>10} {:>10} {:>7} {:>10} {:>12}",
        "Drive", "Label", "Type", "Size", "Used", "Free", "Used%", "MFT Size", "MFT Records"
    );
    println!(
        "{:-<6} {:-<16} {:-<5} {:->10} {:->10} {:->10} {:->7} {:->10} {:->12}",
        "", "", "", "", "", "", "", "", ""
    );

    // Print each drive (* = boot/system drive)
    for info in drive_infos {
        let drive_col = if info.is_boot {
            format!("{}:*", info.letter)
        } else {
            format!("{}:", info.letter)
        };
        println!(
            "{:<6} {:<16} {:<5} {:>10} {:>10} {:>10} {:>6.1}% {:>10} {:>12}",
            drive_col,
            truncate_string(&info.label, 16),
            info.drive_type,
            format_bytes(info.total_size),
            format_bytes(info.used_space),
            format_bytes(info.free_space),
            info.used_pct,
            format_bytes(info.mft_size),
            format_number_commas(info.mft_records),
        );
    }

    // Print totals
    let total_size: u64 = drive_infos.iter().map(|d| d.total_size).sum();
    let total_used: u64 = drive_infos.iter().map(|d| d.used_space).sum();
    let total_free: u64 = drive_infos.iter().map(|d| d.free_space).sum();
    let total_mft: u64 = drive_infos.iter().map(|d| d.mft_size).sum();
    let total_records: u64 = drive_infos.iter().map(|d| d.mft_records).sum();
    let total_used_pct = if total_size > 0 {
        (u64_to_f64(total_used) / u64_to_f64(total_size)) * 100.0
    } else {
        0.0
    };

    println!(
        "{:-<6} {:-<16} {:-<5} {:->10} {:->10} {:->10} {:->7} {:->10} {:->12}",
        "", "", "", "", "", "", "", "", ""
    );
    println!(
        "{:<6} {:<16} {:<5} {:>10} {:>10} {:>10} {:>6.1}% {:>10} {:>12}",
        "TOTAL",
        format!("({} drives)", drive_infos.len()),
        "",
        format_bytes(total_size),
        format_bytes(total_used),
        format_bytes(total_free),
        total_used_pct,
        format_bytes(total_mft),
        format_number_commas(total_records),
    );
    println!();
    println!("  * = boot/system drive");
    println!();
}

/// Machine-readable per-drive record for `drives --format json`.
///
/// Field names are stable JSON keys consumed by the benchmark report; byte
/// counters keep their `_bytes` suffix so units are unambiguous.
#[cfg(windows)]
#[derive(serde::Serialize)]
struct DriveRecord {
    /// Drive letter (e.g. `"C"`).
    drive: String,
    /// `true` when this drive hosts the running OS.
    boot: bool,
    /// Volume label.
    label: String,
    /// Storage kind: `"NVMe"`, `"SSD"`, `"HDD"`, or `"???"` (undetected).
    drive_type: String,
    /// Total volume capacity in bytes.
    total_bytes: u64,
    /// Used capacity in bytes.
    used_bytes: u64,
    /// Free capacity in bytes.
    free_bytes: u64,
    /// Used capacity percentage in `[0, 100]`.
    used_pct: f64,
    /// `$MFT` size in bytes.
    mft_size_bytes: u64,
    /// Allocated MFT record count.
    mft_records: u64,
}

/// Emit the drive list as a pretty-printed JSON array on stdout.
///
/// # Errors
/// Returns an error only if JSON serialisation fails (effectively never, given
/// the plain scalar fields).
#[cfg(windows)]
fn print_drives_json(drive_infos: &[DriveInfo]) -> Result<()> {
    let records: Vec<DriveRecord> = drive_infos
        .iter()
        .map(|info| DriveRecord {
            drive: info.letter.to_string(),
            boot: info.is_boot,
            label: info.label.clone(),
            drive_type: info.drive_type.clone(),
            total_bytes: info.total_size,
            used_bytes: info.used_space,
            free_bytes: info.free_space,
            used_pct: info.used_pct,
            mft_size_bytes: info.mft_size,
            mft_records: info.mft_records,
        })
        .collect();
    let json = serde_json::to_string_pretty(&records).context("serialising drives to JSON")?;
    println!("{json}");
    Ok(())
}
