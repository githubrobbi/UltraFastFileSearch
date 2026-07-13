// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `info` command handler — volume and `$MFT` diagnostics for one drive.
//!
//! Prints human-readable volume metadata to stdout, converts byte counters
//! into KB/MB/percent for display, and uses `Debug` formatting for opaque
//! diagnostic enums.  The lint exemptions below capture those CLI-specific
//! patterns; library code never inherits them.  The sibling `super::drives`
//! module handles multi-drive discovery.
#![expect(
    clippy::print_stdout,
    reason = "intentional user-facing CLI volume info output"
)]
#![expect(
    clippy::float_arithmetic,
    clippy::default_numeric_fallback,
    reason = "byte/percent calculations convert integer counters into f64 for human-readable display"
)]
#![expect(
    clippy::min_ident_chars,
    clippy::shadow_unrelated,
    reason = "short identifiers and sequential rebinding aid readability in CLI driver code"
)]
#![expect(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    reason = "info commands run a configure -> query -> format -> print pipeline that is most readable inline"
)]

use anyhow::{Context as _, Result};
use uffs_mft::{MftReader, bytes_to_mb_f64, u64_to_f64, usize_to_u64};

use crate::cli::OutputFormat;
use crate::display::{format_bytes, format_duration, format_number_commas};

/// `info` CLI command — print MFT and volume diagnostics for `drive`.
///
/// `deep` enables full-MFT scans (slower, more accurate counts), `no_bitmap`
/// disables the `$Bitmap`-driven skip optimisation, and `unique` reports
/// unique-FRS counts in addition to total parse counts.
#[cfg(windows)]
pub(crate) async fn cmd_info(
    drive: uffs_mft::platform::DriveLetter,
    deep: bool,
    no_bitmap: bool,
    unique: bool,
    format: OutputFormat,
) -> Result<()> {
    use std::time::Instant;

    use tracing::debug;
    use uffs_mft::platform::{VolumeHandle, detect_drive_type};

    let start_time = Instant::now();
    debug!(
        drive = %drive,
        deep,
        no_bitmap,
        unique,
        "📊 Retrieving MFT information{}{}{}",
        if deep { " (deep scan)" } else { "" },
        if no_bitmap { " (bitmap disabled)" } else { "" },
        if unique { " (unique FRS mode)" } else { "" }
    );

    debug!(drive = %drive, "🔓 Opening volume handle");
    let handle = VolumeHandle::open(drive).with_context(|| format!("Failed to open {drive}:"))?;

    // Detect drive type for display
    let drive_type = detect_drive_type(drive);
    let drive_type_str = drive_type.label();
    debug!(drive = %drive, drive_type = drive_type_str, "🚀 Drive type detected");

    let vol_data = handle.volume_data();

    // Calculate derived metrics
    let record_count =
        vol_data.mft_valid_data_length / u64::from(vol_data.bytes_per_file_record_segment);
    let mft_size_mb = bytes_to_mb_f64(vol_data.mft_valid_data_length);
    let volume_size_bytes = vol_data.total_clusters * u64::from(vol_data.bytes_per_cluster);
    let volume_size_gb = u64_to_f64(volume_size_bytes) / (1024.0_f64 * 1024.0_f64 * 1024.0_f64);
    let free_space_bytes = vol_data.free_clusters * u64::from(vol_data.bytes_per_cluster);
    let used_space_bytes = volume_size_bytes.saturating_sub(free_space_bytes);
    let free_percentage = if volume_size_bytes > 0 {
        (u64_to_f64(free_space_bytes) / u64_to_f64(volume_size_bytes)) * 100.0
    } else {
        0.0
    };
    let mft_percentage =
        (u64_to_f64(vol_data.mft_valid_data_length) / u64_to_f64(volume_size_bytes)) * 100.0;

    // Log detailed metrics
    debug!(
        drive = %drive,
        bytes_per_sector = vol_data.bytes_per_sector,
        bytes_per_cluster = vol_data.bytes_per_cluster,
        bytes_per_record = vol_data.bytes_per_file_record_segment,
        "📐 Volume geometry"
    );

    debug!(
        drive = %drive,
        total_clusters = vol_data.total_clusters,
        volume_size_gb = format!("{:.2}", volume_size_gb),
        "💾 Volume capacity"
    );

    debug!(
        drive = %drive,
        mft_start_lcn = vol_data.mft_start_lcn,
        mft_valid_length = vol_data.mft_valid_data_length,
        mft_size_mb = format!("{:.2}", mft_size_mb),
        estimated_records = record_count,
        mft_percentage = format!("{:.3}%", mft_percentage),
        "📁 MFT metrics"
    );

    // Fragmentation analysis
    let mut extent_count = 1;
    let mut is_fragmented = false;
    if let Ok(extents) = handle.get_mft_extents() {
        extent_count = extents.len();
        is_fragmented = extent_count > 1;

        if is_fragmented {
            debug!(
                drive = %drive,
                extent_count,
                "⚠️  MFT is fragmented across multiple extents"
            );
            debug!("MFT extent details:");
            for (i, ext) in extents.iter().enumerate() {
                debug!(
                    extent = i,
                    vcn = ext.vcn,
                    lcn = %ext.lcn,
                    clusters = ext.cluster_count,
                    "  Extent {}: VCN {} → LCN {}, {} clusters",
                    i,
                    ext.vcn,
                    ext.lcn,
                    ext.cluster_count
                );
            }
        } else {
            debug!(
                drive = %drive,
                "✅ MFT is contiguous (single extent)"
            );
        }
    }

    // Bitmap analysis
    let mut in_use_records = 0_u64;
    let mut free_records = 0_u64;
    let mut utilization = 0.0_f64;
    if let Ok(bitmap) = handle.get_mft_bitmap() {
        in_use_records = usize_to_u64(bitmap.count_in_use());
        free_records = record_count.saturating_sub(in_use_records);
        utilization = (u64_to_f64(in_use_records) / u64_to_f64(record_count)) * 100.0;

        debug!(
            drive = %drive,
            in_use_records,
            free_records,
            utilization = format!("{:.1}%", utilization),
            "📈 MFT utilization"
        );
    }

    // Health assessment (based on metadata only - no full scan)
    let mut warnings = Vec::new();
    if is_fragmented && extent_count > 10 {
        warnings.push(format!(
            "MFT is heavily fragmented ({extent_count} extents)"
        ));
    }
    if utilization > 95.0 {
        warnings.push(format!("MFT utilization is very high ({utilization:.1}%)"));
    }

    let elapsed = start_time.elapsed();

    // Machine / compact consumers get the lightweight metadata summary and skip
    // the rich human report (and the expensive `--deep` full-MFT scan below).
    if matches!(format, OutputFormat::Json | OutputFormat::Table) {
        let report = InfoReport {
            drive: drive.to_string(),
            drive_type: drive_type_str.to_owned(),
            deep,
            bytes_per_sector: u64::from(vol_data.bytes_per_sector),
            bytes_per_cluster: u64::from(vol_data.bytes_per_cluster),
            bytes_per_record: u64::from(vol_data.bytes_per_file_record_segment),
            total_clusters: vol_data.total_clusters,
            volume_size_bytes,
            used_bytes: used_space_bytes,
            free_bytes: free_space_bytes,
            free_pct: free_percentage,
            mft_start_lcn: vol_data.mft_start_lcn,
            mft_size_bytes: vol_data.mft_valid_data_length,
            mft_pct_of_volume: mft_percentage,
            total_records: record_count,
            in_use_records,
            free_records,
            utilization_pct: utilization,
            extent_count: usize_to_u64(extent_count),
            fragmented: is_fragmented,
            warnings: warnings.clone(),
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        };
        if matches!(format, OutputFormat::Json) {
            print_info_json(&report)?;
        } else {
            print_info_table(&report);
        }
        return Ok(());
    }

    // Print human-readable summary
    println!("═══════════════════════════════════════════════════════════════");
    if deep {
        println!("                    MFT ANALYSIS REPORT");
    } else {
        println!("                    MFT INFO (Lightweight)");
    }
    println!("                    Drive: {drive}: ({drive_type_str})");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("📐 VOLUME GEOMETRY");
    println!("  Drive type:           {drive_type_str}");
    println!(
        "  Bytes per sector:     {}",
        format_number_commas(vol_data.bytes_per_sector.into())
    );
    println!(
        "  Bytes per cluster:    {}",
        format_number_commas(vol_data.bytes_per_cluster.into())
    );
    println!(
        "  Bytes per MFT record: {}",
        format_number_commas(vol_data.bytes_per_file_record_segment.into())
    );
    println!(
        "  Total clusters:       {}",
        format_number_commas(vol_data.total_clusters)
    );
    println!("  Volume size:         {}", format_bytes(volume_size_bytes));
    println!("  Used space:          {}", format_bytes(used_space_bytes));
    println!(
        "  Free space:          {} ({:.1}%)",
        format_bytes(free_space_bytes),
        free_percentage
    );
    println!();
    println!("📁 MFT STRUCTURE");
    println!(
        "  MFT start LCN:        {}",
        format_number_commas(vol_data.mft_start_lcn)
    );
    println!(
        "  MFT size:            {}",
        format_bytes(vol_data.mft_valid_data_length)
    );
    println!("  MFT % of volume:      {mft_percentage:.3}%");
    println!(
        "  Total records:        {}",
        format_number_commas(record_count)
    );
    println!(
        "  In-use records:       {}",
        format_number_commas(in_use_records)
    );
    println!(
        "  Free records:         {}",
        format_number_commas(free_records)
    );
    println!("  Utilization:          {utilization:.1}%");
    println!(
        "  Fragmentation:        {} extent(s) {}",
        extent_count,
        if is_fragmented { "⚠️" } else { "✅" }
    );
    println!();

    if warnings.is_empty() {
        println!("✅ HEALTH STATUS: Good (based on metadata)");
    } else {
        println!("⚠️  HEALTH WARNINGS");
        for warning in &warnings {
            println!("  • {warning}");
        }
    }
    println!();

    // Deep scan: read all MFT records for detailed statistics
    if deep {
        println!(
            "📊 DEEP SCAN: Reading all MFT records{}{}...",
            if no_bitmap { " (bitmap disabled)" } else { "" },
            if unique {
                " (unique FRS mode)"
            } else {
                " (expanding hard links)"
            }
        );
        println!();

        let reader = MftReader::open(drive)
            .with_context(|| format!("Failed to open drive {drive}:"))?
            .with_use_bitmap(!no_bitmap)
            .with_expand_links(!unique); // unique=true means don't expand

        let df = reader.read_all().with_context(|| "Failed to read MFT")?;

        let total_parsed = df.height();

        // Extract statistics from the DataFrame
        let dir_count = df
            .column("is_directory")
            .ok()
            .and_then(|c| c.bool().ok())
            .map_or(0, |b| u64::from(b.sum().unwrap_or(0)));
        let file_count = usize_to_u64(total_parsed) - dir_count;

        // Helper closure to count bool columns
        let count_bool = |name: &str| -> u64 {
            df.column(name)
                .ok()
                .and_then(|c| c.bool().ok())
                .map_or(0, |b| u64::from(b.sum().unwrap_or(0)))
        };

        let hidden_count = count_bool("is_hidden");
        let system_count = count_bool("is_system");
        let compressed_count = count_bool("is_compressed");
        let encrypted_count = count_bool("is_encrypted");
        let sparse_count = count_bool("is_sparse");
        let reparse_count = count_bool("is_reparse");
        let readonly_count = count_bool("is_readonly");
        let archive_count = count_bool("is_archive");

        // Count multi-stream and multi-name files, and total names/streams
        let (multi_stream_count, total_stream_count) = df
            .column("stream_count")
            .ok()
            .and_then(|c| c.u16().ok())
            .map_or((0, 0), |s| {
                let mut multi = 0_u64;
                let mut total = 0_u64;
                for v in s.iter().flatten() {
                    total += u64::from(v);
                    if v > 1 {
                        multi += 1;
                    }
                }
                (multi, total)
            });
        let (multi_name_count, total_name_count) = df
            .column("name_count")
            .ok()
            .and_then(|c| c.u16().ok())
            .map_or((0, 0), |s| {
                let mut multi = 0_u64;
                let mut total = 0_u64;
                for v in s.iter().flatten() {
                    total += u64::from(v);
                    if v > 1 {
                        multi += 1;
                    }
                }
                (multi, total)
            });

        // Calculate the expanded-row estimate (names × streams per record).
        // The reference output expands each record into one row per
        // (name, stream) combination.
        let expanded_row_equivalent_count = df
            .column("name_count")
            .ok()
            .and_then(|c| c.u16().ok())
            .and_then(|names| {
                df.column("stream_count")
                    .ok()
                    .and_then(|c| c.u16().ok())
                    .map(|streams| {
                        names
                            .iter()
                            .zip(streams.iter())
                            .filter_map(|(name_count, stream_count)| {
                                match (name_count, stream_count) {
                                    (Some(names), Some(streams)) => {
                                        Some(u64::from(names) * u64::from(streams))
                                    }
                                    _ => None,
                                }
                            })
                            .sum::<u64>()
                    })
            })
            .unwrap_or(0);

        // Calculate total sizes
        let total_file_size: u64 = df
            .column("size")
            .ok()
            .and_then(|c| c.u64().ok())
            .map_or(0, |s| s.iter().flatten().sum::<u64>());
        let total_allocated_size: u64 = df
            .column("allocated_size")
            .ok()
            .and_then(|c| c.u64().ok())
            .map_or(0, |s| s.iter().flatten().sum::<u64>());

        let slack_space = total_allocated_size.saturating_sub(total_file_size);
        let slack_percentage = if total_allocated_size > 0 {
            (u64_to_f64(slack_space) / u64_to_f64(total_allocated_size)) * 100.0
        } else {
            0.0
        };

        println!("📊 FILE SYSTEM STATISTICS");
        println!(
            "  Parsed records:       {}",
            format_number_commas(usize_to_u64(total_parsed))
        );
        println!(
            "  Directories:          {}",
            format_number_commas(dir_count)
        );
        println!(
            "  Files:                {}",
            format_number_commas(file_count)
        );
        println!();
        println!("🏷️  ATTRIBUTE FLAGS");
        println!(
            "  Hidden:               {}",
            format_number_commas(hidden_count)
        );
        println!(
            "  System:               {}",
            format_number_commas(system_count)
        );
        println!(
            "  Read-only:            {}",
            format_number_commas(readonly_count)
        );
        println!(
            "  Archive:              {}",
            format_number_commas(archive_count)
        );
        println!(
            "  Compressed:           {}",
            format_number_commas(compressed_count)
        );
        println!(
            "  Encrypted:            {}",
            format_number_commas(encrypted_count)
        );
        println!(
            "  Sparse:               {}",
            format_number_commas(sparse_count)
        );
        println!(
            "  Reparse points:       {}",
            format_number_commas(reparse_count)
        );
        println!();
        println!("🔗 EXTENDED ATTRIBUTES");
        println!(
            "  Files with ADS:       {} (Alternate Data Streams)",
            format_number_commas(multi_stream_count)
        );
        println!(
            "  Files with hardlinks: {}",
            format_number_commas(multi_name_count)
        );
        println!(
            "  Total names (links):  {}",
            format_number_commas(total_name_count)
        );
        println!(
            "  Total streams:        {}",
            format_number_commas(total_stream_count)
        );
        println!(
            "  Expanded rows:        {} (names × streams)",
            format_number_commas(expanded_row_equivalent_count)
        );
        println!();
        println!("💾 STORAGE ANALYSIS");
        println!("  Total file size:     {}", format_bytes(total_file_size));
        println!(
            "  Total allocated:     {}",
            format_bytes(total_allocated_size)
        );
        println!(
            "  Slack space:         {} ({:.1}%)",
            format_bytes(slack_space),
            slack_percentage
        );
        println!();

        // =====================================================================
        // WINDOWS COMPARISON SECTION
        // Count files/folders the way Windows defrag does:
        // - Exclude hidden files
        // - Exclude system files
        // - Exclude NTFS metadata (names starting with $)
        // =====================================================================

        // Get column references for filtering
        let is_hidden_col = df.column("is_hidden").ok().and_then(|c| c.bool().ok());
        let is_system_col = df.column("is_system").ok().and_then(|c| c.bool().ok());
        let name_col = df.column("name").ok().and_then(|c| c.str().ok());
        let is_dir_col = df.column("is_directory").ok().and_then(|c| c.bool().ok());

        if let (Some(hidden), Some(system), Some(names), Some(is_dir)) =
            (is_hidden_col, is_system_col, name_col, is_dir_col)
        {
            // Count user-visible entries (not hidden, not system, not $ metadata)
            let mut win_dirs: u64 = 0;
            let mut win_files: u64 = 0;

            for i in 0..df.height() {
                let is_hidden = hidden.get(i).unwrap_or(false);
                let is_system = system.get(i).unwrap_or(false);
                let name = names.get(i).unwrap_or("");
                let is_directory = is_dir.get(i).unwrap_or(false);

                // Skip hidden, system, and NTFS metadata files
                if is_hidden || is_system || name.starts_with('$') {
                    continue;
                }

                if is_directory {
                    win_dirs += 1;
                } else {
                    win_files += 1;
                }
            }

            let win_total = win_dirs + win_files;

            println!("🪟 WINDOWS COMPARISON");
            println!("  (Excludes hidden, system, and NTFS metadata files)");
            println!("  Folders:              {}", format_number_commas(win_dirs));
            println!(
                "  Files:                {}",
                format_number_commas(win_files)
            );
            println!(
                "  Total movable:        {}",
                format_number_commas(win_total)
            );
            println!();
        }

        let deep_elapsed = start_time.elapsed();
        println!(
            "⏱️  Deep scan completed in {}",
            format_duration(deep_elapsed)
        );
    } else {
        println!("💡 TIP: Use --deep for detailed file statistics (dirs, files, attributes).");
        println!();
        println!("⏱️  Completed in {}", format_duration(elapsed));
    }

    println!("═══════════════════════════════════════════════════════════════");

    Ok(())
}

/// Lightweight `info` summary for `--format json` / `--format table`.
///
/// Captures the metadata-only metrics (no full-MFT scan); field names are
/// stable JSON keys, byte counters keep a `_bytes` suffix.
#[cfg(windows)]
#[derive(serde::Serialize)]
struct InfoReport {
    /// Drive letter (e.g. `"C"`).
    drive: String,
    /// Storage kind: `"NVMe"`, `"SSD"`, `"HDD"`, or `"Unknown"`.
    drive_type: String,
    /// Whether a `--deep` scan was requested (deep stats are not in this view).
    deep: bool,
    /// Volume sector size in bytes.
    bytes_per_sector: u64,
    /// Volume cluster size in bytes.
    bytes_per_cluster: u64,
    /// `$MFT` file-record-segment size in bytes.
    bytes_per_record: u64,
    /// Total clusters on the volume.
    total_clusters: u64,
    /// Total volume capacity in bytes.
    volume_size_bytes: u64,
    /// Used capacity in bytes.
    used_bytes: u64,
    /// Free capacity in bytes.
    free_bytes: u64,
    /// Free capacity percentage in `[0, 100]`.
    free_pct: f64,
    /// Starting LCN of the `$MFT`.
    mft_start_lcn: u64,
    /// `$MFT` valid data length in bytes.
    mft_size_bytes: u64,
    /// `$MFT` size as a percentage of the volume.
    mft_pct_of_volume: f64,
    /// Total allocated MFT records (size / record size).
    total_records: u64,
    /// In-use records per the `$MFT::$BITMAP`.
    in_use_records: u64,
    /// Free records per the `$MFT::$BITMAP`.
    free_records: u64,
    /// MFT utilization percentage in `[0, 100]`.
    utilization_pct: f64,
    /// `$MFT` fragment (extent) count.
    extent_count: u64,
    /// Whether the `$MFT` spans more than one extent.
    fragmented: bool,
    /// Metadata-only health warnings.
    warnings: Vec<String>,
    /// Probe wall-clock duration in milliseconds.
    elapsed_ms: u64,
}

/// Emit the lightweight `info` summary as pretty-printed JSON on stdout.
///
/// # Errors
/// Returns an error only if JSON serialisation fails (effectively never).
#[cfg(windows)]
fn print_info_json(report: &InfoReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report).context("serialising info to JSON")?;
    println!("{json}");
    Ok(())
}

/// Print the lightweight `info` summary as a complete aligned key/value table.
///
/// Carries the same metadata as the human report (volume geometry + MFT
/// structure), just in a flat parseable layout — no section banners.
#[cfg(windows)]
fn print_info_table(report: &InfoReport) {
    let frag = if report.fragmented {
        format!("{} extents (fragmented)", report.extent_count)
    } else {
        format!("{} extent (contiguous)", report.extent_count)
    };
    let rows: [(&str, String); 17] = [
        (
            "Drive",
            format!("{}: ({})", report.drive, report.drive_type),
        ),
        (
            "Bytes per sector",
            format_number_commas(report.bytes_per_sector),
        ),
        (
            "Bytes per cluster",
            format_number_commas(report.bytes_per_cluster),
        ),
        (
            "Bytes per MFT record",
            format_number_commas(report.bytes_per_record),
        ),
        (
            "Total clusters",
            format_number_commas(report.total_clusters),
        ),
        ("Volume size", format_bytes(report.volume_size_bytes)),
        ("Used", format_bytes(report.used_bytes)),
        (
            "Free",
            format!(
                "{} ({:.1}%)",
                format_bytes(report.free_bytes),
                report.free_pct
            ),
        ),
        ("MFT start LCN", format_number_commas(report.mft_start_lcn)),
        ("MFT size", format_bytes(report.mft_size_bytes)),
        (
            "MFT % of volume",
            format!("{:.3}%", report.mft_pct_of_volume),
        ),
        ("Total records", format_number_commas(report.total_records)),
        (
            "In-use records",
            format_number_commas(report.in_use_records),
        ),
        ("Free records", format_number_commas(report.free_records)),
        ("Utilization", format!("{:.1}%", report.utilization_pct)),
        ("Fragmentation", frag),
        ("Probe time", format!("{} ms", report.elapsed_ms)),
    ];
    for (key, value) in &rows {
        println!("{key:<22} {value}");
    }
    for warning in &report.warnings {
        println!("⚠️  {warning}");
    }
}
