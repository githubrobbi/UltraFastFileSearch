// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Benchmark-oriented `DataFrame` timing entrypoints.

#[cfg(windows)]
use std::time::Instant;

#[cfg(windows)]
use tracing::{debug, info, warn};
use uffs_polars::DataFrame;

#[cfg(windows)]
use super::PhaseTimings;
#[cfg(windows)]
use super::benchmark::{
    MftMetrics, build_benchmark_result, build_drive_characteristics,
    estimate_combined_phase_timings,
};
use super::{BenchmarkResult, MftReader};
#[cfg(not(windows))]
use crate::error::MftError;
use crate::error::Result;
#[cfg(windows)]
use crate::index::{u64_to_f64, usize_to_f64};

impl MftReader {
    /// Read MFT with detailed phase timing for benchmarking.
    ///
    /// This method measures each phase of MFT reading separately:
    /// - Open: Volume handle and metadata retrieval
    /// - Read: Disk I/O (reading chunks)
    /// - Parse: Record parsing (parallel)
    /// - Merge: Extension record merging
    /// - `DataFrame` build: Converting parsed records to `DataFrame`
    ///
    /// # Arguments
    ///
    /// * `skip_df_build` - If true, skip `DataFrame` building (measure I/O +
    ///   parse only)
    ///
    /// # Returns
    ///
    /// A tuple of (optional `DataFrame`, `BenchmarkResult`).
    ///
    /// # Errors
    ///
    /// Returns an error if MFT reading fails.
    #[cfg(windows)]
    pub fn read_with_timing(
        &self,
        skip_df_build: bool,
    ) -> Result<(Option<DataFrame>, BenchmarkResult)> {
        self.read_mft_with_timing_internal(skip_df_build)
    }

    /// Read MFT with timing (non-Windows stub).
    ///
    /// # Errors
    ///
    /// Always returns `MftError::PlatformNotSupported` on non-Windows
    /// platforms.
    #[cfg(not(windows))]
    pub const fn read_with_timing(
        &self,
        _skip_df_build: bool,
    ) -> Result<(Option<DataFrame>, BenchmarkResult)> {
        let _: &Self = self; // API parity with Windows impl which uses self
        Err(MftError::PlatformNotSupported)
    }

    /// Internal implementation for MFT reading with detailed phase timing.
    ///
    /// This method measures each phase separately for benchmarking purposes.
    #[cfg(windows)]
    fn read_mft_with_timing_internal(
        &self,
        skip_df_build: bool,
    ) -> Result<(Option<DataFrame>, BenchmarkResult)> {
        let total_start = Instant::now();

        let phase1 = self.benchmark_phase1_open()?;
        let Phase1Snapshot {
            extent_map,
            bitmap,
            drive_type,
            characteristics,
            mft_size_bytes,
            open_ms,
        } = phase1;

        let phase23 = self.benchmark_phase23_read_parse(extent_map, bitmap, drive_type)?;
        let ReadParseSnapshot {
            parsed_columns,
            read_ms,
            parse_ms,
            merge_ms,
            records_parsed,
        } = phase23;

        // Phase 4: DataFrame build (optional)
        let (df, df_build_ms) = self.benchmark_phase4_dataframe(parsed_columns, skip_df_build)?;

        // Saturating conversion: a benchmark run is bounded by wall-clock
        // wait time, never approaching u64 milliseconds (~584 million years).
        let total_ms = u64::try_from(total_start.elapsed().as_millis()).unwrap_or(u64::MAX);

        let (throughput_mb_s, records_per_sec) =
            compute_benchmark_throughput(total_ms, mft_size_bytes, records_parsed);

        let timings = PhaseTimings {
            open_ms,
            read_ms,
            parse_ms,
            merge_ms,
            df_build_ms,
            index_build_ms: 0,  // Not applicable for DataFrame path
            tree_metrics_ms: 0, // Not applicable for DataFrame path
            total_ms,
        };

        let result = build_benchmark_result(
            timings,
            characteristics,
            records_parsed,
            throughput_mb_s,
            records_per_sec,
        );

        info!(
            total_ms,
            throughput_mb_s = format!("{:.1}", throughput_mb_s),
            records_per_sec = format!("{:.0}", records_per_sec),
            "📊 Benchmark: Complete"
        );

        Ok((df, result))
    }

    /// Phase 2 + 3 of [`Self::read_mft_with_timing_internal`].
    ///
    /// Drives [`crate::io::ParallelMftReader`] over the MFT, optionally
    /// adds parent-directory placeholders, and returns the resulting
    /// [`crate::io::ParsedColumns`] alongside an estimate of the
    /// read / parse / merge breakdown.
    #[cfg(windows)]
    fn benchmark_phase23_read_parse(
        &self,
        extent_map: crate::io::MftExtentMap,
        bitmap: Option<crate::platform::MftBitmap>,
        drive_type: crate::platform::DriveType,
    ) -> Result<ReadParseSnapshot> {
        use crate::io::ParallelMftReader;

        let read_parse_start = Instant::now();
        let parallel_reader = ParallelMftReader::new_optimized(extent_map, bitmap, drive_type);
        let handle = self.require_handle()?.raw_handle();

        let mut parsed_columns = parallel_reader.read_all_parallel_to_columns::<fn(u64, u64)>(
            handle,
            self.merge_extensions,
            self.expand_links,
            None,
        )?;

        if self.add_placeholders {
            let placeholders_added = parsed_columns.add_missing_parent_placeholders();
            if placeholders_added > 0 {
                debug!(
                    placeholders_added,
                    "Added placeholder records for path resolution"
                );
            }
        }

        let read_parse_ms =
            u64::try_from(read_parse_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let records_parsed = parsed_columns.len();

        let (read_ms, parse_ms, merge_ms) =
            estimate_combined_phase_timings(drive_type, read_parse_ms);

        info!(
            records_parsed,
            read_parse_ms, "📊 Benchmark: Read + Parse complete"
        );

        Ok(ReadParseSnapshot {
            parsed_columns,
            read_ms,
            parse_ms,
            merge_ms,
            records_parsed,
        })
    }

    /// Phase 4 of [`Self::read_mft_with_timing_internal`].
    ///
    /// Builds the optional [`DataFrame`] from `parsed_columns` (`SoA` path),
    /// timing the build itself.  When `skip_df_build` is `true` the call is
    /// a no-op and `df_build_ms` is reported as 0.
    #[cfg(windows)]
    fn benchmark_phase4_dataframe(
        &self,
        parsed_columns: crate::io::ParsedColumns,
        skip_df_build: bool,
    ) -> Result<(Option<DataFrame>, u64)> {
        let _: &Self = self; // method form keeps the call site symmetric with phase1/phase23.
        if skip_df_build {
            return Ok((None, 0));
        }

        let df_start = Instant::now();
        let df = Self::build_dataframe_from_columns(parsed_columns)?;
        let df_ms = u64::try_from(df_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        info!(
            df_build_ms = df_ms,
            "📊 Benchmark: DataFrame build complete (SoA path)"
        );
        Ok((Some(df), df_ms))
    }

    /// Phase 1 of [`Self::read_mft_with_timing_internal`].
    ///
    /// Opens the volume metadata, materialises the MFT extent map and
    /// optional bitmap, generates the chunk plan to size the workload,
    /// and assembles a [`Phase1Snapshot`] for the later phases.
    ///
    /// Returns the elapsed open-phase milliseconds via
    /// [`Phase1Snapshot::open_ms`].
    #[cfg(windows)]
    fn benchmark_phase1_open(&self) -> Result<Phase1Snapshot> {
        use crate::io::{MftExtentMap, generate_read_chunks};
        use crate::platform::detect_drive_type;

        let open_start = Instant::now();
        let record_size = self.require_handle()?.file_record_size();
        let volume_data = self.require_handle()?.volume_data();
        let drive_type = detect_drive_type(self.volume);
        let chunk_size = drive_type.optimal_chunk_size();

        let extents = self
            .require_handle()?
            .get_mft_extents()
            .unwrap_or_else(|err| {
                warn!(error = ?err, "Failed to get MFT extents, using fallback");
                vec![crate::platform::MftExtent {
                    vcn: 0,
                    cluster_count: volume_data.mft_valid_data_length
                        / u64::from(volume_data.bytes_per_cluster),
                    lcn: crate::platform::Lcn::new(volume_data.mft_start_lcn.cast_signed()),
                }]
            });

        let extent_map =
            MftExtentMap::new(extents.clone(), volume_data.bytes_per_cluster, record_size);
        let total_records = extent_map.total_records();
        let mft_size_bytes = total_records * u64::from(record_size);

        let bitmap = self.require_handle()?.get_mft_bitmap().ok();
        let in_use_records = bitmap
            .as_ref()
            .map(|bm| u64::try_from(bm.count_in_use()).unwrap_or(u64::MAX));

        let chunks = generate_read_chunks(&extent_map, bitmap.as_ref(), chunk_size);
        let chunk_count = chunks.len();

        let open_ms = u64::try_from(open_start.elapsed().as_millis()).unwrap_or(u64::MAX);

        let characteristics = build_drive_characteristics(
            self.volume,
            drive_type,
            MftMetrics {
                size_bytes: mft_size_bytes,
                total_records,
                in_use_records,
                extent_count: extents.len(),
                bytes_per_record: record_size,
            },
            chunk_size,
            chunk_count,
        );

        info!(
            volume = %self.volume,
            drive_type = ?drive_type,
            total_records,
            mft_size_mb = mft_size_bytes / (1024 * 1024),
            extents = extents.len(),
            chunks = chunk_count,
            "📊 Benchmark: MFT characteristics"
        );

        Ok(Phase1Snapshot {
            extent_map,
            bitmap,
            drive_type,
            characteristics,
            mft_size_bytes,
            open_ms,
        })
    }
}

/// Output of [`MftReader::benchmark_phase1_open`].
///
/// Bundles the extent map, optional bitmap, detected drive type, and the
/// pre-computed [`crate::reader::DriveCharacteristics`] / `mft_size_bytes` /
/// `open_ms` so the benchmark orchestrator can move them into the read+parse
/// phase without juggling several positional values.
#[cfg(windows)]
struct Phase1Snapshot {
    /// MFT extent map handed off to [`crate::io::ParallelMftReader`].
    extent_map: crate::io::MftExtentMap,
    /// Optional bitmap for skip-optimised chunking.
    bitmap: Option<crate::platform::MftBitmap>,
    /// Detected drive type (HDD/SSD/NVMe/Unknown).
    drive_type: crate::platform::DriveType,
    /// Drive characteristics used in the final benchmark report.
    characteristics: super::DriveCharacteristics,
    /// Total MFT byte size used for throughput calculation.
    mft_size_bytes: u64,
    /// Wall-clock cost of phase 1 in milliseconds.
    open_ms: u64,
}

/// Output of [`MftReader::benchmark_phase23_read_parse`].
///
/// Bundles the parsed columns with the per-phase timing estimates and the
/// final record count so the benchmark orchestrator can move them into
/// phase 4 / the throughput summary in a single binding.
#[cfg(windows)]
struct ReadParseSnapshot {
    /// Parsed MFT records in `SoA` layout, ready for `DataFrame` build.
    parsed_columns: crate::io::ParsedColumns,
    /// Estimated read-phase wall clock in milliseconds.
    read_ms: u64,
    /// Estimated parse-phase wall clock in milliseconds.
    parse_ms: u64,
    /// Estimated merge-phase wall clock in milliseconds.
    merge_ms: u64,
    /// Final number of parsed records.
    records_parsed: usize,
}

/// Compute throughput (MiB/s) and records-per-second for the benchmark
/// summary, returning `(0.0, 0.0)` if `total_ms` is zero.
#[cfg(windows)]
#[expect(
    clippy::float_arithmetic,
    reason = "benchmark telemetry: throughput / records-per-sec require float division"
)]
fn compute_benchmark_throughput(
    total_ms: u64,
    mft_size_bytes: u64,
    records_parsed: usize,
) -> (f64, f64) {
    let total_secs = u64_to_f64(total_ms) / 1000.0_f64;
    if total_secs <= 0.0_f64 {
        return (0.0_f64, 0.0_f64);
    }
    let throughput_mb_s = (u64_to_f64(mft_size_bytes) / (1024.0_f64 * 1024.0_f64)) / total_secs;
    let records_per_sec = usize_to_f64(records_parsed) / total_secs;
    (throughput_mb_s, records_per_sec)
}
