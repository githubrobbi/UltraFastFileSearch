// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Persistence helpers for parquet and raw MFT save/load paths.
//!
//! Windows-specific capture implementations (streaming save and IOCP capture)
//! live in `persistence_capture.rs`.

use std::path::Path;

use uffs_polars::{DataFrame, ParquetReader, ParquetWriter, SerReader as _};

use super::MftReader;
use crate::error::{MftError, Result};
use crate::index::bytes_to_mb_f64;

impl MftReader {
    /// Save a `DataFrame` to Parquet format.
    ///
    /// Parquet provides excellent compression and fast loading times.
    ///
    /// # Arguments
    ///
    /// * `df` - The `DataFrame` to save
    /// * `path` - Output file path
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save_parquet<P: AsRef<Path>>(df: &mut DataFrame, path: P) -> Result<()> {
        let file = std::fs::File::create(path.as_ref())?;
        ParquetWriter::new(file)
            .finish(df)
            .map_err(|err| MftError::Parquet(err.to_string()))?;
        Ok(())
    }

    /// Load a `DataFrame` from Parquet format.
    ///
    /// # Arguments
    ///
    /// * `path` - Input file path
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or is invalid.
    pub fn load_parquet<P: AsRef<Path>>(path: P) -> Result<DataFrame> {
        let file = std::fs::File::open(path.as_ref())?;
        let df = ParquetReader::new(file)
            .finish()
            .map_err(|err| MftError::Parquet(err.to_string()))?;
        Ok(df)
    }

    /// Read the entire MFT as raw bytes.
    ///
    /// This reads all MFT records as contiguous raw bytes, handling fragmented
    /// MFTs by reassembling extents in order. The result can be saved with
    /// [`save_raw_mft`](crate::raw::save_raw_mft) for offline analysis.
    ///
    /// # Returns
    ///
    /// A tuple of (raw bytes, record size).
    ///
    /// # Errors
    ///
    /// Returns an error if MFT reading fails.
    #[cfg(windows)]
    pub fn read_raw(&self) -> Result<(Vec<u8>, u32)> {
        self.read_raw_internal()
    }

    /// Read raw MFT (non-Windows stub).
    ///
    /// # Errors
    ///
    /// Always returns `MftError::PlatformNotSupported` on non-Windows
    /// platforms.
    #[cfg(not(windows))]
    pub const fn read_raw(&self) -> Result<(Vec<u8>, u32)> {
        let _: &Self = self; // API parity with Windows impl which uses self
        Err(MftError::PlatformNotSupported)
    }

    /// Internal raw MFT reading implementation.
    ///
    /// Uses the shared `ParallelMftReader` infrastructure for proper chunk
    /// handling, sector alignment, and dynamic buffer sizing.
    #[cfg(windows)]
    fn read_raw_internal(&self) -> Result<(Vec<u8>, u32)> {
        use crate::io::{MftExtentMap, ParallelMftReader, generate_read_chunks};
        use crate::platform::detect_drive_type;

        let vol_handle = self.require_handle()?;
        let record_size = vol_handle.file_record_size();
        let volume_data = vol_handle.volume_data();

        let extents = vol_handle.get_mft_extents().unwrap_or_else(|_| {
            vec![crate::platform::MftExtent {
                vcn: 0,
                cluster_count: volume_data.mft_valid_data_length
                    / u64::from(volume_data.bytes_per_cluster),
                lcn: crate::platform::Lcn::new(volume_data.mft_start_lcn.cast_signed()),
            }]
        });

        let extent_map = MftExtentMap::new(extents, volume_data.bytes_per_cluster, record_size);
        let total_records = extent_map.total_records();
        let total_records_usize = usize::try_from(total_records).map_err(|err| {
            MftError::InvalidData(format!(
                "save_raw_mft: MFT record count {total_records} exceeds usize::MAX ({err})"
            ))
        })?;
        let total_size = total_records_usize * record_size as usize;
        let mut output = vec![0_u8; total_size];

        let drive_type = detect_drive_type(self.volume);
        let parallel_reader =
            ParallelMftReader::new_optimized(extent_map.clone(), None, drive_type);
        let chunks = generate_read_chunks(&extent_map, None, parallel_reader.chunk_size);
        let handle = vol_handle.raw_handle();

        for chunk in chunks {
            let data = parallel_reader.read_chunk(handle, &chunk, record_size)?;
            let output_offset = usize::try_from(chunk.start_frs).map_err(|err| {
                MftError::InvalidData(format!(
                    "save_raw_mft: chunk start_frs {} exceeds usize::MAX ({err})",
                    chunk.start_frs
                ))
            })? * record_size as usize;
            let copy_size = data.len().min(total_size - output_offset);
            let Some(dest) = output.get_mut(output_offset..output_offset + copy_size) else {
                return Err(MftError::InvalidData(format!(
                    "save_raw_mft: chunk at frs {} size {copy_size} exceeds buffer {total_size}",
                    chunk.start_frs
                )));
            };
            let Some(src) = data.get(..copy_size) else {
                return Err(MftError::InvalidData(format!(
                    "save_raw_mft: chunk at frs {} read-back shorter than expected {copy_size}",
                    chunk.start_frs
                )));
            };
            dest.copy_from_slice(src);
        }

        Ok((output, record_size))
    }

    /// Read raw MFT and save to file using streaming I/O.
    ///
    /// This method uses streaming I/O to avoid buffering the entire MFT in
    /// memory. Each chunk is read from disk and immediately written to the
    /// output file, enabling efficient saves of large MFTs (10+ GB).
    ///
    /// # Errors
    ///
    /// Returns an error if raw MFT reading or writing the output file fails.
    #[cfg(windows)]
    pub fn save_raw_to_file<P: AsRef<Path>>(
        &self,
        path: P,
        options: &crate::raw::SaveRawOptions,
    ) -> Result<crate::raw::RawMftHeader> {
        self.save_raw_streaming(path, options)
    }
    /// Save raw MFT to file (non-Windows stub).
    ///
    /// # Errors
    ///
    /// Always returns `MftError::PlatformNotSupported` on non-Windows
    /// platforms.
    #[cfg(not(windows))]
    pub fn save_raw_to_file<P: AsRef<Path>>(
        &self,
        _path: P,
        _options: &crate::raw::SaveRawOptions,
    ) -> Result<crate::raw::RawMftHeader> {
        let _: &Self = self; // API parity with Windows impl which uses self
        Err(MftError::PlatformNotSupported)
    }

    /// Load raw MFT from file and parse to `DataFrame`.
    ///
    /// # Errors
    ///
    /// Returns an error if the raw file cannot be loaded or parsed.
    pub fn load_raw_to_dataframe<P: AsRef<Path>>(path: P) -> Result<DataFrame> {
        Self::load_raw_to_dataframe_with_options(path, &crate::raw::LoadRawOptions::default())
    }

    /// Load raw MFT from file and convert to `DataFrame` with custom options.
    ///
    /// # Errors
    ///
    /// Returns an error if the raw file cannot be loaded, fixed up, parsed, or
    /// converted into a `DataFrame`.
    pub fn load_raw_to_dataframe_with_options<P: AsRef<Path>>(
        path: P,
        options: &crate::raw::LoadRawOptions,
    ) -> Result<DataFrame> {
        use crate::parse::{MftRecordMerger, apply_fixup, parse_record_full};

        let raw = crate::raw::load_raw_mft(path, options)?;
        let mut merger =
            MftRecordMerger::with_capacity(crate::index::frs_to_usize(raw.header.record_count));

        for (frs, record_data) in raw.iter_records() {
            let mut record_buf = record_data.to_vec();
            if !apply_fixup(&mut record_buf) {
                continue;
            }
            merger.add_result(parse_record_full(&record_buf, frs));
        }

        let parsed_columns = merger.merge_into_columns(true);
        Self::build_dataframe_from_columns(parsed_columns)
    }

    /// Load raw MFT from file and build `MftIndex`.
    ///
    /// # Errors
    ///
    /// Returns an error if the raw file cannot be loaded or parsed into an
    /// index.
    pub fn load_raw_to_index<P: AsRef<Path>>(path: P) -> Result<crate::index::MftIndex> {
        Self::load_raw_to_index_with_options(path, &crate::raw::LoadRawOptions::default())
    }

    /// Load raw MFT from file and build `MftIndex` with custom options.
    ///
    /// Auto-detects file format:
    /// - **UFFS-IOCP**: IOCP capture format (replays Windows IOCP completion
    ///   order)
    /// - **UFFS-MFT**: Standard compressed format
    /// - **Raw NTFS**: Uncompressed MFT bytes (FILE magic)
    ///
    /// # Errors
    ///
    /// Returns an error if the raw file cannot be loaded or if record parsing
    /// or index construction fails.
    // cognitive_complexity fires in `--lib` but not `--tests`, so `#[expect]` is
    // unreliable — use `#[allow]` and suppress the meta-lint.
    #[expect(
        clippy::allow_attributes,
        reason = "cognitive_complexity differs between lib and test compilation"
    )]
    #[allow(
        clippy::cognitive_complexity,
        reason = "parsing logic with forensic/sequential/parallel branches is inherently complex"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "parsing logic with forensic/sequential/parallel branches is inherently complex"
    )]
    pub fn load_raw_to_index_with_options<P: AsRef<Path>>(
        path: P,
        options: &crate::raw::LoadRawOptions,
    ) -> Result<crate::index::MftIndex> {
        use std::time::Instant;

        use tracing::info;

        use crate::index::MftIndex;
        use crate::parse::{
            MftRecordMerger, ParseOptions, ParseResult, apply_fixup, parse_record_forensic,
            parse_record_full,
        };

        let profile = std::env::var_os("UFFS_CACHE_PROFILE").is_some();
        let path_ref = path.as_ref();

        // Check for IOCP capture format first
        if crate::raw_iocp::is_iocp_capture(path_ref)? {
            info!(
                path = %path_ref.display(),
                "📼 Detected IOCP capture format - replaying Windows IOCP order"
            );
            return Self::load_iocp_capture_to_index(path_ref, options);
        }

        let t_read = Instant::now();
        let mut raw = crate::raw::load_raw_mft(path_ref, options)?;
        let read_ms = t_read.elapsed().as_millis();
        let capacity = usize::try_from(raw.header.record_count).unwrap_or(0);
        let total_records_in_file = capacity;

        if profile {
            let mft_mb = bytes_to_mb_f64(raw.header.original_size);
            tracing::debug!(
                target: "cache_profile",
                read_ms = %read_ms,
                mft_mb = %format_args!("{mft_mb:.1}"),
                "mft_read"
            );
        }
        let parse_options = if options.forensic {
            ParseOptions::FORENSIC
        } else {
            ParseOptions::DEFAULT
        };

        if options.forensic {
            let mut parsed_records = Vec::with_capacity(capacity);
            let mut records_examined: u64 = 0;
            let mut fixup_success: u64 = 0;
            let mut fixup_failed: u64 = 0;
            let mut base_records: u64 = 0;

            for (frs, record_data) in raw.iter_records() {
                records_examined += 1;
                let mut record_buf = record_data.to_vec();
                let fixup_ok = apply_fixup(&mut record_buf);
                if fixup_ok {
                    fixup_success += 1;
                } else {
                    fixup_failed += 1;
                }
                let result = parse_record_forensic(&record_buf, frs, parse_options, !fixup_ok);
                if let ParseResult::Base(parsed) = result {
                    base_records += 1;
                    parsed_records.push(parsed);
                }
            }

            info!("📊 OFFLINE PATH PARSE DIAGNOSTICS (Forensic Mode)");
            info!(
                total_records_in_file,
                records_examined,
                fixup_success,
                fixup_failed,
                base_records_parsed = base_records,
                final_record_count = parsed_records.len(),
                "Offline parse pipeline summary"
            );

            let record_count = parsed_records.len();
            let t_build = Instant::now();
            let mut index = MftIndex::from_parsed_records(raw.header.volume_letter, parsed_records);
            // v3+ .bin files carry the reserved-cluster bytes for the root
            // `tree_allocated` adjustment; restore it so an offline load
            // reproduces the live root size-on-disk (0 for older files).
            index.reserved_allocated_bytes = raw.header.reserved_allocated_bytes;
            if profile {
                let build_ms = t_build.elapsed().as_millis();
                tracing::debug!(
                    target: "cache_profile",
                    parse_ms = 0,
                    record_count,
                    mode = "forensic",
                    build_ms = %build_ms,
                    "mft_parse_build"
                );
            }
            Ok(index)
        } else {
            let record_size = raw.header.record_size as usize;
            let single_thread = std::env::var("UFFS_SINGLE_THREAD").is_ok();
            let parse_start = Instant::now();

            if single_thread {
                let mut merger = MftRecordMerger::with_capacity(capacity);
                let mut fixup_success: u64 = 0;
                let mut fixup_failed: u64 = 0;
                let mut base_records: u64 = 0;
                let mut extension_records: u64 = 0;
                let mut skip_records: u64 = 0;

                for (frs, record_data) in raw.iter_records() {
                    let mut record_buf = record_data.to_vec();
                    if !apply_fixup(&mut record_buf) {
                        fixup_failed += 1;
                        continue;
                    }
                    fixup_success += 1;
                    let result = parse_record_full(&record_buf, frs);
                    match &result {
                        ParseResult::Base(_) => base_records += 1,
                        ParseResult::Extension(_) => extension_records += 1,
                        ParseResult::Skip => skip_records += 1,
                    }
                    merger.add_result(result);
                }

                let parsed_records = merger.merge();
                info!(
                    total_records_in_file,
                    parse_ms = parse_start.elapsed().as_millis(),
                    fixup_success,
                    fixup_failed,
                    base_records,
                    extension_records,
                    skip_records,
                    final_merged_count = parsed_records.len(),
                    "Offline parse complete (sequential)"
                );

                let parse_ms = parse_start.elapsed().as_millis();
                let record_count = parsed_records.len();
                let t_build = Instant::now();
                let mut index =
                    MftIndex::from_parsed_records(raw.header.volume_letter, parsed_records);
                index.reserved_allocated_bytes = raw.header.reserved_allocated_bytes;
                if profile {
                    let build_ms = t_build.elapsed().as_millis();
                    tracing::debug!(
                        target: "cache_profile",
                        parse_ms = %parse_ms,
                        record_count,
                        mode = "sequential",
                        build_ms = %build_ms,
                        "mft_parse_build"
                    );
                }
                Ok(index)
            } else {
                use rayon::prelude::*;

                let records_per_chunk = 4096_usize;
                let bytes_per_chunk = records_per_chunk * record_size;
                let buffer_slice = raw.data.as_mut_slice();

                let results: Vec<(Vec<ParseResult>, u64, u64, u64, u64, u64)> = buffer_slice
                    .par_chunks_mut(bytes_per_chunk)
                    .enumerate()
                    .map(|(chunk_idx, chunk)| {
                        let mut results = Vec::new();
                        let mut fixup_ok = 0_u64;
                        let mut fixup_fail = 0_u64;
                        let mut bases = 0_u64;
                        let mut extensions = 0_u64;
                        let mut skips = 0_u64;

                        let start_frs = chunk_idx * records_per_chunk;
                        let records_in_chunk = chunk.len() / record_size;

                        for i in 0..records_in_chunk {
                            let offset = i * record_size;
                            let Some(record_slice) = chunk.get_mut(offset..offset + record_size)
                            else {
                                continue;
                            };

                            if !apply_fixup(record_slice) {
                                fixup_fail += 1;
                                continue;
                            }
                            fixup_ok += 1;

                            let frs = (start_frs + i) as u64;
                            let result = parse_record_full(record_slice, frs);
                            match &result {
                                ParseResult::Base(_) => bases += 1,
                                ParseResult::Extension(_) => extensions += 1,
                                ParseResult::Skip => skips += 1,
                            }
                            if !matches!(result, ParseResult::Skip) {
                                results.push(result);
                            }
                        }

                        (results, fixup_ok, fixup_fail, bases, extensions, skips)
                    })
                    .collect();

                let mut merger = MftRecordMerger::with_capacity(capacity);
                let mut fixup_success: u64 = 0;
                let mut fixup_failed: u64 = 0;
                let mut base_records: u64 = 0;
                let mut extension_records: u64 = 0;
                let mut skip_records: u64 = 0;

                for (chunk_results, ok, fail, bases, exts, skips) in results {
                    fixup_success += ok;
                    fixup_failed += fail;
                    base_records += bases;
                    extension_records += exts;
                    skip_records += skips;
                    for result in chunk_results {
                        merger.add_result(result);
                    }
                }

                let parsed_records = merger.merge();
                info!(
                    total_records_in_file,
                    parse_ms = parse_start.elapsed().as_millis(),
                    fixup_success,
                    fixup_failed,
                    base_records,
                    extension_records,
                    skip_records,
                    final_merged_count = parsed_records.len(),
                    threads = rayon::current_num_threads(),
                    "Offline parse complete (parallel)"
                );

                let parse_ms = parse_start.elapsed().as_millis();
                let record_count = parsed_records.len();
                let t_build = Instant::now();
                let mut index =
                    MftIndex::from_parsed_records(raw.header.volume_letter, parsed_records);
                index.reserved_allocated_bytes = raw.header.reserved_allocated_bytes;
                if profile {
                    let build_ms = t_build.elapsed().as_millis();
                    tracing::debug!(
                        target: "cache_profile",
                        parse_ms = %parse_ms,
                        record_count,
                        mode = "parallel",
                        threads = rayon::current_num_threads(),
                        build_ms = %build_ms,
                        "mft_parse_build"
                    );
                }
                Ok(index)
            }
        }
    }

    /// Load IOCP capture and build `MftIndex` by replaying chunks in captured
    /// order.
    ///
    /// This processes MFT chunks in the exact order Windows IOCP delivered
    /// them, enabling 100% accurate reproduction of LIVE parsing behavior
    /// on any platform.
    ///
    /// # Errors
    ///
    /// Returns an error if the capture file cannot be loaded or parsing fails.
    /// Load IOCP capture and build `MftIndex` using parallel parsing.
    ///
    /// This mirrors the Windows LIVE pipeline exactly:
    /// 1. Load chunks in IOCP completion order
    /// 2. Parse each chunk in parallel using rayon (non-deterministic thread
    ///    order)
    /// 3. Merge all parse results through `MftRecordMerger`
    ///
    /// The parallel parsing is critical for reproducing Windows LIVE behavior,
    /// as it introduces the same non-deterministic ordering that can expose
    /// merger edge cases.
    fn load_iocp_capture_to_index(
        path: &Path,
        options: &crate::raw::LoadRawOptions,
    ) -> Result<crate::index::MftIndex> {
        use std::time::Instant;

        use rayon::prelude::*;
        use tracing::info;

        use crate::index::MftIndex;
        use crate::parse::{MftRecordMerger, ParseResult, apply_fixup, parse_record_full};
        use crate::raw_iocp::load_iocp_capture;

        let load_start = Instant::now();
        let capture = load_iocp_capture(path)?;
        let header = &capture.header;
        let record_size = header.record_size as usize;
        let volume = options.volume_letter.unwrap_or(header.volume_letter);

        info!(
            path = %path.display(),
            chunks = header.chunk_count,
            total_records = header.total_records,
            volume = %volume,
            concurrency = header.concurrency,
            compressed = header.is_compressed(),
            "📼 Loading IOCP capture (parallel replay)"
        );

        let parse_start = Instant::now();
        let capacity = crate::index::frs_to_usize(header.total_records);

        // Collect all chunks with their data for parallel processing
        // This mimics the Windows LIVE pipelined reader's behavior
        let chunks_data: Vec<_> = capture.iter_chunks().collect();

        // Parse all chunks in parallel using rayon - this replicates the
        // non-deterministic ordering of Windows LIVE parallel parsing
        let parse_results: Vec<ParseResult> = chunks_data
            .par_iter()
            .flat_map(|(chunk, data)| {
                let num_records = data.len() / record_size;
                let mut results = Vec::with_capacity(num_records);

                for i in 0..num_records {
                    let offset = i * record_size;
                    if let Some(record_slice) = data.get(offset..offset + record_size) {
                        let mut record_buf = record_slice.to_vec();
                        if apply_fixup(&mut record_buf) {
                            let frs = chunk.start_frs + i as u64;
                            results.push(parse_record_full(&record_buf, frs));
                        }
                    }
                }
                results
            })
            .collect();

        let records_parsed = parse_results.len();
        info!(
            parse_results = records_parsed,
            "✅ Parallel parsing complete"
        );

        // Merge results using MftRecordMerger (single-threaded, as in LIVE)
        let mut merger = MftRecordMerger::with_capacity(capacity);
        for result in parse_results {
            merger.add_result(result);
        }
        let parsed_records = merger.merge();

        let parse_ms = parse_start.elapsed().as_millis();

        info!(
            load_ms = load_start.elapsed().as_millis(),
            parse_ms,
            chunks_processed = header.chunk_count,
            records_parsed,
            final_merged_count = parsed_records.len(),
            "✅ IOCP capture parallel replay complete"
        );

        // from_parsed_records already calls compute_tree_metrics +
        // build_extension_index
        let mut index = MftIndex::from_parsed_records(volume, parsed_records);
        index.reserved_allocated_bytes = header.reserved_allocated_bytes;

        Ok(index)
    }

    /// Save MFT using IOCP capture mode.
    ///
    /// This reads MFT using IOCP and saves chunks in the order they complete,
    /// capturing the non-deterministic I/O ordering for realistic testing.
    ///
    /// # Errors
    ///
    /// Returns an error if raw MFT reading or writing the output file fails.
    /// Save MFT using IOCP capture mode.
    ///
    /// This reads MFT using IOCP and saves chunks in the order they complete,
    /// capturing the non-deterministic I/O ordering for realistic testing.
    ///
    /// # Errors
    ///
    /// Returns an error if raw MFT reading or writing the output file fails.
    #[cfg(windows)]
    pub fn save_iocp_capture<P: AsRef<Path>>(
        &self,
        path: P,
        options: &crate::raw_iocp::IocpCaptureOptions,
    ) -> Result<crate::raw_iocp::IocpCaptureHeader> {
        self.save_iocp_internal(path, options)
    }

    /// Internal IOCP capture implementation.
    #[cfg(windows)]
    #[expect(
        unsafe_code,
        reason = "FFI: ReadFile, GetQueuedCompletionStatus for overlapped IOCP capture"
    )]
    /// Save IOCP capture (non-Windows stub).
    ///
    /// # Errors
    ///
    /// Always returns `MftError::PlatformNotSupported` on non-Windows
    /// platforms.
    #[cfg(not(windows))]
    pub fn save_iocp_capture<P: AsRef<Path>>(
        &self,
        _path: P,
        _options: &crate::raw_iocp::IocpCaptureOptions,
    ) -> Result<crate::raw_iocp::IocpCaptureHeader> {
        Err(MftError::PlatformNotSupported)
    }

    /// Load raw MFT from file and build `MftIndex` using direct-to-index
    /// parser.
    ///
    /// This is a single-pass implementation that parses records directly into
    /// the index without creating intermediate `ParsedRecord` allocations. It
    /// uses the unified `process_record()` single-pass parser.
    ///
    /// # Errors
    ///
    /// Returns an error if the raw file cannot be loaded or if record parsing
    /// or index construction fails.
    pub fn load_raw_to_index_direct<P: AsRef<Path>>(
        path: P,
        options: &crate::raw::LoadRawOptions,
    ) -> Result<crate::index::MftIndex> {
        use std::time::Instant;

        use tracing::info;

        use crate::index::MftIndex;
        use crate::io::process_record;
        use crate::parse::apply_fixup;

        let parse_start = Instant::now();

        // Load raw MFT data
        let mut raw = crate::raw::load_raw_mft(path, options)?;
        let capacity = usize::try_from(raw.header.record_count).unwrap_or(0);
        let total_records_in_file = capacity;
        let record_size = raw.header.record_size as usize;

        // Create index with pre-allocated capacity
        let mut index = MftIndex::with_capacity(raw.header.volume_letter, capacity);
        // v3+ .bin files carry the reserved-cluster bytes for the root
        // `tree_allocated` adjustment; restore it so an offline load (this is
        // the loader the daemon uses) reproduces the live root size-on-disk.
        index.reserved_allocated_bytes = raw.header.reserved_allocated_bytes;

        // Parse records directly into index
        let mut fixup_success: u64 = 0;
        let mut fixup_failed: u64 = 0;
        let mut records_added: u64 = 0;
        let mut name_buf = String::with_capacity(256);

        let buffer_slice = raw.data.as_mut_slice();
        for (frs, chunk) in buffer_slice.chunks_exact_mut(record_size).enumerate() {
            // Apply fixup in place
            if !apply_fixup(chunk) {
                fixup_failed += 1;
                continue;
            }
            fixup_success += 1;

            // Parse record directly into index using unified parser
            // process_record handles both base and extension records
            let added = process_record(chunk, frs as u64, &mut index, &mut name_buf);
            if added {
                records_added += 1;
            }
        }

        // Sort directory children for deterministic output
        // CRITICAL for OFFLINE path: ensures consistent ordering across runs
        index.sort_directory_children();

        // Compute tree metrics
        index.compute_tree_metrics();

        let parse_time = parse_start.elapsed();

        info!(
            total_records_in_file,
            parse_ms = parse_time.as_millis(),
            fixup_success,
            fixup_failed,
            records_added,
            final_index_size = index.len(),
            "Direct-to-index parse complete"
        );

        Ok(index)
    }
}
