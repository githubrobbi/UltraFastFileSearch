// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Lean-index read entrypoints and the core index read pipeline.
//!
//! Exception: Single `impl MftReader` block with tightly coupled cfg-gated
//! pipeline stages. Permanent exception — see
//! `docs/architecture/FILE_SIZE_REFACTOR_WAVES.md`.

#[cfg(windows)]
use std::time::Instant;

#[cfg(windows)]
use tracing::{debug, info, trace, warn};

#[cfg(windows)]
use super::MftReadMode;
#[cfg(windows)]
use super::read_mode::index_effective_mode;
use super::{MftProgress, MftReader};
use crate::error::{MftError, Result};
#[cfg(windows)]
use crate::index::{u64_to_f64, usize_to_f64};
#[cfg(windows)]
use crate::platform::VolumeHandle;

impl MftReader {
    /// Read the entire MFT into a lean `MftIndex` (fast path).
    ///
    /// This method builds a compact `MftIndex` structure instead of a Polars
    /// `DataFrame`. It's significantly faster because it avoids the `DataFrame`
    /// building overhead (~15-20s on large drives).
    ///
    /// Use this when you need fast indexing and searching. Convert to
    /// `DataFrame` later with `MftIndex::to_dataframe()` if you need Polars
    /// analytics.
    ///
    /// # Note
    ///
    /// This function uses `spawn_blocking` internally to run MFT reading on a
    /// dedicated blocking thread. This avoids potential nested tokio runtime
    /// issues that can occur when dependencies (like polars) try to create
    /// their own runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if MFT reading fails.
    /// Read the entire MFT into a lean `MftIndex` (fast path).
    ///
    /// Dispatches automatically based on the data source:
    /// - **Live volume** (Windows): Uses IOCP pipeline for maximum performance.
    /// - **File** (cross-platform): Loads from a pre-captured `.mft` file.
    ///
    /// # Errors
    ///
    /// Returns an error if MFT reading fails.
    pub async fn read_all_index(&self) -> Result<crate::index::MftIndex> {
        match &self.source {
            #[cfg(windows)]
            super::MftSource::LiveVolume(_) => self.read_all_index_live().await,
            super::MftSource::File(file_path) => {
                let file_path_owned: std::path::PathBuf = file_path.clone();
                let volume = self.volume;
                tokio::task::spawn_blocking(move || {
                    Self::read_index_from_file(&file_path_owned, volume)
                })
                .await
                .map_err(|_join_err| MftError::Cancelled {
                    operation: "read_all_index(file)",
                    reason: "spawn_blocking task failed".into(),
                })?
            }
        }
    }

    /// Live-volume implementation of `read_all_index` (Windows IOCP).
    #[cfg(windows)]
    #[tracing::instrument(
        level = "info",
        skip(self),
        fields(
            volume = %self.volume,
            mode = %self.mode,
            use_bitmap = self.use_bitmap,
            merge_extensions = self.merge_extensions,
            expand_links = self.expand_links,
            forensic = self.forensic
        )
    )]
    async fn read_all_index_live(&self) -> Result<crate::index::MftIndex> {
        tracing::debug!(volume = %self.volume, "[TRIP] reader::read_all_index ENTER");
        trace!(volume = %self.volume, "read_all_index: ENTER");
        let volume = self.volume;
        let mode = self.mode;
        let merge_extensions = self.merge_extensions;
        let use_bitmap = self.use_bitmap;
        let expand_links = self.expand_links;
        let add_placeholders = self.add_placeholders;
        let concurrency = self.concurrency;
        let io_size = self.io_size;
        let parallel_parse = self.parallel_parse;
        let parse_workers = self.parse_workers;
        let forensic = self.forensic;

        // Duplicate this reader's already-open handle — whatever it
        // points at, a live `\\.\<letter>:` open or a VSS snapshot
        // device from `open_device_path` — rather than opening
        // `\\.\<letter>:` fresh inside `spawn_blocking` below. `HANDLE`
        // isn't `Send`, so the duplicate crosses the boundary as a
        // plain `u64` (`expose_provenance`), reconstructed on the other
        // side by `VolumeHandle::from_duplicated_handle`. `is_live_letter`
        // must be read off the *original* handle before duplicating —
        // duplication preserves what it points at, not how it was opened.
        let existing_handle = self.require_handle()?;
        let is_live_letter = existing_handle.is_live_letter();
        let handle_ptr =
            u64::try_from(existing_handle.duplicate()?.0.expose_provenance()).unwrap_or(0);

        let result = tokio::task::spawn_blocking(move || {
            trace!(volume = %volume, "read_all_index: INSIDE spawn_blocking");
            let handle = VolumeHandle::from_duplicated_handle(handle_ptr, volume, is_live_letter)?;
            let reader = Self {
                volume,
                source: super::MftSource::LiveVolume(Box::new(handle)),
                mode,
                merge_extensions,
                use_bitmap,
                expand_links,
                add_placeholders,
                concurrency,
                io_size,
                parallel_parse,
                parse_workers,
                forensic,
            };
            let idx = reader.read_mft_index_internal(None::<fn(MftProgress)>);
            trace!(volume = %volume, "read_all_index: read_mft_index_internal done");
            idx
        })
        .await
        .map_err(|error| MftError::from_join_error("read_all_index", &error))?;
        trace!(volume = %self.volume, "read_all_index: EXIT");
        tracing::debug!(volume = %self.volume, "[TRIP] reader::read_all_index EXIT");
        result
    }

    /// Load an `MftIndex` from a pre-captured `.mft` file (cross-platform).
    ///
    /// # Errors
    ///
    /// Returns [`MftError`] if the file cannot be read or parsed.
    fn read_index_from_file(
        path: &std::path::Path,
        volume: crate::platform::DriveLetter,
    ) -> Result<crate::index::MftIndex> {
        // Detect IOCP capture vs raw MFT format
        let is_iocp = crate::is_iocp_capture(path).unwrap_or(false);
        if is_iocp {
            crate::load_iocp_to_index(path)
        } else {
            let options = crate::LoadRawOptions {
                volume_letter: Some(volume),
                ..Default::default()
            };
            Self::load_raw_to_index_direct(path, &options)
        }
    }

    /// Synchronous version of `read_all_index` for use in blocking contexts.
    ///
    /// Dispatches on `MftSource` — works cross-platform.
    ///
    /// # Errors
    ///
    /// Returns an error if MFT reading fails.
    pub fn read_all_index_sync(&self) -> Result<crate::index::MftIndex> {
        match &self.source {
            #[cfg(windows)]
            super::MftSource::LiveVolume(_) => {
                self.read_mft_index_internal(None::<fn(MftProgress)>)
            }
            super::MftSource::File(path) => Self::read_index_from_file(path, self.volume),
        }
    }

    /// Synchronous version of `read_index_with_progress` for use in blocking
    /// contexts.
    ///
    /// # Errors
    ///
    /// Returns an error if MFT reading fails.
    #[cfg(windows)]
    pub fn read_index_with_progress_sync<F>(&self, callback: F) -> Result<crate::index::MftIndex>
    where
        F: Fn(MftProgress) + Send + 'static,
    {
        self.read_mft_index_internal(Some(callback))
    }

    /// Synchronous version of `read_index_with_progress` (non-Windows stub).
    ///
    /// # Errors
    ///
    /// Always returns `MftError::PlatformNotSupported` on non-Windows
    /// platforms.
    #[cfg(not(windows))]
    pub fn read_index_with_progress_sync<F>(&self, _callback: F) -> Result<crate::index::MftIndex>
    where
        F: Fn(MftProgress) + Send + 'static,
    {
        let _: &Self = self; // API parity with Windows impl which uses self
        Err(MftError::PlatformNotSupported)
    }

    /// Read MFT into lean index with progress callback.
    ///
    /// # Arguments
    ///
    /// * `callback` - Function called periodically with progress updates
    ///
    /// # Note
    ///
    /// This function uses `spawn_blocking` internally to run MFT reading on a
    /// dedicated blocking thread. This avoids potential nested tokio runtime
    /// issues.
    ///
    /// # Errors
    ///
    /// Returns an error if MFT reading fails.
    #[cfg(windows)]
    #[tracing::instrument(
        level = "info",
        skip(self, callback),
        fields(
            volume = %self.volume,
            mode = %self.mode,
            use_bitmap = self.use_bitmap,
            merge_extensions = self.merge_extensions,
            expand_links = self.expand_links,
            forensic = self.forensic,
            progress_callback = true
        )
    )]
    pub async fn read_index_with_progress<F>(&self, callback: F) -> Result<crate::index::MftIndex>
    where
        F: Fn(MftProgress) + Send + 'static,
    {
        // Capture configuration to recreate reader in blocking thread
        let volume = self.volume;
        let mode = self.mode;
        let merge_extensions = self.merge_extensions;
        let use_bitmap = self.use_bitmap;
        let expand_links = self.expand_links;
        let add_placeholders = self.add_placeholders;
        let concurrency = self.concurrency;
        let io_size = self.io_size;
        let parallel_parse = self.parallel_parse;
        let parse_workers = self.parse_workers;
        let forensic = self.forensic;

        // See `read_all_index_live`'s matching comment: duplicate this
        // reader's already-open handle instead of opening
        // `\\.\<letter>:` fresh in the blocking closure below, which
        // used to silently bypass a VSS snapshot device and read the
        // live volume instead.
        let existing_handle = self.require_handle()?;
        let is_live_letter = existing_handle.is_live_letter();
        let handle_ptr =
            u64::try_from(existing_handle.duplicate()?.0.expose_provenance()).unwrap_or(0);

        tokio::task::spawn_blocking(move || {
            // Reconstruct the duplicated handle in the blocking thread
            let handle = VolumeHandle::from_duplicated_handle(handle_ptr, volume, is_live_letter)?;
            let reader = Self {
                volume,
                source: super::MftSource::LiveVolume(Box::new(handle)),
                mode,
                merge_extensions,
                use_bitmap,
                expand_links,
                add_placeholders,
                concurrency,
                io_size,
                parallel_parse,
                parse_workers,
                forensic,
            };
            reader.read_mft_index_internal(Some(callback))
        })
        .await
        .map_err(|error| MftError::from_join_error("read_index_with_progress", &error))?
    }

    /// Read MFT into lean index with progress (non-Windows stub).
    ///
    /// # Errors
    ///
    /// Always returns `MftError::PlatformNotSupported` on non-Windows
    /// platforms.
    #[cfg(not(windows))]
    #[expect(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "async signature and by-value callback mirror the Windows impl for cross-cfg API parity"
    )]
    pub async fn read_index_with_progress<F>(&self, _callback: F) -> Result<crate::index::MftIndex>
    where
        F: Fn(MftProgress) + Send + 'static,
    {
        Err(MftError::PlatformNotSupported)
    }

    /// Internal implementation for building lean `MftIndex`.
    ///
    /// This is the fast path that avoids `DataFrame` building overhead.
    /// Uses the same I/O and parsing as `read_mft_internal`, but builds
    /// a compact `MftIndex` instead of a Polars `DataFrame`.
    #[cfg(windows)]
    #[expect(
        clippy::too_many_lines,
        reason = "sequential I/O pipeline with mode-specific branches cannot be meaningfully split"
    )]
    #[tracing::instrument(
        level = "info",
        skip(self, callback),
        fields(
            volume = %self.volume,
            configured_mode = %self.mode,
            use_bitmap = self.use_bitmap,
            merge_extensions = self.merge_extensions,
            expand_links = self.expand_links,
            forensic = self.forensic,
            progress_callback = callback.is_some()
        )
    )]
    #[expect(
        clippy::float_arithmetic,
        reason = "telemetry: bitmap skip-percentage and MB/s throughput require float division for human-readable logging"
    )]
    #[expect(
        clippy::cognitive_complexity,
        reason = "per-mode read pipeline: each MftReadMode arm is a distinct IO strategy that must remain inline for accurate timing/telemetry; extracting helpers would either inline the same control flow or hide the per-mode safety/teardown invariants behind extra indirection"
    )]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the by-value `Option<F>` signature lets callers pass capturing \
                  closures (`Some(move |progress| {..})`) without manually \
                  managing the closure's lifetime; switching to `Option<&F>` \
                  would force every call site to introduce a separate let-binding"
    )]
    fn read_mft_index_internal<F>(&self, callback: Option<F>) -> Result<crate::index::MftIndex>
    where
        F: Fn(MftProgress),
    {
        use crate::index::MftIndex;
        use crate::io::{MftExtentMap, ParallelMftReader};
        use crate::platform::detect_drive_type;

        tracing::debug!(volume = %self.volume, "[TRIP] reader::read_mft_index_internal ENTER");

        info!(volume = %self.volume, "Starting MFT read (lean index)");

        let start_time = Instant::now();
        let handle = self.require_handle()?;
        let record_size = handle.file_record_size();
        let volume_data = handle.volume_data();

        // Detect drive type for optimal I/O tuning
        let drive_type = detect_drive_type(self.volume);
        info!(
            volume = %self.volume,
            drive_type = ?drive_type,
            "🚀 Drive type detected for I/O optimization (lean index)"
        );

        // Get MFT extents for fragmented MFT support
        let extents = handle.get_mft_extents().unwrap_or_else(|err| {
            warn!(error = ?err, "Failed to get MFT extents, using fallback");
            vec![crate::platform::MftExtent {
                vcn: 0,
                cluster_count: volume_data.mft_valid_data_length
                    / u64::from(volume_data.bytes_per_cluster),
                lcn: crate::platform::Lcn::new(volume_data.mft_start_lcn.cast_signed()),
            }]
        });

        info!(num_extents = extents.len(), "MFT extents retrieved");

        // Create extent map
        let extent_map = MftExtentMap::new(extents, volume_data.bytes_per_cluster, record_size);
        let total_records = extent_map.total_records();
        info!(total_records, "Total MFT records to read");

        // Try to get the MFT bitmap for optimization
        let bitmap = if self.use_bitmap {
            let bm = handle.get_mft_bitmap().ok();
            if let Some(bitmap) = &bm {
                let in_use = bitmap.count_in_use();
                info!(
                    in_use_records = in_use,
                    skip_percentage =
                        (usize_to_f64(in_use) / u64_to_f64(total_records)).mul_add(-100.0, 100.0),
                    "MFT bitmap loaded - will skip unused records"
                );
            }
            bm
        } else {
            info!("Bitmap optimization DISABLED - reading ALL records");
            None
        };

        // Report initial progress
        if let Some(cb) = &callback {
            cb(MftProgress {
                records_read: 0,
                total_records: Some(total_records),
                bytes_read: 0,
                elapsed: start_time.elapsed(),
            });
        }

        // Select reader based on mode
        // Historical benchmark insight: "read all then parse" is faster than pipelining
        // even on HDD because: no context switching, CPU cache stays hot, no
        // channel overhead, OS can optimize continuous sequential reads better.
        // For lean index (MftIndex), use SlidingIocpInline for NVMe/SSD - this uses
        // IOCP with multiple reads in flight and inline parsing
        // performance.
        let effective_mode = index_effective_mode(self.mode, drive_type);
        debug!(
            requested_mode = ?self.mode,
            ?drive_type,
            "[PARITY_TRACE] read_mft_index_internal ENTER"
        );

        debug!(
            ?effective_mode,
            total_records, "[PARITY_TRACE] selected mode"
        );
        info!(mode = %effective_mode, "🚀 Using read mode (lean index)");

        let raw_handle = handle.raw_handle();
        let total_bytes = total_records * u64::from(record_size);

        // Read using the selected mode (same as read_mft_internal)
        let mut parsed_records = match effective_mode {
            MftReadMode::Parallel | MftReadMode::Auto => {
                let parallel_reader =
                    ParallelMftReader::new_optimized(extent_map, bitmap, drive_type);

                if let Some(cb) = &callback {
                    let cb_ref = cb;
                    let start = start_time;
                    parallel_reader.read_all_parallel_with_progress(
                        raw_handle,
                        true,
                        Some(move |bytes_read: u64, total_bytes_expected: u64| {
                            let records_approx = bytes_read
                                .saturating_mul(total_records)
                                .checked_div(total_bytes_expected)
                                .unwrap_or(0);
                            cb_ref(MftProgress {
                                records_read: records_approx,
                                total_records: Some(total_records),
                                bytes_read,
                                elapsed: start.elapsed(),
                            });
                        }),
                    )?
                } else {
                    parallel_reader
                        .read_all_parallel_with_progress::<fn(u64, u64)>(raw_handle, true, None)?
                }
            }
            MftReadMode::Pipelined => {
                let pipelined_reader =
                    crate::io::PipelinedMftReader::new(extent_map, bitmap, drive_type);

                if let Some(cb) = &callback {
                    let cb_ref = cb;
                    let start = start_time;
                    pipelined_reader.read_all_pipelined(
                        raw_handle,
                        true,
                        Some(move |bytes_read: u64, total_bytes_expected: u64| {
                            let records_approx = bytes_read
                                .saturating_mul(total_records)
                                .checked_div(total_bytes_expected)
                                .unwrap_or(0);
                            cb_ref(MftProgress {
                                records_read: records_approx,
                                total_records: Some(total_records),
                                bytes_read,
                                elapsed: start.elapsed(),
                            });
                        }),
                    )?
                } else {
                    pipelined_reader.read_all_pipelined::<fn(u64, u64)>(raw_handle, true, None)?
                }
            }
            MftReadMode::PipelinedParallel => {
                let pipelined_reader =
                    crate::io::PipelinedMftReader::new(extent_map, bitmap, drive_type);

                if let Some(cb) = &callback {
                    let cb_ref = cb;
                    let start = start_time;
                    pipelined_reader.read_all_pipelined_parallel(
                        raw_handle,
                        true,
                        Some(move |bytes_read: u64, total_bytes_expected: u64| {
                            let records_approx = bytes_read
                                .saturating_mul(total_records)
                                .checked_div(total_bytes_expected)
                                .unwrap_or(0);
                            cb_ref(MftProgress {
                                records_read: records_approx,
                                total_records: Some(total_records),
                                bytes_read,
                                elapsed: start.elapsed(),
                            });
                        }),
                    )?
                } else {
                    pipelined_reader
                        .read_all_pipelined_parallel::<fn(u64, u64)>(raw_handle, true, None)?
                }
            }
            MftReadMode::IocpParallel => {
                // IOCP parallel mode: Multiple overlapped reads in flight
                // IOCP requires FILE_FLAG_OVERLAPPED, so we open a separate raw_handle
                let overlapped_handle = self.require_handle()?.open_overlapped_handle()?;
                let iocp_reader = crate::io::IocpMftReader::new(extent_map, bitmap, drive_type);

                let result = callback.as_ref().map_or_else(
                    || iocp_reader.read_all_iocp::<fn(u64, u64)>(overlapped_handle, true, None),
                    |cb| {
                        let cb_ref = cb;
                        let start = start_time;
                        iocp_reader.read_all_iocp(
                            overlapped_handle,
                            true,
                            Some(move |bytes_read: u64, total_bytes_expected: u64| {
                                let records_approx = bytes_read
                                    .saturating_mul(total_records)
                                    .checked_div(total_bytes_expected)
                                    .unwrap_or(0);
                                cb_ref(MftProgress {
                                    records_read: records_approx,
                                    total_records: Some(total_records),
                                    bytes_read,
                                    elapsed: start.elapsed(),
                                });
                            }),
                        )
                    },
                );

                // Close the overlapped raw_handle
                #[expect(
                    unsafe_code,
                    reason = "FFI: CloseHandle on valid overlapped raw_handle"
                )]
                {
                    // SAFETY: `overlapped_handle` was opened by `open_overlapped_handle`
                    // and is closed exactly once here.
                    _ = unsafe { windows::Win32::Foundation::CloseHandle(overlapped_handle) };
                };

                result?
            }
            MftReadMode::Bulk => {
                // Bulk mode: read all, then parse
                let parallel_reader =
                    ParallelMftReader::new_optimized(extent_map, bitmap, drive_type);

                if let Some(cb) = &callback {
                    let cb_ref = cb;
                    let start = start_time;
                    parallel_reader.read_all_bulk(
                        raw_handle,
                        true,
                        Some(move |bytes_read: u64, total_bytes_expected: u64| {
                            let records_approx = bytes_read
                                .saturating_mul(total_records)
                                .checked_div(total_bytes_expected)
                                .unwrap_or(0);
                            cb_ref(MftProgress {
                                records_read: records_approx,
                                total_records: Some(total_records),
                                bytes_read,
                                elapsed: start.elapsed(),
                            });
                        }),
                    )?
                } else {
                    parallel_reader.read_all_bulk::<fn(u64, u64)>(raw_handle, true, None)?
                }
            }
            MftReadMode::BulkIocp => {
                // Bulk IOCP mode: queues ALL reads to IOCP at once
                let overlapped_handle = self.require_handle()?.open_overlapped_handle()?;
                let parallel_reader =
                    ParallelMftReader::new_optimized(extent_map, bitmap, drive_type);

                let result = callback.as_ref().map_or_else(
                    || {
                        parallel_reader.read_all_bulk_iocp::<fn(u64, u64)>(
                            overlapped_handle,
                            true,
                            None,
                        )
                    },
                    |cb| {
                        let cb_ref = cb;
                        let start = start_time;
                        parallel_reader.read_all_bulk_iocp(
                            overlapped_handle,
                            true,
                            Some(move |bytes_read: u64, total_bytes_expected: u64| {
                                let records_approx = bytes_read
                                    .saturating_mul(total_records)
                                    .checked_div(total_bytes_expected)
                                    .unwrap_or(0);
                                cb_ref(MftProgress {
                                    records_read: records_approx,
                                    total_records: Some(total_records),
                                    bytes_read,
                                    elapsed: start.elapsed(),
                                });
                            }),
                        )
                    },
                );

                // Close the overlapped raw_handle
                #[expect(
                    unsafe_code,
                    reason = "FFI: CloseHandle on valid overlapped raw_handle"
                )]
                {
                    // SAFETY: `overlapped_handle` came from `open_overlapped_handle`, is
                    // no longer used after the read completes, and is closed exactly once.
                    _ = unsafe { windows::Win32::Foundation::CloseHandle(overlapped_handle) };
                };

                result?
            }
            MftReadMode::SlidingIocp => {
                // Sliding window IOCP mode: adaptive concurrency with multiple reads in flight
                let overlapped_handle = self.require_handle()?.open_overlapped_handle()?;
                let parallel_reader =
                    ParallelMftReader::new_optimized(extent_map, bitmap, drive_type);

                let result = callback.as_ref().map_or_else(
                    || {
                        parallel_reader.read_all_sliding_window_iocp::<fn(u64, u64)>(
                            overlapped_handle,
                            true,
                            None,
                        )
                    },
                    |cb| {
                        let cb_ref = cb;
                        let start = start_time;
                        parallel_reader.read_all_sliding_window_iocp(
                            overlapped_handle,
                            true,
                            Some(move |bytes_read: u64, total_bytes_expected: u64| {
                                let records_approx = bytes_read
                                    .saturating_mul(total_records)
                                    .checked_div(total_bytes_expected)
                                    .unwrap_or(0);
                                cb_ref(MftProgress {
                                    records_read: records_approx,
                                    total_records: Some(total_records),
                                    bytes_read,
                                    elapsed: start.elapsed(),
                                });
                            }),
                        )
                    },
                );

                // Close the overlapped raw_handle
                #[expect(
                    unsafe_code,
                    reason = "FFI: CloseHandle on valid overlapped raw_handle"
                )]
                {
                    // SAFETY: `overlapped_handle` came from `open_overlapped_handle`, is
                    // no longer used after the read completes, and is closed exactly once.
                    _ = unsafe { windows::Win32::Foundation::CloseHandle(overlapped_handle) };
                };

                result?
            }
            MftReadMode::SlidingIocpInline => {
                // Sliding window IOCP with inline parsing and direct index building
                // This mode returns MftIndex directly, skipping the intermediate
                // Vec<ParsedRecord>
                debug!("[PARITY_TRACE] ENTERING SlidingIocpInline branch (Windows LIVE path)");
                let overlapped_handle = self.require_handle()?.open_overlapped_handle()?;
                let parallel_reader =
                    ParallelMftReader::new_optimized(extent_map, bitmap, drive_type);

                let result = parallel_reader.read_all_sliding_window_iocp_to_index::<fn(u64, u64)>(
                    overlapped_handle,
                    self.volume,
                    self.concurrency,
                    self.io_size,
                    None,
                );

                // Close the overlapped raw_handle
                #[expect(
                    unsafe_code,
                    reason = "FFI: CloseHandle on valid overlapped raw_handle"
                )]
                {
                    // SAFETY: `overlapped_handle` came from `open_overlapped_handle`, is
                    // no longer used after the read completes, and is closed exactly once.
                    _ = unsafe { windows::Win32::Foundation::CloseHandle(overlapped_handle) };
                };

                match result {
                    Ok(mut index) => {
                        // ── IOCP inline success path (fast) ─────────────────
                        let ra = volume_data.reserved_allocated_bytes();
                        debug!(
                            iocp_parse_ms = start_time.elapsed().as_millis(),
                            records = index.records.len(),
                            reserved_allocated_bytes = ra,
                            total_reserved = volume_data.total_reserved,
                            mft_zone_start = volume_data.mft_zone_start,
                            mft_zone_end = volume_data.mft_zone_end,
                            bytes_per_cluster = volume_data.bytes_per_cluster,
                            "[TIMING] IOCP+parse complete"
                        );
                        info!(
                            reserved_allocated_bytes = ra,
                            total_reserved = volume_data.total_reserved,
                            mft_zone_start = volume_data.mft_zone_start,
                            mft_zone_end = volume_data.mft_zone_end,
                            bytes_per_cluster = volume_data.bytes_per_cluster,
                            "📊 reserved_allocated_bytes for tree_allocated root adjustment"
                        );
                        index.reserved_allocated_bytes = ra;

                        // Compute tree metrics (directory sizes, descendant counts).
                        debug!(
                            records = index.records.len(),
                            "[PARITY_TRACE] SlidingIocpInline: CALLING compute_tree_metrics()"
                        );
                        let tree_start = Instant::now();
                        index.compute_tree_metrics();
                        debug!(
                            tree_metrics_ms = tree_start.elapsed().as_millis(),
                            "[PARITY_TRACE] SlidingIocpInline: compute_tree_metrics() done"
                        );
                        let tree_ms = tree_start.elapsed().as_millis();
                        debug!(tree_ms, "[TIMING] tree_metrics");
                        info!(
                            tree_metrics_ms = tree_ms,
                            "✅ Tree metrics computed for inline index"
                        );

                        // Build extension index eagerly so filtered queries
                        // (*.txt etc.) get O(matches) lookup immediately.
                        let ext_start = Instant::now();
                        index.build_extension_index();
                        let ext_ms = ext_start.elapsed().as_millis();

                        let total_index_ms = start_time.elapsed().as_millis();
                        debug!(ext_ms, total_index_ms, "[TIMING] ext_index + total");
                        info!(
                            total_index_ms,
                            tree_ms,
                            ext_ms,
                            records = index.records.len(),
                            "📊 Windows LIVE index build timing breakdown"
                        );

                        // Report final progress
                        if let Some(cb) = &callback {
                            cb(MftProgress {
                                records_read: total_records,
                                total_records: Some(total_records),
                                bytes_read: total_bytes,
                                elapsed: start_time.elapsed(),
                            });
                        }

                        // Return early — inline index is complete.
                        return Ok(index);
                    }
                    Err(iocp_err) => {
                        // ── IOCP failed — cascading fallback ────────────────
                        // Write-protected volumes reject IOCP I/O. Try two
                        // fallback strategies before giving up:
                        //
                        // 1. Open `X:\$MFT` as a file (filesystem-mediated)
                        // 2. Re-open volume with FILE_FLAG_NO_BUFFERING (bypasses cache manager,
                        //    direct device I/O)
                        warn!(
                            volume = %self.volume,
                            error = %iocp_err,
                            "⚠️  IOCP inline read failed — trying fallback strategies"
                        );
                        self.read_write_protect_fallback(record_size, total_records)?
                    }
                }
            }
            MftReadMode::Streaming | MftReadMode::Prefetch => {
                // Fallback to parallel for streaming/prefetch modes in lean index
                let parallel_reader =
                    ParallelMftReader::new_optimized(extent_map, bitmap, drive_type);
                parallel_reader
                    .read_all_parallel_with_progress::<fn(u64, u64)>(raw_handle, true, None)?
            }
        };

        // Add placeholder records for missing parent directories.
        // Can be disabled with `with_add_placeholders(false)` for ~15% speedup.
        if self.add_placeholders {
            let placeholders_added =
                crate::io::add_missing_parent_placeholders_to_vec(&mut parsed_records);
            if placeholders_added > 0 {
                debug!(
                    placeholders_added,
                    "Added placeholder records for path resolution"
                );
            }
        }

        let read_elapsed = start_time.elapsed();
        let records_parsed_count = parsed_records.len();
        let throughput_mb_s = if read_elapsed.as_secs_f64() > 0.0 {
            (u64_to_f64(total_bytes) / (1024.0 * 1024.0)) / read_elapsed.as_secs_f64()
        } else {
            0.0
        };

        tracing::debug!(
            volume = %self.volume,
            records_parsed = records_parsed_count,
            "[TRIP] reader::read_mft_index_internal -> I/O+parse done, calling MftIndex::from_parsed_records"
        );
        info!(
            records_parsed = records_parsed_count,
            elapsed_ms = read_elapsed.as_millis(),
            throughput_mb_s = format!("{:.1}", throughput_mb_s),
            "✅ MFT read complete, building lean index"
        );

        // Build lean MftIndex (fast path - no DataFrame overhead)
        let index_start = Instant::now();
        let index = MftIndex::from_parsed_records(self.volume, parsed_records);
        let index_elapsed = index_start.elapsed();

        tracing::debug!(
            volume = %self.volume,
            records = index.records.len(),
            index_build_ms = index_elapsed.as_millis(),
            "[TRIP] reader::read_mft_index_internal -> MftIndex::from_parsed_records done"
        );
        info!(
            records = index.records.len(),
            names_buffer_kb = index.names.len() / 1024,
            index_build_ms = index_elapsed.as_millis(),
            "✅ Lean index built"
        );

        // Report final progress
        if let Some(cb) = &callback {
            cb(MftProgress {
                records_read: total_records,
                total_records: Some(total_records),
                bytes_read: total_bytes,
                elapsed: start_time.elapsed(),
            });
        }

        tracing::debug!(volume = %self.volume, "[TRIP] reader::read_mft_index_internal EXIT");
        Ok(index)
    }

    /// Cascading fallback for write-protected volumes.
    ///
    /// Tries, in order:
    /// 1. Open `X:\$MFT` directly as a file and read it sequentially.
    /// 2. Re-open the volume with `FILE_FLAG_NO_BUFFERING` (bypasses cache
    ///    manager) and use the synchronous parallel reader.
    ///
    /// Returns `Vec<ParsedRecord>` on success.
    #[cfg(windows)]
    pub(crate) fn read_write_protect_fallback(
        &self,
        record_size: u32,
        total_records: u64,
    ) -> Result<Vec<crate::io::ParsedRecord>> {
        let vh = self.require_handle()?;

        // ── Strategy 1: read $MFT as a file ────────────────────────────
        match vh.open_mft_read_handle() {
            Ok(mft_handle) => {
                info!(volume = %self.volume, "📂 Fallback 1: reading $MFT as file");
                let result = crate::io::readers::mft_file::read_mft_from_file_handle(
                    mft_handle,
                    record_size,
                    total_records,
                );
                #[expect(unsafe_code, reason = "FFI: CloseHandle on $MFT file handle")]
                {
                    // SAFETY: `mft_handle` from `open_mft_read_handle`, closed
                    // exactly once after the read completes.
                    _ = unsafe { windows::Win32::Foundation::CloseHandle(mft_handle) };
                };
                return result;
            }
            Err(err) => {
                warn!(
                    volume = %self.volume,
                    error = %err,
                    "⚠️  Fallback 1 ($MFT file) failed — trying unbuffered volume I/O"
                );
            }
        }

        // ── Strategy 2: unbuffered volume handle (FILE_FLAG_NO_BUFFERING) ──
        let unbuf_handle = vh.open_unbuffered_handle()?;
        info!(volume = %self.volume, "📂 Fallback 2: unbuffered volume I/O (NO_BUFFERING)");
        let vd = vh.volume_data();
        let extents = vh.get_mft_extents()?;
        let extent_map = crate::io::MftExtentMap::new(extents, vd.bytes_per_cluster, record_size);
        let reader = crate::io::ParallelMftReader::new_optimized(
            extent_map,
            vh.get_mft_bitmap().ok(),
            crate::platform::DriveType::Hdd,
        );
        let result =
            reader.read_all_parallel_with_progress::<fn(u64, u64)>(unbuf_handle, true, None);
        #[expect(unsafe_code, reason = "FFI: CloseHandle on unbuffered volume handle")]
        {
            // SAFETY: `unbuf_handle` from `open_unbuffered_handle`, closed
            // exactly once after the read completes.
            _ = unsafe { windows::Win32::Foundation::CloseHandle(unbuf_handle) };
        };
        result
    }
}
