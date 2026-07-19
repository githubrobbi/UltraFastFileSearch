// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Pipelined reader implementation.

use super::prelude::*;

/// Message sent from reader thread to parser thread.
struct ReadBuffer {
    /// The buffer containing raw MFT data.
    buffer: AlignedBuffer,
    /// Number of bytes actually read.
    bytes_read: usize,
    /// The chunk metadata.
    chunk: ReadChunk,
    /// Record size in bytes.
    record_size: u32,
}

/// Pipelined MFT reader with true I/O and CPU overlap.
///
/// This reader uses separate threads for I/O and parsing, connected by
/// bounded channels. This allows I/O to proceed while parsing is happening,
/// maximizing throughput especially on HDDs where I/O latency is significant.
///
/// Architecture:
/// ```text
/// ┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
/// │ Reader      │────▶│ Bounded Channel  │────▶│ Parser      │
/// │ Thread      │     │ (backpressure)   │     │ Thread(s)   │
/// └─────────────┘     └──────────────────┘     └─────────────┘
///       │                                             │
///       ▼                                             ▼
///   Read chunks                                 Parse records
///   from disk                                   into ParsedRecord
/// ```
///
/// Key features:
/// - **True overlap**: I/O and parsing happen concurrently
/// - **Backpressure**: Bounded channel prevents memory explosion
/// - **Buffer pool**: Reuses buffers to minimize allocations
pub struct PipelinedMftReader {
    /// Extent map for VCN-to-LCN translation.
    extent_map: MftExtentMap,
    /// Optional bitmap for skip optimization.
    bitmap: Option<crate::platform::MftBitmap>,
    /// Read chunk size in bytes.
    chunk_size: usize,
    /// Number of buffers in the pipeline (channel capacity).
    pipeline_depth: usize,
}

impl PipelinedMftReader {
    /// Creates a new pipelined reader.
    ///
    /// # Arguments
    ///
    /// * `extent_map` - MFT extent map for physical offset calculation
    /// * `bitmap` - Optional MFT bitmap for skipping unused records
    /// * `drive_type` - Drive type for chunk size tuning
    #[must_use]
    pub const fn new(
        extent_map: MftExtentMap,
        bitmap: Option<crate::platform::MftBitmap>,
        drive_type: crate::platform::DriveType,
    ) -> Self {
        // Chunk size based on drive type (use optimal_chunk_size for consistency)
        let chunk_size = drive_type.optimal_chunk_size();

        // Pipeline depth: 2-3 buffers is optimal
        // - 1 being read
        // - 1 being parsed
        // - 1 in the channel (optional, for smoothing)
        let pipeline_depth = 3;

        Self {
            extent_map,
            bitmap,
            chunk_size,
            pipeline_depth,
        }
    }

    /// Reads all MFT records with true I/O and CPU overlap.
    ///
    /// This method spawns a reader thread that reads chunks as fast as
    /// possible, sending them through a bounded channel to the main thread
    /// for parsing. The bounded channel provides backpressure to prevent
    /// memory explosion.
    ///
    /// # Errors
    ///
    /// Returns [`MftError::Io`] if a chunk read fails, if the reader thread
    /// terminates early, or if the bounded channel is closed before all
    /// chunks have been processed. Any platform syscall failure surfaces the
    /// underlying Win32 error code.
    pub fn read_all_pipelined<F>(
        &self,
        handle: HANDLE,
        merge_extensions: bool,
        mut progress_callback: Option<F>,
    ) -> Result<Vec<ParsedRecord>>
    where
        F: FnMut(u64, u64),
    {
        let chunks = generate_read_chunks(&self.extent_map, self.bitmap.as_ref(), self.chunk_size);
        let record_size = self.extent_map.bytes_per_record;
        let num_chunks = chunks.len();

        if num_chunks == 0 {
            return Ok(Vec::new());
        }

        let total_bytes: u64 = chunks
            .iter()
            .map(|chunk| chunk.record_count * u64::from(record_size))
            .sum();

        let estimated_records = self.bitmap.as_ref().map_or_else(
            || frs_to_usize(self.extent_map.total_records()),
            crate::platform::MftBitmap::count_in_use,
        );

        info!(
            chunks = num_chunks,
            estimated_records,
            chunk_size_mb = self.chunk_size / (1024 * 1024),
            pipeline_depth = self.pipeline_depth,
            "🚀 Starting pipelined read with I/O+CPU overlap"
        );

        let max_chunk_size = chunks
            .iter()
            .map(|chunk| chunk.record_count * u64::from(record_size))
            .max()
            .map_or(self.chunk_size, frs_to_usize);

        let (reader_handle, rx) = spawn_pipelined_reader(
            handle,
            chunks,
            record_size,
            max_chunk_size,
            self.pipeline_depth,
        );

        let mut merger = MftRecordMerger::with_capacity(estimated_records);
        let mut bytes_read_total: u64 = 0;

        while let Ok(result) = rx.recv() {
            // Propagate any reader-thread I/O failure to the caller — this
            // makes the function's `Result` wrapper meaningful and prevents
            // the previous behaviour of silently returning a partial result
            // (clippy::unnecessary_wraps).
            let read_buffer = result?;
            let ReadBuffer {
                mut buffer,
                bytes_read,
                chunk,
                record_size: chunk_record_size,
            } = read_buffer;

            bytes_read_total += usize_to_u64(bytes_read);
            parse_buffer_into_merger(
                buffer.as_mut_slice(),
                bytes_read,
                &chunk,
                chunk_record_size,
                merge_extensions,
                &mut merger,
            );

            if let Some(ref mut cb) = progress_callback {
                cb(bytes_read_total, total_bytes);
            }
        }

        if let Err(join_err) = reader_handle.join() {
            warn!("Reader thread panicked: {:?}", join_err);
        }

        let all_results = merger.merge();
        info!(
            records = all_results.len(),
            bytes_mb = bytes_read_total / (1024 * 1024),
            "✅ Pipelined read complete"
        );

        Ok(all_results)
    }

    /// Reads all MFT records with pipelined I/O and parallel parsing.
    ///
    /// This method combines the benefits of pipelined I/O (true I/O+CPU
    /// overlap) with multi-core parallel parsing using Rayon. This is the
    /// optimal mode for HDDs with multi-core CPUs.
    ///
    /// Architecture:
    /// ```text
    /// ┌─────────────┐     ┌──────────────────┐     ┌─────────────────────┐
    /// │ Reader      │────▶│ Bounded Channel  │────▶│ Rayon Thread Pool   │
    /// │ Thread      │     │ (backpressure)   │     │ (parallel parsing)  │
    /// └─────────────┘     └──────────────────┘     └─────────────────────┘
    ///       │                                             │
    ///       ▼                                             ▼
    ///   Read chunks                                 Parse records in
    ///   from disk                                   parallel batches
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`MftError::Io`] if a chunk read fails or the reader thread
    /// terminates early, or [`MftError::RecordRead`] for record-level
    /// fixup/parse failures surfaced by the parallel parsing stage.
    pub fn read_all_pipelined_parallel<F>(
        &self,
        handle: HANDLE,
        merge_extensions: bool,
        progress_callback: Option<F>,
    ) -> Result<Vec<ParsedRecord>>
    where
        F: FnMut(u64, u64),
    {
        let Some(plan) = self.plan_pipelined_read() else {
            return Ok(Vec::new());
        };

        let (reader_handle, rx) = spawn_pipelined_reader(
            handle,
            plan.chunks,
            plan.record_size,
            plan.max_chunk_size,
            self.pipeline_depth * 2,
        );

        let (all_buffers, bytes_read_total) =
            drain_pipelined_reader(&rx, plan.num_chunks, plan.total_bytes, progress_callback)?;

        if let Err(join_err) = reader_handle.join() {
            warn!("Reader thread panicked: {:?}", join_err);
        }

        info!(
            buffers = all_buffers.len(),
            bytes_mb = bytes_read_total / (1024 * 1024),
            "📦 All buffers collected, starting parallel parsing"
        );

        let all_results = parse_and_merge_pipelined_buffers(
            all_buffers,
            merge_extensions,
            plan.estimated_records,
        );

        info!(
            records = all_results.len(),
            bytes_mb = bytes_read_total / (1024 * 1024),
            "✅ Pipelined-parallel read complete"
        );

        Ok(all_results)
    }

    /// Build the chunk plan, byte totals, and estimated record count for a
    /// pipelined-parallel read.  Returns `None` when the volume produces no
    /// chunks (caller should yield an empty `Vec`).
    fn plan_pipelined_read(&self) -> Option<PipelinedReadPlan> {
        let chunks = generate_read_chunks(&self.extent_map, self.bitmap.as_ref(), self.chunk_size);
        let record_size = self.extent_map.bytes_per_record;
        let num_chunks = chunks.len();

        if num_chunks == 0 {
            return None;
        }

        let total_bytes: u64 = chunks
            .iter()
            .map(|chunk| chunk.record_count * u64::from(record_size))
            .sum();

        let estimated_records = self.bitmap.as_ref().map_or_else(
            || frs_to_usize(self.extent_map.total_records()),
            crate::platform::MftBitmap::count_in_use,
        );

        info!(
            chunks = num_chunks,
            estimated_records,
            chunk_size_mb = self.chunk_size / (1024 * 1024),
            pipeline_depth = self.pipeline_depth,
            rayon_threads = rayon::current_num_threads(),
            "🚀 Starting pipelined-parallel read with I/O+CPU overlap and multi-core parsing"
        );

        let max_chunk_size = chunks
            .iter()
            .map(|chunk| chunk.record_count * u64::from(record_size))
            .max()
            .map_or(self.chunk_size, frs_to_usize);

        Some(PipelinedReadPlan {
            chunks,
            record_size,
            num_chunks,
            total_bytes,
            estimated_records,
            max_chunk_size,
        })
    }
}

/// Pre-computed plan for a single pipelined-parallel read.
///
/// Bundled into a struct so [`PipelinedMftReader::read_all_pipelined_parallel`]
/// can hand the fields off to its sub-helpers without exceeding clippy's
/// `too_many_arguments` threshold.
struct PipelinedReadPlan {
    /// Bitmap-aware [`ReadChunk`] schedule (in disk order) handed to the
    /// pipelined reader thread.
    chunks: Vec<ReadChunk>,
    /// `bytes_per_record` from the [`MftExtentMap`], cached so consumers
    /// don't re-read the extent map.
    record_size: u32,
    /// Number of entries in `chunks`; used to size the buffer
    /// pre-allocation in [`drain_pipelined_reader`].
    num_chunks: usize,
    /// Total bytes the reader will deliver (post-skip on bitmap-aware
    /// runs); fed to the progress callback as the denominator.
    total_bytes: u64,
    /// Conservative record-count estimate for pre-allocating the
    /// `MftRecordMerger` (uses bitmap when present, else extent total).
    estimated_records: usize,
    /// Largest single chunk in bytes — used to size the per-chunk
    /// `AlignedBuffer` allocations.
    max_chunk_size: usize,
}

/// Drain `rx` until the reader thread closes the channel, accumulating
/// `ReadBuffer`s and updating `progress_callback` after each delivery.
///
/// Reader-thread errors are propagated via `?` so callers can distinguish
/// a complete pipeline run from a truncated one.  Returns the collected
/// buffers together with the running byte total.
fn drain_pipelined_reader<F>(
    rx: &crossbeam_channel::Receiver<Result<ReadBuffer>>,
    capacity: usize,
    total_bytes: u64,
    mut progress_callback: Option<F>,
) -> Result<(Vec<ReadBuffer>, u64)>
where
    F: FnMut(u64, u64),
{
    let mut all_buffers: Vec<ReadBuffer> = Vec::with_capacity(capacity);
    let mut bytes_read_total: u64 = 0;

    while let Ok(result) = rx.recv() {
        let read_buffer = result?;
        bytes_read_total += usize_to_u64(read_buffer.bytes_read);
        all_buffers.push(read_buffer);

        if let Some(ref mut cb) = progress_callback {
            cb(bytes_read_total, total_bytes);
        }
    }

    Ok((all_buffers, bytes_read_total))
}

/// Parse every buffer in parallel via Rayon (zero-copy in-place fixup) and
/// fold the per-buffer results through [`MftRecordMerger`] to produce the
/// final `Vec<ParsedRecord>`.
fn parse_and_merge_pipelined_buffers(
    mut all_buffers: Vec<ReadBuffer>,
    merge_extensions: bool,
    estimated_records: usize,
) -> Vec<ParsedRecord> {
    let parse_results: Vec<ParseResult> = all_buffers
        .par_iter_mut()
        .flat_map(|read_buffer| {
            parse_buffer_zero_copy_inner(
                read_buffer.buffer.as_mut_slice(),
                read_buffer.bytes_read,
                &read_buffer.chunk,
                read_buffer.record_size,
                merge_extensions,
            )
        })
        .collect();

    info!(
        parse_results = parse_results.len(),
        "✅ Parallel parsing complete"
    );

    let mut merger = MftRecordMerger::with_capacity(estimated_records);
    for result in parse_results {
        merger.add_result(result);
    }
    merger.merge()
}

/// Static helper to read a chunk into a buffer (for use in reader thread).
#[expect(
    unsafe_code,
    reason = "FFI: SetFilePointerEx and ReadFile for pipelined reader thread"
)]
fn read_chunk_into_buffer_static(
    handle: HANDLE,
    chunk: &ReadChunk,
    record_size: u32,
    buffer: &mut AlignedBuffer,
) -> Result<usize> {
    let read_size = chunk.record_count * u64::from(record_size);

    // Align to sector boundary
    let aligned_offset = (chunk.disk_offset / SECTOR_SIZE_U64) * SECTOR_SIZE_U64;
    let offset_adjustment = frs_to_usize(chunk.disk_offset - aligned_offset);
    let aligned_size =
        (frs_to_usize(read_size) + offset_adjustment).div_ceil(SECTOR_SIZE) * SECTOR_SIZE;

    // Resize buffer if needed
    if buffer.len() < aligned_size {
        *buffer = AlignedBuffer::new(aligned_size);
    }

    // Seek to position
    let mut new_pos: i64 = 0;
    // SAFETY: `handle` is a live volume handle and `new_pos` is valid writable
    // storage for the duration of the seek.
    let seek_result = unsafe {
        SetFilePointerEx(
            handle,
            aligned_offset.cast_signed(),
            Some(&raw mut new_pos),
            FILE_BEGIN,
        )
    };

    if seek_result.is_err() {
        return Err(MftError::Io(std::io::Error::last_os_error()));
    }

    // Read data
    let mut bytes_read: u32 = 0;
    let Some(read_slice) = buffer.as_mut_slice().get_mut(..aligned_size) else {
        // Unreachable: buffer was allocated to ≥ aligned_size by the caller.
        return Err(MftError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "aligned buffer shorter than aligned_size",
        )));
    };
    // SAFETY: `handle` is live, the aligned buffer slice spans `aligned_size`
    // writable bytes, and `bytes_read` is a valid out-parameter.
    let read_result =
        unsafe { ReadFile(handle, Some(read_slice), Some(&raw mut bytes_read), None) };

    if read_result.is_err() {
        return Err(MftError::Io(std::io::Error::last_os_error()));
    }

    Ok(u32_as_usize(bytes_read))
}

/// Spawn the pipelined reader thread.
///
/// The reader runs `read_chunk_into_buffer_static` for each chunk and forwards
/// the result through the bounded channel.  Both successful reads and errors
/// are propagated via `Result<ReadBuffer, MftError>`; the consumer threads
/// decide whether to short-circuit (typically via `?`) or continue.
fn spawn_pipelined_reader(
    handle: HANDLE,
    chunks: Vec<ReadChunk>,
    record_size: u32,
    max_chunk_size: usize,
    pipeline_depth: usize,
) -> (
    std::thread::JoinHandle<()>,
    crossbeam_channel::Receiver<Result<ReadBuffer>>,
) {
    use std::thread;

    use crossbeam_channel::{Receiver, Sender, bounded};

    let (tx, rx): (Sender<Result<ReadBuffer>>, Receiver<Result<ReadBuffer>>) =
        bounded(pipeline_depth);

    // `HANDLE` is not `Send`; ferry the raw pointer as `usize` and rebuild on
    // the worker side.  The pointer remains valid because the orchestrator
    // owns the underlying `VolumeHandle` for the duration of this call.
    // SAFETY-NOTE: handle.0 is `*mut c_void`; we serialise it as `usize` purely
    // for cross-thread transport because `HANDLE` is `!Send`. The pointer is
    // reconstructed on the worker thread and the underlying handle remains
    // owned by the orchestrator for the full lifetime of this call.
    let handle_raw = handle.0.expose_provenance();

    let join = thread::spawn(move || {
        let thread_handle = HANDLE(handle_raw as *mut core::ffi::c_void);
        let mut buffer_pool: Vec<AlignedBuffer> = Vec::new();

        for chunk in chunks {
            let mut buffer = buffer_pool
                .pop()
                .unwrap_or_else(|| AlignedBuffer::new(max_chunk_size + SECTOR_SIZE));

            match read_chunk_into_buffer_static(thread_handle, &chunk, record_size, &mut buffer) {
                Ok(bytes_read) => {
                    let read_buffer = ReadBuffer {
                        buffer,
                        bytes_read,
                        chunk,
                        record_size,
                    };
                    if tx.send(Ok(read_buffer)).is_err() {
                        // Receiver dropped — abandon the read pipeline.
                        break;
                    }
                }
                Err(err) => {
                    warn!(error = %err, "Pipelined reader: chunk read failed");
                    // Forward the error and terminate; the consumer will
                    // surface it via `?` and the orchestrator returns Err.
                    // Discard the must_use Result if the receiver has already
                    // disconnected — the error path is already terminal.
                    _ = tx.send(Err(err));
                    break;
                }
            }
        }
        // tx is dropped here, signaling end-of-stream to the consumer.
    });

    (join, rx)
}

/// Parse every effective record in `buffer` (zero-copy, in-place fixup) into
/// the supplied merger.  Extracted from the pipelined orchestrators so each
/// caller stays under the function-length limit.
fn parse_buffer_into_merger(
    buffer_slice: &mut [u8],
    bytes_read: usize,
    chunk: &ReadChunk,
    chunk_record_size: u32,
    merge_extensions: bool,
    merger: &mut MftRecordMerger,
) {
    let skip_begin = frs_to_usize(chunk.skip_begin);
    let effective_count = frs_to_usize(chunk.effective_record_count());
    let record_size_usize = u32_as_usize(chunk_record_size);

    for i in 0..effective_count {
        let offset = (skip_begin + i) * record_size_usize;
        let Some(record_slice) = buffer_slice.get_mut(offset..offset + record_size_usize) else {
            // Short-read: buffer contained fewer bytes than expected.
            break;
        };
        if offset + record_size_usize > bytes_read {
            break;
        }

        let frs = chunk.start_frs + usize_to_u64(skip_begin) + usize_to_u64(i);

        if !apply_fixup(record_slice) {
            continue;
        }

        if merge_extensions {
            merger.add_result(parse_record_full(record_slice, frs));
        } else if let Some(rec) = parse_record(record_slice, frs) {
            merger.add_result(ParseResult::Base(rec));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipelined_reader_creation() {
        // Expected chunk sizes must track `DriveType::optimal_chunk_size`
        // in `crates/uffs-mft/src/platform/system.rs`.  The previous
        // hardcoded `64 * 1024` was stale from an early prototype; the
        // test never caught the drift because `mod pipelined` is
        // `#[cfg(windows)]`-gated in `readers/mod.rs` and had never run
        // in CI before `preview-artifacts.yml`'s `smoke-windows` job
        // (first ran 2026-04-24, PR #52 run 24873800282).  See tracking
        // issue #54 and `docs/architecture/dev-flow-implementation-plan.md`
        // §10.5 bug #6 for the full diagnostic.
        use crate::platform::DriveType;

        let extent_map = MftExtentMap::contiguous(100, 1024 * 1024, 4096, 1024);

        let reader_ssd = PipelinedMftReader::new(extent_map.clone(), None, DriveType::Ssd);
        assert_eq!(reader_ssd.chunk_size, DriveType::Ssd.optimal_chunk_size());
        assert_eq!(reader_ssd.pipeline_depth, 3);

        let reader_hdd = PipelinedMftReader::new(extent_map.clone(), None, DriveType::Hdd);
        assert_eq!(reader_hdd.chunk_size, DriveType::Hdd.optimal_chunk_size());
        assert_eq!(reader_hdd.pipeline_depth, 3);

        let reader_unknown = PipelinedMftReader::new(extent_map, None, DriveType::Unknown);
        assert_eq!(
            reader_unknown.chunk_size,
            DriveType::Unknown.optimal_chunk_size()
        );
    }
}
