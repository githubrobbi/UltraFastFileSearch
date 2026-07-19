// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Bulk IOCP reader path for `ParallelMftReader`.

use core::sync::atomic::AtomicUsize;

use super::prelude::*;

/// Single in-flight overlapped read for the bulk-IOCP pipeline.
///
/// Wrapped in a `Pin<Box<_>>` so the `OVERLAPPED` field's address stays
/// stable while Windows holds a raw pointer to it for the IOCP completion.
struct BulkOverlappedRead {
    /// Win32 `OVERLAPPED` struct passed to `ReadFile` and matched on the
    /// IOCP completion side.  Addressed by raw pointer until the
    /// completion is dequeued, hence the `Pin<Box<_>>` wrapping at the
    /// owning sites.
    overlapped: windows::Win32::System::IO::OVERLAPPED,
}

/// `Send`/`Sync` wrapper around a raw IOCP HANDLE so worker threads can
/// share it.  IOCP handles are kernel objects whose synchronization is
/// provided by the kernel itself, which is the only invariant the
/// wrapper relies on.
#[derive(Clone, Copy)]
struct SendHandle(usize);
#[expect(
    unsafe_code,
    reason = "FFI: copies a kernel IOCP handle value; thread-safety is provided by the kernel."
)]
// SAFETY: `SendHandle` only copies the raw IOCP handle value; the kernel
// object itself is thread-safe and ownership stays external to this wrapper.
unsafe impl Send for SendHandle {}
#[expect(
    unsafe_code,
    reason = "FFI: copies a kernel IOCP handle value; thread-safety is provided by the kernel."
)]
// SAFETY: Sharing copied IOCP handle values across threads is sound because
// all synchronization is provided by the kernel-managed completion port.
unsafe impl Sync for SendHandle {}

impl ParallelMftReader {
    /// Bulk read using true IOCP - queues ALL reads at once, lets Windows
    /// optimize disk scheduling. All I/O is submitted
    /// operations simultaneously, then wait for completions.
    ///
    /// # Arguments
    /// * `overlapped_handle` - Handle opened with `FILE_FLAG_OVERLAPPED`
    /// * `merge_extensions` - Whether to merge extension records
    /// * `progress_callback` - Optional progress callback
    ///
    /// # Errors
    ///
    /// Returns [`MftError::Io`] when `CreateIoCompletionPort`, `ReadFile`, or
    /// `GetQueuedCompletionStatus` fails for any submitted operation.
    #[expect(
        unsafe_code,
        reason = "FFI: dispatches to queue_bulk_iocp_reads (ReadFile) + drain_bulk_iocp_completions (GetQueuedCompletionStatus)"
    )]
    pub(crate) fn read_all_bulk_iocp<F>(
        &self,
        overlapped_handle: HANDLE,
        merge_extensions: bool,
        _progress_callback: Option<F>,
    ) -> Result<Vec<ParsedRecord>>
    where
        F: Fn(u64, u64),
    {
        let record_size = u32_as_usize(self.extent_map.bytes_per_record);
        let total_records = frs_to_usize(self.extent_map.total_records());
        let total_bytes = total_records * record_size;

        info!(
            total_records,
            total_bytes_mb = total_bytes / (1024 * 1024),
            "🚀 Starting IOCP bulk MFT read (queue ALL, then parse)"
        );

        // Phase 1: allocate single buffer for the entire MFT.
        let alloc_start = std::time::Instant::now();
        let mut mft_buffer = AlignedBuffer::new(total_bytes);
        info!(
            alloc_ms = alloc_start.elapsed().as_millis(),
            "📦 Allocated MFT buffer"
        );

        // Phase 2: build the chunk plan + log skip-optimisation savings.
        let (sorted_chunks, bytes_to_read) = plan_bulk_iocp_chunks(
            &self.extent_map,
            self.bitmap.as_ref(),
            self.chunk_size,
            record_size,
            total_bytes,
        );

        // Phase 3: create IOCP, queue every read up-front, drain completions.
        // SAFETY: `overlapped_handle` is a live overlapped-capable handle
        // (per the doc-contract); `mft_buffer` outlives the drain phase.
        unsafe {
            self.run_bulk_iocp_io(
                overlapped_handle,
                &sorted_chunks,
                &mut mft_buffer,
                record_size,
                bytes_to_read,
            )
        }?;

        // Phase 4: parallel parse over the populated buffer.
        let bitmap_ref = self.bitmap.as_ref();
        let estimated_records =
            bitmap_ref.map_or(total_records, crate::platform::MftBitmap::count_in_use);
        Ok(dispatch_bulk_parse(
            mft_buffer.as_mut_slice(),
            bitmap_ref,
            record_size,
            estimated_records,
            merge_extensions,
        ))
    }

    /// Phase 3 driver: queue every read against `overlapped_handle`, then
    /// drain completions on a worker pool.  Logs queue and drain timings
    /// to keep the orchestrator's flow flat.
    ///
    /// # Safety
    ///
    /// Same contract as [`queue_bulk_iocp_reads`] — `overlapped_handle`
    /// must be a live overlapped-capable handle and `mft_buffer` must
    /// outlive the drain phase.
    #[expect(
        unsafe_code,
        reason = "FFI: ReadFile + GetQueuedCompletionStatus driven by raw OVERLAPPED pointers"
    )]
    unsafe fn run_bulk_iocp_io(
        &self,
        overlapped_handle: HANDLE,
        sorted_chunks: &[ReadChunk],
        mft_buffer: &mut AlignedBuffer,
        record_size: usize,
        bytes_to_read: u64,
    ) -> Result<()> {
        let read_start = std::time::Instant::now();
        let iocp = IoCompletionPort::new(0)?;
        iocp.associate(overlapped_handle, 0)?;

        let io_chunk_size = self.drive_type.optimal_io_size();
        // SAFETY: caller's invariant — see method-level Safety doc.
        let pending_count = unsafe {
            queue_bulk_iocp_reads(
                overlapped_handle,
                sorted_chunks,
                mft_buffer,
                record_size,
                io_chunk_size,
                bytes_to_read,
            )
        }?;

        let num_workers = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
        info!(
            queued = pending_count,
            io_size_mb = io_chunk_size / (1024 * 1024),
            workers = num_workers,
            drive_type = ?self.drive_type,
            "📤 Queued all reads to IOCP (adaptive I/O size)"
        );

        let total_bytes_read = drain_bulk_iocp_completions(&iocp, pending_count, num_workers)?;
        info!(
            read_ms = read_start.elapsed().as_millis(),
            bytes_mb = total_bytes_read / (1024 * 1024),
            workers = num_workers,
            "✅ IOCP bulk read complete (multi-threaded)"
        );

        Ok(())
    }
}

/// Phase 4 dispatcher: pick the merging vs. fast parse path and emit the
/// completion-summary tracing event the caller used to do inline.
fn dispatch_bulk_parse(
    buffer: &mut [u8],
    bitmap: Option<&crate::platform::MftBitmap>,
    record_size: usize,
    estimated_records: usize,
    merge_extensions: bool,
) -> Vec<ParsedRecord> {
    let parse_start = std::time::Instant::now();
    let records = if merge_extensions {
        parse_bulk_buffer_with_merge(buffer, bitmap, record_size, estimated_records)
    } else {
        parse_bulk_buffer_fast(buffer, bitmap, record_size, estimated_records)
    };

    info!(
        parse_ms = parse_start.elapsed().as_millis(),
        records = records.len(),
        merge_extensions,
        "✅ IOCP bulk parse complete"
    );

    records
}

/// Records-per-parallel-chunk for the parse phase of
/// [`ParallelMftReader::read_all_bulk_iocp`].  4 KiB records is roughly one
/// L1 of work per Rayon task — large enough to amortise dispatch overhead,
/// small enough to keep stragglers cheap.
const BULK_IOCP_RECORDS_PER_CHUNK: usize = 4096;

/// Phase 2 of [`ParallelMftReader::read_all_bulk_iocp`].
///
/// Sorts the chunk schedule into LCN order (so the disk does fewer seeks),
/// computes the post-skip byte total, and emits a tracing summary of the
/// bitmap-driven savings.
fn plan_bulk_iocp_chunks(
    extent_map: &MftExtentMap,
    bitmap: Option<&crate::platform::MftBitmap>,
    chunk_size: usize,
    record_size: usize,
    total_bytes: usize,
) -> (Vec<ReadChunk>, u64) {
    let mut sorted_chunks: Vec<ReadChunk> = generate_read_chunks(extent_map, bitmap, chunk_size);
    sorted_chunks.sort_by_key(|chunk| chunk.disk_offset);

    let record_size_u64 = usize_to_u64(record_size);
    let bytes_to_read: u64 = sorted_chunks
        .iter()
        .map(|chunk| {
            let effective_records = chunk.record_count - chunk.skip_begin - chunk.skip_end;
            effective_records * record_size_u64
        })
        .sum();

    let savings_pct = if total_bytes > 0 {
        100 - (bytes_to_read * 100 / usize_to_u64(total_bytes))
    } else {
        0
    };

    info!(
        chunks = sorted_chunks.len(),
        bytes_to_read_mb = bytes_to_read / (1024 * 1024),
        savings_pct,
        "📊 Bitmap skip: reading {}MB of {}MB",
        bytes_to_read / (1024 * 1024),
        total_bytes / (1024 * 1024)
    );

    (sorted_chunks, bytes_to_read)
}

/// Phase 3a of [`ParallelMftReader::read_all_bulk_iocp`].
///
/// Submits every read for `sorted_chunks` against `overlapped_handle`,
/// breaking each chunk into `io_chunk_size`-sized async reads.  Returns
/// the number of in-flight operations so the drain phase knows how many
/// completions to wait for.
///
/// # Safety
///
/// Caller must ensure:
/// - `overlapped_handle` is a live overlapped-capable file handle associated
///   with the IOCP that drives the surrounding event loop.
/// - `mft_buffer` outlives every queued read (no `&mut` aliasing inside the
///   slices we hand to Windows until the drain phase observes the matching
///   completion).
#[expect(
    unsafe_code,
    reason = "FFI: ReadFile + raw OVERLAPPED initialisation for IOCP queue-up"
)]
unsafe fn queue_bulk_iocp_reads(
    overlapped_handle: HANDLE,
    sorted_chunks: &[ReadChunk],
    mft_buffer: &mut AlignedBuffer,
    record_size: usize,
    io_chunk_size: usize,
    bytes_to_read: u64,
) -> Result<usize> {
    use core::pin::Pin;

    // Pin all overlapped structs for pointer stability.
    //
    // The collection is the lifetime owner: each `op` we push contains the
    // `OVERLAPPED` struct that Windows holds a raw pointer to until the
    // IOCP completion is dequeued.  Dropping any element early would
    // invalidate that pointer, so we never read the collection back — we
    // simply keep it alive across the whole IOCP wait loop.
    #[expect(
        clippy::collection_is_never_read,
        reason = "OVERLAPPED structs must be kept alive until IOCP completes; this Vec is the lifetime owner"
    )]
    let mut operations: Vec<Pin<Box<BulkOverlappedRead>>> =
        Vec::with_capacity((frs_to_usize(bytes_to_read) / io_chunk_size) + sorted_chunks.len());
    let mut pending_count = 0_usize;

    for chunk in sorted_chunks {
        let skip_begin_bytes = frs_to_usize(chunk.skip_begin) * record_size;
        let effective_records = chunk.record_count - chunk.skip_begin - chunk.skip_end;
        if effective_records == 0 {
            continue;
        }

        let effective_bytes = frs_to_usize(effective_records) * record_size;
        let chunk_disk_offset = chunk.disk_offset + usize_to_u64(skip_begin_bytes);
        let chunk_buffer_offset = frs_to_usize(chunk.start_frs) * record_size + skip_begin_bytes;

        let mut offset_within_chunk = 0_usize;
        while offset_within_chunk < effective_bytes {
            let remaining = effective_bytes - offset_within_chunk;
            let io_size = remaining.min(io_chunk_size);
            let disk_offset = chunk_disk_offset + usize_to_u64(offset_within_chunk);
            let buffer_offset = chunk_buffer_offset + offset_within_chunk;

            // SAFETY: caller holds the live overlapped handle; `mft_buffer`
            // outlives the drain phase; `operations` keeps each pinned op
            // alive until the matching IOCP completion has been processed.
            let op = unsafe {
                queue_one_bulk_read(
                    overlapped_handle,
                    mft_buffer,
                    disk_offset,
                    buffer_offset,
                    io_size,
                )
            }?;
            operations.push(op);
            pending_count += 1;
            offset_within_chunk += io_size;
        }
    }

    Ok(pending_count)
}

/// Submit one async [`ReadFile`] for the bulk queue-up phase and return
/// the pinned [`BulkOverlappedRead`] that owns the in-flight `OVERLAPPED`.
///
/// # Safety
///
/// Same contract as [`queue_bulk_iocp_reads`].
#[expect(unsafe_code, reason = "FFI: ReadFile + raw OVERLAPPED initialisation")]
unsafe fn queue_one_bulk_read(
    overlapped_handle: HANDLE,
    mft_buffer: &mut AlignedBuffer,
    disk_offset: u64,
    buffer_offset: usize,
    io_size: usize,
) -> Result<core::pin::Pin<Box<BulkOverlappedRead>>> {
    use core::pin::Pin;

    use windows::Win32::Foundation::{ERROR_IO_PENDING, GetLastError};
    use windows::Win32::Storage::FileSystem::ReadFile;

    let mut op: Pin<Box<BulkOverlappedRead>> = Box::pin(BulkOverlappedRead {
        // SAFETY: `OVERLAPPED` is a plain Windows FFI struct and an
        // all-zero value is the required initial state before offsets are set.
        overlapped: unsafe { core::mem::zeroed() },
    });

    set_overlapped_offset(&mut op.overlapped, disk_offset);

    // SAFETY: `buffer_offset` is computed from `chunk.start_frs *
    // record_size` and was bounded by upstream chunk validation to stay
    // within the `mft_buffer` allocation.
    let target_ptr = unsafe { mft_buffer.as_mut_slice().as_mut_ptr().add(buffer_offset) };
    // SAFETY: `target_ptr` is the start of an `io_size`-byte writable
    // region inside `mft_buffer`; the slice is only handed to Windows for
    // the duration of the async read.
    let target_slice = unsafe { core::slice::from_raw_parts_mut(target_ptr, io_size) };

    // SAFETY: caller's invariant: `overlapped_handle` is live;
    // `target_slice` covers `io_size` writable bytes; the OVERLAPPED
    // pointer remains valid because `op` stays pinned in the caller's
    // `operations` vector.
    let result = unsafe {
        ReadFile(
            overlapped_handle,
            Some(target_slice),
            None,
            Some(&raw mut op.overlapped),
        )
    };

    if result.is_err() {
        // SAFETY: `GetLastError` reads the calling thread's last-error
        // slot and does not dereference any Rust pointers.
        let last_error = unsafe { GetLastError() };
        if last_error != ERROR_IO_PENDING {
            return Err(MftError::Io(std::io::Error::from_raw_os_error(
                last_error.0.cast_signed(),
            )));
        }
    }

    Ok(op)
}

/// Phase 3b of [`ParallelMftReader::read_all_bulk_iocp`].
///
/// Spawns `num_workers` threads that each pump
/// `GetQueuedCompletionStatus` until `pending_count` completions have
/// been observed (or any thread sees a non-timeout error).  Returns the
/// total bytes transferred or surfaces the first Win32 error encountered.
fn drain_bulk_iocp_completions(
    iocp: &IoCompletionPort,
    pending_count: usize,
    num_workers: usize,
) -> Result<u64> {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    let bytes_read_total = Arc::new(AtomicU64::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    // Win32 error codes are `u32`; storing as `AtomicU32` keeps the i32
    // reinterpret for `from_raw_os_error` an exact bit-pattern cast.
    let error_flag: Arc<core::sync::atomic::AtomicU32> =
        Arc::new(core::sync::atomic::AtomicU32::new(0));

    // The IOCP HANDLE is `!Send`; ferry it across worker boundaries as the raw
    // pointer address via `expose_provenance` / `with_exposed_provenance_mut`,
    // wrapped in `SendHandle` so the kernel-managed pointer satisfies `Send` /
    // `Sync`.  The orchestrator owns the IoCompletionPort for the full drain.
    let iocp_handle_raw = SendHandle(iocp.raw_handle().0.expose_provenance());

    let mut workers = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let bytes_read = Arc::clone(&bytes_read_total);
        let completed_count = Arc::clone(&completed);
        let error = Arc::clone(&error_flag);
        let pending = pending_count;
        let handle_raw = iocp_handle_raw;

        workers.push(std::thread::spawn(move || {
            // `iocp_handle_raw` was constructed from a live IOCP handle
            // owned by the orchestrator and outlives every worker.
            let iocp_handle = HANDLE(core::ptr::with_exposed_provenance_mut::<core::ffi::c_void>(
                handle_raw.0,
            ));
            bulk_iocp_drain_loop(iocp_handle, pending, &bytes_read, &completed_count, &error);
        }));
    }

    for worker in workers {
        // Explicit drop discards the must-use `JoinHandle::join` result
        // without ignoring it — we already surface real errors via
        // `error_flag` and don't need the worker-id payload here.
        drop(worker.join());
    }

    let error_code = error_flag.load(Ordering::Acquire);
    if error_code != 0 {
        // The atomic stored a `WIN32_ERROR` (`u32`); `u32::cast_signed`
        // reinterprets the same bit pattern as `i32` for
        // `from_raw_os_error` without a `cast_possible_wrap` expect.
        return Err(MftError::Io(std::io::Error::from_raw_os_error(
            error_code.cast_signed(),
        )));
    }

    Ok(bytes_read_total.load(Ordering::Acquire))
}

/// Per-worker drain loop used by [`drain_bulk_iocp_completions`].
///
/// Polls `GetQueuedCompletionStatus` with a 100 ms timeout so we can
/// notice both completion-count progress and sibling-thread errors,
/// updating the shared atomics accordingly.
#[expect(
    unsafe_code,
    reason = "FFI: GetQueuedCompletionStatus expects exclusive raw out-pointers"
)]
fn bulk_iocp_drain_loop(
    iocp_handle: HANDLE,
    pending: usize,
    bytes_read: &Arc<AtomicU64>,
    completed_count: &Arc<AtomicUsize>,
    error: &Arc<core::sync::atomic::AtomicU32>,
) {
    use windows::Win32::Foundation::GetLastError;
    use windows::Win32::System::IO::GetQueuedCompletionStatus;

    /// Win32 `WAIT_TIMEOUT` numeric value — used to distinguish a benign
    /// poll deadline from a real I/O error inside the worker loop.
    const WAIT_TIMEOUT_CODE: u32 = 258;

    loop {
        if completed_count.load(Ordering::Acquire) >= pending || error.load(Ordering::Acquire) != 0
        {
            break;
        }

        let mut bytes_transferred: u32 = 0;
        let mut completion_key: usize = 0;
        let mut overlapped_ptr: *mut windows::Win32::System::IO::OVERLAPPED = core::ptr::null_mut();

        // SAFETY: `iocp_handle` is live (caller's invariant) and all
        // out-pointers reference writable stack storage for the call.
        let result = unsafe {
            GetQueuedCompletionStatus(
                iocp_handle,
                &raw mut bytes_transferred,
                &raw mut completion_key,
                &raw mut overlapped_ptr,
                100,
            )
        };

        if result.is_ok() {
            bytes_read.fetch_add(u64::from(bytes_transferred), Ordering::Relaxed);
            let prev = completed_count.fetch_add(1, Ordering::AcqRel);
            if prev + 1 >= pending {
                break;
            }
            continue;
        }

        // SAFETY: `GetLastError` reads the calling thread's last-error
        // slot and does not dereference any Rust pointers.
        let last_error = unsafe { GetLastError() };
        if last_error.0 == WAIT_TIMEOUT_CODE {
            continue;
        }

        error.store(last_error.0, Ordering::Release);
        break;
    }
}

/// Phase 4-merge of [`ParallelMftReader::read_all_bulk_iocp`].
///
/// Parses every record in `buffer` in parallel via Rayon, applies fixup,
/// and pipes the results through [`MftRecordMerger`] for full extension
/// fidelity.
fn parse_bulk_buffer_with_merge(
    buffer: &mut [u8],
    bitmap: Option<&crate::platform::MftBitmap>,
    record_size: usize,
    estimated_records: usize,
) -> Vec<ParsedRecord> {
    let bytes_per_chunk = BULK_IOCP_RECORDS_PER_CHUNK * record_size;

    let results: Vec<Vec<ParseResult>> = buffer
        .par_chunks_mut(bytes_per_chunk)
        .enumerate()
        .map(|(chunk_idx, chunk)| {
            let start_frs = chunk_idx * BULK_IOCP_RECORDS_PER_CHUNK;
            parse_bulk_chunk_to_results(chunk, start_frs, record_size, bitmap)
        })
        .collect();

    let mut merger = MftRecordMerger::with_capacity(estimated_records);
    for chunk_results in results {
        for result in chunk_results {
            merger.add_result(result);
        }
    }
    merger.merge()
}

/// Phase 4-fast of [`ParallelMftReader::read_all_bulk_iocp`].
///
/// Parses every record in `buffer` in parallel via Rayon, applies fixup,
/// and skips extension records (~1% of files with many hard links / ADS).
/// ~15-25% faster on SSD than the merging path; ideal for file search.
fn parse_bulk_buffer_fast(
    buffer: &mut [u8],
    bitmap: Option<&crate::platform::MftBitmap>,
    record_size: usize,
    estimated_records: usize,
) -> Vec<ParsedRecord> {
    let bytes_per_chunk = BULK_IOCP_RECORDS_PER_CHUNK * record_size;

    let results: Vec<Vec<ParsedRecord>> = buffer
        .par_chunks_mut(bytes_per_chunk)
        .enumerate()
        .map(|(chunk_idx, chunk)| {
            let start_frs = chunk_idx * BULK_IOCP_RECORDS_PER_CHUNK;
            parse_bulk_chunk_to_records(chunk, start_frs, record_size, bitmap)
        })
        .collect();

    let mut all_records = Vec::with_capacity(estimated_records);
    for chunk_records in results {
        all_records.extend(chunk_records);
    }
    all_records
}

/// Per-Rayon-chunk worker for [`parse_bulk_buffer_with_merge`] — applies
/// fixup, calls [`parse_record_full`], and returns the [`ParseResult`]s
/// the merger should fold in.
fn parse_bulk_chunk_to_results(
    chunk: &mut [u8],
    start_frs: usize,
    record_size: usize,
    bitmap: Option<&crate::platform::MftBitmap>,
) -> Vec<ParseResult> {
    let mut results = Vec::new();
    let records_in_chunk = chunk.len() / record_size;

    for i in 0..records_in_chunk {
        let frs = usize_to_u64(start_frs + i);

        if let Some(bm) = bitmap
            && !bm.is_record_in_use(frs)
        {
            continue;
        }

        let offset = i * record_size;
        let Some(record_slice) = chunk.get_mut(offset..offset + record_size) else {
            break;
        };

        if !apply_fixup(record_slice) {
            continue;
        }

        let parsed = parse_record_full(record_slice, frs);
        if !matches!(parsed, ParseResult::Skip) {
            results.push(parsed);
        }
    }

    results
}

/// Per-Rayon-chunk worker for [`parse_bulk_buffer_fast`] — applies fixup,
/// calls [`parse_record`], and skips extensions / fixup failures
/// silently.
fn parse_bulk_chunk_to_records(
    chunk: &mut [u8],
    start_frs: usize,
    record_size: usize,
    bitmap: Option<&crate::platform::MftBitmap>,
) -> Vec<ParsedRecord> {
    let mut records = Vec::new();
    let records_in_chunk = chunk.len() / record_size;

    for i in 0..records_in_chunk {
        let frs = usize_to_u64(start_frs + i);

        if let Some(bm) = bitmap
            && !bm.is_record_in_use(frs)
        {
            continue;
        }

        let offset = i * record_size;
        let Some(record_slice) = chunk.get_mut(offset..offset + record_size) else {
            break;
        };

        if !apply_fixup(record_slice) {
            continue;
        }

        if let Some(record) = parse_record(record_slice, frs) {
            records.push(record);
        }
    }

    records
}
