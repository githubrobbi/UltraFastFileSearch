// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Windows-only MFT capture implementations: streaming save and IOCP capture.
//!
//! Extracted from `persistence.rs` to keep it under the 800 LOC threshold.
//! Both functions are `impl MftReader` methods that require a live volume
//! handle.
//!
//! All `as usize` casts in this file go through the centralized
//! `frs_to_usize` / `u32_as_usize` / `usize_to_u64` helpers so the NTFS
//! disk-offset and record-size domain invariants stay encoded at the call
//! site instead of in a module-scoped lint suppression.

#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
use tracing::{debug, info};

#[cfg(windows)]
use super::MftReader;
#[cfg(windows)]
use crate::error::{MftError, Result};
#[cfg(windows)]
use crate::index::frs_to_usize;

#[cfg(windows)]
impl MftReader {
    /// Internal streaming save implementation.
    pub(super) fn save_raw_streaming<P: AsRef<Path>>(
        &self,
        path: P,
        options: &crate::raw::SaveRawOptions,
    ) -> Result<crate::raw::RawMftHeader> {
        use std::thread;

        use crossbeam_channel::{Receiver, Sender, bounded};

        use crate::io::{MftExtentMap, generate_read_chunks};
        use crate::platform::detect_drive_type;
        use crate::raw::StreamingRawMftWriter;

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

        let drive_type = detect_drive_type(self.volume);
        let chunk_size = match drive_type {
            crate::platform::DriveType::Nvme | crate::platform::DriveType::Ssd => 8 * 1024 * 1024,
            crate::platform::DriveType::Hdd
            | crate::platform::DriveType::Removable
            | crate::platform::DriveType::Virtual
            | crate::platform::DriveType::Unknown => 4 * 1024 * 1024,
        };

        let chunks = generate_read_chunks(&extent_map, None, chunk_size);
        let total_chunks = chunks.len();
        info!(
            "Streaming save: {} chunks, {} MB each, drive type: {:?}",
            total_chunks,
            chunk_size / (1024 * 1024),
            drive_type
        );

        let mut writer = StreamingRawMftWriter::new(path, record_size, options)?;
        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = bounded(2);
        let handle_ptr = vol_handle.raw_handle().0.expose_provenance();
        let record_size_copy = record_size;

        let reader_handle = thread::spawn(move || -> Result<()> {
            streaming_capture_read_loop(handle_ptr, chunks, record_size_copy, chunk_size, &tx)
        });

        let mut chunks_written: usize = 0;
        for data in rx {
            writer.write_chunk(&data)?;
            chunks_written += 1;

            if chunks_written.is_multiple_of(100) {
                debug!(
                    "Streaming save progress: {}/{} chunks",
                    chunks_written, total_chunks
                );
            }
        }

        match reader_handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                return Err(MftError::Io(std::io::Error::other(
                    "Reader thread panicked",
                )));
            }
        }

        let header = writer.finish()?;
        info!(
            "Streaming save complete: {} records, {} bytes",
            header.record_count, header.original_size
        );
        Ok(header)
    }

    /// Internal IOCP capture implementation.
    #[expect(
        unsafe_code,
        reason = "FFI: ReadFile, GetQueuedCompletionStatus for overlapped IOCP capture"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "IOCP capture event loop: queue → drain pipeline shares OVERLAPPED slots, the buffer pool, and the streaming-writer state across the queue, drain, and finish phases. Splitting into helpers would either inline the same control flow back or smear shared mutable state across multiple call sites and obscure IOCP-fairness invariants"
    )]
    pub(super) fn save_iocp_internal<P: AsRef<Path>>(
        &self,
        path: P,
        options: &crate::raw_iocp::IocpCaptureOptions,
    ) -> Result<crate::raw_iocp::IocpCaptureHeader> {
        use alloc::collections::VecDeque;
        use core::pin::Pin;

        use windows::Win32::Foundation::{CloseHandle, HANDLE};

        use crate::io::{IoCompletionPort, OverlappedRead, SECTOR_SIZE};
        use crate::raw_iocp::IocpCaptureWriter;

        let vol_handle = self.require_handle()?;
        let record_size = vol_handle.file_record_size();
        let concurrency = usize::from(options.concurrency);

        let (chunks, chunk_size) = plan_iocp_capture_chunks(vol_handle, self.volume, record_size);
        let num_chunks = chunks.len();

        if num_chunks == 0 {
            let writer = IocpCaptureWriter::new(record_size, options);
            return writer.write_to_file(path);
        }

        info!(
            chunks = num_chunks,
            chunk_size_mb = chunk_size / (1024 * 1024),
            concurrency,
            "🎯 Starting IOCP capture with {} concurrent reads",
            concurrency
        );

        // Create capture writer
        let mut writer = IocpCaptureWriter::new(record_size, options);

        // IOCP requires FILE_FLAG_OVERLAPPED, so we need a separate handle
        let handle: HANDLE = vol_handle.open_overlapped_handle()?;

        // Create IOCP and associate overlapped handle
        let iocp = IoCompletionPort::new(0)?;
        if let Err(err) = iocp.associate(handle, 0) {
            // SAFETY: handle was successfully opened by open_overlapped_handle
            _ = unsafe { CloseHandle(handle) };
            return Err(err);
        }

        // Pre-allocate buffer pool and in-flight operations
        let max_chunk_size = chunks
            .iter()
            .map(|chunk| chunk.record_count * u64::from(record_size))
            .max()
            .map_or(chunk_size, frs_to_usize);

        // Don't sort chunks - we want to capture IOCP completion order
        let mut pending_chunks: VecDeque<crate::io::ReadChunk> = chunks.into_iter().collect();
        let mut in_flight: Vec<Option<Pin<Box<OverlappedRead>>>> =
            (0..concurrency).map(|_| None).collect();

        // Issue initial reads
        // SAFETY: `handle` is live (opened by `open_overlapped_handle`
        // above) and `in_flight` is freshly allocated all-`None`.
        if let Err(err) = unsafe {
            prime_in_flight_reads(
                handle,
                record_size,
                max_chunk_size + SECTOR_SIZE,
                &mut pending_chunks,
                &mut in_flight,
            )
        } {
            // SAFETY: handle opened above, no further use.
            _ = unsafe { CloseHandle(handle) };
            return Err(err);
        }

        // Process completions in the order they arrive
        let mut completed_chunks = 0;
        while completed_chunks < num_chunks {
            // SAFETY: `iocp` is the live completion port that all in-flight
            // ops are associated with; `in_flight` is the slot vector those
            // ops live in.
            let (slot_idx, op) = match unsafe { wait_for_completion(&iocp, &mut in_flight) } {
                Ok(Some(pair)) => pair,
                Ok(None) => continue,
                Err(err) => {
                    // SAFETY: handle opened above, no further use.
                    _ = unsafe { CloseHandle(handle) };
                    return Err(err);
                }
            };

            match record_completed_chunk(&op, record_size, &mut writer) {
                Ok(()) => {
                    completed_chunks += 1;
                    debug!(
                        "Captured chunk {} of {} (FRS {}..{})",
                        completed_chunks,
                        num_chunks,
                        op.chunk.start_frs,
                        op.chunk.start_frs + op.chunk.record_count
                    );
                }
                Err(err) => {
                    // SAFETY: handle opened above, no further use.
                    _ = unsafe { CloseHandle(handle) };
                    return Err(err);
                }
            }

            // Issue next read if available
            if let Some(next_chunk) = pending_chunks.pop_front() {
                // SAFETY: `handle` is live and `slot_idx` was just emptied
                // (we `take()`d the previous op above).
                match unsafe {
                    issue_overlapped_read(
                        handle,
                        next_chunk,
                        record_size,
                        max_chunk_size + SECTOR_SIZE,
                        slot_idx,
                    )
                } {
                    Ok(new_op) => {
                        if let Some(slot) = in_flight.get_mut(slot_idx) {
                            *slot = Some(new_op);
                        }
                    }
                    Err(err) => {
                        // SAFETY: handle opened above, no further use.
                        _ = unsafe { CloseHandle(handle) };
                        return Err(err);
                    }
                }
            }
        }

        info!(
            "IOCP capture complete: {} chunks in completion order",
            writer.chunk_count()
        );

        // Close the overlapped handle before writing the file
        // SAFETY: handle was opened by open_overlapped_handle and is no longer needed
        _ = unsafe { CloseHandle(handle) };

        writer.write_to_file(path)
    }
}

/// Issue an [`issue_overlapped_read`] for every empty slot in `in_flight`,
/// draining `pending_chunks`.  Used at the start of an IOCP capture run
/// before the completion-port pump takes over.
///
/// # Safety
///
/// Caller must ensure `handle` is a live overlapped file handle associated
/// with the IOCP that drives the surrounding event loop, and that no slot
/// in `in_flight` already has an in-flight read.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "FFI: forwards to issue_overlapped_read which submits ReadFile"
)]
unsafe fn prime_in_flight_reads(
    handle: windows::Win32::Foundation::HANDLE,
    record_size: u32,
    buffer_size: usize,
    pending_chunks: &mut alloc::collections::VecDeque<crate::io::ReadChunk>,
    in_flight: &mut [Option<core::pin::Pin<Box<crate::io::OverlappedRead>>>],
) -> Result<()> {
    for (slot_idx, slot) in in_flight.iter_mut().enumerate() {
        let Some(chunk) = pending_chunks.pop_front() else {
            break;
        };
        // SAFETY: caller guarantees `handle` is live and the slot is empty.
        let op =
            unsafe { issue_overlapped_read(handle, chunk, record_size, buffer_size, slot_idx) }?;
        *slot = Some(op);
    }
    Ok(())
}

/// Build the `(chunks, chunk_size)` plan for the IOCP capture.
///
/// Falls back to a single-extent plan based on `mft_valid_data_length` when
/// `get_mft_extents` fails (matches legacy behaviour from before the
/// extraction).  `chunk_size` comes from the drive's optimal-chunk hint.
#[cfg(windows)]
fn plan_iocp_capture_chunks(
    vol_handle: &crate::platform::VolumeHandle,
    volume: crate::platform::DriveLetter,
    record_size: u32,
) -> (Vec<crate::io::ReadChunk>, usize) {
    use crate::io::{MftExtentMap, generate_read_chunks};
    use crate::platform::detect_drive_type;

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
    let drive_type = detect_drive_type(volume);
    let chunk_size = drive_type.optimal_chunk_size();
    let chunks = generate_read_chunks(&extent_map, None, chunk_size);
    (chunks, chunk_size)
}

/// Block on `GetQueuedCompletionStatus` for `iocp`, locate the slot whose
/// pinned [`crate::io::OverlappedRead`] matches the returned OVERLAPPED
/// pointer, and take ownership of that op out of `in_flight`.
///
/// Returns:
/// - `Ok(Some((slot_idx, op)))` for a normal completion.
/// - `Ok(None)` when the completion does not correspond to any tracked slot
///   (caller should `continue` the event loop).
/// - `Err(_)` for unrecoverable IOCP failures (caller cleans up the overlapped
///   handle and propagates the error).
///
/// # Safety
///
/// Caller must ensure `iocp` is the live completion port that every
/// `Some(_)` entry in `in_flight` is associated with.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "FFI: GetQueuedCompletionStatus expects exclusive raw out-pointers"
)]
unsafe fn wait_for_completion(
    iocp: &crate::io::IoCompletionPort,
    in_flight: &mut [Option<core::pin::Pin<Box<crate::io::OverlappedRead>>>],
) -> Result<Option<(usize, core::pin::Pin<Box<crate::io::OverlappedRead>>)>> {
    use windows::Win32::System::IO::GetQueuedCompletionStatus;

    let mut bytes_transferred: u32 = 0;
    let mut completion_key: usize = 0;
    let mut overlapped_ptr: *mut windows::Win32::System::IO::OVERLAPPED = core::ptr::null_mut();

    // SAFETY: `iocp.raw_handle()` is a valid IOCP handle (caller's
    // invariant); the four out-parameters are exclusive mutable
    // references to local variables that live for the call.
    let status = unsafe {
        GetQueuedCompletionStatus(
            iocp.raw_handle(),
            &raw mut bytes_transferred,
            &raw mut completion_key,
            &raw mut overlapped_ptr,
            u32::MAX,
        )
    };

    if status.is_err() && overlapped_ptr.is_null() {
        return Err(MftError::Io(std::io::Error::last_os_error()));
    }

    let mut completed_slot_idx: Option<usize> = None;
    for (idx, slot) in in_flight.iter_mut().enumerate() {
        if let Some(op) = slot.as_mut()
            && op.as_mut().as_overlapped_ptr() == overlapped_ptr
        {
            completed_slot_idx = Some(idx);
            break;
        }
    }

    let Some(slot_idx) = completed_slot_idx else {
        return Ok(None);
    };

    let Some(op_slot) = in_flight.get_mut(slot_idx) else {
        return Ok(None);
    };
    let Some(op) = op_slot.take() else {
        return Ok(None);
    };

    Ok(Some((slot_idx, op)))
}

/// Slice the unaligned chunk payload out of the completed
/// [`crate::io::OverlappedRead`]'s buffer, hand the bytes to `writer`, and
/// return `Ok(())` on success.
///
/// Returns [`MftError::Io`] when the buffer is shorter than the expected
/// post-alignment payload (which would indicate a short read or buffer-
/// sizing bug upstream).
#[cfg(windows)]
fn record_completed_chunk(
    op: &crate::io::OverlappedRead,
    record_size: u32,
    writer: &mut crate::raw_iocp::IocpCaptureWriter,
) -> Result<()> {
    use crate::io::SECTOR_SIZE_U64;

    let chunk = &op.chunk;
    let read_size = chunk.record_count * u64::from(record_size);
    let aligned_offset = (chunk.disk_offset / SECTOR_SIZE_U64) * SECTOR_SIZE_U64;
    let offset_adjustment = frs_to_usize(chunk.disk_offset - aligned_offset);

    let data = op
        .buffer
        .as_slice()
        .get(offset_adjustment..offset_adjustment + frs_to_usize(read_size))
        .ok_or_else(|| {
            MftError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "IOCP capture read produced fewer bytes than expected",
            ))
        })?
        .to_vec();

    writer.record_chunk(chunk.start_frs, data);
    Ok(())
}

/// Allocate an aligned buffer for `chunk`, wrap it in a pinned
/// [`crate::io::OverlappedRead`], submit a `ReadFile` against `handle`, and
/// return the pinned op so the caller can park it in their `in_flight` slot.
///
/// `buffer_size` must already include the [`crate::io::SECTOR_SIZE`] head-room
/// required for sector-aligned reads.  `slot_idx` is forwarded to the
/// [`crate::io::OverlappedRead`] for completion-port routing.
///
/// On `ERROR_IO_PENDING` the read is considered successfully queued.
/// Any other failure is returned as [`MftError::Io`] without closing
/// `handle`; callers are responsible for cleaning up.
///
/// # Safety
///
/// Caller must guarantee:
/// - `handle` is a live overlapped file handle associated with the completion
///   port that drives the surrounding event loop.
/// - The returned [`crate::io::OverlappedRead`] outlives the in-flight read
///   until `GetQueuedCompletionStatus` reports its completion.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "FFI: ReadFile + pinned OVERLAPPED reborrow for IOCP capture"
)]
unsafe fn issue_overlapped_read(
    handle: windows::Win32::Foundation::HANDLE,
    chunk: crate::io::ReadChunk,
    record_size: u32,
    buffer_size: usize,
    slot_idx: usize,
) -> Result<core::pin::Pin<Box<crate::io::OverlappedRead>>> {
    use core::pin::Pin;

    use windows::Win32::Foundation::{ERROR_IO_PENDING, GetLastError};
    use windows::Win32::Storage::FileSystem::ReadFile;

    use crate::io::{AlignedBuffer, OverlappedRead, SECTOR_SIZE, SECTOR_SIZE_U64};

    let buffer = AlignedBuffer::new(buffer_size);
    let mut op: Pin<Box<OverlappedRead>> =
        Box::pin(OverlappedRead::new(buffer, chunk, record_size, slot_idx));

    let aligned_offset = (op.chunk.disk_offset / SECTOR_SIZE_U64) * SECTOR_SIZE_U64;
    op.set_offset(aligned_offset);

    let read_size = op.chunk.record_count * u64::from(record_size);
    let offset_adjustment = frs_to_usize(op.chunk.disk_offset - aligned_offset);
    let aligned_size =
        (frs_to_usize(read_size) + offset_adjustment).div_ceil(SECTOR_SIZE) * SECTOR_SIZE;

    // SAFETY: `op` is a pinned Box with this thread as the sole writer; the
    // overlapped raw pointer is consumed before the second mutable reborrow.
    let overlapped_ptr = unsafe { op.as_mut().get_unchecked_mut().as_overlapped_ptr() };
    // SAFETY: same justification as above — pinned Box, sole writer.
    let op_mut = unsafe { op.as_mut().get_unchecked_mut() };
    let Some(read_slice) = op_mut.buffer.as_mut_slice().get_mut(..aligned_size) else {
        // Unreachable: caller sizes `buffer_size` to `max_chunk_size + SECTOR_SIZE` ≥
        // aligned_size.
        return Err(MftError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "IOCP capture buffer shorter than aligned_size",
        )));
    };
    // SAFETY: caller guarantees `handle` is a live overlapped handle;
    // `read_slice` spans `aligned_size` writable bytes; `overlapped_ptr`
    // points to `op`'s pinned OVERLAPPED struct.
    let read_result = unsafe { ReadFile(handle, Some(read_slice), None, Some(overlapped_ptr)) };

    if read_result.is_err() {
        // SAFETY: thread-local Win32 last-error read; no preconditions.
        let err = unsafe { GetLastError() };
        if err != ERROR_IO_PENDING {
            return Err(MftError::Io(std::io::Error::from_raw_os_error(
                err.0.cast_signed(),
            )));
        }
    }

    Ok(op)
}

/// Reader-thread loop for [`MftReader::save_raw_streaming`].
///
/// Sequentially reads each `chunk` into an aligned buffer using
/// `SetFilePointerEx` + `ReadFile`, then forwards the unaligned record
/// payload over `tx`.  Returns early if the receiver disconnects.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "FFI: SetFilePointerEx and ReadFile for streaming capture reader thread"
)]
fn streaming_capture_read_loop(
    handle_ptr: usize,
    chunks: Vec<crate::io::ReadChunk>,
    record_size: u32,
    chunk_size: usize,
    tx: &crossbeam_channel::Sender<Vec<u8>>,
) -> Result<()> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{FILE_BEGIN, ReadFile, SetFilePointerEx};

    use crate::io::{AlignedBuffer, SECTOR_SIZE, SECTOR_SIZE_U64};

    // `handle_ptr` was produced by `expose_provenance()` on the original
    // `HANDLE`'s raw pointer; round-trip via `with_exposed_provenance_mut`
    // to recover the Win32 handle on the worker thread.
    let handle = HANDLE(core::ptr::with_exposed_provenance_mut::<core::ffi::c_void>(
        handle_ptr,
    ));
    let mut buffer = AlignedBuffer::new(chunk_size + SECTOR_SIZE);

    for chunk in chunks {
        let read_size = chunk.record_count * u64::from(record_size);
        let aligned_offset = (chunk.disk_offset / SECTOR_SIZE_U64) * SECTOR_SIZE_U64;
        let offset_adjustment = frs_to_usize(chunk.disk_offset - aligned_offset);
        let aligned_size =
            (frs_to_usize(read_size) + offset_adjustment).div_ceil(SECTOR_SIZE) * SECTOR_SIZE;

        if buffer.len() < aligned_size {
            buffer = AlignedBuffer::new(aligned_size);
        }

        let mut new_pos: i64 = 0;
        // SAFETY: `handle` is a live raw MFT handle and `new_pos` is valid
        // writable storage for the duration of this seek.
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

        let mut bytes_read: u32 = 0;
        let Some(read_slice) = buffer.as_mut_slice().get_mut(..aligned_size) else {
            // Unreachable: buffer was sized to ≥ aligned_size upstream.
            return Err(MftError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "capture buffer shorter than aligned_size",
            )));
        };
        // SAFETY: `handle` is live, the aligned buffer slice covers
        // `aligned_size` writable bytes, and `bytes_read` is a valid
        // out-parameter for the call.
        let read_result =
            unsafe { ReadFile(handle, Some(read_slice), Some(&raw mut bytes_read), None) };
        if read_result.is_err() {
            return Err(MftError::Io(std::io::Error::last_os_error()));
        }

        let actual_size = frs_to_usize(read_size);
        let data_slice = buffer
            .as_slice()
            .get(offset_adjustment..offset_adjustment + actual_size)
            .ok_or_else(|| {
                MftError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "capture read produced fewer bytes than expected",
                ))
            })?;
        let data = data_slice.to_vec();

        if tx.send(data).is_err() {
            // Receiver disconnected — main thread aborted; stop early.
            break;
        }
    }

    Ok(())
}
