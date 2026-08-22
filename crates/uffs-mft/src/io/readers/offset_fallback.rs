// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Fallback reader: `OVERLAPPED`-offset chunk reads on the volume handle
//! the caller **already holds** — no new opens, no IOCP.
//!
//! # Why this rung exists (2026-08 broker incident)
//!
//! Windows stores a file object's IOCP association in the object itself
//! (`FILE_OBJECT.CompletionContext`), not in the handle — and it is
//! one-shot: once any handle to the object has been associated with a
//! completion port, associating another port fails with
//! `ERROR_INVALID_PARAMETER` (0x80070057) for as long as the object
//! lives.  The Access Broker registry keeps its original volume handle
//! open for the daemon's lifetime and every read adopts a
//! `DuplicateHandle` copy of it, so they all share one file object: the
//! **first** IOCP read after startup claims the association and every
//! later one fails at `associate` time.
//!
//! The pre-existing fallbacks (`$MFT`-as-file, unbuffered re-open) both
//! open **new** handles — exactly the operation that needs the elevation
//! the broker exists to avoid — so in broker mode a failed IOCP read had
//! no working path at all: a drive whose compact cache was also unusable
//! stayed `Cold` forever (drive C, 2026-08-22).
//!
//! This reader closes that gap: `read_handle_at` carries the offset in
//! an `OVERLAPPED` with a per-read event, which works on the broker's
//! `FILE_FLAG_OVERLAPPED` duplicates (no synchronous file pointer) and
//! on plain synchronous handles alike, and never touches the file
//! object's completion context.  Chunking follows
//! [`MftExtentMap::read_plan`], whose extent/FRS math is host-tested.
//!
//! Sequential single-reader throughput is deliberately acceptable here:
//! this rung only runs after the primary IOCP read has already failed,
//! and correctness-of-last-resort beats parallelism.

#![cfg(windows)]

use tracing::info;
use windows::Win32::Foundation::HANDLE;

use crate::error::Result;
use crate::index::{frs_to_usize, u32_as_usize};
use crate::io::readers::mft_file::parse_chunk_records;
use crate::io::{AlignedBuffer, MftExtentMap};
use crate::parse::{MftRecordMerger, ParsedRecord};

/// Chunk ceiling for offset reads — matches the 4 MiB the `$MFT`-file
/// fallback streams in, large enough to amortise the per-read event.
const OFFSET_READ_CHUNK_BYTES: u64 = 4 * 1024 * 1024;

/// Read every allocated MFT record through `handle` using
/// `OVERLAPPED`-offset reads and parse them into `ParsedRecord`s.
///
/// `handle` may be any readable volume handle — including an adopted
/// Access-Broker duplicate, the case the IOCP readers cannot serve
/// twice (see the module docs).  The caller keeps ownership of the
/// handle.
///
/// # Errors
///
/// Returns [`crate::error::MftError`] when any chunk read fails
/// (`ReadFile` / `GetOverlappedResult` / short read).  Records that
/// fail NTFS fixup are skipped, matching every other reader.
pub(crate) fn read_mft_via_offset_reads(
    handle: HANDLE,
    extent_map: &MftExtentMap,
    record_size: u32,
    total_records: u64,
) -> Result<Vec<ParsedRecord>> {
    let record_size_usize = u32_as_usize(record_size);
    let plan = extent_map.read_plan(OFFSET_READ_CHUNK_BYTES, total_records);

    info!(
        reads = plan.len(),
        total_records,
        extents = extent_map.extent_count(),
        "📖 Offset-read fallback: OVERLAPPED reads on the existing volume handle"
    );

    let mut merger = MftRecordMerger::with_capacity(frs_to_usize(total_records));
    let mut buffer = AlignedBuffer::new(0);
    for read in &plan {
        // `byte_len` ≤ OFFSET_READ_CHUNK_BYTES, so the narrowing always
        // succeeds; `unwrap_or(0)` keeps the no-panic policy and turns an
        // impossible overflow into a skipped (empty) read.
        let byte_len = usize::try_from(read.byte_len).unwrap_or(0);
        let record_count = byte_len / record_size_usize;
        if record_count == 0 {
            continue;
        }
        if buffer.len() < byte_len {
            buffer = AlignedBuffer::new(byte_len);
        }
        let Some(chunk) = buffer.as_mut_slice().get_mut(..byte_len) else {
            // Unreachable: the buffer was just sized to ≥ byte_len.
            continue;
        };
        crate::platform::read_handle_at(handle, read.volume_offset, chunk)?;
        parse_chunk_records(
            chunk,
            record_size_usize,
            read.base_frs,
            record_count,
            &mut merger,
        );
    }

    let records = merger.merge();
    info!(records = records.len(), "✅ Offset-read fallback complete");
    Ok(records)
}
