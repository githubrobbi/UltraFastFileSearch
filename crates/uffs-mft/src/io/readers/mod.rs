// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Reader implementations and async I/O orchestration for MFT ingestion.
//!
//! The private `prelude` submodule consolidates the common imports every
//! reader needs (rayon traits, Win32 FFI, tracing macros, and the I/O-layer
//! types from `super::*`).  Children import it via `use super::prelude::*;`,
//! which clippy's `wildcard_imports` lint exempts because the module is
//! named `prelude`.

/// Re-exports the imports every reader needs (rayon traits, Win32 FFI,
/// tracing macros, and the I/O-layer types).  Children import via
/// `use super::prelude::*;`, exempt from `clippy::wildcard_imports`
/// because the module is named `prelude`.
#[cfg(windows)]
mod prelude {
    pub(super) use alloc::sync::Arc;
    pub(super) use core::cell::RefCell;
    pub(super) use core::sync::atomic::{AtomicU64, Ordering};

    pub(super) use rayon::prelude::*;
    pub(super) use tracing::{debug, info, trace, warn};
    pub(super) use windows::Win32::Foundation::HANDLE;
    pub(super) use windows::Win32::Storage::FileSystem::{FILE_BEGIN, ReadFile, SetFilePointerEx};

    pub(super) use super::zero_copy::parse_buffer_zero_copy_inner;
    pub(super) use crate::index::{
        frs_to_usize, millis_to_u64, nanos_to_u64, u32_as_usize, usize_to_u64,
    };
    pub(super) use crate::io::{
        AlignedBuffer, MftExtentMap, MftRecordMerger, ParseResult, ParsedColumns, ParsedRecord,
        ReadChunk, SECTOR_SIZE, SECTOR_SIZE_U64, apply_fixup, generate_precise_read_chunks,
        generate_read_chunks, parse_record, parse_record_full, parse_record_zero_alloc,
        process_record,
    };
    pub(super) use crate::{MftError, Result};
}

// Windows-specific readers (require HANDLE and Windows APIs)
#[cfg(windows)]
mod basic;
#[cfg(windows)]
mod iocp;
#[cfg(windows)]
pub(crate) mod mft_file;
/// Offset-read fallback: `OVERLAPPED` reads on the caller's existing
/// handle — the only rung that works on adopted broker handles.
#[cfg(windows)]
pub(crate) mod offset_fallback;
#[cfg(windows)]
mod pipelined;
#[cfg(windows)]
mod prefetch;
#[cfg(windows)]
mod streaming;
#[cfg(windows)]
mod zero_copy;

// Parallel reader available on all platforms (contains ChaosMftReader)
pub mod parallel;

// Reader re-exports.  The Windows IOCP readers (IocpMftReader,
// MultiVolumeIocpReader, VolumeState, prepare_volume_state) and the
// other specialized readers were Phase 2.5-demoted from pub in commit
// 1529cb162 — restored here to preserve their public API contracts.
// IoCompletionPort / OverlappedRead remain pub(crate) (always-internal
// FFI primitives).  MftRecordReader is pub(crate) (was always so).
#[cfg(windows)]
pub(crate) use basic::MftRecordReader;
#[cfg(windows)]
pub(crate) use iocp::{IoCompletionPort, OverlappedRead, set_overlapped_offset};
#[cfg(windows)]
pub use iocp::{
    IocpMftReader, MultiVolumeIoOp, MultiVolumeIocpReader, VolumeState, prepare_volume_state,
};
#[cfg(windows)]
pub use parallel::ParallelMftReader;
pub use parallel::ReadParseTiming;
#[cfg(windows)]
pub use pipelined::PipelinedMftReader;
#[cfg(windows)]
pub use prefetch::PrefetchMftReader;
#[cfg(windows)]
pub use streaming::StreamingMftReader;
