// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Runtime-mmap layout for compact-index columns.
//!
//! Phase 2b of the memory-tiering rollout (see
//! `docs/refactor/memory-tiering-implementation-plan.md` §3 Phase 2b).
//! Replaces the eager heap clone in `compact_cache::deserialize_compact`
//! for the two largest columns of [`crate::compact::DriveCompactIndex`]:
//! `records: Vec<CompactRecord>` and `names: Vec<u8>`.  Those columns
//! are materialised into a daemon-private runtime tempfile (managed
//! by [`uffs_security::runtime_dir`]) at page-aligned offsets, then
//! handed back as mmap-backed [`ColumnStorage`] views.  The other
//! columns (children CSR, trigram CSR, ext-names table) keep their
//! existing heap path — they're small relative to records + names
//! and not on the hot mmap path.
//!
//! # Why a runtime tempfile and not anonymous mmap
//!
//! Anonymous mmap (`memmap2::MmapMut::map_anon`) keeps decrypted
//! plaintext in process-private RAM forever — every byte counts
//! against RSS the same as a `Vec<u8>`, defeating the tiering
//! goal.  A *file-backed* mmap is page-cache-resident: the kernel
//! evicts cold pages under memory pressure and re-populates them
//! lazily on next access.  RSS drops in proportion to access
//! frequency, which is exactly Phase 2b's win.
//!
//! Encryption-at-rest is preserved by the lifecycle: the tempfile
//! lives in a daemon-private `<runtime_root>/<pid>/` directory
//! that's wiped on next startup (orphan sweep) and on Windows
//! flagged `FILE_FLAG_DELETE_ON_CLOSE` so the kernel unlinks it
//! even on `kill -9` / blue-screen.  See
//! [`uffs_security::runtime_dir`] for the cross-platform contract.
//!
//! # Layout
//!
//! ```text
//! offset 0                                               page-aligned
//! ┌───────────────────────────────────────────────────────────────────┐
//! │  records: [CompactRecord; N]   (records_count * size_of::<…>())   │
//! ├───────────────────────────────────────────────────────────────────┤
//! │  padding to next page                                              │
//! ├───────────────────────────────────────────────────────────────────┤
//! │  names: [u8; M]                                                   │
//! ├───────────────────────────────────────────────────────────────────┤
//! │  padding to next page (so total_len is a multiple of 4 KiB)        │
//! └───────────────────────────────────────────────────────────────────┘
//! ```
//!
//! `records` starts at offset 0 (trivially page-aligned).  `names`
//! starts at the next 4 KiB boundary after the records section.
//! Both are page-aligned, satisfying the `align_of::<T>() <= page_size`
//! requirement of `ColumnStorage::from_mmap_region` for any `T: Pod`.

use alloc::sync::Arc;
use core::mem::{align_of, size_of};
use std::fs::File;
use std::io::{self, Seek as _, SeekFrom, Write as _};

use memmap2::Mmap;

use crate::compact::CompactRecord;
use crate::compact_storage::{ColumnStorage, MmapRegionError};

/// Page size we align column starts to.  4 KiB matches the commodity
/// `x86_64` / `Apple Silicon` / Windows 11 page size; larger-page
/// targets (e.g. `Apple Silicon` macOS' 16 KiB user-space pages)
/// align *more* strictly than this so we stay sound there too.
///
/// Page alignment is required for two reasons:
///
/// 1. `ColumnStorage::from_mmap_region` validates that the mmap base `+
///    byte_offset` is `align_of::<T>()`-aligned.  4 KiB is at least as strict
///    as every primitive alignment we care about (`u8` = 1, `u32` = 4,
///    `CompactRecord` = 8 because of `u64` fields).
/// 2. Page-aligned column starts let the kernel evict whole pages cleanly under
///    pressure — no straddling makes the eviction granularity match the access
///    granularity.
const PAGE_SIZE: u64 = 4096;

// Compile-time guard: `CompactRecord`'s alignment must fit into
// `PAGE_SIZE`.  If a future version of `CompactRecord` ever bumps
// past 4 KiB alignment (vanishingly unlikely), this trips so we
// catch it at build time instead of at first runtime mmap.
const _: () = assert!(
    align_of::<CompactRecord>() as u64 <= PAGE_SIZE,
    "CompactRecord alignment must be <= PAGE_SIZE"
);

/// Layout descriptor for a runtime tempfile produced by
/// [`write_runtime_layout`] and consumed by [`load_from_runtime`].
///
/// All offsets are byte offsets from the start of the file.  The
/// layout is a pure value type — passing it across `serialize` /
/// `deserialize` boundaries (e.g. embedding it in a `manifest.json`
/// next to the runtime file) is straightforward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeLayout {
    /// Byte offset of the records column in the runtime file.  Always
    /// `0` in the current layout, but kept explicit so a future
    /// layout (e.g. a small fixed header) can shift it without
    /// changing the API.
    pub records_offset: u64,
    /// Number of `CompactRecord`s in the records column.  The byte
    /// length is `records_count * size_of::<CompactRecord>()`.
    pub records_count: usize,
    /// Byte offset of the names column.  Page-aligned and
    /// `>= records_offset + records_count * size_of::<CompactRecord>()`.
    pub names_offset: u64,
    /// Length of the names column in bytes.
    pub names_len: usize,
    /// Total file length in bytes (rounded up to the next page so the
    /// kernel's page-eviction granularity matches the file).
    pub total_len: u64,
}

impl RuntimeLayout {
    /// Byte length of the records column.
    ///
    /// Used by unit tests to verify layout arithmetic; not needed in the
    /// production hot path because `materialise_columns` computes lengths
    /// inline.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn records_bytes_len(&self) -> usize {
        self.records_count
            .saturating_mul(size_of::<CompactRecord>())
    }
}

/// Materialise the records + names columns into `file` at
/// page-aligned offsets.
///
/// `file` should be a freshly-opened, empty file
/// (typically `RuntimeFile::as_file_mut()` from
/// [`uffs_security::runtime_dir::RuntimeDir::create_owner_only`]).
/// This function:
///
/// 1. Computes a [`RuntimeLayout`] with `records` at offset 0 and `names` at
///    the next 4 KiB boundary.
/// 2. `set_len(total_len)` so the file is exactly the right size (the trailing
///    pad page is zero-filled by the kernel).
/// 3. Writes `records_bytes` at `records_offset` and `names_bytes` at
///    `names_offset`.
/// 4. `flush + sync_all` so the bytes are durable before the caller mmaps.
///
/// # Errors
///
/// Forwards any [`std::io::Error`] from `set_len`, `seek`, `write_all`,
/// `flush`, or `sync_all`.
///
/// # Examples
///
/// ```ignore
/// use uffs_core::compact_mmap::{write_runtime_layout, load_from_runtime};
/// use uffs_security::runtime_dir::{DefaultRuntimeDir, RuntimeDir, mmap_read_only};
/// use std::sync::Arc;
///
/// # fn demo(records_bytes: &[u8], names_bytes: &[u8])
/// #     -> Result<(), Box<dyn std::error::Error>> {
/// let dir = DefaultRuntimeDir::default();
/// let path = std::env::temp_dir().join("doctest.live");
/// // ensure parent dir exists with owner-only perms in production
/// let mut rf = dir.create_owner_only(&path)?;
/// let layout = write_runtime_layout(records_bytes, names_bytes, rf.as_file_mut())?;
/// let mmap = Arc::new(mmap_read_only(&rf)?);
/// let (records, names) = load_from_runtime(layout, mmap)?;
/// assert_eq!(records.len(), layout.records_count);
/// assert_eq!(names.len(), layout.names_len);
/// # let _ = std::fs::remove_file(&path);
/// # Ok(())
/// # }
/// ```
pub(crate) fn write_runtime_layout(
    records_bytes: &[u8],
    names_bytes: &[u8],
    file: &mut File,
) -> io::Result<RuntimeLayout> {
    let records_offset = 0_u64;
    let records_byte_len = u64_from_usize(records_bytes.len())?;
    let records_end = records_offset
        .checked_add(records_byte_len)
        .ok_or_else(|| io::Error::other("runtime layout: records byte length overflows u64"))?;
    let names_offset = align_up(records_end, PAGE_SIZE)?;
    let names_byte_len = u64_from_usize(names_bytes.len())?;
    let names_end = names_offset
        .checked_add(names_byte_len)
        .ok_or_else(|| io::Error::other("runtime layout: names byte length overflows u64"))?;
    let total_len = align_up(names_end, PAGE_SIZE)?;

    file.set_len(total_len)?;
    file.seek(SeekFrom::Start(records_offset))?;
    file.write_all(records_bytes)?;
    file.seek(SeekFrom::Start(names_offset))?;
    file.write_all(names_bytes)?;
    file.flush()?;
    file.sync_all()?;

    let records_count = records_bytes
        .len()
        .checked_div(size_of::<CompactRecord>())
        .unwrap_or(0);
    if records_count.saturating_mul(size_of::<CompactRecord>()) != records_bytes.len() {
        return Err(io::Error::other(
            "runtime layout: records_bytes length is not a multiple of size_of::<CompactRecord>()",
        ));
    }

    Ok(RuntimeLayout {
        records_offset,
        records_count,
        names_offset,
        names_len: names_bytes.len(),
        total_len,
    })
}

/// Build mmap-backed [`ColumnStorage<CompactRecord>`] +
/// [`ColumnStorage<u8>`] over `mmap` using `layout`.
///
/// Both returned columns share the `Arc<Mmap>`; the mmap is dropped
/// only when both columns release it.  Reads slice the mmap directly
/// via `bytemuck::cast_slice` — zero allocation, zero copy.
///
/// # Errors
///
/// Returns [`MmapRegionError`] if either column's byte range exceeds
/// the mmap or fails the alignment check.  Both indicate a bug in
/// [`write_runtime_layout`]'s page-alignment math (or a corrupted
/// runtime file from a different daemon version) rather than user
/// error, so the variant carries enough context to surface in logs.
pub(crate) fn load_from_runtime(
    layout: RuntimeLayout,
    mmap: Arc<Mmap>,
) -> Result<(ColumnStorage<CompactRecord>, ColumnStorage<u8>), MmapRegionError> {
    let records_offset = usize::try_from(layout.records_offset)
        .map_err(|_err: core::num::TryFromIntError| MmapRegionError::Overflow)?;
    let names_offset = usize::try_from(layout.names_offset)
        .map_err(|_err: core::num::TryFromIntError| MmapRegionError::Overflow)?;
    let records = ColumnStorage::<CompactRecord>::from_mmap_region(
        Arc::clone(&mmap),
        records_offset,
        layout.records_count,
    )?;
    let names = ColumnStorage::<u8>::from_mmap_region(mmap, names_offset, layout.names_len)?;
    Ok((records, names))
}

/// Round `value` up to the next multiple of `alignment`.
///
/// Returns an error if the result overflows `u64`.  `alignment` must
/// be a power of two and non-zero — both invariants are upheld
/// statically by the only caller (`PAGE_SIZE`), so this helper is
/// not robust to arbitrary inputs.
fn align_up(value: u64, alignment: u64) -> io::Result<u64> {
    debug_assert!(
        alignment.is_power_of_two() && alignment > 0,
        "align_up: alignment must be a non-zero power of two (got {alignment})",
    );
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or_else(|| io::Error::other("align_up overflow"))
}

/// Convert `usize` to `u64`, surfacing the impossible-on-64-bit
/// overflow as an `io::Error`.
fn u64_from_usize(value: usize) -> io::Result<u64> {
    u64::try_from(value)
        .map_err(|_err: core::num::TryFromIntError| io::Error::other("usize → u64 overflow"))
}

#[cfg(test)]
mod tests;
