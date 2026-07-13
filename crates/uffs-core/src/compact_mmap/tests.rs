// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit tests for [`super::compact_mmap`].
//!
//! Test strategy:
//!
//! * **End-to-end round-trips** through real [`DefaultRuntimeDir`] +
//!   [`mmap_read_only`] — the only sound way to construct a [`RuntimeFile`] is
//!   via the trait, and the only way to mmap it is via the safe wrapper.  Tests
//!   therefore exercise the full production code path on the host platform.
//! * **Layout invariants** asserted explicitly: records always at offset 0,
//!   names always page-aligned past records, `total_len` always page-aligned,
//!   both offsets satisfy `align_of::<T>()` for their column type.
//! * **Boundary cases**: empty records, empty names, both empty (a degenerate
//!   but valid layout).
//! * **Error paths**: misaligned record-byte length surfaces as `io::Error`,
//!   not a silent bug; oversized layout surfaces as
//!   `MmapRegionError::OutOfBounds` from the loader.

use alloc::sync::Arc;
use core::mem::size_of;

use tempfile::TempDir;
use uffs_security::runtime_dir::{DefaultRuntimeDir, RuntimeDir as _, mmap_read_only};

use super::{PAGE_SIZE, RuntimeLayout, load_from_runtime, write_runtime_layout};
use crate::compact::CompactRecord;
use crate::compact_storage::{ColumnStorage, MmapRegionError};

// ─────────────────────────────────────────────────────────────────────
// Fixture helpers.
// ─────────────────────────────────────────────────────────────────────

/// Build a deterministic synthetic record with `seed` fanned out
/// into the integer fields.  Two records with different seeds are
/// guaranteed distinct after `bytemuck::cast_slice` round-trip.
fn synth_record(seed: u32) -> CompactRecord {
    CompactRecord {
        size: u64::from(seed) * 1_000_000_u64,
        allocated: u64::from(seed) * 2_000_000_u64,
        treesize: u64::from(seed) * 3_000_000_u64,
        tree_allocated: u64::from(seed) * 4_000_000_u64,
        created: i64::from(seed),
        modified: i64::from(seed) + 1_i64,
        accessed: i64::from(seed) + 2_i64,
        file_ref: 0,
        name_offset: seed,
        flags: seed,
        parent_idx: seed,
        descendants: seed,
        name_len: u16::try_from(seed & 0xFFFF_u32).unwrap_or(0_u16),
        extension_id: u16::try_from((seed.wrapping_add(7)) & 0xFFFF_u32).unwrap_or(0_u16),
        path_len: u16::try_from((seed.wrapping_add(13)) & 0xFFFF_u32).unwrap_or(0_u16),
        name_first_byte: u8::try_from(seed & 0xFF_u32).unwrap_or(0_u8),
        _pad: [0_u8; 1],
    }
}

/// Run the full `create_owner_only` → [`write_runtime_layout`] →
/// [`mmap_read_only`] → [`load_from_runtime`] pipeline.  Returns
/// the layout + the loaded columns + the tempdir so the caller can
/// keep the tempdir alive for the duration of the assertions.
fn round_trip(
    records: &[CompactRecord],
    names: &[u8],
) -> (
    TempDir,
    RuntimeLayout,
    ColumnStorage<CompactRecord>,
    ColumnStorage<u8>,
) {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("compact_mmap.live");
    let dir = DefaultRuntimeDir::default();
    let mut rf = dir.create_owner_only(&path).expect("create");

    let records_bytes = bytemuck::cast_slice::<CompactRecord, u8>(records);
    let layout =
        write_runtime_layout(records_bytes, names, rf.as_file_mut()).expect("write layout");
    let mmap = Arc::new(mmap_read_only(&rf).expect("mmap"));
    let (records_col, names_col) = load_from_runtime(layout, mmap).expect("load");
    (tmp, layout, records_col, names_col)
}

// ─────────────────────────────────────────────────────────────────────
// Layout invariants.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn layout_places_records_at_offset_zero() {
    let records = [synth_record(1)];
    let (_tmp, layout, _r, _n) = round_trip(&records, b"hello");
    assert_eq!(layout.records_offset, 0_u64);
}

#[test]
fn layout_pads_names_offset_to_next_page() {
    // Records occupy 80 bytes — names must start at offset 4096.
    let records = [synth_record(1)];
    let (_tmp, layout, _r, _n) = round_trip(&records, b"x");
    assert_eq!(layout.records_count, 1);
    assert_eq!(layout.names_offset, PAGE_SIZE);
    assert_eq!(layout.names_offset % PAGE_SIZE, 0_u64);
}

#[test]
fn layout_total_len_is_page_aligned() {
    let records: Vec<CompactRecord> = (0..50_u32).map(synth_record).collect();
    let names = vec![0xAB_u8; 9000]; // straddles 2 pages
    let (_tmp, layout, _r, _n) = round_trip(&records, &names);
    assert_eq!(layout.total_len % PAGE_SIZE, 0_u64);
    // total_len must be at least names_offset + names_len.
    assert!(layout.total_len >= layout.names_offset + (names.len() as u64));
}

#[test]
fn layout_records_byte_len_matches_count() {
    let records: Vec<CompactRecord> = (0..7_u32).map(synth_record).collect();
    let (_tmp, layout, _r, _n) = round_trip(&records, b"");
    assert_eq!(layout.records_count, 7);
    assert_eq!(layout.records_bytes_len(), 7 * size_of::<CompactRecord>());
}

// ─────────────────────────────────────────────────────────────────────
// Round-trip equality.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn round_trip_records_byte_for_byte() {
    let original: Vec<CompactRecord> = (0..1024_u32).map(synth_record).collect();
    let (_tmp, _layout, records_col, _names_col) = round_trip(&original, b"");
    assert_eq!(records_col.len(), original.len());
    let original_bytes = bytemuck::cast_slice::<CompactRecord, u8>(&original);
    let loaded_bytes = bytemuck::cast_slice::<CompactRecord, u8>(records_col.as_slice());
    assert_eq!(loaded_bytes, original_bytes);
}

#[test]
fn round_trip_names_byte_for_byte() {
    let names: Vec<u8> = (0_u8..=u8::MAX).cycle().take(8192).collect();
    let (_tmp, _layout, _records_col, names_col) = round_trip(&[], &names);
    assert_eq!(names_col.as_slice(), names.as_slice());
}

#[test]
fn round_trip_with_realistic_proportions() {
    // ~10 K records (~800 KB) + ~1 MB of names.  Mirrors a small
    // drive on a typical workstation; exercises pages 0-N for
    // records and pages 1-K for names.
    let records: Vec<CompactRecord> = (0..10_000_u32).map(synth_record).collect();
    let names: Vec<u8> = (0..1_048_576_u32)
        .map(|i| u8::try_from(i & 0xFF_u32).unwrap_or(0_u8))
        .collect();
    let (_tmp, layout, records_col, names_col) = round_trip(&records, &names);

    assert_eq!(records_col.len(), 10_000, "record count round-trips");
    assert_eq!(names_col.len(), names.len(), "names length round-trips");
    // Layout invariants must hold even on realistic sizes — names
    // straddles many pages so this catches off-by-one padding bugs.
    assert!(
        layout.total_len >= layout.names_offset + (names.len() as u64),
        "total_len covers names section",
    );
    // Spot-check an interior record (boundary-of-page region) and
    // an interior name byte via Option-returning accessors.
    assert_eq!(
        records_col.get(5000).map(|record| record.size),
        Some(synth_record(5000).size),
        "interior record round-trips byte-for-byte",
    );
    let expected_name_byte = u8::try_from(524_288_u32 & 0xFF_u32).unwrap_or(0_u8);
    assert_eq!(
        names_col.get(524_288),
        Some(&expected_name_byte),
        "interior name byte round-trips",
    );
}

// ─────────────────────────────────────────────────────────────────────
// Boundary: empty inputs.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn round_trip_empty_records() {
    let (_tmp, layout, records_col, names_col) = round_trip(&[], b"hello");
    assert_eq!(layout.records_count, 0);
    assert_eq!(layout.records_offset, 0_u64);
    assert_eq!(layout.names_offset, 0_u64); // align_up(0, 4096) == 0
    assert!(records_col.is_empty());
    assert_eq!(names_col.as_slice(), b"hello");
}

#[test]
fn round_trip_empty_names() {
    let records = [synth_record(42)];
    let (_tmp, layout, records_col, names_col) = round_trip(&records, b"");
    assert_eq!(layout.records_count, 1);
    assert_eq!(layout.names_len, 0);
    assert!(names_col.is_empty());
    assert_eq!(
        records_col.first().map(|record| record.name_offset),
        Some(42_u32),
        "single record round-trips",
    );
}

#[test]
fn round_trip_both_empty() {
    let (_tmp, layout, records_col, names_col) = round_trip(&[], b"");
    assert_eq!(layout.records_count, 0);
    assert_eq!(layout.names_len, 0);
    assert!(records_col.is_empty());
    assert!(names_col.is_empty());
    // The runtime file is still page-aligned (just zero-length data
    // in two zero-length sections).
    assert_eq!(layout.total_len % PAGE_SIZE, 0_u64);
}

// ─────────────────────────────────────────────────────────────────────
// Error paths.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn write_runtime_layout_rejects_misaligned_records_byte_length() {
    // Pass a byte slice whose length is NOT a multiple of
    // size_of::<CompactRecord>() (80).  This would silently truncate
    // in `records_count` if we didn't check it; the function returns
    // an error instead.
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("misaligned.live");
    let dir = DefaultRuntimeDir::default();
    let mut rf = dir.create_owner_only(&path).expect("create");

    let bad_records_bytes = vec![0_u8; 81]; // 81 != multiple of 80
    let err = write_runtime_layout(&bad_records_bytes, b"", rf.as_file_mut())
        .expect_err("misaligned length must error");
    assert!(
        err.to_string().contains("size_of::<CompactRecord>()"),
        "error message should mention the size constraint, got: {err}"
    );
}

#[test]
fn load_from_runtime_rejects_layout_extending_past_mmap() {
    // Build a real layout but then forge a layout that claims more
    // records than the file actually holds.  load_from_runtime
    // should bounce it via MmapRegionError::OutOfBounds.
    let records = [synth_record(1)];
    let names = b"";
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("forged.live");
    let dir = DefaultRuntimeDir::default();
    let mut rf = dir.create_owner_only(&path).expect("create");
    let records_bytes = bytemuck::cast_slice::<CompactRecord, u8>(&records);
    let real = write_runtime_layout(records_bytes, names, rf.as_file_mut()).expect("write");
    let mmap = Arc::new(mmap_read_only(&rf).expect("mmap"));

    let forged = RuntimeLayout {
        records_offset: real.records_offset,
        records_count: 1_000_000, // way bigger than what's in the file
        names_offset: real.names_offset,
        names_len: real.names_len,
        total_len: real.total_len,
    };
    let err = load_from_runtime(forged, Arc::clone(&mmap)).expect_err("forged layout must reject");
    assert!(
        matches!(err, MmapRegionError::OutOfBounds { .. }),
        "expected OutOfBounds, got {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Sharing: both columns hold the same Arc<Mmap>; dropping one keeps
// the other readable.  This is the production layout — one mmap per
// runtime file, two columns over disjoint regions.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn dropping_one_column_keeps_the_other_readable() {
    let records: Vec<CompactRecord> = (0..16_u32).map(synth_record).collect();
    let names = b"keep me alive after records drop";
    let (_tmp, _layout, records_col, names_col) = round_trip(&records, names);

    // Collect a snapshot of the names so we can compare *after*
    // dropping records_col.
    let names_snapshot: Vec<u8> = names_col.as_slice().to_vec();
    drop(records_col);

    // names_col still works even though its Arc<Mmap> sibling is
    // gone — the Arc keeps the underlying Mmap alive.
    assert_eq!(names_col.as_slice(), names_snapshot.as_slice());
    assert_eq!(names_col.as_slice(), names);
}
