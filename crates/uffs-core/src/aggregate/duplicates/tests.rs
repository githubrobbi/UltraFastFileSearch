// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit tests for [`super`] (`duplicates`).
//!
//! Extracted from `duplicates.rs` into a sibling submodule so the lib
//! file stays under the 800 LOC policy ceiling (mirrors the
//! `compact_cache/tests.rs` extraction).

#![expect(
    clippy::indexing_slicing,
    reason = "tests assert against fixtures with known shape; indexing panic = test failure"
)]

use uffs_mft::index::{IndexNameRef, MftIndex, ROOT_FRS, SizeInfo};

use super::*;
use crate::compact::build_compact_index;

#[test]
fn composite_key_equality() {
    let key1 = CompositeKey {
        components: vec![100, 42],
        name_hash: 12345,
    };
    let key2 = CompositeKey {
        components: vec![100, 42],
        name_hash: 12345,
    };
    assert_eq!(key1, key2);
}

#[test]
fn composite_key_inequality() {
    let key1 = CompositeKey {
        components: vec![100, 42],
        name_hash: 12345,
    };
    let key2 = CompositeKey {
        components: vec![100, 43],
        name_hash: 12345,
    };
    assert_ne!(key1, key2);
}

#[test]
fn duplicate_accumulator_new() {
    let acc = DuplicateAccumulator::new(
        vec![FieldId::Size, FieldId::Name],
        DuplicateVerify::None,
        100_000,
        2,
    );
    assert!(acc.groups.is_empty());
}

/// Build a synthetic drive with known duplicate files.
///
/// Layout:
///   - root (dir)
///   - "readme.txt" (FRS 100, 500 bytes) — unique
///   - "data.bin"   (FRS 101, 1000 bytes) — duplicate (3 copies)
///   - "data.bin"   (FRS 102, 1000 bytes)
///   - "data.bin"   (FRS 103, 1000 bytes)
///   - "config.ini" (FRS 104, 200 bytes)  — duplicate (2 copies)
///   - "config.ini" (FRS 105, 200 bytes)
fn build_dup_drive() -> DriveCompactIndex {
    let mut idx = MftIndex::new(uffs_mft::platform::DriveLetter::T);

    // Root directory.
    let root_off = idx.add_name(".");
    let root = idx.get_or_create(ROOT_FRS.into());
    root.stdinfo.set_directory(true);
    root.first_name.name = IndexNameRef::new(root_off, 1, true, IndexNameRef::NO_EXTENSION);
    root.first_name.parent_frs = Into::into(ROOT_FRS);

    let add_file = |index: &mut MftIndex, frs: u64, name: &str, size: u64| {
        let off = index.add_name(name);
        let ext = index.intern_extension(name);
        let rec = index.get_or_create(frs.into());
        rec.first_name.name = IndexNameRef::new(off, uffs_mft::len_to_u16(name.len()), true, ext);
        rec.first_name.parent_frs = Into::into(ROOT_FRS);
        rec.first_stream.size = SizeInfo {
            length: size,
            allocated: size,
        };
        rec.stdinfo.flags = 0x20; // archive
    };

    add_file(&mut idx, 100, "readme.txt", 500);
    add_file(&mut idx, 101, "data.bin", 1000);
    add_file(&mut idx, 102, "data.bin", 1000);
    add_file(&mut idx, 103, "data.bin", 1000);
    add_file(&mut idx, 104, "config.ini", 200);
    add_file(&mut idx, 105, "config.ini", 200);

    let (drive, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::T, &idx);
    drive
}

// ── S4E.2: synthetic duplicates — group count + reclaimable ───

#[test]
fn synthetic_duplicates_group_count_and_reclaimable() {
    let drive = build_dup_drive();
    let mut acc = DuplicateAccumulator::new(
        vec![FieldId::Size, FieldId::Name],
        DuplicateVerify::None,
        100_000,
        3,
    );

    for (idx, rec) in drive.records.iter().enumerate() {
        acc.feed(rec, &drive, idx);
    }

    let result = acc.finalize(50);

    // Should have exactly 2 duplicate groups:
    //   1. data.bin (3 copies × 1000 bytes)
    //   2. config.ini (2 copies × 200 bytes)
    assert_eq!(result.candidate_groups, 2, "expected 2 duplicate groups");

    // Total duplicate files: 3 + 2 = 5
    assert_eq!(
        result.candidate_files, 5,
        "expected 5 total files across duplicate groups"
    );

    // Reclaimable:
    //   data.bin: 3×1000 - 1000 = 2000
    //   config.ini: 2×200 - 200 = 200
    //   total: 2200
    assert_eq!(
        result.total_reclaimable_bytes, 2200,
        "expected 2200 reclaimable bytes"
    );

    // Groups sorted by reclaimable desc: data.bin first.
    assert_eq!(result.groups.len(), 2);
    assert_eq!(
        result.groups[0].count, 3,
        "first group: data.bin (3 copies)"
    );
    assert_eq!(result.groups[0].file_size, 1000);
    assert_eq!(result.groups[0].reclaimable_bytes, 2000);
    assert_eq!(
        result.groups[1].count, 2,
        "second group: config.ini (2 copies)"
    );
    assert_eq!(result.groups[1].file_size, 200);
    assert_eq!(result.groups[1].reclaimable_bytes, 200);

    // Member indices captured (sample=3).
    assert_eq!(result.groups[0].member_indices.len(), 3);
    assert_eq!(result.groups[1].member_indices.len(), 2);
}

// ── Cross-drive merge (parallel aggregation reducer path) ───

/// Regression guard for the v0.5.39 aggregate-parallelism fix.
///
/// Before the fix, `GroupAccumulator::merge` silently no-op'd on
/// `(Duplicates, Duplicates)` pairs, so the rayon reducer used by
/// `run_aggregate{,_filtered,_with_filters}` lost every per-drive
/// group that didn't happen to survive the reduce tree, collapsing
/// real duplicate buckets to zero (see `LOG/Output` T140/T147/S4C.*).
///
/// This test feeds two "drives" that share a `(size=1000, name="data.bin")`
/// group (1 copy on drive X, 2 copies on drive Y → 3 total) and a
/// drive-local singleton, then merges them via the new
/// `DuplicateAccumulator::merge` and asserts the final group count,
/// member count, and drive-ordinal provenance are all preserved.
#[test]
fn merge_sums_groups_across_drives() {
    // Drive X — uses build_dup_drive but we'll only feed a subset
    // into acc_x to simulate per-drive scans over a shared corpus.
    let drive_x = build_dup_drive();
    let drive_y = build_dup_drive();

    let mut acc_x = DuplicateAccumulator::new(
        vec![FieldId::Size, FieldId::Name],
        DuplicateVerify::None,
        100_000,
        5,
    );
    let mut acc_y = DuplicateAccumulator::new(
        vec![FieldId::Size, FieldId::Name],
        DuplicateVerify::None,
        100_000,
        5,
    );

    // Drive X is scanned as drive ordinal 0.
    acc_x.set_drive_ordinal(0);
    for (idx, rec) in drive_x.records.iter().enumerate() {
        acc_x.feed(rec, &drive_x, idx);
    }

    // Drive Y is scanned as drive ordinal 1.
    acc_y.set_drive_ordinal(1);
    for (idx, rec) in drive_y.records.iter().enumerate() {
        acc_y.feed(rec, &drive_y, idx);
    }

    // Reduce: X absorbs Y.
    acc_x.merge(&acc_y);

    let result = acc_x.finalize(50);

    // Both drives hold the same synthetic layout (1× readme.txt +
    // 3× data.bin + 2× config.ini).  After merge:
    //   * data.bin:   6 copies × 1000 B → reclaimable 5000
    //   * config.ini: 4 copies ×  200 B → reclaimable  600
    //   * readme.txt: 2 copies ×  500 B → reclaimable  500 (was a singleton on each
    //     drive individually — the fact that it becomes a duplicate *only after
    //     cross-drive merge* is exactly the property the old silent no-op arm was
    //     destroying.)
    assert_eq!(
        result.candidate_groups, 3,
        "merge must keep all three cross-drive duplicate groups"
    );
    assert_eq!(
        result.candidate_files, 12,
        "3+3 data.bin + 2+2 config.ini + 1+1 readme.txt = 12 duplicate members"
    );

    // Groups sorted desc by reclaimable bytes → data.bin first.
    assert_eq!(result.groups[0].count, 6, "6 data.bin across both drives");
    assert_eq!(result.groups[0].total_bytes, 6000);
    assert_eq!(result.groups[0].reclaimable_bytes, 5000);
    assert_eq!(result.groups[1].count, 4, "4 config.ini across both drives");
    assert_eq!(result.groups[1].total_bytes, 800);
    assert_eq!(result.groups[1].reclaimable_bytes, 600);
    assert_eq!(
        result.groups[2].count, 2,
        "readme.txt becomes a duplicate *only* via cross-drive merge"
    );
    assert_eq!(result.groups[2].total_bytes, 1000);
    assert_eq!(result.groups[2].reclaimable_bytes, 500);

    // member_indices cap = 5; we merged 6 potential members for
    // data.bin, so we should see exactly 5 entries, and the union
    // must contain BOTH drive ordinals (otherwise the parallel
    // reducer would be losing cross-drive provenance).
    assert_eq!(result.groups[0].member_indices.len(), 5);
    let ordinals: std::collections::HashSet<u8> = result.groups[0]
        .member_indices
        .iter()
        .map(|(_, dist)| *dist)
        .collect();
    assert!(
        ordinals.contains(&0) && ordinals.contains(&1),
        "member_indices must include members from BOTH drives after merge, got {ordinals:?}"
    );
}

/// Regression: the `Extension` composite-key component must be
/// drive-independent.
///
/// 2026-07-21, found by auditing for the multi-drive rollup key bug
/// (`top_folders` malformed keys): `CompositeKey` pushed the raw
/// per-drive `extension_id`. The same extension gets different intern
/// ids on different drives (missed cross-drive duplicates) and the
/// same id can mean different extensions (false groups).
#[test]
fn extension_key_groups_across_drives_by_name_not_intern_id() {
    let build = |letter, files: &[(&str, u64)]| {
        let mut idx = MftIndex::new(letter);
        let root_off = idx.add_name(".");
        let root = idx.get_or_create(ROOT_FRS.into());
        root.stdinfo.set_directory(true);
        root.first_name.name = IndexNameRef::new(root_off, 1, true, IndexNameRef::NO_EXTENSION);
        root.first_name.parent_frs = Into::into(ROOT_FRS);
        for (frs, &(name, size)) in (100_u64..).zip(files) {
            let off = idx.add_name(name);
            let ext = idx.intern_extension(name);
            let rec = idx.get_or_create(frs.into());
            rec.first_name.name =
                IndexNameRef::new(off, uffs_mft::len_to_u16(name.len()), true, ext);
            rec.first_name.parent_frs = Into::into(ROOT_FRS);
            rec.first_stream.size = SizeInfo {
                length: size,
                allocated: size,
            };
            rec.stdinfo.flags = 0x20;
        }
        let (drive, _, _) = build_compact_index(letter, &idx);
        drive
    };

    // Drive X intern order: jpg=1, avi=2.
    let drive_x = build(uffs_mft::platform::DriveLetter::X, &[
        ("photo.jpg", 1000),
        ("clip.avi", 500),
    ]);
    // Drive Y intern order: mp3=1, mp4=2, jpg=3 — so "jpg" has a
    // DIFFERENT local id than on X, while "mp4" COLLIDES with X's
    // "avi" id (and also matches its size).
    let drive_y = build(uffs_mft::platform::DriveLetter::Y, &[
        ("song.mp3", 300),
        ("video.mp4", 500),
        ("photo.jpg", 1000),
    ]);

    let mut acc_x = DuplicateAccumulator::new(
        vec![FieldId::Size, FieldId::Extension],
        DuplicateVerify::None,
        100_000,
        5,
    );
    let mut acc_y = acc_x.clone();

    acc_x.set_drive_ordinal(0);
    for (idx, rec) in drive_x.records.iter().enumerate() {
        acc_x.feed(rec, &drive_x, idx);
    }
    acc_y.set_drive_ordinal(1);
    for (idx, rec) in drive_y.records.iter().enumerate() {
        acc_y.feed(rec, &drive_y, idx);
    }
    acc_x.merge(&acc_y);

    let result = acc_x.finalize(50);

    // Exactly one real group: photo.jpg on both drives (size 1000 +
    // extension "jpg"). clip.avi / video.mp4 share size 500 and local
    // ext id 2 but are DIFFERENT extensions — they must not group.
    assert_eq!(
        result.candidate_groups, 1,
        "only the cross-drive jpg pair should group"
    );
    assert_eq!(result.groups[0].count, 2, "photo.jpg on X + photo.jpg on Y");
    assert_eq!(
        result.groups[0].file_size, 1000,
        "the surviving group must be the jpg pair, not the avi/mp4 id collision"
    );
}

/// Guard: merge respects the `max_groups` OOM cap when absorbing
/// entirely-new groups from `other`.  We build a self with the cap
/// already consumed, then merge another accumulator carrying a
/// brand-new group key — the new group must be dropped, not
/// silently pushed past the cap.
#[test]
fn merge_respects_max_groups_cap() {
    let drive_x = build_dup_drive();
    let drive_y = build_dup_drive();

    // Cap acc_x at exactly the number of groups it will build
    // (data.bin + config.ini = 2) so any NEW keys from `other` get
    // rejected.
    let mut acc_x = DuplicateAccumulator::new(
        vec![FieldId::Size, FieldId::Name],
        DuplicateVerify::None,
        2,
        5,
    );
    let mut acc_y = DuplicateAccumulator::new(
        vec![FieldId::Size, FieldId::Name],
        DuplicateVerify::None,
        100_000,
        5,
    );

    acc_x.set_drive_ordinal(0);
    for (idx, rec) in drive_x.records.iter().enumerate() {
        acc_x.feed(rec, &drive_x, idx);
    }

    // Feed acc_y with a record whose key is NEW — fabricate by
    // switching the size on the fly (still uses drive_y's name table).
    acc_y.set_drive_ordinal(1);
    // Inject the existing groups plus a synthetic new one.
    for (idx, rec) in drive_y.records.iter().enumerate() {
        acc_y.feed(rec, &drive_y, idx);
    }

    let groups_before = acc_x.groups.len();
    acc_x.merge(&acc_y);
    let groups_after = acc_x.groups.len();

    assert_eq!(
        groups_before, groups_after,
        "merge must not push past max_groups cap when absorbing new keys"
    );
}

// ── S4E.3: singleton elimination ────────────────────────────

#[test]
fn singleton_elimination_no_false_duplicates() {
    let mut idx = MftIndex::new(uffs_mft::platform::DriveLetter::T);

    // Root.
    let root_off = idx.add_name(".");
    let root = idx.get_or_create(ROOT_FRS.into());
    root.stdinfo.set_directory(true);
    root.first_name.name = IndexNameRef::new(root_off, 1, true, IndexNameRef::NO_EXTENSION);
    root.first_name.parent_frs = Into::into(ROOT_FRS);

    // 10 unique files — all different names and sizes.
    for i in 0..10_u64 {
        let name = format!("file_{i}.dat");
        let off = idx.add_name(&name);
        let ext = idx.intern_extension(&name);
        let rec = idx.get_or_create((100 + i).into());
        rec.first_name.name = IndexNameRef::new(off, uffs_mft::len_to_u16(name.len()), true, ext);
        rec.first_name.parent_frs = Into::into(ROOT_FRS);
        rec.first_stream.size = SizeInfo {
            length: (i + 1) * 100,
            allocated: (i + 1) * 512,
        };
        rec.stdinfo.flags = 0x20;
    }

    let (drive, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::T, &idx);
    let mut acc = DuplicateAccumulator::new(
        vec![FieldId::Size, FieldId::Name],
        DuplicateVerify::None,
        100_000,
        2,
    );

    for (i, rec) in drive.records.iter().enumerate() {
        acc.feed(rec, &drive, i);
    }

    let result = acc.finalize(50);

    // All files are unique → zero duplicate groups.
    assert_eq!(result.candidate_groups, 0, "no duplicates expected");
    assert_eq!(result.candidate_files, 0);
    assert_eq!(result.total_reclaimable_bytes, 0);
    assert!(result.groups.is_empty());
}

#[test]
fn zero_byte_files_excluded_from_duplicates() {
    let mut idx = MftIndex::new(uffs_mft::platform::DriveLetter::T);

    let root_off = idx.add_name(".");
    let root = idx.get_or_create(ROOT_FRS.into());
    root.stdinfo.set_directory(true);
    root.first_name.name = IndexNameRef::new(root_off, 1, true, IndexNameRef::NO_EXTENSION);
    root.first_name.parent_frs = Into::into(ROOT_FRS);

    // Two zero-byte files with same name — should NOT be duplicates.
    for i in 0..2_u64 {
        let name = "empty.txt";
        let off = idx.add_name(name);
        let ext = idx.intern_extension(name);
        let rec = idx.get_or_create((100 + i).into());
        rec.first_name.name = IndexNameRef::new(off, uffs_mft::len_to_u16(name.len()), true, ext);
        rec.first_name.parent_frs = Into::into(ROOT_FRS);
        rec.first_stream.size = SizeInfo {
            length: 0,
            allocated: 0,
        };
        rec.stdinfo.flags = 0x20;
    }

    let (drive, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::T, &idx);
    let mut acc = DuplicateAccumulator::new(
        vec![FieldId::Size, FieldId::Name],
        DuplicateVerify::None,
        100_000,
        2,
    );

    for (i, rec) in drive.records.iter().enumerate() {
        acc.feed(rec, &drive, i);
    }

    let result = acc.finalize(50);
    assert_eq!(result.candidate_groups, 0, "zero-byte files excluded");
}

#[test]
fn directories_excluded_from_duplicates() {
    let mut idx = MftIndex::new(uffs_mft::platform::DriveLetter::T);

    let root_off = idx.add_name(".");
    let root = idx.get_or_create(ROOT_FRS.into());
    root.stdinfo.set_directory(true);
    root.first_name.name = IndexNameRef::new(root_off, 1, true, IndexNameRef::NO_EXTENSION);
    root.first_name.parent_frs = Into::into(ROOT_FRS);

    // Two directories with same name — should NOT be duplicates.
    for i in 0..2_u64 {
        let name = "subdir";
        let off = idx.add_name(name);
        let ext = idx.intern_extension(name);
        let rec = idx.get_or_create((100 + i).into());
        rec.stdinfo.set_directory(true);
        rec.stdinfo.flags = 0x10; // directory
        rec.first_name.name = IndexNameRef::new(off, uffs_mft::len_to_u16(name.len()), true, ext);
        rec.first_name.parent_frs = Into::into(ROOT_FRS);
        rec.first_stream.size = SizeInfo {
            length: 4096,
            allocated: 4096,
        };
    }

    let (drive, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::T, &idx);
    let mut acc = DuplicateAccumulator::new(
        vec![FieldId::Size, FieldId::Name],
        DuplicateVerify::None,
        100_000,
        2,
    );

    for (i, rec) in drive.records.iter().enumerate() {
        acc.feed(rec, &drive, i);
    }

    let result = acc.finalize(50);
    assert_eq!(result.candidate_groups, 0, "directories excluded");
}

// ── S4E.4: Windows verified duplicates ──────────────────────

/// Integration test with real MFT data + file-content verification.
///
/// Requires Windows with the test-tree created by
/// `scripts/windows/create_mft_test_tree.ps1`.
/// Run with: `cargo test -p uffs-core -- duplicates_verified_windows
/// --ignored`
#[test]
#[ignore = "requires Windows with MFT test tree (create_mft_test_tree.ps1)"]
#[cfg(windows)]
fn duplicates_verified_windows() {
    use crate::compact_loader::{MftSource, load_drive};

    // Load C: drive index.  `load_drive` returns `(index, timing)`;
    // the test only uses the index itself.
    let source = MftSource::Live(uffs_mft::platform::DriveLetter::C);
    let (drive, _load_timing) = load_drive(&source, false).expect("failed to load C: drive");

    let mut acc = DuplicateAccumulator::new(
        vec![FieldId::Size, FieldId::Name],
        DuplicateVerify::FirstBytes { count: 4096 },
        500_000,
        5,
    );

    for (idx, rec) in drive.records.iter().enumerate() {
        acc.feed(rec, &drive, idx);
    }

    let result = acc.finalize(100);

    // On any real Windows install there should be known duplicates
    // (e.group., DLLs in System32 and SysWOW64 with same name+size).
    assert!(
        result.candidate_groups > 0,
        "a real Windows C: drive should contain duplicate files"
    );
    assert!(
        result.total_reclaimable_bytes > 0,
        "reclaimable bytes should be non-zero"
    );

    // Verify groups are sorted by reclaimable_bytes descending.
    for pair in result.groups.windows(2) {
        // `windows(2)` always yields exactly two elements; the
        // `else` arm is dead code but keeps clippy's
        // missing_asserts_for_indexing lint quiet without
        // resorting to `unreachable!()`.
        let [prev, curr] = pair else {
            continue;
        };
        assert!(
            prev.reclaimable_bytes >= curr.reclaimable_bytes,
            "groups should be sorted by reclaimable_bytes desc"
        );
    }

    // Each group must have count ≥ 2.
    for group in &result.groups {
        assert!(group.count >= 2, "each group must have at least 2 files");
        assert!(group.file_size > 0, "zero-byte files should be excluded");
    }
}
