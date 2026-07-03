// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit tests for [`super::apply_usn_patch`] — the platform-agnostic
//! in-place USN delta applier shared across the daemon's per-shard
//! USN journal loop (Phase 7 task 7.1).
//!
//! These tests exercise the function with synthesised
//! [`uffs_mft::usn::FileChange`] arrays and a synthesised
//! [`crate::compact::DriveCompactIndex`] so the contract is pinned
//! end-to-end **without** requiring a Windows host or a live MFT
//! source.  The journal source itself
//! ([`uffs_mft::usn::read_usn_journal`]) is Windows-only; everything
//! downstream of `read_usn_journal` is covered here.
//!
//! Extracted into a sibling submodule so `compact_loader.rs` stays
//! well below the file-size policy ceiling.

use alloc::sync::Arc;
use std::path::PathBuf;

use uffs_mft::usn::FileChange;
use uffs_text::case_fold::CaseFold;

use super::{IndexSource, apply_usn_patch};
use crate::compact::{ChildrenIndex, CompactRecord, DriveCompactIndex, ExtensionIndex};
use crate::compact_storage::ColumnStorage;
use crate::trigram::TrigramIndex;

/// Build a synthetic 4-record drive: root directory + three files.
///
/// FRS layout (NTFS-style) → `compact_idx` mapping:
///
/// * FRS  5 → root dir `"C"`        @ `compact_idx` 0
/// * FRS 10 → `"foo.txt"` parent=5 @ `compact_idx` 1
/// * FRS 11 → `"bar.rs"`  parent=5 @ `compact_idx` 2
/// * FRS 12 → `"baz.md"`  parent=5 @ `compact_idx` 3
///
/// `drive.frs_to_compact` is populated with the mapping above plus
/// `u32::MAX` sentinels for FRS 13 (newly-created in the create
/// test) and FRS 99 (unmapped / skipped) so tests can patch the
/// drive in place without touching a separate slice.
pub(super) fn make_synthetic_drive() -> DriveCompactIndex {
    // Names blob layout:
    //   "C"       [0..1]
    //   "foo.txt" [1..8]
    //   "bar.rs"  [8..14]
    //   "baz.md"  [14..20]
    let names = b"Cfoo.txtbar.rsbaz.md".to_vec();
    let records = vec![
        CompactRecord {
            name_offset: 0,
            flags: 0x10, // directory
            parent_idx: u32::MAX,
            name_len: 1,
            name_first_byte: b'C',
            ..CompactRecord::default()
        },
        CompactRecord {
            name_offset: 1,
            parent_idx: 0,
            name_len: 7,
            name_first_byte: b'f',
            ..CompactRecord::default()
        },
        CompactRecord {
            name_offset: 8,
            parent_idx: 0,
            name_len: 6,
            name_first_byte: b'b',
            ..CompactRecord::default()
        },
        CompactRecord {
            name_offset: 14,
            parent_idx: 0,
            name_len: 6,
            name_first_byte: b'b',
            ..CompactRecord::default()
        },
    ];

    let fold = CaseFold::default_table();
    let trigram = TrigramIndex::build(&records, &names, fold);
    let children = ChildrenIndex::build(&records);
    let ext_index = ExtensionIndex::build(&records);

    // FRS → compact_idx mapping.  Sized to 100 entries so test
    // batches can address FRS 13 (newly-created) and FRS 99
    // (skipped — no compact slot) without resize gymnastics.
    // Built via iterator-collect to avoid `clippy::indexing_slicing`;
    // FRS 13 left at u32::MAX so the create-branch fires for it.
    let frs_to_compact: Vec<u32> = (0_usize..100)
        .map(|frs| match frs {
            5 => 0_u32,
            10 => 1,
            11 => 2,
            12 => 3,
            _ => u32::MAX,
        })
        .collect();

    DriveCompactIndex {
        letter: uffs_mft::platform::DriveLetter::T,
        records: ColumnStorage::from_vec(records),
        names: ColumnStorage::from_vec(names),
        trigram: Arc::new(trigram),
        children: Arc::new(children),
        ext_index: Arc::new(ext_index),
        fold,
        ext_names: vec![Box::from("")],
        source: IndexSource::MftFile(PathBuf::from("T:")),
        source_epoch: 42,
        bloom: None,
        path_trie: None,
        frs_to_compact,
        delta: None,
    }
}

/// Headline contract test: a mixed batch of create / delete / rename /
/// skip changes lands the matching counters on `PatchStats` without
/// cross-talk.
#[test]
fn apply_usn_patch_handles_create_delete_rename_skip() {
    let mut drive = make_synthetic_drive();

    let changes = vec![
        // Delete FRS 10 ("foo.txt").
        FileChange {
            frs: 10_u64.into(),
            deleted: true,
            ..FileChange::default()
        },
        // Rename FRS 11 ("bar.rs" → "bar2.rs"), parent unchanged.
        FileChange {
            frs: 11_u64.into(),
            parent_frs: 5_u64.into(),
            filename: "bar2.rs".to_owned(),
            renamed: true,
            ..FileChange::default()
        },
        // Create FRS 13 ("new.txt", parent=root).
        FileChange {
            frs: 13_u64.into(),
            parent_frs: 5_u64.into(),
            filename: "new.txt".to_owned(),
            created: true,
            ..FileChange::default()
        },
        // Skip: FRS 99 doesn't map to any compact record.
        FileChange {
            frs: 99_u64.into(),
            deleted: true,
            ..FileChange::default()
        },
    ];

    let stats = apply_usn_patch(&mut drive, &changes);

    assert_eq!(
        stats.deleted, 1,
        "exactly one delete should have applied (FRS 10)"
    );
    assert_eq!(
        stats.created, 1,
        "exactly one create should have applied (FRS 13)"
    );
    assert_eq!(
        stats.renamed, 1,
        "exactly one rename should have applied (FRS 11)"
    );
    assert_eq!(
        stats.skipped, 1,
        "exactly one skip should have happened (FRS 99 unmapped)"
    );
}

/// Delete contract: the deleted record's `name_len` is zeroed and its
/// `parent_idx` is set to `u32::MAX` so the CSR rebuild excludes it
/// from any directory's child list (tombstone semantics).
#[test]
fn apply_usn_patch_marks_deleted_record_with_zero_name_len() {
    let mut drive = make_synthetic_drive();
    let changes = vec![FileChange {
        frs: 10_u64.into(),
        deleted: true,
        ..FileChange::default()
    }];

    apply_usn_patch(&mut drive, &changes);

    let record = drive
        .records
        .as_slice()
        .get(1)
        .expect("synthetic drive has at least 2 records");
    assert_eq!(record.name_len, 0, "deleted record's name_len must be 0");
    assert_eq!(
        record.parent_idx,
        u32::MAX,
        "deleted record's parent_idx must be u32::MAX so CSR rebuild excludes it"
    );
}

/// Rename contract: the renamed record's `name_offset` points at a
/// fresh slot in the names blob holding the new bytes, and `name_len`
/// reflects the new byte count.
#[test]
fn apply_usn_patch_renamed_record_has_new_name_in_blob() {
    let mut drive = make_synthetic_drive();
    let changes = vec![FileChange {
        frs: 11_u64.into(),
        parent_frs: 5_u64.into(),
        filename: "bar2.rs".to_owned(),
        renamed: true,
        ..FileChange::default()
    }];

    apply_usn_patch(&mut drive, &changes);

    let record = drive
        .records
        .as_slice()
        .get(2)
        .expect("synthetic drive has at least 3 records");
    assert_eq!(record.name_len, 7, "renamed name 'bar2.rs' is 7 bytes");

    let name_start = record.name_offset as usize;
    let name_end = name_start + record.name_len as usize;
    let name_bytes = drive
        .names
        .as_slice()
        .get(name_start..name_end)
        .expect("name slice must lie within names blob");
    assert_eq!(
        name_bytes, b"bar2.rs",
        "renamed record's name slot must hold the new bytes"
    );
}

/// Regression (v0.6.13 field report): a rename that changes the
/// extension (`charlie.log` → `charlie.pdf`) must re-intern the new
/// extension so the record is findable by `--ext pdf` and drops out of
/// `--ext log`. The rename branch used to update only `name_offset` /
/// `name_len`, leaving the stale `extension_id` behind.
#[test]
fn apply_usn_patch_rename_reinterns_extension() {
    let mut drive = make_synthetic_drive();
    // FRS 11 → compact_idx 2 ("bar.rs"). Rename it to "bar.pdf".
    let changes = vec![FileChange {
        frs: 11_u64.into(),
        parent_frs: 5_u64.into(),
        filename: "bar.pdf".to_owned(),
        renamed: true,
        ..FileChange::default()
    }];
    apply_usn_patch(&mut drive, &changes);

    let pdf_ids = drive.resolve_ext_ids(&["pdf".to_owned()]);
    assert_eq!(pdf_ids.len(), 1, "'pdf' must be interned after the rename");
    let pdf_id = *pdf_ids.first().expect("one id");
    let record = drive.records.as_slice().get(2).expect("record 2");
    assert_eq!(
        record.extension_id, pdf_id,
        "renamed record must carry the new 'pdf' extension_id"
    );
    assert_eq!(
        record.name_first_byte, b'b',
        "first-byte cache must reflect the renamed name"
    );
    assert!(
        drive.records_with_ext(pdf_id).contains(&2),
        "records_with_ext(pdf) must include the renamed record"
    );
}

/// Regression (v0.6.13 field report): FRS reuse. NTFS reuses an MFT
/// record number after a delete, so a `created` event can land on a
/// slot whose mapping still points at a *live* (stale) record — e.g.
/// when the prior delete was coalesced away. The create must REPLACE
/// that slot with the new file's identity, not silently skip it (which
/// dropped the new file and was the root of the "delta.pdf vanished"
/// and "recreate after delete loses files" reports).
#[test]
fn apply_usn_patch_create_replaces_live_reused_slot() {
    let mut drive = make_synthetic_drive();
    // FRS 11 → compact_idx 2 ("bar.rs", a LIVE record, name_len 6).
    // A create for FRS 11 means the record number was reused.
    let new_idx = 2_usize;
    let changes = vec![FileChange {
        frs: 11_u64.into(),
        parent_frs: 5_u64.into(),
        filename: "reused.pdf".to_owned(),
        created: true,
        ..FileChange::default()
    }];
    apply_usn_patch(&mut drive, &changes);

    let record = drive.records.as_slice().get(new_idx).expect("record 2");
    let name_start = record.name_offset as usize;
    let name_end = name_start + record.name_len as usize;
    let name_bytes = drive
        .names
        .as_slice()
        .get(name_start..name_end)
        .expect("name slice in blob");
    assert_eq!(
        name_bytes, b"reused.pdf",
        "reused slot must hold the NEW file's name"
    );
    let pdf_ids = drive.resolve_ext_ids(&["pdf".to_owned()]);
    let pdf_id = *pdf_ids.first().expect("'pdf' interned");
    assert_eq!(record.extension_id, pdf_id, "reused slot tagged 'pdf'");
    assert!(
        drive.records_with_ext(pdf_id).contains(&2),
        "ExtensionIndex.get(pdf) must include the reused record"
    );
}

/// Metadata backfill: when the journal source attaches a `RecordMeta`
/// (from a targeted MFT read), the created record carries the real
/// size/timestamps/flags instead of the USN-only zeros. Covers both the
/// append (new FRS) and the overwrite (reused slot) paths, plus rename.
#[test]
fn apply_usn_patch_applies_backfilled_metadata() {
    use uffs_mft::usn::RecordMeta;

    let meta = RecordMeta {
        size: 1_637_013,
        allocated: 1_638_400,
        created: 1_700_000_000_000_000,
        modified: 1_700_000_500_000_000,
        accessed: 1_700_000_900_000_000,
        flags: 0x20, // FILE_ATTRIBUTE_ARCHIVE
    };

    // Append path: brand-new FRS 13 with metadata.
    let mut appended_drive = make_synthetic_drive();
    let appended_idx = appended_drive.records.len();
    apply_usn_patch(&mut appended_drive, &[FileChange {
        frs: 13_u64.into(),
        parent_frs: 5_u64.into(),
        filename: "report.pdf".to_owned(),
        created: true,
        meta: Some(meta),
        ..FileChange::default()
    }]);
    let appended = appended_drive
        .records
        .as_slice()
        .get(appended_idx)
        .expect("appended");
    assert_eq!(
        appended.size, meta.size,
        "appended record carries real size"
    );
    assert_eq!(appended.modified, meta.modified, "and real modified time");
    assert_eq!(appended.flags, meta.flags, "and real attribute flags");

    // Overwrite path: a reused live slot (FRS 11 → idx 2) with metadata.
    let mut overwrite_drive = make_synthetic_drive();
    apply_usn_patch(&mut overwrite_drive, &[FileChange {
        frs: 11_u64.into(),
        parent_frs: 5_u64.into(),
        filename: "reused.pdf".to_owned(),
        created: true,
        meta: Some(meta),
        ..FileChange::default()
    }]);
    let overwritten = overwrite_drive
        .records
        .as_slice()
        .get(2)
        .expect("reused slot");
    assert_eq!(
        overwritten.size, meta.size,
        "overwritten slot carries real size"
    );
    assert_eq!(overwritten.created, meta.created, "and real created time");

    // No metadata (USN-only) still yields zeros — unchanged behaviour.
    let mut bare_drive = make_synthetic_drive();
    let bare_idx = bare_drive.records.len();
    apply_usn_patch(&mut bare_drive, &[FileChange {
        frs: 13_u64.into(),
        parent_frs: 5_u64.into(),
        filename: "bare.pdf".to_owned(),
        created: true,
        ..FileChange::default()
    }]);
    let bare = bare_drive.records.as_slice().get(bare_idx).expect("bare");
    assert_eq!(bare.size, 0, "USN-only create stays zero-size");
    assert_eq!(bare.modified, 0, "USN-only create stays zero-time");
}

/// Create contract: a newly-created FRS that doesn't map to an
/// existing compact slot (`frs_to_compact[frs] == u32::MAX`) appends
/// a fresh record at the end with the correct `parent_idx`,
/// `name_len`, and `name_first_byte`.
#[test]
fn apply_usn_patch_created_record_appended_with_correct_parent() {
    let mut drive = make_synthetic_drive();
    let initial_record_count = drive.records.len();

    let changes = vec![FileChange {
        frs: 13_u64.into(),
        parent_frs: 5_u64.into(),
        filename: "new.txt".to_owned(),
        created: true,
        ..FileChange::default()
    }];

    apply_usn_patch(&mut drive, &changes);

    assert_eq!(
        drive.records.len(),
        initial_record_count + 1,
        "create must append exactly one record"
    );

    let record = drive
        .records
        .as_slice()
        .get(initial_record_count)
        .expect("appended record must be reachable at the new tail");
    assert_eq!(record.name_len, 7, "'new.txt' is 7 bytes");
    assert_eq!(
        record.parent_idx, 0,
        "parent compact_idx should be 0 (root)"
    );
    assert_eq!(
        record.name_first_byte, b'n',
        "first-byte cache must reflect the new name"
    );
}

/// Regression (v0.6.13 field report): a file created via the USN journal
/// patch must become findable by `--ext`.  The create branch used to
/// hardcode `extension_id: 0`, so the rebuilt `ExtensionIndex` filed the
/// new file under "no extension" — `uffs report.pdf` found it by name but
/// `uffs report --ext pdf` returned nothing.  This pins the whole chain:
/// the extension is interned into `ext_names`, the record carries the real
/// `extension_id`, and the inverted index returns it for that id.
#[test]
fn apply_usn_patch_created_record_is_findable_by_extension() {
    let mut drive = make_synthetic_drive();
    let new_idx = drive.records.len();

    // Pre-condition: "pdf" is unknown on this synthetic drive, so an
    // `--ext pdf` query resolves to no ids (the bug's starting point).
    assert!(
        drive.resolve_ext_ids(&["pdf".to_owned()]).is_empty(),
        "fixture must not already know the 'pdf' extension"
    );

    let changes = vec![FileChange {
        frs: 13_u64.into(),
        parent_frs: 5_u64.into(),
        filename: "report.pdf".to_owned(),
        created: true,
        ..FileChange::default()
    }];
    let stats = apply_usn_patch(&mut drive, &changes);
    assert_eq!(stats.created, 1, "the create should have applied");

    // 1. The extension is now interned and resolvable.
    let ids = drive.resolve_ext_ids(&["pdf".to_owned()]);
    assert_eq!(ids.len(), 1, "'pdf' must resolve to exactly one ext id");
    let pdf_id = *ids.first().expect("one id present");
    assert_ne!(
        pdf_id, 0,
        "a real extension must not collapse to the no-ext id"
    );

    // 2. The new record carries that extension_id (not the hardcoded 0).
    let record = drive
        .records
        .as_slice()
        .get(new_idx)
        .expect("created record reachable at the tail");
    assert_eq!(
        record.extension_id, pdf_id,
        "created record must be tagged with the resolved 'pdf' id"
    );

    // 3. records_with_ext (base ∪ delta overlay) returns the new record for that id
    //    — exactly what `--ext pdf` walks.
    let matches = drive.records_with_ext(pdf_id);
    assert!(
        matches.contains(&u32::try_from(new_idx).expect("idx fits u32")),
        "records_with_ext(pdf) must include the USN-created record"
    );
}

/// Companion edge cases for [`DriveCompactIndex::intern_extension`] via the
/// create path: a dotless name and a leading-dot dotfile both resolve to
/// the reserved no-extension id (0) and never pollute `ext_names`.
#[test]
fn apply_usn_patch_dotless_and_dotfile_creates_have_no_extension() {
    let mut drive = make_synthetic_drive();
    let ext_names_before = drive.ext_names.len();

    let changes = vec![
        FileChange {
            frs: 13_u64.into(),
            parent_frs: 5_u64.into(),
            filename: "Makefile".to_owned(), // dotless
            created: true,
            ..FileChange::default()
        },
        FileChange {
            frs: 14_u64.into(),
            parent_frs: 5_u64.into(),
            filename: ".gitignore".to_owned(), // leading-dot dotfile
            created: true,
            ..FileChange::default()
        },
    ];
    apply_usn_patch(&mut drive, &changes);

    let makefile = drive.records.as_slice().get(4).expect("Makefile record");
    let gitignore = drive.records.as_slice().get(5).expect(".gitignore record");
    assert_eq!(makefile.extension_id, 0, "dotless name → no extension");
    assert_eq!(gitignore.extension_id, 0, "dotfile → no extension");
    assert_eq!(
        drive.ext_names.len(),
        ext_names_before,
        "no-extension creates must not append to ext_names"
    );
}

/// Empty-batch fast path: passing zero changes produces all-zero
/// stats and leaves the drive byte-for-byte unchanged in shape (same
/// record count, same names blob length).  Pins that the rebuilt
/// derived structures don't grow on an empty batch.
#[test]
fn apply_usn_patch_no_changes_is_no_op_with_zero_stats() {
    let mut drive = make_synthetic_drive();
    let initial_record_count = drive.records.len();
    let initial_names_len = drive.names.len();

    let stats = apply_usn_patch(&mut drive, &[]);

    assert_eq!(stats.deleted, 0);
    assert_eq!(stats.created, 0);
    assert_eq!(stats.renamed, 0);
    assert_eq!(stats.skipped, 0);
    assert_eq!(drive.records.len(), initial_record_count);
    assert_eq!(drive.names.len(), initial_names_len);
}

/// Rebuild invariant: after `apply_usn_patch` returns, the children
/// CSR reflects the post-mutation `parent_idx` state.  Specifically,
/// once a record is deleted (`parent_idx` → `u32::MAX`), the root's
/// children list must no longer include that record's `compact_idx`.
#[test]
fn apply_usn_patch_rebuilds_children_csr_excluding_deletes() {
    let mut drive = make_synthetic_drive();

    // Pre-state sanity: root (compact_idx 0) starts with three
    // children — compact_idx 1 ("foo.txt"), 2 ("bar.rs"), 3 ("baz.md").
    let initial_root_children: Vec<u32> = drive.children_of(0).into_owned();
    assert_eq!(
        initial_root_children.len(),
        3,
        "synthetic root starts with three children"
    );

    let changes = vec![FileChange {
        frs: 10_u64.into(),
        deleted: true,
        ..FileChange::default()
    }];

    apply_usn_patch(&mut drive, &changes);

    let post_root_children: Vec<u32> = drive.children_of(0).into_owned();
    assert!(
        !post_root_children.contains(&1),
        "deleted compact_idx 1 must not appear in root's children CSR after rebuild"
    );
    assert_eq!(
        post_root_children.len(),
        2,
        "root should have two surviving children after one delete"
    );
}

/// Phase 8 invariant: `apply_usn_patch` keeps `drive.frs_to_compact`
/// in lock-step with `drive.records` across creates and deletes.
///
/// Pins:
/// 1. **Create populates the slot.**  A brand-new FRS (13) lands at the
///    appended `compact_idx`; `drive.frs_to_compact[13]` reflects that slot
///    exactly.
/// 2. **Delete clears the slot.**  After deleting an existing FRS (10),
///    `drive.frs_to_compact[10] == u32::MAX`.
/// 3. **FRS reuse round-trip.**  Create FRS 13 → delete FRS 13 → create FRS 13
///    again yields a *fresh* `compact_idx` (NOT the tombstoned one).  This
///    guards the long-running daemon against NTFS FRS-slot reuse ambiguity.
/// 4. **Out-of-range create extends the table.**  A create on FRS 200 (beyond
///    the fixture's len-100 mapping) grows `frs_to_compact` and registers the
///    new slot at index 200.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "Phase 8 lockstep invariant test — the four pinned cases \
              (Create / Delete / FRS-reuse / Out-of-range-create) form a \
              single linear narrative; splitting into per-case helpers \
              would scatter the read-modify-assert flow across four \
              functions and obscure the invariant the test exists to \
              regression-pin."
)]
fn apply_usn_patch_keeps_frs_to_compact_in_lockstep() {
    // ── 1. Create FRS 13 → expect new compact_idx + mapping update.
    let mut drive = make_synthetic_drive();
    let initial_records = drive.records.len();
    let initial_mapping_len = drive.frs_to_compact.len();
    assert_eq!(
        drive
            .frs_to_compact
            .get(13)
            .copied()
            .expect("fixture sized to 100"),
        u32::MAX,
        "FRS 13 starts unmapped"
    );

    apply_usn_patch(&mut drive, &[FileChange {
        frs: 13_u64.into(),
        parent_frs: 5_u64.into(),
        filename: "n1.txt".to_owned(),
        created: true,
        ..FileChange::default()
    }]);

    let first_compact_idx = drive
        .frs_to_compact
        .get(13)
        .copied()
        .expect("create updated mapping");
    assert_ne!(
        first_compact_idx,
        u32::MAX,
        "create must register FRS 13 → compact_idx mapping"
    );
    assert_eq!(
        first_compact_idx as usize, initial_records,
        "new compact_idx must equal pre-create records.len()"
    );

    // ── 2. Delete existing FRS 10 → expect slot reset to u32::MAX.
    apply_usn_patch(&mut drive, &[FileChange {
        frs: 10_u64.into(),
        deleted: true,
        ..FileChange::default()
    }]);
    assert_eq!(
        drive
            .frs_to_compact
            .get(10)
            .copied()
            .expect("fixture sized to 100"),
        u32::MAX,
        "delete must reset FRS 10 mapping to u32::MAX"
    );

    // ── 3. Reuse round-trip: delete FRS 13, then create FRS 13 again.
    apply_usn_patch(&mut drive, &[FileChange {
        frs: 13_u64.into(),
        deleted: true,
        ..FileChange::default()
    }]);
    assert_eq!(
        drive
            .frs_to_compact
            .get(13)
            .copied()
            .expect("fixture sized to 100"),
        u32::MAX,
        "delete must clear FRS 13 mapping after the create"
    );

    let pre_recreate_records = drive.records.len();
    apply_usn_patch(&mut drive, &[FileChange {
        frs: 13_u64.into(),
        parent_frs: 5_u64.into(),
        filename: "n2.txt".to_owned(),
        created: true,
        ..FileChange::default()
    }]);
    let second_compact_idx = drive
        .frs_to_compact
        .get(13)
        .copied()
        .expect("recreate updated mapping");
    assert_ne!(
        second_compact_idx, first_compact_idx,
        "FRS-13 reuse must yield a fresh compact_idx, not the tombstoned one"
    );
    assert_eq!(
        second_compact_idx as usize, pre_recreate_records,
        "recreated compact_idx must equal records.len() at the second create"
    );

    // ── 4. Out-of-range create grows the mapping.
    apply_usn_patch(&mut drive, &[FileChange {
        frs: 200_u64.into(),
        parent_frs: 5_u64.into(),
        filename: "far.txt".to_owned(),
        created: true,
        ..FileChange::default()
    }]);
    assert!(
        drive.frs_to_compact.len() >= 201,
        "creates beyond the build-time max must extend frs_to_compact \
         (was {initial_mapping_len}; now {})",
        drive.frs_to_compact.len()
    );
    let far_compact_idx = drive
        .frs_to_compact
        .get(200)
        .copied()
        .expect("table extended past index 200");
    assert_ne!(
        far_compact_idx,
        u32::MAX,
        "FRS 200 must map to the freshly-appended compact slot"
    );
    assert_eq!(
        far_compact_idx as usize,
        drive.records.len() - 1,
        "FRS 200 must point at the most recently appended record"
    );
}
