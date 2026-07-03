// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Regression tests for issue #510 — USN batches must apply parents before
//! children ([`super::order_parent_first`] wired into
//! [`super::apply_usn_patch`]), or a same-batch child bakes the
//! unknown-parent sentinel and renders as a phantom root-level path.
//!
//! Sibling file (the `compact_loader_tests.rs` pattern) so both stay under
//! the workspace file-size policy. Reuses that sibling's synthetic-drive
//! fixture via `super::tests::make_synthetic_drive`.

use uffs_mft::usn::FileChange;

use super::apply_usn_patch;
use super::tests::make_synthetic_drive;

/// Regression for issue #510: `aggregate_changes` hands the batch over in
/// arbitrary (`HashMap`) order, so a file's create could be applied BEFORE its
/// parent directory's create — the parent lookup missed and baked the
/// unknown-parent sentinel, which the path machinery renders as a ROOT-LEVEL
/// entry (`C:\<name>`). Live symptom: freshly-unzipped files listed at the
/// drive root, and an uninstall "removing" phantom paths.
#[test]
fn scrambled_child_before_parent_resolves_to_the_new_dir() {
    let mut drive = make_synthetic_drive();
    // Deliberately WORST-CASE order: grandchild first, then child, then the
    // directory that parents them both (FRS 20 dir → FRS 21 subdir → FRS 22
    // file). A single-pass apply would bake u32::MAX for 22 and 21.
    let changes = vec![
        FileChange {
            frs: 22_u64.into(),
            parent_frs: 21_u64.into(),
            filename: "leaf.txt".to_owned(),
            created: true,
            ..FileChange::default()
        },
        FileChange {
            frs: 21_u64.into(),
            parent_frs: 20_u64.into(),
            filename: "sub".to_owned(),
            created: true,
            ..FileChange::default()
        },
        FileChange {
            frs: 20_u64.into(),
            parent_frs: 5_u64.into(),
            filename: "unzipped".to_owned(),
            created: true,
            ..FileChange::default()
        },
    ];

    let stats = apply_usn_patch(&mut drive, &changes);
    assert_eq!(stats.created, 3);

    let idx_of = |frs: usize| drive.frs_to_compact.get(frs).copied().unwrap();
    let (dir_idx, sub_idx, leaf_idx) = (idx_of(20), idx_of(21), idx_of(22));
    assert_ne!(dir_idx, u32::MAX, "dir registered");
    assert_ne!(sub_idx, u32::MAX, "subdir registered");
    assert_ne!(leaf_idx, u32::MAX, "leaf registered");

    let rec = |idx: u32| drive.records.as_slice().get(idx as usize).copied().unwrap();
    // The dir hangs off the root (compact_idx 0 — FRS 5 pre-mapped).
    assert_eq!(rec(dir_idx).parent_idx, 0, "dir parents to root");
    // The chain resolves through the SAME-BATCH creates, not to u32::MAX
    // (which would render as a phantom root-level path — the #510 bake).
    assert_eq!(
        rec(sub_idx).parent_idx,
        dir_idx,
        "subdir must parent to the same-batch dir, not the root sentinel"
    );
    assert_eq!(
        rec(leaf_idx).parent_idx,
        sub_idx,
        "leaf must parent to the same-batch subdir, not the root sentinel"
    );
}

/// A same-batch RENAME into a just-created directory must also wait for the
/// directory's create (renames re-resolve `parent_idx` too).
#[test]
fn scrambled_rename_into_new_dir_resolves() {
    let mut drive = make_synthetic_drive();
    let changes = vec![
        // Move existing FRS 10 ("foo.txt") into the new dir — listed FIRST.
        FileChange {
            frs: 10_u64.into(),
            parent_frs: 30_u64.into(),
            filename: "foo.txt".to_owned(),
            renamed: true,
            ..FileChange::default()
        },
        // The directory it moves into — listed SECOND.
        FileChange {
            frs: 30_u64.into(),
            parent_frs: 5_u64.into(),
            filename: "newdir".to_owned(),
            created: true,
            ..FileChange::default()
        },
    ];

    apply_usn_patch(&mut drive, &changes);

    let dir_idx = drive.frs_to_compact.get(30).copied().unwrap();
    assert_ne!(dir_idx, u32::MAX);
    let moved = drive.records.as_slice().get(1).copied().unwrap(); // FRS 10 @ idx 1
    assert_eq!(
        moved.parent_idx, dir_idx,
        "renamed-into-new-dir must parent to the same-batch dir"
    );
}

/// A parent that is genuinely absent from the batch (its create event was
/// never seen — lost/overflowed journal) keeps today's unknown-parent
/// fallback: the child is still applied, with the sentinel parent.
#[test]
fn genuinely_missing_parent_still_applies_with_sentinel() {
    let mut drive = make_synthetic_drive();
    let changes = vec![FileChange {
        frs: 40_u64.into(),
        parent_frs: 39_u64.into(), // never created anywhere
        filename: "orphan.txt".to_owned(),
        created: true,
        ..FileChange::default()
    }];

    let stats = apply_usn_patch(&mut drive, &changes);
    assert_eq!(stats.created, 1, "the orphan is still applied");
    let idx = drive.frs_to_compact.get(40).copied().unwrap();
    let rec = drive.records.as_slice().get(idx as usize).copied().unwrap();
    assert_eq!(
        rec.parent_idx,
        u32::MAX,
        "unknown parent keeps the sentinel (fallback preserved)"
    );
}
