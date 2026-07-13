// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Snapshot diff: classify the delta between two full compact indexes.
//!
//! The `--newer` (timestamp) delta path can report files *created or modified*
//! after a date, but is structurally blind to *deletions* — a deleted file
//! simply stops appearing, and a timestamp cannot express "this is gone". The
//! USN journal has an explicit `FILE_DELETE` reason; the journal-free fallback
//! recovers delete visibility by comparing two full reads.
//!
//! This module is the deterministic core of that fallback:
//! [`diff_records`] set-differences a baseline against a current index by
//! **NTFS File Reference** — `(sequence_number << 48) | frs`, stored inline on
//! every [`CompactRecord`] as [`CompactRecord::file_ref`]. Keying on the FRS
//! (MFT slot) alone would misclassify a delete-then-reuse of the same slot as a
//! *modify*; the sequence number makes it exact — `(frs=N, seq=3)` in the
//! baseline and `(frs=N, seq=4)` in the current is a **delete of seq 3 plus an
//! add of seq 4**, not a modification.
//!
//! See `docs/architecture/delete-visibility-snapshot-diff.md` for the full
//! design (Mechanism 1: snapshot diff).

use rustc_hash::{FxHashMap, FxHashSet};

use crate::compact::{CompactRecord, DriveCompactIndex};

/// The classified delta between a baseline and a current compact index.
///
/// Every entry is a **row index** into the corresponding index's record array,
/// not a resolved path: path reconstruction needs the whole index (the
/// parent-chain walk), so the caller resolves each index via
/// [`crate::tree::resolve_path`] against the right side — `deleted` against the
/// baseline, `added` / `modified` against the current.
///
/// Rows are reported at *name* granularity: a file with N hard links (which
/// share one File Reference) contributes N rows, so each affected path is
/// surfaced. Synthetic rows (aggregate rollups, `file_ref == 0`) are never
/// classified — see [`diff_records`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeltaReport {
    /// Row indices into the **current** index whose File Reference is absent
    /// from the baseline (newly created since the baseline).
    pub added: Vec<u32>,
    /// Row indices into the **baseline** index whose File Reference is absent
    /// from the current (deleted since the baseline).
    pub deleted: Vec<u32>,
    /// Row indices into the **current** index whose File Reference is present
    /// in the baseline but whose `size` or `modified` timestamp changed.
    pub modified: Vec<u32>,
}

impl DeltaReport {
    /// Total number of classified rows across all three classes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.added.len() + self.deleted.len() + self.modified.len()
    }

    /// Whether the two indexes were identical at File-Reference granularity
    /// (no adds, deletes, or in-place modifications).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.added.is_empty() && self.deleted.is_empty() && self.modified.is_empty()
    }
}

/// The metadata a modify-detection compares: logical size and last-write time.
///
/// Every row that shares a File Reference (hard links / ADS of one file) shares
/// this metadata — it comes from the single base MFT record — so keying the
/// baseline map on `file_ref` and storing the first row's `(size, modified)` is
/// consistent for all of that file's rows.
type Meta = (u64, i64);

/// Whether a record participates in the diff.
///
/// `file_ref == 0` marks a synthetic row — an aggregate rollup, an
/// unresolved/USN-fresh placeholder, or a `CompactRecord::default()`. A zero
/// reference is not a unique file identity (every synthetic row shares it), so
/// such rows are excluded from both sides of the diff. Real files can never
/// have `file_ref == 0`: that would require FRS 0 (the `$MFT` metafile itself),
/// which is excluded from the compact index at build time.
#[inline]
const fn is_real(rec: &CompactRecord) -> bool {
    rec.file_ref != 0
}

/// Diff two compact record arrays, classifying every real row as added,
/// deleted, or modified by NTFS File Reference.
///
/// - **Deleted** — File Reference in `baseline`, absent from `current`.
/// - **Added** — File Reference in `current`, absent from `baseline`.
/// - **Modified** — same File Reference in both, changed `size` or `modified`.
///
/// A delete-then-reuse of the same MFT slot bumps the sequence number, so the
/// old and new File References differ and the pair is reported as a delete plus
/// an add — never as a modify. Synthetic rows (`file_ref == 0`) are skipped.
///
/// Deterministic and allocation-bounded: two hash builds over the inputs plus
/// the three result vectors. Row indices are emitted in ascending array order.
#[must_use]
pub fn diff_records(baseline: &[CompactRecord], current: &[CompactRecord]) -> DeltaReport {
    // Baseline: File Reference -> (size, modified) of the first row seen for it.
    let mut base_meta: FxHashMap<u64, Meta> =
        FxHashMap::with_capacity_and_hasher(baseline.len(), rustc_hash::FxBuildHasher);
    for rec in baseline.iter().filter(|rec| is_real(rec)) {
        base_meta
            .entry(rec.file_ref)
            .or_insert((rec.size, rec.modified));
    }

    // Current: the set of live File References (for the delete pass).
    let mut current_refs: FxHashSet<u64> =
        FxHashSet::with_capacity_and_hasher(current.len(), rustc_hash::FxBuildHasher);
    for rec in current.iter().filter(|rec| is_real(rec)) {
        current_refs.insert(rec.file_ref);
    }

    let mut report = DeltaReport::default();

    // Added + modified: walk the current rows.
    for (idx, rec) in current.iter().enumerate() {
        if !is_real(rec) {
            continue;
        }
        match base_meta.get(&rec.file_ref) {
            None => report.added.push(len_to_u32(idx)),
            Some(&(base_size, base_modified)) => {
                if base_size != rec.size || base_modified != rec.modified {
                    report.modified.push(len_to_u32(idx));
                }
            }
        }
    }

    // Deleted: baseline rows whose File Reference vanished from the current.
    for (idx, rec) in baseline.iter().enumerate() {
        if is_real(rec) && !current_refs.contains(&rec.file_ref) {
            report.deleted.push(len_to_u32(idx));
        }
    }

    report
}

/// Diff two loaded compact indexes. Thin wrapper over [`diff_records`] that
/// operates on their record arrays; see that function for the semantics.
#[must_use]
pub fn diff_indexes(baseline: &DriveCompactIndex, current: &DriveCompactIndex) -> DeltaReport {
    diff_records(&baseline.records, &current.records)
}

/// A record array index (bounded by the index size, which fits `u32` by
/// construction) narrowed to the `u32` the result vectors carry.
#[inline]
fn len_to_u32(idx: usize) -> u32 {
    uffs_mft::len_to_u32(idx)
}

#[cfg(test)]
mod tests {
    use super::{DeltaReport, diff_records};
    use crate::compact::CompactRecord;

    /// Build a real (non-synthetic) record with the given File Reference parts
    /// and the metadata the diff keys on. `name_offset` is set to `idx` only so
    /// distinct rows are visibly distinct; the diff ignores it.
    fn rec(frs: u64, seq: u16, size: u64, modified: i64) -> CompactRecord {
        CompactRecord {
            size,
            modified,
            file_ref: CompactRecord::pack_file_reference(frs, seq),
            ..CompactRecord::default()
        }
    }

    #[test]
    fn identical_indexes_produce_an_empty_delta() {
        let baseline = [rec(10, 1, 100, 5), rec(11, 1, 200, 6)];
        let current = baseline;
        let report = diff_records(&baseline, &current);
        assert!(report.is_empty(), "no changes must yield an empty delta");
        assert_eq!(report.len(), 0);
    }

    #[test]
    fn pure_add_is_classified_added() {
        let baseline = [rec(10, 1, 100, 5)];
        let current = [rec(10, 1, 100, 5), rec(12, 1, 50, 9)];
        let report = diff_records(&baseline, &current);
        assert_eq!(report.added, vec![1], "the new row (idx 1) is an add");
        assert!(report.deleted.is_empty());
        assert!(report.modified.is_empty());
    }

    #[test]
    fn pure_delete_is_classified_deleted() {
        let baseline = [rec(10, 1, 100, 5), rec(11, 1, 200, 6)];
        let current = [rec(10, 1, 100, 5)];
        let report = diff_records(&baseline, &current);
        assert_eq!(report.deleted, vec![1], "baseline idx 1 vanished");
        assert!(report.added.is_empty());
        assert!(report.modified.is_empty());
    }

    #[test]
    fn changed_size_is_classified_modified() {
        let baseline = [rec(10, 1, 100, 5)];
        let current = [rec(10, 1, 999, 5)];
        let report = diff_records(&baseline, &current);
        assert_eq!(report.modified, vec![0], "same ref, changed size → modify");
        assert!(report.added.is_empty());
        assert!(report.deleted.is_empty());
    }

    #[test]
    fn changed_mtime_is_classified_modified() {
        let baseline = [rec(10, 1, 100, 5)];
        let current = [rec(10, 1, 100, 77)];
        let report = diff_records(&baseline, &current);
        assert_eq!(report.modified, vec![0], "same ref, changed mtime → modify");
    }

    /// The anchor test: a delete-then-reuse of the *same MFT slot* bumps the
    /// sequence number. FRS-only keying would call this a "modify"; keying on
    /// the full File Reference makes it an exact delete + add.
    #[test]
    fn slot_reuse_is_delete_plus_add_not_modify() {
        let baseline = [rec(10, 3, 100, 5)]; // (frs=10, seq=3)
        let current = [rec(10, 4, 4096, 9)]; // same slot, seq bumped → different file
        let report = diff_records(&baseline, &current);
        assert_eq!(report.deleted, vec![0], "seq-3 incarnation was deleted");
        assert_eq!(report.added, vec![0], "seq-4 incarnation was added");
        assert!(
            report.modified.is_empty(),
            "slot reuse must NOT be reported as an in-place modify",
        );
    }

    #[test]
    fn synthetic_rows_file_ref_zero_are_ignored() {
        // A default (file_ref == 0) row on each side plus one real unchanged
        // file. Only the real file participates; the synthetic rows never
        // classify, even though their default (size, modified) "match".
        let baseline = [CompactRecord::default(), rec(10, 1, 100, 5)];
        let current = [
            CompactRecord::default(),
            rec(10, 1, 100, 5),
            CompactRecord::default(),
        ];
        let report = diff_records(&baseline, &current);
        assert!(
            report.is_empty(),
            "synthetic file_ref==0 rows must never be added/deleted/modified, got {report:?}",
        );
    }

    #[test]
    fn hard_links_sharing_a_reference_all_report_on_delete() {
        // Two names (hard links) share one File Reference. Deleting the file
        // drops both baseline rows; each is a distinct path, so both report.
        let shared = rec(20, 2, 512, 3);
        let baseline = [shared, shared];
        let current: [CompactRecord; 0] = [];
        let report = diff_records(&baseline, &current);
        assert_eq!(
            report.deleted,
            vec![0, 1],
            "both hard-link rows of the deleted file must surface",
        );
    }

    #[test]
    fn mixed_delta_classifies_each_class_independently() {
        // idx0 unchanged, idx1 deleted, plus one add and one in-place modify.
        let baseline = [
            rec(10, 1, 100, 5), // unchanged
            rec(11, 1, 200, 6), // deleted
            rec(12, 1, 300, 7), // will be modified
        ];
        let current = [
            rec(10, 1, 100, 5),  // unchanged
            rec(12, 1, 4096, 7), // idx1: modified (size changed)
            rec(13, 1, 10, 8),   // idx2: added
        ];
        let report = diff_records(&baseline, &current);
        assert_eq!(report.added, vec![2]);
        assert_eq!(report.deleted, vec![1]);
        assert_eq!(report.modified, vec![1]);
        assert_eq!(report.len(), 3);
    }

    #[test]
    fn delta_report_len_and_is_empty_agree() {
        let empty = DeltaReport::default();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        let one = DeltaReport {
            added: vec![0],
            ..DeltaReport::default()
        };
        assert!(!one.is_empty());
        assert_eq!(one.len(), 1);
    }
}
