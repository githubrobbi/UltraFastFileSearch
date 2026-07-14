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

use crate::compact::{CompactRecord, DriveCompactIndex, MalformedRender};
use crate::search::tree::resolve_path;

/// UFFS-internal marker bit set on a baseline [`CompactRecord`]'s `flags` to
/// tag it as a snapshot-diff **delete** (present in the baseline, absent from
/// the current index).
///
/// Bit 31 of the `u32` attribute word — deliberately **above** every NTFS
/// `FILE_ATTRIBUTE_*` bit (which top out at
/// `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x0040_0000`), so it never collides
/// with a real attribute and never renders in an attribute column. The daemon
/// sets it in `IndexManager::diff_search`;
/// [`crate::search::filters::SearchFilters::deleted`] filters on it.
pub const DELETED_TOMBSTONE_FLAG: u32 = 0x8000_0000;

/// The classified delta between a baseline and a current compact index.
///
/// Every entry is a **row index** into the corresponding index's record array,
/// not a resolved path: path reconstruction needs the whole index (the
/// parent-chain walk), so the caller resolves each index via
/// [`crate::search::tree::resolve_path`] against the right side — `deleted`
/// against the baseline, `added` / `modified` against the current.
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

// ────────────────────────────────────────────────────────────────────────────
// Path-resolved surface (what the daemon RPC / CLI consume)
// ────────────────────────────────────────────────────────────────────────────

/// One classified change with its row resolved to a full path and the metadata
/// a caller needs to render it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaEntry {
    /// Full path (`C:\Users\…\file.ext`), reconstructed by walking the parent
    /// chain in the side the row belongs to (baseline for deletes, current for
    /// adds/modifies).
    pub path: String,
    /// Logical file size in bytes. For a modify this is the *current* size; for
    /// a delete it is the last-known size from the baseline.
    pub size: u64,
    /// Last-write time (Unix microseconds), from the same side as `path`.
    pub modified: i64,
}

/// A [`DeltaReport`] with every row index resolved to a full path + metadata —
/// the presentation-ready form the daemon returns over the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedDelta {
    /// Files present in the current index but not the baseline (created).
    pub added: Vec<DeltaEntry>,
    /// Files present in the baseline but not the current (deleted).
    pub deleted: Vec<DeltaEntry>,
    /// Files in both whose `size` or `modified` timestamp changed.
    pub modified: Vec<DeltaEntry>,
    /// `true` when `limit` capped at least one class (more rows exist than were
    /// returned). `false` means every classified row is present.
    pub truncated: bool,
}

/// Diff two loaded indexes and resolve each classified row to a full path.
///
/// `limit` caps **each class independently** (`0` = unlimited); `truncated` is
/// set when any class had more rows than `limit`. Adds and modifies resolve
/// against `current`; deletes resolve against `baseline` — see [`DeltaReport`]
/// for why each side owns its rows.
#[must_use]
pub fn resolve_delta(
    baseline: &DriveCompactIndex,
    current: &DriveCompactIndex,
    limit: usize,
) -> ResolvedDelta {
    let report = diff_indexes(baseline, current);
    let mut truncated = false;
    let added = resolve_class(current, &report.added, limit, &mut truncated);
    let deleted = resolve_class(baseline, &report.deleted, limit, &mut truncated);
    let modified = resolve_class(current, &report.modified, limit, &mut truncated);
    ResolvedDelta {
        added,
        deleted,
        modified,
        truncated,
    }
}

/// Resolve one class's row indices against `drive`, capping at `limit`
/// (`0` = unlimited) and flagging `truncated` when the cap drops any rows.
fn resolve_class(
    drive: &DriveCompactIndex,
    indices: &[u32],
    limit: usize,
    truncated: &mut bool,
) -> Vec<DeltaEntry> {
    let prefix = format!("{}:\\", drive.letter);
    let capped = if limit > 0 && indices.len() > limit {
        *truncated = true;
        indices.get(..limit).unwrap_or(indices)
    } else {
        indices
    };
    capped
        .iter()
        .filter_map(|&raw_idx| {
            let idx = raw_idx as usize;
            let rec = drive.records.get(idx)?;
            Some(DeltaEntry {
                path: resolve_path(drive, idx, &prefix, MalformedRender::Lossy),
                size: rec.size,
                modified: rec.modified,
            })
        })
        .collect()
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

    // ── Path-resolved surface ────────────────────────────────────────────

    use alloc::sync::Arc;
    use std::path::PathBuf;

    use uffs_text::case_fold::CaseFold;

    use super::resolve_delta;
    use crate::compact::{ChildrenIndex, DriveCompactIndex, ExtensionIndex, IndexSource};
    use crate::compact_storage::ColumnStorage;
    use crate::trigram::TrigramIndex;

    /// Shared names blob for the resolution fixtures:
    /// `C`[0..1] `docs`[1..5] `a.txt`[5..10] `b.txt`[10..15] `c.txt`[15..20].
    const NAMES: &[u8] = b"Cdocsa.txtb.txtc.txt";

    /// A leaf-file record under `docs` (idx 1) with the given identity + size.
    fn file(name_offset: u32, first: u8, frs: u64, size: u64, modified: i64) -> CompactRecord {
        CompactRecord {
            size,
            modified,
            file_ref: CompactRecord::pack_file_reference(frs, 1),
            name_offset,
            parent_idx: 1,
            name_len: 5,
            name_first_byte: first,
            ..CompactRecord::default()
        }
    }

    /// Build a resolvable drive: root `C` (idx0), dir `docs` (idx1), then the
    /// given leaf files (idx2..). Root/dir carry no diff identity (`file_ref`
    /// 0 / an unchanging dir ref), so only the leaves drive the delta.
    fn drive(files: Vec<CompactRecord>) -> DriveCompactIndex {
        let mut records = vec![
            CompactRecord {
                name_offset: 0,
                flags: 0x10,
                parent_idx: u32::MAX,
                name_len: 1,
                name_first_byte: b'C',
                ..CompactRecord::default()
            },
            CompactRecord {
                file_ref: CompactRecord::pack_file_reference(100, 1),
                name_offset: 1,
                flags: 0x10,
                parent_idx: 0,
                name_len: 4,
                name_first_byte: b'd',
                ..CompactRecord::default()
            },
        ];
        records.extend(files);
        let names = NAMES.to_vec();
        let fold = CaseFold::default_table();
        let trigram = TrigramIndex::build(&records, &names, fold);
        let children = ChildrenIndex::build(&records);
        let ext_index = ExtensionIndex::build(&records);
        DriveCompactIndex {
            letter: uffs_mft::platform::DriveLetter::C,
            records: ColumnStorage::from_vec(records),
            names: ColumnStorage::from_vec(names),
            trigram: Arc::new(trigram),
            children: Arc::new(children),
            ext_index: Arc::new(ext_index),
            fold,
            ext_names: vec![Box::from("")],
            source: IndexSource::MftFile(PathBuf::from("C:")),
            source_epoch: 1,
            bloom: None,
            path_trie: None,
            frs_to_compact: Vec::new(),
            delta: None,
        }
    }

    #[test]
    fn resolve_delta_classifies_and_resolves_full_paths() {
        // baseline: a.txt (200), b.txt (201).
        let baseline = drive(vec![
            file(5, b'a', 200, 100, 5),
            file(10, b'b', 201, 200, 6),
        ]);
        // current: a.txt grew (modified), b.txt gone (delete), c.txt new (add).
        let current = drive(vec![file(5, b'a', 200, 999, 5), file(15, b'c', 202, 50, 9)]);

        let delta = resolve_delta(&baseline, &current, 0);

        assert_eq!(delta.added.len(), 1, "c.txt is the only add");
        let added = delta.added.first().expect("one add");
        assert!(added.path.ends_with("docs\\c.txt"), "{:?}", added.path);
        assert_eq!(added.size, 50);

        assert_eq!(delta.deleted.len(), 1, "b.txt is the only delete");
        let deleted = delta.deleted.first().expect("one delete");
        assert!(deleted.path.ends_with("docs\\b.txt"), "{:?}", deleted.path);
        assert_eq!(deleted.size, 200, "delete carries the baseline size");

        assert_eq!(delta.modified.len(), 1, "a.txt is the only modify");
        let modified = delta.modified.first().expect("one modify");
        assert!(
            modified.path.ends_with("docs\\a.txt"),
            "{:?}",
            modified.path
        );
        assert_eq!(modified.size, 999, "modify carries the current size");

        assert!(!delta.truncated, "no limit → nothing truncated");
    }

    #[test]
    fn resolve_delta_limit_caps_each_class_and_flags_truncation() {
        // Two adds; a limit of 1 keeps one and marks the delta truncated.
        let baseline = drive(vec![]);
        let current = drive(vec![file(5, b'a', 200, 1, 1), file(10, b'b', 201, 2, 2)]);
        let delta = resolve_delta(&baseline, &current, 1);
        assert_eq!(delta.added.len(), 1, "limit 1 keeps a single add");
        assert!(
            delta.truncated,
            "dropping the second add must flag truncation"
        );
    }
}
