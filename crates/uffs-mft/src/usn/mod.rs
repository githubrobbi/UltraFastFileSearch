// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! # USN Journal Integration (M5 Optimization)
//!
//! This module provides USN (Update Sequence Number) Journal integration for
//! incremental index updates. Instead of rescanning the entire MFT, we can
//! query the USN Journal for changes since the last index build.
//!
//! ## Module layout
//!
//! * This file (`usn/mod.rs`) holds the platform-agnostic types — the [`Usn`]
//!   newtype, the DTOs ([`UsnJournalInfo`] / [`UsnRecord`] / [`FileChange`]),
//!   the [`reason`] flag constants, the [`ChangeType`] taxonomy, the
//!   [`aggregate_changes`] helper, and the non-Windows error stubs.
//! * `usn/windows.rs` (Windows only) contains the `#[repr(C)]` Win32 ABI mirror
//!   structs and the `FSCTL_QUERY_USN_JOURNAL` / `FSCTL_READ_USN_JOURNAL` /
//!   targeted-FRS-read FFI helpers.  Its public functions are re-exported by
//!   this module under `#[cfg(windows)]`.
//!
//! ## Windows API
//!
//! - `FSCTL_QUERY_USN_JOURNAL` - Get journal info (ID, first/next USN)
//! - `FSCTL_READ_USN_JOURNAL` - Read changes since a given USN
//!
//! ## Change Types
//!
//! - `USN_REASON_FILE_CREATE` - New file created
//! - `USN_REASON_FILE_DELETE` - File deleted
//! - `USN_REASON_RENAME_NEW_NAME` - File renamed
//! - `USN_REASON_DATA_EXTEND/TRUNCATE` - File size changed
//! - `USN_REASON_BASIC_INFO_CHANGE` - Timestamps changed

use core::fmt;
use std::collections::HashMap;

use crate::frs::{Frs, ParentFrs};

/// Monotonically-increasing per-volume Update Sequence Number from the
/// NTFS USN journal.
///
/// Newtype wrapper around the raw `i64` (`LONGLONG`) the Win32 ABI uses
/// for USNs — `FSCTL_QUERY_USN_JOURNAL` / `FSCTL_READ_USN_JOURNAL` and the
/// `USN_RECORD_V2` header all carry signed 64-bit values, and we preserve
/// that representation byte-for-byte so on-disk + on-wire formats are
/// unchanged.
///
/// # Invariants
///
/// Carried by the type system:
///
/// * `Copy + Eq + Hash` — safe to drop into `HashMap` / `BTreeMap` keys,
///   compare cheaply across cursor checkpoints, and pass by value.
/// * `Ord` — monotonic comparison (`cached < current_first` / `start >= next`)
///   is now expressed against the typed value rather than ad-hoc `i64`
///   arithmetic on bare fields.
///
/// Not carried by the type system (kernel-issued / format-defined):
///
/// * Strict monotonicity within a single `journal_id` (kernel-enforced).
/// * Cross-journal-id ordering is meaningless; callers must compare
///   `journal_id` separately before comparing `Usn`s.
///
/// # `ZERO` sentinel
///
/// [`Usn::ZERO`] mirrors the Win32 convention that `0` means *"no prior
/// checkpoint — read from journal head"*.  Use [`Self::is_zero`] for
/// readability at the wrap-detection / first-run call sites.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Usn(i64);

impl Usn {
    /// Sentinel meaning *"no prior checkpoint"* — read from journal head.
    ///
    /// Matches the Win32 convention for `FSCTL_READ_USN_JOURNAL` where a
    /// `StartUsn` of `0` requests the oldest still-readable record.
    pub const ZERO: Self = Self(0);

    /// Wrap a raw `i64` from a Win32 USN-journal ioctl or persisted
    /// cursor.
    ///
    /// USNs are kernel-issued — there is no client-side validation we
    /// can perform on a single value in isolation.  Monotonicity is the
    /// caller's responsibility (and is made trivial by the [`Ord`] impl).
    #[must_use]
    pub const fn new(raw: i64) -> Self {
        Self(raw)
    }

    /// Underlying raw `i64`.
    ///
    /// Use this **only** at FFI / serialization boundaries
    /// (`FSCTL_READ_USN_JOURNAL` input, `to_le_bytes()` for the cache
    /// header).  Internal logic should compare [`Usn`] values directly
    /// via the [`Ord`] impl.
    #[must_use]
    pub const fn raw(self) -> i64 {
        self.0
    }

    /// `true` when this value equals [`Usn::ZERO`].
    ///
    /// Used at wrap-detection sites to special-case the *"no prior
    /// checkpoint — read from journal head"* condition without resorting
    /// to a `== 0` literal that hides intent.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl From<i64> for Usn {
    fn from(raw: i64) -> Self {
        Self(raw)
    }
}

impl From<Usn> for i64 {
    fn from(value: Usn) -> Self {
        value.0
    }
}

impl fmt::Display for Usn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// USN Journal information returned by `FSCTL_QUERY_USN_JOURNAL`.
#[derive(Debug, Clone)]
pub struct UsnJournalInfo {
    /// Unique identifier for this journal instance
    pub journal_id: u64,
    /// First valid USN in the journal
    pub first_usn: Usn,
    /// Next USN to be assigned
    pub next_usn: Usn,
    /// Lowest valid USN (may differ from `first_usn`)
    pub lowest_valid_usn: Usn,
    /// Maximum USN (journal size limit)
    pub max_usn: Usn,
    /// Maximum size of the journal in bytes
    pub max_size: u64,
    /// Allocation delta (how much journal grows)
    pub allocation_delta: u64,
}

/// A single USN Journal change record.
#[derive(Debug, Clone)]
pub struct UsnRecord {
    /// File Reference Number (typed [`Frs`] — fixed at the on-disk
    /// parser boundary in `usn::windows::read_usn_journal`).
    pub frs: Frs,
    /// Parent directory FRS (typed [`ParentFrs`]).
    pub parent_frs: ParentFrs,
    /// USN of this record
    pub usn: Usn,
    /// Reason flags (bitmask of `USN_REASON_*`)
    pub reason: u32,
    /// File attributes
    pub file_attributes: u32,
    /// Filename
    pub filename: String,
}

/// USN reason flags (from Windows SDK).
pub mod reason {
    /// Data in the default data stream was overwritten.
    pub const DATA_OVERWRITE: u32 = 0x0000_0001;
    /// Data in the default data stream was extended.
    pub const DATA_EXTEND: u32 = 0x0000_0002;
    /// Data in the default data stream was truncated.
    pub const DATA_TRUNCATION: u32 = 0x0000_0004;
    /// Data in a named data stream was overwritten.
    pub const NAMED_DATA_OVERWRITE: u32 = 0x0000_0010;
    /// Data in a named data stream was extended.
    pub const NAMED_DATA_EXTEND: u32 = 0x0000_0020;
    /// Data in a named data stream was truncated.
    pub const NAMED_DATA_TRUNCATION: u32 = 0x0000_0040;
    /// A new file or directory was created.
    pub const FILE_CREATE: u32 = 0x0000_0100;
    /// A file or directory was deleted.
    pub const FILE_DELETE: u32 = 0x0000_0200;
    /// Extended attributes were changed.
    pub const EA_CHANGE: u32 = 0x0000_0400;
    /// Security descriptor was changed.
    pub const SECURITY_CHANGE: u32 = 0x0000_0800;
    /// File or directory was renamed (old name).
    pub const RENAME_OLD_NAME: u32 = 0x0000_1000;
    /// File or directory was renamed (new name).
    pub const RENAME_NEW_NAME: u32 = 0x0000_2000;
    /// Indexable content was changed.
    pub const INDEXABLE_CHANGE: u32 = 0x0000_4000;
    /// Basic file attributes were changed.
    pub const BASIC_INFO_CHANGE: u32 = 0x0000_8000;
    /// Hard link was added or removed.
    pub const HARD_LINK_CHANGE: u32 = 0x0001_0000;
    /// Compression state was changed.
    pub const COMPRESSION_CHANGE: u32 = 0x0002_0000;
    /// Encryption state was changed.
    pub const ENCRYPTION_CHANGE: u32 = 0x0004_0000;
    /// Object ID was changed.
    pub const OBJECT_ID_CHANGE: u32 = 0x0008_0000;
    /// Reparse point was changed.
    pub const REPARSE_POINT_CHANGE: u32 = 0x0010_0000;
    /// Named data stream was added or removed.
    pub const STREAM_CHANGE: u32 = 0x0020_0000;
    /// Transacted change.
    pub const TRANSACTED_CHANGE: u32 = 0x0040_0000;
    /// Integrity state was changed.
    pub const INTEGRITY_CHANGE: u32 = 0x0080_0000;
    /// File handle was closed (final record for a change).
    pub const CLOSE: u32 = 0x8000_0000;
}

/// Categorized change type for easier processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeType {
    /// File was created
    Created,
    /// File was deleted
    Deleted,
    /// File was renamed (new name)
    Renamed,
    /// File size changed
    SizeChanged,
    /// File metadata changed (timestamps, attributes)
    MetadataChanged,
    /// Other change (not directly relevant to index)
    Other,
}

impl UsnRecord {
    /// Categorizes this USN record into a `ChangeType`.
    #[must_use]
    pub const fn change_type(&self) -> ChangeType {
        // DELETE before CREATE: a single close record can carry both bits
        // when a file is created and removed within one open→close cycle
        // (e.g. a transient temp file). The net is "gone", so it must
        // classify as Deleted. Distinct create/delete events (the FRS-reuse
        // case) arrive as separate records and are unaffected by this order.
        if self.reason & reason::FILE_DELETE != 0 {
            ChangeType::Deleted
        } else if self.reason & reason::FILE_CREATE != 0 {
            ChangeType::Created
        } else if self.reason & reason::RENAME_NEW_NAME != 0 {
            ChangeType::Renamed
        } else if self.reason & (reason::DATA_EXTEND | reason::DATA_TRUNCATION) != 0 {
            ChangeType::SizeChanged
        } else if self.reason & reason::BASIC_INFO_CHANGE != 0 {
            ChangeType::MetadataChanged
        } else {
            ChangeType::Other
        }
    }

    /// Returns true if this is a "close" record (final record for a change).
    #[must_use]
    pub const fn is_close(&self) -> bool {
        self.reason & reason::CLOSE != 0
    }
}

/// Real per-file metadata that a USN record does NOT carry (size,
/// allocation, timestamps, attribute flags).
///
/// A `UsnRecord` only conveys the FRS, parent FRS, name, and reason flags,
/// so a file created/renamed via the live journal lands in the index with
/// size 0 and zero timestamps. When the journal source issues a targeted
/// MFT read (`read_targeted_frs_records`) to recover the real values, it
/// attaches them here so `apply_usn_patch` can populate the record fully —
/// matching what a cold rebuild would store. Field representation mirrors
/// `CompactRecord` exactly (i64 µs timestamps, raw NTFS attribute flags),
/// so application is a straight copy with no conversion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecordMeta {
    /// Logical file size in bytes.
    pub size: u64,
    /// Allocated size on disk in bytes.
    pub allocated: u64,
    /// Creation time (Unix microseconds).
    pub created: i64,
    /// Last write time (Unix microseconds).
    pub modified: i64,
    /// Last access time (Unix microseconds).
    pub accessed: i64,
    /// Raw NTFS `FILE_ATTRIBUTE_*` flags.
    pub flags: u32,
}

/// Aggregated changes for a single file (consolidates multiple USN records).
// These bools represent independent change flags from USN journal records.
// Using a bitflags pattern would add complexity without benefit for this DTO.
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent change flags from USN journal records"
)]
#[derive(Debug, Clone, Default)]
pub struct FileChange {
    /// File Reference Number (typed [`Frs`]).
    pub frs: Frs,
    /// Parent directory FRS — latest seen across the aggregated
    /// `UsnRecord` stream (typed [`ParentFrs`]).
    pub parent_frs: ParentFrs,
    /// Filename (latest)
    pub filename: String,
    /// Was the file created?
    pub created: bool,
    /// Was the file deleted?
    pub deleted: bool,
    /// Was the file renamed?
    pub renamed: bool,
    /// Did the file size change?
    pub size_changed: bool,
    /// Did metadata change?
    pub metadata_changed: bool,
    /// Real size/timestamp/flags metadata, when a targeted MFT read
    /// backfilled it (USN records carry none). `None` → the applier leaves
    /// the record's metrics zeroed for a later re-warm to fill.
    pub meta: Option<RecordMeta>,
}

/// Aggregates multiple USN records into per-file changes.
///
/// Keyed by the typed [`Frs`] — `Frs` derives `Hash + Eq + Copy` so
/// dropping it into a `HashMap` key is bit-identical to keying on the
/// raw `u64` it wraps.
#[must_use]
pub fn aggregate_changes(records: &[UsnRecord]) -> HashMap<Frs, FileChange> {
    let mut changes: HashMap<Frs, FileChange> = HashMap::new();
    for record in records {
        let entry = changes.entry(record.frs).or_insert_with(|| FileChange {
            frs: record.frs,
            ..Default::default()
        });
        entry.parent_frs = record.parent_frs;
        if !record.filename.is_empty() {
            entry.filename.clone_from(&record.filename);
        }
        // Records arrive in USN (time) order. The create/delete/rename flags
        // are mutually exclusive *net states* for the slot: the LAST such
        // event wins, so reusing an MFT record number (delete old → create
        // new, same masked FRS) nets to a create, and a transient temp file
        // (create → delete) nets to a delete. Size/metadata are independent
        // and accumulate. Resolving order here keeps `apply_usn_patch`'s
        // simple deleted/created/renamed branch dispatch correct.
        match record.change_type() {
            ChangeType::Created => {
                entry.created = true;
                entry.deleted = false;
                entry.renamed = false;
            }
            ChangeType::Deleted => {
                entry.deleted = true;
                entry.created = false;
                entry.renamed = false;
            }
            ChangeType::Renamed => {
                entry.renamed = true;
                entry.deleted = false;
            }
            ChangeType::SizeChanged => entry.size_changed = true,
            ChangeType::MetadataChanged => entry.metadata_changed = true,
            ChangeType::Other => {}
        }
    }
    changes
}

// Windows-only FFI surface lives in a sibling file so this module stays
// under the workspace file-size policy without an exception entry.  All
// three functions are re-exported here so external callers continue to
// reach them via `uffs_mft::usn::*`.
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{query_usn_journal, read_targeted_frs_records, read_usn_journal};

/// Queries the USN Journal for a volume (non-Windows stub).
///
/// # Errors
///
/// Always returns an error on non-Windows platforms.
#[cfg(not(windows))]
pub fn query_usn_journal(
    _volume: crate::platform::DriveLetter,
) -> Result<UsnJournalInfo, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "USN Journal is only available on Windows",
    ))
}

/// Reads USN Journal records starting from a given USN (non-Windows stub).
///
/// # Errors
///
/// Always returns an error on non-Windows platforms.
#[cfg(not(windows))]
pub fn read_usn_journal(
    _volume: crate::platform::DriveLetter,
    _journal_id: u64,
    _start_usn: Usn,
) -> Result<(Vec<UsnRecord>, Usn), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "USN Journal is only available on Windows",
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::Usn;

    #[test]
    fn raw_roundtrip_preserves_i64_exactly() {
        // Wire-format contract: any `i64` the kernel hands us must come
        // back byte-identical via `raw()`.  This is what keeps the
        // on-disk `IndexHeader.next_usn` LE-bytes layout backwards
        // compatible after the newtype migration.
        for raw in [i64::MIN, -1, 0, 1, 42, i64::MAX] {
            assert_eq!(Usn::new(raw).raw(), raw, "round-trip drift for {raw}");
        }
    }

    #[test]
    fn from_into_i64_symmetry() {
        let raw: i64 = 0x0123_4567_89AB_CDEF;
        let usn: Usn = raw.into();
        let back: i64 = usn.into();
        assert_eq!(back, raw);
    }

    #[test]
    fn zero_sentinel_matches_literal_zero() {
        assert_eq!(Usn::ZERO, Usn::new(0));
        assert!(Usn::ZERO.is_zero());
        assert!(!Usn::new(1).is_zero());
        assert!(!Usn::new(-1).is_zero());
    }

    #[test]
    fn display_matches_raw_i64() {
        // Logs / tracing rely on `Display` rendering as the raw number,
        // not the Debug `Usn(N)` wrapper form.
        for raw in [i64::MIN, -1, 0, 1, 1_234_567, i64::MAX] {
            assert_eq!(format!("{}", Usn::new(raw)), raw.to_string());
        }
    }

    #[test]
    fn ord_matches_underlying_i64_ordering() {
        // Cache-wrap detection in `usn_apply::usn_journal_invalidates_cache`
        // compares `Usn`s directly; pin the `Ord` impl to the raw `i64`
        // ordering so cached_usn < first_usn behaves identically before
        // and after the migration.
        let earlier = Usn::new(100);
        let later = Usn::new(200);
        assert!(earlier < later);
        assert!(later > earlier);
        assert!(Usn::new(i64::MIN) < Usn::ZERO);
        assert!(Usn::ZERO < Usn::new(i64::MAX));
    }

    #[test]
    fn usable_as_hashmap_key() {
        // `Hash + Eq` are required by the aggregator paths that key
        // cursor checkpoints by their `Usn` value.
        let mut seen: HashMap<Usn, &'static str> = HashMap::new();
        seen.insert(Usn::new(1), "first");
        seen.insert(Usn::new(2), "second");
        assert_eq!(seen.get(&Usn::new(1)), Some(&"first"));
        assert_eq!(seen.get(&Usn::new(2)), Some(&"second"));
        assert_eq!(seen.get(&Usn::new(3)), None);
    }

    // ── aggregate_changes net-state resolution (was untested) ───────────
    //
    // The original aggregator OR-ed independent created/deleted/renamed
    // bools, losing the time order of the USN stream. NTFS reuses an MFT
    // record number after a delete, so a "delete old, create new" pair
    // lands on the same masked FRS in one poll window — and the net result
    // must reflect the LAST event, not both. These pin that.

    use super::{ChangeType, UsnRecord, aggregate_changes, reason};
    use crate::frs::{Frs, ParentFrs};

    /// Build a minimal `UsnRecord` for a given FRS, reason mask, and name.
    fn rec(frs: u64, reason_mask: u32, name: &str) -> UsnRecord {
        UsnRecord {
            frs: Frs::new(frs),
            parent_frs: ParentFrs::new(5),
            usn: Usn::new(0),
            reason: reason_mask,
            file_attributes: 0,
            filename: name.to_owned(),
        }
    }

    #[test]
    fn aggregate_delete_then_create_reuse_nets_to_created() {
        // FRS 42 deleted (old.txt), then the record number is reused by a
        // newly-created new.pdf — the journal emits both for masked FRS 42.
        // Net: the slot now holds new.pdf. Must NOT report a delete (that
        // would tombstone the brand-new file in apply_usn_patch).
        let records = vec![
            rec(42, reason::FILE_DELETE | reason::CLOSE, "old.txt"),
            rec(42, reason::FILE_CREATE | reason::CLOSE, "new.pdf"),
        ];
        let changes = aggregate_changes(&records);
        let change = changes.get(&Frs::new(42)).expect("FRS 42 present");
        assert!(change.created, "net of delete→create reuse is a create");
        assert!(!change.deleted, "must not also report a delete");
        assert_eq!(change.filename, "new.pdf", "carries the new name");
    }

    #[test]
    fn aggregate_create_then_delete_nets_to_deleted() {
        // A transient file: created then deleted in one window. Net: gone.
        let records = vec![
            rec(7, reason::FILE_CREATE, "temp.tmp"),
            rec(7, reason::FILE_DELETE | reason::CLOSE, "temp.tmp"),
        ];
        let changes = aggregate_changes(&records);
        let change = changes.get(&Frs::new(7)).expect("FRS 7 present");
        assert!(change.deleted, "net of create→delete is a delete");
        assert!(!change.created, "must not also report a create");
    }

    #[test]
    fn change_type_prefers_delete_when_create_and_delete_coincide() {
        // A single close record can carry create+delete in one reason mask
        // (file created and removed within one open→close cycle). The net
        // is "gone", so it must classify as Deleted, not Created.
        let record = rec(
            1,
            reason::FILE_CREATE | reason::FILE_DELETE | reason::CLOSE,
            "x",
        );
        assert!(matches!(record.change_type(), ChangeType::Deleted));
    }

    #[test]
    fn aggregate_keeps_unrelated_frs_separate() {
        // Sanity: two distinct FRS values never cross-contaminate.
        let records = vec![
            rec(10, reason::FILE_CREATE | reason::CLOSE, "a.pdf"),
            rec(20, reason::FILE_DELETE | reason::CLOSE, "b.dll"),
        ];
        let changes = aggregate_changes(&records);
        assert!(
            changes
                .get(&Frs::new(10))
                .is_some_and(|chg| chg.created && !chg.deleted)
        );
        assert!(
            changes
                .get(&Frs::new(20))
                .is_some_and(|chg| chg.deleted && !chg.created)
        );
    }
}
