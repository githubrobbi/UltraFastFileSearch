// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Duplicate file analytics.
//!
//! Groups files by composite key (default: size + name) and identifies
//! candidate duplicate groups. Optionally verifies via first-bytes
//! comparison or full SHA-256 hash.

use core::hash::{Hash, Hasher as _};
use std::collections::HashMap;

use super::accumulators::StatsAccumulator;
use super::spec::DuplicateVerify;
use crate::compact::{CompactRecord, DriveCompactIndex};
use crate::search::field::FieldId;

/// Composite key for duplicate grouping.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CompositeKey {
    /// Key components as u64 values.
    components: Vec<u64>,
    /// Name component (if name is part of the key).
    name_hash: u64,
}

impl CompositeKey {
    /// Build a composite key from a record using the specified fields.
    #[must_use]
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "only key-eligible FieldId variants contribute to composite hash; non-key fields are intentionally ignored"
    )]
    pub(crate) fn from_record(
        record: &CompactRecord,
        drive: &DriveCompactIndex,
        key_fields: &[FieldId],
    ) -> Self {
        let mut components = Vec::with_capacity(key_fields.len());
        let mut name_hash = 0_u64;

        for field in key_fields {
            match field {
                FieldId::Size => components.push(record.size),
                FieldId::SizeOnDisk => components.push(record.allocated),
                FieldId::Extension => {
                    // `extension_id` is a per-drive intern id — the same
                    // extension gets different ids on different drives (and
                    // the same id can mean different extensions), so the id
                    // must never enter a cross-drive merge key. Hash the
                    // interned extension string instead (already lowercased
                    // by the interner, so equal across drives).
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    if let Some(ext) = drive.ext_names.get(usize::from(record.extension_id)) {
                        ext.hash(&mut hasher);
                    }
                    components.push(hasher.finish());
                }
                FieldId::Modified => components.push(uffs_mft::nonneg_to_u64(record.modified)),
                FieldId::Created => components.push(uffs_mft::nonneg_to_u64(record.created)),
                FieldId::Name => {
                    // Hash the lowercase name for the composite key
                    // (case-insensitive grouping — NTFS is case-preserving
                    // but case-insensitive).
                    let name = record.name(&drive.names);
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    for ch in name.chars() {
                        ch.to_ascii_lowercase().hash(&mut hasher);
                    }
                    name_hash = hasher.finish();
                }
                _ => {}
            }
        }

        Self {
            components,
            name_hash,
        }
    }
}

/// A duplicate group — a set of records sharing the same composite key.
#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    /// Number of files in this group.
    pub count: u64,
    /// Total size of all files in this group.
    pub total_bytes: u64,
    /// Size of one file (all should be same if size is a key).
    pub file_size: u64,
    /// Bytes reclaimable (total - one copy).
    pub reclaimable_bytes: u64,
    /// Record indices of members (for sample row output).
    pub member_indices: Vec<(usize, u8)>, // (record_idx, drive_ordinal)
    /// Materialized sample rows — populated during finalization when
    /// `drives` are available.  Empty until then.
    pub sample_rows: Vec<super::finalize::SampleRow>,
    /// Verification status.
    pub verified: bool,
}

/// Duplicate detection accumulator.
#[derive(Debug, Clone)]
pub struct DuplicateAccumulator {
    /// Per-group data, keyed by composite key.
    groups: HashMap<CompositeKey, DuplicateGroupBuilder>,
    /// Key fields for grouping.
    key_fields: Vec<FieldId>,
    /// Verification mode.
    verify: DuplicateVerify,
    /// Max groups to track.
    max_groups: u32,
    /// Max sample rows per group.
    sample: u8,
    /// Current drive ordinal being scanned.
    current_drive: u8,
}

/// Builder for accumulating a duplicate group during scan.
#[derive(Debug, Clone)]
struct DuplicateGroupBuilder {
    /// Stats for this group.
    stats: StatsAccumulator,
    /// Sample member indices (limited to `sample` count).
    members: Vec<(usize, u8)>,
    /// Max sample count.
    max_sample: u8,
}

impl DuplicateGroupBuilder {
    /// Create a new group builder.
    fn new(max_sample: u8) -> Self {
        Self {
            stats: StatsAccumulator::new(),
            members: Vec::with_capacity(usize::from(max_sample)),
            max_sample,
        }
    }

    /// Add a record to this group.
    fn add(&mut self, record: &CompactRecord, idx: usize, drive_ordinal: u8) {
        self.stats.feed_value(record.size, record.allocated);
        if self.members.len() < usize::from(self.max_sample) {
            self.members.push((idx, drive_ordinal));
        }
    }
}

impl DuplicateAccumulator {
    /// Create a new duplicate accumulator.
    #[must_use]
    pub fn new(
        key_fields: Vec<FieldId>,
        verify: DuplicateVerify,
        max_groups: u32,
        sample: u8,
    ) -> Self {
        Self {
            groups: HashMap::new(),
            key_fields,
            verify,
            max_groups,
            sample,
            current_drive: 0,
        }
    }

    /// Set the current drive ordinal (call before scanning each drive).
    pub const fn set_drive_ordinal(&mut self, ordinal: u8) {
        self.current_drive = ordinal;
    }

    /// Feed a record.
    #[inline]
    pub fn feed(&mut self, record: &CompactRecord, drive: &DriveCompactIndex, idx: usize) {
        // Skip directories — duplicates are files only.
        if record.flags & 0x0010 != 0 {
            return;
        }

        // Skip zero-byte files.
        if record.size == 0 {
            return;
        }

        // OOM guard.
        if uffs_mft::len_to_u32(self.groups.len()) >= self.max_groups {
            // Only feed existing groups, don't create new ones.
            let key = CompositeKey::from_record(record, drive, &self.key_fields);
            if let Some(group) = self.groups.get_mut(&key) {
                group.add(record, idx, self.current_drive);
            }
            return;
        }

        let key = CompositeKey::from_record(record, drive, &self.key_fields);
        self.groups
            .entry(key)
            .or_insert_with(|| DuplicateGroupBuilder::new(self.sample))
            .add(record, idx, self.current_drive);
    }

    /// Merge another accumulator's groups into this one.
    ///
    /// Used by the parallel aggregation reducer: each per-drive scan
    /// builds its own `DuplicateAccumulator`, then this method combines
    /// them so that records sharing the same `CompositeKey` across drives
    /// collapse into one group with a summed `count`, merged stats, and a
    /// union of member indices up to `max_sample`.
    ///
    /// Behaviour notes:
    ///
    /// * Groups present on both sides → stats merge; members from `other` are
    ///   appended to `self`'s list, respecting `max_sample`.
    /// * Groups present only in `other` → cloned into `self`, subject to the
    ///   `max_groups` OOM cap (matches [`Self::feed`]'s policy).
    /// * `current_drive` is a transient scan-time field and is not touched —
    ///   members already carry the correct drive ordinal from when they were
    ///   fed on each per-drive pass.
    #[expect(
        clippy::iter_over_hash_type,
        reason = "per-key merge is order-independent: each group merges by key into self"
    )]
    pub fn merge(&mut self, other: &Self) {
        for (key, other_builder) in &other.groups {
            if let Some(existing) = self.groups.get_mut(key) {
                existing.stats.merge(&other_builder.stats);
                let cap = usize::from(existing.max_sample);
                let remaining = cap.saturating_sub(existing.members.len());
                for member in other_builder.members.iter().take(remaining) {
                    existing.members.push(*member);
                }
            } else if uffs_mft::len_to_u32(self.groups.len()) < self.max_groups {
                self.groups.insert(key.clone(), other_builder.clone());
            }
        }
    }

    /// Finalize: drop singletons, sort by reclaimable bytes, return top groups.
    #[must_use]
    pub fn finalize(self, top: u16) -> DuplicateResult {
        let mut groups: Vec<DuplicateGroup> = self
            .groups
            .into_iter()
            .filter(|(_, group)| group.stats.count > 1) // Drop singletons
            .map(|(_, group)| {
                let file_size = group.stats.sum.checked_div(group.stats.count).unwrap_or(0);
                let reclaimable = group.stats.sum.saturating_sub(file_size);
                DuplicateGroup {
                    count: group.stats.count,
                    total_bytes: group.stats.sum,
                    file_size,
                    reclaimable_bytes: reclaimable,
                    member_indices: group.members,
                    sample_rows: Vec::new(), // populated by finalize_one
                    verified: matches!(self.verify, DuplicateVerify::None),
                }
            })
            .collect();

        // Sort by reclaimable bytes descending.
        groups.sort_by_key(|group| core::cmp::Reverse(group.reclaimable_bytes));

        let total_groups = groups.len();
        let total_duplicate_files: u64 = groups.iter().map(|group| group.count).sum();
        let total_reclaimable: u64 = groups.iter().map(|group| group.reclaimable_bytes).sum();

        groups.truncate(usize::from(top));

        DuplicateResult {
            candidate_groups: total_groups,
            candidate_files: total_duplicate_files,
            total_duplicate_bytes: groups.iter().map(|group| group.total_bytes).sum(),
            total_reclaimable_bytes: total_reclaimable,
            groups,
            verification_mode: self.verify,
        }
    }
}

/// Result of duplicate analysis.
#[derive(Debug, Clone)]
pub struct DuplicateResult {
    /// Number of candidate duplicate groups (count > 1).
    pub candidate_groups: usize,
    /// Total files across all candidate groups.
    pub candidate_files: u64,
    /// Total bytes in duplicate groups.
    pub total_duplicate_bytes: u64,
    /// Total reclaimable bytes (total - one copy per group).
    pub total_reclaimable_bytes: u64,
    /// Top duplicate groups sorted by reclaimable bytes.
    pub groups: Vec<DuplicateGroup>,
    /// Verification mode used.
    pub verification_mode: DuplicateVerify,
}

#[cfg(test)]
mod tests;
