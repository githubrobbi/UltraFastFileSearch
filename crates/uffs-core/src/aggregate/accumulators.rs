// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Accumulator types for the aggregation engine.
//!
//! Each [`GroupAccumulator`] tracks statistics for one logical aggregation
//! (count, stats, terms, histogram, etc.). During the scan phase,
//! `feed()` is called for every matching record. After scanning,
//! `finalize()` produces the data needed for the response.

use super::spec::{AggregateKind, BucketMetric, ScalarMetric, TopHitsSpec};
use crate::compact::{CompactRecord, DriveCompactIndex};
use crate::search::field::FieldId;

/// Running statistics for a single group or global scope.
///
/// Tracks count, sum, min, max, and accumulates enough data to
/// compute avg. All values are stored as `u64` (sizes) or `i64`
/// (timestamps). The caller is responsible for interpreting the
/// type based on the source `FieldId`.
#[derive(Debug, Clone)]
pub struct StatsAccumulator {
    /// Number of records in this group.
    pub count: u64,
    /// Sum of values (meaningful for size fields).
    pub sum: u64,
    /// Minimum value seen.
    pub min: u64,
    /// Maximum value seen.
    pub max: u64,
    /// Sum of allocated sizes (for waste calculation).
    pub sum_allocated: u64,
}

impl StatsAccumulator {
    /// Create a new empty stats accumulator.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            count: 0,
            sum: 0,
            min: u64::MAX,
            max: 0,
            sum_allocated: 0,
        }
    }

    /// Feed a value from a record.
    #[inline]
    pub(crate) const fn feed_value(&mut self, value: u64, allocated: u64) {
        self.count += 1;
        self.sum += value;
        if value < self.min {
            self.min = value;
        }
        if value > self.max {
            self.max = value;
        }
        self.sum_allocated += allocated;
    }

    /// Merge another accumulator into this one.
    pub(crate) const fn merge(&mut self, other: &Self) {
        self.count += other.count;
        self.sum += other.sum;
        if other.min < self.min {
            self.min = other.min;
        }
        if other.max > self.max {
            self.max = other.max;
        }
        self.sum_allocated += other.sum_allocated;
    }

    /// Compute the average value (returns 0 if count is 0).
    #[must_use]
    #[expect(
        clippy::float_arithmetic,
        reason = "integer count→f64 division is the documented average formula"
    )]
    pub(crate) fn avg(&self) -> f64 {
        if self.count == 0 {
            0.0_f64
        } else {
            uffs_mft::u64_to_f64(self.sum) / uffs_mft::u64_to_f64(self.count)
        }
    }

    /// Compute waste bytes: `sum_allocated - sum`.
    #[must_use]
    pub(crate) const fn waste_bytes(&self) -> u64 {
        self.sum_allocated.saturating_sub(self.sum)
    }

    /// Compute waste percentage.
    #[must_use]
    #[expect(
        clippy::float_arithmetic,
        reason = "integer waste→f64 division×100 is the documented percentage formula"
    )]
    pub(crate) fn waste_pct(&self) -> f64 {
        if self.sum_allocated == 0 {
            0.0_f64
        } else {
            uffs_mft::u64_to_f64(self.waste_bytes()) / uffs_mft::u64_to_f64(self.sum_allocated)
                * 100.0_f64
        }
    }
}

impl Default for StatsAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// A group accumulator tracks statistics for one aggregation spec.
///
/// This is the main workhorse of the aggregation engine. It's
/// constructed from an `AggregateKind` and fed records during scanning.
///
/// Different kinds use different internal strategies:
/// - `Count`: just a counter
/// - `Stats`: a `StatsAccumulator`
/// - `Terms`: a map from key to `StatsAccumulator`
/// - `Histogram`/`DateHistogram`/`Range`: array of `StatsAccumulator`
/// - `Missing`/`Distinct`: specialized counters
#[derive(Debug, Clone)]
pub struct GroupAccumulator {
    /// What this accumulator computes.
    pub kind: AccumulatorKind,
    /// The source field (if applicable).
    pub field: Option<FieldId>,
    /// Label for output.
    pub label: Option<String>,
}

/// The internal accumulator strategy.
#[derive(Debug, Clone)]
pub enum AccumulatorKind {
    /// Simple record count.
    Count {
        /// Running count.
        count: u64,
    },
    /// Scalar statistics for a single field.
    Stats {
        /// Running statistics.
        stats: StatsAccumulator,
        /// Which metrics were requested.
        metrics: Vec<ScalarMetric>,
    },
    /// Group-by terms: maps key → stats.
    Terms {
        /// Per-group accumulators, keyed by a u64-encoded group key.
        /// For `extension_id`: key = `extension_id` as u64.
        /// For drive: key = `drive_letter` as u64.
        /// For bool: key = 0 or 1.
        /// For type: key = category ordinal.
        groups: std::collections::HashMap<u64, StatsAccumulator>,
        /// Maximum groups to keep.
        top: u16,
        /// Requested metrics.
        metrics: Vec<BucketMetric>,
        /// Per-bucket sample heaps (present when `TopHitsSpec` is configured).
        sample_heaps: Option<std::collections::HashMap<u64, super::sample_heap::SampleHeap>>,
        /// Spec for creating new heaps (stored for lazy init).
        sample_spec: Option<TopHitsSpec>,
    },
    /// Fixed-size histogram buckets.
    Histogram {
        /// One accumulator per bucket (sorted by boundary).
        buckets: Vec<StatsAccumulator>,
        /// Bucket boundaries (upper exclusive).
        boundaries: Vec<u64>,
        /// Requested metrics.
        metrics: Vec<BucketMetric>,
    },
    /// Date histogram with calendar intervals.
    DateHistogram {
        /// Maps truncated-timestamp → stats.
        buckets: alloc::collections::BTreeMap<i64, StatsAccumulator>,
        /// Calendar interval for truncation.
        calendar: super::spec::CalendarInterval,
        /// Requested metrics.
        metrics: Vec<BucketMetric>,
    },
    /// Count of records with missing/zero values.
    Missing {
        /// Count of records with missing value.
        count: u64,
    },
    /// Distinct value count.
    Distinct {
        /// Set of seen values (as u64-encoded keys).
        seen: std::collections::HashSet<u64>,
    },
    /// Path/drive rollup accumulator.
    Rollup {
        /// Inner rollup accumulator.
        inner: super::rollup::RollupAccumulator,
        /// Requested metrics.
        metrics: Vec<BucketMetric>,
        /// Per-group sub-accumulators for nested rollups, keyed by the
        /// drive-qualified rollup group key.
        /// `None` when no sub-aggregation is requested.
        sub_accumulators: Option<std::collections::HashMap<u64, GroupAccumulator>>,
        /// The sub-aggregation spec (cloned from `AggregateKind::Rollup.sub`).
        sub_kind: Option<super::spec::AggregateSpec>,
    },
    /// Duplicate detection accumulator.
    Duplicates {
        /// Inner duplicate accumulator.
        inner: super::duplicates::DuplicateAccumulator,
        /// Sample row spec for materializing member indices post-scan.
        sample_spec: Option<TopHitsSpec>,
    },
}

impl GroupAccumulator {
    /// Create a new accumulator for the given aggregate kind.
    #[must_use]
    #[expect(
        clippy::too_many_lines,
        reason = "exhaustive match over AggregateKind variants — each arm is short but the enum has many cases; splitting per-variant helpers would obscure the dispatch structure"
    )]
    pub(crate) fn from_kind(kind: &AggregateKind, label: Option<String>) -> Self {
        let (acc_kind, field) = match kind {
            AggregateKind::Count => (AccumulatorKind::Count { count: 0 }, None),
            AggregateKind::Stats { field, metrics } => (
                AccumulatorKind::Stats {
                    stats: StatsAccumulator::new(),
                    metrics: metrics.clone(),
                },
                Some(*field),
            ),
            AggregateKind::Terms {
                field,
                top,
                metrics,
                sample,
            } => {
                let (heaps, spec) = sample.as_ref().map_or((None, None), |sample_spec| {
                    (
                        Some(std::collections::HashMap::new()),
                        Some(sample_spec.clone()),
                    )
                });
                (
                    AccumulatorKind::Terms {
                        groups: std::collections::HashMap::new(),
                        top: *top,
                        metrics: metrics.clone(),
                        sample_heaps: heaps,
                        sample_spec: spec,
                    },
                    Some(*field),
                )
            }
            AggregateKind::Histogram { field, metrics, .. } => {
                // For now, use pre-defined size buckets; interval-based
                // histogram expansion happens in the planner.
                (
                    AccumulatorKind::Histogram {
                        buckets: Vec::new(),
                        boundaries: Vec::new(),
                        metrics: metrics.clone(),
                    },
                    Some(*field),
                )
            }
            AggregateKind::DateHistogram {
                field,
                calendar,
                metrics,
            } => (
                AccumulatorKind::DateHistogram {
                    buckets: alloc::collections::BTreeMap::new(),
                    calendar: *calendar,
                    metrics: metrics.clone(),
                },
                Some(*field),
            ),
            AggregateKind::Range {
                field,
                boundaries,
                metrics,
            } => {
                let bucket_count = boundaries.len() + 1;
                (
                    AccumulatorKind::Histogram {
                        buckets: (0..bucket_count).map(|_| StatsAccumulator::new()).collect(),
                        boundaries: boundaries.clone(),
                        metrics: metrics.clone(),
                    },
                    Some(*field),
                )
            }
            AggregateKind::Missing { field } => {
                (AccumulatorKind::Missing { count: 0 }, Some(*field))
            }
            AggregateKind::Distinct { field } => (
                AccumulatorKind::Distinct {
                    seen: std::collections::HashSet::new(),
                },
                Some(*field),
            ),
            AggregateKind::Rollup {
                mode,
                top,
                metrics,
                sub,
                ..
            } => {
                let sub_accumulators = sub
                    .as_ref()
                    .map(|_| std::collections::HashMap::<u64, Self>::new());
                let sub_kind = sub.as_deref().cloned();
                (
                    AccumulatorKind::Rollup {
                        inner: super::rollup::RollupAccumulator::new(*mode, *top),
                        metrics: metrics.clone(),
                        sub_accumulators,
                        sub_kind,
                    },
                    None,
                )
            }
            AggregateKind::Duplicates {
                keys,
                verify,
                sample,
                max_groups,
                ..
            } => {
                let sample_count = sample.as_ref().map_or(2, |sample_spec| sample_spec.count);
                (
                    AccumulatorKind::Duplicates {
                        inner: super::duplicates::DuplicateAccumulator::new(
                            keys.clone(),
                            *verify,
                            *max_groups,
                            sample_count,
                        ),
                        sample_spec: sample.clone().or_else(|| Some(TopHitsSpec::default())),
                    },
                    None,
                )
            }
        };

        Self {
            kind: acc_kind,
            field,
            label,
        }
    }

    /// Feed a record into this accumulator.
    ///
    /// * `record` — the compact record being scanned.
    /// * `drive`  — the drive index (used for group key extraction).
    /// * `idx`   — the record's index within the drive's `records` array.
    /// * `drive_ordinal` — the ordinal position of this drive in the drives
    ///   array, stored in sample heap entries for later materialization.
    #[inline]
    pub(crate) fn feed(
        &mut self,
        record: &CompactRecord,
        drive: &DriveCompactIndex,
        idx: usize,
        drive_ordinal: u8,
        ext_map: &super::ExtensionMap,
    ) {
        let field = self.field;
        match &mut self.kind {
            AccumulatorKind::Count { count } => {
                *count += 1;
            }
            AccumulatorKind::Stats { stats, .. } => {
                let value = extract_value(field, record);
                stats.feed_value(value, record.allocated);
            }
            AccumulatorKind::Terms {
                groups,
                sample_heaps,
                sample_spec,
                ..
            } => {
                let key = extract_group_key(field, record, drive, drive_ordinal, ext_map);
                let stats = groups.entry(key).or_insert_with(StatsAccumulator::new);
                stats.feed_value(record.size, record.allocated);
                // Push into per-bucket sample heap if configured.
                if let (Some(heaps), Some(spec)) = (sample_heaps.as_mut(), sample_spec.as_ref()) {
                    let heap = heaps
                        .entry(key)
                        .or_insert_with(|| super::sample_heap::SampleHeap::from_spec(spec));
                    heap.push(record, uffs_mft::len_to_u32(idx), drive_ordinal);
                }
            }
            AccumulatorKind::Histogram {
                buckets,
                boundaries,
                ..
            } => {
                let value = extract_value(field, record);
                let bucket_idx = boundaries.partition_point(|&boundary| boundary <= value);
                // Grow buckets if needed.
                while buckets.len() <= bucket_idx {
                    buckets.push(StatsAccumulator::new());
                }
                if let Some(bucket) = buckets.get_mut(bucket_idx) {
                    bucket.feed_value(record.size, record.allocated);
                }
            }
            AccumulatorKind::DateHistogram {
                buckets, calendar, ..
            } => {
                let ts = extract_timestamp(field, record);
                let truncated = truncate_timestamp(ts, *calendar);
                let stats = buckets
                    .entry(truncated)
                    .or_insert_with(StatsAccumulator::new);
                stats.feed_value(record.size, record.allocated);
            }
            AccumulatorKind::Missing { count } => {
                if is_missing(field, record) {
                    *count += 1;
                }
            }
            AccumulatorKind::Distinct { seen } => {
                let key = extract_group_key(field, record, drive, drive_ordinal, ext_map);
                seen.insert(key);
            }
            AccumulatorKind::Rollup {
                inner,
                sub_accumulators,
                sub_kind,
                ..
            } => {
                // Compute group key and feed the top-level stats.
                // `feed` returns false when the record is out of scope
                // (ancestor rollups skip records on other drives) — such
                // records must not reach the sub-accumulators either.
                let bucketed = inner.feed(record, drive, idx, drive_ordinal);

                // If nested sub-aggregation is configured, feed the
                // per-group sub-accumulator.
                if bucketed
                    && let (Some(sub_map), Some(sub_spec)) =
                        (sub_accumulators.as_mut(), sub_kind.as_ref())
                {
                    let key = inner.last_key();
                    let sub_acc = sub_map
                        .entry(key)
                        .or_insert_with(|| Self::from_kind(&sub_spec.kind, sub_spec.label.clone()));
                    sub_acc.feed(record, drive, idx, drive_ordinal, ext_map);
                }
            }
            AccumulatorKind::Duplicates { inner, .. } => {
                inner.set_drive_ordinal(drive_ordinal);
                inner.feed(record, drive, idx);
            }
        }
    }

    /// Merge another accumulator into this one (for cross-drive merging).
    #[expect(
        clippy::iter_over_hash_type,
        reason = "per-key merge is order-independent: each entry is merged into self by key"
    )]
    #[expect(
        clippy::min_ident_chars,
        reason = "`a` (self) and `b` (other) are the conventional pair-destructure bindings in this merge function; renaming to verbose names would obscure the parallel structure of each match arm"
    )]
    pub fn merge(&mut self, other: &Self) {
        match (&mut self.kind, &other.kind) {
            (AccumulatorKind::Count { count: a }, AccumulatorKind::Count { count: b })
            | (AccumulatorKind::Missing { count: a }, AccumulatorKind::Missing { count: b }) => {
                *a += b;
            }
            (AccumulatorKind::Stats { stats: a, .. }, AccumulatorKind::Stats { stats: b, .. }) => {
                a.merge(b);
            }
            (
                AccumulatorKind::Terms {
                    groups: a,
                    sample_heaps: a_heaps,
                    ..
                },
                AccumulatorKind::Terms {
                    groups: b,
                    sample_heaps: b_heaps,
                    ..
                },
            ) => {
                for (key, b_stats) in b {
                    a.entry(*key)
                        .and_modify(|a_stats| a_stats.merge(b_stats))
                        .or_insert_with(|| b_stats.clone());
                }
                // Merge per-bucket sample heaps when both sides carry
                // them.  This is the parallel-reducer path: each drive
                // scan produces its own heaps, which must be combined
                // without losing any candidate entries.
                if let (Some(map_a), Some(map_b)) = (a_heaps.as_mut(), b_heaps) {
                    for (key, heap_b) in map_b {
                        map_a
                            .entry(*key)
                            .and_modify(|heap_a| heap_a.merge(heap_b))
                            .or_insert_with(|| heap_b.clone());
                    }
                }
            }
            (
                AccumulatorKind::Histogram { buckets: a, .. },
                AccumulatorKind::Histogram { buckets: b, .. },
            ) => {
                while a.len() < b.len() {
                    a.push(StatsAccumulator::new());
                }
                for (lhs, rhs) in a.iter_mut().zip(b.iter()) {
                    lhs.merge(rhs);
                }
            }
            (
                AccumulatorKind::DateHistogram { buckets: a, .. },
                AccumulatorKind::DateHistogram { buckets: b, .. },
            ) => {
                for (key, b_stats) in b {
                    a.entry(*key)
                        .and_modify(|a_stats| a_stats.merge(b_stats))
                        .or_insert_with(|| b_stats.clone());
                }
            }
            (AccumulatorKind::Distinct { seen: a }, AccumulatorKind::Distinct { seen: b }) => {
                for key in b {
                    a.insert(*key);
                }
            }
            (
                AccumulatorKind::Rollup {
                    inner: a,
                    sub_accumulators: sub_a,
                    ..
                },
                AccumulatorKind::Rollup {
                    inner: b,
                    sub_accumulators: sub_b,
                    ..
                },
            ) => {
                a.merge(b);
                // Merge sub-accumulators if present.
                if let (Some(map_a), Some(map_b)) = (sub_a.as_mut(), sub_b) {
                    for (key, acc_b) in map_b {
                        map_a
                            .entry(*key)
                            .and_modify(|acc_a| acc_a.merge(acc_b))
                            .or_insert_with(|| acc_b.clone());
                    }
                }
            }
            (
                AccumulatorKind::Duplicates { inner: a, .. },
                AccumulatorKind::Duplicates { inner: b, .. },
            ) => {
                // Required when the aggregation engine runs the outer
                // drive loop in parallel: each drive builds its own
                // local `DuplicateAccumulator`, and this arm glues the
                // per-drive groups back together before `finalize`
                // drops singletons.
                a.merge(b);
            }
            _ => {} // mismatched kinds — should not happen
        }
    }
}

/// Extract a numeric value from a record for stats/histogram.
#[inline]
fn extract_value(field: Option<FieldId>, record: &CompactRecord) -> u64 {
    match field {
        Some(FieldId::Size) => record.size,
        Some(FieldId::SizeOnDisk) => record.allocated,
        Some(FieldId::TreeSize) => record.treesize,
        Some(FieldId::TreeAllocated) => record.tree_allocated,
        Some(FieldId::Descendants) => u64::from(record.descendants),
        Some(FieldId::NameLength) => u64::from(record.name_len),
        Some(FieldId::PathLength) => u64::from(record.path_len),
        Some(FieldId::Created) => uffs_mft::nonneg_to_u64(record.created),
        Some(FieldId::Modified) => uffs_mft::nonneg_to_u64(record.modified),
        Some(FieldId::Accessed) => uffs_mft::nonneg_to_u64(record.accessed),
        _ => 0,
    }
}

/// Extract a timestamp from a record.
#[inline]
const fn extract_timestamp(field: Option<FieldId>, record: &CompactRecord) -> i64 {
    match field {
        Some(FieldId::Created) => record.created,
        Some(FieldId::Modified) => record.modified,
        Some(FieldId::Accessed) => record.accessed,
        _ => 0,
    }
}

/// Extract a group key (encoded as u64) from a record.
///
/// For `Extension`, uses the `ExtensionMap` to return a canonical
/// cross-drive extension ID.  This ensures that `"exe"` on drive C and
/// `"exe"` on drive D share the same group key.  The map is required:
/// raw per-drive `extension_id`s must never enter a cross-drive merge
/// key (the same id means different extensions on different drives).
#[inline]
fn extract_group_key(
    field: Option<FieldId>,
    record: &CompactRecord,
    drive: &DriveCompactIndex,
    drive_ordinal: u8,
    ext_map: &super::ExtensionMap,
) -> u64 {
    match field {
        Some(FieldId::Extension) => ext_map.canonical_id(drive_ordinal, record.extension_id),
        Some(FieldId::Drive) => u64::from(u32::from(drive.letter.as_byte())),
        Some(FieldId::Type) => {
            use crate::search::derived::{
                SEMANTIC_TYPE_ID_DIRECTORY, SEMANTIC_TYPE_ID_FILE, semantic_type_id_from_extension,
            };
            if record.flags & 0x0010 != 0 {
                return SEMANTIC_TYPE_ID_DIRECTORY;
            }
            let name = record.name(&drive.names);
            let ext = name.rsplit('.').next().unwrap_or("");
            if ext.len() == name.len() {
                return SEMANTIC_TYPE_ID_FILE;
            }
            // Stack-based lowercase for short extensions (covers 99%+).
            let mut buf = [0_u8; 16];
            let ext_len = ext.len();
            let ext_lower = buf.get_mut(..ext_len).map_or(ext, |slot| {
                for (dst, src) in slot.iter_mut().zip(ext.bytes()) {
                    *dst = src.to_ascii_lowercase();
                }
                core::str::from_utf8(slot).unwrap_or(ext)
            });
            semantic_type_id_from_extension(ext_lower)
        }
        Some(FieldId::DirectoryFlag) => u64::from(record.flags & 0x0010 != 0),
        Some(FieldId::Hidden) => u64::from(record.flags & 0x0002 != 0),
        Some(FieldId::System) => u64::from(record.flags & 0x0004 != 0),
        Some(FieldId::ReadOnly) => u64::from(record.flags & 0x0001 != 0),
        Some(FieldId::Compressed) => u64::from(record.flags & 0x0800 != 0),
        Some(FieldId::Encrypted) => u64::from(record.flags & 0x4000 != 0),
        Some(FieldId::Archive) => u64::from(record.flags & 0x0020 != 0),
        Some(FieldId::Sparse) => u64::from(record.flags & 0x0200 != 0),
        Some(FieldId::Reparse) => u64::from(record.flags & 0x0400 != 0),
        Some(FieldId::Temporary) => u64::from(record.flags & 0x0100 != 0),
        Some(FieldId::Offline) => u64::from(record.flags & 0x1000 != 0),
        Some(FieldId::NotIndexed) => u64::from(record.flags & 0x2000 != 0),
        Some(FieldId::Virtual) => u64::from(record.flags & 0x1_0000 != 0),
        Some(FieldId::Integrity) => u64::from(record.flags & 0x8000 != 0),
        Some(FieldId::NoScrub) => u64::from(record.flags & 0x2_0000 != 0),
        Some(FieldId::Pinned) => u64::from(record.flags & 0x8_0000 != 0),
        Some(FieldId::Unpinned) => u64::from(record.flags & 0x10_0000 != 0),
        Some(FieldId::RecallOnOpen) => u64::from(record.flags & 0x4_0000 != 0),
        Some(FieldId::RecallOnDataAccess) => u64::from(record.flags & 0x40_0000 != 0),
        _ => 0,
    }
}

/// Check if a field has a "missing" value for this record.
#[inline]
const fn is_missing(field: Option<FieldId>, record: &CompactRecord) -> bool {
    match field {
        Some(FieldId::Extension) => record.extension_id == 0,
        Some(FieldId::Size) => record.size == 0,
        Some(FieldId::SizeOnDisk) => record.allocated == 0,
        Some(FieldId::Created) => record.created == 0,
        Some(FieldId::Modified) => record.modified == 0,
        Some(FieldId::Accessed) => record.accessed == 0,
        _ => false,
    }
}

/// Truncate a raw FILETIME (100-ns ticks since 1601) to a calendar interval
/// boundary.
///
/// Returns a FILETIME value aligned to the start of the given interval.
const fn truncate_timestamp(filetime: i64, calendar: super::spec::CalendarInterval) -> i64 {
    use uffs_time::FILETIME_TICKS_PER_SECOND;

    use super::spec::CalendarInterval;

    let ticks_per_hour: i64 = FILETIME_TICKS_PER_SECOND * 3600;
    let ticks_per_day: i64 = FILETIME_TICKS_PER_SECOND * 86400;

    match calendar {
        CalendarInterval::Hour => (filetime / ticks_per_hour) * ticks_per_hour,
        CalendarInterval::Day => (filetime / ticks_per_day) * ticks_per_day,
        CalendarInterval::Week => {
            // FILETIME epoch 1601-01-01 was a Monday — convenient!
            let days = filetime / ticks_per_day;
            let day_of_week = days % 7; // Mon=0 (since 1601-01-01 = Monday)
            (days - day_of_week) * ticks_per_day
        }
        CalendarInterval::Month => {
            // Approximate: 30-day months.
            let ticks_per_30d = ticks_per_day * 30;
            (filetime / ticks_per_30d) * ticks_per_30d
        }
        CalendarInterval::Quarter => {
            let ticks_per_90d = ticks_per_day * 90;
            (filetime / ticks_per_90d) * ticks_per_90d
        }
        CalendarInterval::Year => {
            let ticks_per_365d = ticks_per_day * 365;
            (filetime / ticks_per_365d) * ticks_per_365d
        }
    }
}
