// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Finalization of aggregate results.
//!
//! After accumulators have been fed all matching records, this module
//! converts raw accumulator state into sorted, truncated, labeled
//! response objects.

use super::accumulators::{AccumulatorKind, GroupAccumulator, StatsAccumulator};
use super::planner::AggregatePlan;
use crate::compact::DriveCompactIndex;

/// Options controlling finalization behavior.
#[derive(Debug, Clone)]
pub struct FinalizeOptions {
    /// Whether to compute share-of-total metrics.
    pub compute_shares: bool,
    /// Whether to include empty buckets in output.
    pub include_empty_buckets: bool,
    /// The original query predicates (if any).  These are prepended to
    /// each bucket's drill-down predicate list so that a follow-up query
    /// reproduces the original scope **plus** the bucket constraint.
    pub query_predicates: Vec<DrilldownPredicate>,
}

impl Default for FinalizeOptions {
    fn default() -> Self {
        Self {
            compute_shares: true,
            include_empty_buckets: false,
            query_predicates: Vec::new(),
        }
    }
}

/// The finalized aggregate response.
#[derive(Debug, Clone)]
pub struct AggregateResponse {
    /// One result per spec in the plan.
    pub results: Vec<AggregateResult>,
}

/// Result of a single aggregation spec.
#[derive(Debug, Clone)]
pub struct AggregateResult {
    /// Label for this result (from the spec).
    pub label: Option<String>,
    /// The kind-specific result data.
    pub data: AggregateResultData,
}

/// The kind-specific result payload.
#[derive(Debug, Clone)]
pub enum AggregateResultData {
    /// Simple count.
    Count {
        /// Total count of matching records.
        value: u64,
    },
    /// Scalar statistics.
    Stats {
        /// Field name.
        field: String,
        /// Computed statistics.
        stats: StatsResult,
    },
    /// Grouped bucket results (terms, histogram, `date_histogram`, range).
    Buckets {
        /// Field name.
        field: String,
        /// Sorted, truncated bucket rows.
        rows: Vec<BucketRow>,
        /// Count of records in buckets beyond top-N (for terms).
        other_count: u64,
        /// Total groups before truncation.
        total_groups: usize,
        /// Whether the values are exact (not approximate).
        exact: bool,
    },
    /// Missing value count.
    Missing {
        /// Field name.
        field: String,
        /// Count of records with missing value.
        count: u64,
    },
    /// Distinct value count.
    Distinct {
        /// Field name.
        field: String,
        /// Number of distinct values seen.
        count: u64,
    },
    /// Rollup result (path/drive grouping).
    Rollup {
        /// Rollup mode description.
        mode: String,
        /// Grouped bucket rows.
        rows: Vec<BucketRow>,
    },
    /// Duplicate detection result.
    Duplicates {
        /// Full duplicate result data.
        result: super::duplicates::DuplicateResult,
    },
}

/// Scalar statistics result.
#[derive(Debug, Clone)]
pub struct StatsResult {
    /// Number of records.
    pub count: u64,
    /// Sum of values.
    pub sum: u64,
    /// Minimum value.
    pub min: u64,
    /// Maximum value.
    pub max: u64,
    /// Average value.
    pub avg: f64,
    /// Waste: allocated - logical.
    pub waste_bytes: u64,
    /// Waste percentage.
    pub waste_pct: f64,
}

/// A single row in a bucket result.
#[derive(Debug, Clone)]
pub struct BucketRow {
    /// Display key for this bucket.
    pub key: String,
    /// Number of records in this bucket.
    pub count: u64,
    /// Total logical bytes.
    pub total_bytes: u64,
    /// Total allocated bytes.
    pub total_allocated: u64,
    /// Average file size.
    pub avg_size: f64,
    /// Minimum file size.
    pub min_size: u64,
    /// Maximum file size.
    pub max_size: u64,
    /// Waste bytes.
    pub waste_bytes: u64,
    /// Waste percentage.
    pub waste_pct: f64,
    /// Share of total count (percentage, 0.0–100.0).
    pub share_of_total_count: f64,
    /// Share of total bytes (percentage, 0.0–100.0).
    pub share_of_total_bytes: f64,
    /// Optional sample rows (top-N records in this bucket).
    pub sample_rows: Vec<SampleRow>,
    /// Drill-down predicates: the original query predicates **plus**
    /// a bucket-key predicate that narrows the result set to exactly
    /// the records in this bucket.
    ///
    /// A client can re-issue a row-level search using these predicates
    /// to retrieve the actual records behind the bucket.
    pub drilldown: Vec<DrilldownPredicate>,
    /// Nested sub-aggregation bucket rows (populated by nested rollups).
    ///
    /// When a rollup spec has `sub`, each top-level bucket finalizes
    /// its per-group sub-accumulator and stores the result here.
    pub sub_buckets: Vec<Self>,
}

/// A lightweight predicate for drill-down follow-up queries.
///
/// Mirrors the wire-protocol `SearchPredicate` shape but lives in
/// `uffs-core` so the aggregate module has no dependency on the client
/// crate.  The daemon / CLI can convert these to wire predicates
/// trivially.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DrilldownPredicate {
    /// Canonical field name (e.g. `"extension"`, `"drive"`, `"type"`).
    pub field: String,
    /// Comparison operator (e.g. `"eq"`, `"in"`).
    pub op: String,
    /// Predicate value(s).
    pub value: DrilldownValue,
}

/// Value for a [`DrilldownPredicate`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DrilldownValue {
    /// A single string value.
    String(String),
    /// A single unsigned integer.
    U64(u64),
    /// A single signed integer.
    I64(i64),
    /// A boolean value.
    Bool(bool),
}

/// A materialized sample row — one record's projected fields.
///
/// Produced during finalization from the per-bucket `SampleHeap` entries.
/// Only surviving (top-N) buckets have their samples materialized.
#[derive(Debug, Clone)]
pub struct SampleRow {
    /// Key-value pairs of projected fields.
    ///
    /// Each entry is `(field_name, display_value)`.  The set of fields
    /// is determined by `TopHitsSpec::effective_projection` (internal helper).
    pub fields: Vec<(String, String)>,
    /// The sort key that determined this row's position.
    pub sort_key: i64,
}

impl BucketRow {
    /// Create a bucket row from a stats accumulator and context.
    #[expect(
        clippy::float_arithmetic,
        reason = "integer count/byte→f64 share-of-total percentages are the documented bucket-row formula"
    )]
    fn from_stats(
        key: String,
        stats: &StatsAccumulator,
        total_matched: u64,
        total_bytes: u64,
    ) -> Self {
        let share_count = if total_matched == 0 {
            0.0_f64
        } else {
            uffs_mft::u64_to_f64(stats.count) / uffs_mft::u64_to_f64(total_matched) * 100.0_f64
        };
        let share_bytes = if total_bytes == 0 {
            0.0_f64
        } else {
            uffs_mft::u64_to_f64(stats.sum) / uffs_mft::u64_to_f64(total_bytes) * 100.0_f64
        };
        Self {
            key,
            count: stats.count,
            total_bytes: stats.sum,
            total_allocated: stats.sum_allocated,
            avg_size: stats.avg(),
            min_size: if stats.min == u64::MAX { 0 } else { stats.min },
            max_size: stats.max,
            waste_bytes: stats.waste_bytes(),
            waste_pct: stats.waste_pct(),
            share_of_total_count: share_count,
            share_of_total_bytes: share_bytes,
            sample_rows: Vec::new(),
            drilldown: Vec::new(),
            sub_buckets: Vec::new(),
        }
    }
}

/// Finalize accumulated results into a response.
/// Finalize aggregate results using the cross-drive
/// [`crate::aggregate::ExtensionMap`] for correct extension key resolution.
pub(crate) fn finalize_with_ext_map(
    accumulators: Vec<GroupAccumulator>,
    _plan: &AggregatePlan,
    drives: &[&DriveCompactIndex],
    options: &FinalizeOptions,
    total_matched: u64,
    ext_map: &super::ExtensionMap,
) -> AggregateResponse {
    let global_total_bytes = compute_global_bytes(&accumulators);

    let results = accumulators
        .into_iter()
        .map(|acc| {
            finalize_one(
                acc,
                total_matched,
                global_total_bytes,
                options,
                drives,
                ext_map,
            )
        })
        .collect();

    AggregateResponse { results }
}

/// Compute total bytes across all accumulators (for share-of-total).
fn compute_global_bytes(accumulators: &[GroupAccumulator]) -> u64 {
    for acc in accumulators {
        if let AccumulatorKind::Stats { stats, .. } = &acc.kind
            && acc.field == Some(crate::search::field::FieldId::Size)
        {
            return stats.sum;
        }
    }
    0
}

/// Finalize a standalone accumulator (used by nested rollups).
///
/// Wraps `finalize_one` with default options.
fn finalize_accumulator(
    acc: GroupAccumulator,
    total_matched: u64,
    total_bytes: u64,
    drives: &[&DriveCompactIndex],
    ext_map: &super::ExtensionMap,
    _predicates: &[DrilldownPredicate],
) -> AggregateResult {
    finalize_one(
        acc,
        total_matched,
        total_bytes,
        &FinalizeOptions::default(),
        drives,
        ext_map,
    )
}

/// Convert a sub-aggregation result into drilldown bucket rows.
///
/// Extracts `BucketRow`s from bucket-like result variants; non-bucket
/// results (count, stats, missing, distinct) produce an empty vec.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "non-bucket result variants intentionally collapse to empty rows"
)]
fn sub_result_to_bucket_rows(result: &AggregateResult) -> Vec<BucketRow> {
    match &result.data {
        AggregateResultData::Buckets { rows, .. } | AggregateResultData::Rollup { rows, .. } => {
            rows.clone()
        }
        _ => Vec::new(),
    }
}

/// Finalize a single accumulator into an `AggregateResult`.
fn finalize_one(
    acc: GroupAccumulator,
    total_matched: u64,
    total_bytes: u64,
    options: &FinalizeOptions,
    drives: &[&DriveCompactIndex],
    ext_map: &super::ExtensionMap,
) -> AggregateResult {
    let label = acc.label.clone();
    let field = acc.field;
    let field_name = field
        .map(|f_id| f_id.metadata().canonical_name.to_owned())
        .unwrap_or_default();

    let data = match acc.kind {
        AccumulatorKind::Count { count } => AggregateResultData::Count { value: count },

        AccumulatorKind::Stats { stats, .. } => AggregateResultData::Stats {
            field: field_name,
            stats: StatsResult {
                count: stats.count,
                sum: stats.sum,
                min: if stats.min == u64::MAX { 0 } else { stats.min },
                max: stats.max,
                avg: stats.avg(),
                waste_bytes: stats.waste_bytes(),
                waste_pct: stats.waste_pct(),
            },
        },

        AccumulatorKind::Terms {
            groups,
            top,
            sample_heaps,
            sample_spec,
            ..
        } => finalize_terms(
            field,
            field_name,
            &groups,
            top,
            sample_heaps,
            sample_spec.as_ref(),
            total_matched,
            total_bytes,
            options,
            drives,
            ext_map,
        ),

        AccumulatorKind::Histogram {
            buckets,
            boundaries,
            ..
        } => finalize_histogram(
            field_name,
            &buckets,
            &boundaries,
            total_matched,
            total_bytes,
            options,
        ),

        AccumulatorKind::DateHistogram { buckets, .. } => {
            let rows: Vec<_> = buckets
                .iter()
                .filter(|(_, stats)| options.include_empty_buckets || stats.count > 0)
                .map(|(&ts, stats)| {
                    let key = format_timestamp_key(ts);
                    BucketRow::from_stats(key, stats, total_matched, total_bytes)
                })
                .collect();

            AggregateResultData::Buckets {
                field: field_name,
                rows,
                other_count: 0,
                total_groups: buckets.len(),
                exact: true,
            }
        }

        AccumulatorKind::Missing { count } => AggregateResultData::Missing {
            field: field_name,
            count,
        },

        AccumulatorKind::Distinct { seen } => AggregateResultData::Distinct {
            field: field_name,
            count: seen.len() as u64,
        },

        AccumulatorKind::Rollup {
            inner,
            sub_accumulators,
            ..
        } => finalize_rollup(
            &inner,
            sub_accumulators,
            total_matched,
            total_bytes,
            drives,
            ext_map,
        ),

        AccumulatorKind::Duplicates { inner, sample_spec } => {
            finalize_duplicates(inner, sample_spec, drives)
        }
    };

    AggregateResult { label, data }
}

/// Finalize a `Histogram` accumulator: format range keys, drop empty
/// buckets unless requested otherwise.
fn finalize_histogram(
    field_name: String,
    buckets: &[StatsAccumulator],
    boundaries: &[u64],
    total_matched: u64,
    total_bytes: u64,
    options: &FinalizeOptions,
) -> AggregateResultData {
    let rows: Vec<_> = buckets
        .iter()
        .enumerate()
        .filter(|(_, stats)| options.include_empty_buckets || stats.count > 0)
        .map(|(i, stats)| {
            let key = format_range_key(i, boundaries);
            BucketRow::from_stats(key, stats, total_matched, total_bytes)
        })
        .collect();

    AggregateResultData::Buckets {
        field: field_name,
        rows,
        other_count: 0,
        total_groups: buckets.len(),
        exact: true,
    }
}

/// Finalize a `Terms` accumulator: sort buckets by count, take top-N, attach
/// sample rows and drill-down predicates.
#[expect(
    clippy::too_many_arguments,
    reason = "explicit parameter list keeps the helper signature transparent at the call site"
)]
fn finalize_terms(
    field: Option<crate::search::field::FieldId>,
    field_name: String,
    groups: &std::collections::HashMap<u64, StatsAccumulator>,
    top: u16,
    mut sample_heaps: Option<std::collections::HashMap<u64, super::sample_heap::SampleHeap>>,
    sample_spec: Option<&super::spec::TopHitsSpec>,
    total_matched: u64,
    total_bytes: u64,
    options: &FinalizeOptions,
    drives: &[&DriveCompactIndex],
    ext_map: &super::ExtensionMap,
) -> AggregateResultData {
    let total_groups = groups.len();

    // Build (group_key, BucketRow) pairs so we can correlate surviving keys
    // with their sample heaps.
    let mut keyed_rows: Vec<(u64, BucketRow)> = groups
        .iter()
        .map(|(&key, stats)| {
            let key_str = resolve_group_key(field, key, drives, ext_map);
            (
                key,
                BucketRow::from_stats(key_str, stats, total_matched, total_bytes),
            )
        })
        .collect();

    keyed_rows.sort_by_key(|row| core::cmp::Reverse(row.1.count));

    let limit = usize::from(top);
    let other_count = match keyed_rows.get(limit..) {
        Some(tail) if !tail.is_empty() => {
            let other: u64 = tail.iter().map(|row| row.1.count).sum();
            keyed_rows.truncate(limit);
            other
        }
        _ => 0,
    };

    // Materialize sample rows for surviving buckets only.
    if let Some(ref mut heaps) = sample_heaps {
        let projection = sample_spec
            .map(super::spec::TopHitsSpec::effective_projection)
            .unwrap_or_default();
        for (group_key, row) in &mut keyed_rows {
            if let Some(heap) = heaps.get_mut(group_key) {
                let entries = heap.drain_sorted();
                row.sample_rows = entries
                    .iter()
                    .map(|entry| materialize_sample_entry(entry, projection, drives))
                    .collect();
            }
        }
    }

    // Attach drill-down predicates: original query preds + bucket key.
    for (group_key, row) in &mut keyed_rows {
        row.drilldown = build_drilldown(
            &options.query_predicates,
            field,
            *group_key,
            &row.key,
            drives,
        );
    }

    let rows: Vec<BucketRow> = keyed_rows.into_iter().map(|(_, row)| row).collect();

    AggregateResultData::Buckets {
        field: field_name,
        rows,
        other_count,
        total_groups,
        exact: true,
    }
}

/// Finalize a `Rollup` accumulator: compute mode label, finalize the inner
/// rollup, attach nested sub-aggregation rows where present.
fn finalize_rollup(
    inner: &super::rollup::RollupAccumulator,
    mut sub_accumulators: Option<std::collections::HashMap<u64, GroupAccumulator>>,
    total_matched: u64,
    total_bytes: u64,
    drives: &[&DriveCompactIndex],
    ext_map: &super::ExtensionMap,
) -> AggregateResultData {
    let mode_str = match inner.mode {
        super::spec::RollupMode::Drive => "drive".to_owned(),
        super::spec::RollupMode::Path { depth } => format!("path(depth={depth})"),
        super::spec::RollupMode::Ancestor { record_idx, drive } => {
            format!("ancestor(record={record_idx}, drive={drive})")
        }
    };
    let entries = inner.finalize();
    let rows: Vec<_> = entries
        .into_iter()
        .map(|(key, stats)| {
            let key_str = super::rollup::resolve_rollup_key(key, inner.mode, drives);
            let mut row = BucketRow::from_stats(key_str, stats, total_matched, total_bytes);

            // Attach sub-aggregation from nested sub-accumulator.
            if let Some(sub_acc) = sub_accumulators.as_mut().and_then(|map| map.remove(&key)) {
                let sub_result =
                    finalize_accumulator(sub_acc, total_matched, total_bytes, drives, ext_map, &[]);
                row.sub_buckets = sub_result_to_bucket_rows(&sub_result);
            }

            row
        })
        .collect();
    AggregateResultData::Rollup {
        mode: mode_str,
        rows,
    }
}

/// Finalize a `Duplicates` accumulator: take top-N groups, materialize sample
/// rows for each group's members.
fn finalize_duplicates(
    inner: super::duplicates::DuplicateAccumulator,
    sample_spec: Option<super::spec::TopHitsSpec>,
    drives: &[&DriveCompactIndex],
) -> AggregateResultData {
    let dup_top = 100; // default
    let mut result = inner.finalize(dup_top);
    // Materialize member_indices → SampleRows for each group.
    let spec = sample_spec.unwrap_or_default();
    let projection = spec.effective_projection();
    for group in &mut result.groups {
        group.sample_rows = group
            .member_indices
            .iter()
            .map(|&(rec_idx, drive_ord)| {
                let entry = super::sample_heap::SampleEntry {
                    sort_key: 0,
                    rec_idx: uffs_mft::len_to_u32(rec_idx),
                    drive_ordinal: drive_ord,
                };
                materialize_sample_entry(&entry, projection, drives)
            })
            .collect();
    }
    AggregateResultData::Duplicates { result }
}

/// Build drill-down predicates for a bucket row.
///
/// Returns the original query predicates **plus** a bucket key predicate
/// that narrows to the specific group.
fn build_drilldown(
    query_predicates: &[DrilldownPredicate],
    bucket_field: Option<crate::search::field::FieldId>,
    _group_key: u64,
    display_key: &str,
    _drives: &[&DriveCompactIndex],
) -> Vec<DrilldownPredicate> {
    let mut preds = query_predicates.to_vec();

    // Add the bucket key predicate.
    if let Some(field) = bucket_field {
        let field_name = field.metadata().canonical_name.to_owned();
        preds.push(DrilldownPredicate {
            field: field_name,
            op: "eq".to_owned(),
            value: DrilldownValue::String(display_key.to_owned()),
        });
    }

    preds
}

/// Materialize a single sample entry into a [`SampleRow`].
///
/// Looks up the record by `(drive_ordinal, rec_idx)` in `drives`,
/// then projects the requested fields into key-value pairs.
fn materialize_sample_entry(
    entry: &super::sample_heap::SampleEntry,
    projection: &[crate::search::field::FieldId],
    drives: &[&DriveCompactIndex],
) -> SampleRow {
    let drive_ref = drives.get(usize::from(entry.drive_ordinal));
    let record =
        drive_ref.and_then(|drive| drive.records.get(uffs_mft::u32_as_usize(entry.rec_idx)));

    let fields: Vec<(String, String)> = projection
        .iter()
        .map(|fid| {
            let name = fid.metadata().canonical_name.to_owned();
            let value = match (record, drive_ref) {
                (Some(rec), Some(drv)) => format_field(*fid, rec, drv),
                _ => String::new(),
            };
            (name, value)
        })
        .collect();

    SampleRow {
        fields,
        sort_key: entry.sort_key,
    }
}

/// Format a single field value for sample row output.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "FieldId is open-ended; fields without a textual representation fall back to empty string"
)]
fn format_field(
    field: crate::search::field::FieldId,
    record: &crate::compact::CompactRecord,
    drive: &DriveCompactIndex,
) -> String {
    use crate::search::field::FieldId;
    match field {
        FieldId::Name => record.name(&drive.names).to_owned(),
        FieldId::Size => record.size.to_string(),
        FieldId::SizeOnDisk => record.allocated.to_string(),
        FieldId::Modified => format_timestamp_key(record.modified),
        FieldId::Created => format_timestamp_key(record.created),
        FieldId::Accessed => format_timestamp_key(record.accessed),
        FieldId::Extension => {
            let ext_id = usize::from(record.extension_id);
            drive
                .ext_names
                .get(ext_id)
                .map(ToString::to_string)
                .unwrap_or_default()
        }
        FieldId::Path | FieldId::PathOnly => {
            // Full path resolution is expensive — return parent index
            // as a placeholder.  Callers needing full paths should use
            // the search pipeline instead.
            format!("parent_idx:{}", record.parent_idx)
        }
        FieldId::DirectoryFlag => {
            if record.flags & 0x0010 != 0 {
                "directory".to_owned()
            } else {
                "file".to_owned()
            }
        }
        FieldId::Hidden => format!("{}", record.flags & 0x0002 != 0),
        FieldId::System => format!("{}", record.flags & 0x0004 != 0),
        FieldId::ReadOnly => format!("{}", record.flags & 0x0001 != 0),
        FieldId::TreeSize => record.treesize.to_string(),
        FieldId::Descendants => record.descendants.to_string(),
        _ => String::new(),
    }
}

/// Resolve a u64 group key to a display string.
///
/// For `Extension`, group keys are canonical cross-drive IDs from the
/// [`super::ExtensionMap`]; the map is the only correct way to resolve
/// them (a raw per-drive intern table would map the same id to
/// different extensions on different drives).
fn resolve_group_key(
    field: Option<crate::search::field::FieldId>,
    key: u64,
    _drives: &[&DriveCompactIndex],
    ext_map: &super::ExtensionMap,
) -> String {
    use crate::search::field::FieldId;
    match field {
        Some(FieldId::Extension) => ext_map.resolve(key),
        Some(FieldId::Drive) => {
            let ch = char::from(u8::try_from(key).unwrap_or(b'?'));
            format!("{ch}:")
        }
        Some(FieldId::Type) => crate::search::derived::semantic_type_name_from_id(key).to_owned(),
        Some(FieldId::DirectoryFlag) => {
            if key == 1 {
                "directory".to_owned()
            } else {
                "file".to_owned()
            }
        }
        Some(bool_field)
            if bool_field.metadata().field_type == crate::search::field::FieldType::Bool =>
        {
            if key == 1 {
                "true".to_owned()
            } else {
                "false".to_owned()
            }
        }
        _ => format!("{key}"),
    }
}

/// Format a range bucket key.
fn format_range_key(index: usize, boundaries: &[u64]) -> String {
    let Some((first, last)) = boundaries.first().zip(boundaries.last()) else {
        return format!("bucket_{index}");
    };
    if index == 0 {
        format!("< {first}")
    } else if index >= boundaries.len() {
        format!(">= {last}")
    } else {
        match (boundaries.get(index - 1), boundaries.get(index)) {
            (Some(lo), Some(hi)) => format!("{lo} - {hi}"),
            _ => format!("bucket_{index}"),
        }
    }
}

/// Format a FILETIME timestamp key as an ISO date (`YYYY-MM-DD`).
fn format_timestamp_key(filetime: i64) -> String {
    match uffs_time::filetime_to_calendar(filetime) {
        Some(uffs_time::CalendarParts {
            year, month, day, ..
        }) => format!("{year:04}-{month:02}-{day:02}"),
        None => "0000-00-00".to_owned(),
    }
}
