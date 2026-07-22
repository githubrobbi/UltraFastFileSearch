// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Aggregation wire types — JSON-serialisable mirror of
//! `uffs_core::aggregate::spec::AggregateSpec` and its result family.
//!
//! Extracted from `protocol/mod.rs` to keep that file under the workspace
//! 800-LOC policy ceiling.  Re-exported from [`super`] so existing
//! `uffs_client::protocol::AggregateSpecWire` import paths keep working.

use serde::{Deserialize, Serialize};

/// Wire format for a single aggregation specification.
///
/// This is the JSON-serializable form of
/// `uffs_core::aggregate::spec::AggregateSpec`. It uses tagged-enum style for
/// `kind` to make JSON schemas self-describing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AggregateSpecWire {
    /// The aggregation kind (e.g. `"count"`, `"terms"`, `"stats"`).
    pub kind: String,
    /// Optional label for this aggregation in the output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Field to aggregate on (required for most kinds except `"count"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Maximum groups for terms aggregation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top: Option<u16>,
    /// Bucket interval for histogram aggregation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    /// Calendar interval for date histogram (e.g. `"month"`, `"day"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calendar: Option<String>,
    /// Range boundaries for range aggregation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub boundaries: Vec<u64>,
    /// Metrics to compute per bucket/group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<String>,
    /// Preset name (when `kind` is `"preset"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// Number of sample rows (top-hits) to attach per bucket.
    /// `None` or absent means no samples.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample: Option<u8>,
    /// Sort field for sample rows (e.g. `"size"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_sort: Option<String>,
    /// Sort direction for sample rows.  `true` = descending (largest first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_desc: Option<bool>,
    /// Duplicate verification mode: `"first_bytes"`, `"sha256"`, or
    /// absent/`"none"`.
    ///
    /// Only meaningful when `kind` is `"duplicates"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<String>,
    /// Byte count for `verify=first_bytes` mode (default: 4096).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_bytes: Option<u32>,
    /// Drive letter scoping an `ancestor`/`drilldown` rollup (e.g. `"C"`).
    ///
    /// Required when `kind` is `"rollup"` with `field` = `"ancestor"` —
    /// the rollup's record index is per-drive, so the drilldown must
    /// name the drive it belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drive: Option<String>,
}

/// Wire format for an aggregate result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateResultWire {
    /// Label for this result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The result kind (mirrors the spec kind).
    pub kind: String,
    /// Field name (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Scalar value (for count/missing/distinct).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    /// Scalar statistics (for stats kind).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<StatsWire>,
    /// Bucket rows (for `terms`/`histogram`/`date_histogram`/`range`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub buckets: Vec<BucketWire>,
    /// Count of records beyond top-N (for terms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_count: Option<u64>,
    /// Total groups before truncation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_groups: Option<usize>,
    /// Cursor token for the next page of buckets.
    ///
    /// Present only when the request included `page_size` and more
    /// buckets remain beyond the current page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Whether the bucket values are exact (not approximate).
    ///
    /// `true` for all current implementations — reserved for future
    /// sampling-based approximation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<bool>,
    /// Whether the result contains all distinct values.
    ///
    /// `true` when every group fits within `top` (i.e. `other_count == 0`).
    /// `false` when the result was truncated and `other_count > 0`.
    /// Absent for non-bucket results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values_complete: Option<bool>,
}

/// Wire format for scalar statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsWire {
    /// Record count.
    pub count: u64,
    /// Sum of values.
    pub sum: u64,
    /// Minimum value.
    pub min: u64,
    /// Maximum value.
    pub max: u64,
    /// Average value.
    pub avg: f64,
    /// Waste bytes.
    pub waste_bytes: u64,
    /// Waste percentage.
    pub waste_pct: f64,
}

/// Wire format for a single bucket row.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BucketWire {
    /// Bucket key (display string).
    pub key: String,
    /// Record count in this bucket.
    pub count: u64,
    /// Total bytes in this bucket.
    pub total_bytes: u64,
    /// Total allocated bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_allocated: Option<u64>,
    /// Average file size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_size: Option<f64>,
    /// Share of total count (percentage).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share_count: Option<f64>,
    /// Share of total bytes (percentage).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share_bytes: Option<f64>,
    /// Sample rows (top-hits) — representative records from this bucket.
    /// Empty when no `sample` was requested in the spec.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sample_rows: Vec<SampleRowWire>,
    /// Drill-down predicates for re-querying this bucket's records.
    /// Includes both the original query predicates and the bucket key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drilldown: Vec<DrilldownWire>,
    /// Nested sub-aggregation bucket results (populated by nested rollups).
    ///
    /// When a rollup spec has a `sub` aggregation, each top-level bucket
    /// contains the sub-aggregation's buckets here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sub_buckets: Vec<Self>,
    /// Whether this duplicate group has been content-verified.
    ///
    /// Only present for `kind="duplicates"` results with `verify != "none"`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub verified: bool,
}

/// Wire format for a sample row (top-hit) within a bucket.
///
/// Each entry represents one record from the bucket, projected onto a
/// set of display fields (e.g. `name`, `size`, `modified`).  The daemon
/// populates this from `uffs_core::aggregate::SampleRow` during
/// `BucketRow → BucketWire` conversion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleRowWire {
    /// Projected fields as key-value pairs (e.g. `"name" → "foo.rs"`).
    pub fields: std::collections::HashMap<String, String>,
    /// Sort key used for ordering (e.g. file size).  Absent when the
    /// sample was collected without an explicit sort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort_key: Option<i64>,
}

/// Wire format for a drill-down predicate.
///
/// A client can re-issue a row-level search using the predicates
/// attached to a bucket to retrieve the records behind it.  The
/// `value` is a [`serde_json::Value`] so it naturally maps to JSON
/// without an extra enum on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrilldownWire {
    /// Canonical field name (e.g. `"extension"`, `"drive"`, `"type"`).
    pub field: String,
    /// Comparison operator (e.g. `"eq"`, `"gte"`, `"in"`).
    pub op: String,
    /// Predicate value — string, number, or boolean.
    pub value: serde_json::Value,
}
