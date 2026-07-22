// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Typed error returned by [`super::parser::parse_agg_spec`] and
//! [`super::parser::parse_and_expand_agg_specs`].
//!
//! Lifted out of `parser.rs` purely to keep that file under the
//! 800-line policy ceiling.  The enum is `pub` and re-exported at
//! `uffs_core::aggregate::ParseAggSpecError` via the parent module's
//! glob re-export of `parser::*`.
//!
//! Phase 5d migration of the previous `Result<_, String>` return
//! types: every [`core::fmt::Display`] string stays byte-identical
//! with the pre-migration `format!()` payloads so operator-facing
//! daemon logs (`tracing::warn!("skipping malformed aggregate spec:
//! {e}")` in `uffs-daemon/src/index/aggregation.rs`) and CLI error
//! output are unchanged, while callers can now match on variants and
//! walk [`core::error::Error::source`] for the typed integer-parse
//! chain.
//!
//! `#[non_exhaustive]` per Phase 5c discipline so future aggregate
//! kinds / option keys can grow a variant without a semver bump on
//! the (workspace-internal) consumers.

use core::num::ParseIntError;

/// Typed error returned by [`super::parser::parse_agg_spec`] and
/// [`super::parser::parse_and_expand_agg_specs`].
///
/// See the module-level docs in `parser_error.rs` for the migration
/// rationale.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseAggSpecError {
    /// The top-level `kind:` segment did not match any known
    /// aggregate kind (`count`, `stats`, `terms`, `facet`, `hist`,
    /// `histogram`, `datehist`, `date_histogram`, `range`, `rollup`,
    /// `duplicates`, `dups`, `preset`, `missing`, `distinct`).
    #[error("Unknown aggregate kind: `{kind}`")]
    UnknownKind {
        /// The unrecognised kind token (as supplied on the command line).
        kind: String,
    },
    /// A `field` slot named a column that
    /// [`crate::search::field::FieldId::parse`] does not recognise.
    #[error("Unknown field: `{name}`")]
    UnknownField {
        /// The unrecognised field name.
        name: String,
    },
    /// One of the integer-valued option keys (`top`, `sample`,
    /// `interval`, `range boundary`, `depth`, `record index`,
    /// `max_groups`) failed to parse as the target integer type.
    ///
    /// The `option` field carries the lower-case label used in the
    /// pre-Phase-5d Display message so the byte sequence is
    /// unchanged.  The underlying [`ParseIntError`] is exposed via
    /// [`core::error::Error::source`] for callers that want the typed
    /// chain — net-new coverage over the previous `String` return.
    #[error("Invalid {option}: `{value}`: {source}")]
    InvalidIntOption {
        /// The option label as rendered in the pre-Phase-5d Display
        /// message (`"top"`, `"sample"`, `"interval"`, `"range
        /// boundary"`, `"depth"`, `"record index"`, `"max_groups"`).
        option: &'static str,
        /// The offending value as supplied on the wire / command line.
        value: String,
        /// The underlying `u*::from_str` failure.
        #[source]
        source: ParseIntError,
    },
    /// `calendar=` named a value that
    /// [`crate::aggregate::spec::CalendarInterval::parse`] does not
    /// recognise.
    #[error("Invalid calendar interval: `{val}`")]
    InvalidCalendar {
        /// The unrecognised calendar identifier.
        val: String,
    },
    /// `rollup:ancestor` was supplied without the required
    /// `record=<idx>` option (also known as `frs=` / `ancestor=`).
    #[error("rollup:ancestor requires record=<idx> option")]
    AncestorRequiresRecord,
    /// `rollup:ancestor` was supplied without the required
    /// `drive=<letter>` option. The record index is per-drive, so the
    /// drilldown must name the drive it belongs to.
    #[error("rollup:ancestor requires drive=<letter> option")]
    AncestorRequiresDrive,
    /// The `drive=` option did not parse as a drive letter (`A`–`Z`).
    #[error("Invalid drive letter: `{val}`")]
    InvalidDriveLetter {
        /// The unrecognised drive-letter value.
        val: String,
    },
    /// The rollup mode did not match `path` / `folder` / `dir` /
    /// `drive` / `ancestor` / `drilldown`.
    #[error("Unknown rollup mode: `{mode}`. Use 'path', 'drive', or 'ancestor'.")]
    UnknownRollupMode {
        /// The unrecognised rollup mode.
        mode: String,
    },
    /// The duplicates `verify=` mode did not match `none` /
    /// `first_bytes` / `first` / `sha256` / `hash`.
    #[error("Unknown verify mode: `{val}`")]
    UnknownVerifyMode {
        /// The unrecognised verify mode.
        val: String,
    },
    /// The preset name did not match any of
    /// `AggregatePreset::ALL_NAMES`.
    ///
    /// `available` is the comma-joined list of accepted names,
    /// preserved verbatim from the pre-Phase-5d Display message so
    /// operators see the same help text.
    #[error("Unknown preset: `{name}`. Available: {available}")]
    UnknownPreset {
        /// The unrecognised preset name.
        name: String,
        /// Comma-joined list of accepted preset names.
        available: String,
    },
    /// A `metrics=` segment in a `stats:*` spec named a scalar metric
    /// that did not match `sum` / `min` / `max` / `avg` / `mean` /
    /// `value_count` / `count` / `missing_count` / `missing`.
    #[error("Unknown scalar metric: `{name}`")]
    UnknownScalarMetric {
        /// The unrecognised scalar metric name.
        name: String,
    },
    /// A `metrics=` segment in a bucket-valued spec named a bucket
    /// metric that did not match `count` / `total_bytes` / `bytes` /
    /// `size` / `total_allocated` / `allocated` / `waste_bytes` /
    /// `waste` / `waste_pct` / `waste_percent` / `avg_size` / `avg` /
    /// `min_size` / `min` / `max_size` / `max` / `share_count` /
    /// `share_of_count` / `share_bytes` / `share_of_bytes`.
    #[error("Unknown bucket metric: `{name}`")]
    UnknownBucketMetric {
        /// The unrecognised bucket metric name.
        name: String,
    },
}
