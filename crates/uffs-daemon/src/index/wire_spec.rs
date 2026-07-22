// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Wire → core aggregate-spec conversion.
//!
//! Split out of `aggregation.rs` so the runtime path
//! (`run_aggregations` and the duplicate-verifier glue) and the wire
//! decoder can be read independently.  The decoder has no dependency
//! on [`IndexManager`] state — every match arm is a pure
//! [`uffs_client::protocol::aggregate_wire::AggregateSpecWire`] →
//! [`uffs_core::aggregate::AggregateSpec`] mapping — so isolating it makes the
//! transport contract obvious without changing any call site.
//!
//! Public surface is unchanged: callers still write
//! `IndexManager::convert_wire_spec(ws)`.

use uffs_core::aggregate::TopHitsSpec;

use crate::index::IndexManager;

/// Typed errors produced by [`IndexManager::convert_wire_spec`] and
/// its helpers.
///
/// Phase 5d migration of the previous `Result<_, String>` return type:
/// the [`core::fmt::Display`] strings stay byte-identical with the
/// pre-migration messages so the
/// `tracing::warn!("skipping malformed aggregate spec: {e}")` line in
/// `aggregation.rs` keeps rendering the exact same operator-facing
/// text.  The typed variants give downstream tooling (and future
/// aggregation-level RPC error handlers) something to match on without
/// parsing strings.
///
/// `#[non_exhaustive]` per Phase 5c discipline so a future wire-kind
/// can grow a variant without a semver bump on the
/// (workspace-internal) consumer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum WireSpecError {
    /// `kind == "preset"` but the `preset` field was absent.
    #[error("preset kind requires 'preset' field")]
    PresetFieldMissing,
    /// `preset` named a value that [`AggregatePreset::parse`] does not
    /// recognise.
    ///
    /// [`AggregatePreset::parse`]: uffs_core::aggregate::presets::AggregatePreset::parse
    #[error("unknown preset: `{name}`")]
    UnknownPreset {
        /// The unrecognised preset name as supplied on the wire.
        name: String,
    },
    /// The wire spec's `field` slot was absent for a kind that requires
    /// it (`stats`, `terms`, `histogram`, `range`, `missing`,
    /// `distinct`, `date_histogram`).
    #[error("missing 'field'")]
    FieldMissing,
    /// `field` named a column that [`FieldId::parse`] does not
    /// recognise.
    ///
    /// [`FieldId::parse`]: uffs_core::search::field::FieldId::parse
    #[error("unknown field: `{name}`")]
    UnknownField {
        /// The unrecognised field name as supplied on the wire.
        name: String,
    },
    /// `calendar` named a value that [`CalendarInterval::parse`] does
    /// not recognise.
    ///
    /// [`CalendarInterval::parse`]: uffs_core::aggregate::spec::CalendarInterval::parse
    #[error("unknown calendar interval: `{name}`")]
    UnknownCalendar {
        /// The unrecognised calendar identifier as supplied on the wire.
        name: String,
    },
    /// `kind == "raw"` but the syntax slot (the wire `label` field)
    /// was absent.
    #[error("raw kind requires syntax in 'label' field")]
    RawSyntaxMissing,
    /// [`parse_agg_spec`] rejected the raw spec syntax.
    ///
    /// Phase 5d (post-`uffs-core` migration): tightened from the
    /// pre-migration `RawSyntax(String)` to carry the typed
    /// [`uffs_core::aggregate::ParseAggSpecError`] directly.  Display
    /// stays byte-identical with the pre-Phase-5d payload because
    /// `ParseAggSpecError`'s `Display` impl preserves the original
    /// `format!()` text from `parse_agg_spec`.  Source-chain is now
    /// walkable via [`core::error::Error::source`].
    ///
    /// [`parse_agg_spec`]: uffs_core::aggregate::parser::parse_agg_spec
    #[error("{0}")]
    RawSyntax(#[source] uffs_core::aggregate::ParseAggSpecError),
    /// `kind` did not match any of the supported aggregate kinds.
    #[error("unknown aggregate kind: `{kind}`")]
    UnknownKind {
        /// The unrecognised kind identifier as supplied on the wire.
        kind: String,
    },
    /// An `ancestor`/`drilldown` rollup arrived without a usable
    /// `drive` slot. The rollup's record index is per-drive, so the
    /// drilldown must name the drive it belongs to.
    #[error("ancestor rollup requires a valid 'drive' letter")]
    AncestorDriveMissing,
}

impl IndexManager {
    /// Convert a wire-protocol
    /// [`uffs_client::protocol::aggregate_wire::AggregateSpecWire`] into one or
    /// more core [`uffs_core::aggregate::AggregateSpec`]s.
    ///
    /// Presets expand to multiple specs; all other kinds produce
    /// exactly one.
    ///
    /// # Errors
    ///
    /// Returns [`WireSpecError`] when the wire spec is missing a
    /// required field, names an unknown preset / calendar / kind, or
    /// fails the inner `parse_agg_spec` (for `kind: "raw"`).  The
    /// [`core::fmt::Display`] string stays byte-identical with the
    /// pre-Phase-5d `String` payload so operator-facing log lines are
    /// unchanged.
    ///
    /// [`uffs_core::aggregate::AggregateSpec`]: uffs_core::aggregate::spec::AggregateSpec
    /// [`uffs_client::protocol::aggregate_wire::AggregateSpecWire`]: uffs_client::protocol::AggregateSpecWire
    #[expect(
        clippy::too_many_lines,
        reason = "straightforward match arms — one per wire kind"
    )]
    pub(crate) fn convert_wire_spec(
        ws: &uffs_client::protocol::AggregateSpecWire,
    ) -> Result<Vec<uffs_core::aggregate::spec::AggregateSpec>, WireSpecError> {
        use uffs_core::aggregate::parser::parse_agg_spec;
        use uffs_core::aggregate::presets::AggregatePreset;
        use uffs_core::aggregate::spec::{
            AggregateKind, AggregateSpec, CalendarInterval, DuplicateVerify, RollupMode,
        };
        use uffs_core::search::field::FieldId;

        let make = |kind: AggregateKind| -> Vec<AggregateSpec> {
            let mut spec = AggregateSpec::new(kind);
            spec.label.clone_from(&ws.label);
            vec![spec]
        };

        match ws.kind.as_str() {
            "preset" => {
                let name = ws
                    .preset
                    .as_deref()
                    .ok_or(WireSpecError::PresetFieldMissing)?;
                let preset =
                    AggregatePreset::parse(name).ok_or_else(|| WireSpecError::UnknownPreset {
                        name: name.to_owned(),
                    })?;
                Ok(preset.expand())
            }
            "count" => Ok(make(AggregateKind::Count)),
            "stats" => {
                let field = require_field(ws)?;
                let metrics = parse_scalar_metrics(&ws.metrics);
                Ok(make(AggregateKind::Stats { field, metrics }))
            }
            "terms" | "facet" => {
                let field = require_field(ws)?;
                let top = ws.top.unwrap_or(20);
                let metrics = parse_bucket_metrics(&ws.metrics);
                Ok(make(AggregateKind::Terms {
                    field,
                    top,
                    metrics,
                    sample: build_sample(ws),
                }))
            }
            "histogram" | "hist" => {
                let field = require_field(ws)?;
                let interval = ws.interval.unwrap_or(1_048_576);
                let metrics = parse_bucket_metrics(&ws.metrics);
                Ok(make(AggregateKind::Histogram {
                    field,
                    interval,
                    metrics,
                }))
            }
            "date_histogram" | "datehist" => {
                let field = require_field(ws)?;
                let cal_str = ws.calendar.as_deref().unwrap_or("month");
                let calendar = CalendarInterval::parse(cal_str).ok_or_else(|| {
                    WireSpecError::UnknownCalendar {
                        name: cal_str.to_owned(),
                    }
                })?;
                let metrics = parse_bucket_metrics(&ws.metrics);
                Ok(make(AggregateKind::DateHistogram {
                    field,
                    calendar,
                    metrics,
                }))
            }
            "range" => {
                let field = require_field(ws)?;
                let metrics = parse_bucket_metrics(&ws.metrics);
                Ok(make(AggregateKind::Range {
                    field,
                    boundaries: ws.boundaries.clone(),
                    metrics,
                }))
            }
            "missing" => {
                let field = require_field(ws)?;
                Ok(make(AggregateKind::Missing { field }))
            }
            "distinct" => {
                let field = require_field(ws)?;
                Ok(make(AggregateKind::Distinct { field }))
            }
            "rollup" => {
                let mode_str = ws.field.as_deref().unwrap_or("path");
                let mode = match mode_str {
                    "drive" => RollupMode::Drive,
                    "ancestor" | "drilldown" => {
                        // Use interval field as the record index. The
                        // index is per-drive, so the wire spec must also
                        // name the drive it belongs to.
                        let record_idx = u32::try_from(ws.interval.unwrap_or(0)).unwrap_or(0);
                        let drive = ws
                            .drive
                            .as_deref()
                            .and_then(|letter| letter.parse().ok())
                            .ok_or(WireSpecError::AncestorDriveMissing)?;
                        RollupMode::Ancestor { record_idx, drive }
                    }
                    _ => {
                        let depth = u32::try_from(ws.interval.unwrap_or(1)).unwrap_or(1);
                        RollupMode::Path { depth }
                    }
                };
                let top = ws.top.unwrap_or(30);
                let metrics = parse_bucket_metrics(&ws.metrics);
                Ok(make(AggregateKind::Rollup {
                    mode,
                    top,
                    metrics,
                    sample: build_sample(ws),
                    sub: None, // TODO: wire sub-agg from wire type
                }))
            }
            "duplicates" | "dups" => {
                let parsed_keys: Vec<FieldId> = ws
                    .metrics
                    .iter()
                    .filter_map(|raw| FieldId::parse(raw))
                    .collect();
                let keys = if parsed_keys.is_empty() {
                    vec![FieldId::Size, FieldId::Name]
                } else {
                    parsed_keys
                };
                let top = ws.top.unwrap_or(100);
                let verify = match ws.verify.as_deref() {
                    Some("first_bytes") => DuplicateVerify::FirstBytes {
                        count: ws.verify_bytes.unwrap_or(4096),
                    },
                    Some("sha256") => DuplicateVerify::Sha256,
                    _ => DuplicateVerify::None,
                };
                Ok(make(AggregateKind::Duplicates {
                    keys,
                    verify,
                    top,
                    sample: Some(build_sample(ws).unwrap_or_else(|| TopHitsSpec::with_count(2))),
                    max_groups: 500_000,
                }))
            }
            "raw" => {
                let syntax = ws.label.as_deref().ok_or(WireSpecError::RawSyntaxMissing)?;
                let spec = parse_agg_spec(syntax).map_err(WireSpecError::RawSyntax)?;
                Ok(vec![spec])
            }
            other => Err(WireSpecError::UnknownKind {
                kind: other.to_owned(),
            }),
        }
    }
}

/// Parse the wire spec's `field` slot into a [`FieldId`], producing a
/// typed [`WireSpecError`] when it is absent or names an unknown
/// column.
///
/// [`FieldId`]: uffs_core::search::field::FieldId
fn require_field(
    ws: &uffs_client::protocol::AggregateSpecWire,
) -> Result<uffs_core::search::field::FieldId, WireSpecError> {
    let name = ws.field.as_deref().ok_or(WireSpecError::FieldMissing)?;
    uffs_core::search::field::FieldId::parse(name).ok_or_else(|| WireSpecError::UnknownField {
        name: name.to_owned(),
    })
}

/// Parse wire metric strings to [`uffs_core::aggregate::BucketMetric`]s.
///
/// Empty input falls back to the default `[Count, TotalBytes]` pair so
/// `terms` / `histogram` / `range` / `rollup` / `date_histogram`
/// always emit at least the two metrics every UFFS dashboard relies on.
fn parse_bucket_metrics(wire: &[String]) -> Vec<uffs_core::aggregate::spec::BucketMetric> {
    use uffs_core::aggregate::spec::BucketMetric;
    if wire.is_empty() {
        return vec![BucketMetric::Count, BucketMetric::TotalBytes];
    }
    wire.iter()
        .filter_map(|metric| match metric.as_str() {
            "count" => Some(BucketMetric::Count),
            "total_bytes" | "bytes" | "size" => Some(BucketMetric::TotalBytes),
            "total_allocated" | "allocated" => Some(BucketMetric::TotalAllocated),
            "waste_bytes" | "waste" => Some(BucketMetric::WasteBytes),
            "waste_pct" | "waste_percent" => Some(BucketMetric::WastePct),
            "avg_size" | "avg" => Some(BucketMetric::AvgSize),
            "min_size" | "min" => Some(BucketMetric::MinSize),
            "max_size" | "max" => Some(BucketMetric::MaxSize),
            "share_count" | "share_of_count" => Some(BucketMetric::ShareOfTotalCount),
            "share_bytes" | "share_of_bytes" => Some(BucketMetric::ShareOfTotalBytes),
            _ => None,
        })
        .collect()
}

/// Parse wire metric strings to [`uffs_core::aggregate::ScalarMetric`]s.
///
/// Empty input expands to `[Sum, Min, Max, Avg]`, matching the
/// behaviour every `stats` aggregation has shipped with since v0.5.
fn parse_scalar_metrics(wire: &[String]) -> Vec<uffs_core::aggregate::spec::ScalarMetric> {
    use uffs_core::aggregate::spec::ScalarMetric;
    if wire.is_empty() {
        return vec![
            ScalarMetric::Sum,
            ScalarMetric::Min,
            ScalarMetric::Max,
            ScalarMetric::Avg,
        ];
    }
    wire.iter()
        .filter_map(|metric| match metric.as_str() {
            "sum" => Some(ScalarMetric::Sum),
            "min" => Some(ScalarMetric::Min),
            "max" => Some(ScalarMetric::Max),
            "avg" | "mean" => Some(ScalarMetric::Avg),
            "value_count" | "count" => Some(ScalarMetric::ValueCount),
            "missing_count" | "missing" => Some(ScalarMetric::MissingCount),
            _ => None,
        })
        .collect()
}

/// Build `Option<TopHitsSpec>` from the wire spec's sample fields.
fn build_sample(ws: &uffs_client::protocol::AggregateSpecWire) -> Option<TopHitsSpec> {
    use uffs_core::search::field::FieldId;

    ws.sample.map(|count| {
        let mut th = TopHitsSpec::with_count(count);
        if let Some(field) = &ws.sample_sort
            && let Some(fid) = FieldId::parse(field)
        {
            th.sort_field = fid;
        }
        if let Some(desc) = ws.sample_desc {
            th.sort_desc = desc;
        }
        th
    })
}

#[cfg(test)]
mod tests {
    //! Phase 5d regression tests for [`WireSpecError`].
    //!
    //! Locks the Display message of every variant at the byte-identical
    //! string the pre-Phase-5d `Result<_, String>` returns produced.
    //! The `tracing::warn!("skipping malformed aggregate spec: {e}")`
    //! line in `aggregation.rs` interpolates Display, so operator-facing
    //! daemon logs are guaranteed unchanged by this lock.

    use uffs_client::protocol::AggregateSpecWire;

    use super::{IndexManager, WireSpecError};

    /// Make an empty wire spec with the given `kind` for happy-path
    /// rejection tests.
    fn ws(kind: &str) -> AggregateSpecWire {
        AggregateSpecWire {
            kind: kind.to_owned(),
            ..AggregateSpecWire::default()
        }
    }

    #[test]
    fn preset_field_missing_display_locked() {
        let err = IndexManager::convert_wire_spec(&ws("preset"))
            .expect_err("preset kind without 'preset' field must error");
        assert_eq!(err, WireSpecError::PresetFieldMissing);
        assert_eq!(err.to_string(), "preset kind requires 'preset' field");
    }

    #[test]
    fn unknown_preset_display_locked() {
        let mut spec = ws("preset");
        spec.preset = Some("does-not-exist".to_owned());
        let err =
            IndexManager::convert_wire_spec(&spec).expect_err("unknown preset name must error");
        assert_eq!(err, WireSpecError::UnknownPreset {
            name: "does-not-exist".to_owned(),
        },);
        assert_eq!(err.to_string(), "unknown preset: `does-not-exist`");
    }

    #[test]
    fn field_missing_display_locked() {
        // `stats` requires a `field`; omitting it walks the
        // `require_field` → `FieldMissing` path.
        let err = IndexManager::convert_wire_spec(&ws("stats"))
            .expect_err("stats kind without 'field' must error");
        assert_eq!(err, WireSpecError::FieldMissing);
        assert_eq!(err.to_string(), "missing 'field'");
    }

    #[test]
    fn unknown_field_display_locked() {
        let mut spec = ws("stats");
        spec.field = Some("not-a-column".to_owned());
        let err =
            IndexManager::convert_wire_spec(&spec).expect_err("unknown field name must error");
        assert_eq!(err, WireSpecError::UnknownField {
            name: "not-a-column".to_owned(),
        },);
        assert_eq!(err.to_string(), "unknown field: `not-a-column`");
    }

    #[test]
    fn unknown_calendar_display_locked() {
        let mut spec = ws("date_histogram");
        spec.field = Some("modified".to_owned());
        spec.calendar = Some("fortnight".to_owned());
        let err = IndexManager::convert_wire_spec(&spec)
            .expect_err("unknown calendar interval must error");
        assert_eq!(err, WireSpecError::UnknownCalendar {
            name: "fortnight".to_owned(),
        },);
        assert_eq!(err.to_string(), "unknown calendar interval: `fortnight`");
    }

    #[test]
    fn raw_syntax_missing_display_locked() {
        let err = IndexManager::convert_wire_spec(&ws("raw"))
            .expect_err("raw kind without label must error");
        assert_eq!(err, WireSpecError::RawSyntaxMissing);
        assert_eq!(err.to_string(), "raw kind requires syntax in 'label' field");
    }

    #[test]
    fn raw_syntax_passthrough_preserves_inner_message() {
        // `parse_agg_spec("")` returns
        // `Err(ParseAggSpecError::UnknownKind { kind: "" })`; the
        // typed variant must echo the inner Display verbatim through
        // its own Display so the existing operator-facing message is
        // intact.  Post-`uffs-core` Phase 5d the inner is now a typed
        // `ParseAggSpecError` rather than a `String` — the source
        // chain is walkable via `Error::source`.
        use core::error::Error as _;

        let mut spec = ws("raw");
        spec.label = Some(String::new());
        let err = IndexManager::convert_wire_spec(&spec).expect_err("empty raw spec must error");
        let WireSpecError::RawSyntax(inner) = &err else {
            panic!("expected RawSyntax, got {err:?}");
        };
        // Display equals the inner ParseAggSpecError Display, which
        // for the empty-spec path expands to "Unknown aggregate kind:
        // ``" — byte-identical with the pre-Phase-5d String payload.
        let inner_display = inner.to_string();
        assert!(
            !inner_display.is_empty(),
            "passthrough display must not collapse to empty",
        );
        assert_eq!(err.to_string(), inner_display);
        // The source chain walks to the inner typed error.
        let chained = err.source().expect("RawSyntax exposes its inner source");
        assert_eq!(chained.to_string(), inner_display);
    }

    #[test]
    fn unknown_kind_display_locked() {
        let err = IndexManager::convert_wire_spec(&ws("bogus-kind"))
            .expect_err("unknown kind must error");
        assert_eq!(err, WireSpecError::UnknownKind {
            kind: "bogus-kind".to_owned(),
        },);
        assert_eq!(err.to_string(), "unknown aggregate kind: `bogus-kind`");
    }

    #[test]
    fn ancestor_rollup_without_drive_errors() {
        let mut spec = ws("rollup");
        spec.field = Some("ancestor".to_owned());
        spec.interval = Some(42);
        let err = IndexManager::convert_wire_spec(&spec)
            .expect_err("ancestor rollup without 'drive' must error");
        assert_eq!(err, WireSpecError::AncestorDriveMissing);
        assert_eq!(
            err.to_string(),
            "ancestor rollup requires a valid 'drive' letter"
        );
    }

    #[test]
    fn ancestor_rollup_with_drive_converts() {
        let mut spec = ws("rollup");
        spec.field = Some("ancestor".to_owned());
        spec.interval = Some(42);
        spec.drive = Some("C".to_owned());
        let specs = IndexManager::convert_wire_spec(&spec).expect("valid ancestor rollup");
        assert_eq!(specs.len(), 1);
    }
}
