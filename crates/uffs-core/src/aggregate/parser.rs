// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Power syntax parser for `--agg` specifications.
//!
//! Parses strings like:
//! - `count`
//! - `stats:size`
//! - `terms:extension,top=50,metrics=count+total_bytes`
//! - `hist:size,interval=1048576`
//! - `datehist:modified,calendar=month`
//! - `range:size,bins=0..1024+1024..1048576+1048576..`
//! - `rollup:path,depth=1,top=30`
//! - `duplicates:size+name,verify=none,top=100,sample=2`
//! - `preset:overview`
//! - `missing:extension`
//! - `distinct:extension`

use core::num::ParseIntError;

use super::parser_error::ParseAggSpecError;
use super::spec::{
    AggregateKind, AggregateSpec, BucketMetric, CalendarInterval, DuplicateVerify, RollupMode,
    ScalarMetric, TopHitsSpec,
};
use crate::search::field::FieldId;

/// Build a closure that lifts a [`ParseIntError`] into the typed
/// [`ParseAggSpecError::InvalidIntOption`] variant.
///
/// Keeps every `val.parse().map_err(...)` call site to a single line
/// so the file stays under the 800-LOC policy ceiling without
/// shedding any of the typed-variant information.  `option` is the
/// static label rendered into the pre-Phase-5d Display string
/// (e.g. `"top"`, `"sample"`, `"range boundary"`).
fn invalid_int(
    option: &'static str,
    value: String,
) -> impl FnOnce(ParseIntError) -> ParseAggSpecError {
    move |source| ParseAggSpecError::InvalidIntOption {
        option,
        value,
        source,
    }
}

/// Parse a single `--agg` specification string into an `AggregateSpec`.
///
/// # Errors
///
/// Returns a [`ParseAggSpecError`] variant when the spec is
/// malformed.  Display strings stay byte-identical with the
/// pre-Phase-5d `Result<_, String>` payloads so any operator-facing
/// log output (daemon `tracing::warn!` and CLI stderr) is unchanged.
pub fn parse_agg_spec(input: &str) -> Result<AggregateSpec, ParseAggSpecError> {
    let trimmed = input.trim();

    // Split on first ':'
    let (kind_str, rest) = trimmed.split_once(':').unwrap_or((trimmed, ""));

    match kind_str {
        "count" => Ok(AggregateSpec::new(AggregateKind::Count)),

        "stats" => parse_stats(rest),

        "terms" | "facet" => parse_terms(rest),

        "hist" | "histogram" => parse_histogram(rest),

        "datehist" | "date_histogram" => parse_date_histogram(rest),

        "range" => parse_range(rest),

        "rollup" => parse_rollup(rest),

        "duplicates" | "dups" => parse_duplicates(rest),

        "preset" => parse_preset(rest),

        "missing" => parse_missing(rest),

        "distinct" => parse_distinct(rest),

        _ => Err(ParseAggSpecError::UnknownKind {
            kind: kind_str.to_owned(),
        }),
    }
}

/// Parse key=value options from a comma-separated string.
fn parse_options(input: &str) -> Vec<(&str, &str)> {
    input
        .split(',')
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.split_once('='))
        .collect()
}

/// Extract the field and remaining options from "field,opt=val,opt=val".
fn split_field_and_options(input: &str) -> (&str, &str) {
    input.split_once(',').unwrap_or((input, ""))
}

/// Parse a field name to `FieldId`.
fn parse_field(name: &str) -> Result<FieldId, ParseAggSpecError> {
    FieldId::parse(name).ok_or_else(|| ParseAggSpecError::UnknownField {
        name: name.to_owned(),
    })
}

/// Parse "field,metrics=M+M" → Stats spec.
fn parse_stats(rest: &str) -> Result<AggregateSpec, ParseAggSpecError> {
    let (field_str, opts_str) = split_field_and_options(rest);
    let field = parse_field(field_str)?;
    let opts = parse_options(opts_str);
    let mut metrics = Vec::new();

    for (key, val) in &opts {
        if *key == "metrics" {
            for metric in val.split('+') {
                metrics.push(parse_scalar_metric(metric)?);
            }
        }
    }

    if metrics.is_empty() {
        metrics = vec![
            ScalarMetric::Sum,
            ScalarMetric::Min,
            ScalarMetric::Max,
            ScalarMetric::Avg,
        ];
    }

    Ok(AggregateSpec::new(AggregateKind::Stats { field, metrics }))
}

/// Parse "field,top=N,metrics=M+M" → Terms spec.
fn parse_terms(rest: &str) -> Result<AggregateSpec, ParseAggSpecError> {
    let (field_str, opts_str) = split_field_and_options(rest);
    let field = parse_field(field_str)?;
    let opts = parse_options(opts_str);
    let mut top: u16 = 20;
    let mut metrics = Vec::new();
    let mut sample_count: u8 = 0;

    for (key, val) in &opts {
        match *key {
            "top" => top = val.parse().map_err(invalid_int("top", (*val).to_owned()))?,
            "metrics" => {
                for metric in val.split('+') {
                    metrics.push(parse_bucket_metric(metric)?);
                }
            }
            "sample" => {
                sample_count = val
                    .parse()
                    .map_err(invalid_int("sample", (*val).to_owned()))?;
            }
            _ => {}
        }
    }

    if metrics.is_empty() {
        metrics = vec![BucketMetric::Count, BucketMetric::TotalBytes];
    }

    let sample = (sample_count > 0).then(|| TopHitsSpec::with_count(sample_count));

    Ok(AggregateSpec::new(AggregateKind::Terms {
        field,
        top,
        metrics,
        sample,
    }))
}

/// Parse "field,interval=N" → Histogram spec.
fn parse_histogram(rest: &str) -> Result<AggregateSpec, ParseAggSpecError> {
    let (field_str, opts_str) = split_field_and_options(rest);
    let field = parse_field(field_str)?;
    let opts = parse_options(opts_str);
    let mut interval: u64 = 1_048_576; // 1 MB default
    let mut metrics = vec![BucketMetric::Count, BucketMetric::TotalBytes];

    for (key, val) in &opts {
        match *key {
            "interval" => {
                interval = val
                    .parse()
                    .map_err(invalid_int("interval", (*val).to_owned()))?;
            }
            "metrics" => {
                metrics.clear();
                for metric in val.split('+') {
                    metrics.push(parse_bucket_metric(metric)?);
                }
            }
            _ => {}
        }
    }

    Ok(AggregateSpec::new(AggregateKind::Histogram {
        field,
        interval,
        metrics,
    }))
}

/// Parse "field,calendar=INTERVAL" → `DateHistogram` spec.
fn parse_date_histogram(rest: &str) -> Result<AggregateSpec, ParseAggSpecError> {
    let (field_str, opts_str) = split_field_and_options(rest);
    let field = parse_field(field_str)?;
    let opts = parse_options(opts_str);
    let mut calendar = CalendarInterval::Month;
    let mut metrics = vec![BucketMetric::Count, BucketMetric::TotalBytes];

    for (key, val) in &opts {
        match *key {
            "calendar" | "interval" => {
                calendar = CalendarInterval::parse(val).ok_or_else(|| {
                    ParseAggSpecError::InvalidCalendar {
                        val: (*val).to_owned(),
                    }
                })?;
            }
            "metrics" => {
                metrics.clear();
                for metric in val.split('+') {
                    metrics.push(parse_bucket_metric(metric)?);
                }
            }
            _ => {}
        }
    }

    Ok(AggregateSpec::new(AggregateKind::DateHistogram {
        field,
        calendar,
        metrics,
    }))
}

/// Parse "field,bins=A..B+C..D+E.." → Range spec.
fn parse_range(rest: &str) -> Result<AggregateSpec, ParseAggSpecError> {
    let (field_str, opts_str) = split_field_and_options(rest);
    let field = parse_field(field_str)?;
    let opts = parse_options(opts_str);
    let mut boundaries: Vec<u64> = Vec::new();
    let mut metrics = vec![BucketMetric::Count, BucketMetric::TotalBytes];

    for (key, val) in &opts {
        match *key {
            "bins" | "boundaries" => {
                for boundary_str in val.split('+') {
                    // Each bin can be "A..B" or just "A". Extract the boundary values.
                    for part in boundary_str.split("..") {
                        if !part.is_empty() {
                            let boundary_val: u64 = part
                                .parse()
                                .map_err(invalid_int("range boundary", part.to_owned()))?;
                            if !boundaries.contains(&boundary_val) {
                                boundaries.push(boundary_val);
                            }
                        }
                    }
                }
                boundaries.sort_unstable();
                boundaries.dedup();
            }
            "metrics" => {
                metrics.clear();
                for metric in val.split('+') {
                    metrics.push(parse_bucket_metric(metric)?);
                }
            }
            _ => {}
        }
    }

    Ok(AggregateSpec::new(AggregateKind::Range {
        field,
        boundaries,
        metrics,
    }))
}

/// Parse a `drive=<letter>` option value into a drive letter.
fn parse_drive_letter(val: &str) -> Result<uffs_mft::platform::DriveLetter, ParseAggSpecError> {
    val.parse()
        .map_err(|_ignored| ParseAggSpecError::InvalidDriveLetter {
            val: val.to_owned(),
        })
}

/// Parse "path,depth=N,top=N" or "drive,top=N" or
/// "ancestor,record=N,drive=C" → Rollup spec.
///
/// Nested sub-aggregation syntax: `rollup:drive,sub=terms:type`
fn parse_rollup(rest: &str) -> Result<AggregateSpec, ParseAggSpecError> {
    let (mode_str, opts_str) = split_field_and_options(rest);
    let opts = parse_options(opts_str);
    let mut depth: u32 = 1;
    let mut top: u16 = 30;
    let mut metrics = vec![BucketMetric::Count, BucketMetric::TotalBytes];
    let mut sample_count: u8 = 0;
    let mut record_idx: Option<u32> = None;
    let mut drive: Option<uffs_mft::platform::DriveLetter> = None;
    let mut sub_spec: Option<Box<AggregateSpec>> = None;

    for (key, val) in &opts {
        match *key {
            "depth" => {
                depth = val
                    .parse()
                    .map_err(invalid_int("depth", (*val).to_owned()))?;
            }
            "top" => top = val.parse().map_err(invalid_int("top", (*val).to_owned()))?,
            "record" | "frs" | "ancestor" => {
                record_idx = Some(
                    val.parse()
                        .map_err(invalid_int("record index", (*val).to_owned()))?,
                );
            }
            "drive" => drive = Some(parse_drive_letter(val)?),
            "metrics" => {
                metrics.clear();
                for metric in val.split('+') {
                    metrics.push(parse_bucket_metric(metric)?);
                }
            }
            "sample" => {
                sample_count = val
                    .parse()
                    .map_err(invalid_int("sample", (*val).to_owned()))?;
            }
            "sub" => {
                // Parse nested sub-aggregation spec (e.g. "terms:type").
                let inner = parse_agg_spec(val)?;
                sub_spec = Some(Box::new(inner));
            }
            _ => {}
        }
    }

    let mode = match mode_str {
        "drive" => RollupMode::Drive,
        "path" | "folder" | "dir" => RollupMode::Path { depth },
        "ancestor" | "drilldown" => {
            let idx = record_idx.ok_or(ParseAggSpecError::AncestorRequiresRecord)?;
            let letter = drive.ok_or(ParseAggSpecError::AncestorRequiresDrive)?;
            RollupMode::Ancestor {
                record_idx: idx,
                drive: letter,
            }
        }
        _ => {
            return Err(ParseAggSpecError::UnknownRollupMode {
                mode: mode_str.to_owned(),
            });
        }
    };

    let sample = (sample_count > 0).then(|| TopHitsSpec::with_count(sample_count));

    Ok(AggregateSpec::new(AggregateKind::Rollup {
        mode,
        top,
        metrics,
        sample,
        sub: sub_spec,
    }))
}

/// Parse "size+name,verify=MODE,top=N,sample=N" → Duplicates spec.
fn parse_duplicates(rest: &str) -> Result<AggregateSpec, ParseAggSpecError> {
    let (keys_str, opts_str) = split_field_and_options(rest);
    let opts = parse_options(opts_str);

    let mut keys: Vec<FieldId> = Vec::new();
    for key in keys_str.split('+') {
        keys.push(parse_field(key)?);
    }
    if keys.is_empty() {
        keys = vec![FieldId::Size, FieldId::Name];
    }

    let mut verify = DuplicateVerify::None;
    let mut top: u16 = 100;
    let mut sample_count: u8 = 2;
    let mut max_groups: u32 = 500_000;

    for (key, val) in &opts {
        match *key {
            "verify" => {
                verify = match *val {
                    "none" => DuplicateVerify::None,
                    "first_bytes" | "first" => DuplicateVerify::FirstBytes { count: 4096 },
                    "sha256" | "hash" => DuplicateVerify::Sha256,
                    _ => {
                        return Err(ParseAggSpecError::UnknownVerifyMode {
                            val: (*val).to_owned(),
                        });
                    }
                };
            }
            "top" => top = val.parse().map_err(invalid_int("top", (*val).to_owned()))?,
            "sample" => {
                sample_count = val
                    .parse()
                    .map_err(invalid_int("sample", (*val).to_owned()))?;
            }
            "max_groups" => {
                max_groups = val
                    .parse()
                    .map_err(invalid_int("max_groups", (*val).to_owned()))?;
            }
            _ => {}
        }
    }

    let sample = (sample_count > 0).then(|| TopHitsSpec::with_count(sample_count));

    Ok(AggregateSpec::new(AggregateKind::Duplicates {
        keys,
        verify,
        top,
        sample,
        max_groups,
    }))
}

/// Parse "NAME" → Preset expansion.
fn parse_preset(rest: &str) -> Result<AggregateSpec, ParseAggSpecError> {
    let name = rest.trim();
    if super::presets::AggregatePreset::parse(name).is_none() {
        return Err(ParseAggSpecError::UnknownPreset {
            name: name.to_owned(),
            available: super::presets::AggregatePreset::ALL_NAMES.join(", "),
        });
    }
    // Return a Count as placeholder — the caller should expand the preset.
    // For now, we signal via label that this is a preset.
    Ok(AggregateSpec::with_label(
        AggregateKind::Count,
        format!("__preset__{name}"),
    ))
}

/// Parse "field" → Missing spec.
fn parse_missing(rest: &str) -> Result<AggregateSpec, ParseAggSpecError> {
    let field = parse_field(rest.trim())?;
    Ok(AggregateSpec::new(AggregateKind::Missing { field }))
}

/// Parse "field" → Distinct spec.
fn parse_distinct(rest: &str) -> Result<AggregateSpec, ParseAggSpecError> {
    let field = parse_field(rest.trim())?;
    Ok(AggregateSpec::new(AggregateKind::Distinct { field }))
}

/// Parse a scalar metric name.
fn parse_scalar_metric(name: &str) -> Result<ScalarMetric, ParseAggSpecError> {
    match name {
        "sum" => Ok(ScalarMetric::Sum),
        "min" => Ok(ScalarMetric::Min),
        "max" => Ok(ScalarMetric::Max),
        "avg" | "mean" => Ok(ScalarMetric::Avg),
        "value_count" | "count" => Ok(ScalarMetric::ValueCount),
        "missing_count" | "missing" => Ok(ScalarMetric::MissingCount),
        _ => Err(ParseAggSpecError::UnknownScalarMetric {
            name: name.to_owned(),
        }),
    }
}

/// Parse a bucket metric name.
fn parse_bucket_metric(name: &str) -> Result<BucketMetric, ParseAggSpecError> {
    match name {
        "count" => Ok(BucketMetric::Count),
        "total_bytes" | "bytes" | "size" => Ok(BucketMetric::TotalBytes),
        "total_allocated" | "allocated" => Ok(BucketMetric::TotalAllocated),
        "waste_bytes" | "waste" => Ok(BucketMetric::WasteBytes),
        "waste_pct" | "waste_percent" => Ok(BucketMetric::WastePct),
        "avg_size" | "avg" => Ok(BucketMetric::AvgSize),
        "min_size" | "min" => Ok(BucketMetric::MinSize),
        "max_size" | "max" => Ok(BucketMetric::MaxSize),
        "share_count" | "share_of_count" => Ok(BucketMetric::ShareOfTotalCount),
        "share_bytes" | "share_of_bytes" => Ok(BucketMetric::ShareOfTotalBytes),
        _ => Err(ParseAggSpecError::UnknownBucketMetric {
            name: name.to_owned(),
        }),
    }
}

/// Parse multiple `--agg` specifications and expand presets.
///
/// Returns a flat list of `AggregateSpec`s with all presets expanded.
///
/// # Errors
///
/// Returns errors for any malformed spec.
pub fn parse_and_expand_agg_specs(
    inputs: &[&str],
) -> Result<Vec<AggregateSpec>, ParseAggSpecError> {
    let mut result = Vec::new();

    for input in inputs {
        let spec = parse_agg_spec(input)?;

        // Check if this is a preset placeholder.
        if let Some(label) = &spec.label
            && let Some(name) = label.strip_prefix("__preset__")
            && let Some(preset) = super::presets::AggregatePreset::parse(name)
        {
            result.extend(preset.expand());
            continue;
        }

        result.push(spec);
    }

    Ok(result)
}

// Tests live in a sibling file via `#[path]` to keep this file under
// the 800-line policy ceiling.  The attached child sees this module's
// scope (private items, `use super::*;`) exactly as it did when the
// tests lived inline.
#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;
