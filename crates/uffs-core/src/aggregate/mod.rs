// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Aggregation engine for UFFS.
//!
//! Provides high-performance, single-pass aggregate computations over
//! `CompactRecord` arrays. Designed to operate on the hot path — no
//! `DisplayRow` construction, no path resolution unless explicitly requested.
//!
//! # Architecture
//!
//! ```text
//! AggregateSpec  ──▶  AggregatePlan  ──▶  AggregateEngine::run()
//!                      (compile)           │
//!                                          ├─ per-drive parallel scan
//!                                          ├─ accumulators (feed/merge)
//!                                          └─ finalize → AggregateResult
//! ```
//!
//! See `docs/architecture/UFFS_AGGREGATION_ARCHITECTURE_CONSOLIDATED.md`
//! for the full design.

pub mod accumulators;
pub mod buckets;
pub mod cache;
pub mod duplicates;
pub mod export;
pub mod finalize;
pub mod pagination;
pub mod parser;
pub mod parser_error;
pub(crate) mod planner;
pub mod presets;
pub mod rollup;
/// Per-bucket sample heap for tracking top-N records.
pub(crate) mod sample_heap;
pub mod spec;
/// Duplicate verification (first-bytes / SHA-256).
pub mod verify;

// Re-export core public types.
pub use accumulators::GroupAccumulator;
pub use buckets::{AgeBucket, SizeBucket};
pub use cache::{AggregateCache, CacheStats, hash_specs};
pub use duplicates::{DuplicateAccumulator, DuplicateResult};
pub use export::{ExportFormat, export_results};
pub use finalize::{
    AggregateResponse, BucketRow, DrilldownPredicate, DrilldownValue, FinalizeOptions, SampleRow,
};
pub use pagination::{AggregateCursor, PaginatedBuckets, paginate_result};
pub use parser::{parse_agg_spec, parse_and_expand_agg_specs};
pub use parser_error::ParseAggSpecError;
pub use planner::AggregatePlan;
pub use presets::AggregatePreset;
use rayon::prelude::*;
pub use rollup::RollupAccumulator;
pub use spec::{
    AggregateKind, AggregateSpec, BucketMetric, CalendarInterval, DuplicateVerify, RollupMode,
    ScalarMetric, TopHitsSpec,
};
pub use verify::{DuplicateVerifier, FileReader, VerificationBudget, VerificationSummary};

use crate::compact::{CompactRecord, DriveCompactIndex};

/// Result of running one or more aggregate specs against a set of drives.
///
/// Contains the finalized response plus execution metadata.
#[derive(Debug, Clone)]
pub struct AggregateOutput {
    /// The finalized aggregate response.
    pub response: AggregateResponse,
    /// Total records scanned across all drives.
    pub records_scanned: u64,
    /// Total records that passed filters and contributed to aggregates.
    pub records_matched: u64,
    /// Wall-clock execution time in microseconds.
    pub execution_us: u64,
}

/// Lightweight filter for pre-scan record selection in aggregate queries.
///
/// Unlike the full `SearchFilters` (which lives in the search path and
/// supports pattern matching, path predicates, etc.), this struct carries
/// only the fast, O(1)-per-record checks that can be applied during the
/// aggregation scan without path resolution.
///
/// Extension IDs are **per-drive** — call
/// `DriveCompactIndex::resolve_ext_ids` once per drive before scanning.
#[derive(Debug, Clone, Default, Hash)]
pub struct AggregateFilter {
    /// Extension name strings (lowercase, no dot).  Resolved to per-drive
    /// `u16` IDs before scanning via `DriveCompactIndex::resolve_ext_ids`.
    pub extensions: Vec<String>,
    /// If `Some(true)` only directories; `Some(false)` only files.
    pub directory_only: Option<bool>,
    /// Minimum file size (inclusive).
    pub min_size: Option<u64>,
    /// Maximum file size (inclusive).
    pub max_size: Option<u64>,
}

impl AggregateFilter {
    /// Returns `true` if no filter constraints are set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.extensions.is_empty()
            && self.directory_only.is_none()
            && self.min_size.is_none()
            && self.max_size.is_none()
    }

    /// O(1) per-record check using pre-resolved extension IDs.
    #[inline]
    fn matches(&self, record: &CompactRecord, resolved_ext_ids: &[u16]) -> bool {
        // Directory / file filter.
        if let Some(dirs_only) = self.directory_only
            && record.is_directory() != dirs_only
        {
            return false;
        }
        // Extension filter (fast path via pre-resolved IDs). A requested
        // filter that resolved to no IDs on this drive matches NOTHING —
        // never "no filter" (the drive loop also short-circuits that case;
        // this guard keeps the predicate safe for any future caller).
        if !self.extensions.is_empty()
            && (resolved_ext_ids.is_empty() || !resolved_ext_ids.contains(&record.extension_id))
        {
            return false;
        }
        // Size bounds.
        if let Some(min) = self.min_size
            && record.size < min
        {
            return false;
        }
        if let Some(max) = self.max_size
            && record.size > max
        {
            return false;
        }
        true
    }
}

/// Cross-drive canonical extension mapping.
///
/// Each drive interns extensions independently (`extension_id` is per-drive).
/// This table maps every `(drive_ordinal, local_extension_id)` to a single
/// canonical ID so that `"exe"` on drive C and `"exe"` on drive D share the
/// same group key in aggregation.
///
/// The reverse mapping (`canonical_id → extension name`) is stored in
/// `canonical_names`.
#[derive(Debug, Clone)]
pub(crate) struct ExtensionMap {
    /// `per_drive[drive_ordinal][local_ext_id] → canonical_ext_id`
    per_drive: Vec<Vec<u64>>,
    /// `canonical_names[canonical_ext_id] → extension string`
    canonical_names: Vec<String>,
}

impl ExtensionMap {
    /// Build the cross-drive mapping from a set of drives.
    fn build(drives: &[&DriveCompactIndex]) -> Self {
        let mut name_to_id: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        let mut canonical_names: Vec<String> = Vec::new();
        let mut per_drive: Vec<Vec<u64>> = Vec::with_capacity(drives.len());

        for drive in drives {
            let mut mapping = Vec::with_capacity(drive.ext_names.len());
            for ext_name in &drive.ext_names {
                let name_str: &str = ext_name;
                let canonical_id = if let Some(&id) = name_to_id.get(name_str) {
                    id
                } else {
                    let id = canonical_names.len() as u64;
                    let owned = name_str.to_owned();
                    canonical_names.push(owned.clone());
                    name_to_id.insert(owned, id);
                    id
                };
                mapping.push(canonical_id);
            }
            per_drive.push(mapping);
        }

        Self {
            per_drive,
            canonical_names,
        }
    }

    /// Look up the canonical extension ID for a record.
    #[inline]
    fn canonical_id(&self, drive_ordinal: u8, local_ext_id: u16) -> u64 {
        self.per_drive
            .get(usize::from(drive_ordinal))
            .and_then(|map| map.get(usize::from(local_ext_id)))
            .copied()
            .unwrap_or(u64::MAX)
    }

    /// Resolve a canonical ID to its extension name.
    fn resolve(&self, canonical_id: u64) -> String {
        self.canonical_names
            .get(uffs_mft::frs_to_usize(canonical_id))
            .cloned()
            .unwrap_or_else(|| format!("ext:{canonical_id}"))
    }
}

/// Run aggregation specs against one or more drive indices (unfiltered).
///
/// This is the main entry point for the aggregation engine. It:
/// 1. Compiles specs into an `AggregatePlan`
/// 2. Scans all records per drive
/// 3. Merges per-drive accumulators
/// 4. Finalizes and returns results
///
/// For filtered aggregation, use the search pipeline to pre-filter
/// and then feed matching record indices to the accumulators.
///
/// # Errors
///
/// Returns an error if any spec references an invalid field or if
/// accumulator construction fails.
pub fn run_aggregate(
    drives: &[&DriveCompactIndex],
    specs: &[AggregateSpec],
    options: &FinalizeOptions,
) -> Result<AggregateOutput, AggregateError> {
    let start = std::time::Instant::now();

    // 1. Compile
    let plan = AggregatePlan::compile(specs)?;

    // Build cross-drive extension mapping for correct multi-drive grouping.
    let ext_map = ExtensionMap::build(drives);

    // 2. Drive-level parallel scan.  Outer `par_iter` fans the work out over
    //    drives; each drive's inner scan is sequential.  The per-record work
    //    (`accumulator.feed`) is only a few nanoseconds, which makes wrapping it in
    //    a second layer of `par_iter().fold().reduce()` a net loss under concurrent
    //    load: each nested fold chunk clones a full `Vec<GroupAccumulator>` and
    //    then has to be reduced back together, and with K concurrent aggregate
    //    queries the rayon pool ends up oversubscribed K×cores².  See
    //    `LOG/2026_04_18_08_09_CHANGELOG_HEALING.md` Run 7 for the measurements
    //    that drove this decision.
    let (merged, total_scanned, total_matched): (Vec<GroupAccumulator>, u64, u64) = drives
        .par_iter()
        .enumerate()
        .map(|(drive_ordinal, drive)| {
            let ordinal = u8::try_from(drive_ordinal).unwrap_or(u8::MAX);
            let per_drive_start = std::time::Instant::now();
            let (local, scanned, matched) = scan_drive(drive, &plan, ordinal, &ext_map);
            tracing::debug!(
                drive = %drive.letter,
                scanned,
                matched,
                elapsed_ms = per_drive_start.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                "run_aggregate: drive scan"
            );
            (local, scanned, matched)
        })
        .reduce(
            || (plan.create_accumulators(), 0_u64, 0_u64),
            |(mut acc_a, sa, ma), (acc_b, sb, mb)| {
                merge_accumulator_sets(&mut acc_a, &acc_b);
                (acc_a, sa + sb, ma + mb)
            },
        );

    let t_fin = std::time::Instant::now();
    let scan_ms = start.elapsed().as_millis();

    // 3. Finalize
    let response =
        finalize::finalize_with_ext_map(merged, &plan, drives, options, total_matched, &ext_map);
    let total_ms = start.elapsed().as_millis();
    tracing::info!(
        drives = drives.len(),
        records_scanned = total_scanned,
        records_matched = total_matched,
        scan_ms = u64::try_from(scan_ms).unwrap_or(u64::MAX),
        finalize_ms = u64::try_from(t_fin.elapsed().as_millis()).unwrap_or(u64::MAX),
        total_ms = u64::try_from(total_ms).unwrap_or(u64::MAX),
        "run_aggregate: done"
    );

    Ok(AggregateOutput {
        response,
        records_scanned: total_scanned,
        records_matched: total_matched,
        execution_us: start.elapsed().as_micros().try_into().unwrap_or(u64::MAX),
    })
}

/// Run aggregation specs against records that match a search pattern.
///
/// This scans all records per drive but only feeds records whose name
/// matches `pattern` (a glob like `*.exe`).  This is the correct entry
/// point when combining search + aggregation: e.g. `*.exe --agg
/// terms:extension` should aggregate only `.exe` files, not all files.
///
/// The pattern is compiled once via
/// `index_search::compile_parsed_pattern` and matched inline during
/// the scan — no `DisplayRow` construction or path resolution is needed.
///
/// # Errors
///
/// Returns an error if any spec references an invalid field or if
/// accumulator construction fails.
pub(crate) fn run_aggregate_filtered(
    drives: &[&DriveCompactIndex],
    specs: &[AggregateSpec],
    options: &FinalizeOptions,
    pattern: &str,
) -> Result<AggregateOutput, AggregateError> {
    use uffs_text::case_fold::CaseFold;

    use crate::index_search::compile_parsed_pattern;
    use crate::pattern::ParsedPattern;

    let start = std::time::Instant::now();

    // Compile search pattern.
    let fold = CaseFold::default_table();
    let parsed = ParsedPattern::parse(pattern)
        .map_err(|err| AggregateError::InvalidConfig(format!("bad pattern: {err}")))?;
    let index_pat = compile_parsed_pattern(&parsed)
        .map_err(|err| AggregateError::InvalidConfig(format!("bad pattern: {err}")))?;
    tracing::info!(
        pattern,
        index_pattern = ?index_pat,
        "run_aggregate_filtered: compiled pattern"
    );

    // 1. Compile aggregation plan.
    let plan = AggregatePlan::compile(specs)?;

    // Build cross-drive extension mapping.
    let ext_map = ExtensionMap::build(drives);

    // 2. Drive-level parallel scan with inline pattern filter.  Inner record loop
    //    is sequential — see the rationale block in `run_aggregate` above.
    let index_pat_ref = &index_pat;
    let (merged, total_scanned, total_matched): (Vec<GroupAccumulator>, u64, u64) = drives
        .par_iter()
        .enumerate()
        .map(|(drive_ordinal, drive)| {
            let ordinal = u8::try_from(drive_ordinal).unwrap_or(u8::MAX);
            let mut local = plan.create_accumulators();
            let mut scanned: u64 = 0;
            let mut matched: u64 = 0;
            for (idx, record) in drive.records.iter().enumerate() {
                scanned += 1;
                let name = record.name(&drive.names);
                if name.is_empty() || !index_pat_ref.matches(name, false, fold) {
                    continue;
                }
                matched += 1;
                for acc in &mut local {
                    acc.feed(record, drive, idx, ordinal, &ext_map);
                }
            }
            (local, scanned, matched)
        })
        .reduce(
            || (plan.create_accumulators(), 0_u64, 0_u64),
            |(mut acc_a, sa, ma), (acc_b, sb, mb)| {
                merge_accumulator_sets(&mut acc_a, &acc_b);
                (acc_a, sa + sb, ma + mb)
            },
        );

    let scan_ms = start.elapsed().as_millis();
    let t_fin = std::time::Instant::now();

    // 3. Finalize.
    let response =
        finalize::finalize_with_ext_map(merged, &plan, drives, options, total_matched, &ext_map);
    tracing::info!(
        drives = drives.len(),
        records_scanned = total_scanned,
        records_matched = total_matched,
        scan_ms = u64::try_from(scan_ms).unwrap_or(u64::MAX),
        finalize_ms = u64::try_from(t_fin.elapsed().as_millis()).unwrap_or(u64::MAX),
        total_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
        "run_aggregate_filtered: done"
    );

    Ok(AggregateOutput {
        response,
        records_scanned: total_scanned,
        records_matched: total_matched,
        execution_us: start.elapsed().as_micros().try_into().unwrap_or(u64::MAX),
    })
}

/// Run aggregation with both pattern and record-level filters.
///
/// Combines the glob/regex pattern matching of `run_aggregate_filtered`
/// with the O(1) per-record checks from [`AggregateFilter`] (extension IDs,
/// directory flag, size bounds).  This is the entry point for MCP/daemon
/// aggregate queries that combine `pattern` + `type_filter` + `filter`.
///
/// When `filter.is_empty()` and pattern is `"*"`, this behaves identically
/// to [`run_aggregate`] (unfiltered).
///
/// # Errors
///
/// Returns an error if any spec references an invalid field or if
/// accumulator construction fails.
pub fn run_aggregate_with_filters(
    drives: &[&DriveCompactIndex],
    specs: &[AggregateSpec],
    options: &FinalizeOptions,
    pattern: Option<&str>,
    filter: &AggregateFilter,
) -> Result<AggregateOutput, AggregateError> {
    // Fast path: no filters and trivial pattern → unfiltered scan.
    use uffs_text::case_fold::CaseFold;

    use crate::index_search::compile_parsed_pattern;
    use crate::pattern::ParsedPattern;

    let trivial_pattern = pattern.is_none_or(|pat| matches!(pat, "*" | "**" | "**/*" | ""));
    if filter.is_empty() && trivial_pattern {
        return run_aggregate(drives, specs, options);
    }
    // Pattern-only → delegate to existing filtered path.
    if filter.is_empty() {
        if let Some(pat) = pattern {
            return run_aggregate_filtered(drives, specs, options, pat);
        }
        return run_aggregate(drives, specs, options);
    }

    let start = std::time::Instant::now();

    // Compile pattern (if non-trivial).
    let fold = CaseFold::default_table();
    let compiled_pattern = if trivial_pattern {
        None
    } else {
        let pat = pattern.unwrap_or("*");
        let parsed = ParsedPattern::parse(pat)
            .map_err(|err| AggregateError::InvalidConfig(format!("bad pattern: {err}")))?;
        Some(
            compile_parsed_pattern(&parsed)
                .map_err(|err| AggregateError::InvalidConfig(format!("bad pattern: {err}")))?,
        )
    };

    // 1. Compile aggregation plan.
    let plan = AggregatePlan::compile(specs)?;
    let ext_map = ExtensionMap::build(drives);

    // 2. Drive-level parallel scan with combined record-level + pattern filter.
    //    Inner record loop is sequential — see the rationale block in
    //    `run_aggregate` above.
    let compiled_pattern_ref = compiled_pattern.as_ref();
    let (merged, total_scanned, total_matched): (Vec<GroupAccumulator>, u64, u64) = drives
        .par_iter()
        .enumerate()
        .map(|(drive_ordinal, drive)| {
            let ordinal = u8::try_from(drive_ordinal).unwrap_or(u8::MAX);
            let mut local = plan.create_accumulators();
            let mut scanned: u64 = 0;
            let mut matched: u64 = 0;
            // Resolve extension names → per-drive u16 IDs (< 1µs).
            let resolved_ext_ids = drive.resolve_ext_ids(&filter.extensions);
            // An extension filter that resolves to NO interned IDs on this
            // drive can match nothing — `*.dll --count` on a drive with zero
            // `.dll` files must contribute 0, not fall through to an
            // unfiltered scan. (An empty resolution previously read as "no
            // extension filter", counting every record on the drive — found
            // live by the bench suite's count-vs-file-sink cross-check.)
            if !filter.extensions.is_empty() && resolved_ext_ids.is_empty() {
                return (local, 0, 0);
            }

            for (idx, record) in drive.records.iter().enumerate() {
                scanned += 1;

                // Record-level filter (O(1) — extension ID + directory flag + size).
                if !filter.matches(record, &resolved_ext_ids) {
                    continue;
                }

                // Pattern filter (if non-trivial).
                if let Some(pat) = compiled_pattern_ref {
                    let name = record.name(&drive.names);
                    if name.is_empty() || !pat.matches(name, false, fold) {
                        continue;
                    }
                }

                matched += 1;
                for acc in &mut local {
                    acc.feed(record, drive, idx, ordinal, &ext_map);
                }
            }
            (local, scanned, matched)
        })
        .reduce(
            || (plan.create_accumulators(), 0_u64, 0_u64),
            |(mut acc_a, sa, ma), (acc_b, sb, mb)| {
                merge_accumulator_sets(&mut acc_a, &acc_b);
                (acc_a, sa + sb, ma + mb)
            },
        );

    let scan_ms = start.elapsed().as_millis();
    let t_fin = std::time::Instant::now();

    // 3. Finalize.
    let response =
        finalize::finalize_with_ext_map(merged, &plan, drives, options, total_matched, &ext_map);
    tracing::info!(
        drives = drives.len(),
        records_scanned = total_scanned,
        records_matched = total_matched,
        has_pattern = compiled_pattern.is_some(),
        ext_count = filter.extensions.len(),
        dir_only = ?filter.directory_only,
        scan_ms = u64::try_from(scan_ms).unwrap_or(u64::MAX),
        finalize_ms = u64::try_from(t_fin.elapsed().as_millis()).unwrap_or(u64::MAX),
        total_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
        "run_aggregate_with_filters: done"
    );

    Ok(AggregateOutput {
        response,
        records_scanned: total_scanned,
        records_matched: total_matched,
        execution_us: start.elapsed().as_micros().try_into().unwrap_or(u64::MAX),
    })
}

/// Merge per-drive accumulator sets.
///
/// Pairs accumulators by index and calls [`GroupAccumulator::merge`]
/// on each pair.  Used by the outer `drives.par_iter().reduce(…)` in
/// every public entry point.  Every accumulator variant (including
/// `Terms` sample heaps and `Duplicates` groups) implements `merge`
/// correctly as of v0.5.40.
#[inline]
fn merge_accumulator_sets(into: &mut [GroupAccumulator], from: &[GroupAccumulator]) {
    for (left, right) in into.iter_mut().zip(from.iter()) {
        left.merge(right);
    }
}

/// Scan a single drive's records **sequentially**, feeding all
/// accumulators.
///
/// The drive loop in [`run_aggregate`] is parallel
/// (`drives.par_iter()`), so on a multi-drive host the N drives already
/// occupy N cores.  The per-record work here — `accumulator.feed` —
/// is only a handful of nanoseconds, which makes adding a second layer
/// of rayon parallelism a net loss under concurrent load (each nested
/// fold chunk clones the full `Vec<GroupAccumulator>` before having to
/// be reduced back together, and the rayon pool ends up oversubscribed
/// K×cores² with K concurrent queries).  See
/// `LOG/2026_04_18_08_09_CHANGELOG_HEALING.md` Run 7 for the
/// measurements that drove v0.5.43's revert from intra-drive rayon.
///
/// Returns `(accumulators, records_scanned, records_matched)`.
/// For unfiltered aggregation `matched == scanned == records.len()`.
fn scan_drive(
    drive: &DriveCompactIndex,
    plan: &AggregatePlan,
    drive_ordinal: u8,
    ext_map: &ExtensionMap,
) -> (Vec<GroupAccumulator>, u64, u64) {
    let records = &drive.records;
    let mut accumulators = plan.create_accumulators();
    for (idx, record) in records.iter().enumerate() {
        for acc in &mut accumulators {
            acc.feed(record, drive, idx, drive_ordinal, ext_map);
        }
    }
    let n = u64::try_from(records.len()).unwrap_or(u64::MAX);
    (accumulators, n, n)
}

/// Errors that can occur during aggregation.
///
/// `#[non_exhaustive]` is applied per Phase 5 §5c: future aggregation
/// failure modes (e.g. `OverflowedAccumulator { field, kind }` when
/// sum/avg accumulators saturate, or `IncompatibleSchemas` when
/// cross-drive aggregates encounter divergent column types) can be
/// added without breaking downstream exhaustive matchers.
/// Workspace-wide audit at PR-time confirmed all 10 `AggregateError::*`
/// references live inside `uffs-core` itself — zero external
/// exhaustive matches today (refs #192).
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum AggregateError {
    /// A spec referenced a field that doesn't support the requested operation.
    #[error("field `{field}` does not support {operation}")]
    UnsupportedField {
        /// The field name.
        field: String,
        /// The operation that was attempted.
        operation: String,
    },
    /// An invalid configuration was provided.
    #[error("invalid aggregate configuration: {0}")]
    InvalidConfig(String),
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::min_ident_chars,
    reason = "test code — relaxed for readability and fail-fast assertions"
)]
mod integration_tests;
