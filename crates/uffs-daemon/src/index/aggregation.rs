// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.
//! Exception: `file_size_policy` — aggregation dispatch, tightly coupled
//! helpers.

// Aggregation handler bridges wire protocol to core aggregate engine.
// Same statistical patterns as uffs-core::aggregate apply here.
#![allow(
    clippy::min_ident_chars,
    clippy::too_many_lines,
    clippy::shadow_reuse,
    clippy::redundant_closure_for_method_calls,
    clippy::option_if_let_else,
    clippy::bool_to_int_with_if,
    clippy::manual_let_else,
    clippy::clone_on_ref_ptr,
    clippy::assigning_clones,
    clippy::single_match_else,
    reason = "aggregation handler: statistical patterns, wire↔core mapping"
)]

//! Aggregation execution: convert wire specs to core specs and run them.

use uffs_client::protocol::{DrilldownWire, SampleRowWire};
use uffs_core::aggregate::finalize::{DrilldownPredicate, DrilldownValue, SampleRow};
use uffs_core::aggregate::spec::DuplicateVerify;
use uffs_core::aggregate::verify::{DuplicateVerifier, FileReader, VerificationBudget};
use uffs_core::search::backend::DriveIndex;

use super::IndexManager;

// ── Daemon file reader for duplicate verification ───────────────────

/// File reader that resolves `(record_idx, drive_ordinal)` to a file path
/// via the compact index, then reads bytes from disk.
///
/// Only functional on Windows where the resolved paths (e.g. `C:\Users\...`)
/// point to real files. On macOS/Linux (offline mode), reads always fail
/// gracefully — verification is skipped and groups remain unverified.
struct DaemonFileReader<'a> {
    /// Loaded drive indices for path resolution.
    drives: &'a [alloc::sync::Arc<uffs_core::compact::DriveCompactIndex>],
}

impl DaemonFileReader<'_> {
    /// Resolve a record to its full file path.
    fn resolve_path(&self, record_idx: usize, drive_ordinal: u8) -> Option<String> {
        let drive = self.drives.get(usize::from(drive_ordinal))?;
        let volume_prefix = format!("{}:\\", drive.letter);
        Some(uffs_core::search::tree::resolve_path(
            drive,
            record_idx,
            &volume_prefix,
            uffs_core::compact::MalformedRender::Lossy,
        ))
    }
}

impl FileReader for DaemonFileReader<'_> {
    fn read_first_bytes(
        &self,
        record_idx: usize,
        drive_ordinal: u8,
        count: u32,
    ) -> std::io::Result<Vec<u8>> {
        use std::io::Read as _;
        let path = self
            .resolve_path(record_idx, drive_ordinal)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "drive ordinal out of range")
            })?;
        let mut file = std::fs::File::open(&path)?;
        let mut buf = vec![0_u8; uffs_mft::u32_as_usize(count)];
        let n = file.read(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn read_all(&self, record_idx: usize, drive_ordinal: u8) -> std::io::Result<Vec<u8>> {
        let path = self
            .resolve_path(record_idx, drive_ordinal)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "drive ordinal out of range")
            })?;
        std::fs::read(&path)
    }
}

/// Default verification budget: 256 MB total, 10 000 files max.
const DEFAULT_VERIFY_BUDGET_BYTES: u64 = 256 * 1024 * 1024;
/// Default max files for verification budget.
const DEFAULT_VERIFY_BUDGET_FILES: u32 = 10_000;

/// Convert a core [`SampleRow`] to a wire [`SampleRowWire`].
fn sample_row_to_wire(sr: SampleRow) -> SampleRowWire {
    SampleRowWire {
        fields: sr.fields.into_iter().collect(),
        sort_key: Some(sr.sort_key),
    }
}

/// Format bytes as compact human-readable size (e.g. `1.3 MB`).
#[expect(
    clippy::float_arithmetic,
    reason = "float division required for human-readable size formatting"
)]
fn format_size_compact(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;
    let bytes_f64 = uffs_mft::u64_to_f64(bytes);
    if bytes >= TB {
        format!("{:.2} TB", bytes_f64 / uffs_mft::u64_to_f64(TB))
    } else if bytes >= GB {
        format!("{:.2} GB", bytes_f64 / uffs_mft::u64_to_f64(GB))
    } else if bytes >= MB {
        format!("{:.1} MB", bytes_f64 / uffs_mft::u64_to_f64(MB))
    } else if bytes >= KB {
        format!("{:.1} KB", bytes_f64 / uffs_mft::u64_to_f64(KB))
    } else {
        format!("{bytes} B")
    }
}

/// Materialize duplicate group member indices into wire sample rows.
///
/// For each `(record_idx, drive_ordinal)`, resolve the record name, path,
/// and size from the compact index.
fn materialize_dup_members(
    members: &[(usize, u8)],
    drives: &[&uffs_core::compact::DriveCompactIndex],
) -> Vec<SampleRowWire> {
    members
        .iter()
        .filter_map(|&(rec_idx, drive_ord)| {
            let drive = drives.get(usize::from(drive_ord))?;
            let record = drive.records.get(rec_idx)?;
            let name = record.name(&drive.names).to_owned();
            let volume_prefix = format!("{}:\\", drive.letter);
            let path = uffs_core::search::tree::resolve_path(
                drive,
                rec_idx,
                &volume_prefix,
                uffs_core::compact::MalformedRender::Lossy,
            );

            let mut fields = std::collections::HashMap::new();
            fields.insert("name".to_owned(), name);
            fields.insert("path".to_owned(), path);
            fields.insert("size".to_owned(), record.size.to_string());

            Some(SampleRowWire {
                fields,
                sort_key: Some(record.size.cast_signed()),
            })
        })
        .collect()
}

/// Convert a core [`DrilldownPredicate`] to a wire [`DrilldownWire`].
fn drilldown_to_wire(dp: DrilldownPredicate) -> DrilldownWire {
    let value = match dp.value {
        DrilldownValue::String(s) => serde_json::Value::String(s),
        DrilldownValue::U64(n) => serde_json::Value::Number(n.into()),
        DrilldownValue::I64(n) => serde_json::Value::Number(n.into()),
        DrilldownValue::Bool(b) => serde_json::Value::Bool(b),
    };
    DrilldownWire {
        field: dp.field,
        op: dp.op,
        value,
    }
}

/// Cache lookup state shared between [`IndexManager::run_aggregations`]
/// and its helpers.
///
/// Pairs the request-specific cache key with the (optional) cache
/// instance so callers can pass a single bundle instead of two
/// always-correlated parameters.  `key_hash == None` means caching
/// was disabled for this call, regardless of whether `cache` is
/// `Some`.
#[derive(Clone, Copy)]
struct AggregateCacheCtx<'a> {
    /// Pre-computed `build_agg_cache_key` digest, or `None` when
    /// caching is disabled (the caller passed `cache: None`).
    key_hash: Option<u64>,
    /// Shared cache instance, when one is configured.
    cache: Option<&'a uffs_core::aggregate::AggregateCache>,
}

/// Bundled inputs for [`IndexManager::run_aggregations`].
///
/// Wraps the predicates, pagination knobs, and scope filters that
/// would otherwise blow past clippy's `too_many_arguments` budget,
/// and gives tests a clean builder-style call site:
///
/// ```ignore
/// IndexManager::run_aggregations(
///     &snapshot,
///     None,
///     &specs,
///     AggregationRequest::default(),
/// );
/// ```
///
/// All fields are optional / default-friendly so callers only set the
/// knobs they care about.  Production callers populate everything;
/// most unit tests need only the defaults.
#[derive(Default)]
pub(crate) struct AggregationRequest<'a> {
    /// Drill-down predicates from the search-scope `where` clause,
    /// forwarded into `FinalizeOptions` so each bucket's drilldown
    /// reflects the original query.
    pub query_predicates: Vec<DrilldownPredicate>,
    /// Opaque pagination cursor encoded as
    /// `result_index:offset:page_size`.  `None` requests the first
    /// page (or no pagination at all when `agg_page_size` is also
    /// `None`).
    pub agg_cursor: Option<&'a str>,
    /// Page size for fresh paginated requests (`None` = no
    /// pagination, return all buckets).
    pub agg_page_size: Option<u16>,
    /// Glob / regex name matcher applied during the scan.  `None`
    /// disables name matching.
    pub pattern: Option<&'a str>,
    /// Subset of drive letters to include; empty = all drives.
    pub drives_filter: &'a [uffs_mft::platform::DriveLetter],
    /// O(1)-per-record predicates: extension IDs, directory flag,
    /// size bounds.  Defaults to "no filter" via
    /// [`uffs_core::aggregate::AggregateFilter::default`].
    pub record_filter: uffs_core::aggregate::AggregateFilter,
}

impl IndexManager {
    /// Run aggregation specs from wire format against loaded drives.
    ///
    /// All scope inputs (predicates, pagination, pattern, drive
    /// filter, record filter) are bundled into [`AggregationRequest`]
    /// so the call site stays readable and the function signature
    /// stays under clippy's `too_many_arguments` budget.
    ///
    /// `request.pattern` applies glob/regex name matching;
    /// `request.record_filter` applies O(1)-per-record constraints
    /// (extension IDs, directory flag, size bounds).  Both are
    /// optional and compose: a record must pass *both* to be fed to
    /// accumulators.
    pub(crate) fn run_aggregations(
        snapshot: &DriveIndex,
        cache: Option<&uffs_core::aggregate::AggregateCache>,
        wire_specs: &[uffs_client::protocol::AggregateSpecWire],
        request: AggregationRequest<'_>,
    ) -> (Vec<uffs_client::protocol::AggregateResultWire>, u64) {
        use uffs_core::aggregate::finalize::FinalizeOptions;
        use uffs_core::aggregate::spec::AggregateSpec;

        let AggregationRequest {
            query_predicates,
            agg_cursor,
            agg_page_size,
            pattern,
            drives_filter,
            record_filter,
        } = request;

        // Convert wire specs to core specs.
        let mut specs: Vec<AggregateSpec> = Vec::new();
        for ws in wire_specs {
            match Self::convert_wire_spec(ws) {
                Ok(converted) => specs.extend(converted),
                Err(e) => {
                    tracing::warn!(kind = %ws.kind, "skipping malformed aggregate spec: {e}");
                }
            }
        }

        if specs.is_empty() {
            return (vec![], 0);
        }

        // Apply drive filter: if non-empty, only include matching drives.
        let drive_refs: Vec<&uffs_core::compact::DriveCompactIndex> = snapshot
            .drives
            .iter()
            .filter(|arc| drives_filter.is_empty() || drives_filter.contains(&arc.letter))
            .map(|arc| arc.as_ref())
            .collect();
        // ── Cache lookup ────────────────────────────────────────────
        //
        // The cache key mixes every input that can change the
        // computed `AggregateOutput` (core scan + merge + duplicate
        // verification).  Pagination inputs (`agg_cursor`,
        // `agg_page_size`) and wire-conversion details are excluded
        // because they're applied *after* the cached step.
        //
        // Build the key before consuming `query_predicates` below so
        // the predicates are still available by reference.
        let cache_key_hash = cache.map(|_| {
            Self::build_agg_cache_key(
                &specs,
                pattern,
                drives_filter,
                &record_filter,
                &query_predicates,
            )
        });

        let options = FinalizeOptions {
            query_predicates,
            ..FinalizeOptions::default()
        };

        tracing::info!(
            pattern = ?pattern,
            ext_count = record_filter.extensions.len(),
            dir_only = ?record_filter.directory_only,
            cache_key = cache_key_hash.unwrap_or(0),
            cached = cache_key_hash.is_some(),
            "running aggregation"
        );

        let output = match Self::compute_aggregate_output(
            AggregateCacheCtx {
                key_hash: cache_key_hash,
                cache,
            },
            &drive_refs,
            &specs,
            &options,
            pattern,
            &record_filter,
            &snapshot.drives,
        ) {
            Some(out) => out,
            None => return (vec![], 0),
        };

        // Note: duplicate verification already ran on the miss path
        // before the result was cached, so cache hits return
        // verified results for free.  Running `run_duplicate_verification`
        // a second time here would re-read every member file from disk
        // (the verifier has no "already verified" short-circuit), so
        // we deliberately skip it.
        let records_matched = output.records_matched;
        let wire_results = convert_aggregate_results_to_wire(
            output.response.results,
            agg_cursor,
            agg_page_size,
            &snapshot.drives,
        );
        (wire_results, records_matched)
    }

    /// Look up the cached `AggregateOutput` if present, otherwise run
    /// the core aggregation with duplicate verification + cache fill.
    ///
    /// Returns `None` on a hard error from the core aggregation
    /// engine; the orchestrator surfaces this to the caller as an
    /// empty `(vec![], 0)` response.
    fn compute_aggregate_output(
        cache_ctx: AggregateCacheCtx<'_>,
        drive_refs: &[&uffs_core::compact::DriveCompactIndex],
        specs: &[uffs_core::aggregate::spec::AggregateSpec],
        options: &uffs_core::aggregate::finalize::FinalizeOptions,
        pattern: Option<&str>,
        record_filter: &uffs_core::aggregate::AggregateFilter,
        drives: &[alloc::sync::Arc<uffs_core::compact::DriveCompactIndex>],
    ) -> Option<uffs_core::aggregate::AggregateOutput> {
        let AggregateCacheCtx { key_hash, cache } = cache_ctx;
        if let Some(hit) = key_hash.and_then(|k| cache.and_then(|c| c.get(k))) {
            tracing::debug!(
                scanned = hit.records_scanned,
                matched = hit.records_matched,
                "aggregation cache hit"
            );
            return Some(hit);
        }

        match uffs_core::aggregate::run_aggregate_with_filters(
            drive_refs,
            specs,
            options,
            pattern,
            record_filter,
        ) {
            Ok(mut fresh) => {
                tracing::info!(
                    scanned = fresh.records_scanned,
                    matched = fresh.records_matched,
                    "aggregation complete"
                );
                // Duplicate verification is part of the cacheable
                // result: its effect lives in `fresh.response`, so
                // run it *before* populating the cache so future
                // hits include verification state.
                Self::run_duplicate_verification(specs, &mut fresh, drives);
                if let (Some(k), Some(c)) = (key_hash, cache) {
                    c.put(k, fresh.clone());
                }
                Some(fresh)
            }
            Err(e) => {
                tracing::error!(error = %e, "aggregation failed");
                None
            }
        }
    }

    /// Build a deterministic `u64` cache key for an aggregate request.
    ///
    /// The key mixes every input that can change the computed
    /// [`uffs_core::aggregate::AggregateOutput`]:
    /// - `specs` — the compiled list of
    ///   [`uffs_core::aggregate::AggregateSpec`]s, including every `kind`,
    ///   `label`, `top`, sample spec, and rollup field.
    /// - `pattern` — glob/regex name matcher (`None` vs. `Some("")` are
    ///   distinguished by `Option::hash`).
    /// - `drives_filter` — the set of drive letters to scope the scan.
    /// - `record_filter` — extensions, directory flag, size bounds.
    /// - `query_predicates` — drill-down predicates forwarded to
    ///   `FinalizeOptions` so bucket drilldowns reflect the original query
    ///   scope.
    ///
    /// Excludes pagination (`agg_cursor`, `agg_page_size`) and
    /// wire-conversion knobs; those are applied *after* the cached
    /// step, so they don't affect the cached `AggregateOutput`.
    ///
    /// Implementation: feeds each input into a single `DefaultHasher`
    /// via the standard [`Hash`] trait.  All participating types
    /// derive `Hash` in `uffs-core`, so the digest is a direct
    /// structural fingerprint — no `Debug` round-trip, no string
    /// allocation.  Stable across daemon restarts of the same build;
    /// hash-seed randomization only matters across processes, which
    /// is aligned with cache lifetime.
    fn build_agg_cache_key(
        specs: &[uffs_core::aggregate::spec::AggregateSpec],
        pattern: Option<&str>,
        drives_filter: &[uffs_mft::platform::DriveLetter],
        record_filter: &uffs_core::aggregate::AggregateFilter,
        query_predicates: &[DrilldownPredicate],
    ) -> u64 {
        use core::hash::{Hash as _, Hasher as _};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        // Each field is hashed with an implicit domain separator:
        // slices and `Option` write their length / discriminant
        // before their contents, so `("ab", "c")` and `("a", "bc")`
        // cannot collide.
        specs.hash(&mut hasher);
        pattern.hash(&mut hasher);
        drives_filter.hash(&mut hasher);
        record_filter.hash(&mut hasher);
        query_predicates.hash(&mut hasher);
        hasher.finish()
    }

    /// Convert a single wire spec into one or more core `AggregateSpec`s.
    ///
    /// Run duplicate verification on any `Duplicates` result that has
    /// `verify != None`.
    ///
    /// Extracts the verify mode from the original specs, builds a
    /// [`DaemonFileReader`], and calls [`DuplicateVerifier::verify`].
    /// Results are mutated in place.
    fn run_duplicate_verification(
        specs: &[uffs_core::aggregate::spec::AggregateSpec],
        output: &mut uffs_core::aggregate::AggregateOutput,
        drives: &[alloc::sync::Arc<uffs_core::compact::DriveCompactIndex>],
    ) {
        use uffs_core::aggregate::finalize::AggregateResultData;
        use uffs_core::aggregate::spec::AggregateKind;

        // Collect verify modes from specs (parallel to results).
        let verify_modes: Vec<DuplicateVerify> = specs
            .iter()
            .map(|s| match &s.kind {
                AggregateKind::Duplicates { verify, .. } => *verify,
                AggregateKind::Count
                | AggregateKind::Stats { .. }
                | AggregateKind::Terms { .. }
                | AggregateKind::Histogram { .. }
                | AggregateKind::DateHistogram { .. }
                | AggregateKind::Range { .. }
                | AggregateKind::Missing { .. }
                | AggregateKind::Distinct { .. }
                | AggregateKind::Rollup { .. } => DuplicateVerify::None,
            })
            .collect();

        // Short-circuit: no verification needed.
        if verify_modes
            .iter()
            .all(|m| matches!(m, DuplicateVerify::None))
        {
            return;
        }

        let reader = DaemonFileReader { drives };
        let budget =
            VerificationBudget::new(DEFAULT_VERIFY_BUDGET_BYTES, DEFAULT_VERIFY_BUDGET_FILES);

        // Walk results in parallel with specs. Each result corresponds to a
        // spec at the same index.
        for (result, mode) in output.response.results.iter_mut().zip(verify_modes.iter()) {
            if matches!(mode, DuplicateVerify::None) {
                continue;
            }
            if let AggregateResultData::Duplicates { result: dup_result } = &mut result.data {
                let mut verifier = DuplicateVerifier::new(*mode, budget);
                // Move current result out, verify, and put it back.
                let placeholder = uffs_core::aggregate::duplicates::DuplicateResult {
                    candidate_groups: 0,
                    candidate_files: 0,
                    total_duplicate_bytes: 0,
                    total_reclaimable_bytes: 0,
                    groups: Vec::new(),
                    verification_mode: DuplicateVerify::None,
                };
                let current = core::mem::replace(dup_result, placeholder);
                let (vfy_result, summary) = verifier.verify(current, &reader);
                *dup_result = vfy_result;

                tracing::info!(
                    mode = ?mode,
                    groups_verified = summary.groups_verified,
                    groups_rejected = summary.groups_rejected,
                    groups_skipped = summary.groups_skipped,
                    groups_errored = summary.groups_errored,
                    bytes_read = summary.bytes_read,
                    budget_exhausted = summary.budget_exhausted,
                    "duplicate verification complete"
                );
            }
        }
    }
}

// `IndexManager::convert_wire_spec` lives in `wire_spec.rs` so the
// runtime aggregation path (`run_aggregations` + verifier glue above)
// stays decoupled from the wire-protocol decoder.

// ── Wire conversion ─────────────────────────────────────────────────
//
// Splits the per-`AggregateResult` mapping out of `run_aggregations`
// so the orchestrator stays under clippy's cognitive-complexity bar.
// Each `AggregateResultData` arm gets its own `wire_*` helper that
// returns the 9-tuple consumed by `apply_pagination_and_finalize`.

/// Convert a fully-resolved [`uffs_core::aggregate::AggregateOutput`]'s results
/// into the wire format expected by clients, applying cursor-based
/// pagination per result-index.
fn convert_aggregate_results_to_wire(
    results: Vec<uffs_core::aggregate::finalize::AggregateResult>,
    agg_cursor: Option<&str>,
    agg_page_size: Option<u16>,
    drives: &[alloc::sync::Arc<uffs_core::compact::DriveCompactIndex>],
) -> Vec<uffs_client::protocol::AggregateResultWire> {
    use uffs_core::aggregate::pagination::{AggregateCursor, paginate_result};

    let decoded_cursor = agg_cursor.and_then(AggregateCursor::decode);
    let page_size = decoded_cursor
        .as_ref()
        .map(|c| c.page_size)
        .or_else(|| agg_page_size.map(usize::from));

    results
        .into_iter()
        .enumerate()
        .map(|(idx, result)| {
            let pagination = page_size.and_then(|ps| {
                let cursor = decoded_cursor
                    .as_ref()
                    .filter(|c| c.result_index == idx)
                    .cloned()
                    .unwrap_or_else(|| AggregateCursor::new(idx, ps));
                paginate_result(&result, &cursor)
            });
            build_aggregate_result_wire(result, pagination.as_ref(), drives)
        })
        .collect()
}

/// Build the [`uffs_client::protocol::aggregate_wire::AggregateResultWire`] for
/// a single result, dispatching to one of the per-kind `wire_*` helpers and
/// applying pagination.
fn build_aggregate_result_wire(
    result: uffs_core::aggregate::finalize::AggregateResult,
    pagination: Option<&uffs_core::aggregate::pagination::PaginatedBuckets>,
    drives: &[alloc::sync::Arc<uffs_core::compact::DriveCompactIndex>],
) -> uffs_client::protocol::AggregateResultWire {
    use uffs_client::protocol::AggregateResultWire;
    use uffs_core::aggregate::finalize::AggregateResultData;

    let label = result.label.clone();
    let (kind, field, value, stats, buckets, other_count, total_groups, exact, values_complete) =
        match result.data {
            AggregateResultData::Count { value } => wire_count(value),
            AggregateResultData::Stats { field, stats } => wire_stats(field, &stats),
            AggregateResultData::Buckets {
                field,
                rows,
                other_count,
                total_groups,
                exact,
            } => wire_buckets(field, rows, other_count, total_groups, exact),
            AggregateResultData::Missing { field, count } => wire_missing(field, count),
            AggregateResultData::Distinct { field, count } => wire_distinct(field, count),
            AggregateResultData::Rollup { mode, rows } => wire_rollup(mode, rows),
            AggregateResultData::Duplicates { result } => wire_duplicates(result, drives),
        };

    // Apply pagination: replace full bucket list with the current page
    // and attach `next_cursor` for the caller.
    let (buckets, next_cursor) = if let Some(pg) = pagination {
        let start = pg.offset.min(buckets.len());
        let end = (start + pg.rows.len()).min(buckets.len());
        let page = buckets.get(start..end).map_or_else(Vec::new, <[_]>::to_vec);
        (page, pg.next_cursor.clone())
    } else {
        (buckets, None)
    };

    AggregateResultWire {
        label,
        kind,
        field,
        value,
        stats,
        buckets,
        other_count,
        total_groups,
        next_cursor,
        exact,
        values_complete,
    }
}

/// Tuple type returned by every `wire_*` arm helper.
///
/// Order mirrors the destructured pattern in
/// [`build_aggregate_result_wire`]: `kind`, `field`, `value`, `stats`,
/// `buckets`, `other_count`, `total_groups`, `exact`,
/// `values_complete`.
type AggregateWireTuple = (
    String,
    Option<String>,
    Option<u64>,
    Option<uffs_client::protocol::StatsWire>,
    Vec<uffs_client::protocol::BucketWire>,
    Option<u64>,
    Option<usize>,
    Option<bool>,
    Option<bool>,
);

/// Wire builder for
/// [`uffs_core::aggregate::finalize::AggregateResultData::Count`].
fn wire_count(value: u64) -> AggregateWireTuple {
    (
        "count".to_owned(),
        None,
        Some(value),
        None,
        vec![],
        None,
        None,
        None,
        None,
    )
}

/// Wire builder for
/// [`uffs_core::aggregate::finalize::AggregateResultData::Stats`].
fn wire_stats(
    field: String,
    stats: &uffs_core::aggregate::finalize::StatsResult,
) -> AggregateWireTuple {
    use uffs_client::protocol::StatsWire;
    (
        "stats".to_owned(),
        Some(field),
        None,
        Some(StatsWire {
            count: stats.count,
            sum: stats.sum,
            min: stats.min,
            max: stats.max,
            avg: stats.avg,
            waste_bytes: stats.waste_bytes,
            waste_pct: stats.waste_pct,
        }),
        vec![],
        None,
        None,
        None,
        None,
    )
}

/// Wire builder for
/// [`uffs_core::aggregate::finalize::AggregateResultData::Buckets`].
fn wire_buckets(
    field: String,
    rows: Vec<uffs_core::aggregate::finalize::BucketRow>,
    other_count: u64,
    total_groups: usize,
    exact: bool,
) -> AggregateWireTuple {
    use uffs_client::protocol::BucketWire;

    let buckets = rows
        .into_iter()
        .map(|r| {
            let samples = r.sample_rows.into_iter().map(sample_row_to_wire).collect();
            let drills = r.drilldown.into_iter().map(drilldown_to_wire).collect();
            BucketWire {
                key: r.key,
                count: r.count,
                total_bytes: r.total_bytes,
                total_allocated: Some(r.total_allocated),
                avg_size: Some(r.avg_size),
                share_count: Some(r.share_of_total_count),
                share_bytes: Some(r.share_of_total_bytes),
                sample_rows: samples,
                drilldown: drills,
                sub_buckets: Vec::new(),
                verified: false,
            }
        })
        .collect();
    (
        "buckets".to_owned(),
        Some(field),
        None,
        None,
        buckets,
        Some(other_count),
        Some(total_groups),
        Some(exact),
        Some(other_count == 0),
    )
}

/// Wire builder for
/// [`uffs_core::aggregate::finalize::AggregateResultData::Missing`].
fn wire_missing(field: String, count: u64) -> AggregateWireTuple {
    (
        "missing".to_owned(),
        Some(field),
        Some(count),
        None,
        vec![],
        None,
        None,
        None,
        None,
    )
}

/// Wire builder for
/// [`uffs_core::aggregate::finalize::AggregateResultData::Distinct`].
fn wire_distinct(field: String, count: u64) -> AggregateWireTuple {
    (
        "distinct".to_owned(),
        Some(field),
        Some(count),
        None,
        vec![],
        None,
        None,
        None,
        None,
    )
}

/// Wire builder for
/// [`uffs_core::aggregate::finalize::AggregateResultData::Rollup`].
fn wire_rollup(
    mode: String,
    rows: Vec<uffs_core::aggregate::finalize::BucketRow>,
) -> AggregateWireTuple {
    use uffs_client::protocol::BucketWire;

    let buckets = rows
        .into_iter()
        .map(|r| {
            let samples = r.sample_rows.into_iter().map(sample_row_to_wire).collect();
            let drills = r.drilldown.into_iter().map(drilldown_to_wire).collect();
            let subs = r
                .sub_buckets
                .into_iter()
                .map(|sub| BucketWire {
                    key: sub.key,
                    count: sub.count,
                    total_bytes: sub.total_bytes,
                    total_allocated: Some(sub.total_allocated),
                    avg_size: Some(sub.avg_size),
                    share_count: Some(sub.share_of_total_count),
                    share_bytes: Some(sub.share_of_total_bytes),
                    sample_rows: Vec::new(),
                    drilldown: Vec::new(),
                    sub_buckets: Vec::new(),
                    verified: false,
                })
                .collect();
            BucketWire {
                key: r.key,
                count: r.count,
                total_bytes: r.total_bytes,
                total_allocated: Some(r.total_allocated),
                avg_size: Some(r.avg_size),
                share_count: Some(r.share_of_total_count),
                share_bytes: Some(r.share_of_total_bytes),
                sample_rows: samples,
                drilldown: drills,
                sub_buckets: subs,
                verified: false,
            }
        })
        .collect();
    (
        "rollup".to_owned(),
        Some(mode),
        None,
        None,
        buckets,
        None,
        None,
        Some(true),
        None,
    )
}

/// Wire builder for
/// [`uffs_core::aggregate::finalize::AggregateResultData::Duplicates`].
///
/// Materialises sample rows from the daemon-side compact index, then
/// builds a summary [`uffs_client::protocol::aggregate_wire::StatsWire`]
/// mirroring the verifier's view of the duplicate set.
#[expect(
    clippy::float_arithmetic,
    reason = "percentage calculation for waste_pct"
)]
fn wire_duplicates(
    result: uffs_core::aggregate::DuplicateResult,
    drives: &[alloc::sync::Arc<uffs_core::compact::DriveCompactIndex>],
) -> AggregateWireTuple {
    use uffs_client::protocol::{BucketWire, StatsWire};

    let total_groups = result.candidate_groups;
    let total_reclaimable = result.total_reclaimable_bytes;
    let dup_drive_refs: Vec<&uffs_core::compact::DriveCompactIndex> =
        drives.iter().map(|d| d.as_ref()).collect();
    let buckets: Vec<BucketWire> = result
        .groups
        .into_iter()
        .map(|g| {
            // Materialize sample rows from member_indices.
            let samples: Vec<SampleRowWire> =
                materialize_dup_members(&g.member_indices, &dup_drive_refs);
            // Derive human-readable key from first sample row's name field,
            // falling back to file size.
            let display_name = samples
                .first()
                .and_then(|s| s.fields.get("name").cloned())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| format_size_compact(g.file_size));
            let key = format!(
                "{} ({}, {} copies)",
                display_name,
                format_size_compact(g.file_size),
                g.count,
            );
            BucketWire {
                key,
                count: g.count,
                total_bytes: g.total_bytes,
                total_allocated: Some(g.reclaimable_bytes),
                avg_size: Some(uffs_mft::u64_to_f64(g.file_size)),
                share_count: None,
                share_bytes: None,
                sample_rows: samples,
                drilldown: Vec::new(),
                sub_buckets: Vec::new(),
                verified: g.verified,
            }
        })
        .collect();

    // Build stats with summary: total reclaimable in waste_bytes,
    // total candidate files in count.
    let summary = StatsWire {
        count: result.candidate_files,
        sum: result.total_duplicate_bytes,
        min: 0,
        max: 0,
        avg: 0.0,
        waste_bytes: total_reclaimable,
        waste_pct: if result.total_duplicate_bytes > 0 {
            (uffs_mft::u64_to_f64(total_reclaimable)
                / uffs_mft::u64_to_f64(result.total_duplicate_bytes))
                * 100.0
        } else {
            0.0
        },
    };

    (
        "duplicates".to_owned(),
        None,
        Some(result.candidate_files),
        Some(summary),
        buckets,
        None,
        Some(total_groups),
        None,
        None,
    )
}
