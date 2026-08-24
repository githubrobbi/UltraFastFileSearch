// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! The [`SearchParams`] → [`SearchFilters`] resolution, shared by the
//! search pipeline and the `warm_plan` RPC.
//!
//! Factored out of `run_search_over` so the promote-plan the daemon
//! reports to external gates (`warm_plan`, consumed by the MCP
//! cold-index gate) is derived through the *same* filter resolution
//! the search itself will use — most importantly the resolved
//! extension-term set that drives the Phase 4 bloom pre-check.  Two
//! copies of this mapping would eventually disagree on exactly the
//! field the bloom contract depends on.

use uffs_client::protocol::SearchParams;
use uffs_core::search::filters::{SearchFilterParams, SearchFilters};

/// Resolve a search's record/display filter set from its (already
/// canonicalised) wire params.  Pure parameter mapping: predicates
/// compilation, diff-mode overlays, and other pipeline-stage mutations
/// stay with the caller.
pub(super) fn build_search_filters(ep: &SearchParams) -> SearchFilters {
    let mut filters = SearchFilters::from_params(&SearchFilterParams {
        hide_system: ep.hide_system,
        hide_ads: ep.hide_ads,
        min_size: ep.min_size,
        max_size: ep.max_size,
        min_descendants: ep.min_descendants,
        max_descendants: ep.max_descendants,
        newer: ep.newer.as_deref(),
        older: ep.older.as_deref(),
        newer_created: ep.newer_created.as_deref(),
        older_created: ep.older_created.as_deref(),
        newer_accessed: ep.newer_accessed.as_deref(),
        older_accessed: ep.older_accessed.as_deref(),
        attr_filter: ep.attr.as_deref(),
        ext_filter: ep.ext.as_deref(),
        exclude: ep.exclude.as_deref(),
        path_contains: ep.path_contains.as_deref(),
        path_excludes: ep.path_excludes.as_deref(),
        type_filter: ep.type_filter.as_deref(),
        min_bulkiness: ep.min_bulkiness,
        max_bulkiness: ep.max_bulkiness,
        min_name_len: ep.min_name_len,
        max_name_len: ep.max_name_len,
        min_path_len: ep.min_path_len,
        max_path_len: ep.max_path_len,
        min_allocated: ep.min_allocated,
        max_allocated: ep.max_allocated,
        min_treesize: ep.min_treesize,
        max_treesize: ep.max_treesize,
        min_tree_allocated: ep.min_tree_allocated,
        max_tree_allocated: ep.max_tree_allocated,
        allowed_months: &ep.allowed_months,
    });
    // Display-only: select the malformed-name render mode for resolved
    // paths + the name column (`--normalize-malformed`).
    filters.normalize_malformed = ep.normalize_malformed;
    filters
}
