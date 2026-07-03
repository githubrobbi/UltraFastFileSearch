// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `uffs_facet_values` tool — search within facet values for a field.

use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::Deserialize;
use uffs_client::connect::UffsClient;
use uffs_client::protocol::{AggregateSpecWire, SearchParams};

use crate::error::BridgeError;
use crate::roots::{self, RootsState};
use crate::text::{format_aggregate_summary, format_scan_header};

/// Input parameters for the `uffs_facet_values` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct FacetValuesArgs {
    /// Field to facet on (e.g. `extension`, `type`, `drive`).
    pub field: String,
    /// Search pattern to scope facet (default: `*`).
    #[serde(default = "default_pattern")]
    pub pattern: String,
    /// Filter facet values by prefix.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Number of facet values to return (default: 20).
    #[serde(default = "default_top")]
    pub top: u16,
    /// Filter: `all`, `files`, `dirs`.
    #[serde(default)]
    pub filter: Option<String>,
    /// File type category (e.g. `"code"`, `"document"`, `"picture"`,
    /// `"video"`, `"audio"`, `"executable"`, `"system"`).
    #[serde(default)]
    pub type_filter: Option<String>,
    /// Opaque cursor from a previous response for pagination.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Max buckets per page (enables pagination).
    #[serde(default)]
    pub page_size: Option<u16>,
}

/// Default pattern.
fn default_pattern() -> String {
    "*".to_owned()
}

/// Default top-N count.
const fn default_top() -> u16 {
    20
}

/// Execute the facet values tool.
///
/// # Errors
///
/// Returns [`BridgeError`] if the daemon call fails.
pub(crate) async fn run(
    client: &mut UffsClient,
    args: FacetValuesArgs,
    roots_state: &RootsState,
) -> Result<CallToolResult, BridgeError> {
    // When prefix-filtering, request more buckets since we'll filter
    // client-side and need enough candidates.
    let request_top = if args.prefix.is_some() {
        args.top.saturating_mul(5).max(200)
    } else {
        args.top
    };

    let agg_spec = AggregateSpecWire {
        kind: "terms".to_owned(),
        label: Some(format!("facet_{}", args.field)),
        field: Some(args.field.clone()),
        top: Some(request_top),
        interval: None,
        calendar: None,
        boundaries: vec![],
        metrics: vec!["count".to_owned(), "total_bytes".to_owned()],
        preset: None,
        sample: None,
        sample_sort: None,
        sample_desc: None,
        verify: None,
        verify_bytes: None,
    };

    let mut params = SearchParams {
        pattern: args.pattern,
        aggregations: vec![agg_spec],
        include_rows: false,
        limit: Some(1), // See aggregate.rs — prevents 25M row collection.
        filter: args.filter,
        type_filter: args.type_filter,
        agg_cursor: args.cursor,
        agg_page_size: args.page_size,
        ..Default::default()
    };

    // Apply roots-based scoping (drive + path prefix).
    roots::apply_roots_scope(roots_state, &mut params);

    let mut response = client
        .search(&params)
        .await
        .map_err(|err| BridgeError::Daemon(format!("Facet values failed: {err}")))?;

    // Apply prefix filter to aggregation buckets.
    if let Some(prefix) = &args.prefix {
        let prefix_lower = prefix.to_ascii_lowercase();
        let limit = usize::from(args.top);
        for agg in &mut response.aggregations {
            agg.buckets
                .retain(|bkt| bkt.key.to_ascii_lowercase().starts_with(&prefix_lower));
            agg.buckets.truncate(limit);
        }
    }

    let summary = format!(
        "{}\n{}",
        format_scan_header(response.records_scanned, response.duration_ms),
        format_aggregate_summary(&response.aggregations)
    );

    // Extract the first non-None next_cursor from the aggregation results.
    let next_cursor = response
        .aggregations
        .iter()
        .find_map(|agg| agg.next_cursor.clone());

    let structured = crate::schemas::FacetValuesOutput {
        field: args.field,
        records_scanned: response.records_scanned,
        duration_ms: response.duration_ms,
        aggregations: serde_json::to_value(&response.aggregations)?,
        next_cursor,
    };

    let json = serde_json::to_string_pretty(&structured)?;

    let mut result = CallToolResult::success(vec![ContentBlock::text(format!(
        "{summary}\n\n```json\n{json}\n```"
    ))]);
    result.structured_content = Some(serde_json::to_value(structured)?);
    Ok(result)
}
