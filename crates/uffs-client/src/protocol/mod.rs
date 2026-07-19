// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! JSON-RPC 2.0 protocol types shared between client and daemon.
//!
//! These types define the wire format for IPC communication. Both
//! `uffsd` (daemon) and `uffs` (CLI) both depend on this module.
//!
//! Phase 3b API-hygiene decisions for this module live at the crate
//! root (see `crates/uffs-client/src/lib.rs`) since they are
//! workspace-wide policy, not type-specific records.

pub mod aggregate_wire;
pub mod cli_args;
mod cli_args_helpers;
pub mod response;
pub(crate) mod response_status;
pub(crate) mod response_tiering;
pub mod search_params;
#[cfg(test)]
mod tests;

pub use aggregate_wire::{
    AggregateResultWire, AggregateSpecWire, BucketWire, DrilldownWire, SampleRowWire, StatsWire,
};
use serde::{Deserialize, Serialize};

// ────────────────────────────────────────────────────────────────────────────
// JSON-RPC 2.0 envelope
// ────────────────────────────────────────────────────────────────────────────

/// JSON-RPC 2.0 request.
#[derive(Debug, Serialize, Deserialize)]
pub struct RpcRequest {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Request ID (correlates request → response). `None` for notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    /// Method name (e.g. `"search"`, `"drives"`, `"status"`).
    pub method: String,
    /// Method parameters (JSON object or array).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 success response.
#[derive(Debug, Serialize, Deserialize)]
pub struct RpcResponse {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Matching request ID.
    pub id: u64,
    /// Result payload (method-specific).
    pub result: serde_json::Value,
}

/// JSON-RPC 2.0 error response.
#[derive(Debug, Serialize, Deserialize)]
pub struct RpcErrorResponse {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Matching request ID.
    pub id: Option<u64>,
    /// Error details.
    pub error: RpcError,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Serialize, Deserialize)]
pub struct RpcError {
    /// Error code (standard JSON-RPC or application-specific).
    pub code: i32,
    /// Human-readable error message.
    pub message: String,
    /// Optional structured error data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 notification (no `id`, no response expected).
#[derive(Debug, Serialize, Deserialize)]
pub struct RpcNotification {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Notification method (e.g. `"drive_loaded"`, `"refresh_complete"`).
    pub method: String,
    /// Notification parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

// Standard JSON-RPC error codes
/// Parse error (invalid JSON).
pub const ERR_PARSE: i32 = -32700;
/// Invalid request (missing fields).
pub const ERR_INVALID_REQUEST: i32 = -32600;
/// Method not found.
pub const ERR_METHOD_NOT_FOUND: i32 = -32601;
/// Invalid parameters.
pub const ERR_INVALID_PARAMS: i32 = -32602;
/// Internal error.
pub const ERR_INTERNAL: i32 = -32603;

/// Canonical result filter mode for file-vs-directory selection.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SearchFilterMode {
    /// Return both files and directories.
    All,
    /// Return files only.
    Files,
    /// Return directories only.
    Dirs,
}

/// Canonical sort direction in the daemon wire contract.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SearchSortDirection {
    /// Ascending order.
    Asc,
    /// Descending order.
    Desc,
}

/// Canonical sort clause in the daemon wire contract.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SearchSortSpec {
    /// Canonical field name or accepted alias.
    pub field: String,
    /// Explicit direction. When omitted, the daemon applies the field default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<SearchSortDirection>,
}

/// Canonical predicate operator in the daemon wire contract.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SearchPredicateOp {
    /// Equality comparison.
    Eq,
    /// Inequality comparison.
    Ne,
    /// Strictly less-than comparison.
    Lt,
    /// Less-than-or-equal comparison.
    Lte,
    /// Strictly greater-than comparison.
    Gt,
    /// Greater-than-or-equal comparison.
    Gte,
    /// Membership in a set of values.
    In,
    /// Exclusion from a set of values.
    NotIn,
    /// Field contains all listed values.
    HasAll,
    /// Field contains any listed value.
    HasAny,
    /// Field contains none of the listed values.
    HasNone,
    /// Pattern/glob match.
    Match,
    /// Negated pattern/glob match.
    NotMatch,
    /// Case-insensitive substring containment.
    Contains,
    /// Case-insensitive prefix match.
    StartsWith,
    /// Case-insensitive suffix match.
    EndsWith,
}

/// Canonical predicate value in the daemon wire contract.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SearchPredicateValue {
    /// String scalar.
    String(String),
    /// String list.
    StringList(Vec<String>),
    /// Unsigned integer scalar.
    U64(u64),
    /// Signed integer scalar.
    I64(i64),
    /// Boolean scalar.
    Bool(bool),
}

/// Canonical predicate clause in the daemon wire contract.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SearchPredicate {
    /// Canonical field name or accepted alias.
    pub field: String,
    /// Comparison operator.
    pub op: SearchPredicateOp,
    /// Predicate operand.
    pub value: SearchPredicateValue,
}

/// Canonical response shaping mode for direct daemon callers.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SearchResponseMode {
    /// Traditional full-row response.
    Rows,
    /// Projected JSON objects keyed by projected field name.
    Json,
}

// Application error codes (daemon-specific)
/// Daemon is still loading indices.
pub const ERR_NOT_READY: i32 = -1;
/// Search pattern compilation failed (bad regex).
pub const ERR_BAD_PATTERN: i32 = -2;
/// Method is wired into the protocol surface but has no handler
/// implementation yet.
///
/// Used by the Phase 8-A scaffolding stage of the memory-tiering
/// rollout: `hibernate` / `preload` / `forget` / `status_drives` are
/// reachable in the dispatcher and serialise round-trip cleanly,
/// but each handler returns this error until the corresponding
/// follow-up sub-phase (8-B / 8-C / 8-D / 8-E) fills in the logic.
pub const ERR_NOT_IMPLEMENTED: i32 = -3;
/// Drive is non-`Cold` and cannot be modified by a destructive
/// operation that requires it to be at rest.
///
/// Reserved for the `forget` method (Phase 8-D) which refuses to
/// delete cache files for a drive whose shard is still warm in RAM.
/// Operators must `hibernate` the drive first or pass `force = true`.
pub const ERR_DRIVE_BUSY: i32 = -4;

// ────────────────────────────────────────────────────────────────────────────
// Method parameters
// ────────────────────────────────────────────────────────────────────────────

/// Parameters for the `search` method.
///
/// All filter fields mirror the CLI surface; see
/// `uffs_core::search::filters::SearchFilters` for semantics.
/// Every field is optional — omitted fields impose no constraint.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "JSON-RPC wire type — boolean fields are the natural JSON encoding for on/off flags"
)]
pub struct SearchParams {
    // ── Core ────────────────────────────────────────────────────────
    /// Search pattern (glob, regex with `>` prefix, or substring).
    pub pattern: String,
    /// Case-sensitive matching.
    #[serde(default)]
    pub case_sensitive: bool,
    /// Whole-word matching.
    #[serde(default)]
    pub whole_word: bool,
    /// Match pattern against the full path (not just the filename).
    ///
    /// When true, directory records whose name matches the pattern will also
    /// contribute all their descendants to the result set.  Default (`false`)
    /// matches filename-only, consistent with Everything's default behaviour.
    #[serde(default)]
    pub match_path: bool,

    // ── Sort ────────────────────────────────────────────────────────
    /// Sort column name (e.g. `"modified"`, `"size"`, `"name"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,
    /// Canonical ordered sort clauses. Preferred over legacy `sort`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sorts: Vec<SearchSortSpec>,
    /// Sort direction: `true` = descending.
    #[serde(default)]
    pub sort_desc: bool,

    // ── Limit ───────────────────────────────────────────────────────
    /// Maximum results to return (`None` = unlimited).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    // ── Filter mode ────────────────────────────────────────────────
    /// Filter mode: `"all"` (default), `"files"`, `"dirs"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    /// Canonical filter mode. Preferred over legacy `filter`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_mode: Option<SearchFilterMode>,
    /// Canonical predicates. Preferred over legacy filter fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub predicates: Vec<SearchPredicate>,
    /// Specific drives to search (empty = all loaded).
    #[serde(default)]
    pub drives: Vec<uffs_mft::platform::DriveLetter>,
    /// Requested projection fields in canonical order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projection: Vec<String>,
    /// Requested response shaping mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<SearchResponseMode>,

    // ── Size filters ───────────────────────────────────────────────
    /// Minimum file size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_size: Option<u64>,
    /// Maximum file size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,

    // ── Descendant filters ─────────────────────────────────────────
    /// Minimum descendant count (inclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_descendants: Option<u32>,
    /// Maximum descendant count (inclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_descendants: Option<u32>,

    // ── Time filters ───────────────────────────────────────────────
    /// Modified-time lower bound (e.g. `"7d"`, `"24h"`, `"2026-01-15"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newer: Option<String>,
    /// Modified-time upper bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub older: Option<String>,
    /// Created-time lower bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newer_created: Option<String>,
    /// Created-time upper bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub older_created: Option<String>,
    /// Accessed-time lower bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newer_accessed: Option<String>,
    /// Accessed-time upper bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub older_accessed: Option<String>,

    // ── Attribute filter ───────────────────────────────────────────
    /// Attribute filter spec (e.g. `"hidden,compressed,!system"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attr: Option<String>,

    // ── Extension filter ───────────────────────────────────────────
    /// Comma-separated extension filter (e.g. `"rs,toml,md"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<String>,

    // ── Exclude ────────────────────────────────────────────────────
    /// Exclude glob pattern (e.g. `"backup*"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude: Option<String>,
    /// Directory-path pattern (glob). Only matches against the directory
    /// portion of the path, not the filename.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_contains: Option<String>,
    /// Directory-path **exclude** patterns — a comma-separated list of globs
    /// (e.g. `"*appdata*,*.cargo*,*.rustup*"`). A record is dropped when its
    /// directory portion matches **any** of them. Inverse of `path_contains`;
    /// the comma-list lets several noise dirs be excluded in one query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_excludes: Option<String>,
    /// File type/category filter (e.g. `"code"`, `"document"`, `"picture"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_filter: Option<String>,
    /// Minimum bulkiness percentage (100 = perfectly packed, >100 = wasteful).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_bulkiness: Option<u64>,
    /// Maximum bulkiness percentage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bulkiness: Option<u64>,

    // ── Length filters ─────────────────────────────────────────────
    /// Minimum filename length in characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_name_len: Option<u16>,
    /// Maximum filename length in characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_name_len: Option<u16>,
    /// Minimum full-path length in characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_path_len: Option<u16>,
    /// Maximum full-path length in characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_path_len: Option<u16>,

    // ── Size-on-disk filters ──────────────────────────────────────
    /// Minimum allocated (on-disk) size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_allocated: Option<u64>,
    /// Maximum allocated (on-disk) size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_allocated: Option<u64>,

    // ── Tree metric filters ────────────────────────────────────────
    /// Minimum subtree logical size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_treesize: Option<u64>,
    /// Maximum subtree logical size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_treesize: Option<u64>,
    /// Minimum subtree allocated (on-disk) size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_tree_allocated: Option<u64>,
    /// Maximum subtree allocated (on-disk) size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tree_allocated: Option<u64>,

    // ── Month-of-year filter ──────────────────────────────────────
    /// Allowed month numbers (1-12).  Empty = no month filter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_months: Vec<u32>,

    // ── WI-4.4 malformed-name filter ───────────────────────────────
    /// Filter on whether the leaf name is ill-formed (not valid UTF-8).
    /// `Some(true)` = only malformed names, `Some(false)` = only well-formed,
    /// `None` = no filter. Emitted as a `malformed` predicate (hot-path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub malformed: Option<bool>,
    /// Filter on whether any path component is ill-formed. Emitted as a
    /// `malformed_path` predicate (post-filter, since it is path-derived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub malformed_path: Option<bool>,

    // ── Misc ───────────────────────────────────────────────────────
    /// Hide system meta-files (names starting with `$`).
    #[serde(default)]
    pub hide_system: bool,
    /// Hide NTFS Alternate Data Streams from results.
    #[serde(default)]
    pub hide_ads: bool,
    /// Render ill-formed (surrogate-bearing) names with greppable `<BAD:HHHH>`
    /// markers instead of the default U+FFFD (`�`). Display-only — does not
    /// filter results (use the malformed filter for that).
    #[serde(default)]
    pub normalize_malformed: bool,

    // ── Profiling ──────────────────────────────────────────────────
    /// Request detailed timing breakdown from the daemon.
    #[serde(default)]
    pub profile: bool,

    // ── Aggregation ────────────────────────────────────────────────
    /// Aggregation specs to compute alongside or instead of rows.
    ///
    /// When non-empty, the daemon runs the aggregation engine in addition
    /// to (or instead of) returning rows, depending on `include_rows`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aggregations: Vec<AggregateSpecWire>,
    /// Whether to include result rows in the response.
    ///
    /// Defaults to `true`. Set to `false` for aggregate-only queries
    /// (equivalent to `--count` or `--aggregate` without `--rows`).
    #[serde(default = "default_true")]
    pub include_rows: bool,
    /// Resolve each matched row's true on-disk physical location (LCN)
    /// and return rows sorted by ascending LCN instead of match order.
    ///
    /// Opt-in and off by default: resolving physical location costs one
    /// extra targeted MFT record read per matched row, so this is meant
    /// for bulk content-read jobs (`uffs-content`) ordering reads to
    /// minimize seeks, not interactive queries. Real-hardware
    /// benchmarking found match order (and even ascending-FRS order)
    /// captures only a fraction of the achievable seek-distance
    /// reduction on a volume that's been reorganized over years — see
    /// `docs/architecture/content-stream-tool-design.md`.
    #[serde(default)]
    pub resolve_lcn_order: bool,

    // ── Aggregation pagination ─────────────────────────────────────
    /// Opaque cursor token from a previous response's `next_cursor`.
    ///
    /// When set, the daemon resumes pagination from the encoded position.
    /// The cursor encodes `result_index:offset:page_size`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agg_cursor: Option<String>,
    /// Maximum buckets per aggregation result page.
    ///
    /// When set (and `agg_cursor` is absent), the daemon returns at most
    /// this many buckets per result, with a `next_cursor` on any result
    /// that has more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agg_page_size: Option<u16>,

    // ── Direct file output ────────────────────────────────────────
    /// When set, the daemon writes results directly to this file path
    /// instead of sending rows through IPC.  The response contains only
    /// metadata (`rows_written`, timing).  This eliminates serialization
    /// and IPC overhead for bulk exports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_file: Option<String>,
    /// Output config: column separator (default: `","`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_separator: Option<String>,
    /// Output config: quote character for strings (default: `"\""`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_quote: Option<String>,
    /// Output config: include header row (default: `true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_header: Option<bool>,
    /// Output config: representation for active boolean attributes (default:
    /// `"1"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_pos: Option<String>,
    /// Output config: representation for inactive boolean attributes (default:
    /// `"0"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_neg: Option<String>,
    /// Output config: columns to output (default: all).
    /// Comma-separated column names like `"path,name,size"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_columns: Option<String>,
    /// Output config: enable parity-compat formatting (trailing `\` on
    /// directory paths, empty `Name` for dirs, `treesize` for dir `Size`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_parity_compat: Option<bool>,
    /// Output config: timezone offset in hours from UTC for timestamp
    /// formatting (overrides auto-detected local timezone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tz_offset_hours: Option<i32>,
    /// Output config: CLI-layer `--format` value (e.g. `"csv"`, `"json"`,
    /// `"custom"`, `"table"`).
    ///
    /// The daemon uses this field to decide how to pre-format rows
    /// server-side into a
    /// [`SearchPayload::InlineBlob`](crate::protocol::response::SearchPayload::InlineBlob)
    /// / [`SearchPayload::ShmemBlob`](crate::protocol::response::SearchPayload::ShmemBlob).
    /// As of Phase 3:
    ///
    /// - `Some("csv")` (or absent — CLI default is `csv`) → pre-format through
    ///   [`uffs_format::write_rows`], emitting the canonical CSV bytes.
    /// - `Some("custom")` → pre-format the CSV body, then append the legacy
    ///   `Drives? … / MMMmmm …` footer via
    ///   [`uffs_format::write_legacy_drive_footer`] (gated on
    ///   `output_drive_targets` being non-empty).
    /// - `Some("json")` / `Some("table")` → skip pre-format.  The CLI keeps
    ///   ownership of those structural formats.
    ///
    /// Byte-parity between the CLI slow path and the daemon fast path
    /// is pinned by
    /// `uffs_cli::commands::output::tests::{parity_byte_parity_*,
    /// columnar_byte_parity_*}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<String>,

    /// Drive letters the search targeted, echoed back into the legacy
    /// drive footer when `output_format == Some("custom")`.
    ///
    /// Matches the CLI's local `targets` computation: populated from
    /// `--drive` / `--drives` (and, in the thin-client passthrough
    /// path, `--mft-file` by extracting drive letters from the file
    /// paths).  Empty → footer omitted entirely, matching
    /// `uffs_format::write_legacy_drive_footer`'s "no drives, no
    /// footer" rule.
    ///
    /// The field is intentionally separate from [`Self::drives`]
    /// because "which drives to search" and "which drives to show in
    /// the footer" are semantically different — e.g.  `--mft-file
    /// C.mft` targets drive C for the footer but leaves `drives`
    /// empty because the MFT path is a separate wire selector.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_drive_targets: Vec<uffs_mft::platform::DriveLetter>,

    // ── Snapshot-diff (delete visibility) ──────────────────────────
    /// When set, this is a **snapshot-diff search**: the daemon loads the
    /// baseline MFT capture at this path, marks the records whose File
    /// Reference vanished from the live index (the deletes), and runs this
    /// search over the **baseline** restricted to those deleted rows. Every
    /// other field (pattern, `ext`, `newer`/`older`, `min_size`, sort,
    /// projection, output format) then filters/shapes the deleted set exactly
    /// like a normal search. `None` = ordinary live search.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_baseline: Option<String>,
}

/// Default-true helper for serde.
const fn default_true() -> bool {
    true
}

impl Default for SearchParams {
    fn default() -> Self {
        Self {
            pattern: String::new(),
            case_sensitive: false,
            whole_word: false,
            match_path: false,
            sort: None,
            sorts: vec![],
            sort_desc: false,
            limit: None,
            filter: None,
            filter_mode: None,
            predicates: vec![],
            drives: vec![],
            projection: vec![],
            response_mode: None,
            min_size: None,
            max_size: None,
            min_descendants: None,
            max_descendants: None,
            newer: None,
            older: None,
            newer_created: None,
            older_created: None,
            newer_accessed: None,
            older_accessed: None,
            attr: None,
            ext: None,
            exclude: None,
            path_contains: None,
            path_excludes: None,
            type_filter: None,
            min_bulkiness: None,
            max_bulkiness: None,
            min_name_len: None,
            max_name_len: None,
            min_path_len: None,
            max_path_len: None,
            min_allocated: None,
            max_allocated: None,
            min_treesize: None,
            max_treesize: None,
            min_tree_allocated: None,
            max_tree_allocated: None,
            allowed_months: vec![],
            malformed: None,
            malformed_path: None,
            hide_system: false,
            hide_ads: false,
            normalize_malformed: false,
            profile: false,
            aggregations: vec![],
            include_rows: true,
            resolve_lcn_order: false,
            agg_cursor: None,
            agg_page_size: None,
            output_file: None,
            output_separator: None,
            output_quote: None,
            output_header: None,
            output_pos: None,
            output_neg: None,
            output_columns: None,
            output_parity_compat: None,
            output_tz_offset_hours: None,
            output_format: None,
            output_drive_targets: Vec::new(),
            diff_baseline: None,
        }
    }
}

// Aggregation wire types live in the sibling [`aggregate_wire`] module and are
// re-exported at the top of this file.  Split off to keep `mod.rs` under the
// 800-LOC policy ceiling.
