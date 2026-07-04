// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Response types, RPC convenience methods, and command parameter types.
//!
//! Daemon-state responses (`DrivesResponse`, `StatusResponse`,
//! `StatsResponse`, `DaemonStatus`, `DriveMemoryInfo`, `DriveInfo`)
//! live in the sibling `response_status` module and are re-exported below
//! for back-compat with the historical `crate::protocol::response::*`
//! import surface.

use serde::{Deserialize, Serialize};

pub use super::response_status::{
    DaemonPaths, DaemonStatus, DriveInfo, DriveMemoryInfo, DrivesResponse, LiveUpdateInfo,
    ShardTier, StatsResponse, StatusResponse,
};
pub use super::response_tiering::{
    DEFAULT_PRELOAD_PIN_MINUTES, DriveTierStatus, ForgetParams, ForgetResponse, HibernateParams,
    HibernateResponse, PreloadParams, PreloadResponse, StatusDrivesParams, StatusDrivesResponse,
};
use super::{
    AggregateResultWire, BucketWire, RpcError, RpcErrorResponse, RpcRequest, RpcResponse,
    SearchResponseMode, SearchSortSpec,
};

/// Parameters for the `refresh` method.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RefreshParams {
    /// Specific drives to refresh (empty = all loaded).
    #[serde(default)]
    pub drives: Vec<uffs_mft::platform::DriveLetter>,
}

/// Parameters for the `load_drive` method.
///
/// Tells the daemon to hot-load one or more MFT files that it doesn't
/// already have.  Used when the CLI connects to an already-running daemon
/// that was started without a particular drive's data.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct LoadDriveParams {
    /// MFT file paths to load (absolute paths).
    #[serde(default)]
    pub mft_files: Vec<String>,
    /// Drive letters to hot-load (e.g. `['D', 'E']`).
    /// On Windows, reads the live NTFS MFT.
    /// On non-Windows, discovers from the daemon's `data_dir`.
    #[serde(default)]
    pub drives: Vec<uffs_mft::platform::DriveLetter>,
    /// Skip cache when loading.
    #[serde(default)]
    pub no_cache: bool,
}

/// Response for the `load_drive` method.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoadDriveResponse {
    /// Drives that were successfully loaded.
    pub loaded: Vec<uffs_mft::platform::DriveLetter>,
    /// Drives that were already present (skipped).
    pub already_loaded: Vec<uffs_mft::platform::DriveLetter>,
    /// Errors encountered (drive letter → message).
    pub errors: Vec<String>,
}

/// Parameters for the `facet_values` convenience method.
///
/// Retrieves the distinct values (with counts) for a given field.
/// Internally translates to a `search` with a `terms` aggregation.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct FacetValuesParams {
    /// Field to facet on (e.g. `"extension"`, `"type"`).
    #[serde(default = "default_facet_field")]
    pub field: String,

    /// Optional glob pattern to restrict which records are included.
    /// Defaults to `"*"` (all records).
    #[serde(default = "default_pattern")]
    pub pattern: String,

    /// Maximum number of values to return per page.
    /// Defaults to `50`.
    #[serde(default)]
    pub page_size: Option<u16>,

    /// Cursor token from a previous response for pagination.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Default facet field.
fn default_facet_field() -> String {
    "extension".to_owned()
}

/// Default pattern.
fn default_pattern() -> String {
    "*".to_owned()
}

/// Response from the `facet_values` method.
#[derive(Debug, Serialize, Deserialize)]
pub struct FacetValuesResponse {
    /// The field that was faceted.
    pub field: String,

    /// Facet values with counts, sorted by count descending.
    pub values: Vec<BucketWire>,

    /// Total number of distinct values (before pagination).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_distinct: Option<usize>,

    /// Cursor for the next page.  `None` when all values fit in this
    /// page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Parameters for the `info` method.
#[derive(Debug, Serialize, Deserialize)]
pub struct InfoParams {
    /// Full path to look up.
    pub path: String,
}

/// Parameters for the `keepalive` method.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct KeepaliveParams {
    /// Session type hint for idle timeout differentiation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_type: Option<String>,
}

// ────────────────────────────────────────────────────────────────────────────
// Method responses
// ────────────────────────────────────────────────────────────────────────────

/// Delivery channel for search results.
///
/// v0.5.62 collapsed the five mutually-exclusive fields
/// (`rows`, `shmem_path`, `shmem_count`, `paths_blob`,
/// `paths_blob_shmem`) of the old `SearchResponse` into this single
/// tagged enum so that:
///
/// 1. **Illegal states are unrepresentable.**  The type system enforces exactly
///    one payload channel per response; no more "inline blob AND shmem rows
///    both set" correctness hazard.
/// 2. **The client dispatch is exhaustive.**  A `match` on this enum guarantees
///    the CLI handles every variant, and adding a new transport (e.g.
///    `InlineNdjson`, `MsgpackShmem`) is a variant addition caught at compile
///    time at every call site.
/// 3. **Format and transport are orthogonal axes.**  Two axes — *Format*
///    (Structured `SearchRow` list vs. pre-formatted UTF-8 bytes) and
///    *Transport* (Inline in the RPC envelope vs. Shmem file) — combine into
///    four natural variants, plus [`Self::Empty`] for the no-payload case.
///
/// ## Dispatch priority (daemon side)
///
/// 1. Caller opted out of rows or no matches → [`Self::Empty`].
/// 2. Pre-formattable projection (path-only, or multi-column CSV whose options
///    match the daemon's formatter):
///    - blob ≤ [`crate::shmem::PATHS_BLOB_SHMEM_THRESHOLD`] →
///      [`Self::InlineBlob`]
///    - blob > threshold → [`Self::ShmemBlob`]
/// 3. Otherwise (JSON mode, aggregations-only, or format flags the daemon
///    cannot replicate):
///    - rows ≤ [`crate::shmem::SHMEM_THRESHOLD`] → [`Self::InlineRows`]
///    - rows > threshold → [`Self::ShmemRows`]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum SearchPayload {
    /// No rows, no blob.  Used for no-match queries, `--no-output`,
    /// and `--out=file` responses where the daemon streamed directly
    /// to disk.  Metadata fields (`total_count`, `duration_ms`,
    /// `aggregations`, …) on the enclosing [`SearchResponse`] may
    /// still carry useful information.
    ///
    /// Marked `#[default]` so [`core::mem::take`] on a payload field
    /// can swap the owned variant out without requiring a manual
    /// replacement — the daemon's `try_pack_paths_blob` relies on
    /// this to consume a `Vec<SearchRow>` without cloning it.
    #[default]
    Empty,

    /// Structured [`SearchRow`] list delivered as a JSON array
    /// inside the RPC envelope.  Used for JSON-mode callers, the
    /// [`projected_rows`](SearchResponse::projected_rows) direct API
    /// path, and multi-column CLI responses whose format flags
    /// (custom separator, quote character, locale-specific date
    /// format, etc.) would diverge from the daemon's CSV writer
    /// defaults.
    InlineRows(Vec<SearchRow>),

    /// Structured rows delivered via a memory-mapped binary file.
    /// The client reads the file with
    /// [`crate::shmem::read_search_results`] and must delete it
    /// afterwards (best-effort — the daemon's GC
    /// ([`crate::shmem::cleanup_stale_shmem_files`]) sweeps any
    /// orphans on restart).
    ShmemRows {
        /// Absolute path to the mmap'd binary rows file.
        path: String,
        /// Number of [`SearchRow`] records the daemon wrote to the
        /// file.  Lets the client size its destination vec up front
        /// without re-counting.
        count: u64,
    },

    /// Pre-formatted UTF-8 text delivered inline as a JSON string.
    /// The daemon has already applied the user's `--columns`,
    /// `--sep`, `--quotes`, `--header`, etc. — the CLI writes the
    /// bytes straight to stdout with a single `write_all` and
    /// treats them as opaque output.
    ///
    /// The final byte is always `\n` when the blob is non-empty.
    /// Used when the blob is at most
    /// [`crate::shmem::PATHS_BLOB_SHMEM_THRESHOLD`] bytes; above
    /// that, the daemon switches to [`Self::ShmemBlob`] to avoid
    /// the ~80 ms round-trip JSON escape/unescape cost on
    /// multi-megabyte backslash-heavy Windows-path blobs.
    InlineBlob(String),

    /// Pre-formatted UTF-8 text delivered via a memory-mapped
    /// binary file.  The file carries the raw bytes — no framing,
    /// no length prefix, no JSON — and the client streams it via
    /// [`crate::shmem::stream_paths_blob_into`], which mmaps the
    /// file, runs a single `write_all`, and deletes the file
    /// afterwards.  No JSON encode on the daemon, no JSON decode on
    /// the client, no intermediate allocation.
    ///
    /// Used when the blob exceeds
    /// [`crate::shmem::PATHS_BLOB_SHMEM_THRESHOLD`].
    ShmemBlob(String),
}

impl SearchPayload {
    /// Return `true` when no payload is attached.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    /// Return `true` when the payload carries structured
    /// [`SearchRow`] records (either inline or via shmem).
    ///
    /// Useful on the client side to decide between row-walking
    /// formatters and opaque `write_all` fast paths.
    #[must_use]
    pub const fn is_rows(&self) -> bool {
        matches!(self, Self::InlineRows(_) | Self::ShmemRows { .. })
    }

    /// Return `true` when the payload carries pre-formatted UTF-8
    /// bytes (either inline or via shmem).  The client writes these
    /// straight to stdout without format dispatch.
    #[must_use]
    pub const fn is_blob(&self) -> bool {
        matches!(self, Self::InlineBlob(_) | Self::ShmemBlob(_))
    }

    /// Best-effort structured row count, when known without
    /// reading a shmem file.
    ///
    /// Returns:
    /// - `Some(0)` for [`Self::Empty`].
    /// - `Some(len)` for [`Self::InlineRows`].
    /// - `Some(count)` for [`Self::ShmemRows`] (the daemon's pre-computed
    ///   count).
    /// - `None` for blob variants — counting newlines would require mmapping
    ///   the file and is usually unnecessary.
    #[must_use]
    pub fn row_count_hint(&self) -> Option<usize> {
        match self {
            Self::Empty => Some(0),
            Self::InlineRows(rows) => Some(rows.len()),
            Self::ShmemRows { count, .. } => Some(usize::try_from(*count).unwrap_or(usize::MAX)),
            Self::InlineBlob(_) | Self::ShmemBlob(_) => None,
        }
    }

    /// Consume the payload and return the inline `SearchRow` list.
    ///
    /// Programmatic callers that always request structured rows
    /// (e.g. the MCP bridge, the `uffs_client::connect::UffsClientSync::search`
    /// API) use this to unwrap the payload after the transport
    /// layer has transparently resolved any [`Self::ShmemRows`]
    /// back to [`Self::InlineRows`].
    ///
    /// Returns:
    /// - `Some(rows)` for [`Self::InlineRows`] (the common case).
    /// - `Some(Vec::new())` for [`Self::Empty`] — a no-match query is not an
    ///   error.
    /// - `None` for every other variant:
    ///   - [`Self::ShmemRows`] — the caller forgot to run the
    ///     transparent-resolve step (`connect::search` does this automatically;
    ///     direct `send_request` users must call
    ///     [`crate::shmem::read_search_results`] themselves).
    ///   - [`Self::InlineBlob`] / [`Self::ShmemBlob`] — the daemon
    ///     pre-formatted the output for stdout, which programmatic callers
    ///     don't ask for (blobs only fire when the CLI explicitly requests a
    ///     path-only or multi-column CSV projection that the daemon can fully
    ///     render server-side).
    #[must_use]
    pub fn into_inline_rows(self) -> Option<Vec<SearchRow>> {
        match self {
            Self::InlineRows(rows) => Some(rows),
            Self::Empty => Some(Vec::new()),
            Self::ShmemRows { .. } | Self::InlineBlob(_) | Self::ShmemBlob(_) => None,
        }
    }
}

/// Response for the `search` method.
///
/// The payload (matching rows or a pre-formatted output blob)
/// travels in [`Self::payload`] as a tagged enum — see
/// [`SearchPayload`] for the full taxonomy of delivery channels and
/// the dispatch priority the daemon uses to pick between them.
///
/// Everything else on this struct is per-response metadata
/// (timings, aggregations, applied flags) that is independent of
/// the payload shape.
#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResponse {
    /// Payload delivery channel selected by the daemon for this
    /// response.  See [`SearchPayload`] for the variants + the
    /// dispatch priority that picks between them.
    pub payload: SearchPayload,
    /// Total number of matching records (before `limit` truncation).
    ///
    /// When the search uses a `limit`, only a subset of rows is returned
    /// but `total_count` reflects the full match count.
    #[serde(default)]
    pub total_count: u64,
    /// Total records scanned.
    pub records_scanned: usize,
    /// Search duration in milliseconds.
    pub duration_ms: u64,
    /// Whether results were truncated by limit.
    pub truncated: bool,
    /// Detailed timing breakdown from the daemon (only when
    /// `SearchParams::profile` was `true`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<SearchProfile>,
    /// Effective canonical sort clauses applied by the daemon.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied_sorts: Vec<SearchSortSpec>,
    /// Effective projection fields applied by the daemon.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied_projection: Vec<String>,
    /// Response shaping mode for the payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<SearchResponseMode>,
    /// Projected rows for direct daemon callers.
    ///
    /// When the daemon is called via the programmatic (non-CLI) API
    /// with a custom projection list, each row is reshaped into a
    /// JSON object keyed by column name and delivered here instead
    /// of via [`Self::payload`].  The payload is
    /// [`SearchPayload::Empty`] in that case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projected_rows: Option<Vec<serde_json::Map<String, serde_json::Value>>>,
    /// Aggregation results (present when `SearchParams::aggregations` was
    /// non-empty).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aggregations: Vec<AggregateResultWire>,
}

/// Daemon-side timing breakdown returned when `SearchParams::profile` is set.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SearchProfile {
    /// Daemon uptime in milliseconds (time since daemon started).
    pub uptime_ms: u64,
    /// Total startup duration: first drive start → last drive ready (ms).
    pub startup_ms: u64,
    /// Time to acquire the `RwLock` + prepare filters (ms).
    pub lock_ms: u64,
    /// Pure search time across all drives (ms).
    pub search_ms: u64,
    /// Time to convert `DisplayRow` → `SearchRow` (ms).
    pub row_build_ms: u64,
    /// JSON serialization / shmem write time (ms).
    pub serialize_ms: u64,
    /// Scan phase of the `collect_global_top_n_numeric` pipeline (ms).
    ///
    /// Populated only for `pattern == "*"` / ext-fast-path queries that
    /// take the numeric-sort branch.  `0` for other dispatch paths
    /// (regex, trigram, path-sorted tree walk) and for older daemons
    /// that predate the `PhaseTimings` instrumentation.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub scan_ms: u64,
    /// Sort phase: heap drain + `sort_unstable_by_key` + truncate (ms).
    /// Same caveats as `scan_ms`.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub sort_ms: u64,
    /// Path-resolve phase: per-candidate `resolve_path_cached` +
    /// `DisplayRow` materialisation (ms).  Typically the dominant
    /// cost at high row counts when sorting by a non-path field.
    /// Same caveats as `scan_ms`.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub path_resolve_ms: u64,
    /// Row-write phase: time the daemon spent streaming
    /// `SearchRow`s to disk (`write_rows_to_file`) — only populated
    /// for `--out` / file-sink queries.  `0` for shared-memory and
    /// in-memory responses.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub write_ms: u64,
    /// Deep-profile counter: number of candidates that reached
    /// the path-resolve loop in the numeric-sort branch.  Divide
    /// `path_resolve_ms` by this to get per-record cost.  `0` for
    /// other dispatch paths and for daemons that predate the
    /// deep-profile instrumentation.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub path_candidates: u64,
    /// Deep-profile counter: total `DirCache` entries across all
    /// drives at the end of the path-resolve loop.  Because
    /// `DirCache` is keyed by parent and only grows on misses,
    /// this equals the miss count.  `path_candidates -
    /// path_cache_entries = hit count`.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub path_cache_entries: u64,
    /// Deep-profile counter: cumulative nanoseconds spent inside
    /// `tree::resolve_path_cached`.  Isolates the path-walk cost
    /// from the surrounding row-build work; compare against
    /// `path_build_row_ns`.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub path_resolve_fn_ns: u64,
    /// Deep-profile counter: cumulative nanoseconds spent in
    /// `make_display_row` + the subsequent `Vec::push`.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub path_build_row_ns: u64,
    /// Per-drive breakdown.
    pub drives: Vec<DriveProfile>,
}

/// `serde` helper: omit zero-valued phase timings from the wire
/// representation to keep CLI JSON output clean when the new fields
/// aren't populated (regex/trigram paths, old daemons, shmem sink).
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde `skip_serializing_if` requires `&T` signature"
)]
const fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

/// Per-drive timing within a search (search + load/startup metrics).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DriveProfile {
    /// Drive letter.
    pub drive: uffs_mft::platform::DriveLetter,
    /// Records in this drive's index.
    pub records: usize,
    /// Matching rows found in this search.
    pub matches: usize,
    // ── Startup/load timing (captured once at daemon start) ─────
    /// Compact-cache deserialization time (ms). 0 if cache miss.
    #[serde(default)]
    pub cache_ms: u64,
    /// MFT read time (ms). 0 if cache hit.
    #[serde(default)]
    pub mft_ms: u64,
    /// Compact index build time (ms). 0 if cache hit.
    #[serde(default)]
    pub compact_ms: u64,
    /// Trigram index build time (ms). 0 if cache hit.
    #[serde(default)]
    pub trigram_ms: u64,
}

/// A single search result row.
#[derive(Debug, Serialize, Deserialize)]
pub struct SearchRow {
    /// Drive letter.
    pub drive: uffs_mft::platform::DriveLetter,
    /// Full resolved path.
    pub path: String,
    /// Filename.
    pub name: String,
    /// File size in bytes.
    pub size: u64,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// Last modified time (Unix microseconds).
    pub modified: i64,
    /// Creation time (Unix microseconds).
    pub created: i64,
    /// Last access time (Unix microseconds).
    pub accessed: i64,
    /// Raw NTFS attribute flags.
    pub flags: u32,
    /// Allocated size on disk.
    pub allocated: u64,
    /// Descendant count.
    pub descendants: u32,
    /// Subtree size.
    pub treesize: u64,
    /// Sum of allocated sizes in entire subtree (directories only).
    #[serde(default)]
    pub tree_allocated: u64,
    /// WI-4.4 forensic flag: the leaf name's true bytes are not valid UTF-8.
    /// `#[serde(default)]` keeps the wire format backward/forward compatible —
    /// an old daemon omits it (deserializes `false`); an old client ignores it.
    #[serde(default)]
    pub malformed: bool,
    /// WI-4.4 forensic flag: some component of the resolved path is ill-formed.
    #[serde(default)]
    pub malformed_path: bool,
    /// WI-4.4 forensic evidence: hex of the true (WTF-8) leaf-name bytes.
    /// `Some` for every malformed row, `None` otherwise — it is keyed on
    /// name validity, not on column projection. `skip_serializing_if` drops
    /// the `None` case so well-formed rows stay lean, but malformed rows
    /// carry `name_hex` in `--format json` by DEFAULT (no `--columns`
    /// needed). The CSV/columnar surface still treats it as an opt-in
    /// column (it is not in `BASELINE_COLUMN_ORDER`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_hex: Option<String>,
}

/// Feed `SearchRow` directly into the shared `uffs-format` writer.
///
/// This is the thin-client half of the v0.5.62 formatter unification
/// — the CLI receives `Vec<SearchRow>` over IPC and streams them
/// through `uffs_format::write_rows` so its stdout output is
/// byte-identical to the daemon's `--out=file` path (which feeds
/// `DisplayRow`s through the same writer).
///
/// Every accessor is O(1) and just hands back a struct field,
/// matching the trait's inlineability requirement.  `SearchRow`
/// stores `name` separately rather than as a slice into `path` (the
/// JSON wire format cannot carry `name_start` offsets), so the
/// filename accessor returns `&self.name` directly.
impl uffs_format::FormatRow for SearchRow {
    #[inline]
    fn drive(&self) -> char {
        // `uffs-format` is a foundation crate that intentionally
        // doesn't depend on `uffs-mft`, so the trait surface stays
        // `char`-typed.  We translate at this boundary; the cost is
        // one byte read.
        self.drive.as_char()
    }
    #[inline]
    fn path(&self) -> &str {
        &self.path
    }
    #[inline]
    fn name(&self) -> &str {
        &self.name
    }
    #[inline]
    fn size(&self) -> u64 {
        self.size
    }
    #[inline]
    fn is_directory(&self) -> bool {
        self.is_directory
    }
    #[inline]
    fn modified(&self) -> i64 {
        self.modified
    }
    #[inline]
    fn created(&self) -> i64 {
        self.created
    }
    #[inline]
    fn accessed(&self) -> i64 {
        self.accessed
    }
    #[inline]
    fn flags(&self) -> u32 {
        self.flags
    }
    #[inline]
    fn allocated(&self) -> u64 {
        self.allocated
    }
    #[inline]
    fn descendants(&self) -> u32 {
        self.descendants
    }
    #[inline]
    fn treesize(&self) -> u64 {
        self.treesize
    }
    #[inline]
    fn tree_allocated(&self) -> u64 {
        self.tree_allocated
    }
    #[inline]
    fn malformed(&self) -> bool {
        self.malformed
    }
    #[inline]
    fn malformed_path(&self) -> bool {
        self.malformed_path
    }
    #[inline]
    fn name_hex(&self) -> Option<&str> {
        self.name_hex.as_deref()
    }
}

/// Response for the `info` method (all 25 columns for a path).
#[derive(Debug, Serialize, Deserialize)]
pub struct InfoResponse {
    /// Whether the path was found.
    pub found: bool,
    /// File details (if found).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<serde_json::Value>,
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

impl RpcRequest {
    /// Create a new JSON-RPC 2.0 request.
    #[must_use]
    pub fn new(id: u64, method: &str, params: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id: Some(id),
            method: method.to_owned(),
            params,
        }
    }
}

impl RpcResponse {
    /// Create a success response.
    #[must_use]
    pub fn success(id: u64, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result,
        }
    }
}

impl RpcErrorResponse {
    /// Create an error response.
    #[must_use]
    pub fn error(id: Option<u64>, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            error: RpcError {
                code,
                message: message.to_owned(),
                data: None,
            },
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Display Helpers
// ────────────────────────────────────────────────────────────────────────────

/// Format a byte count as human-readable size (e.g. "1.23 MB").
///
/// Routes the `u64 -> f64` conversion through [`crate::format::u64_to_f64`]
/// so this function no longer needs a local `cast_precision_loss` expect.
#[must_use]
#[expect(
    clippy::float_arithmetic,
    reason = "floating-point division is intentional for human-readable size formatting"
)]
pub fn format_size(bytes: u64) -> String {
    let bytes_f64 = crate::format::u64_to_f64(bytes);
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes_f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes_f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes_f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Format a raw FILETIME timestamp as `YYYY-MM-DD HH:MM`.
///
/// Decomposes the FILETIME directly — no intermediate Unix conversion.
/// Every `as u32` narrowing in the Hinnant algorithm goes through
/// `u32::try_from(...).unwrap_or(...)`; the algorithm's intermediate
/// values are bounded (`hour` ∈ `[0, 23]`, `minute` ∈ `[0, 59]`,
/// `doe` ∈ `[0, 146_096]`) so the saturating fallbacks are unreachable
/// for any valid FILETIME.
#[must_use]
pub fn format_time(filetime: i64) -> String {
    const TICKS_PER_SECOND: i64 = 10_000_000; // 100-ns intervals per second
    if filetime == 0 {
        return "—".to_owned();
    }
    let total_secs = filetime / TICKS_PER_SECOND;
    let days_since_1601 = total_secs.div_euclid(86400);
    let day_secs = total_secs.rem_euclid(86400);
    let hour = u32::try_from(day_secs / 3600).unwrap_or(0);
    let minute = u32::try_from((day_secs % 3600) / 60).unwrap_or(0);

    // Hinnant civil_from_days:
    // 719468 (0000-03-01→1970-01-01) − 134774 (1601-01-01→1970-01-01) = 584694
    let z = days_since_1601 + 584_694;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = u32::try_from(z - era * 146_097).unwrap_or(0);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}")
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────
