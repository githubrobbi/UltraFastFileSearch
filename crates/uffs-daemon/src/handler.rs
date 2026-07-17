// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! JSON-RPC request handler: dispatches methods to
//! [`crate::index::IndexManager`].

use uffs_client::protocol::response::{
    DEFAULT_PRELOAD_PIN_MINUTES, FacetValuesParams, FacetValuesResponse, ForgetParams,
    ForgetResponse, HibernateParams, HibernateResponse, LoadDriveParams, LoadDriveResponse,
    PreloadParams, PreloadResponse, RefreshParams, SearchPayload, StatusDrivesResponse,
};
use uffs_client::protocol::{
    AggregateSpecWire, ERR_DRIVE_BUSY, ERR_INVALID_PARAMS, ERR_METHOD_NOT_FOUND, RpcErrorResponse,
    RpcRequest, RpcResponse, SearchParams,
};

/// Maximum pattern length to prevent regex `DoS` (`S4.4.3`).
const MAX_PATTERN_LENGTH: usize = 4096;

use crate::index::IndexManager;
use crate::lifecycle::LifecycleHandle;

// The blob-fast-path helpers (`try_pack_paths_blob`,
// `try_pack_csv_blob`, and their sub-dispatchers) live in a sibling
// file to keep `handler.rs` under the 800-line policy ceiling.
// `#[path]` keeps them attached to the same `impl RequestHandler`,
// so every caller (including `handle_search` below and the
// `handler::tests` suite) uses the normal
// `Self::try_pack_paths_blob(...)` method syntax — no call-site changes.
#[path = "handler_blob.rs"]
mod blob;

// `ParseSearchParamsError` lives in its own sibling file for the same
// 800-LOC policy reason and to keep the typed-error introduction
// physically separate from the dispatcher.  Re-exporting the type
// here lets every call site (and the co-located test module) refer
// to it unqualified.
#[path = "handler_parse_search_params.rs"]
mod parse_search_params;
use parse_search_params::ParseSearchParamsError;

// `diff_search_response` (the snapshot-diff error mapping) lives in a sibling
// file for the same 800-LOC policy reason as `handler_blob.rs`; `#[path]` keeps
// it an `impl RequestHandler` method the dispatcher calls as
// `self.diff_search_response(...)`.
#[path = "handler_diff.rs"]
mod diff_handler;

/// Request handler holding shared daemon state.
pub(crate) struct RequestHandler {
    /// Shared index manager.
    pub index: alloc::sync::Arc<IndexManager>,
    /// Lifecycle handle for idle timer, shutdown, connections.
    pub lifecycle: LifecycleHandle,
}

impl RequestHandler {
    /// Handle a single JSON-RPC request and return a JSON response string.
    pub(crate) async fn handle(&self, req: &RpcRequest) -> String {
        // Every incoming request — search, drives, status, keepalive, etc. —
        // extends the daemon's sliding-window idle deadline.  This is the
        // single authoritative call site; individual handlers do not need to
        // repeat it (keepalive still calls it for documentation clarity, but
        // that is idempotent: `notify_one` stores at most one permit).
        self.lifecycle.reset_idle_timer();

        let id = req.id.unwrap_or(0_u64);
        let connections = self.lifecycle.active_connections();

        match req.method.as_str() {
            "search" => self.handle_search(id, req).await,
            "drives" => self.handle_drives(id).await,
            "status" => self.handle_status(id, connections).await,
            "search_cli" => self.handle_search_cli(id, req).await,
            "stats" => self.handle_stats(id).await,
            "info" => self.handle_info(id, req).await,
            "load_drive" => self.handle_load_drive(id, req).await,
            "refresh" => self.handle_refresh(id, req),
            "facet_values" => self.handle_facet_values(id, req).await,
            "keepalive" => self.handle_keepalive(id, req),
            "shutdown" => self.handle_shutdown(id, req),
            // Phase 8-B … 8-E — operator-driven memory tiering.
            // Phase 8-A scaffolded these arms with NotImplemented
            // stubs; sub-phases 8-B / 8-C / 8-D / 8-E filled in
            // `hibernate`, `preload`, `forget`, and `status_drives`
            // respectively.
            "hibernate" => self.handle_hibernate(id, req).await,
            "preload" => self.handle_preload(id, req).await,
            "forget" => self.handle_forget(id, req).await,
            "status_drives" => self.handle_status_drives(id).await,
            _ => serde_json::to_string(&RpcErrorResponse::error(
                Some(id),
                ERR_METHOD_NOT_FOUND,
                &format!("Method not found: {}", req.method),
            ))
            .unwrap_or_default(),
        }
    }

    /// Handle `search` method.
    async fn handle_search(&self, id: u64, req: &RpcRequest) -> String {
        let search_params = match Self::parse_and_validate_search_params(req) {
            Ok(params) => params,
            Err(parse_err) => return parse_err.to_rpc_error_json(id),
        };
        let search_started = std::time::Instant::now();
        tracing::info!(
            pattern = %search_params.pattern,
            drives = ?search_params.drives,
            path_contains = ?search_params.path_contains,
            "search: request received"
        );

        self.auto_load_missing_drives(&search_params.drives).await;

        // A `--diff <baseline>` routes to the snapshot-diff path (which may
        // early-return a JSON-RPC error); everything else is a live search.
        // Row count is captured up-front (by `run_search_or_diff`) for
        // logging and threshold dispatch: both blob-packing and
        // shmem-rows routing may replace the payload variant in-place,
        // at which point `response.payload.row_count_hint()` returns
        // `None` (for blob variants) or a stale value (for consumed rows).
        let (mut response, row_count) = match self
            .run_search_or_diff(id, &search_params, search_started)
            .await
        {
            Ok(result) => result,
            Err(error_json) => return error_json,
        };

        // Path-only single-buffer fast path (see `try_pack_paths_blob`).
        // May replace `response.payload` with `InlineBlob` or `ShmemBlob`.
        Self::try_pack_paths_blob(&search_params, &mut response);

        // Multi-column CSV pre-format fast path (see `try_pack_csv_blob`).
        // Runs after `try_pack_paths_blob` so the path-only check gets
        // first crack at the rows; when it consumes the payload this
        // method short-circuits on the non-`InlineRows` guard.
        Self::try_pack_csv_blob(&search_params, &mut response);

        // D5.1: adaptive routing — use shmem rows for large multi-column
        // result sets that did NOT qualify for the blob fast path.
        let shmem_ms = Self::route_via_shmem_if_needed(&mut response, row_count);

        // Back-patch serialize_ms into the profile with shmem write time
        // (the dominant cost).  JSON serialization time is measured
        // below but can't be included in the JSON itself (chicken-and-egg).
        if let Some(ref mut prof) = response.profile {
            prof.serialize_ms = u64::try_from(shmem_ms).unwrap_or(u64::MAX);
        }

        let t_serialize = std::time::Instant::now();
        let result = serde_json::to_value(&response).unwrap_or_default();
        let json = serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default();
        let ser_ms = t_serialize.elapsed().as_millis();

        if row_count > 10_000 || ser_ms > 100 {
            tracing::info!(
                rows = row_count,
                serialize_ms = ser_ms,
                json_bytes = json.len(),
                payload_kind = Self::payload_kind_name(&response.payload),
                "🔌 search response serialized"
            );
        }

        json
    }

    /// Decode `req.params` into a [`SearchParams`] and enforce
    /// [`MAX_PATTERN_LENGTH`].
    ///
    /// Phase 5d migration: previously this returned
    /// `Result<SearchParams, String>` where the `String` was a
    /// pre-serialised JSON-RPC error body.  The serialisation concern
    /// has been hoisted to [`ParseSearchParamsError::to_rpc_error_json`]
    /// at the wire boundary so the parser expresses only the domain
    /// concern ("did the params parse?") and the request `id` no
    /// longer threads through this private helper.
    ///
    /// # Errors
    ///
    /// Returns [`ParseSearchParamsError::MissingOrInvalidParams`] when
    /// `req.params` is absent or fails to deserialise as
    /// [`SearchParams`]; returns
    /// [`ParseSearchParamsError::PatternTooLong`] when
    /// `search_params.pattern` exceeds [`MAX_PATTERN_LENGTH`] (S4.4.3
    /// regex-DoS guard).  The wire bytes produced by
    /// [`ParseSearchParamsError::to_rpc_error_json`] are byte-identical
    /// with the pre-Phase-5d output so clients see no change.
    fn parse_and_validate_search_params(
        req: &RpcRequest,
    ) -> Result<SearchParams, ParseSearchParamsError> {
        let search_params: SearchParams = req
            .params
            .as_ref()
            .and_then(|val| serde_json::from_value::<SearchParams>(val.clone()).ok())
            .ok_or(ParseSearchParamsError::MissingOrInvalidParams)?;

        // S4.4.3: Reject overly long patterns (regex DoS prevention).
        if search_params.pattern.len() > MAX_PATTERN_LENGTH {
            return Err(ParseSearchParamsError::PatternTooLong {
                len: search_params.pattern.len(),
            });
        }

        Ok(search_params)
    }

    /// Adaptive shmem routing for large multi-column result sets.
    ///
    /// Only fires when the payload is still `InlineRows` above the
    /// shmem threshold — blob variants already consumed the rows, so
    /// taking the `ShmemRows` branch there would write an empty row
    /// table and waste the file-creation syscall.
    ///
    /// Returns the shmem-write duration in milliseconds (or 0 when the
    /// fast path was not entered) so the caller can patch
    /// `SearchProfile::serialize_ms` accordingly.
    fn route_via_shmem_if_needed(
        response: &mut uffs_client::protocol::response::SearchResponse,
        row_count: usize,
    ) -> u128 {
        let SearchPayload::InlineRows(rows) = &response.payload else {
            return 0;
        };
        if rows.len() <= uffs_client::shmem::SHMEM_THRESHOLD {
            return 0;
        }

        let t_shmem = std::time::Instant::now();
        match uffs_client::shmem::write_search_results(
            rows,
            response.duration_ms,
            response.records_scanned as u64,
            response.truncated,
        ) {
            Ok(path) => {
                let shmem_ms = t_shmem.elapsed().as_millis();
                let count = rows.len() as u64;
                let path_str = path.to_string_lossy().into_owned();
                tracing::info!(
                    rows = row_count,
                    shmem_write_ms = shmem_ms,
                    path = %path_str,
                    "🗂️ shmem: wrote bulk results"
                );
                // Swap the payload to `ShmemRows` — consumes the
                // inline `Vec<SearchRow>` so no double delivery.
                response.payload = SearchPayload::ShmemRows {
                    path: path_str,
                    count,
                };
                shmem_ms
            }
            Err(shmem_err) => {
                let shmem_ms = t_shmem.elapsed().as_millis();
                tracing::warn!(
                    error = %shmem_err,
                    rows = row_count,
                    shmem_write_ms = shmem_ms,
                    "shmem write failed; falling back to inline JSON"
                );
                // Fall through — send inline (may be slow for very
                // large result sets, but at least it works).
                shmem_ms
            }
        }
    }

    /// Short human-readable name for the payload variant.
    ///
    /// Used by the serialised-response log line to replace the old
    /// boolean `shmem = …` field: the new enum has five variants, so
    /// a single `kind` string is more informative than any one bool.
    const fn payload_kind_name(payload: &SearchPayload) -> &'static str {
        match payload {
            SearchPayload::Empty => "empty",
            SearchPayload::InlineRows(_) => "inline_rows",
            SearchPayload::ShmemRows { .. } => "shmem_rows",
            SearchPayload::InlineBlob(_) => "inline_blob",
            SearchPayload::ShmemBlob(_) => "shmem_blob",
        }
    }

    /// Handle `search_cli` method — parse raw CLI args into [`SearchParams`]
    /// and run the standard search.
    ///
    /// The CLI sends its raw `argv` (after subcommand detection) so it
    /// never needs to parse search flags locally.
    async fn handle_search_cli(&self, id: u64, req: &RpcRequest) -> String {
        // Extract the `args` array from the params.
        let args: Vec<String> = match req
            .params
            .as_ref()
            .and_then(|val| val.get("args"))
            .and_then(|val| serde_json::from_value(val.clone()).ok())
        {
            Some(cli_args) => cli_args,
            None => {
                return serde_json::to_string(&RpcErrorResponse::error(
                    Some(id),
                    ERR_INVALID_PARAMS,
                    "Missing or invalid 'args' array",
                ))
                .unwrap_or_default();
            }
        };

        // Parse into SearchParams using the shared CLI parser.
        //
        // Phase 5d: `from_cli_args` now returns a typed
        // `uffs_client::protocol::cli_args::Error` (alias of
        // `CliArgsError`) whose Display string is byte-identical with
        // the pre-Phase-5d `String` payload, so the JSON-RPC error
        // message stays unchanged.
        let search_params = match SearchParams::from_cli_args(&args) {
            Ok(params) => params,
            Err(err) => {
                return serde_json::to_string(&RpcErrorResponse::error(
                    Some(id),
                    ERR_INVALID_PARAMS,
                    &err.to_string(),
                ))
                .unwrap_or_default();
            }
        };

        // Construct a synthetic RpcRequest with the parsed params
        // and delegate to the standard search handler.
        let search_req = RpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(id),
            method: "search".to_owned(),
            params: serde_json::to_value(&search_params).ok(),
        };
        self.handle_search(id, &search_req).await
    }

    /// Handle `stats` method — performance metrics.
    async fn handle_stats(&self, id: u64) -> String {
        let response = self.index.stats().await;
        let result = serde_json::to_value(&response).unwrap_or_default();
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }

    /// Handle `drives` method.
    async fn handle_drives(&self, id: u64) -> String {
        let response = self.index.drives().await;
        let result = serde_json::to_value(&response).unwrap_or_default();
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }

    /// Handle `status` method.
    async fn handle_status(&self, id: u64, connections: usize) -> String {
        let response = self.index.status(connections).await;
        let result = serde_json::to_value(&response).unwrap_or_default();
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }

    /// Handle `info` method — look up a file by path.
    async fn handle_info(&self, id: u64, req: &RpcRequest) -> String {
        let file_path = req
            .params
            .as_ref()
            .and_then(|val| val.get("path"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        if file_path.is_empty() {
            return serde_json::to_string(&RpcErrorResponse::error(
                Some(id),
                ERR_INVALID_PARAMS,
                "Missing 'path' parameter",
            ))
            .unwrap_or_default();
        }

        let response = self.index.info(file_path).await;
        let result = serde_json::to_value(&response).unwrap_or_default();
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }

    /// Handle `facet_values` method — convenience wrapper for distinct
    /// field values with counts.
    ///
    /// Translates to a `search` call with a `terms` aggregation, then
    /// reshapes the response to return just the values and pagination.
    async fn handle_facet_values(&self, id: u64, req: &RpcRequest) -> String {
        let fv_params: FacetValuesParams = req
            .params
            .as_ref()
            .and_then(|val| serde_json::from_value(val.clone()).ok())
            .unwrap_or_default();

        // Build a terms aggregation spec for the requested field.
        // `top` controls how many distinct values the engine computes.
        // We always ask for all values (up to u16::MAX) and rely on
        // `agg_page_size` to paginate the wire response.
        let agg_spec = AggregateSpecWire {
            kind: "terms".to_owned(),
            label: Some(format!("facet_{}", fv_params.field)),
            field: Some(fv_params.field.clone()),
            top: Some(u16::MAX),
            metrics: vec!["count".to_owned(), "total_bytes".to_owned()],
            ..AggregateSpecWire::default()
        };

        let search_params = SearchParams {
            pattern: fv_params.pattern,
            aggregations: vec![agg_spec],
            include_rows: false,
            limit: Some(0),
            agg_cursor: fv_params.cursor,
            agg_page_size: fv_params.page_size,
            ..Default::default()
        };

        let response = self.index.search(&search_params).await;

        // Extract the first aggregation result.
        let (values, next_cursor, total_distinct) = response.aggregations.first().map_or_else(
            || (vec![], None, None),
            |agg| {
                (
                    agg.buckets.clone(),
                    agg.next_cursor.clone(),
                    agg.total_groups,
                )
            },
        );

        let fv_response = FacetValuesResponse {
            field: fv_params.field,
            values,
            total_distinct,
            next_cursor,
        };

        let result = serde_json::to_value(&fv_response).unwrap_or_default();
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }

    /// Handle `load_drive` method — hot-load MFT files into the daemon.
    async fn handle_load_drive(&self, id: u64, req: &RpcRequest) -> String {
        let params: LoadDriveParams = req
            .params
            .as_ref()
            .and_then(|val| serde_json::from_value(val.clone()).ok())
            .unwrap_or_default();

        let mut loaded: Vec<uffs_mft::platform::DriveLetter> = Vec::new();
        let mut already_loaded: Vec<uffs_mft::platform::DriveLetter> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        // Hot-load by MFT file path.
        for mft_file in &params.mft_files {
            let path = std::path::PathBuf::from(mft_file);
            match self
                .index
                .load_single_mft_file(&path, params.no_cache)
                .await
            {
                Ok(Some(letter)) => loaded.push(letter),
                Ok(None) => {
                    // Infer the drive letter from the file stem for
                    // reporting.  Falls back to `DriveLetter::X` for
                    // malformed filenames — matches the historical
                    // `'?'` sentinel behaviour (rows get bucketed
                    // under the "unknown" letter).
                    let letter = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .and_then(|stem| stem.chars().next())
                        .and_then(|ch| uffs_mft::platform::DriveLetter::parse(ch).ok())
                        .unwrap_or(uffs_mft::platform::DriveLetter::X);
                    already_loaded.push(letter);
                }
                Err(load_err) => {
                    errors.push(format!("{}: {load_err}", path.display()));
                }
            }
        }

        // Hot-load by drive letter (live NTFS on Windows, data_dir on other
        // platforms).
        for &letter in &params.drives {
            match self.index.hot_load_drive(letter, params.no_cache).await {
                Ok(records) => {
                    tracing::info!(drive = %letter, records, "Drive hot-loaded via RPC");
                    // `DriveLetter` is uppercase by construction; no
                    // remap needed before push.
                    loaded.push(letter);
                }
                Err(load_err) => {
                    errors.push(format!("{letter}: {load_err}"));
                }
            }
        }

        let response = LoadDriveResponse {
            loaded,
            already_loaded,
            errors,
        };
        let result = serde_json::to_value(&response).unwrap_or_default();
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }

    /// Handle `refresh` method — spawns refresh in background, returns
    /// immediate ack.
    ///
    /// # Task ownership
    ///
    /// The spawned refresh task is **fire-and-forget** — the
    /// `JoinHandle` is intentionally discarded.  The closure captures
    /// an `Arc<IndexManager>` clone, keeping the manager alive for the
    /// refresh duration even if the original client connection drops.
    ///
    /// * **Owner:** none held; the runtime owns the task.
    /// * **Shutdown:** none — [`IndexManager::refresh`] runs to completion
    ///   regardless of daemon shutdown signal.  Acceptable because refresh is
    ///   short-lived (seconds), and the daemon's
    ///   `await_shutdown_then_force_exit` watchdog will `process::exit` after
    ///   the load-task timeout, terminating any in-flight refresh with the
    ///   runtime.
    /// * **Error obs.:** [`IndexManager::refresh`] logs internally; no upward
    ///   propagation.  The immediate ack returned to the client asserts only
    ///   that the refresh was scheduled, not that it succeeded — clients poll
    ///   `status` for completion.
    /// * **Cancel behavior:** not cancellable; runs to completion or process
    ///   exit.
    ///
    /// See Phase 10c task-ownership inventory.
    ///
    /// [`IndexManager::refresh`]: crate::index::IndexManager::refresh
    fn handle_refresh(&self, id: u64, req: &RpcRequest) -> String {
        let refresh_params: RefreshParams = req
            .params
            .as_ref()
            .and_then(|val| serde_json::from_value(val.clone()).ok())
            .unwrap_or_default();

        let idx_clone = alloc::sync::Arc::clone(&self.index);
        tokio::spawn(async move {
            idx_clone.refresh(&refresh_params.drives).await;
        });

        let result = serde_json::json!({"ok": true, "message": "refresh started"});
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }

    /// Handle `keepalive` method.
    ///
    /// D3.4.3: Also processes optional `session_type` parameter to set
    /// differentiated idle timeout tier.
    fn handle_keepalive(&self, id: u64, req: &RpcRequest) -> String {
        self.lifecycle.reset_idle_timer();

        // D3.4.3: If session_type is provided, update the timeout tier
        if let Some(session_type) = req
            .params
            .as_ref()
            .and_then(|val| val.get("session_type"))
            .and_then(serde_json::Value::as_str)
        {
            self.lifecycle.set_session_type(session_type);
        }

        let result = serde_json::json!({"ok": true});
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }

    /// Handle `hibernate` method (Phase 8-B).
    ///
    /// Parses [`HibernateParams`] from the JSON-RPC envelope, walks
    /// the registry via [`IndexManager::hibernate_shards`], and
    /// returns the structured [`HibernateResponse`] reporting
    /// drives demoted from each pre-call tier plus drives that were
    /// already at the bottom.
    ///
    /// Empty `drives` in the params means "every loaded drive";
    /// non-matching letters in a non-empty `drives` filter are
    /// silently dropped (the operator audit lives on the
    /// `already_cold` field of the response, which lists only
    /// drives the daemon actually knows about).
    ///
    /// Malformed params (anything that fails to deserialise as
    /// [`HibernateParams`]) fall back to the empty-default
    /// (hibernate every drive); the wire contract is "best-effort
    /// match" rather than "strict reject" because the all-loaded
    /// path is always safe and an over-strict reject would surprise
    /// scripts that send slightly-non-canonical JSON.
    async fn handle_hibernate(&self, id: u64, req: &RpcRequest) -> String {
        let params: HibernateParams = req
            .params
            .as_ref()
            .and_then(|val| serde_json::from_value(val.clone()).ok())
            .unwrap_or_default();
        let outcome = self.index.hibernate_shards(&params.drives).await;
        let response = HibernateResponse {
            hot_demoted: outcome.hot_demoted,
            warm_demoted: outcome.warm_demoted,
            parked_demoted: outcome.parked_demoted,
            already_cold: outcome.already_cold,
        };
        let result = serde_json::to_value(&response).unwrap_or_default();
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }

    /// Handle `preload` method (Phase 8-C).
    ///
    /// Parses [`PreloadParams`] from the JSON-RPC envelope, loops
    /// over the requested drives calling
    /// [`IndexManager::preload_drive`] for each, and aggregates the
    /// per-drive [`crate::index::tiering_ops::PreloadOutcome`]s into
    /// a single [`PreloadResponse`].
    ///
    /// Validates that the params include at least one drive — an
    /// empty `drives` vector returns [`ERR_INVALID_PARAMS`] so a
    /// caller's mistyped script doesn't silently succeed.  The pin
    /// duration defaults to [`DEFAULT_PRELOAD_PIN_MINUTES`] when
    /// the params omit `pin_minutes`.
    async fn handle_preload(&self, id: u64, req: &RpcRequest) -> String {
        let params: PreloadParams = req
            .params
            .as_ref()
            .and_then(|val| serde_json::from_value(val.clone()).ok())
            .unwrap_or_default();
        if params.drives.is_empty() {
            return serde_json::to_string(&RpcErrorResponse::error(
                Some(id),
                ERR_INVALID_PARAMS,
                "preload: `drives` must contain at least one drive letter",
            ))
            .unwrap_or_default();
        }
        let pin_minutes = params.pin_minutes.unwrap_or(DEFAULT_PRELOAD_PIN_MINUTES);

        let mut promoted: Vec<uffs_mft::platform::DriveLetter> = Vec::new();
        let mut already_hot: Vec<uffs_mft::platform::DriveLetter> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let mut latest_pin_until_ms: i64 = 0;

        for &letter in &params.drives {
            use crate::index::tiering_ops::PreloadOutcome;
            match self.index.preload_drive(letter, pin_minutes).await {
                PreloadOutcome::Promoted { pin_until_ms, .. } => {
                    promoted.push(letter);
                    latest_pin_until_ms = i64::try_from(pin_until_ms).unwrap_or(i64::MAX);
                }
                PreloadOutcome::AlreadyHot { pin_until_ms } => {
                    already_hot.push(letter);
                    latest_pin_until_ms = i64::try_from(pin_until_ms).unwrap_or(i64::MAX);
                }
                PreloadOutcome::UnknownDrive => {
                    errors.push(format!("{letter}: drive not loaded"));
                }
                PreloadOutcome::LoadFailed => {
                    errors.push(format!("{letter}: body load failed"));
                }
                PreloadOutcome::Busy { from_state } => {
                    errors.push(format!(
                        "{letter}: drive busy in transient state ({from_state})"
                    ));
                }
            }
        }

        let response = PreloadResponse {
            promoted,
            already_hot,
            errors,
            pin_until_unix_ms: latest_pin_until_ms,
        };
        let result = serde_json::to_value(&response).unwrap_or_default();
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }

    /// Handle `forget` method (Phase 8-D).
    ///
    /// Parses [`ForgetParams`] from the JSON-RPC envelope and
    /// dispatches to [`IndexManager::forget_drives`].  Empty
    /// `drives` is rejected up-front with [`ERR_INVALID_PARAMS`];
    /// non-`Cold` drives without `force = true` produce a
    /// top-level [`ERR_DRIVE_BUSY`] refusal listing the busy
    /// drives.  Successful runs return [`ForgetResponse`] populated
    /// from [`crate::index::forget_drive::ForgetOutcome`].
    async fn handle_forget(&self, id: u64, req: &RpcRequest) -> String {
        use crate::index::forget_drive::ForgetOutcomeOrBusy;

        let params: ForgetParams = req
            .params
            .as_ref()
            .and_then(|val| serde_json::from_value(val.clone()).ok())
            .unwrap_or_default();
        if params.drives.is_empty() {
            return serde_json::to_string(&RpcErrorResponse::error(
                Some(id),
                ERR_INVALID_PARAMS,
                "forget: `drives` must contain at least one drive letter",
            ))
            .unwrap_or_default();
        }

        match self.index.forget_drives(&params.drives, params.force).await {
            ForgetOutcomeOrBusy::Busy(busy) => {
                let listing = busy
                    .iter()
                    .map(|(letter, state)| format!("{letter} ({state})"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let message = format!(
                    "forget refused: drive(s) busy: {listing}. \
                     Pass `force = true` to auto-hibernate first."
                );
                serde_json::to_string(&RpcErrorResponse::error(Some(id), ERR_DRIVE_BUSY, &message))
                    .unwrap_or_default()
            }
            ForgetOutcomeOrBusy::Ok(outcome) => {
                let response = ForgetResponse {
                    forgotten: outcome.forgotten,
                    already_absent: outcome.already_absent,
                    freed_bytes: outcome.freed_bytes,
                    errors: outcome.errors,
                };
                let result = serde_json::to_value(&response).unwrap_or_default();
                serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
            }
        }
    }

    /// Handle `status_drives` method (Phase 8-E).
    ///
    /// No params — the unit-struct
    /// [`uffs_client::protocol::response::StatusDrivesParams`]
    /// serialises as `{}` so callers omitting the envelope flow
    /// through unchanged.  Dispatches to
    /// [`IndexManager::status_drives`] and returns the per-drive
    /// tier + telemetry snapshot directly.
    async fn handle_status_drives(&self, id: u64) -> String {
        let response: StatusDrivesResponse = self.index.status_drives().await;
        let result = serde_json::to_value(&response).unwrap_or_default();
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }

    /// Handle `shutdown` method.
    ///
    /// `S4.4.9`: Requires a `nonce` parameter matching the one in the PID file.
    /// This prevents unauthorized shutdown via the socket.
    fn handle_shutdown(&self, id: u64, req: &RpcRequest) -> String {
        let provided_nonce = req
            .params
            .as_ref()
            .and_then(|val| val.get("nonce"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        if !self.lifecycle.verify_shutdown_nonce(provided_nonce) {
            return serde_json::to_string(&RpcErrorResponse::error(
                Some(id),
                ERR_INVALID_PARAMS,
                "Invalid or missing shutdown nonce (read from daemon.pid file)",
            ))
            .unwrap_or_default();
        }

        self.lifecycle.request_shutdown();
        let result = serde_json::json!({"ok": true, "message": "shutting down"});
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }
}

// Tests live in two sibling files so neither exceeds the 800-line
// policy ceiling: `handler_paths_blob_tests.rs` covers the path-only
// fast path (`try_pack_paths_blob`), and `handler_csv_blob_tests.rs`
// covers the multi-column / parity / `--format custom` fast path
// (`try_pack_csv_blob`).  `#[path]` keeps each attached as a child
// of `handler` so `super::` from within the tests still resolves
// against `handler`'s scope, including private items like
// `RequestHandler::core_config_to_format` the shmem byte-parity
// test calls into.
#[cfg(test)]
#[path = "handler_paths_blob_tests.rs"]
mod paths_blob_tests;

#[cfg(test)]
#[path = "handler_csv_blob_tests.rs"]
mod csv_blob_tests;

#[cfg(test)]
#[path = "handler_parse_search_params_tests.rs"]
mod parse_search_params_tests;
