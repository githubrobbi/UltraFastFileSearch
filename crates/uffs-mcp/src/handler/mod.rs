// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! MCP [`ServerHandler`](rmcp::ServerHandler) implementation — bridges rmcp to
//! the UFFS daemon.
//!
//! This is the core of the MCP server.  It implements the rmcp
//! [`ServerHandler`](rmcp::ServerHandler) trait, dispatching `tools/call`,
//! `resources/read`, and `prompts/get` to the appropriate handlers.

use crate::handler::definitions::percent_decode_path;

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use rmcp::model::{
    CallToolRequestParams, CallToolResult, GetPromptRequestParams, GetPromptResult, Implementation,
    ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult, ListToolsResult,
    PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResult, Resource,
    ResourceContents, ResourceTemplate, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde_json::Value;
use uffs_client::connect::UffsClient;

use crate::error::BridgeError;
use crate::roots::{self, SharedRootsState};
use crate::stats::McpStats;
use crate::tools;

pub mod definitions;
pub(crate) mod instructions;
pub mod prompts;

use definitions::is_known_tool;
use instructions::AGENT_INSTRUCTIONS;

/// Connection strategy for the daemon client.
///
/// The MCP server does **not** cache a shared daemon connection.  Every
/// tool call (and every daemon-backed resource read) opens a fresh
/// [`UffsClient`] via [`UffsClient::connect_with_args`] and drops it when
/// the call completes.  Rationale:
///
/// * **Per-request independence.** No shared `Mutex` across async boundaries,
///   so a slow query never head-of-line-blocks other in-flight requests.  rmcp
///   already dispatches each `tools/call` on its own task; a per-call
///   connection is what lets those tasks actually run in parallel all the way
///   down to the daemon.
/// * **Capacity is owned by the daemon.** `uffs-daemon` caps concurrent
///   searches with a tuned `Semaphore` (`max(2, (cpus × 26) / (drives × 10))`
///   by default — roughly `2.6 × cpus / drives` — overridable via
///   `UFFS_SEARCH_MAX_CONCURRENCY`) and internally fans each query out via
///   rayon, so any MCP-side pool would be redundant (and worse, a potential
///   extra bottleneck).
/// * **Local-socket connect is sub-millisecond.** On Unix domain sockets /
///   Windows named pipes the per-call overhead is far below the cost of the
///   query itself.  Auto-reconnect is a natural side-effect: if the daemon
///   restarted between calls, the next call just opens a new connection and
///   succeeds.
enum ClientSlot {
    /// Active mode — `spawn_args` are forwarded to
    /// [`UffsClient::connect_with_args`] on every daemon-backed call.
    Active {
        /// Args forwarded to `uffs --daemon run` on auto-start.
        spawn_args: Vec<std::ffi::OsString>,
    },
    /// No daemon — metadata-only / testing.
    None,
}

/// The UFFS MCP server — wraps a daemon client and dispatches MCP requests.
///
/// # Field discipline (Phase 3b §3.4)
///
/// All fields are **private**; construction goes through one of
/// [`Self::new`], [`Self::new_lazy`], [`Self::new_unconnected`], or
/// the `pub(crate)` `Self::new_lazy_with_stats`.  This preserves
/// the invariant that every server instance has a `ClientSlot`, a
/// fresh `last_activity` epoch, and an `McpStats` shared handle —
/// none of which a caller should be poking at directly.
///
/// # `#[non_exhaustive]` decision (Phase 3b §3.6)
///
/// **N/A** — no `pub` fields means there is nothing for callers to
/// match exhaustively or struct-literal-construct from outside the
/// crate.  Future fields slot in without any API impact.
pub struct UffsMcpServer {
    /// Daemon connection strategy (active with `spawn_args`, or none).
    slot: ClientSlot,
    /// Current roots state (updated via `on_roots_list_changed`).
    roots: SharedRootsState,
    /// Timestamp of the last MCP activity (tool call, resource read, etc.).
    /// Used by the idle-timeout logic in [`crate::run_mcp_server_with_config`].
    last_activity: Arc<AtomicU64>,
    /// Runtime statistics (shared across sessions in HTTP mode).
    stats: Arc<McpStats>,
}

impl UffsMcpServer {
    /// Create a new server that dispatches to the daemon identified by
    /// `spawn_args` (which are forwarded to
    /// [`UffsClient::connect_with_args`] on every tool call).
    ///
    /// Callers that have already run a readiness check against the
    /// daemon should simply drop their [`UffsClient`] before calling
    /// this — the first dispatched tool call will open its own fresh
    /// connection.  See the private `ClientSlot` enum for the
    /// rationale behind the per-call connection model.
    #[must_use]
    pub fn new(spawn_args: Vec<std::ffi::OsString>) -> Self {
        Self::with_stats(
            ClientSlot::Active { spawn_args },
            Arc::new(McpStats::default()),
        )
    }

    /// Create a server that lazily connects to the daemon on first tool call.
    ///
    /// Semantically identical to [`Self::new`] under the per-call
    /// connection model; retained as a distinct constructor because the
    /// HTTP gateway factory closure calls it explicitly.
    #[must_use]
    pub fn new_lazy(spawn_args: Vec<std::ffi::OsString>) -> Self {
        Self::new_lazy_with_stats(spawn_args, Arc::new(McpStats::default()))
    }

    /// Create a lazy server with shared stats (for HTTP gateway).
    #[must_use]
    pub(crate) fn new_lazy_with_stats(
        spawn_args: Vec<std::ffi::OsString>,
        stats: Arc<McpStats>,
    ) -> Self {
        stats.session_started();
        Self::with_stats(ClientSlot::Active { spawn_args }, stats)
    }

    /// Create a server without a daemon connection.
    ///
    /// Listing tools/resources/prompts works, but calling tools that need the
    /// daemon will return an error.  Useful for testing and metadata
    /// introspection.
    #[must_use]
    pub fn new_unconnected() -> Self {
        Self::with_stats(ClientSlot::None, Arc::new(McpStats::default()))
    }

    /// Internal constructor.
    fn with_stats(slot: ClientSlot, stats: Arc<McpStats>) -> Self {
        Self {
            slot,
            roots: SharedRootsState::default(),
            last_activity: Arc::new(AtomicU64::new(Self::now_secs())),
            stats,
        }
    }

    /// Get a shared handle to the stats for the HTTP `/status` endpoint.
    #[must_use]
    pub const fn stats(&self) -> &Arc<McpStats> {
        &self.stats
    }

    /// Get a shared handle to the last-activity timestamp for the idle
    /// timeout loop.
    #[must_use]
    pub(crate) fn last_activity_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.last_activity)
    }

    /// Record that the server just handled an MCP request.
    fn touch(&self) {
        self.last_activity
            .store(Self::now_secs(), Ordering::Relaxed);
    }

    /// Current time as seconds since the Unix epoch.
    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |dur| dur.as_secs())
    }

    /// Open a fresh daemon connection for a single tool call or
    /// resource read.
    ///
    /// This is the sole entry point for acquiring a [`UffsClient`]
    /// inside the handler.  Each caller gets its own connection, so
    /// concurrent requests are fully independent — a slow query on one
    /// connection cannot stall any other connection.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::Daemon`] if the daemon cannot be reached
    /// (after `UffsClient`'s own retry / auto-start logic has failed)
    /// or if the server was constructed without a daemon backend
    /// (`ClientSlot::None`).
    async fn connect_daemon(&self) -> Result<UffsClient, BridgeError> {
        match &self.slot {
            ClientSlot::Active { spawn_args } => UffsClient::connect_with_args(spawn_args)
                .await
                .map_err(|err| BridgeError::Daemon(err.to_string())),
            ClientSlot::None => Err(BridgeError::Daemon("Not connected to daemon".to_owned())),
        }
    }

    /// Read-only access to the shared roots state.
    #[must_use]
    pub const fn roots(&self) -> &SharedRootsState {
        &self.roots
    }
}

impl UffsMcpServer {
    /// Gate on daemon readiness — returns `Err` if the daemon is still
    /// loading drives so the LLM receives a transient error and retries.
    ///
    /// Returns `Ok(())` when ready.
    async fn readiness_gate(client: &mut UffsClient) -> Result<(), BridgeError> {
        use uffs_client::protocol::response::DaemonStatus;
        let status = client
            .status()
            .await
            .map_err(|err| BridgeError::Daemon(format!("readiness check failed: {err}")))?;
        match status.status {
            DaemonStatus::Loading {
                drives_loaded,
                drives_total,
            } => Err(BridgeError::Daemon(format!(
                "⏳ Daemon is starting up — {drives_loaded}/{drives_total} drives loaded. \
                 Please retry in a few seconds."
            ))),
            DaemonStatus::Ready | DaemonStatus::Refreshing { .. } => Ok(()),
        }
    }

    /// Dispatch a single tool call to the appropriate handler.
    ///
    /// Separated from `call_tool` so the retry-on-reconnect logic can
    /// call it a second time with the same arguments.
    ///
    /// # Concurrency
    ///
    /// Snapshots the [`RootsState`] upfront via `.read().await.clone()`
    /// rather than holding the read guard across the daemon-RPC tool
    /// dispatch awaits below.  Without the snapshot, the guard would
    /// be held for the duration of every tool call (potentially
    /// seconds for a large `uffs_search` / `uffs_aggregate`), blocking
    /// any concurrent [`ServerHandler::on_roots_list_changed`] writer
    /// — which acquires `self.roots.write().await` to refresh the
    /// state — for the duration of every in-flight tool call across
    /// the whole MCP session.  Cloning `RootsState` is cheap (small
    /// `Vec<RootScope>` of typically `< 10` short-string entries; see
    /// the type's rustdoc).  See Phase 10b audit findings.
    ///
    /// [`RootsState`]: crate::roots::RootsState
    /// [`ServerHandler::on_roots_list_changed`]: rmcp::handler::server::ServerHandler::on_roots_list_changed
    async fn dispatch_tool(
        &self,
        tool_name: &str,
        args: serde_json::Map<String, Value>,
    ) -> Result<CallToolResult, BridgeError> {
        let mut client = self.connect_daemon().await?;

        // Gate: don't run queries against a partially-loaded daemon.
        // The `uffs_status` tool is exempt so the agent can check
        // readiness explicitly.
        if tool_name != "uffs_status" {
            Self::readiness_gate(&mut client).await?;
        }

        let roots_state = self.roots.read().await.clone();

        match tool_name {
            "uffs_search" => {
                let parsed = serde_json::from_value(Value::Object(args)).map_err(|err| {
                    BridgeError::InvalidParam {
                        name: "arguments",
                        reason: err.to_string(),
                    }
                })?;
                tools::search::run(&mut client, parsed, &roots_state).await
            }
            "uffs_drives" => tools::drives::run(&mut client).await,
            "uffs_status" => tools::status::run(&mut client).await,
            "uffs_info" => {
                let parsed = serde_json::from_value(Value::Object(args)).map_err(|err| {
                    BridgeError::InvalidParam {
                        name: "arguments",
                        reason: err.to_string(),
                    }
                })?;
                tools::info::run(&mut client, parsed).await
            }
            "uffs_aggregate" => {
                let parsed = serde_json::from_value(Value::Object(args)).map_err(|err| {
                    BridgeError::InvalidParam {
                        name: "arguments",
                        reason: err.to_string(),
                    }
                })?;
                tools::aggregate::run(&mut client, parsed, &roots_state).await
            }
            "uffs_facet_values" => {
                let parsed = serde_json::from_value(Value::Object(args)).map_err(|err| {
                    BridgeError::InvalidParam {
                        name: "arguments",
                        reason: err.to_string(),
                    }
                })?;
                tools::facet_values::run(&mut client, parsed, &roots_state).await
            }
            other => Err(BridgeError::Daemon(format!("Unknown tool: {other}"))),
        }
    }
}

impl Drop for UffsMcpServer {
    fn drop(&mut self) {
        // Decrement active session count for HTTP gateway sessions.
        if matches!(self.slot, ClientSlot::Active { .. }) {
            self.stats.session_ended();
        }
    }
}

impl ServerHandler for UffsMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
        .with_server_info(Implementation::new("uffs", env!("CARGO_PKG_VERSION")))
        .with_instructions(AGENT_INSTRUCTIONS.to_owned())
    }

    #[cfg_attr(
        feature = "streamable-http",
        expect(
            clippy::cognitive_complexity,
            reason = "async match + await + iteration + logging contributes to Clippy score"
        )
    )]
    async fn on_roots_list_changed(&self, context: rmcp::service::NotificationContext<RoleServer>) {
        // Ask the client for the current list of roots. This match is the ONLY
        // place in uffs-mcp that speaks the SEP-2577-deprecated Roots wire API
        // (`Peer::list_roots` + `rmcp::model::Root`); `roots.rs` is transport-
        // agnostic (`AdvertisedRoot`). When rmcp removes the API, delete this
        // hook — workspace scoping then flows from the explicit path filters
        // the search tools already accept.
        #[expect(
            deprecated,
            reason = "SEP-2577 deprecates MCP Roots with no replacement API; clients still \
                      advertise roots today, so this single boundary hook converts them to \
                      the transport-agnostic AdvertisedRoot. Delete the hook when rmcp \
                      removes the method (hard error then, not a silenced warning)."
        )]
        match context.peer.list_roots().await {
            Ok(result) => {
                let advertised: Vec<roots::AdvertisedRoot> = result
                    .roots
                    .iter()
                    .map(|root| roots::AdvertisedRoot {
                        uri: root.uri.clone(),
                        name: root.name.clone(),
                    })
                    .collect();
                let mut state = self.roots.write().await;
                roots::update_roots_state(&mut state, &advertised);
                let mapped = state
                    .roots
                    .iter()
                    .filter(|root| root.ntfs_prefix.is_some())
                    .count();
                let unmapped = state.roots.len() - mapped;
                tracing::info!(total = state.roots.len(), mapped, unmapped, "roots updated");
                for warning in &state.warnings {
                    tracing::warn!("{warning}");
                }
            }
            Err(err) => {
                tracing::warn!("failed to list roots from client: {err}");
            }
        }
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "rmcp ServerHandler trait mandates an async signature; this handler returns precomputed data and has no .await"
    )]
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        self.touch();
        Ok(ListToolsResult {
            tools: definitions::tool_definitions(),
            next_cursor: None,
            meta: None,
        })
    }

    #[cfg_attr(
        feature = "streamable-http",
        expect(
            clippy::cognitive_complexity,
            reason = "tool dispatch with timing, error handling, stats, and reconnect"
        )
    )]
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.touch();
        let tool_name = request.name.to_string();
        let args = request.arguments.unwrap_or_default();

        let args_json = serde_json::to_string(&args).unwrap_or_default();
        tracing::info!(
            tool = %tool_name,
            args = %args_json,
            "→ tool call received"
        );
        let t0 = std::time::Instant::now();

        // Reject unknown tools early (before touching the daemon).
        if !is_known_tool(&tool_name) {
            return Err(McpError::invalid_params(
                format!("Unknown tool: {tool_name}"),
                None,
            ));
        }

        // First attempt — retry once on daemon connection errors.
        let first_result = self.dispatch_tool(&tool_name, args.clone()).await;
        let final_result = match first_result {
            Err(err) if err.is_daemon_connection_error() => {
                tracing::warn!(
                    tool = %tool_name,
                    error = %err,
                    "Daemon connection lost — retrying with fresh connection..."
                );
                // Under the per-call connection model each dispatch
                // already opens a new socket, so a plain re-dispatch is
                // sufficient — there is no stale cached client to clear.
                self.dispatch_tool(&tool_name, args).await
            }
            other => other,
        };

        let elapsed = t0.elapsed();
        let latency_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        match &final_result {
            Ok(_) => {
                tracing::info!(
                    tool = %tool_name,
                    elapsed_ms,
                    "← tool call OK"
                );
                self.stats.record_tool_call(&tool_name, latency_us);
            }
            Err(err) => {
                tracing::warn!(
                    tool = %tool_name,
                    elapsed_ms,
                    error = %err,
                    "← tool call FAILED"
                );
                self.stats.record_tool_error(&tool_name, latency_us);
            }
        }

        final_result.map_err(McpError::from)
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "rmcp ServerHandler trait mandates an async signature; this handler returns precomputed data and has no .await"
    )]
    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        self.touch();
        Ok(ListResourcesResult {
            resources: vec![
                Resource::new("uffs://schema/fields", "Field Catalog")
                    .with_description(
                        "Complete catalog of fields available for searching, filtering, \
                         sorting, and aggregating — includes types and capabilities",
                    )
                    .with_mime_type("application/json"),
                Resource::new("uffs://drives", "Indexed Drives")
                    .with_description(
                        "Live listing of currently indexed NTFS drives with record counts",
                    )
                    .with_mime_type("application/json"),
                Resource::new("uffs://status", "Daemon Status")
                    .with_description(
                        "Daemon health, state, uptime, memory, PID, and drive-loading progress",
                    )
                    .with_mime_type("application/json"),
                Resource::new("uffs://schema/search", "Search Request Schema")
                    .with_description("JSON Schema for the uffs_search tool input parameters")
                    .with_mime_type("application/json"),
                Resource::new("uffs://schema/aggregate", "Aggregate Request Schema")
                    .with_description("JSON Schema for the uffs_aggregate tool input parameters")
                    .with_mime_type("application/json"),
                Resource::new("uffs://presets/aggregate", "Aggregate Presets")
                    .with_description(
                        "Built-in aggregate presets (overview, by_type, by_extension, \
                         storage, etc.) with descriptions",
                    )
                    .with_mime_type("application/json"),
                // ── Agent cookbook (query examples) ──────────────────
                Resource::new("uffs://cookbook", "Query Cookbook")
                    .with_description(
                        "Curated example MCP tool calls organized by workflow — \
                         ready-to-use arguments objects, tips, and multi-step patterns. \
                         Read this first to learn how to compose effective UFFS queries.",
                    )
                    .with_mime_type("application/json"),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "rmcp ServerHandler trait mandates an async signature; this handler returns precomputed data and has no .await"
    )]
    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        self.touch();
        Ok(ListResourceTemplatesResult {
            resource_templates: vec![
                ResourceTemplate::new("uffs://info/{path}", "File/Directory Info")
                    .with_description(
                        "Full metadata for a file or directory by path. \
                     The {path} parameter is a percent-encoded Windows path \
                     with forward slashes (e.g. C:/Users/me/file.txt).",
                    )
                    .with_mime_type("application/json"),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        self.touch();
        self.stats.record_resource_read();
        let uri_str = request.uri.as_str().to_owned();

        // Static schema resources — no daemon connection needed.
        let json = match uri_str.as_str() {
            "uffs://schema/fields" => crate::resources::field_catalog_json(),
            "uffs://schema/search" => crate::resources::search_schema_json(),
            "uffs://schema/aggregate" => crate::resources::aggregate_schema_json(),
            "uffs://presets/aggregate" => crate::resources::aggregate_presets_json(),
            "uffs://cookbook" => crate::cookbook::cookbook_json(),

            // Live metadata resources — need daemon.
            "uffs://drives" => {
                let mut client = self
                    .connect_daemon()
                    .await
                    .map_err(|err| McpError::internal_error(err.to_string(), None))?;
                let resp = client
                    .drives()
                    .await
                    .map_err(|err| McpError::internal_error(format!("drives: {err}"), None))?;
                drop(client);
                serde_json::to_string_pretty(&resp)
                    .map_err(|err| McpError::internal_error(err.to_string(), None))?
            }
            "uffs://status" => {
                let mut client = self
                    .connect_daemon()
                    .await
                    .map_err(|err| McpError::internal_error(err.to_string(), None))?;
                let resp = client
                    .status()
                    .await
                    .map_err(|err| McpError::internal_error(format!("status: {err}"), None))?;
                drop(client);
                serde_json::to_string_pretty(&resp)
                    .map_err(|err| McpError::internal_error(err.to_string(), None))?
            }
            // Dynamic info resource: uffs://info/{percent-encoded-path}
            _ if uri_str.starts_with("uffs://info/") => {
                let info_prefix_len = "uffs://info/".len();
                let encoded_path = uri_str.get(info_prefix_len..).unwrap_or_default();
                let decoded_path = percent_decode_path(encoded_path);
                // Normalize URI-style forward slashes back to Windows backslashes.
                let win_path = decoded_path.replace('/', "\\");

                let mut client = self
                    .connect_daemon()
                    .await
                    .map_err(|err| McpError::internal_error(err.to_string(), None))?;
                let resp = client
                    .info(&win_path)
                    .await
                    .map_err(|err| McpError::internal_error(format!("info: {err}"), None))?;
                drop(client);
                serde_json::to_string_pretty(&resp)
                    .map_err(|err| McpError::internal_error(err.to_string(), None))?
            }

            _ => {
                return Err(McpError::resource_not_found(
                    format!("Unknown resource: {uri_str}"),
                    None,
                ));
            }
        };

        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            json,
            request.uri,
        )]))
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "rmcp ServerHandler trait mandates an async signature; this handler returns precomputed data and has no .await"
    )]
    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        self.touch();
        Ok(ListPromptsResult {
            prompts: definitions::prompt_definitions(),
            next_cursor: None,
            meta: None,
        })
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "rmcp ServerHandler trait mandates an async signature; this handler builds prompt messages synchronously with no .await"
    )]
    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        self.stats.record_prompt_get();
        let prompt_args = request.arguments.unwrap_or_default();

        let messages = prompts::build_prompt_messages(request.name.as_ref(), &prompt_args)?;

        Ok(GetPromptResult::new(messages)
            .with_description(format!("UFFS prompt: {}", request.name)))
    }
}

#[cfg(test)]
mod tests {
    /// Verify that optional/skippable fields are NOT in the `required` array.
    ///
    /// MCP hosts reject `structuredContent` that omits a `required` field.
    /// Fields with `#[serde(skip_serializing_if)]` must use
    /// `#[schemars(default)]` so schemars excludes them from `required`.
    #[test]
    fn output_schema_required_fields_match_serde() {
        use crate::schemas::SearchOutput;
        let settings = schemars::generate::SchemaSettings::draft2020_12();
        let generator = settings.into_generator();
        let schema = generator.into_root_schema_for::<SearchOutput>();
        let json = serde_json::to_string_pretty(&schema).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        let required = val
            .get("required")
            .and_then(|req| req.as_array())
            .unwrap()
            .iter()
            .map(|elem| elem.as_str().unwrap())
            .collect::<Vec<_>>();
        // These are skip_serializing_if — must NOT be required.
        assert!(
            !required.contains(&"warnings"),
            "warnings must not be required"
        );
        assert!(
            !required.contains(&"next_cursor"),
            "next_cursor must not be required"
        );
        // These ARE always present — must be required.
        assert!(required.contains(&"returned"));
        assert!(required.contains(&"rows"));
    }
}
