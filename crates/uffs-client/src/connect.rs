// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Daemon connection management: auto-start, connect, reconnect.
//!
//! `UffsClient` is the single entry point for all surfaces (CLI, TUI,
//! GUI, MCP) to communicate with the daemon.
//!
//! # Platform Support
//!
//! | Platform | IPC Transport |
//! |----------|--------------|
//! | **macOS** | Unix domain socket (`~/Library/Application Support/uffs/daemon.sock`) |
//! | **Linux** | Unix domain socket (`$XDG_RUNTIME_DIR/uffs/daemon.sock`) |
//! | **Windows** | Named pipe (`\\.\pipe\uffs-<user-sid-hash>`) |

use core::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

use crate::daemon_ctl::pid_file_path;
use crate::protocol::response::{DaemonStatus, DrivesResponse, SearchResponse, StatusResponse};
use crate::protocol::{RpcRequest, SearchParams};

/// Thin client for the UFFS daemon.
///
/// Uses boxed async I/O so the same struct works with Unix domain sockets
/// (macOS/Linux) and named pipes (Windows) without generics leaking into
/// the public API.
///
/// # Field discipline (Phase 3b §3.4)
///
/// All fields are **private**; the only way to construct a
/// `UffsClient` is via one of the connection entry points
/// ([`Self::connect`], [`Self::connect_with_args`], or — for tests —
/// the `pub(crate)` `from_parts` / `from_parts_for_test`).  This
/// protects two non-trivial invariants:
///
/// - The `reader` / `writer` halves both belong to the same IPC endpoint (a
///   mismatched pair would silently corrupt RPCs).
/// - `next_id` starts at `1` and is monotonically incremented by
///   `Self::next_request_id`, preserving JSON-RPC's correlation guarantee.
///
/// # `#[non_exhaustive]` decision (Phase 3b §3.6)
///
/// **N/A** — no `pub` fields means future fields slot in transparently.
pub struct UffsClient {
    /// Buffered reader for the IPC connection.
    reader: BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
    /// Writer for the IPC connection.
    writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    /// Monotonically increasing request ID.
    next_id: AtomicU64,
    /// Cached `DaemonStatus` from the most recent `status` RPC — lets
    /// [`Self::await_ready`] skip a redundant round-trip when the
    /// connect-time `deep_health_check` already observed `Ready`.
    /// Cleared on probe error and on reconnect so a stale `Ready` can
    /// never short-circuit on a lie.  See the sync sibling
    /// [`crate::connect_sync::UffsClientSync`] for the full rationale.
    cached_status: Option<DaemonStatus>,
    /// Notification sender — incoming daemon notifications are forwarded here.
    notification_tx: tokio::sync::mpsc::UnboundedSender<crate::protocol::RpcNotification>,
    /// Notification receiver — consumers read daemon events from this.
    notification_rx: tokio::sync::mpsc::UnboundedReceiver<crate::protocol::RpcNotification>,
}

impl UffsClient {
    /// Assemble a client from its reader/writer halves.
    ///
    /// Crate-internal constructor used by
    /// [`crate::connect_platform`] — lets the split `impl` build a
    /// value without touching private fields directly.  Mirrors the
    /// sync sibling's `UffsClientSync::from_parts`.
    pub(crate) fn from_parts(
        reader: BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
        writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    ) -> Self {
        // Phase 10d: unbounded by-design — see backpressure_audit.md.
        let (notification_tx, notification_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            reader,
            writer,
            next_id: AtomicU64::new(1),
            cached_status: None,
            notification_tx,
            notification_rx,
        }
    }

    /// Test-only constructor that wires the client to arbitrary in-memory
    /// `AsyncRead` / `AsyncWrite` halves — no real socket, no daemon.
    ///
    /// Mirrors [`crate::connect_sync::UffsClientSync::from_parts_for_test`].
    /// Gated on `#[cfg(test)]` so it cannot leak into production builds.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_parts_for_test(
        reader: BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
        writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    ) -> Self {
        Self::from_parts(reader, writer)
    }

    /// Test-only accessor for seeding `cached_status` without routing
    /// through the RPC path.  Mirrors the sync sibling and lets the
    /// Run 10 Part B regression pins verify the short-circuit
    /// without round-tripping a synthetic response through the mock.
    #[cfg(test)]
    pub(crate) fn set_cached_status_for_test(&mut self, status: DaemonStatus) {
        self.cached_status = Some(status);
    }

    /// Receive the next daemon notification (non-blocking).
    ///
    /// Returns `None` if no notifications are pending. Use this in an
    /// event loop to process daemon events (`drive_loaded`,
    /// `refresh_complete`).
    pub fn try_recv_notification(&mut self) -> Option<crate::protocol::RpcNotification> {
        self.notification_rx.try_recv().ok()
    }

    /// Send a JSON-RPC request and read the response.
    ///
    /// D3.4.5: While waiting for the response, any incoming notifications
    /// (messages without an `id` field) are routed to the notification channel.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`](crate::error::ClientError) if serialisation,
    /// I/O, or response parsing fails.
    async fn send_request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, crate::error::ClientError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req = RpcRequest::new(id, method, params);

        let json = serde_json::to_string(&req)
            .map_err(|ser_err| crate::error::ClientError::Protocol(ser_err.to_string()))?;

        tracing::info!(id, method, "send_request: writing request");
        self.writer
            .write_all(json.as_bytes())
            .await
            .map_err(|io_err| crate::error::ClientError::Io(io_err.to_string()))?;
        self.writer
            .write_all(b"\n")
            .await
            .map_err(|io_err| crate::error::ClientError::Io(io_err.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|io_err| crate::error::ClientError::Io(io_err.to_string()))?;
        tracing::info!(
            id,
            method,
            "send_request: write+flush done, reading response"
        );

        // Read lines until we get a response with matching id.
        // Notifications (no id) are routed to the notification channel.
        loop {
            let mut line = String::new();
            let read_result = tokio::time::timeout(
                core::time::Duration::from_mins(5),
                self.reader.read_line(&mut line),
            )
            .await
            .map_err(|_timeout_err| {
                tracing::info!(id, method, "send_request: read timed out after 300s");
                crate::error::ClientError::Timeout
            })?
            .map_err(|io_err| crate::error::ClientError::Io(io_err.to_string()))?;

            if read_result == 0 {
                return Err(crate::error::ClientError::ConnectionClosed);
            }

            let trimmed = line.trim();

            // Check if this is a notification (has "method" but no "id")
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed)
                && value.get("method").is_some()
                && value.get("id").is_none()
            {
                // It's a notification — route to channel
                if let Ok(notif) = serde_json::from_value::<crate::protocol::RpcNotification>(value)
                {
                    drop(self.notification_tx.send(notif));
                }
                continue; // keep reading for the actual response
            }

            // It's a response — could be success (has `result`) or error (has `error`).
            let value: serde_json::Value = serde_json::from_str(trimmed).map_err(|err| {
                crate::error::ClientError::Protocol(format!("Bad response: {err}"))
            })?;

            // Check for JSON-RPC error response first.
            if let Some(err_obj) = value.get("error") {
                let msg = err_obj
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown RPC error");
                return Err(crate::error::ClientError::Protocol(msg.to_owned()));
            }

            // Success response.
            if let Some(result) = value.get("result") {
                return Ok(result.clone());
            }

            return Err(crate::error::ClientError::Protocol(
                "Response has neither `result` nor `error`".to_owned(),
            ));
        }
    }

    // ── Public Query API ────────────────────────────────────────────────

    /// Search files across loaded drives.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` on connection, protocol, or timeout failure.
    pub async fn search(
        &mut self,
        params: &SearchParams,
    ) -> Result<SearchResponse, crate::error::ClientError> {
        let value = serde_json::to_value(params)
            .map_err(|err| crate::error::ClientError::Protocol(err.to_string()))?;
        let result = self.send_request("search", Some(value)).await?;
        let response: SearchResponse = serde_json::from_value(result)
            .map_err(|err| crate::error::ClientError::Protocol(err.to_string()))?;

        // D5.1: transparent shmem reading — if the daemon delivered
        // structured rows via a shmem file, materialise them into the
        // returned `SearchResponse` so programmatic callers see an
        // `InlineRows` payload and never have to know about the
        // transport.  Blob variants (`InlineBlob` / `ShmemBlob`) are
        // raw bytes destined for stdout and are opaque here — the
        // async `search()` API returns them as-is; only the CLI path
        // interprets them via `stream_paths_blob_into`.
        if let crate::protocol::response::SearchPayload::ShmemRows { path, .. } = &response.payload
        {
            let t_shmem = std::time::Instant::now();
            let shmem_path = std::path::Path::new(path);
            let shmem_response = crate::shmem::read_search_results(shmem_path).map_err(|err| {
                crate::error::ClientError::Protocol(format!("shmem read failed: {err}"))
            })?;
            let shmem_read_ms = t_shmem.elapsed().as_millis();
            let row_count = shmem_response.payload.row_count_hint().unwrap_or(0);
            tracing::info!(
                rows = row_count,
                shmem_read_ms = shmem_read_ms,
                path = %path,
                "🗂️ shmem: read bulk results"
            );
            tracing::debug!(
                target: "cache_profile",
                shmem_read_ms = %shmem_read_ms,
                row_count,
                "shmem_read"
            );
            return Ok(shmem_response);
        }

        Ok(response)
    }

    /// List loaded drives.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` on connection, protocol, or timeout failure.
    pub async fn drives(&mut self) -> Result<DrivesResponse, crate::error::ClientError> {
        let result = self.send_request("drives", None).await?;
        serde_json::from_value(result)
            .map_err(|err| crate::error::ClientError::Protocol(err.to_string()))
    }

    /// Get daemon status.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` on connection, protocol, or timeout failure.
    pub async fn status(&mut self) -> Result<StatusResponse, crate::error::ClientError> {
        let result = self.send_request("status", None).await?;
        serde_json::from_value(result)
            .map_err(|err| crate::error::ClientError::Protocol(err.to_string()))
    }

    /// Query daemon performance statistics (queries, timing, startup).
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` on connection, protocol, or timeout failure.
    pub async fn stats(
        &mut self,
    ) -> Result<crate::protocol::response::StatsResponse, crate::error::ClientError> {
        let result = self.send_request("stats", None).await?;
        serde_json::from_value(result)
            .map_err(|err| crate::error::ClientError::Protocol(err.to_string()))
    }

    /// Wait until the daemon has finished loading its indices.
    ///
    /// Polls `status()` with exponential backoff (250ms → 2s cap) until the
    /// daemon reports [`crate::protocol::response::DaemonStatus::Ready`].
    ///
    /// `timeout` is an **idle** budget, not a hard wall-clock cutoff: every
    /// time the daemon reports forward progress (`DaemonStatus::Loading`'s
    /// `drives_loaded` advancing), the deadline resets to `now + timeout`.
    /// A big multi-drive load under heavy system load that keeps visibly
    /// making progress is never killed by an arbitrary fixed cutoff — only
    /// a daemon that stops progressing for a full `timeout` window is. A
    /// hard outer ceiling (`5 * timeout`) still bounds the total wait so a
    /// daemon stuck oscillating on the same drive count can't hang the
    /// caller forever.
    ///
    /// If multiple consecutive I/O errors occur (e.g. broken pipe from a
    /// stale socket), the client automatically reconnects to the daemon.
    ///
    /// # Errors
    ///
    /// Returns `ClientError` on connection failure, or once the idle
    /// budget (or hard ceiling) elapses without reaching `Ready`.
    pub async fn await_ready(
        &mut self,
        timeout: core::time::Duration,
    ) -> Result<(), crate::error::ClientError> {
        /// Consecutive I/O errors before attempting a reconnect.
        const RECONNECT_THRESHOLD: u32 = 3;

        // Hot path: cached `Ready` from connect-time deep_health_check
        // lets us skip the RPC round-trip entirely (Run 10 Part B).
        if matches!(self.cached_status, Some(DaemonStatus::Ready)) {
            return Ok(());
        }

        let start = tokio::time::Instant::now();
        // Even under continuous progress, don't wait forever — 5x the
        // caller's own idle budget scales with however patient it already
        // asked to be, without introducing a load-independent magic number.
        let hard_ceiling = start + timeout.saturating_mul(5);
        let mut deadline = start + timeout;
        let mut delay_ms = 250_u64;
        let mut poll_count = 0_u32;
        let mut consecutive_io_errors = 0_u32;
        let mut last_drives_loaded: Option<usize> = None;

        loop {
            poll_count += 1;
            tracing::info!(poll_count, delay_ms, "await_ready: sending status poll");

            match self.poll_status_once(poll_count).await {
                PollOutcome::Ready => {
                    // Refresh cache so follow-up calls short-circuit.
                    self.cached_status = Some(DaemonStatus::Ready);
                    return Ok(());
                }
                PollOutcome::Loading { drives_loaded } => {
                    consecutive_io_errors = 0;
                    if last_drives_loaded != Some(drives_loaded) {
                        last_drives_loaded = Some(drives_loaded);
                        deadline = (tokio::time::Instant::now() + timeout).min(hard_ceiling);
                    }
                }
                PollOutcome::NotReady => {
                    consecutive_io_errors = 0;
                }
                PollOutcome::IoError => {
                    consecutive_io_errors += 1;
                    if consecutive_io_errors >= RECONNECT_THRESHOLD {
                        self.attempt_reconnect(&mut consecutive_io_errors).await;
                    }
                }
                PollOutcome::OtherError => {}
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(crate::error::ClientError::ConnectionFailed(
                    "Timed out waiting for daemon to finish loading".to_owned(),
                ));
            }

            tokio::time::sleep(core::time::Duration::from_millis(delay_ms)).await;
            delay_ms = (delay_ms * 2).min(2000);
        }
    }

    /// Attempt a reconnect to the daemon, replacing internal reader/writer.
    async fn attempt_reconnect(&mut self, consecutive_io_errors: &mut u32) {
        let error_count = *consecutive_io_errors;
        tracing::info!(error_count, "await_ready: reconnecting to daemon");
        match Self::platform_connect().await {
            Ok(new_client) => {
                self.reader = new_client.reader;
                self.writer = new_client.writer;
                self.next_id = new_client.next_id;
                // Fresh transport — stale status cache must not leak.
                self.cached_status = None;
                self.notification_tx = new_client.notification_tx;
                self.notification_rx = new_client.notification_rx;
                *consecutive_io_errors = 0;
                tracing::info!("await_ready: reconnected successfully");
            }
            Err(reconn_err) => {
                tracing::info!(error = %reconn_err, "await_ready: reconnect failed, will retry");
            }
        }
    }

    /// Hot-load MFT files into the running daemon.
    ///
    /// Files whose drive letter is already loaded are skipped.  Returns
    /// which drives were loaded, which were already present, and any errors.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` on connection, protocol, or timeout failure.
    pub async fn load_drive(
        &mut self,
        mft_files: &[String],
        no_cache: bool,
    ) -> Result<crate::protocol::response::LoadDriveResponse, crate::error::ClientError> {
        let params = serde_json::json!({
            "mft_files": mft_files,
            "no_cache": no_cache,
        });
        let result = self.send_request("load_drive", Some(params)).await?;
        serde_json::from_value(result)
            .map_err(|err| crate::error::ClientError::Protocol(err.to_string()))
    }

    /// Trigger a drive refresh.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` on connection, protocol, or timeout failure.
    pub async fn refresh(
        &mut self,
        drives: &[uffs_mft::platform::DriveLetter],
    ) -> Result<(), crate::error::ClientError> {
        let params = serde_json::json!({"drives": drives});
        let _result = self.send_request("refresh", Some(params)).await?;
        Ok(())
    }

    /// Look up detailed info for a specific file path.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` on connection, protocol, or timeout failure.
    pub async fn info(
        &mut self,
        path: &str,
    ) -> Result<crate::protocol::response::InfoResponse, crate::error::ClientError> {
        let params = serde_json::json!({"path": path});
        let result = self.send_request("info", Some(params)).await?;
        serde_json::from_value(result)
            .map_err(|err| crate::error::ClientError::Protocol(err.to_string()))
    }

    /// Send a keepalive to reset the daemon's idle timer.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` on connection or timeout failure.
    pub async fn keepalive(&mut self) -> Result<(), crate::error::ClientError> {
        let _result = self.send_request("keepalive", None).await?;
        Ok(())
    }

    /// Commit C — **deep health check**: round-trip a cheap `status`
    /// RPC right after connect to prove the daemon's request/response
    /// loop is responsive, and cache the returned [`DaemonStatus`] so
    /// [`Self::await_ready`] can short-circuit a redundant round-trip.
    ///
    /// See `UffsClientSync::deep_health_check` in `connect_sync.rs` for
    /// the full rationale (Run 10 Part B, 2026-04-19: consolidated the
    /// prior `drives` + `status` pair into a single probe).
    /// Skippable via `UFFS_CLIENT_SKIP_HEALTH_CHECK=1`.  Cost:
    /// ~200–600 µs on local IPC.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::ClientError::ConnectionFailed`] wrapping
    /// the underlying probe failure.
    pub(crate) async fn deep_health_check(&mut self) -> Result<(), crate::error::ClientError> {
        match self.status().await {
            Ok(resp) => {
                self.cached_status = Some(resp.status);
                Ok(())
            }
            Err(probe_err) => {
                // Torn probe — clear cache so await_ready can't lie.
                self.cached_status = None;
                Err(crate::error::ClientError::ConnectionFailed(format!(
                    "Deep health check failed: the daemon accepted the connection but did \
                     not respond correctly to a probe `status` RPC ({probe_err}). The \
                     daemon may be wedged (deadlocked worker, stuck kernel I/O); consider \
                     `uffs --daemon kill` and restart.  Set UFFS_CLIENT_SKIP_HEALTH_CHECK=1 \
                     to bypass this probe."
                )))
            }
        }
    }

    /// Set the session type (D3.4.3) — tells daemon which idle timeout tier to
    /// use.
    ///
    /// - `"cli"` → short timeout (5 min default)
    /// - `"tui"`, `"gui"`, `"mcp"` → long timeout (15 min default)
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` on connection or timeout failure.
    pub async fn set_session_type(
        &mut self,
        session_type: &str,
    ) -> Result<(), crate::error::ClientError> {
        let params = serde_json::json!({"session_type": session_type});
        let _result = self.send_request("keepalive", Some(params)).await?;
        Ok(())
    }

    /// Request graceful daemon shutdown.
    ///
    /// Reads the shutdown nonce from the PID file (S4.4.9) and sends it
    /// with the shutdown request.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` on connection or timeout failure.
    pub async fn shutdown(&mut self) -> Result<(), crate::error::ClientError> {
        // Read nonce from PID file (line 4): {pid}\n{timestamp}\n{exe_hash}\n{nonce}\n
        let nonce = std::fs::read_to_string(pid_file_path())
            .ok()
            .and_then(|content| content.lines().nth(3).map(ToOwned::to_owned))
            .unwrap_or_default();
        let params = serde_json::json!({"nonce": nonce});
        let _result = self.send_request("shutdown", Some(params)).await?;
        Ok(())
    }
}

// `start_keepalive` and `KeepaliveGuard` live in
// [`crate::connect_keepalive`] — import directly from there rather
// than relying on a `pub use` cascade through this module.

// ── Readiness polling helpers ────────────────────────────────────────

/// Outcome of a single status poll in [`UffsClient::await_ready`].
enum PollOutcome {
    /// Daemon reports `Ready`.
    Ready,
    /// Daemon reports `Loading`, with its current drive-count progress —
    /// carried so `await_ready` can detect forward progress and extend
    /// its idle deadline instead of applying a fixed wall-clock cutoff.
    Loading {
        /// Drives loaded so far, per `DaemonStatus::Loading::drives_loaded`.
        drives_loaded: usize,
    },
    /// Daemon responded but is neither `Ready` nor `Loading` (e.g.
    /// `Refreshing`).
    NotReady,
    /// I/O or connection-closed error (may need reconnect).
    IoError,
    /// Non-I/O protocol error.
    OtherError,
}

impl UffsClient {
    /// Poll the daemon status once, returning a classified outcome.
    async fn poll_status_once(&mut self, poll_count: u32) -> PollOutcome {
        match self.status().await {
            Ok(resp) => {
                tracing::info!(poll_count, status = ?resp.status, "await_ready: got status");
                match resp.status {
                    DaemonStatus::Ready => PollOutcome::Ready,
                    DaemonStatus::Loading { drives_loaded, .. } => {
                        PollOutcome::Loading { drives_loaded }
                    }
                    DaemonStatus::Refreshing { .. } => PollOutcome::NotReady,
                }
            }
            Err(
                err @ (crate::error::ClientError::Io(_)
                | crate::error::ClientError::ConnectionClosed),
            ) => {
                tracing::info!(poll_count, error = %err, "await_ready: status poll I/O error");
                PollOutcome::IoError
            }
            Err(status_err) => {
                tracing::info!(
                    poll_count,
                    error = %status_err,
                    "await_ready: status poll failed"
                );
                PollOutcome::OtherError
            }
        }
    }
}

// Platform-specific `platform_connect` impls live in
// `crate::connect_platform` (split `impl UffsClient` blocks gated on
// `#[cfg(unix)]` / `#[cfg(windows)]`).  Extraction is a file-size
// policy requirement after the Run 10 Part B `cached_status` addition.
// Daemon lifecycle / elevation / tracing helpers live in
// `crate::daemon_ctl`, `crate::daemon_spawn`, `crate::connect_logging`.
