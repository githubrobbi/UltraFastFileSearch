// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Connect / auto-start entry points for [`crate::connect::UffsClient`]
//! (async variant).
//!
//! Extracted from `connect.rs` to keep that file under the workspace
//! 800-LOC policy ceiling. All items live on `UffsClient` via a split
//! `impl` block — no public surface moves. Mirrors the sync-path split
//! in `connect_sync_autostart.rs`, though that sibling holds only the
//! spawn helper (the sync client's retry loop stays inline); here the
//! whole connect → auto-start → retry chain moves together since it is
//! one tightly-coupled call sequence.

use crate::connect::UffsClient;
use crate::connect_logging::{log_connect_attempt, log_connect_error, log_spawn_details};
use crate::daemon_ctl::{
    deep_health_check_enabled, find_daemon_exe, pid_file_path, socket_path,
    verify_daemon_after_connect_strict,
};
use crate::daemon_spawn::{ElevationPolicy, resolve_elevation_policy, spawn_daemon};

impl UffsClient {
    /// Connect to a running daemon, or auto-start one if not running.
    ///
    /// Tries to connect to the socket. If the socket doesn't exist or
    /// connection fails, spawns `uffsd` as a detached process and retries
    /// with exponential backoff (up to ~30s).
    ///
    /// On Windows the daemon auto-discovers live NTFS drives so no extra
    /// args are needed.  On Mac/Linux, pass `--data-dir` or `--mft-file`
    /// via [`Self::connect_with_args`] so the daemon knows where to find data.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionFailed` if the daemon cannot be reached after
    /// multiple retries, or `DaemonStartFailed` if auto-start fails.
    pub async fn connect() -> Result<Self, crate::error::ClientError> {
        Self::connect_with_args(&[]).await
    }

    /// Try to connect to an already-running daemon **without** auto-starting.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionFailed` if no daemon is listening.
    pub async fn connect_raw() -> Result<Self, crate::error::ClientError> {
        Self::platform_connect().await.map_err(|conn_err| {
            crate::error::ClientError::ConnectionFailed(format!("No daemon is running: {conn_err}"))
        })
    }

    /// Connect to a running daemon, or auto-start one with extra CLI
    /// arguments.
    ///
    /// `spawn_args` are forwarded to `uffsd` **only** when the daemon
    /// is not already running and must be auto-started.  If a daemon is
    /// already listening, the args are ignored (it already has its data
    /// loaded).
    ///
    /// Auto-start uses the default
    /// `ElevationPolicy::RequireExistingElevation` — on Windows, if
    /// the daemon must be spawned and the current process is not
    /// elevated, this returns
    /// [`crate::error::ClientError::DaemonNeedsElevation`] instead of
    /// triggering a UAC prompt.  Callers that want the
    /// pre-v0.5.36 behavior (automatic UAC dialog) should use
    /// [`Self::connect_with_elevation`] or set `UFFS_ELEVATE=1`.
    ///
    /// Typical usage (Mac/Linux):
    /// ```rust,ignore
    /// let args = vec!["--data-dir".into(), "/path/to/uffs_data".into()];
    /// let client = UffsClient::connect_with_args(&args).await?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ConnectionFailed`, `DaemonStartFailed`, or
    /// `DaemonNeedsElevation` (Windows, non-admin shell only).
    pub async fn connect_with_args(
        spawn_args: &[std::ffi::OsString],
    ) -> Result<Self, crate::error::ClientError> {
        Self::connect_with_args_inner(spawn_args, resolve_elevation_policy(false)).await
    }

    /// Connect to a running daemon; if we must auto-start it, explicitly
    /// request a UAC prompt on Windows when the current process is not
    /// elevated.
    ///
    /// This is the opt-in variant used by `uffs --daemon start --elevate`.
    /// All other entry points default to
    /// `ElevationPolicy::RequireExistingElevation`.
    ///
    /// # Errors
    ///
    /// Same as [`Self::connect_with_args`], minus
    /// `DaemonNeedsElevation` (which is turned into a UAC prompt).
    pub async fn connect_with_elevation(
        spawn_args: &[std::ffi::OsString],
    ) -> Result<Self, crate::error::ClientError> {
        Self::connect_with_args_inner(spawn_args, ElevationPolicy::AllowUacPrompt).await
    }

    /// Shared body for [`Self::connect_with_args`] and
    /// [`Self::connect_with_elevation`].
    ///
    /// Takes an explicit [`ElevationPolicy`] so each public entry
    /// point can decide whether a missing elevated context is a
    /// hard error (the default) or a prompt request.
    async fn connect_with_args_inner(
        spawn_args: &[std::ffi::OsString],
        policy: ElevationPolicy,
    ) -> Result<Self, crate::error::ClientError> {
        let sock = socket_path();
        let pid_path = pid_file_path();
        tracing::debug!(
            socket_path = %sock.display(),
            socket_exists = sock.exists(),
            pid_file = %pid_path.display(),
            pid_file_exists = pid_path.exists(),
            ?policy,
            "connect_with_args: paths"
        );

        // Try connecting directly first — daemon may already be running.
        if let Ok(client) = Self::try_connect_existing().await {
            return Ok(client);
        }

        // Auto-start the daemon (`uffsd`) with the requested policy.
        Self::auto_start_daemon(spawn_args, policy)?;

        // Retry with exponential backoff until connected.
        Self::retry_connect(&sock, &pid_path).await
    }

    /// Attempt to connect to an already-running daemon.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`](crate::error::ClientError) if no daemon is
    /// running or the connection handshake fails.
    async fn try_connect_existing() -> Result<Self, crate::error::ClientError> {
        match Self::platform_connect().await {
            Ok(mut client) => {
                tracing::debug!("connect_with_args: already connected to existing daemon");
                // Commit B: strict identity verification — refuse to
                // hand back a client bound to a hijacked pipe/socket.
                verify_daemon_after_connect_strict()?;
                // Commit C: deep health check — prove the daemon is
                // actually responsive to RPCs, not just listening.
                if deep_health_check_enabled() {
                    client.deep_health_check().await?;
                }
                Ok(client)
            }
            Err(conn_err) => {
                tracing::debug!(%conn_err, "connect_with_args: initial connect failed");
                Err(conn_err)
            }
        }
    }

    /// Spawn the daemon process with the given extra args and elevation
    /// policy.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`](crate::error::ClientError) if the daemon
    /// executable cannot be found, the spawn fails, or the policy
    /// forbids elevation in the current context.
    fn auto_start_daemon(
        spawn_args: &[std::ffi::OsString],
        policy: ElevationPolicy,
    ) -> Result<(), crate::error::ClientError> {
        tracing::info!(?policy, "Daemon not running, auto-starting via `uffsd`...");

        let daemon_exe = find_daemon_exe();
        log_spawn_details(&daemon_exe, spawn_args);

        // On Windows, reading the MFT requires Administrator privileges.
        // The default policy is `RequireExistingElevation` — if we are
        // not already elevated, we return `DaemonNeedsElevation` and let
        // the CLI render an actionable message.  Callers opt in to a
        // UAC prompt via `connect_with_elevation` or `UFFS_ELEVATE=1`.
        spawn_daemon(&daemon_exe, spawn_args, policy)?;
        tracing::debug!("auto_start_daemon: spawn returned OK");
        Ok(())
    }

    /// Retry connecting to the daemon with exponential backoff.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`](crate::error::ClientError) if all connection
    /// attempts are exhausted.
    async fn retry_connect(
        sock: &std::path::Path,
        pid_path: &std::path::Path,
    ) -> Result<Self, crate::error::ClientError> {
        let mut delay_ms = 50_u64;
        let max_attempts = 20_usize;
        for attempt in 1_usize..=max_attempts {
            tokio::time::sleep(core::time::Duration::from_millis(delay_ms)).await;
            log_connect_attempt(attempt, max_attempts, delay_ms, sock, pid_path);

            match Self::platform_connect().await {
                Ok(mut client) => {
                    tracing::info!(attempt, "Connected to daemon");
                    // Commit B: strict identity verification — refuse to
                    // hand back a client bound to a hijacked endpoint,
                    // even when we just spawned the daemon ourselves.
                    verify_daemon_after_connect_strict()?;
                    // Commit C: deep health check — prove the daemon is
                    // actually responsive to RPCs, not just listening.
                    if deep_health_check_enabled() {
                        client.deep_health_check().await?;
                    }
                    return Ok(client);
                }
                Err(conn_err) => {
                    log_connect_error(attempt, max_attempts, &conn_err);
                }
            }

            delay_ms = (delay_ms * 2).min(2000);
        }

        tracing::warn!(max_attempts, "all connect attempts exhausted");
        Err(crate::error::ClientError::ConnectionFailed(
            "Could not connect to daemon after auto-start".to_owned(),
        ))
    }
}
