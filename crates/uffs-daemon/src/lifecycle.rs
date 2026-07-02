// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Daemon lifecycle: PID file, idle timeout, auto-retire, shutdown.
//!
//! Exception: `file_size_policy` allows this file to exceed 800 LOC.
//! Rationale: `LifecycleManager` + `LifecycleHandle` plus the
//! `run_idle_timer` state machine (active-connection guard,
//! load-stall heartbeat, session-tier deadline extension) form a
//! single cohesive unit; splitting the helpers across files would
//! fragment the shutdown semantics.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use std::path::PathBuf;

use tokio::sync::{Notify, watch};

use crate::events::{DaemonEvent, EventSender};

/// Maximum time (seconds) a load phase may run without progress before
/// the daemon force-retires.  Prevents an unkillable zombie when a raw
/// NTFS volume read hangs in kernel-mode I/O.
const LOAD_STALL_TIMEOUT_SECS: u64 = 300; // 5 minutes

/// Handle given to request handlers to control the lifecycle.
#[derive(Clone)]
pub(crate) struct LifecycleHandle {
    /// Send `true` to trigger shutdown.
    shutdown_tx: watch::Sender<bool>,
    /// Notified on every incoming RPC request to extend the idle deadline.
    ///
    /// Uses [`tokio::sync::Notify`] (one stored permit) so that any number
    /// of rapid-fire requests between two `select!` iterations collapse into
    /// a single wakeup — exactly what a sliding-window timer needs.
    activity_notify: Arc<Notify>,
    /// Shutdown nonce — must be provided in the `shutdown` RPC call (S4.4.9).
    shutdown_nonce: Arc<std::sync::Mutex<Option<String>>>,
    /// Active connection count (D2.6.7: don't retire if > 0).
    active_connections: Arc<core::sync::atomic::AtomicUsize>,
    /// Longest session type seen (D2.6.6: TUI/GUI/MCP get 15 min, CLI gets 5
    /// min).
    max_session_tier: Arc<core::sync::atomic::AtomicU8>,
    /// Event broadcaster — connection and lifecycle events.
    events: EventSender,
    /// Load heartbeat — epoch seconds of the last drive-load progress.
    /// Updated by `IndexManager` when each drive finishes loading.
    /// Checked by the idle timer to detect stuck loads.
    load_heartbeat: Arc<AtomicU64>,
    /// Load-phase complete latch.  Set by [`record_load_complete`] once
    /// the load task in `spawn_load_task` finishes draining both
    /// data-dir loads and (on Windows) live-drive loads.  Latches
    /// `false` → `true` exactly once and never reverses.  While unset,
    /// [`LifecycleManager::load_stalled_force_retire`] enforces the
    /// `LOAD_STALL_TIMEOUT_SECS` heartbeat-freshness invariant against a
    /// hung kernel-mode NTFS read; once set, the guard is permanently
    /// disarmed so a fully-loaded daemon serving zero queries against
    /// fully-Parked drives doesn't get killed by the startup safety
    /// net.  Per-drive stuck-load detection remains active via
    /// `DRIVE_LOAD_TIMEOUT` inside
    /// `index/loading.rs::collect_drive_load_results`.
    ///
    /// [`record_load_complete`]: Self::record_load_complete
    load_complete: Arc<AtomicBool>,
}

impl LifecycleHandle {
    /// Signal the daemon to shut down gracefully.
    pub(crate) fn request_shutdown(&self) {
        self.events.emit(DaemonEvent::ShuttingDown {
            reason: "shutdown requested via RPC".to_owned(),
        });
        let _ignore = self.shutdown_tx.send(true);
    }

    /// Reset the idle timer (called on every incoming RPC request).
    ///
    /// Stores one wakeup permit in the [`Notify`].  If the idle-timer task
    /// is currently sleeping it wakes immediately; if it is not yet awaiting
    /// `notified()` the permit is stored and consumed on the next poll.
    /// Either way there is **no race window** — activity can never be lost.
    pub(crate) fn reset_idle_timer(&self) {
        self.activity_notify.notify_one();
    }

    /// Increment active connection count and emit event.
    pub(crate) fn connection_opened(&self) {
        let active = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
        self.events.emit(DaemonEvent::ConnectionChanged { active });
    }

    /// Decrement active connection count and emit event.
    pub(crate) fn connection_closed(&self) {
        let active = self
            .active_connections
            .fetch_sub(1, Ordering::Relaxed)
            .saturating_sub(1);
        self.events.emit(DaemonEvent::ConnectionChanged { active });
    }

    /// Get active connection count.
    pub(crate) fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Update session type (D2.6.6). Higher tier = longer timeout.
    /// 0 = CLI (5 min), 1 = TUI/GUI/MCP (15 min).
    pub(crate) fn set_session_type(&self, session_type: &str) {
        let tier = match session_type {
            "tui" | "gui" | "mcp" => 1,
            _ => 0, // cli or unknown
        };
        // Only upgrade, never downgrade
        self.max_session_tier.fetch_max(tier, Ordering::Relaxed);
    }

    /// Verify a shutdown nonce matches the one in the PID file (S4.4.9).
    ///
    /// If no nonce is set (shouldn't happen), allows shutdown anyway.
    pub(crate) fn verify_shutdown_nonce(&self, provided: &str) -> bool {
        let guard = self
            .shutdown_nonce
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.as_deref() == Some(provided) || guard.is_none()
    }

    /// Record load progress — called by `IndexManager` each time a drive
    /// finishes loading.  Updates the heartbeat timestamp so the idle
    /// timer knows the load phase is still making progress.
    #[cfg(windows)]
    pub(crate) fn record_load_progress(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |dur| dur.as_secs());
        let prev = self.load_heartbeat.swap(now, Ordering::Relaxed);
        let delta = now.saturating_sub(prev);
        tracing::debug!(heartbeat_delta_secs = delta, "Load heartbeat updated");
    }

    /// Latch the load phase as complete — called by `spawn_load_task`
    /// once both data-dir loads and (on Windows) live-drive loads have
    /// drained.  After this latch is set,
    /// [`LifecycleManager::load_stalled_force_retire`] is a no-op, so a
    /// daemon serving zero queries against fully-loaded drives doesn't
    /// get killed by the stuck-NTFS-read safety net at the next idle
    /// deadline.
    ///
    /// Idempotent: calling this multiple times has no effect after the
    /// first — the underlying [`AtomicBool`] is a one-shot latch.
    pub(crate) fn record_load_complete(&self) {
        let was_complete = self.load_complete.swap(true, Ordering::Relaxed);
        if !was_complete {
            tracing::debug!("Load phase complete — stall guard disarmed");
        }
    }
}

/// Lifecycle manager: PID file, idle timer, shutdown coordination.
pub(crate) struct LifecycleManager {
    /// Shutdown receiver — await this to know when to exit.
    shutdown_rx: watch::Receiver<bool>,
    /// The handle that handlers use to control lifecycle.
    handle: LifecycleHandle,
    /// PID file path.
    pid_path: PathBuf,
    /// Idle timeout duration. `None` = no auto-retire (--no-retire).
    idle_timeout: Option<Duration>,
    /// Shutdown nonce (written to PID file, required for RPC shutdown).
    shutdown_nonce: Option<String>,
    /// Whether this instance owns the PID file (wrote it on startup).
    /// When `false`, `Drop` must NOT remove files that belong to another
    /// running daemon.
    owns_pid_file: bool,
}

impl LifecycleManager {
    /// Create a new lifecycle manager.
    ///
    /// `idle_timeout`: `None` for `--no-retire`, `Some(duration)` otherwise.
    pub(crate) fn new(
        data_dir: &std::path::Path,
        idle_timeout: Option<Duration>,
        events: EventSender,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let activity_notify = Arc::new(Notify::new());
        let shutdown_nonce_shared = Arc::new(std::sync::Mutex::new(None));
        let active_connections = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let max_session_tier = Arc::new(core::sync::atomic::AtomicU8::new(0));
        // Seed the load heartbeat with "now" so the stall detector
        // doesn't fire before the first drive even starts loading.
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |dur| dur.as_secs());
        let load_heartbeat = Arc::new(AtomicU64::new(now_epoch));
        // Load-phase latch starts unset — the stall guard is armed
        // until `spawn_load_task` calls `record_load_complete` after
        // draining the data-dir + (Windows) live-drive load paths.
        let load_complete = Arc::new(AtomicBool::new(false));

        let pid_path = data_dir.join("daemon.pid");

        Self {
            shutdown_rx,
            handle: LifecycleHandle {
                shutdown_tx,
                activity_notify,
                shutdown_nonce: shutdown_nonce_shared,
                active_connections,
                max_session_tier,
                events,
                load_heartbeat,
                load_complete,
            },
            pid_path,
            idle_timeout,
            shutdown_nonce: None,
            owns_pid_file: false,
        }
    }

    /// Get a handle for request handlers.
    pub(crate) fn handle(&self) -> LifecycleHandle {
        self.handle.clone()
    }

    /// Write the PID file.
    ///
    /// Format: `{pid}\n{start_timestamp}\n{exe_path_hash}\n{shutdown_nonce}\n`
    /// - `exe_path_hash`: FNV-1a hash of the daemon executable path (for
    ///   identity verification)
    /// - `shutdown_nonce`: random token required for the `shutdown` RPC method
    ///   (S4.4.9)
    pub(crate) fn write_pid_file(&mut self) -> std::io::Result<()> {
        if let Some(parent) = self.pid_path.parent() {
            uffs_security::fs::create_secure_dir(parent)?;
        }

        let exe_hash = Self::exe_path_hash();
        let nonce = Self::generate_nonce();
        self.shutdown_nonce = Some(nonce.clone());

        // Sync nonce to the shared handle so handlers can verify it
        if let Ok(mut guard) = self.handle.shutdown_nonce.lock() {
            *guard = Some(nonce.clone());
        }

        let content = format!(
            "{}\n{}\n{}\n{}\n",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |dur| dur.as_secs()),
            exe_hash,
            nonce,
        );
        std::fs::write(&self.pid_path, content)?;
        uffs_security::fs::set_file_permissions_owner_only(&self.pid_path)?;
        self.owns_pid_file = true;
        tracing::info!(path = %self.pid_path.display(), "PID file written");
        Ok(())
    }

    /// Remove the PID file (called on shutdown).
    pub(crate) fn remove_pid_file(&self) {
        if self.pid_path.exists() {
            let _ignore = std::fs::remove_file(&self.pid_path);
            tracing::info!(path = %self.pid_path.display(), "PID file removed");
        }
    }

    /// Path to the launch-state sidecar (next to the PID file).
    fn launch_state_path(&self) -> PathBuf {
        self.pid_path.with_file_name("daemon.state.json")
    }

    /// Persist this daemon's launch recipe next to the PID file.
    ///
    /// The self-updater reads this back to restart the daemon faithfully
    /// (same image + same switches) without scraping the OS for another
    /// process's command line — more reliable than `Win32`/PEB
    /// introspection and free of any PowerShell shell-out.
    pub(crate) fn write_launch_state(&self) {
        let path = self.launch_state_path();
        let image = std::env::current_exe()
            .ok()
            .map(|exe| exe.display().to_string())
            .unwrap_or_default();
        let command_line = std::env::args().collect::<Vec<_>>().join(" ");
        let started_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |dur| dur.as_secs());
        let state = serde_json::json!({
            "pid": std::process::id(),
            "image_path": image,
            "command_line": command_line,
            "version": env!("CARGO_PKG_VERSION"),
            "started_unix": started_unix,
            // Whether this daemon runs elevated. The CLI's daemon-management
            // elevation gate reads it: a non-elevated daemon in the caller's
            // own %LOCALAPPDATA% is theirs to stop/restart without admin.
            "elevated": uffs_mft::is_elevated(),
        });
        let Ok(content) = serde_json::to_string_pretty(&state) else {
            return;
        };
        if std::fs::write(&path, content).is_err() {
            return;
        }
        let _ignore = uffs_security::fs::set_file_permissions_owner_only(&path);
        tracing::info!(path = %path.display(), "launch-state file written");
    }

    /// Remove the launch-state sidecar (called on shutdown).
    pub(crate) fn remove_launch_state(&self) {
        let path = self.launch_state_path();
        if path.exists() {
            let _ignore = std::fs::remove_file(&path);
        }
    }

    /// Remove the IPC socket file (called on shutdown).
    ///
    /// Without this, a stale socket file remains after graceful stop and
    /// subsequent `daemon status` connects to it, gets EOF, and reports
    /// "connection closed" instead of "not running".
    #[expect(
        clippy::unused_self,
        reason = "method signature matches remove_pid_file(&self); both called in Drop"
    )]
    pub(crate) fn remove_socket_file(&self) {
        let sock_path = crate::ipc::IpcServer::socket_path();
        if sock_path.exists() {
            let _ignore = std::fs::remove_file(&sock_path);
            tracing::info!(path = %sock_path.display(), "Socket file removed");
        }
    }

    /// Check for stale PID file on startup. Returns `true` if safe to proceed.
    ///
    /// Uses [`crate::lifecycle::LifecycleManager::parse_pid_file`] for
    /// structured parsing and validates the exe
    /// hash via [`crate::lifecycle::LifecycleManager::expected_daemon_exe_hash`] to detect stale files from
    /// different binaries.
    pub(crate) fn check_stale_pid(&self) -> bool {
        if !self.pid_path.exists() {
            return true;
        }

        let Some((pid, _ts, exe_hash, _nonce)) = Self::parse_pid_file(&self.pid_path) else {
            // Unparseable — remove and proceed
            let _ignore = std::fs::remove_file(&self.pid_path);
            return true;
        };

        if pid == 0 {
            let _ignore = std::fs::remove_file(&self.pid_path);
            return true;
        }

        // Liveness check comes FIRST — if the process is alive, the daemon
        // is running regardless of whether the binary was rebuilt since then.
        if Self::is_process_alive(pid) {
            tracing::warn!(
                pid,
                "Another daemon instance is running. Use 'shutdown' to stop it first."
            );
            return false;
        }

        // Process is dead.  The exe hash is only useful for detecting
        // leftover PID files from a *different* binary installation (e.g.
        // after `just use-local` rebuilt everything), but only when the
        // process is already gone.
        let expected_hash = Self::expected_daemon_exe_hash();
        if expected_hash != 0 && exe_hash != expected_hash {
            tracing::info!(
                pid,
                "PID file exe hash mismatch (stale from different binary), cleaning up"
            );
        } else {
            tracing::info!(pid, "Cleaning up stale PID file from dead process");
        }
        let _ignore = std::fs::remove_file(&self.pid_path);
        true
    }

    /// Run the idle timer.  Returns when shutdown is requested, the idle
    /// deadline expires, or a stalled load is detected.
    ///
    /// ## Sliding-window design (`sleep_until` + `reset()`)
    ///
    /// Every incoming RPC request calls [`LifecycleHandle::reset_idle_timer`],
    /// which stores a wakeup permit via [`tokio::sync::Notify::notify_one`].
    /// The `notified()` arm in the `select!` loop below consumes that permit
    /// and calls `sleep.as_mut().reset(now + effective_timeout)` — extending
    /// the deadline by one full window from the moment of the last request.
    ///
    /// Because `Notify` collapses any number of concurrent permits into one,
    /// even thousands of requests per second only produce a single wakeup, and
    /// `reset()` on a pinned [`tokio::time::Sleep`] is O(1) (one wheel update).
    /// There is **no race window**: a permit stored before `notified()` is
    /// polled is consumed immediately on the first poll.
    ///
    /// ## Load-stall guard
    ///
    /// During the `Loading` phase, `await_ready` status polls keep sending
    /// activity resets, which would hide a hung NTFS volume read indefinitely.
    /// The **load heartbeat** (`record_load_progress`) is updated whenever a
    /// drive finishes loading.  If no heartbeat arrives within
    /// [`LOAD_STALL_TIMEOUT_SECS`] of the last one, the daemon force-retires
    /// even though IPC activity is still present.  This check runs when the
    /// idle deadline fires — the same moment as before — so existing behaviour
    /// is preserved.
    ///
    /// ## Session-tier timeout differentiation (D2.6.6)
    ///
    /// - Tier 0 (CLI): `base_timeout` (default 10 min)
    /// - Tier 1 (TUI / GUI / MCP): `base_timeout × 3` (default 30 min)
    ///
    /// The tier is re-read each time the deadline is extended, so a session
    /// upgrade takes effect on the very next activity reset.
    ///
    /// ## Active-connection guard (D2.6.7)
    ///
    /// If connections are open when the deadline fires, the deadline is pushed
    /// one full window into the future and the loop continues.
    pub(crate) async fn run_idle_timer(&mut self) {
        let Some(base_timeout) = self.idle_timeout else {
            // --no-retire: wait for an explicit shutdown signal only.
            let _shutdown = self.shutdown_rx.wait_for(|&done| done).await;
            return;
        };

        // Clone the handle so we can borrow `self.shutdown_rx` mutably in
        // `select!` while also accessing the handle fields from a separate
        // binding — the borrow checker cannot see through field projections.
        let handle = self.handle.clone();

        // Seed the sliding window at a full timeout from now.
        let initial_eff = Self::effective_timeout_from_tier(
            base_timeout,
            handle.max_session_tier.load(Ordering::Relaxed),
        );
        let idle_sleep = tokio::time::sleep(initial_eff);
        tokio::pin!(idle_sleep);

        loop {
            tokio::select! {
                // ── Shutdown wins above all else ─────────────────────────
                _ = self.shutdown_rx.wait_for(|&done| done) => {
                    tracing::info!("Shutdown requested");
                    return;
                }

                // ── Activity: extend the sliding-window deadline ─────────
                () = handle.activity_notify.notified() => {
                    let eff = Self::extended_timeout_for_activity(&handle, base_timeout);
                    idle_sleep.as_mut().reset(tokio::time::Instant::now() + eff);
                }

                // ── Idle deadline fired ──────────────────────────────────
                () = &mut idle_sleep => {
                    match Self::idle_deadline_fired(&handle, base_timeout) {
                        Some(reset_after) => {
                            idle_sleep.as_mut().reset(
                                tokio::time::Instant::now() + reset_after,
                            );
                        }
                        None => return,
                    }
                }
            }
        }
    }

    /// Compute the new effective timeout for the activity-notify
    /// branch and emit the matching trace.
    ///
    /// Re-reads the session tier so an MCP / TUI upgrade takes effect
    /// immediately on the next request.
    fn extended_timeout_for_activity(handle: &LifecycleHandle, base_timeout: Duration) -> Duration {
        let tier = handle.max_session_tier.load(Ordering::Relaxed);
        let eff = Self::effective_timeout_from_tier(base_timeout, tier);
        tracing::trace!(
            effective_secs = eff.as_secs(),
            session_tier = tier,
            "Idle deadline extended by activity"
        );
        eff
    }

    /// Decide what to do when the idle-deadline timer fires.
    ///
    /// Returns `Some(reset_after)` to push the deadline forward (the
    /// load-stall guard already returned `None` if it tripped, so a
    /// `Some` return always means defer because of active connections);
    /// returns `None` to instruct the caller to retire.
    ///
    /// The load-stall guard runs **before** the active-connection
    /// guard so a stuck NTFS read is caught even when clients are
    /// polling `status` (those polls extend the idle deadline but
    /// don't update the heartbeat).
    fn idle_deadline_fired(handle: &LifecycleHandle, base_timeout: Duration) -> Option<Duration> {
        if Self::load_stalled_force_retire(handle) {
            return None;
        }

        let conns = handle.active_connections();
        if conns > 0 {
            tracing::debug!(
                connections = conns,
                "Idle deadline fired but active connections open — deferring"
            );
            let tier = handle.max_session_tier.load(Ordering::Relaxed);
            return Some(Self::effective_timeout_from_tier(base_timeout, tier));
        }

        // Retire path: trace the cause, emit ShuttingDown, signal the
        // caller to break the loop.
        let tier = handle.max_session_tier.load(Ordering::Relaxed);
        let eff = Self::effective_timeout_from_tier(base_timeout, tier);
        tracing::info!(
            timeout_secs = eff.as_secs(),
            session_tier = tier,
            "Idle timeout reached — auto-retiring"
        );
        handle.events.emit(DaemonEvent::ShuttingDown {
            reason: format!("idle timeout ({}s, tier {tier})", eff.as_secs()),
        });
        None
    }

    /// Returns `true` when the load heartbeat is older than the
    /// stall threshold, in which case the caller must force-retire.
    ///
    /// Once `LifecycleHandle::record_load_complete` has been called,
    /// the guard is permanently disarmed: a fully-loaded daemon
    /// serving zero queries is legitimately idle, not stalled.
    /// Per-drive stuck-load detection remains active independently via
    /// `DRIVE_LOAD_TIMEOUT` inside `collect_drive_load_results`.
    fn load_stalled_force_retire(handle: &LifecycleHandle) -> bool {
        if handle.load_complete.load(Ordering::Relaxed) {
            return false;
        }
        let last_hb = handle.load_heartbeat.load(Ordering::Relaxed);
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |dur| dur.as_secs());
        let hb_age = now_epoch.saturating_sub(last_hb);
        tracing::debug!(
            heartbeat_age_secs = hb_age,
            stall_threshold = LOAD_STALL_TIMEOUT_SECS,
            "Idle deadline fired — checking load heartbeat"
        );
        if last_hb > 0 && hb_age >= LOAD_STALL_TIMEOUT_SECS {
            tracing::error!(
                stall_secs = LOAD_STALL_TIMEOUT_SECS,
                heartbeat_age_secs = hb_age,
                "Load stalled — no drive progress, force-retiring"
            );
            handle.events.emit(DaemonEvent::ShuttingDown {
                reason: format!("load stalled (no progress for {LOAD_STALL_TIMEOUT_SECS}s)"),
            });
            return true;
        }
        false
    }

    /// Compute the effective idle timeout from the base and the session tier.
    ///
    /// - Tier 0 (CLI / unknown): `base_timeout`
    /// - Tier 1+ (TUI / GUI / MCP): `base_timeout × 3`
    const fn effective_timeout_from_tier(base: Duration, tier: u8) -> Duration {
        if tier >= 1 {
            base.saturating_mul(3)
        } else {
            base
        }
    }

    /// Get the data directory path (parent of PID file).
    pub(crate) fn data_dir(&self) -> &std::path::Path {
        self.pid_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
    }

    // ── Private helpers ───────────────────────────────────────────────

    /// Check if a process with the given PID is alive (Unix).
    #[cfg(unix)]
    #[expect(
        clippy::single_call_fn,
        reason = "platform-specific helper — clarity over inlining"
    )]
    fn is_process_alive(pid: u32) -> bool {
        // pid_t is i32; PIDs above i32::MAX are invalid on POSIX.
        let Ok(target_pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        #[expect(
            unsafe_code,
            reason = "kill(pid, 0) is a standard POSIX liveness check"
        )]
        // SAFETY: `kill(pid, 0)` is a standard POSIX liveness check — it
        // sends no signal, just tests whether the process exists.
        let alive = unsafe { libc::kill(target_pid, 0_i32) == 0_i32 };
        alive
    }

    /// Check if a process with the given PID is alive (Windows).
    #[cfg(windows)]
    fn is_process_alive(pid: u32) -> bool {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        #[expect(unsafe_code, reason = "OpenProcess requires unsafe FFI")]
        // SAFETY: `OpenProcess` is a well-defined Win32 API; we only pass
        // a static access mask plus the caller-provided pid and inherit
        // its raw handle out.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };

        handle.is_ok_and(|proc_handle| {
            #[expect(
                unsafe_code,
                reason = "CloseHandle balances the OpenProcess call above"
            )]
            // SAFETY: `proc_handle` was just returned by `OpenProcess` and
            // is not aliased anywhere else, so closing it now is sound.
            let _close = unsafe { CloseHandle(proc_handle) };
            true
        })
    }

    /// `FNV-1a` hash of the current executable path (S4.3.1).
    #[expect(
        clippy::single_call_fn,
        reason = "hashing helper — clarity over inlining"
    )]
    fn exe_path_hash() -> u64 {
        let exe_path = std::env::current_exe()
            .map(|exe| exe.to_string_lossy().to_string())
            .unwrap_or_default();
        Self::fnv1a_hash(exe_path.as_bytes())
    }

    /// `FNV-1a` 64-bit hash (no external dep needed).
    fn fnv1a_hash(data: &[u8]) -> u64 {
        let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
        for &byte in data {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01B3);
        }
        hash
    }

    /// Generate a random 16-char hex nonce for the shutdown handshake
    /// (S4.4.9).
    ///
    /// # Security property (WI-8.2)
    ///
    /// This nonce is **not** a cryptographic authenticator. It provides
    /// *liveness* / accidental-cross-talk protection — proving the shutdown
    /// caller read the current PID file and is talking to *this* daemon
    /// incarnation, not a stale one. Its confidentiality rests **entirely**
    /// on the `0700` runtime/PID-file directory (see
    /// [`uffs_security::fs::create_secure_dir`], hardened in WI-2.2): any
    /// process that can *read* the PID file already learns the nonce, so the
    /// nonce defends only against callers that cannot read it. The FNV-1a
    /// exe-path hash on the same PID line is likewise an integrity/sanity
    /// check, not a signature.
    ///
    /// If the threat model ever requires *authenticating* the shutdown peer
    /// (e.g. a multi-user box where another user can read the runtime dir),
    /// replace this scheme with an HMAC over a shared secret delivered out of
    /// band — do not add bits to the nonce and call it authentication.
    #[expect(
        clippy::single_call_fn,
        reason = "nonce generation — clarity over inlining"
    )]
    fn generate_nonce() -> String {
        use rand::Rng as _;
        let mut nonce_bytes = [0_u8; 8];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let mut nonce_str = String::with_capacity(16_usize);
        for byte in &nonce_bytes {
            use core::fmt::Write as _;
            let _ignore = write!(nonce_str, "{byte:02x}");
        }
        nonce_str
    }

    /// Parse a PID file and extract its fields.
    ///
    /// Returns `(pid, timestamp, exe_hash, nonce)`.
    #[expect(
        clippy::single_call_fn,
        reason = "PID file parser — public API for clients"
    )]
    pub(crate) fn parse_pid_file(path: &std::path::Path) -> Option<(u32, u64, u64, String)> {
        let file_content = std::fs::read_to_string(path).ok()?;
        let mut lines_iter = file_content.lines();
        let pid: u32 = lines_iter.next()?.parse().ok()?;
        let timestamp: u64 = lines_iter.next()?.parse().ok()?;
        let exe_hash: u64 = lines_iter.next()?.parse().ok()?;
        let nonce = lines_iter.next()?.to_owned();
        Some((pid, timestamp, exe_hash, nonce))
    }

    /// Get the expected `exe_path_hash` for daemon identity verification.
    ///
    /// Clients call this to compute what the daemon's exe hash should be,
    /// then compare against the PID file.
    #[expect(
        clippy::single_call_fn,
        reason = "exe hash verifier — public API for clients"
    )]
    pub(crate) fn expected_daemon_exe_hash() -> u64 {
        if let Ok(current) = std::env::current_exe()
            && let Some(dir) = current.parent()
        {
            let daemon = dir.join("uffsd");
            if daemon.exists() {
                return Self::fnv1a_hash(daemon.to_string_lossy().as_bytes());
            }
            let daemon_exe = dir.join("uffsd.exe");
            if daemon_exe.exists() {
                return Self::fnv1a_hash(daemon_exe.to_string_lossy().as_bytes());
            }
        }
        0_u64
    }
}

impl Drop for LifecycleManager {
    fn drop(&mut self) {
        // Only clean up files that belong to this instance.  If we detected
        // another running daemon (`check_stale_pid` returned false) we never
        // wrote a PID file, so we must not delete the other daemon's files.
        if self.owns_pid_file {
            self.remove_pid_file();
            self.remove_launch_state();
            self.remove_socket_file();
        }
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::*;
    use crate::events;

    /// Helper: construct a `LifecycleManager` wired to a temp directory.
    fn test_lifecycle(timeout: Option<Duration>) -> LifecycleManager {
        let dir = std::env::temp_dir().join(format!("uffs-test-{}", std::process::id()));
        drop(std::fs::create_dir_all(&dir));
        let (events_tx, _rx) = events::event_channel();
        LifecycleManager::new(&dir, timeout, events_tx)
    }

    // ── effective_timeout_from_tier ──────────────────────────────────────

    #[test]
    fn tier_0_returns_base_timeout() {
        let base = Duration::from_mins(10);
        assert_eq!(LifecycleManager::effective_timeout_from_tier(base, 0), base);
    }

    #[test]
    fn tier_1_returns_3x_base_timeout() {
        let base = Duration::from_mins(10);
        assert_eq!(
            LifecycleManager::effective_timeout_from_tier(base, 1),
            Duration::from_mins(30)
        );
    }

    #[test]
    fn tier_255_returns_3x_base_timeout() {
        let base = Duration::from_secs(100);
        assert_eq!(
            LifecycleManager::effective_timeout_from_tier(base, 255),
            Duration::from_mins(5)
        );
    }

    // ── Sliding-window: activity extends deadline ───────────────────────

    #[tokio::test]
    async fn idle_timer_extends_deadline_on_activity() {
        // 200 ms idle timeout — should NOT fire because we reset at 100 ms.
        let mut mgr = test_lifecycle(Some(Duration::from_millis(200)));
        let handle = mgr.handle();

        // Spawn the idle timer.
        let timer = tokio::spawn(async move { mgr.run_idle_timer().await });

        // After 100 ms, send activity.
        tokio::time::sleep(Duration::from_millis(100)).await;
        handle.reset_idle_timer();

        // After another 150 ms (total 250 ms from start, but only 150 ms
        // from the activity reset), the timer should still be running because
        // the 200 ms window was extended at t=100 ms.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !timer.is_finished(),
            "timer should still be alive after activity reset"
        );

        // Now wait for the remaining ~50 ms + margin so the timer actually fires.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(timer.is_finished(), "timer should have fired by now");
    }

    // ── Sliding-window: genuine idle causes retirement ──────────────────

    #[tokio::test]
    async fn idle_timer_retires_after_full_window_without_activity() {
        let mut mgr = test_lifecycle(Some(Duration::from_millis(100)));

        let timer = tokio::spawn(async move { mgr.run_idle_timer().await });

        // No activity — timer should fire after ~100 ms.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            timer.is_finished(),
            "timer should have retired after idle window"
        );
    }

    // ── Shutdown signal wins immediately ─────────────────────────────────

    #[tokio::test]
    async fn shutdown_signal_preempts_idle_timer() {
        let mut mgr = test_lifecycle(Some(Duration::from_hours(1)));
        let handle = mgr.handle();

        let timer = tokio::spawn(async move { mgr.run_idle_timer().await });

        // Request shutdown immediately.
        handle.request_shutdown();

        // Timer should exit promptly.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(timer.is_finished(), "shutdown should preempt idle timer");
    }

    // ── Active connections defer retirement (D2.6.7) ─────────────────────

    #[tokio::test]
    async fn active_connections_defer_retirement() {
        let mut mgr = test_lifecycle(Some(Duration::from_millis(100)));
        let handle = mgr.handle();

        // Open a connection before the timer starts.
        handle.connection_opened();

        let h2 = handle.clone();
        let timer = tokio::spawn(async move { mgr.run_idle_timer().await });

        // Wait for the idle deadline to fire — it should be deferred.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !timer.is_finished(),
            "should not retire with active connections"
        );

        // Close the connection; the next deadline firing should retire.
        h2.connection_closed();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(timer.is_finished(), "should retire after connections close");
    }

    // ── No-retire mode waits for explicit shutdown ───────────────────────

    #[tokio::test]
    async fn no_retire_waits_for_shutdown() {
        let mut mgr = test_lifecycle(None);
        let handle = mgr.handle();

        let timer = tokio::spawn(async move { mgr.run_idle_timer().await });

        // Should not exit on its own.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !timer.is_finished(),
            "no-retire should not exit spontaneously"
        );

        handle.request_shutdown();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            timer.is_finished(),
            "no-retire should exit after shutdown signal"
        );
    }

    // ── Load-stall guard: heartbeat-age force-retire (Phase 5 G4 finding) ─

    /// Test helper installed on `LifecycleHandle` only under `cfg(test)`.
    /// Required because `LOAD_STALL_TIMEOUT_SECS` is wall-clock-based via
    /// `SystemTime::now()` and can't be mocked; without this we'd have to
    /// wait 300+ seconds per test.
    impl LifecycleHandle {
        pub(crate) fn set_load_heartbeat_for_test(&self, secs: u64) {
            self.load_heartbeat.store(secs, Ordering::Relaxed);
        }
    }

    /// Helper: epoch seconds "now" for the regression tests.
    fn epoch_now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |dur| dur.as_secs())
    }

    #[test]
    fn load_stall_force_retire_fires_during_loading_with_stale_heartbeat() {
        // Preserves the original safety-net contract: while loading is
        // in progress (load_complete unset) and no heartbeat update has
        // arrived for >= LOAD_STALL_TIMEOUT_SECS, the guard MUST fire.
        let mgr = test_lifecycle(Some(Duration::from_mins(1)));
        let handle = mgr.handle();

        let now = epoch_now_secs();
        handle.set_load_heartbeat_for_test(now.saturating_sub(LOAD_STALL_TIMEOUT_SECS + 100));

        assert!(
            LifecycleManager::load_stalled_force_retire(&handle),
            "guard must fire when heartbeat is stale and load_complete is unset"
        );
    }

    #[test]
    fn load_stall_force_retire_disarms_after_record_load_complete() {
        // Regression for Phase 5 G4 capture (LOG/uffsd-G4-bonus.log line
        // 104, 2 h 11 min mark): a daemon that finished loading long ago
        // but is serving zero queries against fully-Parked drives is
        // legitimately idle, not stalled.  Once `record_load_complete`
        // latches the load phase as done, the guard MUST stay quiet.
        let mgr = test_lifecycle(Some(Duration::from_mins(1)));
        let handle = mgr.handle();

        let now = epoch_now_secs();
        handle.set_load_heartbeat_for_test(now.saturating_sub(LOAD_STALL_TIMEOUT_SECS + 100));

        handle.record_load_complete();

        assert!(
            !LifecycleManager::load_stalled_force_retire(&handle),
            "guard must be disarmed after record_load_complete, even with stale heartbeat"
        );
    }

    #[test]
    fn record_load_complete_is_idempotent() {
        // Calling `record_load_complete` more than once must not re-arm
        // the guard or panic.  The latch is `false` → `true` exactly
        // once; subsequent calls are a no-op.
        let mgr = test_lifecycle(Some(Duration::from_mins(1)));
        let handle = mgr.handle();

        handle.record_load_complete();
        handle.record_load_complete();

        let now = epoch_now_secs();
        handle.set_load_heartbeat_for_test(now.saturating_sub(LOAD_STALL_TIMEOUT_SECS + 100));

        assert!(
            !LifecycleManager::load_stalled_force_retire(&handle),
            "guard must remain disarmed after multiple record_load_complete calls"
        );
    }

    // ── Session tier upgrades take effect on next activity ───────────────

    #[tokio::test]
    async fn session_tier_upgrade_extends_timeout() {
        // 100 ms base timeout at tier 0. After upgrade to tier 1, effective
        // timeout becomes 300 ms.
        let mut mgr = test_lifecycle(Some(Duration::from_millis(100)));
        let handle = mgr.handle();

        let timer = tokio::spawn(async move { mgr.run_idle_timer().await });

        // At 80 ms, upgrade session tier and send activity.
        tokio::time::sleep(Duration::from_millis(80)).await;
        handle.set_session_type("mcp"); // tier 1 → 300 ms effective
        handle.reset_idle_timer();

        // At 350 ms from activity (430 ms from start), timer should still be alive
        // because the new effective timeout is 300 ms from the activity at t=80 ms,
        // meaning deadline is at t=380 ms.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            !timer.is_finished(),
            "tier 1 timeout should extend deadline"
        );

        // Wait for the deadline to fire.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            timer.is_finished(),
            "should retire after tier-1 window expires"
        );
    }
}
