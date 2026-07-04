// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `--status` observability signals kept off the live-indexing hot path.
//!
//! Live-update liveness is reported as the **number of running per-shard
//! journal loops**, recorded once when they spawn (`set_active_loops` — a
//! single relaxed store). It is deliberately *not* a per-patch "last applied"
//! timestamp: that would add a store to every USN apply on the hot path, and
//! "N loops running" already answers the operative question — is live update
//! actually active? The daemon's filesystem locations are gathered on demand
//! from the shared path helpers. Both are read only when a `status` RPC lands.

use core::sync::atomic::{AtomicUsize, Ordering};

use uffs_client::protocol::response::{DaemonPaths, LiveUpdateInfo};

/// Number of per-shard journal loops currently running. Set once after the
/// loops spawn; `0` means live update is not active (offline MFT / non-Windows,
/// or before the loops start).
static ACTIVE_LOOPS: AtomicUsize = AtomicUsize::new(0);

/// Record how many live journal loops are running — called once, right after
/// they spawn. A single relaxed store, so it adds nothing to the per-patch
/// apply path.
pub(crate) fn set_active_loops(count: usize) {
    ACTIVE_LOOPS.store(count, Ordering::Relaxed);
}

/// Snapshot live-update liveness for a `status` RPC. `None` when no loops are
/// running, so the field is omitted for offline-MFT / non-Windows daemons.
pub(crate) fn snapshot() -> Option<LiveUpdateInfo> {
    match ACTIVE_LOOPS.load(Ordering::Relaxed) {
        0 => None,
        active_loops => Some(LiveUpdateInfo { active_loops }),
    }
}

/// The daemon's filesystem locations for a `status` RPC, gathered on demand
/// from the shared path helpers (index/cache dir, client socket/pipe, log dir).
/// Always available, so the caller wraps it in `Some`.
pub(crate) fn daemon_paths() -> DaemonPaths {
    DaemonPaths {
        data_dir: uffs_mft::cache::cache_dir().display().to_string(),
        socket: uffs_client::daemon_ctl::socket_path().display().to_string(),
        log_dir: std::env::var("UFFS_LOG_DIR").unwrap_or_default(),
    }
}
