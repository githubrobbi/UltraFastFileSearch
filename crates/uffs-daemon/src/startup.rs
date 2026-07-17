// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Pre-spawn startup helpers for [`crate::run_daemon`].
//!
//! Hosts the orchestrator's setup phase: panic-hook install,
//! structured startup logging, `daemon.toml` resolution, lifecycle-
//! manager bootstrap, data-source gathering + validation, and drive-
//! list resolution.  Extracted from `lib.rs` so the orchestrator and
//! the `spawn_*` cluster stay focused on lifecycle wiring without the
//! data-source-discovery noise.  Every fn here is `pub(crate)` — no
//! external caller.

use alloc::sync::Arc;
use std::path::PathBuf;

use crate::{DaemonConfig, config, events, lifecycle};

/// Bail if the daemon has nothing to serve.
pub(crate) fn validate_data_sources(
    mft_files: &[PathBuf],
    drives: &[uffs_mft::platform::DriveLetter],
    device_sources: &[(String, uffs_mft::platform::DriveLetter)],
    lifecycle_mgr: &lifecycle::LifecycleManager,
) -> anyhow::Result<()> {
    let has_data = !mft_files.is_empty() || !device_sources.is_empty() || {
        #[cfg(windows)]
        {
            !drives.is_empty()
        }
        #[cfg(not(windows))]
        {
            // `drives` is Windows-only; no auto-discovery on macOS/Linux.
            // The explicit type pins the annotation clippy expects on
            // discarded bindings.
            let _: &[uffs_mft::platform::DriveLetter] = drives;
            false
        }
    };
    if !has_data {
        tracing::error!(
            "No data sources provided. On macOS/Linux pass --mft-file; \
             on Windows, NTFS drives are auto-discovered."
        );
        lifecycle_mgr.remove_pid_file();
        anyhow::bail!(
            "Daemon has no data sources to load. \
             Provide --mft-file <path> (or --data-dir when launching via CLI)."
        );
    }
    Ok(())
}

/// Emit the startup `tracing::info!` line with every config field
/// the operator might want to grep for.  Extracted so the orchestrator
/// stays under clippy's `cognitive_complexity` budget.
pub(crate) fn log_daemon_starting(config: &DaemonConfig) {
    // NOTE: do NOT probe the Access Broker here.  The previous
    // `broker_available()` call used `GetFileAttributesW`, which *connects to*
    // the broker's single pipe instance and leaves it busy — so the real
    // `warm_up_broker_handles` request milliseconds later failed with
    // ERROR_PIPE_BUSY (2026-06-13 VM finding).  Broker presence is now
    // established only by attempting the handle request itself.
    // `git` is the short commit the binary was built from (emitted by this
    // crate's build.rs; "unknown" when git was unavailable at build time) — it
    // pins exactly which build a field log came from.
    tracing::info!(
        pid = std::process::id(),
        version = env!("CARGO_PKG_VERSION"),
        git = option_env!("UFFS_GIT_SHA").unwrap_or("unknown"),
        mft_files = ?config.mft_files,
        drives = ?config.drives,
        data_dir = ?config.data_dir,
        no_cache = config.no_cache,
        no_retire = config.no_retire,
        "uffsd starting"
    );
}

/// Publish the [`events::DaemonEvent::DaemonStarting`] notification
/// so any pre-IPC subscriber (e.g. the embedded MCP server) sees the
/// transition.
pub(crate) fn emit_daemon_starting_event(event_tx: &events::EventSender) {
    event_tx.emit(events::DaemonEvent::DaemonStarting {
        pid: std::process::id(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    });
}

/// Install a panic hook that runs the existing default hook (so the
/// usual stack trace + payload still print) and then force-exits.
///
/// Without this, a panic on any blocking I/O thread can leave the
/// daemon in a zombie state — the default hook tries to unwind through
/// kernel-mode I/O which may never return.  Force-exiting with code
/// `101` matches Rust's standard panic exit code so process supervisors
/// don't see a "clean" 0-exit on a panic.
pub(crate) fn install_catastrophe_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        #[expect(clippy::exit, reason = "catastrophe safety net — force-exit on panic")]
        {
            std::process::exit(101);
        }
    }));
}

/// Resolve the operator's `daemon.toml` from the platform-default
/// location and emit a structured `tracing::info!` event with the
/// resolved path.
///
/// Phase 6 Commit C task 6.5 helper.  A missing file is **not** an
/// error: [`config::Config::load_default`] returns the
/// Phase-3-equivalent defaults so every existing deployment boots
/// with the same observable behavior (plan task 6.8).  A malformed
/// file propagates as a startup error so a typo doesn't silently
/// fall back to defaults — the operator gets a precise parser error
/// with line and column.
///
/// Returned as `Arc<Config>` so the index manager and any future
/// background controller can share a single read-only view without
/// cloning the BTreeMap-bearing `[shards.per_drive]` table.
pub(crate) fn load_daemon_config() -> anyhow::Result<Arc<config::Config>> {
    let cfg = config::Config::load_default()
        .map_err(|err| anyhow::anyhow!("Failed to load daemon.toml from default path: {err}"))?;
    tracing::info!(
        daemon_config_path = ?config::Config::default_path(),
        "daemon.toml resolved (or defaults used when missing)",
    );
    Ok(Arc::new(cfg))
}

/// Build the [`lifecycle::LifecycleManager`], gate against another
/// running instance via the PID file, and write a fresh PID file.
///
/// Returns the manager ready for use, or bails when another daemon is
/// already alive.
pub(crate) fn bootstrap_lifecycle_manager(
    config: &DaemonConfig,
    event_tx: events::EventSender,
) -> anyhow::Result<lifecycle::LifecycleManager> {
    // Determine data directory:
    // - lifecycle_dir: %LOCALAPPDATA%\uffs (or, for an ephemeral instance — see
    //   `DaemonConfig::ephemeral_id` — `.../uffs/ephemeral/<id>`) — PID/socket/lock
    //   files
    // - data_dir: user-supplied --data-dir (for MFT file discovery/hot-load)
    let lifecycle_dir = config.ephemeral_id.as_deref().map_or_else(
        || {
            dirs_next::data_local_dir()
                .map_or_else(|| PathBuf::from("/tmp/uffs"), |base| base.join("uffs"))
        },
        uffs_client::daemon_ctl::ephemeral_lifecycle_dir,
    );

    let idle_timeout = if config.no_retire {
        None
    } else {
        Some(core::time::Duration::from_secs(config.idle_timeout))
    };
    let mut lifecycle_mgr =
        lifecycle::LifecycleManager::new(&lifecycle_dir, idle_timeout, event_tx);

    tracing::info!(data_dir = %lifecycle_mgr.data_dir().display(), "Lifecycle data directory");

    if !lifecycle_mgr.check_stale_pid() {
        tracing::error!("Another daemon instance is already running");
        anyhow::bail!("Another daemon instance is already running");
    }

    lifecycle_mgr.write_pid_file()?;
    lifecycle_mgr.write_launch_state();
    tracing::info!("PID file written");
    Ok(lifecycle_mgr)
}

/// Merge `--mft-file` arguments with files discovered under
/// `--data-dir`, applying the `--drive` filter when present.
pub(crate) fn gather_mft_files(config: &DaemonConfig) -> Vec<PathBuf> {
    let mut mft_files = config.mft_files.clone();
    let Some(dir) = config.data_dir.as_ref() else {
        return mft_files;
    };

    let discovered = uffs_mft::discovery::discover_mft_files(dir);
    let filtered: Vec<PathBuf> = if config.drives.is_empty() {
        discovered
    } else {
        discovered
            .into_iter()
            .filter(|path| drive_letter_matches(path, &config.drives))
            .collect()
    };
    tracing::info!(
        data_dir = %dir.display(),
        count = filtered.len(),
        filter = ?config.drives,
        "Discovered MFT files from --data-dir"
    );
    mft_files.extend(filtered);
    mft_files
}

/// Returns `true` when `path`'s parent directory carries a
/// `drive_<letter>` prefix that matches one of `wanted` (case-
/// insensitive — `DriveLetter::parse` canonicalises to uppercase).
///
/// `pub(crate)` so the regression-pin test in
/// `crate::tests` can exercise the contract directly without
/// going through [`gather_mft_files`].
pub(crate) fn drive_letter_matches(
    path: &std::path::Path,
    wanted: &[uffs_mft::platform::DriveLetter],
) -> bool {
    path.parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("drive_"))
        .and_then(|suffix| suffix.chars().next())
        .and_then(|letter_ch| uffs_mft::platform::DriveLetter::parse(letter_ch).ok())
        .is_some_and(|letter| wanted.contains(&letter))
}

/// Resolve the drive list to scan.
///
/// On Windows, an empty `--drive` triggers auto-discovery; non-empty
/// respects the explicit list.  Always empty on non-Windows since
/// live MFT scanning is Windows-only.
#[cfg(windows)]
pub(crate) fn resolve_drive_list(config: &DaemonConfig) -> Vec<uffs_mft::platform::DriveLetter> {
    let explicit = config.drives.clone();
    if explicit.is_empty() {
        let auto_drives = uffs_mft::detect_ntfs_drives();
        tracing::info!(
            count = auto_drives.len(),
            drives = ?auto_drives,
            "Auto-discovered NTFS drives (no --drive flag)"
        );
        auto_drives
    } else {
        tracing::info!(
            drives = ?explicit,
            "Loading only requested drives (--drive flag)"
        );
        explicit
    }
}

/// Non-Windows variant: live MFT scanning is unsupported, so the
/// drive list is always empty regardless of `config`.
#[cfg(not(windows))]
pub(crate) const fn resolve_drive_list(
    _config: &DaemonConfig,
) -> Vec<uffs_mft::platform::DriveLetter> {
    Vec::new()
}
