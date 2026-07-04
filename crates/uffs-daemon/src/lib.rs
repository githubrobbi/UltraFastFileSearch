// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! UFFS Daemon library — reusable daemon entry point.
//!
//! This crate exposes [`run_daemon`] so the daemon logic can be invoked
//! both from the standalone `uffs-daemon` binary and from the embedded
//! `uffs --daemon run` subcommand in the CLI.
//!
//! Setup helpers + shutdown coordination live in sibling modules
//! ([`log_init`], `startup`, `shutdown` — the latter two are
//! crate-private); the orchestrator [`run_daemon`] and the `spawn_*`
//! cluster live here so the parent-task lifetime relationships stay
//! cohesive in one file.
//!
//! # Environment
//!
//! Env vars read by this crate (registry:
//! `docs/architecture/code-quality/build_codegen_policy.md` §5, playbook
//! §1049-1056).  Cache-tier knobs are read via `pub(crate) const FOO_ENV: &str
//! = "UFFS_FOO_…";` indirections in `cache::policy`; the audit script
//! `scripts/dev/build_codegen_audit.sh` detects these.
//!
//! | Env var | Type | Default | Notes |
//! |---|---|---|---|
//! | `CARGO_MANIFEST_DIR` | `path` | (set by Cargo) | Test-fixture path resolution.  CARGO semver class. |
//! | `CARGO_PKG_VERSION` | `string` | (set by Cargo) | Read via `env!()` for status payload + log preludes.  CARGO semver class. |
//! | `RUST_LOG` | `string` | `info` | `tracing-subscriber` filter directive; consulted in `main` when `UFFS_LOG` is unset.  STANDARD semver class (tracing convention). |
//! | `UFFS_LOG` | `string` | `info` | UFFS-specific log level override for the daemon binary.  INTERNAL semver class. |
//! | `UFFS_HOT_TO_WARM_IDLE_SECS` | `int` (seconds) | `600` (10 min) | Cache tier `Hot → Warm` transition timer override (via `HOT_TO_WARM_IDLE_ENV` const indirection).  INTERNAL semver class. |
//! | `UFFS_WARM_TO_PARKED_IDLE_SECS` | `int` (seconds) | `1_800` (30 min) | Cache tier `Warm → Parked` transition timer override (via `WARM_TO_PARKED_IDLE_ENV` const indirection).  INTERNAL semver class. |
//! | `UFFS_PARKED_TO_COLD_IDLE_SECS` | `int` (seconds) | `86_400` (24 h) | Cache tier `Parked → Cold` transition timer override (via `PARKED_TO_COLD_IDLE_ENV` const indirection).  INTERNAL semver class. |
//! | `UFFS_USN_REFRESH_INTERVAL_SECS` | `int` (seconds) | `300` (5 min) | USN journal refresh interval override (via `USN_REFRESH_INTERVAL_ENV` const indirection).  INTERNAL semver class. |
//! | `UFFS_SEARCH_MAX_CONCURRENCY` | `int` (search permits) | auto: `max(2, cpus × 26 / (drives × 10))` | Overrides the auto-tuned search-permit target for `(cpus, drives)` topology (via `index::DriveIndex::SEARCH_CONCURRENCY_ENV` const indirection).  INTERNAL semver class. |
//! | `XDG_RUNTIME_DIR` | `path` | (XDG: `/run/user/$UID`) | Linux daemon-socket location.  STANDARD semver class. |
//!
//! # Concurrency
//!
//! Runs on `#[tokio::main]` (default multi-threaded runtime).  The
//! daemon's startup graph spawns a fixed set of long-lived tasks via
//! the named `spawn_*` constructors above:
//!
//! * `spawn_load_task` — drive-load orchestration with per-drive timeout
//!   (`IndexManager::DRIVE_LOAD_TIMEOUT`).
//! * `spawn_ipc_servers` — Unix-socket accept loop + Windows `AF_UNIX` bridge;
//!   per-connection idle timeout (`IDLE_CONNECTION_SECS`).
//! * `spawn_stats_heartbeat` — periodic `DaemonStats` snapshot to subscribed
//!   clients.
//! * `spawn_idle_demote_controller` — memory-pressure-driven shard-demote
//!   signal source.
//! * `spawn_journal_loops_for_warm_shards` — per-shard USN journal loops, each
//!   cooperatively cancelled via a dedicated `watch::Sender<bool>`.
//! * `spawn_pressure_subscriber` — listens to OS memory-pressure events and
//!   drives the demote controller.
//!
//! All shutdown coordination flows through the daemon's top-level
//! `LifecycleHandle` (`watch::Sender<bool>` broadcast + force-exit
//! watchdog).  See the crate-private `lifecycle` module for the full
//! ownership diagram and
//! `docs/architecture/code-quality/concurrency_policy.md` for the
//! workspace contract.

// Enable unstable Windows Unix domain socket support (Windows 10 1803+).
#![cfg_attr(windows, feature(windows_unix_domain_sockets))]

extern crate alloc;

// Linked for this crate's binary target(s), which call
// `uffs_version::handle_version!` in `main`; the library itself does not
// reference it (sanctioned unused-crate-dependencies marker).
use alloc::sync::Arc;
use std::path::PathBuf;

// Suppress unused crate warnings for deps used by sub-modules, the binary, or
// behind cfg gates.
use clap as _;
use dirs_next as _;
use mimalloc as _;
use serde as _;
use thiserror as _;
use tracing_appender as _;
use tracing_subscriber as _;
use uffs_mft as _;
use uffs_version as _;

/// Broker client — volume handle requests (Windows) / stubs (other).
mod broker_client;
/// Shard-based index cache with per-drive lifecycle.
///
/// Phase 1 of the memory-tiering work — see
/// `docs/refactor/memory-tiering-implementation-plan.md`.
mod cache;
/// `daemon.toml` parser — Phase 6 of memory-tiering.
///
/// Schema mirrors plan §11; defaults match Phase-3 static behavior.
/// The type is named [`config::Config`] (idiomatic
/// `crate::module::Type`) to avoid collision with the existing
/// [`DaemonConfig`] runtime-args wrapper that this file owns.
/// Commit C wires the loader into [`run_daemon`] startup and
/// replaces the env-var-overridable static getters in
/// [`crate::cache::policy`] with config-driven readers.
mod config;
/// Daemon event broadcasting — push notifications to connected clients.
pub mod events;
/// JSON-RPC request handler.
mod handler;
/// Index manager — loads and queries MFT data.
mod index;
/// IPC server — Unix domain socket / named pipe listener.
mod ipc;
/// Lifecycle manager — PID file, idle timer, shutdown coordination.
mod lifecycle;
/// JSON-RPC protocol types.
mod protocol;
/// Phase 2b memory-tiering: runtime-tempfile orphan cleanup at boot.
mod runtime_orphans;
/// Process-level memory and runtime telemetry.
pub(crate) mod telemetry;

/// Tracing-subscriber bootstrap (re-exports [`init_tracing`] as part
/// of the daemon library's public API).
pub mod log_init;
/// Graceful-shutdown + force-exit watchdog.
mod shutdown;
/// Pre-spawn startup helpers (panic-hook install, data-source
/// gathering, lifecycle bootstrap).
mod startup;

pub use log_init::init_tracing;

/// Configuration for [`run_daemon`].
pub struct DaemonConfig {
    /// MFT files to load.
    pub mft_files: Vec<PathBuf>,
    /// Data directory containing `drive_*` subdirectories.
    pub data_dir: Option<PathBuf>,
    /// Explicit drive letters (Windows only).
    pub drives: Vec<uffs_mft::platform::DriveLetter>,
    /// Idle timeout in seconds (0 = use default 7200s / 2 hours).
    pub idle_timeout: u64,
    /// Disable auto-retire.
    pub no_retire: bool,
    /// Skip cache.
    pub no_cache: bool,
    /// Log level string (e.g. "info", "debug").
    pub log_level: String,
    /// Optional log file path.  When set, daemon tracing output is
    /// written to this file instead of stdout.  If the value is empty
    /// or `"-"`, the daemon defaults to `./uffs_daemon.log` in the
    /// current working directory.
    pub log_file: Option<PathBuf>,
}

/// Run the UFFS daemon with the given configuration.
///
/// This is the main entry point shared by both the standalone
/// `uffs-daemon` binary and the embedded `uffs --daemon run` subcommand.
///
/// **Does not return** until the daemon shuts down (idle timeout,
/// RPC shutdown, or signal).
///
/// # Errors
///
/// Returns an error if another daemon is already running, data sources
/// are missing, or the IPC server fails to bind.
pub async fn run_daemon(config: DaemonConfig) -> anyhow::Result<()> {
    startup::install_catastrophe_panic_hook();
    startup::log_daemon_starting(&config);

    let (event_tx, _event_rx) = events::event_channel();
    startup::emit_daemon_starting_event(&event_tx);

    let lifecycle_mgr = startup::bootstrap_lifecycle_manager(&config, event_tx.clone())?;

    // D5.0: clean up stale shmem files from previous daemon sessions.
    uffs_client::shmem::cleanup_stale_shmem_files();

    // Phase 2b: wipe runtime-tempfile leftovers from dead daemon PIDs
    // before our own PID-scoped subdir gets created by the first
    // `load_compact_cache` call.  The cross-platform `cleanup_orphans`
    // contract makes this safe even when other live daemons share the
    // root directory.
    runtime_orphans::sweep_runtime_tempfile_orphans();

    // Phase 6 Commit C task 6.5 — resolve `daemon.toml` from the
    // platform-default location.  Factored out to keep
    // `run_daemon`'s cognitive complexity under the workspace's
    // strict-clippy ceiling.
    let daemon_config = startup::load_daemon_config()?;

    // Create index manager — uses the user-supplied --data-dir for offline MFT
    // discovery and hot-loading (not the lifecycle directory).
    let idx = Arc::new(index::IndexManager::new(
        config.data_dir.clone(),
        event_tx,
        Arc::clone(&daemon_config),
    ));
    tracing::debug!(index_data_dir = ?idx.data_dir(), "Index manager created");

    let mft_files = startup::gather_mft_files(&config);
    let drives = startup::resolve_drive_list(&config);
    tracing::info!(mft_files = mft_files.len(), drives = ?drives, "Final data sources");

    // Refuse to start with zero data sources — an empty daemon is useless.
    startup::validate_data_sources(&mft_files, &drives, &lifecycle_mgr)?;
    tracing::info!("Data sources validated OK");

    let load_task = spawn_load_task(
        Arc::clone(&idx),
        mft_files,
        drives,
        config.no_cache,
        lifecycle_mgr.handle(),
    );

    let ipc_task = spawn_ipc_servers(&idx, &lifecycle_mgr);
    let _stats_task = spawn_stats_heartbeat(Arc::clone(&idx), lifecycle_mgr.handle());
    let _mem_snapshot_task = telemetry::spawn_mem_snapshot_task(
        Arc::clone(&idx),
        telemetry::DEFAULT_MEM_SNAPSHOT_INTERVAL,
    );
    // Phase 3 Commit D — periodic shard idle-demote sweep.
    let _idle_demote_task = spawn_idle_demote_controller(Arc::clone(&idx));

    // Phase 7 activation: per-shard journal loops are spawned
    // inside `spawn_load_task` after `record_load_complete()`.  They
    // replace the deleted Phase-5 `spawn_usn_refresh_controller`
    // 5-min global tick with per-letter event-driven refresh — see
    // `spawn_journal_loops_for_warm_shards` below.

    // Phase 5 task 5.6 — memory-pressure subscriber.  Cascade-
    // demotes LRU Warm shards on `Low` transitions until pressure
    // clears (`High`) or no Warm shards remain.  No-op on Mac/Linux
    // (the platform `PressureSignal` never fires).
    let _pressure_task = spawn_pressure_subscriber(Arc::clone(&idx));

    // Run idle timer (blocks until shutdown or timeout) then tear
    // everything down.  Returns `!` so `force_exit_with_watchdog`
    // covers the post-await tail.
    shutdown::await_shutdown_then_force_exit(lifecycle_mgr, ipc_task, load_task).await
}

/// Spawn the parallel load task that reads `mft_files` from disk and
/// (on Windows) the live drives via the broker / direct path.  The
/// task also enforces the zero-drive shutdown guard so a daemon that
/// fails every load doesn't linger in `Ready` with an empty index.
fn spawn_load_task(
    load_index: Arc<index::IndexManager>,
    mft_files: Vec<PathBuf>,
    drives: Vec<uffs_mft::platform::DriveLetter>,
    no_cache: bool,
    load_lifecycle: lifecycle::LifecycleHandle,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!(mft_files = mft_files.len(), drives = ?drives, "Load task starting");
        if !mft_files.is_empty() {
            tracing::info!("Loading MFT files from data dir...");
            load_index.load_from_data_dir(&mft_files, no_cache).await;
            tracing::info!("MFT files loaded");
        }
        // Live-MFT scanning is Windows-only; on every other platform the
        // load task is fully covered by `load_from_data_dir` above.
        #[cfg(windows)]
        load_live_drives_if_windows(&load_index, &drives, no_cache, &load_lifecycle).await;
        tracing::info!("Load task completed");

        // Latch the load phase as complete: from this point on, a daemon
        // serving zero queries against fully-loaded drives is legitimately
        // idle (not stalled), so the load-stall force-retire guard is
        // permanently disarmed.  Per-drive stuck-load detection remains
        // active via `DRIVE_LOAD_TIMEOUT` inside the load loop itself.
        // Closes the Phase 5 G4 finding (LOG/uffsd-G4-bonus.log line 104,
        // 2 h 11 min force-retire on a healthy idle daemon).
        load_lifecycle.record_load_complete();

        // Phase 7 activation: spawn one per-shard journal loop for
        // every loaded letter.  Replaces the deleted Phase-5 global
        // 5-min `refresh_usn_for_warm_shards` tick.  The applier
        // task's JoinHandle is fire-and-forget here — it stays alive
        // for the daemon's lifetime via the `Arc<RegistryPatchSink>`
        // captured by the per-loop sink clones; on shutdown the
        // applier exits cleanly when the last sink Arc drops.
        let _journal_applier = spawn_journal_loops_for_warm_shards(&load_index).await;

        zero_drive_shutdown_guard(&load_index, &load_lifecycle).await;
    })
}

/// Windows live-drive load step.  Walks the broker for an elevated
/// handle per drive (best-effort), then drives `load_live_drives` to
/// scan their MFTs.
#[cfg(windows)]
async fn load_live_drives_if_windows(
    load_index: &Arc<index::IndexManager>,
    drives: &[uffs_mft::platform::DriveLetter],
    no_cache: bool,
    load_lifecycle: &lifecycle::LifecycleHandle,
) {
    if drives.is_empty() {
        return;
    }
    warm_up_broker_handles_unless_elevated(drives);
    tracing::info!(drives = ?drives, "Loading live drives...");
    load_index
        .load_live_drives(drives, no_cache, load_lifecycle)
        .await;
    tracing::info!("Live drives loaded");
}

/// Run the broker warm-up only when the daemon is **not** already elevated.
///
/// Gate on the daemon's OWN elevation, not on a broker probe.  An elevated
/// daemon opens volumes directly (`CreateFileW`), so a broker request would be
/// a futile per-drive pipe-open + WARN.  Crucially, `is_elevated()` is a token
/// query — it does NOT touch the broker pipe, so it has none of the race the
/// removed `broker_available()` probe had (that probe connected to and consumed
/// the broker's single pipe instance, starving the real request; 2026-06-13 VM
/// finding).  When NOT elevated, the handle request itself is the authoritative
/// broker-presence test: it succeeds when a broker is serving and fails fast
/// (WARN + direct-open fallback) when not.
///
/// Extracted from `load_live_drives_if_windows` so that caller stays under the
/// `cognitive_complexity` ceiling.
#[cfg(windows)]
fn warm_up_broker_handles_unless_elevated(drives: &[uffs_mft::platform::DriveLetter]) {
    if uffs_mft::is_elevated() {
        tracing::debug!(
            pid = std::process::id(),
            "Daemon is elevated — skipping broker warm-up (direct volume open)"
        );
        return;
    }
    tracing::info!(
        pid = std::process::id(),
        drive_count = drives.len(),
        "Daemon not elevated — attempting broker warm-up"
    );
    warm_up_broker_handles(drives);
}

/// Best-effort broker pre-warm: ask the elevated broker for a volume
/// handle per drive so the subsequent `load_live_drives` skips the
/// per-drive elevation prompt.  Failures are debug-traced and
/// ignored — the direct-open path takes over transparently.
#[cfg(windows)]
fn warm_up_broker_handles(drives: &[uffs_mft::platform::DriveLetter]) {
    tracing::info!(
        daemon_pid = std::process::id(),
        drives = ?drives,
        "warm_up_broker_handles: requesting volume handles from the Access Broker"
    );
    for &drive_letter in drives {
        match broker_client::request_volume_handle(drive_letter) {
            Ok(handle) => {
                // Deposit the broker's (elevated, overlapped) volume handle in
                // the uffs-mft registry; the subsequent `VolumeHandle::open`
                // for this drive adopts it instead of calling `CreateFileW`
                // (which a non-elevated daemon can't do).  This is what makes
                // the broker path actually load the MFT — previously the
                // handle was fetched and dropped, so the reader fell back to a
                // direct open and failed with access-denied.
                uffs_mft::register_broker_handle(drive_letter, handle);
                tracing::info!(drive = %drive_letter, handle, "Registered broker volume handle");
            }
            Err(broker_err) => {
                tracing::warn!(
                    drive = %drive_letter,
                    error = %broker_err,
                    "Access Broker handle request FAILED — falling back to direct (elevated) open"
                );
            }
        }
    }
}

/// Catch the "every load failed but `Ready` fired anyway" zombie
/// state.  Triggers an explicit shutdown request when the post-load
/// drive count is zero so the lifecycle's `select!` tears the daemon
/// down cleanly instead of leaving it queryable-but-empty.
async fn zero_drive_shutdown_guard(
    load_index: &Arc<index::IndexManager>,
    load_lifecycle: &lifecycle::LifecycleHandle,
) {
    let loaded_drives = load_index.loaded_drive_letters().await;
    if loaded_drives.is_empty() {
        tracing::error!(
            "Daemon loaded zero drives even though data sources were provided — every \
             parse attempt failed.  Shutting down to avoid the Ready-with-no-data state. \
             Check the load errors above; common causes: missing/corrupt .iocp files, \
             insufficient privileges on live drives, or a data_dir that contains no MFT \
             captures."
        );
        load_lifecycle.request_shutdown();
    }
}

/// Spawn the IPC server task(s).
///
/// Always spawns the `AF_UNIX` listener (the cross-platform fallback);
/// on Windows additionally spawns the named-pipe listener which is
/// the preferred transport (no `ws2_32` dependency, ~54 ms faster per
/// CLI launch).  Returns the `AF_UNIX` `JoinHandle` so the caller can
/// `.abort()` it during graceful shutdown; the named-pipe task is
/// fire-and-forget — the watchdog will reap it.
fn spawn_ipc_servers(
    idx: &Arc<index::IndexManager>,
    lifecycle_mgr: &lifecycle::LifecycleManager,
) -> tokio::task::JoinHandle<()> {
    let ipc_index = Arc::clone(idx);
    let ipc_lifecycle = lifecycle_mgr.handle();

    tracing::info!("Starting IPC server...");
    let ipc_task = tokio::spawn(async move {
        if let Err(ipc_err) = ipc::run_ipc_server(ipc_index, ipc_lifecycle).await {
            tracing::error!(error = %ipc_err, "IPC server error");
        }
    });
    tracing::info!("IPC server task spawned");

    // Task ownership (Phase 10c): the Windows named-pipe IPC server is
    // **fire-and-forget** — the `_pipe_task` `JoinHandle` is bound but
    // never `.abort()`-ed.  Rationale (mirrors the parent fn rustdoc):
    //
    //   * **Owner:** the binding `_pipe_task` lives until end-of-scope in
    //     `spawn_ipc_servers`; the task itself outlives the binding (Tokio detaches
    //     a spawned task once its `JoinHandle` drops).
    //   * **Shutdown:** none cooperative — the pipe `accept` loop has no
    //     cancellation hook; the `await_shutdown_then_force_exit` watchdog
    //     `process::exit`s the daemon, terminating the task with the runtime.
    //   * **Error obs.:** body logs via `tracing::error!`; outer `JoinHandle` drop
    //     discards the result.
    //   * **Cancel behavior:** process-exit only.
    //
    // The sibling AF_UNIX task IS returned + held + `.abort()`-ed —
    // that's the "primary" IPC transport on Unix.  On Windows, both
    // transports coexist (AF_UNIX for tools using the cross-platform
    // socket path; named-pipe for native Windows tooling); aborting
    // just one and letting the other ride out process exit is a
    // deliberate asymmetry.
    #[cfg(windows)]
    let _pipe_task = {
        let pipe_index = Arc::clone(idx);
        let pipe_lifecycle = lifecycle_mgr.handle();
        tracing::info!("Starting named-pipe IPC server...");
        tokio::spawn(async move {
            if let Err(pipe_err) = ipc::run_pipe_server(pipe_index, pipe_lifecycle).await {
                tracing::error!(error = %pipe_err, "Named-pipe IPC server error");
            }
        })
    };

    ipc_task
}

/// Spawn the periodic stats heartbeat — pushes `StatsHeartbeat`
/// events to all connected clients every 30 seconds.
fn spawn_stats_heartbeat(
    stats_index: Arc<index::IndexManager>,
    stats_lifecycle: lifecycle::LifecycleHandle,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(core::time::Duration::from_secs(30));
        // Skip the first tick (fires immediately).
        interval.tick().await;
        loop {
            interval.tick().await;
            let total_records = stats_index.total_records().await;
            let stats = stats_index.stats().await;
            stats_index
                .event_sender()
                .emit(events::DaemonEvent::StatsHeartbeat {
                    total_queries: stats.total_queries,
                    uptime_secs: stats.uptime_secs,
                    total_records,
                    connections: stats_lifecycle.active_connections(),
                });
        }
    })
}

/// Spawn the Phase 3 idle-demote controller — every 30 s, ask
/// `IndexManager::demote_idle_shards` to walk the registry and
/// demote any shard whose idle time exceeds its tier's TTL (see
/// `cache::policy`).
///
/// The 30 s cadence is shorter than the shortest TTL (300 s
/// Hot→Warm) by an order of magnitude, so a freshly idle Hot
/// shard demotes within at most one tick of crossing its
/// boundary.  Sampling `unix_now_ms()` once at the top of each
/// tick (and threading it into the manager) keeps every shard's
/// idle-secs computation referenced to the same baseline — a
/// slow read-lock acquisition can't push later shards in the
/// same batch over a TTL boundary mid-walk.
fn spawn_idle_demote_controller(idx: Arc<index::IndexManager>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(core::time::Duration::from_secs(30));
        // Skip the first tick (fires immediately at task spawn).
        // We want the controller to take its first reading 30 s
        // after startup, not at t=0 when no shard could possibly
        // be idle yet.
        interval.tick().await;
        loop {
            interval.tick().await;
            idx.demote_idle_shards(cache::unix_now_ms()).await;
        }
    })
}

/// Phase 7 activation: spawn one [`crate::cache::journal_loop::JournalLoop`]
/// per loaded drive letter.
///
/// Replaces the deleted Phase-5 `spawn_usn_refresh_controller`
/// global 5-min tick with per-shard event-driven refresh.  Each
/// loop polls its drive's NTFS USN journal at the configured
/// cadence (default 500 ms via
/// [`crate::cache::journal_loop::JournalLoopConfig`]) and fires save triggers
/// when the per-shard `SaveTrigger`'s events-threshold (50K events) or
/// age-threshold (5 min) crosses. Each save trigger drives a full
/// [`crate::index::IndexManager::handle_journal_refresh`] which
/// reuses the Phase-5
/// [`uffs_core::compact_loader::load_drive_with_usn_refresh`] infrastructure
/// for the body refresh + compact-cache write.
///
/// All loops share a single [`crate::cache::journal_sink::RegistryPatchSink`]
/// applier task: the sink's mpsc channel preserves FIFO ordering
/// across letters and avoids re-entering the runtime from the
/// loop's sync `accept` callback — see the `journal_sink` module
/// docs for the full rationale.
///
/// **Platform split**:
/// * **Windows**: each letter gets a `WindowsJournalSource` (real
///   `FSCTL_QUERY_USN_JOURNAL` + `FSCTL_READ_USN_JOURNAL`) and a
///   [`crate::cache::cursor_store::DiskCursorStore`] rooted at
///   `uffs_mft::cache::cache_dir()`.
/// * **macOS / Linux**: each letter gets a
///   [`crate::cache::journal_loop::sources::MacStubJournalSource`]
///   (always-empty polls) and a
///   [`crate::cache::journal_loop::sources::NullCursorStore`] (no-op).  The
///   loop ticks at the configured cadence but produces no patches and triggers
///   no saves — there's no live USN journal to drive against.
///
/// Returns the [`tokio::task::JoinHandle`] for the applier task.
/// The caller (`run_daemon`) keeps it alive for the daemon's
/// lifetime; per-letter loop handles are stored on `IndexManager`
/// via [`crate::index::IndexManager::attach_journal_handle`].  On
/// daemon shutdown the per-loop `watch::Sender`s are dropped with
/// the `IndexManager`, signalling every loop's cancellation arm
/// (matching the existing fire-and-forget pattern used by
/// `spawn_idle_demote_controller` / `spawn_pressure_subscriber`).
async fn spawn_journal_loops_for_warm_shards(
    idx: &Arc<index::IndexManager>,
) -> tokio::task::JoinHandle<()> {
    use cache::cursor_store::DiskCursorStore;
    use cache::journal_loop::sources::NullCursorStore;
    use cache::journal_loop::{
        CursorStore, JournalLoopConfig, JournalSource, PatchSink, spawn_journal_loop,
    };
    use cache::journal_sink::RegistryPatchSink;

    // Cursor-store choice: Windows persists per-drive cursors next
    // to the compact cache; Mac/Linux uses the always-zero
    // NullCursorStore (no journal → no cursor → fall back to
    // "start from journal head" semantics, which is the correct
    // no-op on those platforms).
    //
    // Shared with the applier: the sink persists each loop's cursor
    // in lockstep with a successful compact-cache body save (the
    // loops only seed from it and reset it on wrap), so the on-disk
    // cursor never outruns the on-disk body.  See `journal_sink`.
    let cursor_store: Arc<dyn CursorStore> = if cfg!(windows) {
        Arc::new(DiskCursorStore::new(uffs_mft::cache::cache_dir()))
    } else {
        Arc::new(NullCursorStore)
    };

    let (sink, applier_handle) =
        RegistryPatchSink::spawn_with_applier(idx, Arc::clone(&cursor_store));
    let sink_dyn: Arc<dyn PatchSink> = sink;

    let config = JournalLoopConfig::from_env();
    let letters = idx.loaded_drive_letters().await;
    tracing::info!(
        target: "shard.journal",
        count = letters.len(),
        letters = ?letters,
        poll_interval_ms = config.poll_interval.as_millis(),
        apply_interval_ms = config.apply_interval.as_millis(),
        save_threshold_events = config.save_threshold_events,
        save_threshold_age_secs = config.save_threshold_age.as_secs(),
        "Spawning per-shard journal loops",
    );
    for letter in letters {
        let source: Arc<dyn JournalSource> = make_journal_source(letter);
        let handle = spawn_journal_loop(
            letter,
            source,
            Arc::clone(&sink_dyn),
            Arc::clone(&cursor_store),
            config.clone(),
        );
        idx.attach_journal_handle(letter, handle);
    }

    applier_handle
}

/// Construct the platform-correct [`crate::cache::journal_loop::JournalSource`]
/// for `letter`.
///
/// Extracted from [`spawn_journal_loops_for_warm_shards`] as two
/// cfg-gated definitions so the unused-`letter` parameter on
/// Mac/Linux uses the canonical `_letter` rename rather than a
/// `let _ = letter;` body workaround that clippy flags.
#[cfg(windows)]
fn make_journal_source(
    letter: uffs_mft::platform::DriveLetter,
) -> Arc<dyn cache::journal_loop::JournalSource> {
    Arc::new(cache::journal_loop::sources::WindowsJournalSource::new(
        letter,
    ))
}

/// Mac/Linux variant of [`make_journal_source`] — always returns
/// the [`crate::cache::journal_loop::sources::MacStubJournalSource`]
/// stub (no NTFS USN journal on these platforms).
#[cfg(not(windows))]
fn make_journal_source(
    _letter: uffs_mft::platform::DriveLetter,
) -> Arc<dyn cache::journal_loop::JournalSource> {
    Arc::new(cache::journal_loop::sources::MacStubJournalSource)
}

/// Spawn the Phase 5 task 5.6 memory-pressure subscriber.
///
/// Subscribes to [`IndexManager::subscribe_pressure`] and reacts to
/// transitions:
///
/// * `Low` — enters cascade mode: calls
///   [`IndexManager::cascade_demote_one_step`] in a loop until either no Warm
///   shards remain (the `None` return) or a `High` / `Normal` transition
///   arrives.  After every step we `tokio::task::yield_now` and check
///   `rx.has_changed()` so a `High` transition can preempt promptly without
///   waiting for the next demote to finish.
/// * `High` / `Normal` — no-op; the loop returns to `rx.changed().await` for
///   the next transition.
///
/// The cascade decision is made via
/// [`PressureLevel::requires_cascade_demote`] rather than direct pattern
/// matching on `PressureLevel::Low`, because the `Low` and `High` variants
/// are platform-conditional — they only exist on Windows and under
/// `cfg(test)` (the targets where the watcher / test fake actually
/// constructs them).  The method ships a `false` branch on Mac/Linux
/// production builds so this loop body compiles cleanly on every host.
///
/// On Mac/Linux the platform [`PressureSignal`] never fires, so this
/// task blocks on `rx.changed().await` forever — TTL-driven demotion
/// via `spawn_idle_demote_controller` is the only demote driver on
/// those targets by design.
///
/// Returns the [`tokio::task::JoinHandle`] so the caller can `.abort()`
/// it during graceful shutdown.  When the [`watch::Sender`] inside
/// `IndexManager::pressure` is dropped the receiver's `changed()`
/// returns `Err`; the loop breaks cleanly without any extra signal.
///
/// `pub(crate)` so the Phase 5 end-to-end integration test in
/// `crate::index::tests::lifecycle_hooks` can drive the full
/// subscribe → cascade → preempt loop against a `ControllablePressureSignal`
/// fake without re-implementing the loop body in test code.  Production
/// callers stay limited to [`run_daemon`] which is the only place this
/// runs in the live daemon.
///
/// [`PressureLevel::requires_cascade_demote`]: crate::cache::pressure::PressureLevel::requires_cascade_demote
/// [`PressureSignal`]: crate::cache::pressure::PressureSignal
/// [`IndexManager::subscribe_pressure`]: crate::index::IndexManager::subscribe_pressure
/// [`IndexManager::cascade_demote_one_step`]: crate::index::IndexManager::cascade_demote_one_step
/// [`watch::Sender`]: tokio::sync::watch::Sender
pub(crate) fn spawn_pressure_subscriber(
    idx: Arc<index::IndexManager>,
) -> tokio::task::JoinHandle<()> {
    let mut rx = idx.subscribe_pressure();
    tokio::spawn(async move {
        loop {
            // Wait for a pressure transition.  `changed()` returns
            // `Err` when the watch sender is dropped, which happens
            // when `IndexManager` (the only owner) is dropped at
            // daemon shutdown.
            if rx.changed().await.is_err() {
                tracing::debug!(
                    target: "cache.pressure",
                    "Pressure-signal sender dropped; subscriber loop exiting",
                );
                break;
            }
            let level = *rx.borrow_and_update();
            tracing::info!(
                target: "cache.pressure",
                ?level,
                "Pressure transition observed",
            );
            if !level.requires_cascade_demote() {
                continue;
            }
            // Cascade-demote until we run out of Warm shards or
            // pressure clears.  `cascade_demote_one_step` returns
            // `None` when no Warm shards remain.
            loop {
                let Some(_demoted) = idx.cascade_demote_one_step().await else {
                    break; // no more Warm shards; cascade exhausted
                };
                // Yield so the runtime can deliver a pending
                // pressure-clearing transition before we loop.
                tokio::task::yield_now().await;
                if rx.has_changed().unwrap_or(false) {
                    let new_level = *rx.borrow_and_update();
                    if !new_level.requires_cascade_demote() {
                        tracing::info!(
                            target: "cache.pressure",
                            ?new_level,
                            "Cascade preempted by transition out of Low",
                        );
                        break;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests;
