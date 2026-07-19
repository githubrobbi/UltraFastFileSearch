// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! [`IndexManager`] constructors.
//!
//! Four entry points share the inner [`IndexManager::new_with_lifecycle_hooks`]
//! builder so the field-initialization list lives in one place:
//!
//! 1. [`IndexManager::new`] — production constructor that takes an explicit
//!    [`Arc<Config>`](crate::config::Config).  Used by [`crate::run_daemon`]
//!    after [`crate::config::Config::load_default`] resolves the config (Phase
//!    6 Commit C).  Tests that don't care about adaptive-TTL behaviour pass
//!    `Arc::new(crate::config::Config::default())` and get the
//!    Phase-3-equivalent ladder.
//! 2. [`IndexManager::new_with_lifecycle_hooks`] — module-private builder that
//!    takes every hook bundled into a [`LifecycleHooks`] struct plus the
//!    config. Production paths reach this via [`IndexManager::new`]; tests
//!    reach it via the `_for_test` variants below.
//! 3. `IndexManager::with_body_loader_for_test` — test-only entry point that
//!    swaps in a custom body loader and keeps the platform defaults for the
//!    other hooks (Phase 4 Commit E + earlier).
//! 4. `IndexManager::with_lifecycle_hooks_for_test` — test-only entry point
//!    that swaps every lifecycle hook (Phase 5) and accepts an explicit
//!    `Arc<Config>` (Phase 6).
//!
//! The hooks themselves live in a [`LifecycleHooks`] struct so the
//! constructor signatures stay under clippy's 7-argument ceiling and
//! tests can build `LifecycleHooks::production()` then override only
//! the hook(s) they care about — see the struct's docs for the
//! production-vs-test usage pattern.

use alloc::sync::Arc;
use core::sync::atomic::AtomicU64;
use std::path::PathBuf;
use std::sync::Mutex as StdMutex;
use std::time::Instant;

use tokio::sync::{RwLock, Semaphore};
use uffs_client::protocol::response::DaemonStatus;
use uffs_core::aggregate::AggregateCache;

use super::IndexManager;
use crate::cache::ShardRegistry;
use crate::events::EventSender;

/// Bundle of trait-object lifecycle hooks injected into
/// [`IndexManager`].
///
/// Reduces the constructor surface from five trait-object `Arc`
/// parameters to a single struct.  This (a) keeps the constructor
/// signatures under clippy's 7-argument ceiling and (b) lets test
/// code build [`LifecycleHooks::production`] then override only the
/// hook(s) the test cares about, e.g.
///
/// ```ignore
/// let hooks = LifecycleHooks {
///     working_set_trim: counting_trim,
///     ..LifecycleHooks::production()
/// };
/// ```
///
/// Each field maps 1:1 to a Phase 5 / Phase 6 lifecycle dependency
/// — see the corresponding documentation comments on the
/// [`IndexManager`] struct fields for the per-hook contract.
pub(crate) struct LifecycleHooks {
    /// Source for `Parked` / `Cold` shard bodies during
    /// promote-on-search.
    pub(crate) body_loader: Arc<dyn crate::cache::body_loader::BodyLoader>,
    /// Process-level working-set trim hook (Phase 5 task 5.1).
    pub(crate) working_set_trim: Arc<dyn crate::cache::working_set::WorkingSetTrim>,
    /// Region kernel-prefetch hook (Phase 5 task 5.2).
    pub(crate) prefetch: Arc<dyn crate::cache::prefetch::Prefetch>,
    /// Memory-pressure signal source (Phase 5 task 5.3).
    pub(crate) pressure: Arc<dyn crate::cache::pressure::PressureSignal>,
    /// Thread-level background-I/O priority hook (Phase 5 task 5.7).
    pub(crate) background_io: Arc<dyn crate::cache::background_io::BackgroundIoPriority>,
    /// Per-drive cache-file cleanup hook (Phase 8-D `forget` RPC).
    /// Production uses [`crate::cache::cache_cleaner::PlatformCacheCleaner`];
    /// tests inject a test-only `CountingCacheCleaner`
    /// so registry-eviction behaviour can be verified without
    /// touching the host's real cache directory.
    pub(crate) cache_cleaner: Arc<dyn crate::cache::cache_cleaner::CacheCleaner>,
}

impl LifecycleHooks {
    /// Production hook bundle — every hook wired to its
    /// `crate::cache::*::Platform*` impl.  Used by
    /// [`IndexManager::new`] (via [`IndexManager::new_with_lifecycle_hooks`])
    /// and as the spread base for the `_for_test` constructors when a
    /// test only needs to override one hook.
    #[must_use]
    pub(crate) fn production() -> Self {
        Self {
            body_loader: Arc::new(crate::cache::body_loader::DiskBodyLoader),
            working_set_trim: Arc::new(crate::cache::working_set::PlatformWorkingSetTrim),
            prefetch: Arc::new(crate::cache::prefetch::PlatformPrefetch),
            pressure: Arc::new(crate::cache::pressure::PlatformPressureSignal::new()),
            background_io: Arc::new(crate::cache::background_io::PlatformBackgroundIoPriority),
            cache_cleaner: Arc::new(crate::cache::cache_cleaner::PlatformCacheCleaner),
        }
    }
}

impl IndexManager {
    /// Production constructor — the single entry point for
    /// `crate::run_daemon` after [`crate::config::Config::load_default`]
    /// resolves the operator's `daemon.toml`.
    ///
    /// Tests that don't care about adaptive-TTL behaviour pass
    /// `Arc::new(crate::config::Config::default())` and get the
    /// Phase-3-equivalent ladder; tests that exercise per-drive
    /// `min_tier` overrides or non-default `TiersConfig` values
    /// reach for the test-only `with_lifecycle_hooks_for_test` so they
    /// can also inject counting / recording fakes.
    #[must_use]
    pub(crate) fn new(
        data_dir: Option<PathBuf>,
        events: EventSender,
        config: Arc<crate::config::Config>,
    ) -> Self {
        Self::new_with_lifecycle_hooks(data_dir, events, LifecycleHooks::production(), config)
    }

    /// Inner constructor that threads a [`LifecycleHooks`] bundle
    /// (body loader, working-set trim, prefetch, pressure signal,
    /// background-I/O priority) plus the parsed
    /// [`Config`](crate::config::Config).
    ///
    /// Production code calls [`IndexManager::new`]
    /// which wires the platform impls; the Phase 5 / Phase 6 unit tests
    /// use this path through the test-only `with_lifecycle_hooks_for_test`
    /// to inject counting / recording / controllable fakes without
    /// touching the platform cache directory, the process working set,
    /// or the OS pressure-notification API, and to exercise per-drive
    /// `min_tier` overrides + non-default [`TiersConfig`] values
    /// without writing a real `daemon.toml` to disk.
    ///
    /// [`TiersConfig`]: crate::config::TiersConfig
    fn new_with_lifecycle_hooks(
        data_dir: Option<PathBuf>,
        events: EventSender,
        hooks: LifecycleHooks,
        config: Arc<crate::config::Config>,
    ) -> Self {
        let LifecycleHooks {
            body_loader,
            working_set_trim,
            prefetch,
            pressure,
            background_io,
            cache_cleaner,
        } = hooks;
        let cpus = std::thread::available_parallelism().map_or(4, core::num::NonZeroUsize::get);
        Self {
            index: RwLock::new(Arc::new(ShardRegistry::new())),
            status: RwLock::new(DaemonStatus::Loading {
                drives_loaded: 0,
                drives_total: 0,
            }),
            start_time: Instant::now(),
            data_dir,
            events,
            search_semaphore: RwLock::new(Arc::new(Semaphore::new(cpus))),
            cpus,
            aggregate_cache: Arc::new(AggregateCache::default_ttl()),
            index_version: AtomicU64::new(0),
            queries_total: AtomicU64::new(0),
            queries_total_us: AtomicU64::new(0),
            startup_duration_us: AtomicU64::new(0),
            drive_timings: RwLock::new(std::collections::HashMap::new()),
            device_paths: RwLock::new(std::collections::HashMap::new()),
            body_loader,
            working_set_trim,
            prefetch,
            pressure,
            background_io,
            cache_cleaner,
            in_flight_promotes: Arc::new(StdMutex::new(std::collections::HashMap::new())),
            journal_handles: Arc::new(StdMutex::new(std::collections::HashMap::new())),
            config,
        }
    }

    /// Test-only constructor that swaps in a custom body-loader.
    ///
    /// Used by the Commit-E integration tests to inject deterministic
    /// fakes — no platform cache directory touched, no
    /// process-global env-var override, no `tempfile`-juggling.
    /// Threads [`LifecycleHooks::production`] for the other hooks
    /// since pre-Phase-5 tests don't care about them.
    #[cfg(test)]
    pub(crate) fn with_body_loader_for_test(
        data_dir: Option<PathBuf>,
        events: EventSender,
        body_loader: Arc<dyn crate::cache::body_loader::BodyLoader>,
    ) -> Self {
        let hooks = LifecycleHooks {
            body_loader,
            ..LifecycleHooks::production()
        };
        Self::new_with_lifecycle_hooks(
            data_dir,
            events,
            hooks,
            Arc::new(crate::config::Config::default()),
        )
    }

    /// Test-only constructor that swaps in custom hooks for the
    /// full memory-tiering lifecycle plus the parsed config.  Phase 5
    /// tasks 5.8 / 5.9 / 5.10 inject counting / recording /
    /// controllable fakes here so the demote-batch, promote-on-search,
    /// and pressure-cascade assertions can run deterministically
    /// without touching the process's actual working set, kernel page
    /// cache, or OS pressure-notification API; Phase 6 Commit C tests
    /// pass an explicit `Arc<Config>` so per-drive `min_tier` overrides
    /// and non-default [`TiersConfig`] values can be exercised
    /// deterministically.
    ///
    /// Pre-Phase-6 tests that don't care about the config can pass
    /// `Arc::new(crate::config::Config::default())` and the controller
    /// behaves identically to the Phase-3 static ladder (plan task 6.8
    /// contract — pinned by the unit tests in `crate::config::tests`).
    ///
    /// [`TiersConfig`]: crate::config::TiersConfig
    #[cfg(test)]
    pub(crate) fn with_lifecycle_hooks_for_test(
        data_dir: Option<PathBuf>,
        events: EventSender,
        hooks: LifecycleHooks,
        config: Arc<crate::config::Config>,
    ) -> Self {
        Self::new_with_lifecycle_hooks(data_dir, events, hooks, config)
    }
}
