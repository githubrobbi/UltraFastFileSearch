// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `daemon.toml` parser — Phase 6 Commit B of the memory-tiering
//! work (`docs/refactor/memory-tiering-implementation-plan.md`).
//!
//! ## Schema
//!
//! Mirrors [tiering-plan §11](../../../docs/refactor/memory-tiering-plan.md):
//!
//! ```toml
//! [memory]
//! max_total_resident_mb        = 2048
//! respect_os_low_memory        = true
//! enable_working_set_trim      = true
//! enable_large_pages           = false
//! unencrypted_sidecar          = false
//!
//! [tiers]
//! hot_ttl_base_secs            = 60
//! warm_ttl_base_secs           = 300
//! parked_ttl_secs              = 86400
//! heavy_query_auto_hot         = true
//! sustained_rate_auto_hot_qpm  = 3
//!
//! [shards]
//! cache_root                   = "%LOCALAPPDATA%/uffs/cache/shards"
//! runtime_root                 = "%LOCALAPPDATA%/uffs/runtime"
//! checkpoint_interval_secs     = 300
//! checkpoint_after_events      = 50000
//! journal_poll_ms              = 500
//! usn_refresh_interval_secs    = 300
//!
//! [shards.per_drive]
//! "C:" = { min_tier = "WARM", max_tier = "HOT" }
//! "Z:" = { max_tier = "PARKED" }
//! ```
//!
//! ## Layering
//!
//! * **Commit B (this file):** types + serde + parser + tests.  No callers
//!   wired yet.
//! * **Commit C (next):** wire [`crate::config::Config::load_from_path`] into
//!   `crate::run_daemon` startup; replace `cache::policy`'s static getters with
//!   config-driven readers; pass `TierThresholds` into
//!   [`crate::cache::policy::next_state_for_idle_with_thresholds`] from
//!   `IndexManager::demote_idle_shards`.
//!
//! ## Defaults
//!
//! [`crate::config::Config::default()`] matches the Phase-3 static behavior
//! (plan task 6.8): missing `daemon.toml` ⇒ same idle thresholds as
//! the bare [`crate::cache::policy`] module.  Production users opt
//! into longer retention or per-drive constraints by writing an
//! explicit config.
//!
//! ## Forward-compat posture
//!
//! `#[serde(default, deny_unknown_fields)]` everywhere:
//!
//! * `default` — missing section / field falls through to the defaults above
//!   (task 6.8 contract).
//! * `deny_unknown_fields` — typos in the user's config (e.g.
//!   `hot_tt1_base_secs`) become parse errors instead of silent noops.  UFFS
//!   ships daemon + config together, so the user is never running an older
//!   daemon against a newer config; the typo-catching value outweighs the
//!   forward-compat tax.

use alloc::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cache::policy::{
    hot_to_warm_idle_secs, parked_to_cold_idle_secs, usn_refresh_interval_secs,
    warm_to_parked_idle_secs,
};
use crate::cache::shard::ShardState;

/// Top-level `daemon.toml` schema.
///
/// Each section is a defaultable inner struct, so omitting a
/// section in the user's TOML produces the Phase-3-static defaults
/// (plan task 6.8 contract).  Phase 6 Commit C will pass a
/// borrowed reference of this type into `IndexManager::new`; for
/// now the type exists in isolation with full test coverage.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Config {
    /// Global memory budget + OS integration knobs.
    pub memory: MemoryConfig,
    /// Adaptive-TTL base / cap knobs and auto-promotion rules.
    pub tiers: TiersConfig,
    /// Cache and runtime root paths plus per-drive overrides.
    pub shards: ShardsConfig,
}

// ── [memory] ─────────────────────────────────────────────────────

/// `[memory]` — global memory budget + OS integration knobs.
///
/// Defaults track [tiering-plan
/// §11](../../../docs/refactor/memory-tiering-plan.md): 2 GiB resident cap;
/// respect OS low-memory signals; trim working set after demote (Phase 5.1);
/// large pages opt-in (requires `SeLockMemoryPrivilege` on Windows); plaintext
/// sidecar opt-in (see `CACHE_SECURITY_ANALYSIS.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the four booleans — respect_os_low_memory, \
              enable_working_set_trim, enable_large_pages, \
              unencrypted_sidecar — each represent an independent \
              opt-in/opt-out switch defined by the plan §11 schema. \
              Collapsing them into a flags enum would obscure the \
              one-to-one mapping between the user's `daemon.toml` \
              keys and the in-memory representation, hurting the \
              round-trip and reviewability properties."
)]
pub(crate) struct MemoryConfig {
    /// Global resident-set ceiling, in MiB.  Once exceeded, the
    /// pressure controller (Phase 5.3) cascades demotes until the
    /// total drops back under the cap.
    pub max_total_resident_mb: u64,
    /// On Windows, hook the low-memory notification API and treat
    /// `LowMemoryResourceNotification` as an immediate demote
    /// trigger.  Mac is a no-op (no equivalent public API).
    pub respect_os_low_memory: bool,
    /// Call `EmptyWorkingSet` after each demote on Windows so the
    /// freed pages return to the OS quickly (plan §8.2).
    pub enable_working_set_trim: bool,
    /// Allocate the runtime mmap tempfile region with large pages
    /// when available (Windows: `MEM_LARGE_PAGES` requires the
    /// `SeLockMemoryPrivilege` token; opt-in to avoid surprising
    /// non-admin users with cryptic failures).
    pub enable_large_pages: bool,
    /// Mirror the encrypted compact cache to a plaintext sidecar
    /// for debug / analysis tooling.  Default OFF — see
    /// `docs/refactor/CACHE_SECURITY_ANALYSIS.md` for the threat
    /// model.
    pub unencrypted_sidecar: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            max_total_resident_mb: 2048,
            respect_os_low_memory: true,
            enable_working_set_trim: true,
            enable_large_pages: false,
            unencrypted_sidecar: false,
        }
    }
}

// ── [tiers] ──────────────────────────────────────────────────────

/// `[tiers]` — adaptive-TTL base / cap knobs and auto-promotion rules.
///
/// The `*_base_secs` defaults match the
/// [`crate::cache::policy::HOT_TO_WARM_IDLE_SECS`] /
/// [`crate::cache::policy::WARM_TO_PARKED_IDLE_SECS`] /
/// [`crate::cache::policy::PARKED_TO_COLD_IDLE_SECS`] constants —
/// pin verified by the
/// `defaults_match_phase3_static_behavior` regression test below
/// (plan task 6.8).
///
/// Phase 6 Commit C will feed the `*_base_secs` values into the
/// adaptive TTL formulas (`hot_ttl(rate, base, cap)` etc.) so the
/// controller can size each shard's demote edge from the live rate
/// EMA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct TiersConfig {
    /// Hot → Warm idle threshold floor, in seconds.
    pub hot_ttl_base_secs: u64,
    /// Hot → Warm adaptive-TTL ceiling, in seconds.  At
    /// `rate_ema → ∞` the formula
    /// [`crate::cache::policy::hot_ttl`] clamps to this value.
    /// Default 3600 s (1 hr) — matches the plan §5.2 reference
    /// point and the `hot_ttl` unit-test pin.
    pub hot_ttl_cap_secs: u64,
    /// Warm → Parked idle threshold floor, in seconds.
    pub warm_ttl_base_secs: u64,
    /// Warm → Parked adaptive-TTL ceiling, in seconds.  At
    /// `rate_ema → ∞` the formula
    /// [`crate::cache::policy::warm_ttl`] clamps to this value.
    /// Default 14400 s (4 hr) — matches the plan §5.2 reference
    /// point and the `warm_ttl` unit-test pin.
    pub warm_ttl_cap_secs: u64,
    /// Parked → Cold idle threshold (no rate dependence — see
    /// `crate::cache::policy::parked_ttl`), in seconds.
    pub parked_ttl_secs: u64,
    /// When `true`, a shard whose query rate exceeds
    /// `sustained_rate_auto_hot_qpm` for ≥ 60 s gets auto-promoted
    /// from Warm → Hot.
    pub heavy_query_auto_hot: bool,
    /// Sustained query-rate threshold (queries/minute) at which
    /// `heavy_query_auto_hot` kicks in.
    pub sustained_rate_auto_hot_qpm: u64,
}

impl Default for TiersConfig {
    fn default() -> Self {
        // The `*_idle_secs()` getters are env-var-overridable
        // (`UFFS_HOT_TO_WARM_IDLE_SECS` etc.) — funnelling them
        // through the Config layer means env-var overrides keep
        // working after Phase 6 Commit C wired `IndexManager` to
        // read TTL bases from `Config` rather than the policy
        // module's getters directly.  Without this, an operator
        // who set `UFFS_HOT_TO_WARM_IDLE_SECS=10` for a benchmark
        // would silently get the static default (60 s) once
        // Commit C landed.
        Self {
            hot_ttl_base_secs: hot_to_warm_idle_secs(),
            hot_ttl_cap_secs: 3_600,
            warm_ttl_base_secs: warm_to_parked_idle_secs(),
            warm_ttl_cap_secs: 14_400,
            parked_ttl_secs: parked_to_cold_idle_secs(),
            heavy_query_auto_hot: true,
            sustained_rate_auto_hot_qpm: 3,
        }
    }
}

// ── [shards] ─────────────────────────────────────────────────────

/// `[shards]` — cache and runtime root paths, checkpoint /
/// USN-refresh cadences, and per-drive overrides.
///
/// `cache_root` and `runtime_root` are `Option<PathBuf>` so that an
/// unset config field falls back to the platform default rather
/// than to an empty string.  Commit C will resolve `None` against
/// `dirs_next::config_dir()` etc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ShardsConfig {
    /// Encrypted authoritative cache root.  `None` ⇒ daemon picks
    /// the platform default at startup (Windows:
    /// `%LOCALAPPDATA%/uffs/cache/shards`; macOS / Linux:
    /// `~/.cache/uffs/shards`).
    pub cache_root: Option<PathBuf>,
    /// Ephemeral mmap tempfile root.  Same fallback rules as
    /// `cache_root`.
    pub runtime_root: Option<PathBuf>,
    /// Checkpoint cadence, in seconds.
    pub checkpoint_interval_secs: u64,
    /// Force a checkpoint after this many MFT events even if the
    /// time-based cadence hasn't elapsed.
    pub checkpoint_after_events: u64,
    /// USN journal poll cadence, in milliseconds.
    pub journal_poll_ms: u64,
    /// USN refresh cadence — Phase 5 (#95) background refresh
    /// controller.  Default tracks
    /// [`crate::cache::policy::USN_REFRESH_INTERVAL_SECS`].
    pub usn_refresh_interval_secs: u64,
    /// Per-drive overrides keyed by canonical drive label
    /// (e.g. `"C:"`).  `BTreeMap` for deterministic round-trip
    /// ordering — task 6.5 (TOML round-trip) would otherwise be
    /// flaky on a `HashMap`.
    pub per_drive: BTreeMap<String, PerDriveConfig>,
}

impl Default for ShardsConfig {
    fn default() -> Self {
        Self {
            cache_root: None,
            runtime_root: None,
            checkpoint_interval_secs: 300,
            checkpoint_after_events: 50_000,
            journal_poll_ms: 500,
            // Env-var-overridable for the same reason
            // `TiersConfig::default` uses the `*_idle_secs()`
            // getters: keep `UFFS_USN_REFRESH_INTERVAL_SECS`
            // working after Phase 6 Commit C started threading
            // refresh cadence through the Config surface.
            usn_refresh_interval_secs: usn_refresh_interval_secs(),
            per_drive: BTreeMap::new(),
        }
    }
}

// ── [shards.per_drive."<key>"] ───────────────────────────────────

/// `[shards.per_drive."<key>"]` — clamps the demote / promote
/// ladder for a specific drive.
///
/// Both fields are optional: a missing value imposes no constraint.
///
/// Plan §11 example:
///
/// ```toml
/// "C:" = { min_tier = "WARM", max_tier = "HOT" }
/// "Z:" = { max_tier = "PARKED" }
/// ```
///
/// `"C:"` (system drive) keeps the runtime mmap resident at all
/// times (`min_tier = WARM`) but never auto-promotes to `HOT`
/// (which would also build the trigram index — costly on a
/// system drive that rarely sees full-text queries).
///
/// `"Z:"` (archive drive) starts cold and at most reaches
/// `Parked` (filters resident, no body) — long-tail access
/// pattern doesn't justify the 1 GiB body footprint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PerDriveConfig {
    /// Demote-ladder floor.  `min_tier = "WARM"` ⇒ the demote
    /// controller never drops this drive below `Warm`.  `None` ⇒
    /// the ladder bottoms at `Cold`.
    pub min_tier: Option<TierLevel>,
    /// Promote-ladder ceiling.  `max_tier = "PARKED"` ⇒ this drive
    /// never reaches `Hot` or `Warm`.  `None` ⇒ the ladder tops at
    /// `Hot`.
    pub max_tier: Option<TierLevel>,
}

// ── TierLevel ────────────────────────────────────────────────────

/// User-facing tier-level enum that round-trips through TOML.
///
/// The wire format is `UPPERCASE` (`"HOT"` / `"WARM"` / `"PARKED"`)
/// to match the plan §11 example and the existing
/// `shard.transition` tracing-event vocabulary.
///
/// `Cold`, `Unknown`, and `Evicting` are deliberately not mapped
/// here: those are controller-only states that the user can't
/// request the daemon target.  `Cold` is the demote-ladder floor;
/// `Unknown` / `Evicting` are mid-transition states owned by the
/// shard registry's promote / demote write-swap path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum TierLevel {
    /// Top of the ladder — body resident, trigram index built,
    /// runtime mmap active.  Selected as `min_tier` for drives
    /// that must serve queries instantly with no JIT cost.
    Hot,
    /// Mid tier — body resident, runtime mmap active, trigram
    /// index built lazily on the next query.  Default ceiling for
    /// ordinary drives.
    Warm,
    /// Cold-resident tier — bloom + path trie only, no body.
    /// Selected as `max_tier` for archive drives that should
    /// never hold a full body in memory.
    Parked,
}

impl TierLevel {
    /// Lift a [`TierLevel`] into the corresponding [`ShardState`]
    /// for comparison against the controller's tier ladder.
    #[must_use]
    pub(crate) const fn to_state(self) -> ShardState {
        match self {
            Self::Hot => ShardState::Hot,
            Self::Warm => ShardState::Warm,
            Self::Parked => ShardState::Parked,
        }
    }
}

// ── Parser surface ───────────────────────────────────────────────

impl Config {
    /// Parse a `daemon.toml` body.
    ///
    /// Returns the structured config or a [`ConfigError::Parse`]
    /// describing the parse failure (line / column included via
    /// `toml::de::Error`'s `Display`).
    pub(crate) fn from_toml(body: &str) -> Result<Self, ConfigError> {
        toml::from_str(body).map_err(ConfigError::Parse)
    }

    /// Read and parse `daemon.toml` from disk.
    ///
    /// A missing file is **not** an error: returns
    /// `Ok(Self::default())` so the daemon boots with
    /// Phase-3-equivalent behavior on first run, with no
    /// `daemon.toml` ever written.  This is the task 6.8 contract.
    ///
    /// All other I/O errors (permission denied, EISDIR on a path
    /// that exists as a directory, etc.) propagate as
    /// [`ConfigError::Io`].
    pub(crate) fn load_from_path(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(body) => Self::from_toml(&body),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(ConfigError::Io(err)),
        }
    }

    /// Serialize back to TOML.
    ///
    /// Used by the round-trip test (task 6.5) and by future
    /// `uffs --daemon config dump` commands.  Pretty-prints with
    /// section headers so a human can compare two configs visually.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Phase 6+ admin tooling will surface this; \
                      until then the serializer is exercised only \
                      by the round-trip unit test in this module."
        )
    )]
    pub(crate) fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(ConfigError::Serialize)
    }

    /// Platform-default `daemon.toml` location.
    ///
    /// Returns `Some(<data_local_dir>/uffs/daemon.toml)`:
    ///
    /// * **Windows** ⇒ `%LOCALAPPDATA%\uffs\daemon.toml`.
    /// * **macOS** ⇒ `~/Library/Application Support/uffs/daemon.toml`.
    /// * **Linux** ⇒ `$XDG_DATA_HOME/uffs/daemon.toml` (or
    ///   `~/.local/share/uffs/daemon.toml` if unset).
    ///
    /// Returns `None` only when `dirs_next::data_local_dir()`
    /// itself fails (no `HOME` and no platform fallback) — in
    /// practice on every supported platform the answer is `Some`.
    ///
    /// Mirrors the conventions used by [`crate::ipc::IpcServer::socket_path`]
    /// and [`crate::log_init::default_log_file`] so the `daemon.toml` lives
    /// alongside the lifecycle / log artifacts the daemon already
    /// writes there.
    #[must_use]
    pub(crate) fn default_path() -> Option<PathBuf> {
        dirs_next::data_local_dir().map(|dir| dir.join("uffs").join("daemon.toml"))
    }

    /// Load the config from the platform-default location.
    ///
    /// Convenience wrapper for the common
    /// `Config::load_from_path(&Config::default_path().unwrap_or(...))`
    /// idiom at daemon startup.  Returns `Self::default()` (Phase 3
    /// behavior) when:
    ///
    /// * `dirs_next::data_local_dir()` itself fails — extremely rare, only on
    ///   broken Linux installs with no `HOME` and `$XDG_DATA_HOME`; the daemon
    ///   prefers a working config to a hard error here.
    /// * The file at [`Self::default_path`] does not exist — task 6.8 contract:
    ///   missing `daemon.toml` ⇒ defaults match Phase 3 static behavior.
    ///
    /// Other I/O / parse errors propagate as [`ConfigError`] so a
    /// malformed config doesn't silently fall through to defaults
    /// (which would mask the user's typo).
    pub(crate) fn load_default() -> Result<Self, ConfigError> {
        Self::default_path().map_or_else(|| Ok(Self::default()), |path| Self::load_from_path(&path))
    }
}

/// Errors surfaced by [`crate::config::Config::load_from_path`] /
/// [`Config::from_toml`] / [`Config::to_toml`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    /// `toml::de::Error` from a malformed config body.
    #[error("daemon.toml parse: {0}")]
    Parse(#[from] toml::de::Error),
    /// `toml::ser::Error` from a serialize-side failure (e.g. a
    /// future schema change introduces a non-serializable field).
    #[error("daemon.toml serialize: {0}")]
    Serialize(#[from] toml::ser::Error),
    /// `std::io::Error` from a non-`NotFound` filesystem failure.
    #[error("daemon.toml read: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Defaults ──────────────────────────────────────────────────

    /// Plan task 6.8: missing `daemon.toml` ⇒ defaults match Phase
    /// 3 static behavior.  Pin the exact tier / USN / cap values so
    /// a future tweak to `cache::policy` constants cannot silently
    /// drift the defaultable config away from the controller's
    /// statics.
    #[test]
    fn defaults_match_phase3_static_behavior() {
        // Without the env-var override, the getter must collapse
        // to the documented static default — pin the constant
        // mapping at the policy layer so a future tweak to the
        // const cannot silently drift the default config without
        // also failing this test.  Done via a const-pin so the
        // value is fixed at build time and the assertion holds
        // regardless of `OnceLock` cache state.  Hoisted above the
        // first `let` so `clippy::items_after_statements` doesn't
        // fire — the const block is build-time, so its position is
        // purely stylistic relative to the runtime asserts below.
        const _: () = {
            assert!(crate::cache::policy::HOT_TO_WARM_IDLE_SECS == 600);
            assert!(crate::cache::policy::WARM_TO_PARKED_IDLE_SECS == 1_800);
            assert!(crate::cache::policy::PARKED_TO_COLD_IDLE_SECS == 86_400);
            assert!(crate::cache::policy::USN_REFRESH_INTERVAL_SECS == 300);
        };

        let cfg = Config::default();

        // Tier defaults track the env-var-aware Phase-3 getters
        // (`hot_to_warm_idle_secs()` etc.), which themselves
        // resolve to the `HOT_TO_WARM_IDLE_SECS` constants when
        // the corresponding `UFFS_*_IDLE_SECS` env vars are
        // unset.  Asserting against the getters preserves the
        // env-var-override contract end-to-end: a developer who
        // sets `UFFS_HOT_TO_WARM_IDLE_SECS=10` for a benchmark
        // gets `cfg.tiers.hot_ttl_base_secs == 10` and the test
        // still passes.
        assert_eq!(cfg.tiers.hot_ttl_base_secs, hot_to_warm_idle_secs());
        assert_eq!(cfg.tiers.warm_ttl_base_secs, warm_to_parked_idle_secs());
        assert_eq!(cfg.tiers.parked_ttl_secs, parked_to_cold_idle_secs());
        assert_eq!(
            cfg.shards.usn_refresh_interval_secs,
            usn_refresh_interval_secs()
        );

        // No per-drive overrides by default — ladder is uniform.
        assert!(cfg.shards.per_drive.is_empty());

        // Memory budget tracks plan §11 (2 GiB; respect OS;
        // working-set trim ON; large-pages OFF; unencrypted
        // sidecar OFF).
        assert_eq!(cfg.memory.max_total_resident_mb, 2048);
        assert!(cfg.memory.respect_os_low_memory);
        assert!(cfg.memory.enable_working_set_trim);
        assert!(!cfg.memory.enable_large_pages);
        assert!(!cfg.memory.unencrypted_sidecar);

        // Auto-promotion defaults: rate-driven hot upgrade ON at
        // 3 q/min sustained.
        assert!(cfg.tiers.heavy_query_auto_hot);
        assert_eq!(cfg.tiers.sustained_rate_auto_hot_qpm, 3);
    }

    /// Plan task 6.8 continued: an empty `daemon.toml` body parses
    /// to the same value as `Config::default()`.  Distinct
    /// from the missing-file case (which is exercised by
    /// `load_from_path_missing_file_returns_defaults`) — this pins
    /// the `#[serde(default)]` plumbing on every nested struct.
    #[test]
    fn empty_toml_body_parses_to_defaults() {
        let cfg = Config::from_toml("").expect("empty body must parse");
        assert_eq!(cfg, Config::default());
    }

    /// Plan task 6.8 final clause: a missing `daemon.toml` file
    /// ⇒ defaults, no error.  Uses `tempfile::tempdir` to get a
    /// guaranteed-empty directory; the missing path inside it is
    /// the missing-file case the loader has to tolerate.
    #[test]
    fn load_from_path_missing_file_returns_defaults() {
        let dir = tempfile::tempdir().expect("tempdir create");
        let missing = dir.path().join("daemon.toml");
        let cfg = Config::load_from_path(&missing)
            .expect("missing daemon.toml must yield defaults, not error");
        assert_eq!(cfg, Config::default());
    }

    /// Loader returns the parsed body when the file exists.  Uses
    /// a single-section overlay (just `[tiers]`) to also pin the
    /// "missing section ⇒ default" behavior at the file boundary.
    #[test]
    fn load_from_path_with_partial_file_overlays_defaults() {
        let dir = tempfile::tempdir().expect("tempdir create");
        let path = dir.path().join("daemon.toml");
        std::fs::write(
            &path,
            "[tiers]\n\
             hot_ttl_base_secs = 999\n",
        )
        .expect("write fixture");

        let cfg = Config::load_from_path(&path).expect("parse fixture");
        // Overridden field landed.
        assert_eq!(cfg.tiers.hot_ttl_base_secs, 999);
        // Sibling fields fell through to defaults — same env-var-aware
        // contract as `defaults_match_phase3_static_behavior`.
        assert_eq!(cfg.tiers.warm_ttl_base_secs, warm_to_parked_idle_secs());
        // Sibling sections fell through to defaults.
        assert_eq!(cfg.memory, MemoryConfig::default());
        assert_eq!(cfg.shards, ShardsConfig::default());
    }

    // ── Round-trip ────────────────────────────────────────────────

    /// Plan task 6.5: TOML round-trip on the full default config
    /// (serialize → deserialize → equality).  Belt-and-braces
    /// regression: a future schema change that adds a non-default
    /// field without a `#[serde(default)]` will fail this test
    /// before it can ship.
    #[test]
    fn default_config_round_trips_through_toml() {
        let original = Config::default();
        let body = original.to_toml().expect("serialize default");
        let parsed = Config::from_toml(&body).expect("parse round-trip");
        assert_eq!(parsed, original);
    }

    /// Round-trip with a non-trivial `[shards.per_drive]` map.
    /// Pins the `BTreeMap` deterministic ordering — a `HashMap`
    /// substitution would make this test flaky.
    #[test]
    fn full_config_with_per_drive_round_trips() {
        let mut original = Config::default();
        original
            .shards
            .per_drive
            .insert("C:".to_owned(), PerDriveConfig {
                min_tier: Some(TierLevel::Warm),
                max_tier: Some(TierLevel::Hot),
            });
        original
            .shards
            .per_drive
            .insert("Z:".to_owned(), PerDriveConfig {
                min_tier: None,
                max_tier: Some(TierLevel::Parked),
            });
        original.memory.enable_large_pages = true;
        original.tiers.sustained_rate_auto_hot_qpm = 5;

        let body = original.to_toml().expect("serialize full");
        let parsed = Config::from_toml(&body).expect("parse full round-trip");
        assert_eq!(parsed, original);
    }

    // ── Per-drive overrides (task 6.6 partial — parse side) ───────

    /// Plan task 6.6 (partial — parser side; the demote-ladder
    /// enforcement is Commit C): a `[shards.per_drive."C:"]`
    /// section with `min_tier = "WARM"` parses into
    /// `Some(TierLevel::Warm)` so the controller can clamp the
    /// ladder at Commit C wiring time.
    #[test]
    fn per_drive_min_tier_warm_parses() {
        let body = r#"
[shards.per_drive."C:"]
min_tier = "WARM"
"#;
        let cfg = Config::from_toml(body).expect("parse per-drive override");
        let entry = cfg
            .shards
            .per_drive
            .get("C:")
            .expect("C: override must be present");
        assert_eq!(entry.min_tier, Some(TierLevel::Warm));
        assert_eq!(entry.max_tier, None);
    }

    /// Inline-table form (the plan §11 canonical example shape) of
    /// the same override.  Both shapes must produce identical
    /// parsed output — TOML's inline-table sugar is purely
    /// surface-level.
    #[test]
    fn per_drive_inline_table_form_matches_section_form() {
        let inline = r#"
[shards.per_drive]
"C:" = { min_tier = "WARM", max_tier = "HOT" }
"Z:" = { max_tier = "PARKED" }
"#;
        let cfg = Config::from_toml(inline).expect("parse inline form");
        let c_entry = cfg.shards.per_drive.get("C:").expect("C: present");
        assert_eq!(c_entry.min_tier, Some(TierLevel::Warm));
        assert_eq!(c_entry.max_tier, Some(TierLevel::Hot));
        let z_entry = cfg.shards.per_drive.get("Z:").expect("Z: present");
        assert_eq!(z_entry.min_tier, None);
        assert_eq!(z_entry.max_tier, Some(TierLevel::Parked));
    }

    // ── TierLevel wire format ─────────────────────────────────────

    /// Pin the wire format: serialize emits `UPPERCASE`, matching
    /// the plan §11 example and the `shard.transition` tracing
    /// vocabulary.  Uses [`TierLevelWrapper`] because TOML requires
    /// a table at the document root — a bare `TierLevel` is not a
    /// valid TOML document on its own.
    #[test]
    fn tier_level_serializes_uppercase() {
        for (variant, expected) in [
            (TierLevel::Hot, "value = \"HOT\"\n"),
            (TierLevel::Warm, "value = \"WARM\"\n"),
            (TierLevel::Parked, "value = \"PARKED\"\n"),
        ] {
            let body =
                toml::to_string(&TierLevelWrapper { value: variant }).expect("serialize wrapper");
            assert_eq!(body, expected, "unexpected wire form for {variant:?}");
        }
    }

    /// Pin the deserialize side: `"HOT"` / `"WARM"` / `"PARKED"`
    /// parse cleanly.  Lowercase / mixed case is **not** accepted
    /// — opinionated to keep the wire format unambiguous in logs
    /// and CLI output.
    #[test]
    fn tier_level_deserializes_uppercase_only() {
        for (raw, expected) in [
            ("\"HOT\"", TierLevel::Hot),
            ("\"WARM\"", TierLevel::Warm),
            ("\"PARKED\"", TierLevel::Parked),
        ] {
            let parsed: TierLevel = toml::from_str(&format!("value = {raw}")).map_or_else(
                |_| panic!("parse {raw}"),
                |wrapper: TierLevelWrapper| wrapper.value,
            );
            assert_eq!(parsed, expected);
        }

        // Lowercase rejected — pins the rename_all = "UPPERCASE"
        // contract.  A future relaxation to case-insensitive
        // would have to update this test deliberately.
        let lower: Result<TierLevelWrapper, _> = toml::from_str("value = \"warm\"");
        assert!(
            lower.is_err(),
            "lowercase tier level must be rejected to keep wire format unambiguous",
        );
    }

    /// Helper for the round-trip `TierLevel` pins above.
    /// `toml::{from_str, to_string}` both require a containing
    /// table at the document root because `TierLevel` itself
    /// (a bare enum value) isn't a valid TOML document.
    #[derive(Serialize, Deserialize)]
    struct TierLevelWrapper {
        /// Wrapped value — single-field shim so a bare
        /// `TierLevel` can deserialize from `value = "WARM"` in
        /// a TOML root context.
        value: TierLevel,
    }

    /// `TierLevel::to_state` lifts each variant to the matching
    /// `ShardState`.  Pin so a future addition (e.g. a hypothetical
    /// `Frozen` tier) has to update this test deliberately.
    #[test]
    fn tier_level_to_state_pin() {
        assert_eq!(TierLevel::Hot.to_state(), ShardState::Hot);
        assert_eq!(TierLevel::Warm.to_state(), ShardState::Warm);
        assert_eq!(TierLevel::Parked.to_state(), ShardState::Parked);
    }

    // ── Strictness ────────────────────────────────────────────────

    /// `#[serde(deny_unknown_fields)]` makes typos fail the parse
    /// rather than silently no-op.  Exercise on a plausible typo
    /// (`hot_tt1_base_secs` instead of `hot_ttl_base_secs`) so a
    /// future relaxation to permissive parsing has to update this
    /// test.
    #[test]
    fn unknown_field_in_tiers_section_rejected() {
        let body = "
[tiers]
hot_tt1_base_secs = 999
";
        let err = Config::from_toml(body).expect_err("typo'd field must produce a parse error");
        let msg = format!("{err}");
        assert!(
            msg.contains("hot_tt1_base_secs") || msg.contains("unknown field"),
            "error should mention the unknown field: got {msg:?}",
        );
    }

    /// Same strictness pin at the top-level section boundary.
    #[test]
    fn unknown_top_level_section_rejected() {
        let body = "
[bogus_section]
foo = 42
";
        let err = Config::from_toml(body)
            .expect_err("unknown top-level section must produce a parse error");
        let msg = format!("{err}");
        assert!(
            msg.contains("bogus_section") || msg.contains("unknown field"),
            "error should mention the unknown section: got {msg:?}",
        );
    }
}
