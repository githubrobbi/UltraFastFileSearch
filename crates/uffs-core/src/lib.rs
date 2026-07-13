// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! # uffs-core: Query Engine for UFFS (Ultra Fast File Search)
//!
//! This crate provides a powerful query engine for searching and filtering
//! MFT data using Polars lazy API.
//!
//! ## Features
//!
//! - **Fluent Query API**: Chain filters naturally
//! - **Pattern Matching**: Glob and regex support with SIMD acceleration
//! - **Path Resolution**: Reconstruct full paths from FRS numbers
//! - **Export Formats**: Table, JSON, CSV output
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use uffs_mft::MftReader;
//! use uffs_core::MftQuery;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load MFT data
//!     let df = MftReader::load_parquet("c_drive.parquet")?;
//!
//!     // Query using fluent API
//!     let results = MftQuery::new(df)
//!         .glob("*.rs")
//!         .files_only()
//!         .min_size(1024)
//!         .sort_by_size(true)
//!         .limit(100)
//!         .collect()?;
//!
//!     // Export results
//!     uffs_core::export_table(&results, std::io::stdout())?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## API hygiene policy (Phase 3b §3.4 / §3.6 / §3.7)
//!
//! `uffs-core` is the query-engine and aggregation crate (Layer 3
//! per `docs/architecture/crate-graph.md`), consumed exclusively by
//! `uffs-daemon`.  Its public surface — 69 `pub struct`, 35 `pub enum`,
//! 1 `pub trait` — falls into four uniform categories with shared
//! decisions:
//!
//! 1. **Aggregation specs & results** (`aggregate::spec::*`,
//!    `aggregate::buckets::*`, `aggregate::duplicates::*`,
//!    `aggregate::finalize::*`, `aggregate::accumulators::*`): builder-style
//!    `pub`-field DTOs that the daemon constructs from incoming JSON wire
//!    input.  Hundreds of struct-literal construction sites in handler /
//!    facet-values / aggregate paths; a `#[non_exhaustive]` migration would
//!    require introducing a typed builder for every spec type for marginal
//!    benefit while the crate is Polars-blocked from publishing.  **Kept
//!    exhaustive.**
//!
//! 2. **Search backend value types** (`search::backend::DisplayRow`,
//!    `search::backend::DriveScopedRows`, `search::field::*`): canonical row
//!    representations that the formatter and the daemon hold in memory.  `pub`
//!    fields are the contract that `uffs-format::FormatRow` ↔ `DisplayRow` and
//!    the parallel-writer fast path depend on.  **Kept exhaustive.**
//!
//! 3. **Compact-cache headers** (`compact::*`, `compact_cache::*`,
//!    `compact_loader::*`, `compact_storage::*`): on-disk format contracts
//!    paralleling the NTFS zerocopy types in `uffs-mft`. Field layout **is**
//!    the cache file format; `pub` fields are non-negotiable.  **Kept
//!    exhaustive.**
//!
//! 4. **Pattern / trigram / bloom / index-search** types: search- pipeline data
//!    structures with `pub` constructor results. Same migration-cost rationale;
//!    **kept exhaustive**.
//!
//! The 35 `pub enum` declarations are **state-machine / dispatch
//! enums** (`FieldId`, `AggregateOp`, `BucketKind`, `SortDirection`,
//! pattern AST nodes, etc.) consumed by hundreds of exhaustive `match`
//! arms across `uffs-daemon`.  The compile-time exhaustiveness check
//! is the safety net guaranteeing every variant has handling logic at
//! every dispatch site — the playbook §3.6 "keep exhaustive" rule.
//! **Kept exhaustive.**
//!
//! The single `pub trait` — [`aggregate::verify::FileReader`] — is
//! the **dependency-injection point** between the daemon's real file
//! reader and the test-side mock reader.  External impls are by
//! design.  Sealing would defeat the trait's purpose.  **Kept open**
//! (see the type-level decision record on `FileReader` itself).
//!
//! # Environment
//!
//! Env vars read by this crate (registry:
//! `docs/architecture/code-quality/build_codegen_policy.md` §5, playbook
//! §1049-1056):
//!
//! | Env var | Type | Default | Notes |
//! |---|---|---|---|
//! | `UFFS_CACHE_PROFILE` | `bool` (`env::var_os(…).is_some()` — *any* value enables) | `false` (unset) | Emits per-phase cache I/O timings to stderr (`[CACHE_PROFILE]` prefix) from `compact_cache::{load,save,seek}` and `search::query`.  Dev / benchmark only.  INTERNAL semver class. |

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]

extern crate alloc;

// Suppress unused crate warnings for deps used by sub-modules or reserved
#[cfg(test)]
use criterion as _;
use devicons as _;
use memchr as _;
use tokio as _;

// ============================================================================
// Module declarations
// ============================================================================

pub mod aggregate;
pub mod bloom;
pub mod compact;
pub mod compact_cache;
pub(crate) mod compact_filters;
pub mod compact_loader;
// Phase 3: `compact_mmap` and `glob` have zero external module-path
// consumers (verified 2026-05-13 via workspace grep).  They retain
// internal use via `crate::*` paths.
pub(crate) mod compact_mmap;
pub mod compact_storage;
pub(crate) mod compiled_pattern;
pub mod diff;
mod error;
mod export;
pub mod extensions;
pub(crate) mod glob;
pub(crate) mod index_search;
pub mod output;
mod path_resolver;
pub mod path_trie;
pub mod pattern;
mod query;
pub mod search;
pub(crate) mod slot_pool;
pub mod tree;
pub mod trigram;
// Internal helper module — pack/unpack 3 folded `u16` codepoints into a `u64`
// trigram key.  Relocated from `uffs-text::trigram_key` on 2026-05-14 to keep
// the `uffs-text` publish surface scoped to the NTFS case-folding engine.
// `pub(crate)` because these packers are UFFS-index-specific and have no
// meaning outside this crate's `trigram` / `compact_cache` submodules.
mod trigram_key;

// ============================================================================
// Public API re-exports
// ============================================================================

pub use compiled_pattern::{CompiledPattern, GlobKind, classify_glob, compile_pattern};
pub use error::{CoreError, Result};
pub use export::{export_csv, export_json, export_table};
pub use extensions::{
    ExtensionFilter, ExtensionIndex, ExtensionIndexStats, add_ext_column, ext_expr, has_ext_column,
};
#[expect(
    deprecated,
    reason = "re-exporting deprecated function for backward compatibility"
)]
pub use path_resolver::add_path_column_multi_drive;
pub use path_resolver::{
    FastPathResolver, FastPathResolverMultiDrive, FastPathResolverStats, NameArena, PathResolver,
    add_path_only_column, add_paths_from_full_data,
};
pub use query::MftQuery;
pub use slot_pool::{DriveLoadEstimate, SlotPool, compute_load_budget, estimate_drive_cost};
pub use tree::{TreeColumn, add_tree_columns, apply_directory_treesize};
// `CaseFold` is the only cross-crate re-export here: it lives on
// `ParkedBody.fold` / `DriveCompactIndex.fold` and is re-exported so
// downstream crates (uffs-daemon, uffs-cli, tests) that touch those
// types don't need a direct `uffs-text` dependency.
//
// Polars types (`DataFrame`, `LazyFrame`, `IntoLazy`, `col`, `lit`,
// `columns`) and `uffs_mft::FileFlags` were re-exported here until
// 2026-05-08 but are NOT anymore — both blocks were dead code (zero
// downstream consumers, verified via repo-wide grep before deletion).
// Consumers that need polars types or `FileFlags` must depend on
// `uffs-polars` / `uffs-mft` directly.  This keeps the polars-tainted
// dep graph explicit and avoids transitive re-publishing of polars
// APIs through `uffs-core` — see `release-automation-plan.md`
// deviation log row "R6 → R8 publishability resolution (Path A)".
pub use uffs_text::case_fold::CaseFold;
