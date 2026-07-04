// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.
//
//! `clap` command-line parser target for the UFFS CI pipeline driver.
//!
//! One `Cli` struct for every global flag the pipeline reads and one
//! `Commands` enum for the subcommand dispatch.  Both types are visible
//! to sibling modules via `pub(crate)`; keep everything else `private`
//! so the public API of the binary crate stays narrow.

use clap::{Parser, Subcommand};

/// Top-level `clap` parser target.  One field per global CLI flag plus
/// a `command: Commands` subcommand.  See [`Commands`] for the per-
/// subcommand shape.
// `Cli` is a `clap::Parser` derive target that deliberately mirrors
// every boolean CLI flag as a `bool` field.  Refactoring this into a
// bitflags struct or grouping-by-subcommand would break the `clap`
// derive machinery and the `--help` output.  The "too many bools" lint
// is legitimately noise for option-parsing types; scope the suppression
// to this struct only.
#[derive(Parser)]
#[command(name = "ci-pipeline")]
#[command(about = "UFFS High-Performance CI Pipeline with Async Orchestration")]
#[expect(
    clippy::struct_excessive_bools,
    reason = "clap Parser target: one bool per --flag; refactoring breaks the CLI surface"
)]
pub(crate) struct Cli {
    /// Selected subcommand (`ship`, `go`, `check-all`, ...).
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output (show all command details)
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Generate coverage report (slower, but comprehensive)
    #[arg(short, long, global = true)]
    pub coverage_report: bool,

    /// Force a full `cargo clean` at the start (slower, but can recover from
    /// stale artifacts)
    #[arg(long, global = true)]
    pub clean: bool,

    /// Force skipping cargo clean even when auto-clean would run (dangerous if
    /// disk is tight).
    #[arg(long, global = true)]
    pub no_clean: bool,

    /// Auto-clean if free disk space (GiB) is below this threshold.
    #[arg(long, global = true, default_value_t = 25)]
    pub min_free_gb: u64,

    /// Auto-clean if the cargo target directory exceeds this size (GiB).
    /// Best-effort; unix only.
    #[arg(long, global = true, default_value_t = 120)]
    pub max_target_gb: u64,

    /// Override Cargo build parallelism (`CARGO_BUILD_JOBS` / rustc job count).
    /// Also caps the parallel fan-out of validation commands to this value.
    /// If omitted, `CARGO_BUILD_JOBS` defaults to `min(num_cpus, 16)` and
    /// fan-out defaults to `max(num_cpus / 4, 2)`.
    #[arg(long, global = true)]
    pub jobs: Option<usize>,

    /// Disable sccache auto-detection/integration even if it is installed.
    #[arg(long, global = true)]
    pub no_sccache: bool,

    /// Force a fresh run, ignoring any previously completed steps.
    /// Use this to start the pipeline from scratch.
    #[arg(long, global = true)]
    pub fresh: bool,

    /// Skip the nightly toolchain bump even on `--fresh` runs.
    ///
    /// By default `ship --fresh` invokes `just toolchain-sync` (bumps
    /// `rust-toolchain.toml` to today's nightly).  Pass this flag when
    /// the latest nightly is known-broken and you want to keep the
    /// currently pinned one — the pipeline will fall back to
    /// `just toolchain-ensure` (install-the-pinned-one).  Non-fresh
    /// `ship` runs always use `toolchain-ensure` regardless of this
    /// flag; the sync only happens on `--fresh`.
    #[arg(long, global = true)]
    pub skip_toolchain_sync: bool,
}

/// CLI subcommands.  Each variant maps 1:1 to a sub-entry-point in
/// `main`; see that dispatch for the runtime semantics.
#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Safe-by-default validation workflow (no version bump, deploy, commit, or
    /// push)
    Go,
    /// Full ship pipeline: Phase 1 validation + Phase 2 deploy (resumable)
    /// Re-runs skip already-completed steps. Use --fresh to start from scratch.
    Ship,
    /// Comprehensive nightly-grade validation with parallel execution
    CheckAll,
    /// Phase 1 nightly validation gates with maximum parallelism
    Phase1,
    /// Explicit ship lane: version bump, build, deploy, commit, and push
    Phase2,
    /// Generate coverage report from existing data (or run tests if needed)
    CoverageReport,
    /// Multi-tool security audit with parallelism
    AuditComprehensive,
    /// Check current workflow status
    WorkflowStatus,
    /// Reset workflow state (force clean slate)
    WorkflowReset,
    /// Resume incomplete workflow
    WorkflowResume,
    /// Nightly cross-compilation validation
    CrossCheck,
    /// Write an auto-generated draft into CHANGELOG `[Unreleased]` from the
    /// Conventional-Commit subjects since the last release tag. A placeholder
    /// to polish before shipping; never overwrites hand-authored notes.
    ChangelogDraft,
}
