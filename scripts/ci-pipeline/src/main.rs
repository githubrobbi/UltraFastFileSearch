// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.
//
// UFFS - UltraFastFileSearch: High-Performance File Search Tool
// Contact: 50460704+githubrobbi@users.noreply.github.com for licensing
// inquiries.

#![expect(
    clippy::print_stdout,
    clippy::use_debug,
    reason = "operational CLI tool — user-facing banner + debug formatting of workflow state \
              go to stdout via println! (issue #212)"
)]

//! UFFS CI pipeline driver — Tokio async orchestration of the
//! pre-push, pre-ship, and ship workflows.
//!
//! Module layout (each module is self-contained with its own docs):
//!
//! * [`cli`]         — `clap` parser (`Cli`, `Commands`).
//! * [`context`]     — `PipelineContext`, `PipelineFlags`, and the small
//!   filesystem helpers used by context construction.
//! * [`workflow`]    — resumable-workflow state machine (`WorkflowState`,
//!   `StepTracker`, `WorkflowPhase`, `STEP_*` ids).
//! * [`exec`]        — subprocess execution primitives (`execute_command*`,
//!   `execute_parallel*`, `execute_step_with_tracking`).
//! * [`version`]     — version discovery + bump helpers.
//! * [`git_ops`]     — `git` + `gh` CLI orchestration for Phase 2 (commit,
//!   push, open PR, enable auto-merge).
//! * [`phases`]      — non-resumable `phase1_optimized` / `phase2_optimized`
//!   driver functions.
//! * [`ship`]        — resumable ship pipeline (`run_enhanced_phase1`,
//!   `run_enhanced_phase2`, `run_ship_pipeline`).
//! * [`cross_check`] — Linux + Windows cross-compilation syntax validation.
//!
//! `main` itself is just the CLI dispatch: parse → build context →
//! print banner → match subcommand → delegate.  Every subcommand
//! handler that survives in this file (`handle_go`,
//! `handle_check_all`, etc.) is a small coordinator — the real work
//! lives in the modules above.

// `BTreeMap`/`BTreeSet` live in `alloc`; the workspace
// `clippy::std_instead_of_alloc` lint correctly prefers the canonical
// path over `std::collections::*` re-exports.  Bin crates need the
// explicit `extern crate alloc;` to make the `alloc::` namespace
// visible (libraries get it for free via the 2024 edition's prelude).
extern crate alloc;

mod changelog;
mod cli;
mod context;
mod cross_check;
mod exec;
mod git_ops;
mod phases;
mod ship;
mod version;
mod workflow;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use colored::Colorize as _;
use tokio::process::Command;

use crate::cli::{Cli, Commands};
use crate::context::PipelineContext;
use crate::cross_check::handle_cross_check;
use crate::exec::execute_parallel;
use crate::phases::{coverage_report_command, phase1_optimized, phase2_optimized};
use crate::ship::{print_sccache_stats_if_verbose, run_ship_pipeline};
use crate::workflow::{WorkflowState, print_workflow_status};

// ─────────────────────────────────────────────────────────────────────────────
// Startup helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Print the startup banner (verbose mode + coverage status + sccache
/// status + log file location), then eagerly start the sccache server
/// if enabled so the first real compile inherits a warm connection.
async fn print_startup_banner_and_warm_sccache(ctx: &PipelineContext) {
    if ctx.flags.verbose {
        println!("{} Verbose mode enabled", "🔍".blue());
        println!(
            "{} Coverage report: {}",
            "📊".blue(),
            if ctx.flags.coverage_report {
                "enabled"
            } else {
                "disabled"
            }
        );
    }

    if ctx.flags.sccache_enabled {
        println!("{} sccache: enabled (RUSTC_WRAPPER=sccache)", "⚡".green());
    } else if ctx.flags.verbose {
        println!(
            "{} sccache: disabled (install sccache for big CI wins)",
            "⚡".yellow()
        );
    }

    if let Some(log_path) = &ctx.log_file {
        println!("{} Log file: {}", "📝".blue(), log_path.display());
    }

    if ctx.flags.sccache_enabled {
        // No-op if already running; safe and fast.  Best-effort
        // warm-up; ignore failures (e.g. sccache binary missing).
        _ = Command::new("sccache").arg("--start-server").output().await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Subcommand handlers that stay in `main.rs` (small enough that a
// separate module would just add import noise).
// ─────────────────────────────────────────────────────────────────────────────

/// `go` subcommand: Phase 1 validation + completion footer (total
/// time, coverage tip, next-step hint for `just phase2-ship`).
async fn handle_go(ctx: &PipelineContext) -> Result<()> {
    println!(
        "{}",
        "🚀 Safe-by-Default Validation Workflow (OPTIMIZED)"
            .blue()
            .bold()
    );
    phase1_optimized(ctx)
        .await
        .context("Validation workflow failed")?;

    let total_time = ctx.start_time.elapsed();
    println!(
        "{} Total pipeline time: {}s",
        "🎉".green(),
        total_time.as_secs()
    );

    print_sccache_stats_if_verbose(ctx).await;

    if !ctx.flags.coverage_report {
        println!(
            "{} Tip: Use --coverage-report to generate HTML coverage report",
            "💡".blue()
        );
    }
    println!("{} Run 'just phase2-ship' when ready to ship", "💡".blue());
    Ok(())
}

/// `check-all` subcommand: comprehensive validation using the same
/// `phase1_optimized` stack as `go`, with a distinct banner.
async fn handle_check_all(ctx: &PipelineContext) -> Result<()> {
    println!("{}", "📋 Comprehensive Validation (PARALLEL)".blue().bold());
    phase1_optimized(ctx)
        .await
        .context("Comprehensive validation failed")?;
    println!("{} Comprehensive validation complete!", "✅".green());
    Ok(())
}

/// `audit-comprehensive` subcommand: parallel multi-tool security
/// audit (cargo audit + cargo deny + cargo audit --deny warnings).
async fn handle_audit_comprehensive(ctx: &PipelineContext) -> Result<()> {
    println!(
        "{}",
        "🔒 Multi-Tool Security Audit (PARALLEL)".blue().bold()
    );
    let audit_commands = vec![
        ("Cargo audit", "cargo", vec!["audit"]),
        ("Cargo deny", "cargo", vec!["deny", "check"]),
        ("Security advisory", "cargo", vec![
            "audit", "--deny", "warnings",
        ]),
    ];
    execute_parallel(audit_commands, ctx)
        .await
        .context("Security audit failed")
}

/// `workflow-reset` subcommand: atomically replace the workflow state
/// file with a fresh default.
fn handle_workflow_reset() -> Result<()> {
    let state = WorkflowState::default();
    state
        .save()
        .context("Failed to save reset workflow state")?;
    println!("🧹 Workflow state reset to clean slate");
    Ok(())
}

/// `workflow-resume` subcommand: print a resumable-phase hint if a
/// partial ship is detected, otherwise fall through to the workflow
/// status display.
fn handle_workflow_resume() -> Result<()> {
    let state = WorkflowState::load().context("Failed to load workflow state")?;
    if state.is_resumable() {
        println!("🔄 Resuming workflow from phase: {:?}", state.phase);
        println!("💡 Run 'just phase2-ship' to continue the explicit ship lane");
    } else {
        println!("❌ No resumable workflow found");
        print_workflow_status(&state);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

/// CLI entry point.  Parses args, builds the [`PipelineContext`],
/// prints the startup banner, and dispatches to the `handle_*`
/// sub-function matching the chosen subcommand.  Each handler owns its
/// own footer printing so this dispatch stays a one-arm-per-command
/// match.
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let validation_command = matches!(
        cli.command,
        Commands::Go | Commands::CheckAll | Commands::Phase1
    );
    let ctx = PipelineContext::new(&cli, validation_command);

    print_startup_banner_and_warm_sccache(&ctx).await;

    match cli.command {
        Commands::Go => handle_go(&ctx).await?,
        Commands::Ship => run_ship_pipeline(&ctx)
            .await
            .context("Ship pipeline failed")?,
        Commands::CheckAll => handle_check_all(&ctx).await?,
        Commands::Phase1 => phase1_optimized(&ctx)
            .await
            .context("PHASE 1 standalone execution failed")?,
        Commands::Phase2 => phase2_optimized(&ctx)
            .await
            .context("PHASE 2 standalone execution failed")?,
        Commands::CoverageReport => coverage_report_command(&ctx)
            .await
            .context("Coverage report generation failed")?,
        Commands::AuditComprehensive => handle_audit_comprehensive(&ctx).await?,
        Commands::WorkflowStatus => {
            let state = WorkflowState::load().context("Failed to load workflow state")?;
            print_workflow_status(&state);
        }
        Commands::WorkflowReset => handle_workflow_reset()?,
        Commands::WorkflowResume => handle_workflow_resume()?,
        Commands::CrossCheck => handle_cross_check(&ctx).await?,
        Commands::ChangelogDraft => changelog::write_draft_into_unreleased()
            .context("Failed to draft CHANGELOG [Unreleased] from commits")?,
    }

    Ok(())
}
