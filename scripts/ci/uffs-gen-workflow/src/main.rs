// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

#![expect(
    clippy::print_stderr,
    reason = "operational CLI tool — user-facing summary + drift report go to stderr (issue #212)"
)]

//! `uffs-gen-workflow` — gate-manifest workflow structural validator.
//!
//! Phase 3 deliverable from `docs/architecture/gates-manifest-plan.md`
//! (relative to the repo root).
//!
//! # Design
//!
//! Plan §4.2 originally specified a YAML emitter that would own the
//! per-gate job blocks in `.github/workflows/pr-fast.yml` between
//! marker comments.  Investigation during Phase 3 prep showed every
//! per-gate job in the workflow is bespoke (eleven distinct shapes
//! for ~thirteen pr-fast-tier gates: differences in runner OS,
//! timeout, `needs:` chain, rust-cache key strategy, free-disk
//! preamble, conditional cargo-vet install + run, multi-step
//! commands).  Encoding all of that in TOML so the generator can
//! emit it back is a YAML-in-TOML translation problem with no real
//! upside, AND it stakes branch protection on a hand-rolled YAML
//! emitter.
//!
//! The plan was revised in PR #142 to a `--check`-only structural
//! validator that retains every drift-protection guarantee at the
//! same risk profile as Phase 1's `gates-drift` — the tool only
//! reads files; it cannot break the workflow.
//!
//! # Properties enforced
//!
//! 1. **Job presence** — every manifest gate with `tier="pr-fast"` has a
//!    corresponding job in `pr-fast.yml` (resolved via
//!    `consumer_names["pr-fast"]` if present, else the gate id). Multiple gates
//!    may fold into one job (e.g. `rustdoc` + `doc-tests` → `docs`); the
//!    validator handles many-to-one.
//! 2. **`if:` predicate alignment** — for each pr-fast job, the job's `if:`
//!    predicate must be at least as permissive as the least-upper-bound of the
//!    `gate_when` classes of the gates folded into it.  Wider is fine
//!    (over-runs); narrower is drift (would block a gate from running on its
//!    trigger).
//! 3. **Aggregator coverage** — every gate's resolved job-id is in
//!    `required.needs:` AND the `declare -A R=(...)` aggregator inside the
//!    `required` job.  This is the exact rename-bookkeeping failure mode that
//!    motivated the whole plan.  (The `notify-failure.needs:` invariant was
//!    retired in the Design C refactor for #209; failure notification now lives
//!    in `.github/workflows/ci-failure-notify.yml`.)
//! 4. **Branch-protection guard** — the `required` job's `name:` field is
//!    exactly the literal string `PR Fast CI / required`. This name is in the
//!    repo's branch-protection rule (`required_status_checks`); a refactor that
//!    renamed it would silently break merge for every subsequent PR.
//!
//! Property 5 from the plan ("naming convention") is intentionally
//! deferred — see plan §4.2 for the rationale (multiple gates fold
//! into one job, so display names like `Clippy` are not 1:1
//! derivable from manifest fields without a schema extension).

// `BTreeMap`/`BTreeSet` live in `alloc`; the workspace
// `clippy::std_instead_of_alloc` lint correctly prefers the canonical
// path over `std::collections::*` re-exports.  Bin crates need the
// explicit `extern crate alloc;` to make the `alloc::` namespace
// visible (libraries get it for free via the 2024 edition's prelude).
extern crate alloc;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::Parser;

mod manifest;
mod validate;
mod workflow;

/// Default path to the gate manifest, relative to the workspace root.
///
/// Hidden CLI flag `--manifest` overrides for tests.
const DEFAULT_MANIFEST_PATH: &str = "scripts/ci/gates.toml";

/// Default path to the GitHub Actions PR workflow, relative to the
/// workspace root.  Hidden CLI flag `--workflow` overrides for tests.
const DEFAULT_WORKFLOW_PATH: &str = ".github/workflows/pr-fast.yml";

/// Validate `.github/workflows/pr-fast.yml` against the gate manifest.
///
/// `--check` is the default and only behaviour; the flag exists for
/// symmetry with `uffs-gen-hooks` so a contributor reading the pre-push
/// hook output sees a consistent CLI shape.  There is no `--write`
/// mode — see plan §4.2 for the design rationale.
#[derive(Debug, Parser)]
#[command(
    name = "uffs-gen-workflow",
    about = "Validate pr-fast.yml structurally against scripts/ci/gates.toml.",
    long_about = None,
)]
struct Args {
    /// Run in check-only mode (the default; flag retained for CLI symmetry
    /// with `uffs-gen-hooks`).  Exits 1 if drift is detected.
    #[arg(long, default_value_t = true)]
    check: bool,

    /// Path to the gate manifest TOML.  Hidden; defaults to the
    /// workspace-relative `scripts/ci/gates.toml`.
    #[arg(long, hide = true, default_value = DEFAULT_MANIFEST_PATH)]
    manifest: PathBuf,

    /// Path to the GitHub Actions workflow YAML.  Hidden; defaults to the
    /// workspace-relative `.github/workflows/pr-fast.yml`.
    #[arg(long, hide = true, default_value = DEFAULT_WORKFLOW_PATH)]
    workflow: PathBuf,

    /// Print per-property summary on success (default: silent on success).
    #[arg(long)]
    verbose: bool,
}

fn main() -> ExitCode {
    uffs_version::handle_version!("uffs-gen-workflow");
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("❌ uffs-gen-workflow: {err:#}");
            ExitCode::from(1)
        }
    }
}

/// Top-level fallible entry point — reads both inputs, runs the
/// validator, exits non-zero on the first drift class detected.
fn run() -> Result<()> {
    let args = Args::parse();

    let manifest_text = std::fs::read_to_string(&args.manifest)
        .with_context(|| format!("read gate manifest at {}", args.manifest.display()))?;
    let workflow_text = std::fs::read_to_string(&args.workflow)
        .with_context(|| format!("read workflow at {}", args.workflow.display()))?;

    let manifest = manifest::parse(&manifest_text).context("parse gate manifest")?;
    let workflow = workflow::parse(&workflow_text).context("parse pr-fast.yml")?;

    let report = validate::validate(&manifest, &workflow, &workflow_text)
        .context("run structural validator")?;

    if report.is_empty() {
        if args.verbose {
            eprintln!(
                "✅ uffs-gen-workflow: pr-fast.yml is structurally consistent with gates.toml"
            );
            eprintln!("   (4 properties checked; see plan §4.2)");
        }
        Ok(())
    } else {
        eprintln!(
            "❌ uffs-gen-workflow: {} structural drift issue(s) detected:",
            report.len()
        );
        for issue in &report {
            eprintln!("   • {issue}");
        }
        eprintln!();
        eprintln!("   Manifest: {}", args.manifest.display());
        eprintln!("   Workflow: {}", args.workflow.display());
        eprintln!(
            "   Plan: docs/architecture/gates-manifest-plan.md §4.2 lists the four enforced properties."
        );
        anyhow::bail!("structural drift detected");
    }
}
