// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

#![expect(
    clippy::print_stderr,
    reason = "operational CLI tool — findings + summary go to stderr so consumers can pipe \
              stdout (currently empty) without losing the diagnostic stream (issue #212)"
)]

//! `uffs-manifest-audit` — workspace manifest-inheritance drift detector.
//!
//! Phase 1 follow-up tool from
//! `docs/dev/architecture/code_clean/phase_1_manifest_implementation_plan.md`
//! (local-only).  Encodes the 15 manifest invariants from §3 of that
//! plan as machine-checkable assertions, runs them against the
//! current workspace, and exits non-zero on the first drift.
//!
//! # Design
//!
//! * **`--check`-mode only** — the tool is read-only; it never mutates a
//!   manifest.  Consistent shape with `uffs-gen-workflow` and `uffs-gen-hooks
//!   --check`.
//! * **Source-of-truth** — `Cargo.toml` files under `crates/`,
//!   `scripts/ci-pipeline/`, and `scripts/ci/`.  The discovery pattern matches
//!   the existing `gates-drift` / `workflow-drift` detectors so the three gates
//!   triangulate the same member set.
//! * **Exit code** — `0` on no findings; `1` on any finding (with per-finding
//!   diagnostic written to stderr).

// `BTreeMap`/`BTreeSet` live in `alloc`; the workspace
// `clippy::std_instead_of_alloc` lint correctly prefers the canonical
// path over `std::collections::*` re-exports.  Bin crates need the
// explicit `extern crate alloc;` declaration to make the `alloc::`
// namespace visible.
extern crate alloc;

use alloc::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::Parser;

mod audit;
mod manifest;

use crate::audit::{DiscoveredMember, Finding, audit_all};

/// Workspace-relative path to the root `Cargo.toml`.
const ROOT_MANIFEST: &str = "Cargo.toml";

/// Workspace-relative roots under which member manifests are discovered.
/// Mirrors the discovery pattern used by Phase 1 §3.1 audit scripts.
const MEMBER_ROOTS: &[&str] = &["crates", "scripts/ci-pipeline", "scripts/ci"];

/// Validate the workspace manifest set against the 15 invariants.
///
/// `--check` is the default (and only) mode; the flag exists for
/// symmetry with `uffs-gen-hooks` / `uffs-gen-workflow` so the pre-push hook
/// output reads consistently across drift detectors.
#[derive(Debug, Parser)]
#[command(
    name = "uffs-manifest-audit",
    about = "Validate Cargo.toml inheritance against the 15 Phase-1 invariants.",
    long_about = None,
)]
struct Args {
    /// Run in check-only mode (the default).  Flag retained for CLI
    /// symmetry with `uffs-gen-hooks` / `uffs-gen-workflow`.
    #[arg(long, default_value_t = true)]
    check: bool,

    /// Workspace root directory.  Hidden flag for tests.
    #[arg(long, hide = true, default_value = ".")]
    workspace_root: PathBuf,

    /// Print per-invariant summary on success (default: silent).
    #[arg(long)]
    verbose: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("❌ uffs-manifest-audit: {err:#}");
            ExitCode::from(1)
        }
    }
}

/// Fallible entry point that owns every fs-read / parse / audit
/// step.  Split from `main` so the top-level `ExitCode` mapping
/// stays declarative.
fn run() -> Result<()> {
    let args = Args::parse();
    let root = &args.workspace_root;

    // Discover every member Cargo.toml + the root.
    let root_path = root.join(ROOT_MANIFEST);
    let root_text = std::fs::read_to_string(&root_path)
        .with_context(|| format!("read root manifest at {}", root_path.display()))?;
    let root_manifest = manifest::parse_root(&root_text).context("parse root Cargo.toml")?;

    let mut discovered_paths: BTreeSet<String> = BTreeSet::new();
    let mut member_texts: Vec<(String, String)> = Vec::new(); // (path, raw text)
    for member_root in MEMBER_ROOTS {
        let member_root_path = root.join(member_root);
        if !member_root_path.exists() {
            continue;
        }
        discover_members_recursive(&member_root_path, member_root, &mut discovered_paths)
            .with_context(|| format!("discover members under {member_root}"))?;
    }
    for path in &discovered_paths {
        let manifest_file = root.join(path).join("Cargo.toml");
        let text = std::fs::read_to_string(&manifest_file)
            .with_context(|| format!("read member manifest at {}", manifest_file.display()))?;
        member_texts.push((format!("{path}/Cargo.toml"), text));
    }

    // Parse every discovered member manifest.
    let parsed: Vec<(String, manifest::MemberManifest)> = member_texts
        .iter()
        .map(|(path, text)| {
            let parsed = manifest::parse_member(text)
                .with_context(|| format!("parse member manifest at {path}"))?;
            Ok::<_, anyhow::Error>((path.clone(), parsed))
        })
        .collect::<Result<Vec<_>>>()?;

    let discovered_members: Vec<DiscoveredMember<'_>> = parsed
        .iter()
        .map(|(path, manifest)| DiscoveredMember {
            manifest_path: path,
            manifest,
        })
        .collect();

    let findings = audit_all(
        &root_manifest,
        &root_text,
        &discovered_members,
        &discovered_paths,
    );

    if findings.is_empty() {
        if args.verbose {
            eprintln!(
                "✅ uffs-manifest-audit: workspace manifests pass all 15 Phase-1 invariants \
                 ({} member(s) checked)",
                discovered_members.len()
            );
        }
        Ok(())
    } else {
        emit_findings_report(&findings);
        anyhow::bail!(
            "uffs-manifest-audit detected {} drift finding(s)",
            findings.len()
        );
    }
}

/// Walk `dir` (workspace-relative `prefix`) looking for member
/// `Cargo.toml` files.  Records each *directory* (relative to the
/// workspace root) in `out`.  Does not descend into `target/`.
fn discover_members_recursive(
    dir: &Path,
    workspace_relative_prefix: &str,
    out: &mut BTreeSet<String>,
) -> Result<()> {
    // Direct child Cargo.toml?
    if dir.join("Cargo.toml").is_file() {
        out.insert(workspace_relative_prefix.to_owned());
    }
    // Recurse into subdirectories (one level — UFFS nests at most
    // `scripts/ci/<crate>` deep).
    let entries = std::fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))?;
    for entry_result in entries {
        let entry = entry_result.context("read_dir entry")?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == "target" || name_str.starts_with('.') {
            continue;
        }
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let child_prefix = format!("{workspace_relative_prefix}/{name_str}");
        if path.join("Cargo.toml").is_file() {
            out.insert(child_prefix);
        }
    }
    Ok(())
}

/// Print findings to stderr, grouped by invariant for human
/// scannability.
fn emit_findings_report(findings: &[Finding]) {
    eprintln!(
        "❌ uffs-manifest-audit: {} drift finding(s) detected:",
        findings.len()
    );
    eprintln!();
    for finding in findings {
        eprintln!("   • {finding}");
    }
    eprintln!();
    eprintln!(
        "   Fix locally with manifest edits (NOT lint suppressions).  Each finding cites the \
         Phase-1 invariant number — see \
         `docs/dev/architecture/code_clean/phase_1_manifest_implementation_plan.md` §3 for the \
         clean-state contract."
    );
}
