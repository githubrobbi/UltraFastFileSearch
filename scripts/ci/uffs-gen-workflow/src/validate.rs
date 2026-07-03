// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Structural validation logic.
//!
//! Each of the four properties from plan §4.2 is implemented as a
//! standalone function returning `Vec<String>` of human-readable
//! drift descriptions (empty on success).  [`validate`] runs all
//! four and concatenates results.
//!
//! # Design choices
//!
//! - **No early returns between properties.**  A single drift in Property 1
//!   should not hide drift in Property 3.  Operators debugging a manifest
//!   renumbering want to see all issues at once.
//! - **`required` job's bash table is parsed via regex over the raw workflow
//!   text**, not via the YAML model.  The bash script is a YAML scalar string;
//!   structural validation of *bash code* would need a bash parser, which is
//!   overkill for the `[<job-id>]='${{ ... }}'` line shape.  Regex with a tight
//!   anchor pattern is sufficient and self-documenting.
//! - **Predicate alignment uses a [`PermissiveSet`] lattice.**  The set of
//!   change classes a job must accept is the union of its folded gates'
//!   classes; the set the `if:` predicate accepts is parsed from a small
//!   recognised vocabulary (see [`PermissiveSet::from_if_expr`]).  Drift = any
//!   class needed but not accepted.

use alloc::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result};
use regex::Regex;

use crate::manifest::{Gate, Manifest};
use crate::workflow::Workflow;

/// Run all four structural property checks; return the concatenated
/// list of drift descriptions in property order so reviewers can
/// pattern-match the output regardless of how many issues fire at
/// once.
///
/// # Errors
///
/// Returns an error if a regex used by Property 3 fails to compile;
/// in practice this can only happen if the `regex` crate itself is
/// broken, since the patterns are literal strings tested by the
/// crate's unit tests.
pub(crate) fn validate(
    manifest: &Manifest,
    workflow: &Workflow,
    workflow_text: &str,
) -> Result<Vec<String>> {
    let mut issues = Vec::new();
    issues.extend(check_job_presence(manifest, workflow));
    issues.extend(check_if_predicates(manifest, workflow));
    issues.extend(check_aggregator_coverage(
        manifest,
        workflow,
        workflow_text,
    )?);
    issues.extend(check_required_name_guard(workflow));
    Ok(issues)
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 1 — Job presence
// ─────────────────────────────────────────────────────────────────────────────

/// For every pr-fast-tier gate, the resolved job-id must exist as a
/// key in the workflow's `jobs:` map.  Multiple gates may resolve to
/// the same job-id (e.g. `rustdoc` + `doc-tests` → `docs`); each gate
/// that maps to a missing job is reported separately so a reviewer
/// sees the full picture.
fn check_job_presence(manifest: &Manifest, workflow: &Workflow) -> Vec<String> {
    let mut issues = Vec::new();
    for gate in manifest.pr_fast_gates() {
        let job_id = gate.pr_fast_job_id();
        if !workflow.jobs.contains_key(job_id) {
            issues.push(format!(
                "Property 1 (job presence): manifest gate `{gate_id}` (label={label:?}) resolves to job `{job_id}` which is missing from pr-fast.yml",
                gate_id = gate.id,
                label = gate.label,
            ));
        }
    }
    issues
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 2 — `if:` predicate alignment
// ─────────────────────────────────────────────────────────────────────────────

/// Set of change classes a predicate (or a fold of gates) accepts.
///
/// Implements the Property 2 lattice: a job's `if:` is valid iff its
/// set is a SUPERSET of the union of its folded gates' sets.
///
/// Modeled as a `u8` bitset with one bit per change class
/// (rust / dep / infra / always).  This is materially cleaner than
/// the original `struct { rust: bool, dep: bool, infra: bool,
/// always: bool }` shape — single-byte values, free `Copy`, free
/// `union` via `|`, free `contains` via `&` — and avoids the
/// `clippy::struct_excessive_bools` lint at the root cause (the
/// data shape itself, not via a per-item suppression).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct PermissiveSet(u8);

impl PermissiveSet {
    /// `*.rs` files changed.
    const RUST: Self = Self(1 << 0);
    /// `Cargo.toml` / `Cargo.lock` / `supply-chain/` changed.
    const DEP: Self = Self(1 << 1);
    /// `.github/`, `scripts/`, `.cargo/`, `just/` etc. changed.
    const INFRA: Self = Self(1 << 2);
    /// "Run unconditionally" — `always()` / no `if:` field / no
    /// classification gating.  Strictly stronger than rust+dep+infra
    /// because it also runs on pure docs-only PRs that wouldn't
    /// trigger any of the other three classes.
    const ALWAYS: Self = Self(1 << 3);
    /// rust + dep + infra (matches `gate_when = "code_changed"`).
    const CODE: Self = Self(Self::RUST.0 | Self::DEP.0 | Self::INFRA.0);
    /// rust + dep + infra + always (matches `gate_when = "always"`
    /// and the `always()` workflow predicate).
    const ALL: Self = Self(Self::CODE.0 | Self::ALWAYS.0);

    /// Build the set a single gate's `gate_when` field accepts.
    /// Unknown values yield an empty set, which guarantees a
    /// downstream drift report (the job will fail to satisfy the
    /// superset check, surfacing the unrecognised value).
    fn from_gate_when(when: &str) -> Self {
        match when {
            "always" => Self::ALL,
            "code_changed" => Self::CODE,
            "rust_changed" => Self::RUST,
            "dep_changed" => Self::DEP,
            "infra_changed" => Self::INFRA,
            _ => Self::default(),
        }
    }

    /// Parse the workflow's `if:` predicate string into a
    /// permissive set.  Only the vocabulary actually used in
    /// `pr-fast.yml` is recognised:
    ///
    /// - `always()` or `None`                       → all four bits
    /// - `needs.classify.outputs.code == 'true'`    → rust + dep + infra
    /// - `needs.classify.outputs.rust == 'true'`    → rust
    /// - `needs.classify.outputs.dep == 'true'`     → dep
    /// - `needs.classify.outputs.infra == 'true'`   → infra
    ///
    /// Any other shape falls through to the default empty set,
    /// triggering a drift report on the next superset check.
    fn from_if_expr(expr: Option<&str>) -> Self {
        let Some(text) = expr else {
            // No `if:` field → unconditional → all classes accepted.
            return Self::ALL;
        };
        if text.contains("always()") {
            return Self::ALL;
        }
        if text.contains("classify.outputs.code") {
            return Self::CODE;
        }
        let mut set = Self::default();
        if text.contains("classify.outputs.rust") {
            set = set.union(Self::RUST);
        }
        if text.contains("classify.outputs.dep") {
            set = set.union(Self::DEP);
        }
        if text.contains("classify.outputs.infra") {
            set = set.union(Self::INFRA);
        }
        set
    }

    /// Set union — used to combine multiple folded gates'
    /// requirements into a single demand the job must satisfy.
    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// `true` iff every bit set in `needed` is also set in `self`.
    /// Drift = `!self.contains(needed)`.
    const fn contains(self, needed: Self) -> bool {
        (self.0 & needed.0) == needed.0
    }

    /// Human-readable list of the change classes this set accepts,
    /// for error messages.
    fn describe(self) -> String {
        if self == Self::ALL {
            return "always (rust, dep, infra, docs-only)".to_owned();
        }
        let mut parts = Vec::new();
        if self.contains(Self::RUST) {
            parts.push("rust");
        }
        if self.contains(Self::DEP) {
            parts.push("dep");
        }
        if self.contains(Self::INFRA) {
            parts.push("infra");
        }
        if self.contains(Self::ALWAYS) {
            parts.push("always");
        }
        if parts.is_empty() {
            "(none — predicate not recognised)".to_owned()
        } else {
            parts.join(" + ")
        }
    }
}

/// Group manifest gates by resolved pr-fast job-id, preserving
/// manifest order for deterministic error reporting.
fn group_by_job_id(manifest: &Manifest) -> BTreeMap<&str, Vec<&Gate>> {
    let mut groups: BTreeMap<&str, Vec<&Gate>> = BTreeMap::new();
    for gate in manifest.pr_fast_gates() {
        groups.entry(gate.pr_fast_job_id()).or_default().push(gate);
    }
    groups
}

/// For each job that has manifest gates folded into it, verify the
/// job's `if:` predicate accepts every change class the constituent
/// gates need to run on.
fn check_if_predicates(manifest: &Manifest, workflow: &Workflow) -> Vec<String> {
    let mut issues = Vec::new();
    for (job_id, gates) in group_by_job_id(manifest) {
        let Some(job) = workflow.jobs.get(job_id) else {
            // Job absent → already reported by Property 1.
            continue;
        };
        let needed: PermissiveSet = gates
            .iter()
            .map(|gate| PermissiveSet::from_gate_when(&gate.when))
            .fold(PermissiveSet::default(), PermissiveSet::union);

        let actual = PermissiveSet::from_if_expr(job.if_expr.as_deref());

        if !actual.contains(needed) {
            let gate_summary = gates
                .iter()
                .map(|gate| format!("{}({})", gate.id, gate.when))
                .collect::<Vec<_>>()
                .join(", ");
            issues.push(format!(
                "Property 2 (if: predicate alignment): job `{job_id}` accepts [{actual_desc}] but folded gates [{gate_summary}] need [{needed_desc}]; predicate is too narrow",
                actual_desc = actual.describe(),
                needed_desc = needed.describe(),
            ));
        }
    }
    issues
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 3 — Aggregator coverage
// ─────────────────────────────────────────────────────────────────────────────

/// Pattern for the bash `R=(...)` table line shape:
/// `<whitespace>[<job-id>]=<rest>`.
///
/// Anchored to start-of-line (after whitespace) and an opening `[`
/// so the regex does not match `${{ needs.foo.result }}`
/// substitutions or other bracket-bearing tokens that happen to sit
/// mid-line.
const AGGREGATOR_LINE_PATTERN: &str = r"^\s*\[([a-zA-Z0-9_-]+)\]=";

/// Compile the [`AGGREGATOR_LINE_PATTERN`] regex.
///
/// # Errors
///
/// Returns an error if the `regex` crate fails to compile a literal
/// pattern.  In practice that only happens if the crate itself is
/// broken; the pattern is exercised by every test in this module so
/// any real breakage surfaces immediately.
fn aggregator_table_regex() -> Result<Regex> {
    Regex::new(AGGREGATOR_LINE_PATTERN)
        .with_context(|| format!("compile aggregator regex {AGGREGATOR_LINE_PATTERN:?}"))
}

/// Extract the set of job-ids declared in the `required` job's bash
/// `declare -A R=(...)` table.  Operates on the raw workflow text
/// because the bash code lives inside a YAML string scalar — pulling
/// it from the YAML model requires schema-modelling step contents,
/// which the validator deliberately avoids (see plan §4.2 "What is
/// explicitly NOT validated").
///
/// # Errors
///
/// Propagates the regex compilation error from
/// [`aggregator_table_regex`].
fn extract_aggregator_ids(workflow_text: &str) -> Result<BTreeSet<String>> {
    let regex = aggregator_table_regex()?;
    let mut inside_table = false;
    let mut ids = BTreeSet::new();
    for line in workflow_text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("declare -A R=(") {
            inside_table = true;
            continue;
        }
        if inside_table {
            // The closing `)` ends the table.  Match it with leading
            // whitespace only to avoid mid-line `)` in expressions.
            if trimmed.starts_with(')') {
                inside_table = false;
                continue;
            }
            if let Some(captures) = regex.captures(line)
                && let Some(id) = captures.get(1)
            {
                ids.insert(id.as_str().to_owned());
            }
        }
    }
    Ok(ids)
}

/// For each manifest gate's resolved job-id, verify presence in:
/// 1. `workflow.jobs["required"].needs`
/// 2. the bash `declare -A R=(...)` table inside `required`
///
/// The third invariant — coverage in `workflow.jobs["notify-failure"].needs:`
/// — was retired in the Design C refactor for #209.  Failure notification
/// is now produced by `.github/workflows/ci-failure-notify.yml`, which
/// triggers off `workflow_run [completed]` rather than via an in-workflow
/// `notify-failure` job needing a `needs:` list of every gate.
///
/// # Errors
///
/// Propagates the regex compilation error from
/// [`extract_aggregator_ids`].
fn check_aggregator_coverage(
    manifest: &Manifest,
    workflow: &Workflow,
    workflow_text: &str,
) -> Result<Vec<String>> {
    let mut issues = Vec::new();

    let required_needs: BTreeSet<String> = workflow
        .jobs
        .get("required")
        .map(|job| job.needs.iter().cloned().collect())
        .unwrap_or_default();
    let aggregator_ids = extract_aggregator_ids(workflow_text)?;

    // Each manifest job-id must appear in both lists.  We dedupe via
    // BTreeSet to avoid duplicate reports for folded gates (e.g.
    // rustdoc + doc-tests both → docs).
    let needed_ids: BTreeSet<&str> = manifest.pr_fast_gates().map(Gate::pr_fast_job_id).collect();

    for job_id in needed_ids {
        if !required_needs.contains(job_id) {
            issues.push(format!(
                "Property 3 (aggregator coverage): job `{job_id}` is missing from required.needs:"
            ));
        }
        if !aggregator_ids.contains(job_id) {
            issues.push(format!(
                "Property 3 (aggregator coverage): job `{job_id}` is missing from the `declare -A R=(...)` table inside the required job"
            ));
        }
    }

    Ok(issues)
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 4 — Branch-protection guard
// ─────────────────────────────────────────────────────────────────────────────

/// The literal string GitHub branch protection matches against.
/// Source-of-truth: the repository's
/// `required_status_checks.contexts` ruleset.  Plan §4.2 Property 4
/// enforces this string verbatim.
pub(crate) const REQUIRED_JOB_NAME: &str = "PR Fast CI / required";

/// The `required` job's `name:` field MUST be exactly
/// [`REQUIRED_JOB_NAME`].  A rename here silently breaks branch
/// protection for every subsequent PR — there's no other guard.
fn check_required_name_guard(workflow: &Workflow) -> Vec<String> {
    let mut issues = Vec::new();
    let Some(job) = workflow.jobs.get("required") else {
        issues.push(format!(
            "Property 4 (branch-protection guard): job key `required` is missing from pr-fast.yml; branch protection requires a job whose name is exactly `{REQUIRED_JOB_NAME}`"
        ));
        return issues;
    };
    match job.name.as_deref() {
        Some(name) if name == REQUIRED_JOB_NAME => {}
        Some(name) => {
            issues.push(format!(
                "Property 4 (branch-protection guard): required job's name is `{name:?}` but branch protection requires exactly `{REQUIRED_JOB_NAME}`"
            ));
        }
        None => {
            issues.push(format!(
                "Property 4 (branch-protection guard): required job has no `name:` field; branch protection requires exactly `{REQUIRED_JOB_NAME}`"
            ));
        }
    }
    issues
}

#[cfg(test)]
#[expect(
    clippy::min_ident_chars,
    clippy::indexing_slicing,
    reason = "test code uses idiomatic short bindings + positional indexing against fixed-shape \
              fixtures; failures panic with adequate context (issue #212)"
)]
mod tests {
    use super::*;
    use crate::{manifest, workflow};

    /// Manifest fixture covering all four classes of `gate_when`:
    /// `always`, `code_changed`, `rust_changed`, `dep_changed`.
    /// Includes folding: `cargo-check` (code) + `vet` (dep) → sanity.
    const MANIFEST_FIXTURE: &str = r#"
[[gate]]
id = "fmt"
label = "fmt"
tiers = ["pr-fast"]
gate_when = "rust_changed"

[[gate]]
id = "file-size"
label = "file-size"
tiers = ["pr-fast"]
gate_when = "always"

[[gate]]
id = "cargo-check"
label = "cargo check"
tiers = ["pr-fast"]
gate_when = "code_changed"
consumer_names = { "pr-fast" = "sanity" }

[[gate]]
id = "vet"
label = "cargo vet"
tiers = ["pr-fast"]
gate_when = "dep_changed"
consumer_names = { "pr-fast" = "sanity" }

[[gate]]
id = "lint-prod"
label = "ultra-strict clippy"
tiers = ["pre-commit", "pre-push"]
gate_when = "rust_changed"
"#;

    /// Workflow fixture that's CONSISTENT with the manifest above.
    /// Tests mutate this string to provoke each drift class.
    const WORKFLOW_FIXTURE: &str = "
name: PR Fast CI
on: pull_request
jobs:
  classify:
    name: Classify changes
    runs-on: ubuntu-22.04
    outputs:
      rust: ${{ steps.x.outputs.rust }}
    steps:
      - run: echo

  fmt:
    name: Format check
    runs-on: ubuntu-22.04
    needs: classify
    if: needs.classify.outputs.rust == 'true'
    steps:
      - run: cargo fmt

  file-size:
    name: File size
    runs-on: ubuntu-22.04
    needs: classify
    steps:
      - run: bash check.sh

  sanity:
    name: Sanity
    runs-on: ubuntu-22.04
    needs: classify
    if: needs.classify.outputs.code == 'true'
    steps:
      - run: cargo check

  required:
    name: PR Fast CI / required
    runs-on: ubuntu-22.04
    if: always()
    needs:
      - classify
      - fmt
      - file-size
      - sanity
    steps:
      - run: |
          declare -A R=(
            [fmt]='${{ needs.fmt.result }}'
            [file-size]='${{ needs.file-size.result }}'
            [sanity]='${{ needs.sanity.result }}'
          )
";

    /// Helper — parse both fixtures and run the validator.
    /// `unwrap()` is allowed in tests via `clippy.toml`'s
    /// `allow-unwrap-in-tests = true`.
    fn validate_fixture(manifest_text: &str, workflow_text: &str) -> Vec<String> {
        let m = manifest::parse(manifest_text).unwrap();
        let w = workflow::parse(workflow_text).unwrap();
        validate(&m, &w, workflow_text).unwrap()
    }

    // ─── Permissive-set lattice unit tests ────────────────────────

    #[test]
    fn permissive_set_from_gate_when() {
        assert_eq!(PermissiveSet::from_gate_when("always"), PermissiveSet::ALL);
        assert_eq!(
            PermissiveSet::from_gate_when("code_changed"),
            PermissiveSet::CODE
        );
        assert_eq!(
            PermissiveSet::from_gate_when("rust_changed"),
            PermissiveSet::RUST
        );
        // Unknown gate_when → empty set (drift will surface in the
        // downstream contains() check).
        assert_eq!(
            PermissiveSet::from_gate_when("does_not_exist"),
            PermissiveSet::default()
        );
    }

    #[test]
    fn permissive_set_from_if_expr() {
        assert!(PermissiveSet::from_if_expr(None).contains(PermissiveSet::ALWAYS));
        assert!(PermissiveSet::from_if_expr(Some("always()")).contains(PermissiveSet::ALWAYS));
        let code = PermissiveSet::from_if_expr(Some("needs.classify.outputs.code == 'true'"));
        assert!(code.contains(PermissiveSet::CODE));
        assert!(!code.contains(PermissiveSet::ALWAYS));
        let rust = PermissiveSet::from_if_expr(Some("needs.classify.outputs.rust == 'true'"));
        assert!(rust.contains(PermissiveSet::RUST));
        assert!(!rust.contains(PermissiveSet::DEP));
    }

    #[test]
    fn permissive_set_union_handles_mixed_classes() {
        // sanity job folds rust_changed + dep_changed gates → must
        // accept BOTH rust and dep.
        let folded = PermissiveSet::from_gate_when("rust_changed")
            .union(PermissiveSet::from_gate_when("dep_changed"));
        assert!(folded.contains(PermissiveSet::RUST));
        assert!(folded.contains(PermissiveSet::DEP));
        assert!(!folded.contains(PermissiveSet::INFRA));
        assert!(!folded.contains(PermissiveSet::ALWAYS));

        // job's if: code accepts rust + dep + infra → contains folded.
        let job = PermissiveSet::from_if_expr(Some("classify.outputs.code"));
        assert!(job.contains(folded));

        // job's if: rust does NOT contain rust + dep — too narrow.
        let narrow = PermissiveSet::from_if_expr(Some("classify.outputs.rust"));
        assert!(!narrow.contains(folded));
    }

    // ─── Happy-path: the consistent fixture passes ────────────────

    #[test]
    fn consistent_fixture_passes_all_four_properties() {
        let issues = validate_fixture(MANIFEST_FIXTURE, WORKFLOW_FIXTURE);
        assert!(
            issues.is_empty(),
            "expected no drift, got:\n{}",
            issues.join("\n")
        );
    }

    // ─── Property 1 mutation tests ────────────────────────────────

    #[test]
    fn property1_detects_missing_job() {
        // Remove the `sanity` job — both cargo-check and vet fold
        // into it, so we expect 2 issues (one per gate).
        let workflow = WORKFLOW_FIXTURE.replace(
            "  sanity:\n    name: Sanity\n    runs-on: ubuntu-22.04\n    needs: classify\n    if: needs.classify.outputs.code == 'true'\n    steps:\n      - run: cargo check\n\n",
            "",
        );
        let issues = validate_fixture(MANIFEST_FIXTURE, &workflow);
        let p1: Vec<&String> = issues.iter().filter(|s| s.contains("Property 1")).collect();
        assert_eq!(
            p1.len(),
            2,
            "expected one P1 issue per missing-job gate, got {}: {:?}",
            p1.len(),
            issues
        );
        assert!(p1.iter().any(|s| s.contains("`cargo-check`")));
        assert!(p1.iter().any(|s| s.contains("`vet`")));
    }

    // ─── Property 2 mutation tests ────────────────────────────────

    #[test]
    fn property2_detects_too_narrow_predicate() {
        // sanity folds {cargo-check (code), vet (dep)} → needs code
        // permissions.  Narrow it to `rust` only — should fail.
        let workflow = WORKFLOW_FIXTURE.replace(
            "    if: needs.classify.outputs.code == 'true'\n    steps:\n      - run: cargo check",
            "    if: needs.classify.outputs.rust == 'true'\n    steps:\n      - run: cargo check",
        );
        let issues = validate_fixture(MANIFEST_FIXTURE, &workflow);
        let p2: Vec<&String> = issues.iter().filter(|s| s.contains("Property 2")).collect();
        assert_eq!(p2.len(), 1, "expected one P2 issue, got: {issues:?}");
        assert!(p2[0].contains("`sanity`"));
        assert!(p2[0].contains("too narrow"));
    }

    #[test]
    fn property2_accepts_wider_predicate() {
        // Widen fmt's `if:` from `rust` to `code` — wider is fine.
        let workflow = WORKFLOW_FIXTURE.replace(
            "    if: needs.classify.outputs.rust == 'true'",
            "    if: needs.classify.outputs.code == 'true'",
        );
        let issues = validate_fixture(MANIFEST_FIXTURE, &workflow);
        assert!(
            issues.iter().all(|s| !s.contains("Property 2")),
            "wider predicate should pass, got: {issues:?}"
        );
    }

    // ─── Property 3 mutation tests ────────────────────────────────

    #[test]
    fn property3_detects_missing_required_needs() {
        let workflow = WORKFLOW_FIXTURE.replace("      - sanity\n", "");
        let issues = validate_fixture(MANIFEST_FIXTURE, &workflow);
        assert!(
            issues
                .iter()
                .any(|s| s.contains("Property 3") && s.contains("required.needs:")),
            "expected P3 missing-from-required-needs, got: {issues:?}"
        );
    }

    #[test]
    fn property3_detects_missing_aggregator_entry() {
        let workflow =
            WORKFLOW_FIXTURE.replace("            [sanity]='${{ needs.sanity.result }}'\n", "");
        let issues = validate_fixture(MANIFEST_FIXTURE, &workflow);
        assert!(
            issues
                .iter()
                .any(|s| s.contains("Property 3") && s.contains("declare -A R=")),
            "expected P3 missing-from-aggregator, got: {issues:?}"
        );
    }

    // `property3_detects_missing_notify_failure_needs` was retired with
    // the Design C refactor for #209.  The notify-failure invariant
    // no longer applies because failure notification has been moved
    // out of pr-fast.yml into ci-failure-notify.yml (workflow_run-
    // triggered, post-auto-rerun-window), which doesn't carry a
    // `needs:` list of every gate.

    // ─── Property 4 mutation tests ────────────────────────────────

    #[test]
    fn property4_detects_renamed_required() {
        let workflow = WORKFLOW_FIXTURE.replace(
            "    name: PR Fast CI / required",
            "    name: PR Fast CI / Required", // capital R = drift
        );
        let issues = validate_fixture(MANIFEST_FIXTURE, &workflow);
        let p4: Vec<&String> = issues.iter().filter(|s| s.contains("Property 4")).collect();
        assert_eq!(p4.len(), 1, "expected one P4 issue, got: {issues:?}");
        assert!(p4[0].contains("PR Fast CI / required"));
    }

    #[test]
    fn property4_detects_missing_required_job() {
        // Remove the entire `required:` job block.  Property 1
        // fires for every gate (since they all fold INTO required's
        // needs check), but Property 4 also fires once for the
        // missing required job itself.
        let workflow = WORKFLOW_FIXTURE.split("  required:").next().unwrap();
        let issues = validate_fixture(MANIFEST_FIXTURE, workflow);
        assert!(
            issues
                .iter()
                .any(|s| s.contains("Property 4") && s.contains("missing")),
            "expected P4 missing-required-job, got: {issues:?}"
        );
    }

    // ─── Aggregator-extraction unit tests ─────────────────────────

    #[test]
    fn extract_aggregator_ids_handles_realistic_table() {
        let yaml = r#"
      - run: |
          declare -A R=(
            [file-size]='${{ needs.file-size.result }}'
            [gates-drift]='${{ needs.gates-drift.result }}'
            [hooks-drift]='${{ needs.hooks-drift.result }}'
          )
          for j in "${!R[@]}"; do
            echo "$j: ${R[$j]}"
          done
"#;
        let ids = extract_aggregator_ids(yaml).unwrap();
        assert_eq!(
            ids,
            ["file-size", "gates-drift", "hooks-drift"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect()
        );
    }

    #[test]
    fn extract_aggregator_ids_ignores_unrelated_brackets() {
        // `${{ needs.foo.result }}` patterns inside tables shouldn't
        // be matched as job-ids.  Lines outside the table shouldn't
        // be matched at all.
        let yaml = r#"
      - run: |
          echo "${{ matrix.os }}"
          declare -A R=(
            [valid-id]='something'
          )
          echo "${{ steps.x.outputs.y }}"
          [other-bracket]=ignored
"#;
        let ids = extract_aggregator_ids(yaml).unwrap();
        let expected: BTreeSet<String> = core::iter::once("valid-id".to_owned()).collect();
        assert_eq!(ids, expected);
    }
}
