// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Minimal subset of the gate-manifest schema needed by the workflow
//! structural validator.
//!
//! # Why duplicate (a subset of) `scripts/ci/uffs-gen-hooks/src/manifest.rs`?
//!
//! `uffs-gen-hooks` and `uffs-gen-workflow` both read `scripts/ci/gates.toml`.
//! A purist refactor would extract a shared `uffs-gates-schema`
//! library crate that both binaries depend on.  We deliberately
//! deferred that for this PR for two reasons:
//!
//! 1. The cross-tool dependency graph is currently zero-coupled (uffs-gen-hooks
//!    doesn't depend on uffs-gen-workflow and vice versa); a shared crate would
//!    introduce a new internal dependency just to hold ~30 lines of struct
//!    definitions.
//! 2. Serde's default `deserialize_unknown_fields = false` means additive
//!    changes to the manifest schema (new fields in `[[gate]]`) are silently
//!    absorbed by both deserializers — the common drift mode (uffs-gen-hooks
//!    gains a field, uffs-gen-workflow stays blissfully unaware) is safe.
//!    Removal of a field uffs-gen-workflow uses fails noisily on first parse;
//!    loud regression beats silent corruption every time.
//!
//! When this assumption breaks (e.g. both generators need a complex
//! shared validator), promote this module + the uffs-gen-hooks one into a
//! `scripts/ci/gates-schema` library.  Until then: keep it simple.
//!
//! # Schema subset
//!
//! uffs-gen-workflow only needs:
//! - `id` — gate's stable identifier
//! - `label` — human-readable string (used in error messages)
//! - `tiers` — to filter to `pr-fast`
//! - `gate_when` — the change-classification predicate, mapped to the
//!   workflow's `if:` field
//! - `consumer_names` — per-tier job-id override (e.g. `lint-ci` appears as job
//!   `clippy` in pr-fast.yml)
//!
//! Every other field (`command`, `bucket`, `notes`, etc.) is
//! ignored via `serde(default)` on the surrounding struct + serde's
//! permissive mode for unknown TOML keys.

use alloc::collections::BTreeMap;

use anyhow::{Context as _, Result};
use serde::Deserialize;

/// Top-level gate-manifest document.
///
/// Mirrors the shape of `scripts/ci/gates.toml`'s `[[gate]]` array
/// but only carries the fields the workflow validator inspects.
#[derive(Debug, Deserialize)]
pub(crate) struct Manifest {
    /// One entry per `[[gate]]` block in the TOML.  Renamed to
    /// `gates` on the Rust side for readability.
    #[serde(rename = "gate")]
    pub(crate) gates: Vec<Gate>,
}

/// A single gate entry — minimal subset.  Field ordering matches the
/// canonical schema in `uffs-gen-hooks/src/manifest.rs::Gate` so a
/// reviewer comparing the two structs sees them line up.
#[derive(Debug, Deserialize)]
pub(crate) struct Gate {
    /// Stable kebab-case identifier; primary key for cross-file
    /// references.
    pub(crate) id: String,

    /// Human-readable name surfaced in error messages.  Free-form;
    /// not enforced by any property.
    pub(crate) label: String,

    /// Set of tiers this gate runs in.  The workflow validator
    /// filters to entries that include `"pr-fast"`.
    pub(crate) tiers: Vec<String>,

    /// Change-classification predicate.  Mapped to the workflow's
    /// `if:` field by the validator's `PermissiveSet::from_gate_when`
    /// (see plan §4.2 Property 2 for the predicate-alignment lattice).
    ///
    /// The TOML field is named `gate_when` (matching the canonical
    /// schema doc) but renamed to `when` on the Rust side to avoid
    /// `clippy::struct_field_names` triggering on the `gate_` prefix.
    /// `serde(rename = "gate_when")` bridges the two.
    #[serde(rename = "gate_when")]
    pub(crate) when: String,

    /// Per-tier job-id override.  Multiple gates can map to the
    /// same workflow job (e.g. `rustdoc` + `doc-tests` both have
    /// `consumer_names = { "pr-fast" = "docs" }`).  The validator
    /// resolves each gate to a job-id via this map; if a tier is
    /// not present, the gate id is used directly.
    #[serde(default)]
    pub(crate) consumer_names: BTreeMap<String, String>,
}

/// Parse the manifest TOML.  Errors propagate with file-level context.
pub(crate) fn parse(text: &str) -> Result<Manifest> {
    toml::from_str::<Manifest>(text).context("deserialize gates.toml")
}

impl Manifest {
    /// Iterator over gates that include `"pr-fast"` in their `tiers`
    /// list, in manifest order.  Order matters for deterministic
    /// error reporting.
    pub(crate) fn pr_fast_gates(&self) -> impl Iterator<Item = &Gate> {
        self.gates
            .iter()
            .filter(|gate| gate.tiers.iter().any(|tier| tier == "pr-fast"))
    }
}

impl Gate {
    /// Resolve the workflow job-id this gate maps to in the pr-fast
    /// tier.  Falls back to the gate id when no override is set.
    pub(crate) fn pr_fast_job_id(&self) -> &str {
        self.consumer_names
            .get("pr-fast")
            .map_or(self.id.as_str(), String::as_str)
    }
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

    /// Minimal fixture mirroring two real gates from `gates.toml`:
    /// one with no `consumer_names` (`fmt`) and one with a pr-fast
    /// override (`lint-ci` → `clippy`).
    const FIXTURE: &str = r#"
[[gate]]
id = "fmt"
label = "cargo fmt --check"
tiers = ["pre-commit", "pre-push", "pr-fast"]
gate_when = "rust_changed"

[[gate]]
id = "lint-ci"
label = "CI-mirror clippy"
tiers = ["pre-commit", "pre-push", "pr-fast"]
gate_when = "rust_changed"
consumer_names = { "pr-fast" = "clippy" }

[[gate]]
id = "lint-prod"
label = "ultra-strict production clippy"
tiers = ["pre-commit", "pre-push"]
gate_when = "rust_changed"
"#;

    #[test]
    fn parses_minimal_manifest() {
        let manifest = parse(FIXTURE).unwrap();
        assert_eq!(manifest.gates.len(), 3);
        assert_eq!(manifest.gates[0].id, "fmt");
        assert_eq!(manifest.gates[1].when, "rust_changed");
    }

    #[test]
    fn pr_fast_gates_filters_correctly() {
        let manifest = parse(FIXTURE).unwrap();
        let ids: Vec<&str> = manifest.pr_fast_gates().map(|g| g.id.as_str()).collect();
        assert_eq!(ids, vec!["fmt", "lint-ci"]); // lint-prod excluded
    }

    #[test]
    fn pr_fast_job_id_falls_back_to_gate_id() {
        let manifest = parse(FIXTURE).unwrap();
        assert_eq!(manifest.gates[0].pr_fast_job_id(), "fmt");
    }

    #[test]
    fn pr_fast_job_id_honors_consumer_override() {
        let manifest = parse(FIXTURE).unwrap();
        // lint-ci has consumer_names = { "pr-fast" = "clippy" }
        assert_eq!(manifest.gates[1].pr_fast_job_id(), "clippy");
    }

    #[test]
    fn gate_when_field_rename_round_trips() {
        // Regression-guards the `serde(rename = "gate_when")` directive
        // — if someone removed it, this would fail to parse.
        let manifest = parse(FIXTURE).unwrap();
        assert!(manifest.gates.iter().all(|g| g.when == "rust_changed"));
    }

    #[test]
    fn unknown_fields_are_silently_ignored() {
        // Documents the schema-coupling design decision: uffs-gen-hooks
        // can add new manifest fields without breaking uffs-gen-workflow.
        let with_extra = r#"
[[gate]]
id = "fmt"
label = "fmt"
tiers = ["pr-fast"]
gate_when = "rust_changed"
command = ["cargo", "fmt"]
bucket = "bg"
order = 10
notes = "irrelevant for the validator"
"#;
        let manifest = parse(with_extra).unwrap();
        assert_eq!(manifest.gates.len(), 1);
    }

    #[test]
    fn missing_required_field_fails_noisily() {
        // The other half of the design: removal of a field this
        // validator depends on fails parse, not silently corrupts.
        let bad = r#"
[[gate]]
id = "fmt"
tiers = ["pr-fast"]
gate_when = "rust_changed"
"#;
        // Missing `label`.
        let err = parse(bad).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("label"),
            "expected error to mention missing field 'label', got: {msg}"
        );
    }
}
