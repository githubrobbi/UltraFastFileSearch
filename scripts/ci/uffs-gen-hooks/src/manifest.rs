// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.
//
// Manifest schema model — mirrors `scripts/ci/gates.toml`.
//
// The `gates.toml` file is the canonical source-of-truth for the
// workspace's PR-time gate set.  See `docs/architecture/gates-manifest-plan.md`
// §3 for the schema spec.  This module does the bare minimum:
//
//   1. Deserialise the file via `serde` + `toml::from_str`.
//   2. Validate the invariants the codegen relies on (no duplicate ids, every
//      `tiers` entry valid, every `bucket` valid, every `gate_when` valid).
//
// The validator is intentionally lightweight — it only catches schema
// bugs that would crash the generator.  Cross-consumer drift detection
// is the Phase-1 `check_gates_drift.sh` script's job and stays
// authoritative there.

use alloc::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::Deserialize;

/// Top-level manifest layout.  TOML key names match `gates.toml`
/// verbatim so `[[gate]]` arrays of tables deserialise straight in.
#[derive(Debug, Deserialize)]
pub(crate) struct Manifest {
    /// Optional `[manifest]` header table — version + plan-doc
    /// cross-reference.  Surfaced by `--verbose`; Phase 3 will also
    /// gate generator compatibility on `version`.
    #[serde(default, rename = "manifest")]
    pub(crate) header: ManifestMeta,

    /// Optional `[classification]` table — the regex stack used by
    /// `_lint_pre_push.sh` for `RUST_CHANGED` / `DEP_CHANGED` /
    /// `INFRA_CHANGED` detection.  Phase 2 keeps the regexes in the
    /// embedded `preamble` template (§5 of the plan: codegen is
    /// layered, not big-bang); the generator only echoes them via
    /// `--verbose` so contributors can confirm what they parsed.
    /// Phase 3 will wire them through to the preamble.
    #[serde(default)]
    pub(crate) classification: Option<Classification>,

    /// Every `[[gate]]` table in the manifest.  TOML preserves
    /// declaration order on parse; the generator re-sorts before
    /// emit (see `emit.rs`) so the output is deterministic regardless
    /// of declaration order.
    #[serde(default)]
    pub(crate) gate: Vec<Gate>,
}

/// `[manifest]` header table.  Captures the manifest's own version
/// and the cross-reference back to the plan doc.  All fields are
/// optional so an early manifest snapshot without the header still
/// parses cleanly.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct ManifestMeta {
    /// Schema version.  Surfaced by `--verbose`; Phase 3 will also
    /// reject manifests whose major bumps this past the generator's
    /// known maximum.
    #[serde(default)]
    pub(crate) version: u32,
    /// Path (relative to repo root) of the architecture plan
    /// document this manifest implements.  Surfaced by `--verbose`
    /// and (Phase 2.x) the regen banner.
    #[serde(default)]
    pub(crate) plan_doc: Option<String>,
}

/// `[classification]` is a free-form map of class-name → regex pattern.
/// Phase 2 does not consume these for emission (the regexes are
/// embedded literally in `templates/preamble.sh`); the generator only
/// echoes them via `--verbose`.  Phase 3 will tie the two together so
/// the manifest's regex stack drives the preamble's classification
/// block.
#[derive(Debug, Deserialize)]
pub(crate) struct Classification {
    /// Class-name → regex map.  Class names are short identifiers like
    /// `rust`, `dep`, `infra`, `docs`; the values are anchored regex
    /// patterns matched against `git diff --name-only` output.
    #[serde(flatten)]
    pub(crate) patterns: BTreeMap<String, String>,
}

/// One `[[gate]]` table.  Field names match `gates.toml` modulo the
/// `when` ↔ `gate_when` rename: the TOML schema spells the trigger
/// classifier `gate_when` (matching the Phase-1 plan doc and the
/// drift-detector script), while the Rust field uses the unprefixed
/// `when` to keep the struct-name-prefix lint clean.  `serde(rename)`
/// bridges the two without requiring the manifest authors to know
/// the Rust spelling.
#[derive(Debug, Deserialize)]
pub(crate) struct Gate {
    /// Kebab-case canonical identifier — the `spawn_bg` / `run_seq`
    /// label emitted into the hook (modulo `consumer_names` overrides).
    pub(crate) id: String,
    /// Human-readable name surfaced by drift-detector messages and
    /// (future) the regen banner.
    pub(crate) label: String,
    /// Command line as a TOML array.  Token zero is the executable;
    /// subsequent tokens are arguments.  See `emit::format_command`
    /// for the bash-quoting rules.
    pub(crate) command: Vec<String>,
    /// Subset of `{pre-commit, pre-push, pr-fast, tier-2}`.  The
    /// generator filters by membership.
    pub(crate) tiers: Vec<String>,
    /// One of `always` / `rust_changed` / `dep_changed` /
    /// `infra_changed` / `code_changed`.  Drives Bucket-2 inner
    /// guards and (future) Bucket-1 conditional emission.
    /// TOML schema name: `gate_when` (preserved via `serde(rename)`).
    #[serde(rename = "gate_when")]
    pub(crate) when: String,
    /// `true` for hard-fail gates; `false` for soft-skip with
    /// command-v guard.
    pub(crate) hard: bool,
    /// Missing-tool detection key.  Members of `ASSUMED_TOOLS` are
    /// emitted unguarded; everything else gets a `command -v`
    /// guard (or hard-fail-with-hint for `cargo-vet`).
    pub(crate) tool: String,
    /// Documentary expected runtime in seconds.  Surfaced by
    /// `--verbose`; Phase 2.x's manifest viewer + Tier-2 budget
    /// pre-flight will also read it.
    #[serde(default)]
    pub(crate) expected_runtime_secs: u32,
    /// Bucket assignment — `"bg"` (Bucket 1, fire-and-forget) or
    /// `"seq"` (Bucket 2, sequential / fail-fast).  Optional because
    /// it is only meaningful when the gate participates in the
    /// `pre-push` tier; pr-fast-only gates (e.g. the full `tests` run
    /// that is too slow for pre-push) legitimately omit it.
    #[serde(default)]
    pub(crate) bucket: Option<String>,
    /// Within-bucket ordering hint.  Lower fires first.  Ties
    /// resolve by lexicographic id ordering (see
    /// `Manifest::gates_for_tier`).
    #[serde(default)]
    pub(crate) order: i32,
    /// Per-tier consumer-name override.  When set, the generator
    /// emits the override (e.g. `tests`) as the `spawn_bg` /
    /// `run_seq` label instead of the canonical gate id (e.g.
    /// `test-build`).  Read by `emit::consumer_label`; the same
    /// field shape is consumed by `check_gates_drift.sh` so the
    /// two stay aligned.
    #[serde(default)]
    pub(crate) consumer_names: BTreeMap<String, String>,
    /// Free-form Markdown.  The first non-blank line is surfaced by
    /// `--verbose`.  Phase 2.x will also emit it as a comment block
    /// in the rendered hook (see `emit.rs::render_dispatch`).
    #[serde(default)]
    pub(crate) notes: String,
}

impl Manifest {
    /// Lightweight invariant validation — only the things the codegen
    /// itself depends on.  Cross-consumer drift is Phase 1's job.
    pub(crate) fn validate(&self) -> Result<()> {
        // No duplicate ids.
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for gate in &self.gate {
            ensure!(
                seen.insert(gate.id.as_str()),
                "duplicate gate id `{}` in manifest",
                gate.id
            );
        }

        // Every gate has a non-empty command and a known bucket / when.
        for gate in &self.gate {
            ensure!(
                !gate.command.is_empty(),
                "gate `{}` has an empty command",
                gate.id
            );
            // `bucket` is required IFF the gate participates in pre-push.
            // pr-fast-only gates (e.g. full `tests`) legitimately omit it.
            let in_pre_push = gate.tiers.iter().any(|tier_name| tier_name == "pre-push");
            match (in_pre_push, gate.bucket.as_deref()) {
                (true, Some(bucket)) => ensure!(
                    matches!(bucket, "bg" | "seq"),
                    "gate `{}` has unknown bucket `{}` (want `bg` or `seq`)",
                    gate.id,
                    bucket
                ),
                (true, None) => anyhow::bail!(
                    "gate `{}` is in the `pre-push` tier but has no `bucket` field",
                    gate.id
                ),
                (false, Some(bucket)) => ensure!(
                    matches!(bucket, "bg" | "seq"),
                    "gate `{}` has unknown bucket `{}` (want `bg` or `seq`)",
                    gate.id,
                    bucket
                ),
                (false, None) => {}
            }
            ensure!(
                matches!(
                    gate.when.as_str(),
                    "always" | "rust_changed" | "dep_changed" | "infra_changed" | "code_changed"
                ),
                "gate `{}` has unknown gate_when `{}`",
                gate.id,
                gate.when
            );
            for tier in &gate.tiers {
                ensure!(
                    matches!(
                        tier.as_str(),
                        "pre-commit" | "pre-push" | "pr-fast" | "tier-2"
                    ),
                    "gate `{}` has unknown tier `{}`",
                    gate.id,
                    tier
                );
            }
        }
        Ok(())
    }

    /// Filter gates by tier membership — the codegen iterates this
    /// once per emit.  Sorted by `(bucket-as-defined-order, order)` so
    /// Bucket-1 `spawn_bg` lines come before Bucket-2 `run_seq` lines
    /// and within each bucket gates fire in the order the plan declares.
    pub(crate) fn gates_for_tier<'a>(&'a self, tier: &str) -> Vec<&'a Gate> {
        let mut out: Vec<&'a Gate> = self
            .gate
            .iter()
            .filter(|gate| gate.tiers.iter().any(|tier_name| tier_name == tier))
            .collect();
        out.sort_by_key(|gate| {
            (
                bucket_rank(gate.bucket.as_deref().unwrap_or("")),
                gate.order,
                gate.id.as_str().to_owned(),
            )
        });
        out
    }
}

/// Sort key for bucket strings: Bucket 1 (`bg`) before Bucket 2
/// (`seq`); pr-fast-only gates without a bucket sink to the bottom.
fn bucket_rank(bucket: &str) -> u8 {
    match bucket {
        "bg" => 0,
        "seq" => 1,
        _ => 99,
    }
}

#[cfg(test)]
#[expect(
    clippy::min_ident_chars,
    clippy::indexing_slicing,
    clippy::get_unwrap,
    reason = "test code uses idiomatic short bindings + positional indexing + .get().unwrap() \
              against fixed-shape fixtures; failures panic with adequate context (issue #212)"
)]
mod tests {
    use super::*;

    fn fixture() -> &'static str {
        // Minimal valid manifest covering one bg + one seq gate.
        r#"
[manifest]
version = 1
plan_doc = "docs/architecture/gates-manifest-plan.md"

[classification]
rust  = "\\.rs$"
dep   = "^(.*Cargo\\.toml$|Cargo\\.lock$|supply-chain/)"
infra = "^(\\.github/|scripts/|)"

[[gate]]
id        = "fmt"
label     = "cargo fmt --check"
command   = ["cargo", "fmt", "--all", "--", "--check"]
tiers     = ["pre-push"]
gate_when = "always"
hard      = true
tool      = "cargo"
bucket    = "bg"
order     = 10
notes     = "Always-on rustfmt."

[[gate]]
id        = "lint-ci"
label     = "CI-mirror clippy"
command   = ["just", "lint-ci"]
tiers     = ["pre-commit", "pre-push"]
gate_when = "rust_changed"
hard      = true
tool      = "cargo"
bucket    = "seq"
order     = 20
"#
    }

    #[test]
    fn parses_minimal_manifest() {
        let m: Manifest = toml::from_str(fixture()).unwrap();
        assert_eq!(m.gate.len(), 2);
        assert_eq!(m.header.version, 1);
    }

    #[test]
    fn validates_clean() {
        let m: Manifest = toml::from_str(fixture()).unwrap();
        m.validate().unwrap();
    }

    #[test]
    fn rejects_duplicate_ids() {
        let dup = format!(
            "{}\n[[gate]]\nid=\"fmt\"\nlabel=\"x\"\ncommand=[\"true\"]\ntiers=[\"pre-push\"]\ngate_when=\"always\"\nhard=true\ntool=\"bash\"\nbucket=\"bg\"\n",
            fixture()
        );
        let m: Manifest = toml::from_str(&dup).unwrap();
        let err = m.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate gate id"));
    }

    #[test]
    fn rejects_bad_bucket() {
        let bad = fixture().replace("bucket    = \"bg\"", "bucket    = \"nope\"");
        let m: Manifest = toml::from_str(&bad).unwrap();
        let err = m.validate().unwrap_err();
        assert!(err.to_string().contains("unknown bucket"));
    }

    #[test]
    fn gates_for_tier_filters_and_sorts() {
        let m: Manifest = toml::from_str(fixture()).unwrap();
        let gates = m.gates_for_tier("pre-push");
        assert_eq!(gates.len(), 2);
        // Bucket bg before seq.
        assert_eq!(gates[0].id, "fmt");
        assert_eq!(gates[1].id, "lint-ci");
    }

    #[test]
    fn gates_for_tier_empty_for_unknown_tier() {
        let m: Manifest = toml::from_str(fixture()).unwrap();
        assert!(m.gates_for_tier("nonexistent").is_empty());
    }

    #[test]
    fn gate_when_field_rename_round_trips() {
        // The TOML schema spells the trigger classifier `gate_when`
        // (matching the Phase-1 plan doc and the drift detector); the
        // Rust field is named `when`.  Regression-guard for the
        // `serde(rename = "gate_when")` directive.
        let m: Manifest = toml::from_str(fixture()).unwrap();
        let fmt_gate = m.gate.iter().find(|g| g.id == "fmt").unwrap();
        assert_eq!(fmt_gate.when, "always");
        let clippy_gate = m.gate.iter().find(|g| g.id == "lint-ci").unwrap();
        assert_eq!(clippy_gate.when, "rust_changed");
    }

    #[test]
    fn classification_block_parses() {
        // Regression-guard for the free-form `Classification`
        // shape: any class-name → regex map should round-trip
        // cleanly into the BTreeMap.  The verbose-dump path reads
        // these keys; if parsing breaks, --verbose breaks silently.
        let m: Manifest = toml::from_str(fixture()).unwrap();
        let cls = m.classification.as_ref().expect("classification block");
        assert_eq!(cls.patterns.len(), 3);
        assert_eq!(cls.patterns.get("rust").unwrap(), r"\.rs$");
        assert!(cls.patterns.contains_key("dep"));
        assert!(cls.patterns.contains_key("infra"));
    }

    #[test]
    fn consumer_names_round_trips() {
        let toml_text = r#"
[[gate]]
id        = "test-build"
label     = "x"
command   = ["true"]
tiers     = ["pre-push"]
gate_when = "code_changed"
hard      = true
tool      = "cargo-nextest"
bucket    = "seq"
consumer_names = { "pre-push" = "tests", "pr-fast" = "test-build" }
"#;
        let m: Manifest = toml::from_str(toml_text).unwrap();
        m.validate().unwrap();
        let g = &m.gate[0];
        assert_eq!(g.consumer_names.len(), 2);
        assert_eq!(g.consumer_names.get("pre-push").unwrap(), "tests");
        assert_eq!(g.consumer_names.get("pr-fast").unwrap(), "test-build");
    }

    #[test]
    fn pr_fast_only_gate_may_omit_bucket() {
        // Mirrors the real `tests` gate (the full nextest run): it
        // is too slow for pre-push and lives only in the pr-fast
        // tier, where `bucket` is meaningless.  The validator must
        // accept this.
        let toml_text = r#"
[[gate]]
id        = "tests"
label     = "full nextest"
command   = ["cargo", "nextest", "run"]
tiers     = ["pr-fast"]
gate_when = "code_changed"
hard      = true
tool      = "cargo-nextest"
"#;
        let m: Manifest = toml::from_str(toml_text).unwrap();
        m.validate().unwrap();
        assert!(m.gate[0].bucket.is_none());
    }

    #[test]
    fn pre_push_gate_without_bucket_is_rejected() {
        // Counterpart to the above: if a gate claims the pre-push
        // tier, `bucket` becomes mandatory because emit.rs needs to
        // know whether to spawn_bg or run_seq.
        let toml_text = r#"
[[gate]]
id        = "ghost"
label     = "x"
command   = ["true"]
tiers     = ["pre-push"]
gate_when = "always"
hard      = true
tool      = "bash"
"#;
        let m: Manifest = toml::from_str(toml_text).unwrap();
        let err = m.validate().unwrap_err();
        assert!(
            err.to_string().contains("no `bucket` field"),
            "expected bucket-required error, got: {err}"
        );
    }

    #[test]
    fn unknown_gate_when_is_rejected() {
        let bad = fixture().replace("gate_when = \"always\"", "gate_when = \"sometimes\"");
        let m: Manifest = toml::from_str(&bad).unwrap();
        let err = m.validate().unwrap_err();
        assert!(err.to_string().contains("unknown gate_when"));
    }

    #[test]
    fn unknown_tier_is_rejected() {
        let bad = fixture().replace("tiers     = [\"pre-push\"]", "tiers     = [\"banana\"]");
        let m: Manifest = toml::from_str(&bad).unwrap();
        let err = m.validate().unwrap_err();
        assert!(err.to_string().contains("unknown tier"));
    }
}
