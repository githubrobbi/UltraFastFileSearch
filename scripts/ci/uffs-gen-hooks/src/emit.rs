// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.
//
// Hook emission — turns a parsed `Manifest` into the bash text of
// `_lint_pre_push.sh`.
//
// Layout of the emitted file (top to bottom):
//
//   1. AUTO-GENERATED banner + manifest cross-reference.
//   2. Embedded preamble template — colors, change-classification, `spawn_bg` /
//      `run_seq` helpers.  Static; lives in `templates/preamble.sh`. Maintained
//      by hand because it is pure scaffolding (no gate-specific knowledge).
//   3. Generated dispatch block — Bucket 1 (spawn_bg) lines for every pre-push
//      gate with `bucket = "bg"`, then Bucket 2 (run_seq) lines wrapped in the
//      `if (( CODE_CHANGED ))` conditional for every gate with `bucket =
//      "seq"`.  This is the bit the manifest drives.
//   4. Embedded footer template — bucket reaping, result reporting,
//      optional-tool hint, failure dump.  Static; lives in
//      `templates/footer.sh`.
//
// Per-gate special cases are hardcoded (not parameterised by the
// manifest) so the generator stays small and reviewable.  The
// `gates.toml` fields drive the *decision* of which pattern to
// emit; the *templates* themselves live here.

use crate::manifest::{Gate, Manifest};

/// Tools the generator treats as "always present" — no install check
/// guards are emitted around gates that use these tools.  Adding a
/// new tool to the workspace baseline (e.g. via `just install-dev-tools`)
/// requires extending this list and updating the workspace tooling
/// docs in `CONTRIBUTING.md` simultaneously.
const ASSUMED_TOOLS: &[&str] = &["cargo", "bash", "cargo-nextest", "cargo-deny"];

/// Embedded scaffolding for `_lint_pre_push.sh` — colors,
/// change-classification, `spawn_bg` / `run_seq` helpers.  Pure bash;
/// no per-gate knowledge.
const PREAMBLE_PRE_PUSH: &str = include_str!("../templates/preamble.sh");
/// Embedded scaffolding emitted after `_lint_pre_push.sh`'s dispatch
/// section — bucket reaping, result reporting, optional-tool hint,
/// failure dump.  Pure bash; no per-gate knowledge.
const FOOTER_PRE_PUSH: &str = include_str!("../templates/footer.sh");

/// Embedded scaffolding for `_lint_fast.sh` — colors, staged-file
/// inventory, `has_staged_*` helpers, `spawn` helper.  Pure bash; no
/// per-gate knowledge.
const PREAMBLE_PRE_COMMIT: &str = include_str!("../templates/preamble_fast.sh");
/// Embedded scaffolding emitted after `_lint_fast.sh`'s dispatch
/// section — wait loop, per-job report, optional-tool hint, failure
/// dump.  Pure bash; no per-gate knowledge.
const FOOTER_PRE_COMMIT: &str = include_str!("../templates/footer_fast.sh");

/// Generation target.  One variant per emitted hook file.  Adding a
/// new target means adding a variant here, the matching `render_*`
/// function, and a `templates/preamble_*.sh` + `templates/footer_*.sh`
/// pair.  The `EmitTarget::render` dispatch keeps the rest of the
/// crate target-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmitTarget {
    /// `_lint_pre_push.sh` — the workspace pre-push gate (Phase 2).
    PrePush,
    /// `_lint_fast.sh` — the workspace pre-commit gate (Phase 3a).
    PreCommit,
}

impl EmitTarget {
    /// Render the full bash file as a single owned `String`.
    pub(crate) fn render(self, manifest: &Manifest) -> String {
        match self {
            Self::PrePush => render_pre_push(manifest),
            Self::PreCommit => render_pre_commit(manifest),
        }
    }

    /// Default on-disk path for this target's emitted hook.
    pub(crate) const fn default_output_path(self) -> &'static str {
        match self {
            Self::PrePush => "scripts/hooks/_lint_pre_push.sh",
            Self::PreCommit => "scripts/hooks/_lint_fast.sh",
        }
    }

    /// Manifest-tier name for this target.  Used to filter
    /// `[[gate]]` entries via `Manifest::gates_for_tier`.
    pub(crate) const fn tier(self) -> &'static str {
        match self {
            Self::PrePush => "pre-push",
            Self::PreCommit => "pre-commit",
        }
    }
}

/// Render the complete `_lint_pre_push.sh` file: AUTO-GENERATED
/// banner, embedded preamble, generated dispatch, embedded footer.
fn render_pre_push(manifest: &Manifest) -> String {
    let mut out = String::with_capacity(16 * 1024);
    out.push_str(banner_pre_push());
    out.push_str(PREAMBLE_PRE_PUSH);
    out.push_str(&render_dispatch(manifest));
    out.push_str(FOOTER_PRE_PUSH);
    out
}

/// Render the complete `_lint_fast.sh` file: AUTO-GENERATED banner,
/// embedded preamble, generated dispatch, embedded footer.
fn render_pre_commit(manifest: &Manifest) -> String {
    let mut out = String::with_capacity(8 * 1024);
    out.push_str(banner_pre_commit());
    out.push_str(PREAMBLE_PRE_COMMIT);
    out.push_str(&render_dispatch_fast(manifest));
    out.push_str(FOOTER_PRE_COMMIT);
    out
}

/// Top-of-file banner emitted ahead of the embedded `_lint_pre_push.sh`
/// preamble.  Carries the AUTO-GENERATED notice + a quick-link to the
/// manifest and the regen recipe so a contributor opening the file in
/// their editor knows exactly where to make changes.
// REUSE-IgnoreStart -- the literal `SPDX-License-Identifier:` text
// in the returned bash banner is part of the GENERATED hook's
// header, not this Rust file's REUSE metadata.  Without this
// directive `reuse lint` parses the embedded `MPL-2.0\n\` as if it
// were the SPDX expression for `emit.rs` itself and rejects it.
const fn banner_pre_push() -> &'static str {
    "#!/usr/bin/env bash\n\
     # SPDX-License-Identifier: MPL-2.0\n\
     # Copyright (c) 2025-2026 SKY, LLC.\n\
     #\n\
     # AUTO-GENERATED by `scripts/ci/uffs-gen-hooks` from `scripts/ci/gates.toml`.\n\
     # MANUAL EDITS WILL BE OVERWRITTEN.\n\
     #\n\
     # To change a gate, edit the manifest and regenerate:\n\
     #     vim scripts/ci/gates.toml\n\
     #     just uffs-gen-hooks\n\
     #\n\
     # Plan: docs/architecture/gates-manifest-plan.md\n\
     #\n\
     # Workspace-wide two-bucket pre-push gate.  See the plan doc for\n\
     # bucket semantics, fail-fast ordering, and the full per-gate\n\
     # rationale (the `notes` field on each `[[gate]]` table in\n\
     # `gates.toml` carries the same documentation that used to live\n\
     # in this header before Phase 2 codegen).\n\
     \n"
}
// REUSE-IgnoreEnd

/// Top-of-file banner emitted ahead of the embedded `_lint_fast.sh`
/// preamble.  Sibling of [`banner_pre_push`]; shape mirrors it
/// exactly, only the regen recipe and the workflow-architecture
/// summary differ.
// REUSE-IgnoreStart -- same rationale as `banner_pre_push`.
const fn banner_pre_commit() -> &'static str {
    "#!/usr/bin/env bash\n\
     # SPDX-License-Identifier: MPL-2.0\n\
     # Copyright (c) 2025-2026 SKY, LLC.\n\
     #\n\
     # AUTO-GENERATED by `scripts/ci/uffs-gen-hooks` from `scripts/ci/gates.toml`.\n\
     # MANUAL EDITS WILL BE OVERWRITTEN.\n\
     #\n\
     # To change a gate, edit the manifest and regenerate:\n\
     #     vim scripts/ci/gates.toml\n\
     #     just gen-fast\n\
     #\n\
     # Plan: docs/architecture/gates-manifest-plan.md\n\
     #\n\
     # Staged-scoped parallel pre-commit gate.  See the plan doc for\n\
     # the routing rules and per-gate rationale (the `notes` field on\n\
     # each `[[gate]]` table in `gates.toml` carries the same\n\
     # documentation that used to live in this header before Phase 3a\n\
     # codegen).\n\
     \n"
}
// REUSE-IgnoreEnd

/// Generate the dispatch block: Bucket 1 `spawn_bg` lines for every
/// pre-push gate with `bucket = "bg"`, then Bucket 2 `run_seq` lines
/// wrapped in `if (( CODE_CHANGED ))` for every gate with
/// `bucket = "seq"`.  Per-gate special cases (commit-subjects, vet,
/// soft-skip-with-command-v) are dispatched in [`emit_bg`] /
/// [`emit_seq`].
fn render_dispatch(manifest: &Manifest) -> String {
    let gates = manifest.gates_for_tier("pre-push");
    let bg: Vec<&Gate> = gates
        .iter()
        .filter(|gate| gate.bucket.as_deref() == Some("bg"))
        .copied()
        .collect();
    let seq: Vec<&Gate> = gates
        .iter()
        .filter(|gate| gate.bucket.as_deref() == Some("seq"))
        .copied()
        .collect();

    let mut out = String::with_capacity(4 * 1024);
    out.push_str("# ── Dispatch (generated from gates.toml) ──────────────────────────────\n");

    out.push_str("# Bucket 1 — fire-and-forget.  Cheap, parallel; no cargo lock\n");
    out.push_str("# contention.  See gates.toml for the canonical gate set.\n");
    for gate in &bg {
        out.push_str(&emit_bg(gate));
    }

    if !seq.is_empty() {
        out.push('\n');
        out.push_str("# Bucket 2 — sequential, fail-fast.  Only runs when code\n");
        out.push_str("# changed (rust | dep | infra).  Pure-docs-only pushes skip\n");
        out.push_str("# the compile/test gate entirely.\n");
        out.push_str("if (( CODE_CHANGED )); then\n");
        for gate in &seq {
            out.push_str(&indent_block(&emit_seq(gate), 4));
        }
        out.push_str("fi\n");
    }

    out
}

/// Generate the dispatch block for `_lint_fast.sh`: staged-scoped
/// parallel `spawn` lines, one per pre-commit-tier gate.  Routing is
/// driven by gate id + `gate_when` + `hard` + `tool`; per-gate special
/// cases (fmt, taplo, vet-fmt) are hardcoded mirrors of the existing
/// hand-written hook so behavior is byte-identical at the spawn level.
///
/// Emission order mirrors `Manifest::gates_for_tier` (bucket-rank
/// then `order` then `id`).  All `rust_changed` gates other than
/// `fmt` are collapsed into a single `if has_staged_rs; then` block
/// (3 spawns instead of 3 separate guard blocks) to match the
/// existing hook's terse shape.
fn render_dispatch_fast(manifest: &Manifest) -> String {
    let gates = manifest.gates_for_tier("pre-commit");

    // Pre-collect the rust-staged group (lint-prod / lint-tests /
    // lint-ci, in manifest order).  `fmt` is excluded — it has a
    // wider predicate (`has_staged_rs || ! has_any_staged`) and is
    // emitted on its own.
    let rust_staged: Vec<&Gate> = gates
        .iter()
        .filter(|gate| gate.when == "rust_changed" && gate.id != "fmt")
        .copied()
        .collect();

    let mut out = String::with_capacity(2 * 1024);
    out.push_str("# ── Dispatch (generated from gates.toml) ──────────────────────────────\n");

    let mut emitted_rust_block = false;
    for gate in &gates {
        if gate.id == "fmt" {
            out.push_str(&emit_fast_fmt(gate));
            continue;
        }
        if gate.id == "taplo" {
            out.push_str(&emit_fast_taplo(gate));
            continue;
        }
        if gate.id == "vet-fmt" {
            out.push_str(&emit_fast_vet_fmt(gate));
            continue;
        }
        if gate.when == "rust_changed" {
            if !emitted_rust_block {
                out.push_str(&emit_fast_rust_staged_block(&rust_staged));
                emitted_rust_block = true;
            }
            continue;
        }
        out.push_str(&emit_fast_default(gate));
    }

    out
}

/// Default fast-emit shape: handles always-on hard gates (`file-size`)
/// and always-on soft-skip gates (`typos`, `reuse`).  Hard gates with
/// an assumed tool emit unconditionally; soft-skip gates with a
/// non-assumed tool wrap in a `command -v $tool` guard.
fn emit_fast_default(gate: &Gate) -> String {
    let cmd = format_command(&gate.command);
    let label = consumer_label_pre_commit(gate);
    if !gate.hard && !is_assumed(&gate.tool) {
        return format!(
            "\nif command -v {tool} >/dev/null 2>&1; then\n\
             {pad}spawn \"{label}\" {cmd}\n\
             fi\n",
            tool = gate.tool,
            label = label,
            cmd = cmd,
            pad = "    ",
        );
    }
    format!("\nspawn \"{label}\" {cmd}\n")
}

/// Fast-emit for `fmt` — the only pre-commit gate whose predicate is
/// "rust-staged OR no-staged".  The "no-staged" branch keeps manual
/// `just lint-fast` runs on a clean worktree useful as a sanity pass
/// (otherwise the entire dispatch would no-op).
fn emit_fast_fmt(gate: &Gate) -> String {
    let cmd = format_command(&gate.command);
    let label = consumer_label_pre_commit(gate);
    format!(
        "\nif has_staged_rs || ! has_any_staged; then\n\
         {pad}spawn \"{label}\" {cmd}\n\
         fi\n",
        label = label,
        cmd = cmd,
        pad = "    ",
    )
}

/// Fast-emit for the `rust_changed`-tier gates other than `fmt`.
/// Collapses the trio (lint-prod / lint-tests / lint-ci, in manifest
/// order) into a single `if has_staged_rs; then` block — three
/// `spawn` lines instead of three separate guard blocks, matching
/// the existing hook's terse shape.  An empty input yields an empty
/// string (no leading newline) so the caller can treat it inline.
fn emit_fast_rust_staged_block(gates: &[&Gate]) -> String {
    use core::fmt::Write as _;
    if gates.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(256);
    out.push_str("\nif has_staged_rs; then\n");
    for gate in gates {
        let cmd = format_command(&gate.command);
        let label = consumer_label_pre_commit(gate);
        // Writes to a `String` are infallible — discard the
        // `Result<(), fmt::Error>` so the call type-checks under
        // `must_use` without an `expect("...")` that would never
        // fire.
        _ = writeln!(out, "    spawn \"{label}\" {cmd}");
    }
    out.push_str("fi\n");
    out
}

/// Fast-emit for `taplo` — the only pre-commit gate whose command
/// embeds the `{{STAGED_TOML}}` placeholder (resolved via a bash
/// command-substitution over `$STAGED_TOML_NONVET`).  The placeholder
/// must NOT leak into the emitted bash; it is rewritten here into
/// the literal `bash -c` invocation the existing hook uses.
fn emit_fast_taplo(gate: &Gate) -> String {
    let label = consumer_label_pre_commit(gate);
    format!(
        "\nif has_staged_toml_nonvet && command -v {tool} >/dev/null 2>&1; then\n\
         {pad}# shellcheck disable=SC2086\n\
         {pad}spawn \"{label}\" bash -c \"taplo fmt --check $(printf '%s ' $STAGED_TOML_NONVET)\"\n\
         fi\n",
        tool = gate.tool,
        label = label,
        pad = "    ",
    )
}

/// Fast-emit for `vet-fmt` — supply-chain TOML staged AND `cargo-vet`
/// installed.  The `command -v cargo-vet` guard is at the dispatch
/// level (not the optional-tool footer) because at pre-commit a
/// missing `cargo-vet` is a soft-skip; the upstream pre-push `vet`
/// gate is the hard backstop.
fn emit_fast_vet_fmt(gate: &Gate) -> String {
    let cmd = format_command(&gate.command);
    let label = consumer_label_pre_commit(gate);
    format!(
        "\nif has_staged_vet && command -v cargo-vet >/dev/null 2>&1; then\n\
         {pad}spawn \"{label}\" {cmd}\n\
         fi\n",
        label = label,
        cmd = cmd,
        pad = "    ",
    )
}

/// Resolve the consumer-side label for a gate at the pre-commit tier.
/// Honors the per-tier `consumer_names` override (e.g. `fmt` →
/// `fmt-check`) and falls back to the gate id when no override is
/// set.  Sibling of [`consumer_label`].
fn consumer_label_pre_commit(gate: &Gate) -> &str {
    gate.consumer_names
        .get("pre-commit")
        .map_or(gate.id.as_str(), String::as_str)
}

/// Bucket 1 emission for a single gate.
///
/// Special cases (in order of precedence):
///   1. `commit-subjects` — multi-line `bash -c` reading `COMMIT_RANGES`.
///   2. `cargo-vet` + `gate_when="dep_changed"` + `hard=true` — emit the
///      `DEP_CHANGED` gate WITH a missing-tool hard-fail and install hint.
///      Closes the PR #43 loophole.
///   3. `hard=false` + non-assumed tool — silent `command -v` guard.
///   4. Default — unconditional `spawn_bg`.
///
/// Gates whose `gate_when` equals one of `rust_changed` /
/// `infra_changed` / `code_changed` are still emitted unconditionally
/// at Bucket-1 today (matching the pre-Phase-2 hand-written hook):
/// they are cheap enough that running them on a pure-docs push is
/// cheaper than evaluating a guard.  Phase 3 may add explicit
/// per-class guards if the runtime budget changes.
fn emit_bg(gate: &Gate) -> String {
    if gate
        .command
        .iter()
        .any(|arg| arg.contains("{{COMMIT_RANGES}}"))
    {
        return emit_commit_subjects(gate);
    }

    if gate.tool == "cargo-vet" && gate.when == "dep_changed" && gate.hard {
        return emit_vet(gate);
    }

    let cmd = format_command(&gate.command);
    let label = consumer_label(gate);
    if !gate.hard && !is_assumed(&gate.tool) {
        return format!(
            "command -v {tool} >/dev/null 2>&1 && spawn_bg \"{label}\" {cmd}\n",
            tool = gate.tool,
            label = label,
            cmd = cmd,
        );
    }

    format!("spawn_bg \"{label}\" {cmd}\n")
}

/// Bucket 2 emission.  Already inside `if (( CODE_CHANGED ))` so the
/// outer rust/code conditionals are implied; an inner `dep_changed`
/// guard is emitted explicitly because `dep_changed` is *strictly
/// stronger* than `code_changed`.
fn emit_seq(gate: &Gate) -> String {
    let cmd = format_command(&gate.command);
    let label = consumer_label(gate);

    if !gate.hard && !is_assumed(&gate.tool) {
        return format!(
            "if command -v {tool} >/dev/null 2>&1; then\n\
             {pad}run_seq \"{label}\" {cmd}\n\
             fi\n",
            tool = gate.tool,
            label = label,
            cmd = cmd,
            pad = "    ",
        );
    }

    if gate.when == "dep_changed" {
        return format!(
            "if (( DEP_CHANGED )); then\n\
             {pad}run_seq \"{label}\" {cmd}\n\
             fi\n",
            label = label,
            cmd = cmd,
            pad = "    ",
        );
    }

    format!("run_seq \"{label}\" {cmd}\n")
}

/// Hardcoded multi-line bash for `commit-subjects` — the only gate
/// whose command embeds `{{COMMIT_RANGES}}` (the iterated stdin
/// captured during change-classification).  Phase 3 may generalise
/// this if a second template variable enters the manifest.
fn emit_commit_subjects(gate: &Gate) -> String {
    format!(
        "spawn_bg \"{id}\" bash -c '\n\
         {pad}set -euo pipefail\n\
         {pad}[[ -z \"${{COMMIT_RANGES// /}}\" ]] && exit 0\n\
         {pad}while IFS= read -r range; do\n\
         {pad}{pad}[[ -z \"$range\" ]] && continue\n\
         {pad}{pad}bash scripts/ci/check_commit_subjects.sh range \"$range\"\n\
         {pad}done <<< \"$COMMIT_RANGES\"\n\
         '\n",
        id = gate.id,
        pad = "    ",
    )
}

/// Hardcoded `vet` block — the only hard=true Bucket-1 gate that
/// uses a non-assumed tool with an install hint.  Closes PR #43's
/// CI-only-checked loophole: missing `cargo-vet` on a `dep_changed`
/// push aborts before the rest of the hook runs.
fn emit_vet(gate: &Gate) -> String {
    let cmd = format_command(&gate.command);
    let label = consumer_label(gate);
    format!(
        "if (( DEP_CHANGED )); then\n\
         {pad}if ! command -v {tool} >/dev/null 2>&1; then\n\
         {pad}{pad}printf '%s\u{274c} {tool} required (Cargo.{{toml,lock}} or supply-chain/ changed)%s\\n' \"$C_RED\" \"$C_RESET\" >&2\n\
         {pad}{pad}printf '   %sinstall: %scargo install {tool} --locked%s\\n' \"$C_YELLOW\" \"$C_CYAN\" \"$C_RESET\" >&2\n\
         {pad}{pad}printf '   %sor run:  %sjust install-dev-tools%s\\n'           \"$C_YELLOW\" \"$C_CYAN\" \"$C_RESET\" >&2\n\
         {pad}{pad}exit 2\n\
         {pad}fi\n\
         {pad}spawn_bg \"{label}\" {cmd}\n\
         fi\n",
        tool = gate.tool,
        label = label,
        cmd = cmd,
        pad = "    ",
    )
}

/// Resolve the consumer-side label for a gate at the pre-push tier.
/// Honors the per-tier `consumer_names` override (legacy naming) and
/// falls back to the gate id when no override is set.  This keeps
/// the emitted hook byte-equivalent to the pre-Phase-2 hand-written
/// names (`test-build` gate id → `tests` legacy label, etc.).
fn consumer_label(gate: &Gate) -> &str {
    gate.consumer_names
        .get("pre-push")
        .map_or(gate.id.as_str(), String::as_str)
}

/// Predicate: does the workspace's tooling baseline guarantee that
/// `tool` is on every contributor's PATH?  See `ASSUMED_TOOLS` above.
fn is_assumed(tool: &str) -> bool {
    ASSUMED_TOOLS.contains(&tool)
}

/// Render a TOML command-array as a bash command line.  Tokens are
/// emitted as-is (unquoted) when they are pure shell-safe identifiers
/// or option-style flags, and double-quoted otherwise.  Matches the
/// idiom used in the pre-Phase-2 hand-written hook.
fn format_command(cmd: &[String]) -> String {
    cmd.iter()
        .map(|tok| shell_quote(tok))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Quote a single bash token.  Tokens that are pure shell-safe
/// identifiers, paths, flags, or numeric values pass through
/// unquoted; everything else gets single-quoted with embedded
/// single-quotes escaped via the `'\''` idiom.
fn shell_quote(token: &str) -> String {
    if token.is_empty() {
        return "''".to_owned();
    }
    let safe = token.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '/' | '.' | ',' | '=' | ':')
    });
    if safe {
        return token.to_owned();
    }
    let escaped = token.replace('\'', r"'\''");
    format!("'{escaped}'")
}

/// Indent every non-empty line of `text` by `n` spaces.  Used to
/// nest Bucket-2 emission inside the `if (( CODE_CHANGED ))` block.
fn indent_block(text: &str, n: usize) -> String {
    let pad = " ".repeat(n);
    let mut out = String::with_capacity(text.len() + n * text.lines().count());
    for line in text.lines() {
        if !line.is_empty() {
            out.push_str(&pad);
            out.push_str(line);
        }
        out.push('\n');
    }
    if !text.ends_with('\n') {
        // Preserve trailing-newline absence so the caller's join
        // semantics are not broken.
        out.pop();
    }
    out
}

#[cfg(test)]
#[expect(
    clippy::min_ident_chars,
    clippy::string_slice,
    reason = "test code uses idiomatic short bindings + ASCII-only fixture substring slicing; \
              failures panic with full context via assert!/assert_eq! (issue #212)"
)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;

    fn parse(toml_text: &str) -> Manifest {
        let m: Manifest = toml::from_str(toml_text).unwrap();
        m.validate().unwrap();
        m
    }

    #[test]
    fn dispatch_emits_bg_then_seq() {
        let m = parse(
            r#"
[[gate]]
id="fmt"
label="x"
command=["cargo","fmt","--all","--","--check"]
tiers=["pre-push"]
gate_when="always"
hard=true
tool="cargo"
bucket="bg"
order=10

[[gate]]
id="lint-ci"
label="x"
command=["just","lint-ci"]
tiers=["pre-push"]
gate_when="rust_changed"
hard=true
tool="cargo"
bucket="seq"
order=20
"#,
        );
        let out = render_dispatch(&m);
        let bg_pos = out.find("spawn_bg \"fmt\"").unwrap();
        let seq_pos = out.find("run_seq \"lint-ci\"").unwrap();
        assert!(bg_pos < seq_pos, "Bucket 1 must be emitted before Bucket 2");
        assert!(out.contains("if (( CODE_CHANGED )); then"));
    }

    #[test]
    fn commit_subjects_uses_special_template() {
        let m = parse(
            r#"
[[gate]]
id="commit-subjects"
label="x"
command=["bash","scripts/ci/check_commit_subjects.sh","range","{{COMMIT_RANGES}}"]
tiers=["pre-push"]
gate_when="always"
hard=true
tool="bash"
bucket="bg"
"#,
        );
        let out = render_dispatch(&m);
        assert!(out.contains("bash -c '"));
        assert!(out.contains("while IFS= read -r range"));
        assert!(out.contains("$COMMIT_RANGES"));
        // The literal `{{COMMIT_RANGES}}` placeholder must NOT leak
        // into the emitted bash.
        assert!(!out.contains("{{COMMIT_RANGES}}"));
    }

    #[test]
    fn vet_emits_dep_changed_hard_fail_block() {
        let m = parse(
            r#"
[[gate]]
id="vet"
label="x"
command=["cargo","vet","check","--locked"]
tiers=["pre-push"]
gate_when="dep_changed"
hard=true
tool="cargo-vet"
bucket="bg"
"#,
        );
        let out = render_dispatch(&m);
        assert!(out.contains("if (( DEP_CHANGED )); then"));
        assert!(out.contains("if ! command -v cargo-vet >/dev/null 2>&1"));
        assert!(out.contains("install: "));
        assert!(out.contains("just install-dev-tools"));
    }

    #[test]
    fn soft_skip_emits_command_v_guard() {
        let m = parse(
            r#"
[[gate]]
id="typos"
label="x"
command=["typos","."]
tiers=["pre-push"]
gate_when="always"
hard=false
tool="typos"
bucket="bg"
"#,
        );
        let out = render_dispatch(&m);
        assert!(out.contains("command -v typos >/dev/null 2>&1 && spawn_bg \"typos\""));
    }

    #[test]
    fn deny_in_seq_wraps_in_dep_changed() {
        let m = parse(
            r#"
[[gate]]
id="deny"
label="x"
command=["cargo","deny","check"]
tiers=["pre-push"]
gate_when="dep_changed"
hard=true
tool="cargo-deny"
bucket="seq"
"#,
        );
        let out = render_dispatch(&m);
        // Bucket 2 emission is indented inside `if (( CODE_CHANGED ))`.
        assert!(out.contains("    if (( DEP_CHANGED )); then"));
        assert!(out.contains("run_seq \"deny\""));
    }

    #[test]
    fn windows_lint_in_seq_wraps_in_command_v() {
        let m = parse(
            r#"
[[gate]]
id="lint-ci-windows"
label="x"
command=["just","lint-ci-windows"]
tiers=["pre-push"]
gate_when="code_changed"
hard=false
tool="cargo-xwin"
bucket="seq"
"#,
        );
        let out = render_dispatch(&m);
        assert!(out.contains("if command -v cargo-xwin >/dev/null 2>&1; then"));
        assert!(out.contains("run_seq \"lint-ci-windows\""));
    }

    #[test]
    fn shell_quote_passes_safe_tokens() {
        assert_eq!(shell_quote("cargo"), "cargo");
        assert_eq!(shell_quote("--locked"), "--locked");
        assert_eq!(shell_quote("scripts/ci/x.sh"), "scripts/ci/x.sh");
        assert_eq!(shell_quote(""), "''");
        // Spaces force quoting.
        assert_eq!(shell_quote("a b"), "'a b'");
        // Embedded single quote escaped.
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn consumer_names_override_is_honoured_in_emission() {
        // Mirrors the real `test-build` gate which carries
        // `consumer_names = { "pre-push" = "tests" }` for legacy
        // compatibility with the pre-Phase-2 hook.  The emitted
        // run_seq label MUST use the override; otherwise the drift
        // detector flags the regenerated hook as out of sync with
        // the manifest.
        let m = parse(
            r#"
[[gate]]
id="test-build"
label="x"
command=["cargo","nextest","run","--no-run"]
tiers=["pre-push"]
gate_when="code_changed"
hard=true
tool="cargo-nextest"
bucket="seq"
consumer_names = { "pre-push" = "tests" }
"#,
        );
        let out = render_dispatch(&m);
        assert!(
            out.contains("run_seq \"tests\""),
            "expected `run_seq \"tests\"` (override), got:\n{out}"
        );
        assert!(
            !out.contains("run_seq \"test-build\""),
            "raw gate id leaked into output despite override:\n{out}"
        );
    }

    #[test]
    fn missing_consumer_override_falls_back_to_gate_id() {
        // No override for the active tier → emit gate id verbatim.
        let m = parse(
            r#"
[[gate]]
id="cargo-check"
label="x"
command=["cargo","check"]
tiers=["pre-push"]
gate_when="code_changed"
hard=true
tool="cargo"
bucket="seq"
consumer_names = { "pr-fast" = "sanity" }
"#,
        );
        let out = render_dispatch(&m);
        // pre-push has no override; emit canonical id.
        assert!(out.contains("run_seq \"cargo-check\""));
        // The pr-fast override must NOT leak into the pre-push emit.
        assert!(!out.contains("run_seq \"sanity\""));
    }

    #[test]
    fn full_render_is_idempotent() {
        // Plan §4.4 idempotency contract: running the generator
        // twice in a row must produce no diff on the second run.
        // This covers the entire pipeline (banner + preamble +
        // dispatch + footer), not just the dispatch slice.
        let m = parse(
            r#"
[[gate]]
id="fmt"
label="x"
command=["cargo","fmt","--all","--","--check"]
tiers=["pre-push"]
gate_when="always"
hard=true
tool="cargo"
bucket="bg"
order=10
"#,
        );
        let r1 = EmitTarget::PrePush.render(&m);
        let r2 = EmitTarget::PrePush.render(&m);
        assert_eq!(r1, r2, "non-deterministic render");
        // Banner + preamble + dispatch + footer must all be present.
        assert!(r1.starts_with("#!/usr/bin/env bash\n"));
        assert!(r1.contains("AUTO-GENERATED"));
        assert!(r1.contains("spawn_bg \"fmt\""));
        assert!(r1.contains("BG_FAILED"));
    }

    /// Fixture covering all four pre-commit dispatch shapes:
    ///   * `fmt`      \u2014 special rust-or-no-staged predicate
    ///   * `file-size`\u2014 always-on hard
    ///   * `lint-prod`/`lint-tests`/`lint-ci` \u2014 rust-staged group
    ///   * `taplo`    \u2014 special toml-nonvet + cmd-v + bash-c
    ///   * `vet-fmt`  \u2014 special vet-staged + cargo-vet cmd-v
    ///   * `typos`    \u2014 always-on soft-skip
    ///
    /// Mirrors the real manifest's pre-commit-tier subset closely
    /// enough that the generated dispatch matches the on-disk
    /// `_lint_fast.sh` shape; intentionally trimmed (no `reuse`,
    /// no `lint-tests` re-stub) so the assertion message stays
    /// readable when something drifts.
    fn pre_commit_fixture() -> Manifest {
        parse(
            r#"
[[gate]]
id        = "fmt"
label     = "x"
command   = ["cargo", "fmt", "--all", "--", "--check"]
tiers     = ["pre-commit"]
gate_when = "rust_changed"
hard      = true
tool      = "cargo"
bucket    = "bg"
order     = 10
consumer_names = { "pre-commit" = "fmt-check" }

[[gate]]
id        = "file-size"
label     = "x"
command   = ["bash", "scripts/ci/check_file_size_policy.sh"]
tiers     = ["pre-commit"]
gate_when = "always"
hard      = true
tool      = "bash"
bucket    = "bg"
order     = 20

[[gate]]
id        = "typos"
label     = "x"
command   = ["typos", "."]
tiers     = ["pre-commit"]
gate_when = "always"
hard      = false
tool      = "typos"
bucket    = "bg"
order     = 50

[[gate]]
id        = "taplo"
label     = "x"
command   = ["taplo", "fmt", "--check", "{{STAGED_TOML}}"]
tiers     = ["pre-commit"]
gate_when = "always"
hard      = false
tool      = "taplo"
bucket    = "bg"
order     = 70

[[gate]]
id        = "vet-fmt"
label     = "x"
command   = ["bash", "scripts/hooks/_check_vet_fmt.sh"]
tiers     = ["pre-commit"]
gate_when = "always"
hard      = true
tool      = "bash"
bucket    = "bg"
order     = 80

[[gate]]
id        = "lint-prod"
label     = "x"
command   = ["just", "lint-prod"]
tiers     = ["pre-commit"]
gate_when = "rust_changed"
hard      = true
tool      = "cargo"
bucket    = "seq"
order     = 30

[[gate]]
id        = "lint-tests"
label     = "x"
command   = ["just", "lint-tests"]
tiers     = ["pre-commit"]
gate_when = "rust_changed"
hard      = true
tool      = "cargo"
bucket    = "seq"
order     = 40

[[gate]]
id        = "lint-ci"
label     = "x"
command   = ["just", "lint-ci"]
tiers     = ["pre-commit"]
gate_when = "rust_changed"
hard      = true
tool      = "cargo"
bucket    = "seq"
order     = 20
"#,
        )
    }

    #[test]
    fn fast_dispatch_emits_all_six_shapes() {
        let out = render_dispatch_fast(&pre_commit_fixture());

        // Special-case: fmt's rust-or-no-staged predicate.
        assert!(
            out.contains("if has_staged_rs || ! has_any_staged; then"),
            "missing fmt predicate:\n{out}"
        );
        assert!(out.contains("spawn \"fmt-check\" cargo fmt --all -- --check"));

        // Always-on hard: file-size unconditional.
        assert!(out.contains("\nspawn \"file-size\" bash scripts/ci/check_file_size_policy.sh\n"));

        // Always-on soft-skip: typos via command -v.
        assert!(out.contains("if command -v typos >/dev/null 2>&1; then"));
        assert!(out.contains("spawn \"typos\" typos ."));

        // Special-case: taplo (toml-nonvet + cmd-v + bash-c with cmd sub).
        assert!(
            out.contains("if has_staged_toml_nonvet && command -v taplo >/dev/null 2>&1; then")
        );
        assert!(out.contains("# shellcheck disable=SC2086"));
        assert!(out.contains("$STAGED_TOML_NONVET"));
        // The literal `{{STAGED_TOML}}` placeholder must NOT leak.
        assert!(
            !out.contains("{{STAGED_TOML}}"),
            "{{{{STAGED_TOML}}}} placeholder leaked into emitted bash:\n{out}"
        );

        // Special-case: vet-fmt.
        assert!(out.contains("if has_staged_vet && command -v cargo-vet >/dev/null 2>&1; then"));
        assert!(out.contains("spawn \"vet-fmt\" bash scripts/hooks/_check_vet_fmt.sh"));

        // Rust-staged group: ONE block, three spawns inside, manifest-order sorted.
        assert!(
            out.contains("if has_staged_rs; then"),
            "missing rust-staged guard:\n{out}"
        );
        let block_start = out.find("if has_staged_rs; then").unwrap();
        let block_end = out[block_start..].find("\nfi\n").unwrap() + block_start;
        let block = &out[block_start..block_end];
        // lint-ci(order=20) before lint-prod(30) before lint-tests(40).
        let p_ci = block.find("spawn \"lint-ci\"").unwrap();
        let p_prod = block.find("spawn \"lint-prod\"").unwrap();
        let p_tests = block.find("spawn \"lint-tests\"").unwrap();
        assert!(
            p_ci < p_prod && p_prod < p_tests,
            "rust-staged order wrong:\n{block}"
        );
    }

    #[test]
    fn fast_dispatch_emits_exactly_one_rust_staged_block() {
        // Regression-guard for the "emit once at first member" logic
        // in render_dispatch_fast: the rust-staged trio must
        // collapse into ONE `if has_staged_rs; then` block, not
        // three.  A buggy refactor (e.g. losing the
        // `emitted_rust_block` flag) would emit three blocks.
        let out = render_dispatch_fast(&pre_commit_fixture());
        let count = out.matches("\nif has_staged_rs; then\n").count();
        assert_eq!(
            count, 1,
            "expected exactly one rust-staged block, found {count}:\n{out}"
        );
    }

    #[test]
    fn fast_dispatch_honours_pre_commit_consumer_override() {
        // `fmt` carries `consumer_names = { "pre-commit" = "fmt-check" }`
        // for legacy compatibility with the pre-Phase-3a hook.  The
        // emitted spawn label MUST use the override; otherwise a
        // pre-commit run would show up as `fmt` (gate id) rather
        // than `fmt-check` (legacy label) and contributors would
        // see a confusing rename.
        let out = render_dispatch_fast(&pre_commit_fixture());
        assert!(
            out.contains("spawn \"fmt-check\""),
            "expected `spawn \"fmt-check\"` (override), got:\n{out}"
        );
        assert!(
            !out.contains("spawn \"fmt\" cargo"),
            "raw gate id leaked into output despite override:\n{out}"
        );
    }

    #[test]
    fn fast_emit_fmt_spans_no_staged_branch() {
        // Property: the `fmt` predicate is a strict superset of
        // every other rust_changed gate.  A no-staged sanity run
        // (manual `just lint-fast` on a clean worktree) MUST still
        // run rustfmt; otherwise the recipe becomes a no-op when
        // the user has nothing staged.
        let m = parse(
            r#"
[[gate]]
id        = "fmt"
label     = "x"
command   = ["cargo", "fmt", "--all", "--", "--check"]
tiers     = ["pre-commit"]
gate_when = "rust_changed"
hard      = true
tool      = "cargo"
bucket    = "bg"
"#,
        );
        let out = render_dispatch_fast(&m);
        assert!(
            out.contains("|| ! has_any_staged"),
            "fmt missing no-staged branch:\n{out}"
        );
    }

    #[test]
    fn fast_emit_rust_staged_block_is_empty_when_no_rust_gates() {
        // Edge case: a pre-commit-tier manifest with NO
        // rust_changed gates other than `fmt` must NOT emit a
        // dangling `if has_staged_rs; then ... fi` block — the
        // generator drops it entirely.
        let m = parse(
            r#"
[[gate]]
id        = "fmt"
label     = "x"
command   = ["cargo", "fmt"]
tiers     = ["pre-commit"]
gate_when = "rust_changed"
hard      = true
tool      = "cargo"
bucket    = "bg"

[[gate]]
id        = "file-size"
label     = "x"
command   = ["bash", "x.sh"]
tiers     = ["pre-commit"]
gate_when = "always"
hard      = true
tool      = "bash"
bucket    = "bg"
"#,
        );
        let out = render_dispatch_fast(&m);
        // fmt has its own block; the trio block must NOT exist.
        assert!(out.contains("if has_staged_rs || ! has_any_staged; then"));
        assert!(
            !out.contains("\nif has_staged_rs; then\n"),
            "empty rust-staged block leaked:\n{out}"
        );
    }

    #[test]
    fn pre_commit_render_is_idempotent() {
        // Plan §4.4 idempotency contract: running the generator
        // twice in a row must produce no diff on the second run.
        // Regression-guard against any non-deterministic ordering
        // in the gates_for_tier sort or the dispatch emission.
        let m = pre_commit_fixture();
        let r1 = EmitTarget::PreCommit.render(&m);
        let r2 = EmitTarget::PreCommit.render(&m);
        assert_eq!(r1, r2, "non-deterministic pre-commit render");

        // Banner + preamble + dispatch + footer must all be present.
        assert!(r1.starts_with("#!/usr/bin/env bash\n"));
        assert!(r1.contains("AUTO-GENERATED"));
        assert!(r1.contains("just gen-fast"));
        assert!(r1.contains("set -euo pipefail"));
        assert!(r1.contains("has_staged_rs"));
        assert!(r1.contains("# ── Dispatch (generated from gates.toml)"));
        assert!(r1.contains("Optional-tool hint"));
        assert!(r1.contains("✅ lint-fast passed"));
    }

    #[test]
    fn pre_commit_and_pre_push_render_distinct_files() {
        // Sanity: the same manifest emits two materially different
        // bash files.  Catches a refactor that accidentally aliases
        // the two render paths (e.g. forgetting to switch templates
        // when adding a new EmitTarget variant).
        let m = pre_commit_fixture();
        let pre_push = EmitTarget::PrePush.render(&m);
        let pre_commit = EmitTarget::PreCommit.render(&m);
        assert_ne!(pre_push, pre_commit);
        // Pre-push uses spawn_bg; pre-commit uses spawn.
        assert!(pre_commit.contains("\nspawn \"file-size\""));
        // Pre-commit must NOT contain the pre-push two-bucket plumbing.
        assert!(
            !pre_commit.contains("BG_PIDS"),
            "pre-push plumbing leaked into pre-commit:\n{pre_commit}"
        );
        assert!(!pre_commit.contains("SEQ_RESULTS"));
        assert!(!pre_commit.contains("CODE_CHANGED"));
    }

    #[test]
    fn emit_target_default_output_paths_are_distinct() {
        // The drift-detector wires uffs-gen-hooks --check against the
        // matching on-disk path for each target; if both targets
        // accidentally pointed at the same file the second --check
        // would always succeed by reading whatever the first wrote.
        assert_ne!(
            EmitTarget::PrePush.default_output_path(),
            EmitTarget::PreCommit.default_output_path()
        );
        assert_eq!(EmitTarget::PrePush.tier(), "pre-push");
        assert_eq!(EmitTarget::PreCommit.tier(), "pre-commit");
    }

    #[test]
    fn render_is_deterministic() {
        let toml_text = r#"
[[gate]]
id="b"
label="x"
command=["true"]
tiers=["pre-push"]
gate_when="always"
hard=true
tool="bash"
bucket="bg"
order=20

[[gate]]
id="a"
label="x"
command=["true"]
tiers=["pre-push"]
gate_when="always"
hard=true
tool="bash"
bucket="bg"
order=10
"#;
        let m1 = parse(toml_text);
        let m2 = parse(toml_text);
        let r1 = render_dispatch(&m1);
        let r2 = render_dispatch(&m2);
        assert_eq!(r1, r2);
        // `a` (order=10) before `b` (order=20).
        let pa = r1.find("spawn_bg \"a\"").unwrap();
        let pb = r1.find("spawn_bg \"b\"").unwrap();
        assert!(pa < pb);
    }
}
