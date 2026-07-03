#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025-2026 SKY, LLC.
#
# Phase 9 — Build scripts, macros, and code generation inventory for the
# UFFS workspace.
#
# Companion to:
#   - docs/dev/architecture/code_clean/phase_9_build_scripts_macros_codegen_implementation_plan.md
#   - scripts/dev/feature_dep_audit.sh   (Phase 8a — same shape, different
#     pattern set)
#   - scripts/dev/trait_generic_audit.sh (Phase 7a — same shape)
#   - scripts/dev/clone_alloc_audit.sh   (Phase 6a — same shape)
#
# Purpose
# -------
# Walk every workspace member and emit, **per crate**, the inventory the
# playbook §1013-1078 calls out:
#
#   * `build.rs` presence + LOC + target-gate shape + `cargo:` directives
#     emitted + env vars read at build-time.
#   * `proc-macro = true` declarations (currently 0 workspace-wide; the
#     audit script confirms the deliberate non-introduction).
#   * `macro_rules!` declarations — name, file, line, scope (`pub` /
#     `pub(crate)` / function-local), justification class per playbook
#     §1064 (syntax shaping / trait impl repetition / pattern capture).
#   * Codegen binaries — workspace-internal generator/validator binaries
#     under `scripts/ci/` (`uffs-gen-hooks`, `uffs-gen-workflow`, `uffs-manifest-audit`,
#     `ci-pipeline`) + their drift-detector wiring per `gates.toml`.
#   * Env-var consumption — every `env::var(…)` / `env!(…)` /
#     `option_env!(…)` use site, per env-var-name aggregation.
#   * `include_bytes!` / `include_str!` / `include!` use sites — small
#     leaf-data embedding (case-fold tables, embedded resources) vs
#     codegen-pipeline magic.
#
# Workspace-level inventory:
#   * Total `build.rs` count; per-crate gate (target_os / target_env /
#     etc) — proves each one is necessary per playbook §1041-1046.
#   * Total `proc-macro = true` count (expected: 0).
#   * Total `macro_rules!` count, grouped by crate.
#   * Codegen binary inventory cross-referenced against
#     `scripts/ci/gates.toml` drift detectors.
#   * Env-var registry — every distinct name, grouped by scope.
#
# Excludes (because the workspace's `clippy.toml` already relaxes lint
# posture inside these, and build/macro/codegen work is prod-only):
#
#   * `tests/`, `benches/`, `examples/` directories under any crate.
#   * Files named `tests.rs`, `*_tests.rs`, `*_test.rs`, `test_*.rs`.
#
# `build.rs` IS audited (it's the central artifact of this phase).
#
# Caveats (documented in the output preamble)
# -------------------------------------------
# 1. The `macro_rules!` parser uses ripgrep + a small line-by-line scan;
#    it captures the macro name from `macro_rules!\s+NAME` but does not
#    attempt to parse the macro body or measure its complexity.  Phase
#    9d's per-macro audit re-classifies each.
#
# 2. Env-var detection uses three regex shapes: `env::var\("…"\)`,
#    `env!\("…"\)`, `option_env!\("…"\)`.  Build-time envs read via the
#    `CARGO_CFG_*` family are captured but not deduped against `env!`
#    macros that read the same name.
#
# 3. The `proc-macro = true` check is a grep over each crate's
#    `Cargo.toml` `[lib]` table — true if the line is present anywhere
#    in the manifest (which is sufficient for a 0-result audit).
#
# Optional cargo cross-checks
# ---------------------------
# Pass `--with-cargo` to also run, in order:
#   * `cargo build --workspace --timings`                 (~30 s warm)
#   * `cargo expand` summary on the 6 `macro_rules!` sites (~5 s each)
#
# The default mode (no flag) is rg+awk only and runs in ~1 s.
#
# Usage
# -----
#   scripts/dev/build_codegen_audit.sh                   # fast (~1 s)
#   scripts/dev/build_codegen_audit.sh --with-cargo      # + cargo build --timings
#
# Output goes to stdout in Markdown.  Redirect to capture:
#
#   scripts/dev/build_codegen_audit.sh \
#     > docs/dev/baseline/2026-05-19/phase_9_build_baseline.md
#
# Exit codes
# ----------
#   0 — script ran to completion.  The *counts* of build.rs / macros /
#       env vars are information, not a failure signal.
#   1 — fatal scripting error (rg missing, repo root not detectable,
#       cargo invocation failed when `--with-cargo` was requested).

set -uo pipefail

WITH_CARGO=0
for arg in "$@"; do
    case "$arg" in
        --with-cargo) WITH_CARGO=1 ;;
        --help | -h)
            sed -n '1,90p' "$0"
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument '$arg' (expected --with-cargo | --help)" >&2
            exit 1
            ;;
    esac
done

# ── Locate workspace root ─────────────────────────────────────────────
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$ROOT" ]] || [[ ! -d "$ROOT/crates" ]]; then
    echo "ERROR: not inside the UFFS workspace (expected 'crates/' at git root)" >&2
    exit 1
fi
cd "$ROOT" || {
    echo "ERROR: cd to '$ROOT' failed" >&2
    exit 1
}

# ── Required tooling ──────────────────────────────────────────────────
if ! command -v rg >/dev/null 2>&1; then
    echo "ERROR: 'rg' (ripgrep) not found in PATH" >&2
    exit 1
fi
if [[ "$WITH_CARGO" -eq 1 ]] && ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: 'cargo' not found in PATH (required for --with-cargo)" >&2
    exit 1
fi

# ── Crate inventory ───────────────────────────────────────────────────
mapfile -t CRATES < <(
    find crates -mindepth 2 -maxdepth 2 -name Cargo.toml \
        | sed -E 's|^crates/([^/]+)/Cargo.toml$|\1|' \
        | sort
)
if [[ ${#CRATES[@]} -eq 0 ]]; then
    echo "ERROR: no crates discovered under crates/" >&2
    exit 1
fi

# Workspace-internal codegen binaries (under scripts/ci/, not crates/).
mapfile -t CODEGEN_BINS < <(
    find scripts/ci -mindepth 2 -maxdepth 2 -name Cargo.toml \
        | sed -E 's|^scripts/ci/([^/]+)/Cargo.toml$|\1|' \
        | sort
)
# Also include scripts/ci-pipeline (the release orchestrator).
if [[ -f "scripts/ci-pipeline/Cargo.toml" ]]; then
    CODEGEN_BINS+=("ci-pipeline")
fi

# ── rg filter (prod-only — but INCLUDING build.rs unlike phase-6/7/8) ─
RG_PROD_GLOBS=(
    -g '*.rs'
    -g '!tests/**'
    -g '!benches/**'
    -g '!examples/**'
    -g '!**/tests.rs'
    -g '!**/*_tests.rs'
    -g '!**/*_test.rs'
    -g '!**/test_*.rs'
)

# Count pattern occurrences across a directory.
count_pattern() {
    local dir="$1"
    local pattern="$2"
    local fixed="${3:-0}"
    local rg_flags=("${RG_PROD_GLOBS[@]}" --no-heading --no-filename --count-matches)
    if [[ "$fixed" -eq 1 ]]; then
        rg_flags+=(-F)
    fi
    rg "${rg_flags[@]}" "$pattern" "$dir" 2>/dev/null \
        | awk 'BEGIN{s=0} {s+=$1} END{print s+0}'
}

# Check whether a Cargo.toml declares `proc-macro = true`.  Returns
# "yes" or "no".
is_proc_macro_crate() {
    local toml="$1"
    if grep -q '^proc-macro[[:space:]]*=[[:space:]]*true' "$toml" 2>/dev/null; then
        echo "yes"
    else
        echo "no"
    fi
}

# Extract every `macro_rules! NAME` declaration in a directory.
# Output: "<rel-path>:<line>:<name>"
list_macro_rules() {
    local dir="$1"
    rg "${RG_PROD_GLOBS[@]}" \
        --no-heading -n -o \
        '\bmacro_rules!\s+[A-Za-z_][A-Za-z0-9_]*' \
        "$dir" 2>/dev/null \
        | sed -E 's|macro_rules!\s+||'
}

# Extract env-var names from a directory, filtering out matches that
# appear inside comments (lines whose first non-whitespace characters
# are `//`, `///`, or `*`).  Requires env-var names to be 2+ chars to
# avoid matching single-letter rustdoc placeholders like `X` in prose.
#
# Detection covers four shapes:
#   1. `env::var("NAME")`              — sync read
#   2. `env::var_os("NAME")`           — read-OsString (absence-checking idiom)
#   3. `env!("NAME")` / `option_env!("NAME")` — build-time literal
#   4. `const FOO: &str = "NAME";`     — const-indirection (read via
#      `env::var*(Self::FOO)` or `env::var*(FOO)` where the audit cannot
#      grep through the indirection itself).  Restricted to known
#      env-var prefixes (`UFFS_`, `RUST_`, `XDG_`, `CARGO_`) to avoid
#      flagging arbitrary string consts.
#
# Caveat: bare locals like `let foo = "UFFS_X"; env::var(foo);` are NOT
# detected.  No such pattern exists in the workspace as of 2026-05-19;
# audit re-runs flag the gap if it appears.
_extract_env_var_names() {
    local dir="$1"
    {
        rg "${RG_PROD_GLOBS[@]}" -N \
            '(?:std::)?env::var(?:_os)?\("[A-Z_][A-Z0-9_]+"\)' "$dir" 2>/dev/null
        rg "${RG_PROD_GLOBS[@]}" -N \
            '(?:env|option_env)!\("[A-Z_][A-Z0-9_]+"\)' "$dir" 2>/dev/null
        # Const-name indirection: a `const _: &str = "NAME";` declaration
        # whose value matches a known env-var prefix is treated as a
        # read site (the actual `env::var*(CONST)` call is non-literal
        # and unreachable by literal-arg regexes).
        rg "${RG_PROD_GLOBS[@]}" -N \
            'const [A-Z_][A-Z0-9_]+: ?&(?:'\''static )?str = "(?:UFFS_|RUST_|XDG_|CARGO_)[A-Z][A-Z0-9_]+"' \
            "$dir" 2>/dev/null
    } | grep -Ev '^[[:space:]]*(//|/\*|\*[[:space:]])' \
      | sed -nE 's|.*"([A-Z_][A-Z0-9_]+)".*|\1|p'
}

# Count distinct env-var names read in a directory.
count_env_vars() {
    _extract_env_var_names "$1" | sort -u | grep -c .
}

# List distinct env-var names workspace-wide, with each name reported
# once.
list_env_vars_workspace() {
    {
        _extract_env_var_names crates
        _extract_env_var_names scripts
    } | sort -u
}

# Count `include_bytes!` / `include_str!` / `include!` use sites.
# Filters out matches in `//`, `///`, `/*`, and ` * ` comment-prefix lines
# (which otherwise inflate the count when the macro name is mentioned in
# rustdoc prose).
count_includes() {
    local dir="$1"
    rg "${RG_PROD_GLOBS[@]}" --no-heading -N \
        '\b(include_bytes|include_str|include)!\(' "$dir" 2>/dev/null \
        | grep -Ev '^[^:]+:[[:space:]]*(//|/\*|\*[[:space:]])' \
        | wc -l | tr -d ' '
}

# Extract a `build.rs` summary: LOC, target gate shape, `cargo:`
# directive count, env vars read.
build_rs_summary() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        echo "absent"
        return
    fi
    local loc cargo_dirs envs gates
    loc=$(wc -l <"$path" | tr -d ' ')
    cargo_dirs=$(grep -c '^[[:space:]]*println!("cargo:' "$path" 2>/dev/null || echo 0)
    envs=$(rg -o 'env::var\("[A-Z_][A-Z0-9_]*"\)|env!\("[A-Z_][A-Z0-9_]*"\)' "$path" 2>/dev/null | wc -l | tr -d ' ')
    if grep -qE 'target_(os|env|family|arch)' "$path"; then
        gates="cfg-gated"
    else
        gates="unconditional"
    fi
    echo "${loc} LOC, ${cargo_dirs} cargo: directives, ${envs} env-var reads, ${gates}"
}

# ── Markdown preamble ─────────────────────────────────────────────────
SHA="$(git rev-parse HEAD)"
DATE_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat <<EOF
# Phase 9 — Build / macro / codegen / env-var baseline

**Captured:** ${DATE_UTC}
**SHA:** \`${SHA}\`
**Methodology:** \`scripts/dev/build_codegen_audit.sh\` — \`rg\`-based count
across each crate's \`src/\` tree plus \`build.rs\` plus the workspace
\`scripts/ci/\` and \`scripts/ci-pipeline/\` codegen binaries.  Excludes
\`tests/\`, \`benches/\`, \`examples/\`, and files matching \`tests.rs\` /
\`*_tests.rs\` / \`*_test.rs\` / \`test_*.rs\`.

**Companion plan:** \`docs/dev/architecture/code_clean/phase_9_build_scripts_macros_codegen_implementation_plan.md\` (local-only).
**Tracking issue:** [#298](https://github.com/skyllc-ai/UltraFastFileSearch/issues/298).

---

## §1 — Per-crate inventory

| Crate | \`build.rs\` | proc-macro | \`macro_rules!\` | env-var reads | \`include_*!\` |
|---|---|:---:|---:|---:|---:|
EOF

for c in "${CRATES[@]}"; do
    crate_dir="crates/$c"
    toml="$crate_dir/Cargo.toml"
    build_rs_path="$crate_dir/build.rs"

    if [[ -f "$build_rs_path" ]]; then
        build_summary="$(build_rs_summary "$build_rs_path")"
    else
        build_summary="—"
    fi

    proc_macro=$(is_proc_macro_crate "$toml")

    macro_count=$(list_macro_rules "$crate_dir" | wc -l | tr -d ' ')
    env_count=$(count_env_vars "$crate_dir")
    include_count=$(count_includes "$crate_dir")

    printf "| \`%s\` | %s | %s | %d | %d | %d |\n" \
        "$c" "$build_summary" "$proc_macro" \
        "$macro_count" "$env_count" "$include_count"
done

# Workspace totals.
total_build=$(find crates -maxdepth 2 -name build.rs | wc -l | tr -d ' ')
total_proc_macro=0
for c in "${CRATES[@]}"; do
    [[ "$(is_proc_macro_crate "crates/$c/Cargo.toml")" == "yes" ]] && total_proc_macro=$((total_proc_macro + 1))
done
total_macros=0
for c in "${CRATES[@]}"; do
    n=$(list_macro_rules "crates/$c" | wc -l | tr -d ' ')
    total_macros=$((total_macros + n))
done
total_env_distinct=$(list_env_vars_workspace | wc -l | tr -d ' ')
total_includes=0
for c in "${CRATES[@]}"; do
    n=$(count_includes "crates/$c")
    total_includes=$((total_includes + n))
done

cat <<EOF
| **Workspace total** | **${total_build} file(s)** | **${total_proc_macro}** | **${total_macros}** | **${total_env_distinct} distinct** | **${total_includes}** |

---

## §2 — \`build.rs\` detail

EOF

if [[ "$total_build" -eq 0 ]]; then
    echo "_No \`build.rs\` files found in any crate._"
else
    for c in "${CRATES[@]}"; do
        path="crates/$c/build.rs"
        if [[ -f "$path" ]]; then
            cat <<EOF
### \`$path\`

- **LOC:** $(wc -l <"$path" | tr -d ' ')
- **Target gate(s):** $(rg -o 'target_(os|env|family|arch)\s*==\s*"[a-z0-9_-]+"' "$path" 2>/dev/null | sort -u | paste -sd ', ' - || echo "(none — unconditional)")
- **\`cargo:\` directives emitted:**
$(grep -E '^[[:space:]]*println!\("cargo:' "$path" 2>/dev/null \
    | sed -E 's|.*println!\("(cargo:[^"]*)".*|  - `\1`|' \
    | sort -u || echo "  - (none)")
- **Env vars read at build time:**
$({ rg -o 'env::var\("[A-Z_][A-Z0-9_]*"\)' "$path" 2>/dev/null \
    | sed -E 's|.*"([^"]+)".*|  - `\1` (env::var)|'
    rg -o 'env!\("[A-Z_][A-Z0-9_]*"\)' "$path" 2>/dev/null \
    | sed -E 's|.*"([^"]+)".*|  - `\1` (env!)|'; } | sort -u || echo "  - (none)")
- **\`#[allow]\` / \`#[expect]\` annotations:**
$(rg -n '#!\[(allow|expect)\(' "$path" 2>/dev/null \
    | sed -E 's|^([0-9]+):|  - line \1: |' || echo "  - (none)")

EOF
        fi
    done
fi

cat <<EOF
---

## §3 — Proc-macro crates

EOF

if [[ "$total_proc_macro" -eq 0 ]]; then
    cat <<EOF
**0 proc-macro crates** workspace-wide.  No \`proc-macro = true\` in any
\`Cargo.toml\` \`[lib]\` section.

This is the deliberate workspace posture (see \`build_codegen_policy.md\`
§3 — to be created in Phase 9f).  Introducing a proc-macro crate
requires:

1. A unanimous-review decision recorded in \`build_codegen_policy.md\`'s
   decisions log.
2. A compile-time impact analysis (proc-macro crates add compile cost
   workspace-wide because every consumer must link the proc-macro at
   compile time).
3. A boundary contract: which crates may depend on the proc-macro
   crate, and what's the API surface.
EOF
else
    echo "**${total_proc_macro} proc-macro crate(s) found** — listed below:"
    for c in "${CRATES[@]}"; do
        if [[ "$(is_proc_macro_crate "crates/$c/Cargo.toml")" == "yes" ]]; then
            echo "- \`crates/$c\`"
        fi
    done
fi

cat <<EOF

---

## §4 — Declarative \`macro_rules!\` inventory

EOF

if [[ "$total_macros" -eq 0 ]]; then
    echo "_No \`macro_rules!\` declarations found in any crate._"
else
    cat <<EOF
| Crate | Macro name | File:line |
|---|---|---|
EOF
    for c in "${CRATES[@]}"; do
        list_macro_rules "crates/$c" | while IFS=: read -r path line name; do
            printf "| \`%s\` | \`%s\` | \`%s:%s\` |\n" "$c" "$name" "$path" "$line"
        done
    done
fi

cat <<EOF

Per-macro justification class per playbook §1064 (syntax shaping /
trait impl repetition / pattern capture) is captured in
\`docs/dev/baseline/<date>/phase_9_macro_audit_findings.md\` by Phase 9d.

---

## §5 — Codegen binaries (workspace-internal)

EOF

if [[ ${#CODEGEN_BINS[@]} -eq 0 ]]; then
    echo "_No codegen binaries found under \`scripts/ci/\` or \`scripts/ci-pipeline/\`._"
else
    cat <<EOF
| Binary | Purpose | Drift detector |
|---|---|---|
EOF
    for bin in "${CODEGEN_BINS[@]}"; do
        if [[ "$bin" == "ci-pipeline" ]]; then
            bin_path="scripts/ci-pipeline"
            purpose="Release-automation orchestrator (\`just ship\` flow per \`release-automation-plan.md\`)"
            drift="N/A — orchestrator, not an emitter; no idempotency contract"
        elif [[ -f "scripts/ci/$bin/src/main.rs" || -f "scripts/ci/$bin/src/lib.rs" ]]; then
            bin_path="scripts/ci/$bin"
            case "$bin" in
                uffs-gen-hooks)
                    purpose="Generates \`scripts/hooks/_lint_pre_push.sh\` + \`_lint_fast.sh\` from \`scripts/ci/gates.toml\`"
                    drift="\`hooks-drift\` + \`fast-drift\` gates (\`--check\` mode)"
                    ;;
                uffs-gen-workflow)
                    purpose="Validates \`.github/workflows/pr-fast.yml\` structurally against \`scripts/ci/gates.toml\`"
                    drift="\`workflow-drift\` gate (\`--check\` only — no emission)"
                    ;;
                uffs-manifest-audit)
                    purpose="Validates the 15 Phase-1 workspace-inheritance manifest invariants across every member \`Cargo.toml\`"
                    drift="\`manifest-drift\` gate (\`--check\` mode)"
                    ;;
                *)
                    purpose="(unknown — Phase 9d to classify)"
                    drift="(unknown)"
                    ;;
            esac
        else
            continue
        fi
        printf "| \`%s\` | %s | %s |\n" "$bin_path" "$purpose" "$drift"
    done
fi

cat <<EOF

---

## §6 — Env-var registry (distinct names workspace-wide)

EOF

mapfile -t ENV_VARS < <(list_env_vars_workspace)
if [[ ${#ENV_VARS[@]} -eq 0 ]]; then
    echo "_No env vars consumed in any source file._"
else
    cat <<EOF
**${#ENV_VARS[@]} distinct env-var names** consumed across the workspace
via \`env::var(…)\` / \`env!(…)\` / \`option_env!(…)\`.

| Env var | Read sites (count) | Sample location |
|---|---:|---|
EOF
    for ev in "${ENV_VARS[@]}"; do
        # Prod-only sample (matches the same filters as the per-crate count).
        sample=$(rg "${RG_PROD_GLOBS[@]}" -l "\"$ev\"" crates scripts 2>/dev/null | head -1)
        count=$(rg "${RG_PROD_GLOBS[@]}" -l "\"$ev\"" crates scripts 2>/dev/null | wc -l | tr -d ' ')
        printf "| \`%s\` | %d | \`%s\` |\n" "$ev" "$count" "${sample:-N/A}"
    done
fi

cat <<EOF

The §988-mirror contract for each (name / scope / type / default / where
read / semver class) is captured in
\`docs/architecture/code-quality/build_codegen_policy.md\` §"Environment
variables" registry by Phase 9f.

---

## §7 — \`include_*!\` use sites

EOF

if [[ "$total_includes" -eq 0 ]]; then
    echo "_No \`include_bytes!\` / \`include_str!\` / \`include!\` use sites found._"
else
    cat <<EOF
**${total_includes} use site(s)** workspace-wide.  Listed below:

EOF
    rg "${RG_PROD_GLOBS[@]}" -n -B0 -A0 \
        '\b(include_bytes|include_str|include)!' crates 2>/dev/null \
        | sed -E 's|^([^:]+):([0-9]+):(.*)$|- `\1:\2` — `\3`|' \
        | head -40
fi

cat <<EOF

---

## §8 — Workspace totals

- \`build.rs\` files: **${total_build}**
- Proc-macro crates: **${total_proc_macro}**
- \`macro_rules!\` declarations: **${total_macros}**
- Distinct env-var names consumed: **${total_env_distinct}**
- \`include_*!\` use sites: **${total_includes}**

---

EOF

if [[ "$WITH_CARGO" -eq 1 ]]; then
    cat <<EOF
## §9 — Cargo cross-check (\`--with-cargo\` mode)

> \`cargo build --workspace --timings\` — only available when invoked
> with \`--with-cargo\`.  Captures the timing HTML report under
> \`target/cargo-timings/cargo-timing-\$DATE-\$SHA.html\`.

EOF
    echo '```'
    cargo build --workspace --timings 2>&1 | tail -10
    echo '```'
    echo
    echo "HTML report saved to \`target/cargo-timings/cargo-timing-*.html\`."
fi

cat <<EOF

---

## Next steps (per plan §1)

1. **Phase 9b** — manual audit of \`crates/uffs-cli/build.rs\` against
   playbook §1041-1046 (justified per native-lib-detection /
   codegen-tied / compile-time-probing category).
2. **Phase 9c** — record the deliberate "0 proc-macro crates" posture
   in \`build_codegen_policy.md\` §3.
3. **Phase 9d** — per-macro audit of the \`macro_rules!\` sites against
   playbook §1064.
4. **Phase 9e** — cross-link the codegen binaries to
   \`gates-manifest-plan.md\` + document the drift-detector cadence.
5. **Phase 9f** — produce the env-var \$988-mirror registry in
   \`build_codegen_policy.md\` §"Environment variables".
EOF
