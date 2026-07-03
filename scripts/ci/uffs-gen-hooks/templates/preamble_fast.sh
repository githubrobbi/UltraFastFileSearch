# shellcheck shell=bash
#
# Called by:
#   - `scripts/hooks/pre-commit` (git hook)
#   - `just lint-fast`           (manual runs)
#
# Architecture (Phase 2 of dev-flow-implementation-plan.md § 2.4):
#
#   Single-bucket parallel gate.  Per-gate routing (which file
#   classes each gate fires on) is driven by `gates.toml` and
#   rendered into the dispatch section below.
#
# Budget:
#   * docs / config-only commits:        sub-2 s
#   * Rust commits (warm sccache):       ~8-15 s (three clippy passes;
#                                        cargo's target-dir lock serialises
#                                        them so the 2nd and 3rd are
#                                        incremental-cheap)
#
# Windows xwin check was removed from this gate in Phase 2 of
# dev-flow-implementation-plan.md § 2.4 because its 40-90 s cold cost
# violated the T1 budget.  xwin lives at pre-push (advisory, upgraded
# to strict clippy in Phase W5.6 of windows-clippy-and-linux-cross-plan.md)
# and `pr-fast.yml` (authoritative native `windows-lint` job).
#
# Soft-skips missing optional tools (typos, taplo, reuse) with a
# one-line install hint so new contributors are not blocked before
# running `just install-dev-tools`.
#
# Per-gate documentation (label, command, rationale, expected runtime,
# CI counterpart) lives in `scripts/ci/gates.toml`'s `[[gate]]` tables
# - that is the single source of truth, and the generator preserves
# it on every regen.

set -euo pipefail

# ── Colours ────────────────────────────────────────────────────────────
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    C_BLUE=$'\033[0;34m'
    C_CYAN=$'\033[0;36m'
    C_GREEN=$'\033[0;32m'
    C_RED=$'\033[0;31m'
    C_RESET=$'\033[0m'
else
    # Explicit empty-string form.  The `VAR=` shorthand works but
    # trips SC1007 because a stray trailing space would turn it into
    # `VAR= other_cmd` (a single-line env override in front of a
    # command invocation).  Using `VAR=''` makes the intent
    # unambiguous and keeps the linter quiet.
    C_BLUE=''
    C_CYAN=''
    C_GREEN=''
    C_RED=''
    C_RESET=''
fi

# ── Staged-file inventory ──────────────────────────────────────────────
# Tool-routing rationale (see also .taplo.toml):
# `supply-chain/*.toml` is cargo-vet's data store, formatted by
# `cargo vet fmt` (which has opinions taplo does not share - e.g.
# column-aligned trailing comments).  Two formatters fighting over the
# same file is a pre-push dead-end, so we split ownership at the
# pre-commit hook: taplo handles every other TOML; cargo-vet handles
# the store.
STAGED_ALL=$(git diff --cached --name-only --diff-filter=ACMR 2>/dev/null || true)
STAGED_TOML=$(printf '%s\n' "$STAGED_ALL" | grep '\.toml$' || true)
STAGED_TOML_NONVET=$(printf '%s\n' "$STAGED_TOML" | grep -v '^supply-chain/' || true)
STAGED_VET=$(printf '%s\n' "$STAGED_TOML" | grep '^supply-chain/' || true)
has_staged_rs()          { printf '%s\n' "$STAGED_ALL" | grep -q '\.rs$';   }
has_staged_toml_nonvet() { [[ -n "${STAGED_TOML_NONVET//[[:space:]]/}" ]]; }
has_staged_vet()         { [[ -n "${STAGED_VET//[[:space:]]/}" ]]; }
has_any_staged()         { [[ -n "${STAGED_ALL//[[:space:]]/}" ]]; }

printf '%s🚦 lint-fast — staged-scoped parallel gate%s\n' "$C_BLUE" "$C_RESET"
START=$(date +%s)

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

NAMES=()
PIDS=()
spawn() {
    local name="$1"
    shift
    NAMES+=("$name")
    ( "$@" ) >"$TMP/$name.out" 2>&1 &
    PIDS+=($!)
}

