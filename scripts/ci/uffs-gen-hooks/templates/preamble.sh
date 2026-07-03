# shellcheck shell=bash
#
# Called by:
#   - `scripts/hooks/pre-push` (git hook)
#   - `just lint-pre-push`     (manual runs)
#
# Architecture (Phase 2 of dev-flow-implementation-plan.md § 1.4):
#
#   Bucket 1 — cheap, parallel, fire-and-forget.  Non-cargo jobs plus
#              cargo-vet (which is fast and dep-gated).  Waits at the
#              end of the script; all Bucket 1 results report even
#              when Bucket 2 fails.
#
#   Bucket 2 — cargo-heavy, sequential, FAIL-FAST.  Ordered cheapest →
#              most expensive so the first actionable red surfaces
#              within ~15 s rather than the old ~40-60 s.  After the
#              first failure, remaining jobs are marked `skip` and
#              not executed.  Cargo's target-dir lock would serialise
#              these anyway; explicit ordering lets us abort sooner.
#
# Change classification (see git's pre-push stdin protocol):
#   rust_changed  = any `*.rs`
#   dep_changed   = Cargo.{toml,lock} | supply-chain/**
#   infra_changed = .github/** | scripts/** | .cargo/** | .config/** |
#                   just/** | rust-toolchain* | {clippy,rustfmt,deny,REUSE}.toml
#   code_changed  = rust | dep | infra
#
# Bucket 2 only runs when code_changed.  Pure-docs-only pushes skip
# the compile/test gate entirely.
#
# Per-gate documentation (label, command, rationale, expected runtime,
# CI counterpart) lives in `scripts/ci/gates.toml`'s `[[gate]]` tables
# — that is the single source of truth, and the generator preserves
# it on every regen.

set -euo pipefail

# ── Colours ────────────────────────────────────────────────────────────
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    C_BLUE=$'\033[0;34m'
    C_CYAN=$'\033[0;36m'
    C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[1;33m'
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
    C_YELLOW=''
    C_RED=''
    C_RESET=''
fi

# ── Change classification ──────────────────────────────────────────────
# Detect whether invoked by git pre-push (stdin pipe with ref updates)
# or manually (e.g. `just lint-pre-push`).  git's pre-push hook protocol
# (https://git-scm.com/docs/githooks#_pre_push) pipes one line per ref:
#     <local_ref> <local_oid> <remote_ref> <remote_oid>
# In manual mode we can't know what's about to be pushed so we
# conservatively treat ALL file classes as changed (runs every gate;
# never silently skips a hard one).  See
# docs/architecture/dev-flow-implementation-plan.md § 2.3 for details.
ZERO='0000000000000000000000000000000000000000'
CHANGED_FILES=""
# Newline-delimited list of `BASE..LOCAL_OID` ranges for the
# `commit-subjects` Bucket-1 job.  Same data source as `CHANGED_FILES`
# (git's pre-push stdin protocol) so the validator iterates the same
# set of new commits that classification inspected.
COMMIT_RANGES=""
if [[ ! -t 0 ]]; then
    # stdin is piped; try git's pre-push protocol.
    while IFS=' ' read -r _local_ref local_oid _remote_ref remote_oid; do
        [[ -z "${local_oid:-}" || "$local_oid" == "$ZERO" ]] && continue
        if [[ "$remote_oid" == "$ZERO" ]]; then
            # New remote ref (first push of this branch).  Diff against
            # best available base: merge-base with origin/main, fall back
            # to the root commit if none.
            base=$(git merge-base "$local_oid" origin/main 2>/dev/null \
                || git rev-list --max-parents=0 "$local_oid" 2>/dev/null | tail -n1 \
                || echo "")
        else
            base="$remote_oid"
        fi
        if [[ -n "$base" ]]; then
            CHANGED_FILES+=$'\n'$(git diff --name-only "$base" "$local_oid" 2>/dev/null || true)
            COMMIT_RANGES+="$base..$local_oid"$'\n'
        else
            CHANGED_FILES="__UNKNOWN__"
            break
        fi
    done
fi
# Empty stdin (manual invocation, or push with only deletions) → conservative.
[[ -z "${CHANGED_FILES// /}" ]] && CHANGED_FILES="__UNKNOWN__"
# Manual-mode commit-range fallback: validate everything between
# `origin/main` and the current HEAD.  Branches with no diverged
# commits (already merged, or fresh `main` checkout) get an empty
# range which the validator silently accepts.
if [[ -z "${COMMIT_RANGES// /}" ]]; then
    if git rev-parse --verify origin/main >/dev/null 2>&1; then
        COMMIT_RANGES="origin/main..HEAD"$'\n'
    fi
fi
# Exported so the Bucket-1 `commit-subjects` job can read it from the
# `bash -c` subshell environment (forked shells inherit env vars but
# not unexported shell vars).
export COMMIT_RANGES

class_matches() {
    [[ "$CHANGED_FILES" == "__UNKNOWN__" ]] && return 0
    printf '%s\n' "$CHANGED_FILES" | grep -E "$1" >/dev/null
}

RUST_CHANGED=0;  class_matches '\.rs$' && RUST_CHANGED=1
DEP_CHANGED=0;   class_matches '^(.*Cargo\.toml$|Cargo\.lock$|supply-chain/)' && DEP_CHANGED=1
INFRA_CHANGED=0; class_matches '^(\.github/|scripts/|\.cargo/|\.config/|just/|rust-toolchain|clippy\.toml$|rustfmt\.toml$|deny\.toml$|REUSE\.toml$|codecov\.yml$)' && INFRA_CHANGED=1
CODE_CHANGED=$(( RUST_CHANGED || DEP_CHANGED || INFRA_CHANGED ))

printf '%s🚦 lint-pre-push — workspace parallel gate%s\n' "$C_BLUE" "$C_RESET"
if [[ "$CHANGED_FILES" == "__UNKNOWN__" ]]; then
    printf '   %s(manual mode — no pushed range detected; running all gates)%s\n' "$C_CYAN" "$C_RESET"
else
    printf '   %s(rust=%d dep=%d infra=%d code=%d)%s\n' \
        "$C_CYAN" "$RUST_CHANGED" "$DEP_CHANGED" "$INFRA_CHANGED" "$CODE_CHANGED" "$C_RESET"
fi
START=$(date +%s)

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ── Bucket 1 (cheap, parallel) ─────────────────────────────────────────
# Non-cargo jobs + cargo-vet (dep-gated).  All run concurrently; we wait
# at the end.  Cargo-heavy jobs are deliberately NOT here — they would
# serialise on cargo's target-dir lock and stall the cheap jobs.
BG_NAMES=()
BG_PIDS=()
spawn_bg() {
    local name="$1"; shift
    BG_NAMES+=("$name")
    ( "$@" ) >"$TMP/$name.out" 2>&1 &
    BG_PIDS+=($!)
}

# ── Bucket 2 (sequential, fail-fast) ───────────────────────────────────
# Cargo-heavy jobs run in deliberate order so the FIRST actionable red
# aborts the rest.  Order is cheapest → most expensive so most failures
# surface within ~15 s rather than the old ~40-60 s.  See
# docs/architecture/dev-flow-implementation-plan.md § 1.4 / 2.3.
SEQ_RESULTS=()    # "name:ok|fail|skip"
SEQ_FIRST_FAIL=""
run_seq() {
    local name="$1"; shift
    if [[ -n "$SEQ_FIRST_FAIL" ]]; then
        SEQ_RESULTS+=("$name:skip")
        return 0
    fi
    # Split `local` from assignment so a non-zero exit from the
    # command substitution propagates (shellcheck SC2155: the `local`
    # builtin itself always returns 0 and would otherwise mask a
    # failure of `date +%s`).
    local stamp
    stamp=$(date +%s)
    if "$@" >"$TMP/$name.out" 2>&1; then
        local dt
        dt=$(( $(date +%s) - stamp ))
        SEQ_RESULTS+=("$name:ok:$dt")
    else
        local dt
        dt=$(( $(date +%s) - stamp ))
        SEQ_RESULTS+=("$name:fail:$dt")
        SEQ_FIRST_FAIL="$name"
    fi
}

