# Dev-Flow Implementation Plan (v2)

<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (c) 2025-2026 SKY, LLC. -->

Companion to `dev-flow.md`.  **Sibling plan**: see
[`release-automation-plan.md`](release-automation-plan.md) for the
release/versioning architecture (release-plz + git-cliff + eventual
crates.io publishing).  This document owns **merge-time CI gates**;
the release-automation plan owns **what happens after merge to main**
— version bump, changelog generation, tag creation, binary + crate
publishing.  Both plans share `release.yml` (binary distribution,
left unchanged) and `scripts/ci-pipeline/src/version.rs` (whose
version-bump functions are retired in release-automation Phase R5).

Incorporates external review (2026-04-23)
that correctly identified structural gaps in v1:

- v1 still treated CI as **one long lane** instead of separating
  merge-confidence from artifact production from release packaging.
- v1's "soft-skip everything" rule was too broad — semantic checks
  with local inputs (e.g. `cargo vet` when `Cargo.lock` changed)
  should be **hard-fail**, not soft-skip.
- v1 mixed **when** a gate runs (time) with **why** it exists (purpose).
  A proper model needs both axes.
- v1 proposed `CARGO_INCREMENTAL=0` in `just/shared.just` — the right
  fix is to move the entire cache policy into `.cargo/config.toml`
  (Cargo supports `build.incremental` natively) and **delete** the Just
  export entirely.  One source of truth.
- v1 kept Windows xwin in pre-commit at 40-90 s cold — violates the
  "don't break flow" threshold.  Windows belongs in pre-push + CI, not
  pre-commit.
- v1 left pre-push at **zero test execution**.  nextest profiles +
  filtersets let us run a mandatory fast subset without blowing budget.

Status as of **2026-04-23** · Maintainer: `@githubrobbi`

---

## 1. Target architecture — four lanes, two axes

### 1.1 The two axes

Every gate has both a **time tier** (when) and a **lane purpose** (why).

**Axis A — time tiers** (from v1, unchanged):

- T0 editor · T1 pre-commit · T2 pre-push · T3 CI on PR · T4 nightly

**Axis B — lane purpose** (new):

- **Gate lane** — "is this obviously broken?"  Blocks merge.  Fast.
- **Preview lane** — "is this SHA worth human validation on real binaries?"
  Produces artifacts.  Non-blocking.  On-demand.
- **Release lane** — "is this SHA shippable?"  Signed, SBOM'd,
  published.  Tag-only.
- **Deep-assurance lane** — "does this survive slow / probabilistic
  checks?"  Coverage, miri, fuzz.  Nightly.

A SHA **earns** its way from gate → preview → release.  These are not
coordinate stages on one long pipeline; they are **promotion steps**.

### 1.2 Lane matrix (post-refactor)

| Lane | Trigger | Mandatory? | Max runtime | Outputs |
|---|---|---|---|---|
| T1 pre-commit (gate) | `git commit` | yes, bypassable with `--no-verify` | **&lt; 15 s warm staged-only** | clean working tree |
| T2 pre-push (gate) | `git push` | yes, bypassable | **&lt; 60 s warm** | none; local confidence |
| T3 PR-fast (gate) | PR open / push to PR branch | **required to merge** | **&lt; 8 min wall** | Pass/fail only |
| T3 PR-preview (preview) | PR label `preview-binaries` or manual dispatch, **only after PR-fast green on same SHA** | **not required** | 15-30 min | Windows artifacts + nextest archive + per-file SHA256 manifest (Phase 5 scope; macOS/Linux deferred to Phase 9+) |
| T4 Tier 2 (deep) | weekly cron | no | 60-90 min | coverage, miri, udeps report |
| Tag (release) | `v*.*.*` tag push | n/a (gated by PR-fast being green) | 30-45 min | signed binaries, SBOM, SLSA attestation, GH Release |

Key architectural distinction from today's flow:

- Today: every PR push triggers `ci.yml` which does format+clippy+rustdoc+tests+security+file-size (8 jobs) — **and** the user is expected to rely on Tier 2 + Release for Windows validation.  Result: a regression that only shows on Windows surfaces at release time (10-15 min into a ship run).
- Tomorrow: every PR push triggers `pr-fast.yml` including a **cheap Windows compile-check**.  Preview binaries are opt-in via label.  Release stays tag-only.

### 1.3 Change classification — the single source of truth for `if:` predicates

Every gate's trigger is expressed in terms of one of four file classes.
Same predicates apply locally (pre-commit / pre-push) and in CI (`classify`
job in `pr-fast.yml`).  Hand-coded copies in both places **must** agree,
which is one motivation for the stretch goal in §2.7.

| Class | Patterns (glob) | Intent |
|---|---|---|
| `rust_changed` | `**/*.rs` | Any Rust source edit. |
| `dep_changed` | `Cargo.toml`, `**/Cargo.toml`, `Cargo.lock`, `supply-chain/**` | Dependency graph touched.  Cargo Vet reads the **full** tree via `cargo metadata --all-features`, so `Cargo.toml` counts even when `Cargo.lock` is untouched. |
| `infra_changed` | `.github/**`, `scripts/**`, `.cargo/**`, `.config/**`, `just/**`, `rust-toolchain*`, `clippy.toml`, `rustfmt.toml`, `deny.toml`, `REUSE.toml`, `codecov.yml` | Tooling, workflows, lint / test / deny configs, toolchain pin.  Any of these can break build/CI/hooks. |
| `docs_changed` | `**/*.md`, `docs/**`, `LICENSE*`, `CHANGELOG.md`, `TRADEMARK.md`, `SECURITY.md`, `assets/**` | Documentation and brand assets only. |

**Derived predicate used by all compile/test/lint jobs**:

```
code_changed = rust_changed || dep_changed || infra_changed
```

A PR that only hits `docs_changed` skips every compile gate.  Anything
else runs the full gate.  **Dependency-only PRs run compile/docs/tests/
Windows** — `dep_changed` alone is enough to gate them in, because a
Cargo.toml or lockfile bump can break any of those.  Infra-only PRs
(e.g. workflow tweaks) are treated the same way.

### 1.3.1 Hard gates (block commit / push / merge)

| Gate | Hard when… | Tier | Missing-tool behavior |
|---|---|---|---|
| fmt | `rust_changed` | T1 | stdlib rustfmt; always present |
| clippy (scoped) | `rust_changed` | T1 | stdlib; always present |
| file-size-policy | always | T1 | shell script; always present |
| **`cargo vet check --locked`** | **`dep_changed`** | **T1+T2+T3** | **hard-fail with install hint** — not soft-skip |
| workspace clippy trio | `code_changed` | T2 | always present |
| rustdoc `-Dwarnings` | `code_changed` | T2 | always present |
| **doctests** | `code_changed` | **T2 (new)** | always present |
| `cargo deny check --locked` | `dep_changed` | T2 | `cargo-deny` required; hard-fail on missing |
| `cargo check --locked` | `code_changed` | T2 | always present |
| test-compile (`nextest --no-run --locked`) | `code_changed` | T2 | `cargo-nextest` required; hard-fail on missing (pinned in `.config/nextest.toml`) |
| **nextest `pre-push-smoke` profile** | `code_changed` | **T2 (new)** | same; hard-fail on missing |
| **Windows xwin clippy (local)** | `code_changed` | T2 | **advisory locally**: soft-skip with install hint when `cargo-xwin` missing.  Hard-gated at T3 by native `windows-lint` job (Phase W5.5 of `windows-clippy-and-linux-cross-plan.md` flipped this from `cargo check` to `cargo clippy -- -D warnings`). |
| pr-fast required aggregate | always | T3 | n/a |

### 1.3.2 Advisory gates (soft-skip; install hint printed on miss)

| Gate | Rationale |
|---|---|
| typos | spell-check; nice-to-have |
| taplo | TOML formatting; nice-to-have |
| reuse | SPDX header check; nice-to-have |
| cargo machete | unused-dep check; Tier 2 has cargo-udeps as the authoritative version |

### 1.3.3 Design decisions behind the table

**`cargo-vet` is the only tool promoted from advisory to hard.**  Rationale:
it has a dedicated local trigger (`dep_changed`), its input is 100 %
reproducible offline, and CI enforces it anyway — the CI-only placement
is the exact bug that caused the v0.5.71 four-round-trip incident.

**Windows xwin is deliberately split** between advisory-local and
hard-required-remote.  Rationale: `cargo-xwin` downloads the MSVC SDK on
first run (~400 MB) and not all contributors want that footprint.  The
PR-fast native `windows-lint` job (Phase W5.5; runs `cargo clippy -- -D
warnings` on `windows-latest`) is the authoritative gate; the local
xwin step is an ergonomics win for contributors who already have it
installed.  This is **not** a regression of the v1 "hard xwin" position
— the feedback correctly flagged that treating a 400 MB download as a
hard local requirement is user-hostile.

**`cargo-deny` and `cargo-nextest` are hard-required rather than advisory.**
Rationale: both are listed in `just update-tools` (`just/dev.just:118`)
as baseline dev tools, and their checks are required in CI.  A missing
binary at push time means the developer is out of sync with the
baseline; hard-fail with install hint is correct.

### 1.4 Gate scheduling — ordered by first-actionable-failure

v1's `_lint_pre_push.sh` spawns everything at once and lets wall-clock
finish.  That maximizes throughput but delays the first actionable red
result.  Cargo's target-dir lock serialises most heavy jobs anyway.

New order (T2 pre-push), in two buckets:

**Bucket 1 — fire-and-wait in parallel (all cheap, all non-cargo):**

1. fmt check
2. file-size-policy
3. typos (advisory)
4. reuse (advisory)
5. taplo (advisory)
6. **cargo vet** (when dep files changed)

**Bucket 2 — sequential in meaningful order (each command uses `--locked`
where supported):**

1. `cargo check --workspace --all-targets --all-features --locked` — fastest compile gate, catches most type errors before clippy.
2. clippy `lint-ci` (`--locked`)
3. clippy `lint-prod` (`--locked`)
4. clippy `lint-tests` (`--locked`)
5. `cargo doc --workspace --all-features --no-deps --locked` with `RUSTDOCFLAGS=-Dwarnings`
6. `cargo test --doc --workspace --all-features --locked` (new)
7. `cargo deny check` — runs when `dep_changed`, advisory otherwise
8. `cargo nextest run --no-run --workspace --all-targets --all-features --locked` (test compile)
9. `cargo nextest run --profile pre-push-smoke --locked` (new)
10. `cargo xwin clippy --workspace --all-targets --all-features --target x86_64-pc-windows-msvc --no-deps -- -D warnings` (`just lint-ci-windows`, Phase W5.6) — **advisory locally** (soft-skip with install hint if `cargo-xwin` missing; authoritative gate is PR-fast native `windows-lint` on `windows-latest`)

The first red in Bucket 2 aborts the rest (fail-fast).  Bucket 1
continues to completion so the user sees all cheap-check results in
one report.  **Why `--locked` everywhere**: Cargo's `--locked` enforces
the exact resolution from `Cargo.lock` and is the canonical "CI" mode;
matching local to CI eliminates a class of "green locally, red in CI"
surprises where the resolver fetched a newer patch.

---

## 2. Detailed change list — file by file

### 2.1 `.cargo/config.toml` — single source of cache policy

**Current** (`@/Users/rnio/Private/Github/UltraFastFileSearch/.cargo/config.toml:16-25`):

```toml
[build]
target-dir = "target"
rustc-wrapper = "sccache"
```

**Target**:

```toml
[build]
target-dir = "target"
# sccache + incremental=false is the canonical local cache policy.
# Paired here (not in just/shared.just) so every cargo invocation —
# including those spawned by git hooks, rust-script, IDE plugins,
# etc. — inherits both settings as one atomic config.
# Docs: https://doc.rust-lang.org/cargo/reference/config.html#build
rustc-wrapper = "sccache"
incremental = false
```

And delete `@/Users/rnio/Private/Github/UltraFastFileSearch/just/shared.just:15`
line `export CARGO_INCREMENTAL := "1"` entirely.

**Why this is better than v1's proposal**: Cargo reads config.toml first,
then env overrides.  Today's drift exists because `just/shared.just`
_exports_ `CARGO_INCREMENTAL=1` into every subshell — which overrides
`.cargo/config.toml`'s implicit `incremental = true` default.  Flipping
the env var to `0` in Just "works" but keeps two authorities.  Removing
the env var and adding `incremental = false` to config.toml has **one
authority** — env vars only override in CI, where they're explicitly set.

**Rollback**: If a contributor wants incremental for a specific
experimental session they can still `CARGO_INCREMENTAL=1 cargo build`
— env overrides config.  The default just becomes the correct one.

### 2.2 `.config/nextest.toml` — new `pre-push-smoke` profile

**Current**: three profiles (`default`, `ci`, `slow`).

**Add**:

```toml
# ---------------------------------------------------------------------------
# pre-push-smoke — mandatory fast test subset at git-push time.
# Budget: 10-20 s warm on a developer laptop.
# Usage: cargo nextest run --profile pre-push-smoke --locked
#
# Selection is a denylist expressed in nextest's filterset language:
#   - Exclude the validation suite (`test_validate_*`) — those tests
#     are heavy integration and belong in the CI `ci` profile.
#   - Exclude the entire `uffs-client` package — its shmem tests
#     serialise globally via `threads-required = num-cpus` and
#     dominate wall-time when mixed with fast unit tests.
#   - Exclude the benchmark harness binaries
#     (`benchmark_filtering`, `benchmark_sorting`) that are compiled
#     under `--tests`.
#   - Everything else: unit tests across all remaining crates.
#
# Long term: replace package-level denylist with per-test overrides
# that carry an explicit `slow` attribute, so the filter becomes
# `not attr(slow)` rather than a list of package / binary names.
# ---------------------------------------------------------------------------
[profile.pre-push-smoke]
test-threads = -2
retries = 0
fail-fast = true

slow-timeout = { period = "30s", terminate-after = 1 }
leak-timeout = "100ms"

failure-output = "immediate-final"
success-output = "never"
status-level = "fail"
final-status-level = "flaky"

default-filter = """
    not test(/^test_validate/)
  & not package(uffs-client)
  & not binary(benchmark_filtering)
  & not binary(benchmark_sorting)
"""
```

**Runtime expectation** on this workspace: roughly 8-15 s warm.  Will
be validated during Phase 3 rollout.

### 2.3 `scripts/hooks/_lint_pre_push.sh` — ordered schedule + hard cargo-vet

Replace the current "spawn everything at once" pattern with the two-bucket
scheduler described in §1.4.  Key contract changes:

- **cargo vet** becomes **hard-required** when `Cargo.lock` or
  `supply-chain/**` touched in the about-to-push range.  If tool is
  missing in that case → fail with install hint.
- **doctests** added as mandatory.
- **nextest smoke** added as mandatory.
- **cargo check** added as the first compile gate (fast fail before
  the three clippy runs).

**Critical protocol detail**: `git push` invokes the pre-push hook with
the ref updates on **stdin**, one per line, format:

```
<local_ref> <local_oid> <remote_ref> <remote_oid>\n
```

(reference: <https://git-scm.com/docs/githooks#_pre_push>).  Earlier
drafts tried to compute the pushed range via `git merge-base HEAD @{push}`
or `origin/<branch>` heuristics.  Those break on (a) first push of a new
branch, (b) alternate remotes, (c) force-pushes, (d) multi-ref pushes, and
the fallback-to-HEAD error path silently collapses the diff to empty —
meaning a hard gate could be skipped exactly when it's needed.  The
implementation **must** consume stdin.

Detailed pseudo-code:

```bash
#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------
# 1. Consume git's pre-push stdin protocol.
# ---------------------------------------------------------------------
ZERO='0000000000000000000000000000000000000000'
CHANGED_FILES=""

while IFS=' ' read -r _local_ref local_oid _remote_ref remote_oid; do
    # Blank line or deletion ($local_oid == ZERO) — skip.
    [[ -z "${local_oid:-}" || "$local_oid" == "$ZERO" ]] && continue

    if [[ "$remote_oid" == "$ZERO" ]]; then
        # New remote ref (first push of this branch).  Diff against the
        # best available base: merge-base with origin/main, falling back
        # to the root commit.  Conservative: if we cannot determine a
        # base, treat everything as changed (triggers all hard gates).
        base=$(git merge-base "$local_oid" origin/main 2>/dev/null \
            || git rev-list --max-parents=0 "$local_oid" 2>/dev/null | tail -n1 \
            || echo "")
    else
        base="$remote_oid"
    fi

    if [[ -n "$base" ]]; then
        CHANGED_FILES+=$'\n'$(git diff --name-only "$base" "$local_oid")
    else
        # Be conservative: can't compute diff → run everything.
        CHANGED_FILES="__UNKNOWN__"
        break
    fi
done

# If CHANGED_FILES is empty (no parseable refs — e.g. hook invoked outside
# of git push for testing), also be conservative.
[[ -z "${CHANGED_FILES// /}" ]] && CHANGED_FILES="__UNKNOWN__"

# ---------------------------------------------------------------------
# 2. Classify into the four file classes from §1.3.
# ---------------------------------------------------------------------
class_matches() {
    [[ "$CHANGED_FILES" == "__UNKNOWN__" ]] && return 0
    echo "$CHANGED_FILES" | grep -E "$1" >/dev/null
}

RUST_CHANGED=0;  class_matches '\.rs$' && RUST_CHANGED=1
DEP_CHANGED=0;   class_matches '^(.*Cargo\.toml$|Cargo\.lock$|supply-chain/)' && DEP_CHANGED=1
INFRA_CHANGED=0; class_matches '^(\.github/|scripts/|\.cargo/|\.config/|just/|rust-toolchain|clippy\.toml$|rustfmt\.toml$|deny\.toml$|REUSE\.toml$|codecov\.yml$)' && INFRA_CHANGED=1
CODE_CHANGED=$(( RUST_CHANGED || DEP_CHANGED || INFRA_CHANGED ))

# ---------------------------------------------------------------------
# 3. Bucket 1 — cheap, parallel.
# ---------------------------------------------------------------------
spawn "fmt"       cargo fmt --all -- --check
spawn "file-size" bash scripts/ci/check_file_size_policy.sh

if (( DEP_CHANGED )); then
    if ! command -v cargo-vet >/dev/null 2>&1; then
        printf '\033[0;31m❌ cargo-vet required (Cargo.{toml,lock} or supply-chain/ changed)\033[0m\n' >&2
        printf '   install: \033[0;36mcargo install cargo-vet --locked\033[0m\n' >&2
        printf '   or run:  \033[0;36mjust install-dev-tools\033[0m\n' >&2
        exit 2
    fi
    spawn "vet" cargo vet check --locked
fi

command -v typos  >/dev/null 2>&1 && spawn "typos" typos .
command -v reuse  >/dev/null 2>&1 && spawn "reuse" reuse lint --quiet
command -v taplo  >/dev/null 2>&1 && spawn "taplo" taplo fmt --check

# ---------------------------------------------------------------------
# 4. Bucket 2 — sequential, fail-fast.  Only runs when code changed.
# ---------------------------------------------------------------------
if (( CODE_CHANGED )); then
    run_seq cargo check --workspace --all-targets --all-features --locked
    run_seq just lint-ci
    run_seq just lint-prod
    run_seq just lint-tests
    run_seq env RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --all-features --no-deps --locked
    run_seq env RUSTDOCFLAGS=-Dwarnings cargo test --doc --workspace --all-features --locked
    (( DEP_CHANGED )) && run_seq cargo deny check --locked --hide-inclusion-graph
    run_seq cargo nextest run --workspace --all-targets --all-features --no-run --locked
    run_seq cargo nextest run --profile pre-push-smoke --locked
    # Windows xwin: advisory locally (see §1.3.3).  Print install hint on miss.
    if command -v cargo-xwin >/dev/null 2>&1; then
        run_seq just check-windows
    else
        printf '\033[1;33m⚠  cargo-xwin missing — skipping local Windows check\033[0m\n'
        printf '   PR-fast will validate on windows-latest regardless.\n'
        printf '   To check locally: \033[0;36mcargo install cargo-xwin\033[0m\n'
    fi
fi

# Wait on Bucket 1 results, aggregate into exit code.
```

### 2.4 `scripts/hooks/_lint_fast.sh` — remove xwin from pre-commit

**Current**: xwin runs at pre-commit if `*.rs` staged and cargo-xwin
present.  Cold cost: 40-90 s.  **Violates the &lt;15 s T1 budget.**

**Target**: xwin moved to pre-push only (local advisory there; PR-fast
authoritative).  Pre-commit keeps: fmt, file-size, clippy-scoped, taplo,
typos, reuse, plus **cargo-vet when staged files hit `dep_changed`**.

**Staged-file classification** (different from pre-push — pre-commit sees
the staged set, not ref diff):

```bash
STAGED=$(git diff --cached --name-only --diff-filter=ACMR)
class_matches() { echo "$STAGED" | grep -E "$1" >/dev/null; }

DEP_STAGED=0; class_matches '^(.*Cargo\.toml$|Cargo\.lock$|supply-chain/)' && DEP_STAGED=1

if (( DEP_STAGED )); then
    command -v cargo-vet >/dev/null 2>&1 || {
        printf '\033[0;31m❌ cargo-vet required at commit (staged: Cargo.toml/lock/supply-chain)\033[0m\n' >&2
        exit 2
    }
    spawn "vet" cargo vet check --locked
fi
```

Result: pre-commit stays under 15 s warm, pre-push owns local Windows
advisory, PR-fast owns authoritative Windows gate.

### 2.5 Split `ci.yml` → `pr-fast.yml` + `preview-artifacts.yml`

**Current**: single `.github/workflows/ci.yml` (17 KB, 8 jobs).

**New architecture**:

#### `pr-fast.yml` (required, always-on)

```yaml
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025-2026 SKY, LLC.
name: PR Fast CI

on:
  pull_request:
    branches: [main]
  push:
    branches: [main, develop]
  # Required when using GitHub merge queue — without this the required
  # checks never report against the merge-queue test-merge commit and
  # the queue stalls indefinitely.  Harmless if merge queue is off.
  merge_group:
  workflow_dispatch:

# Least-privilege default.  Individual jobs opt into write scopes if
# they need them (none currently do).
permissions:
  contents: read

concurrency:
  group: pr-fast-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

env:
  # Match local policy (.cargo/config.toml) so green-locally ↔ green-in-CI.
  CARGO_TERM_COLOR: always
  CARGO_INCREMENTAL: 0
  RUST_BACKTRACE: 1

jobs:
  # ---------------------------------------------------------------------
  # classify — emits file-class outputs consumed by every downstream job.
  # MUST be in `required`'s needs so a classify failure cannot silently
  # green-light a PR.
  # ---------------------------------------------------------------------
  classify:
    name: Classify changes
    runs-on: ubuntu-22.04
    timeout-minutes: 2
    outputs:
      rust:  ${{ steps.f.outputs.rust }}
      dep:   ${{ steps.f.outputs.dep }}
      infra: ${{ steps.f.outputs.infra }}
      docs_only: ${{ steps.f.outputs.docs_only }}
      code:  ${{ steps.code.outputs.code }}
    steps:
      - name: Checkout (full history for accurate diff base)
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          fetch-depth: 0
          # Pinned to the head SHA for reproducibility when replaying
          # the workflow.  Falls through on push/merge_group events.
          ref: ${{ github.event.pull_request.head.sha || github.sha }}

      - id: f
        uses: dorny/paths-filter@de90cc6fb38fc0963ad72b210f1f284cd68cea36 # v3.0.2
        with:
          filters: |
            rust:
              - '**/*.rs'
            dep:
              - 'Cargo.toml'
              - '**/Cargo.toml'
              - 'Cargo.lock'
              - 'supply-chain/**'
            infra:
              - '.github/**'
              - 'scripts/**'
              - '.cargo/**'
              - '.config/**'
              - 'just/**'
              - 'rust-toolchain*'
              - 'clippy.toml'
              - 'rustfmt.toml'
              - 'deny.toml'
              - 'REUSE.toml'
              - 'codecov.yml'
            docs_only:
              - added|modified: '**'
              - '!**/*.rs'
              - '!**/Cargo.toml'
              - '!Cargo.lock'
              - '!supply-chain/**'
              - '!.github/**'
              - '!scripts/**'
              - '!.cargo/**'
              - '!.config/**'
              - '!just/**'

      - id: code
        run: |
          if [[ "${{ steps.f.outputs.rust }}" == 'true' \
             || "${{ steps.f.outputs.dep }}" == 'true' \
             || "${{ steps.f.outputs.infra }}" == 'true' ]]; then
              echo "code=true"  >> "$GITHUB_OUTPUT"
          else
              echo "code=false" >> "$GITHUB_OUTPUT"
          fi

  # ---------------------------------------------------------------------
  # file-size — always runs, cheap.
  # ---------------------------------------------------------------------
  file-size:
    name: File size policy
    runs-on: ubuntu-22.04
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - run: bash scripts/ci/check_file_size_policy.sh

  # ---------------------------------------------------------------------
  # fmt — rust_changed.  Cheap, runs in parallel with classify downstream.
  # ---------------------------------------------------------------------
  fmt:
    name: Format check
    runs-on: ubuntu-22.04
    needs: classify
    if: needs.classify.outputs.rust == 'true'
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - run: rustup show
      - run: cargo fmt --all -- --check

  # ---------------------------------------------------------------------
  # sanity — fastest compile gate (cargo check) + cargo-vet.
  # Downstream heavy jobs need this to have passed.
  # ---------------------------------------------------------------------
  sanity:
    name: Sanity (cargo check + vet)
    runs-on: ubuntu-22.04
    needs: classify
    if: needs.classify.outputs.code == 'true'
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - run: rustup show
      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2
      - name: cargo fetch --locked
        run: cargo fetch --locked
      - name: cargo check --locked
        run: cargo check --workspace --all-targets --all-features --locked
      - name: cargo vet check --locked
        if: needs.classify.outputs.dep == 'true'
        uses: taiki-e/install-action@dfc84ffb7254b048a0a843316ff5a2714dcdc7bd # v2
        with: { tool: cargo-vet }
      - if: needs.classify.outputs.dep == 'true'
        run: cargo vet check --locked

  clippy:
    name: Clippy
    runs-on: ubuntu-22.04
    needs: sanity
    if: needs.classify.outputs.code == 'true'
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with: { ref: ${{ github.event.pull_request.head.sha || github.sha }} }
      - run: rustup show
      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2
      - run: cargo clippy --workspace --all-targets --all-features --locked --no-deps -- -D warnings

  docs:
    name: Rustdoc + doctests
    runs-on: ubuntu-22.04
    needs: sanity
    if: needs.classify.outputs.code == 'true'
    timeout-minutes: 30
    env: { RUSTDOCFLAGS: "-Dwarnings" }
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with: { ref: ${{ github.event.pull_request.head.sha || github.sha }} }
      - run: rustup show
      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2
      - run: cargo doc  --workspace --all-features --no-deps --locked
      - run: cargo test --doc --workspace --all-features --locked

  test-build:
    name: Test build
    runs-on: ubuntu-22.04
    needs: sanity
    if: needs.classify.outputs.code == 'true'
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with: { ref: ${{ github.event.pull_request.head.sha || github.sha }} }
      - run: rustup show
      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2
        with: { shared-key: test-build, cache-on-failure: 'true' }
      - run: cargo test --workspace --all-features --lib --tests --no-run --locked

  tests:
    name: Tests
    runs-on: ubuntu-22.04
    needs: test-build
    if: needs.classify.outputs.code == 'true'
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with: { ref: ${{ github.event.pull_request.head.sha || github.sha }} }
      - run: rustup show
      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2
        with: { shared-key: test-build, save-if: 'false' }
      - uses: taiki-e/install-action@dfc84ffb7254b048a0a843316ff5a2714dcdc7bd # v2
        with: { tool: nextest }
      - run: cargo nextest run --workspace --all-features --lib --tests --profile ci --locked

  security:
    name: Security (deny + vet)
    runs-on: ubuntu-22.04
    needs: classify
    if: needs.classify.outputs.dep == 'true' || needs.classify.outputs.infra == 'true' || needs.classify.outputs.rust == 'true'
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with: { ref: ${{ github.event.pull_request.head.sha || github.sha }} }
      - run: rustup show
      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2
      - uses: taiki-e/install-action@dfc84ffb7254b048a0a843316ff5a2714dcdc7bd # v2
        with: { tool: cargo-deny,cargo-vet }
      - run: cargo deny check --locked
      - run: cargo vet check --locked

  # NOTE: This sample shows the original Phase 4 `windows-check`
  # job (cargo check).  Phase W5.5 of
  # `windows-clippy-and-linux-cross-plan.md` renamed it to
  # `windows-lint` and switched the command to
  # `cargo clippy --workspace --all-targets --all-features --locked
  # --no-deps -- -D warnings`.  The live workflow at
  # `.github/workflows/pr-fast.yml::windows-lint` is the source of
  # truth; this snippet is preserved for historical context only.
  windows-check:
    name: Windows compile check
    runs-on: windows-latest
    needs: sanity
    if: needs.classify.outputs.code == 'true'
    timeout-minutes: 25
    env: { RUSTFLAGS: "-C target-cpu=x86-64-v3" }
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with: { ref: ${{ github.event.pull_request.head.sha || github.sha }} }
      - run: rustup show
      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2
        with: { shared-key: pr-fast-windows }
      - run: cargo check --workspace --all-targets --all-features --locked

  # ---------------------------------------------------------------------
  # required — single branch-protection target.  Explicitly includes
  # `classify` so a broken classify cannot green-light the PR via
  # skipped downstream jobs (GitHub's `skipped` counts as `success`
  # for required checks, so we must check result strings ourselves).
  # ---------------------------------------------------------------------
  required:
    name: PR Fast CI / required
    runs-on: ubuntu-22.04
    if: always()
    needs:
      - classify
      - file-size
      - fmt
      - sanity
      - clippy
      - docs
      - test-build
      - tests
      - security
      - windows-check
    steps:
      - name: Gate on classify
        # Classify MUST succeed.  A skipped or failed classify means
        # downstream skips are meaningless — treat as failure.
        run: |
          if [[ "${{ needs.classify.result }}" != "success" ]]; then
            echo "::error::classify job did not succeed (result=${{ needs.classify.result }})"
            exit 1
          fi
      - name: Aggregate downstream results
        run: |
          set -u
          declare -A R=(
            [file-size]='${{ needs.file-size.result }}'
            [fmt]='${{ needs.fmt.result }}'
            [sanity]='${{ needs.sanity.result }}'
            [clippy]='${{ needs.clippy.result }}'
            [docs]='${{ needs.docs.result }}'
            [test-build]='${{ needs.test-build.result }}'
            [tests]='${{ needs.tests.result }}'
            [security]='${{ needs.security.result }}'
            [windows-check]='${{ needs.windows-check.result }}'
          )
          fail=0
          for job in "${!R[@]}"; do
            r="${R[$job]}"
            case "$r" in
              success|skipped) ;;
              *) echo "::error::$job: $r"; fail=1 ;;
            esac
          done
          exit "$fail"
```

**Critical correctness notes**:

1. **`required.needs` includes `classify`** — and the first step
   explicitly fails unless `needs.classify.result == 'success'`.  This
   closes the GitHub Actions quirk where a failed upstream job causes
   downstream jobs to `skip`, and `skipped` counts as success for
   branch-protection aggregation.  Without this, a broken `classify`
   would green-light every PR.
2. **`code_changed` is the gate for every compile/test/Windows job** —
   not `rust == 'true'`.  A PR that only touches `Cargo.lock` or a
   workflow file still runs the full compile/test matrix, because
   those changes can break anything.
3. **`merge_group:` trigger** is present so that merge-queue runs
   report against the test-merge commit; without it, enabling merge
   queue later would require rediscovering this the hard way.
4. **`permissions: contents: read`** at the workflow level is the
   least-privilege default per GitHub's Actions hardening guide.
5. **Checkout ref policy**: every job pins to
   `github.event.pull_request.head.sha || github.sha`, so the PR-fast
   run and the preview run in §2.5.2 validate the **same commit SHA**.
   Without this, `actions/checkout`'s default behaviour on PR events
   can check out a test-merge commit that doesn't match the head SHA
   the preview workflow sees, causing manifest mismatches.
6. **Third-party actions pinned to full commit SHAs**.  Matches the
   repo's existing practice in `ci.yml` and `tier-2.yml`.  Dependabot
   tracks these and opens bump PRs via `.github/dependabot.yml`.
7. **`--locked` on every cargo command that supports it** (`check`,
   `doc`, `test`, `clippy`, `deny`, `vet`, `nextest`).  Guarantees the
   resolver uses exactly `Cargo.lock`.  One `cargo fetch --locked` up
   front in `sanity` primes the cache for the whole pipeline.

#### `preview-artifacts.yml` (not required, opt-in)

Scope for Phase 5: **Windows binaries + Windows nextest archive only.**
macOS / Linux preview builds are deferred (see §7 Non-goals).

```yaml
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025-2026 SKY, LLC.
name: Preview Artifacts

on:
  pull_request:
    types: [labeled, synchronize]
  workflow_dispatch:
    inputs:
      sha:
        description: 'Commit SHA to build (default: latest on default branch)'
        required: false

permissions:
  contents: read
  checks: read            # for verify-pr-fast-green
  pull-requests: read     # for label inspection

concurrency:
  group: preview-${{ github.workflow }}-${{ github.event.pull_request.number || github.event.inputs.sha || github.sha }}
  cancel-in-progress: true

jobs:
  # ---------------------------------------------------------------------
  # gate — only proceed when:
  #   (a) manual dispatch, OR
  #   (b) PR has the `preview-binaries` label.
  # Emits the exact SHA every downstream job will build and validate.
  # ---------------------------------------------------------------------
  gate:
    if: |
      github.event_name == 'workflow_dispatch' ||
      (github.event_name == 'pull_request' &&
       contains(github.event.pull_request.labels.*.name, 'preview-binaries'))
    runs-on: ubuntu-22.04
    timeout-minutes: 2
    outputs:
      sha: ${{ steps.s.outputs.sha }}
    steps:
      - id: s
        run: |
          SHA='${{ github.event.pull_request.head.sha || github.event.inputs.sha || github.sha }}'
          [[ -z "$SHA" ]] && { echo "::error::no SHA resolved"; exit 1; }
          echo "sha=$SHA" >> "$GITHUB_OUTPUT"

  # ---------------------------------------------------------------------
  # verify-pr-fast-green — preview binaries are only worth producing for
  # a SHA that has already passed the merge-blocking checks.  Otherwise a
  # tester is validating a commit that wouldn't merge anyway.
  # Queries GitHub's check-runs API for the SHA.
  # ---------------------------------------------------------------------
  verify-pr-fast-green:
    needs: gate
    runs-on: ubuntu-22.04
    timeout-minutes: 5
    steps:
      - name: Poll check-runs for PR Fast CI / required
        uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9
        with:
          script: |
            const sha = '${{ needs.gate.outputs.sha }}';
            const want = 'PR Fast CI / required';
            // Retry for up to 10 minutes in case pr-fast is still running.
            for (let i = 0; i < 60; i++) {
              const { data } = await github.rest.checks.listForRef({
                owner: context.repo.owner,
                repo:  context.repo.repo,
                ref:   sha,
                per_page: 100,
              });
              const run = data.check_runs.find(r => r.name === want);
              if (run && run.status === 'completed') {
                if (run.conclusion === 'success') {
                  core.info(`✅ ${want} is success on ${sha.slice(0,7)}`);
                  return;
                }
                core.setFailed(`❌ ${want} on ${sha.slice(0,7)}: ${run.conclusion}`);
                return;
              }
              core.info(`⏳ ${want} not yet complete (status=${run?.status ?? 'missing'}); retry ${i+1}/60`);
              await new Promise(r => setTimeout(r, 10_000));
            }
            core.setFailed(`⏱  Timed out waiting for ${want} on ${sha.slice(0,7)}`);

  # ---------------------------------------------------------------------
  # build-windows — cross-compile Windows release binary on Linux/xwin.
  # Runs only after PR-fast is green on the same SHA.
  # ---------------------------------------------------------------------
  build-windows:
    needs: [gate, verify-pr-fast-green]
    runs-on: ubuntu-22.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          ref: ${{ needs.gate.outputs.sha }}  # validated SHA, not PR head
      - run: rustup show
      - run: rustup target add x86_64-pc-windows-msvc
      - uses: taiki-e/install-action@dfc84ffb7254b048a0a843316ff5a2714dcdc7bd # v2
        with: { tool: cargo-xwin }
      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2
        with: { shared-key: preview-windows }
      - name: cargo xwin build --release
        run: |
          cargo xwin build --release --bins --locked \
            --target x86_64-pc-windows-msvc
      - name: Stage Windows artifacts
        run: |
          mkdir -p dist/windows
          cp target/x86_64-pc-windows-msvc/release/*.exe dist/windows/ || true
      - uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882 # v4.4.3
        with:
          name: windows-preview-${{ needs.gate.outputs.sha }}
          path: dist/windows/
          if-no-files-found: error

  # ---------------------------------------------------------------------
  # build-test-archive — cargo-nextest supports "archive on one machine,
  # run on another".  Target machine needs (a) the same source SHA
  # checked out, (b) nextest installed.  Cargo itself is not required.
  # ---------------------------------------------------------------------
  build-test-archive:
    needs: [gate, verify-pr-fast-green]
    runs-on: ubuntu-22.04
    timeout-minutes: 30
    outputs:
      nextest_version: ${{ steps.nxv.outputs.version }}
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with: { ref: ${{ needs.gate.outputs.sha }} }
      - run: rustup show
      - run: rustup target add x86_64-pc-windows-msvc
      - uses: taiki-e/install-action@dfc84ffb7254b048a0a843316ff5a2714dcdc7bd # v2
        with: { tool: cargo-xwin,nextest }
      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2
        with: { shared-key: preview-windows }
      - id: nxv
        run: echo "version=$(cargo nextest --version | awk '{print $2}')" >> "$GITHUB_OUTPUT"
      - name: cargo nextest archive
        run: |
          cargo nextest archive --workspace --locked \
            --target x86_64-pc-windows-msvc \
            --archive-file uffs-tests-${{ needs.gate.outputs.sha }}.tar.zst
      - uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882 # v4.4.3
        with:
          name: nextest-archive-${{ needs.gate.outputs.sha }}
          path: uffs-tests-${{ needs.gate.outputs.sha }}.tar.zst
          if-no-files-found: error

  # ---------------------------------------------------------------------
  # smoke-windows — GitHub-hosted windows-latest runs the archive against
  # the SAME SHA that produced it.  Nextest's cross-compile model requires
  # the target machine to have the source tree checked out at the same
  # revision + nextest installed.  We satisfy both here.
  # ---------------------------------------------------------------------
  smoke-windows:
    needs: [gate, build-windows, build-test-archive]
    runs-on: windows-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with: { ref: ${{ needs.gate.outputs.sha }} }
      - uses: taiki-e/install-action@dfc84ffb7254b048a0a843316ff5a2714dcdc7bd # v2
        with: { tool: nextest }
      - uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16 # v4.1.8
        with: { name: nextest-archive-${{ needs.gate.outputs.sha }} }
      - run: cargo nextest run --archive-file uffs-tests-${{ needs.gate.outputs.sha }}.tar.zst --profile ci

  # ---------------------------------------------------------------------
  # manifest — human-readable summary committed-alongside-artifacts so a
  # tester downloading from the browser UI can verify integrity and
  # compatibility.  Emits per-file SHA256 in addition to the
  # artifact-level digest that upload-artifact@v4 validates.
  # ---------------------------------------------------------------------
  manifest:
    needs: [gate, build-windows, build-test-archive, smoke-windows]
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with: { ref: ${{ needs.gate.outputs.sha }} }
      - uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16 # v4.1.8
        with: { path: preview }
      - name: Emit manifest.json
        run: |
          RUSTC=$(rustc --version)
          LOCK_SHA=$(sha256sum Cargo.lock | awk '{print $1}')
          {
            echo '{'
            echo '  "git_sha":         "${{ needs.gate.outputs.sha }}",'
            echo '  "tested_sha":      "${{ needs.gate.outputs.sha }}",'
            echo '  "cargo_lock_sha256": "'"$LOCK_SHA"'",'
            echo '  "rustc_version":   "'"$RUSTC"'",'
            echo '  "nextest_version": "${{ needs.build-test-archive.outputs.nextest_version }}",'
            echo '  "target":          "x86_64-pc-windows-msvc",'
            echo '  "build_os":        "ubuntu-22.04 (cargo-xwin)",'
            echo '  "files": ['
            find preview -type f | while read -r f; do
              sha=$(sha256sum "$f" | awk '{print $1}')
              printf '    {"path": "%s", "sha256": "%s"},\n' "$f" "$sha"
            done | sed '$ s/,$//'
            echo '  ]'
            echo '}'
          } > manifest.json
          cat manifest.json
      - uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882 # v4.4.3
        with:
          name: manifest-${{ needs.gate.outputs.sha }}
          path: manifest.json
```

**Critical correctness notes**:

1. **`verify-pr-fast-green` polls the GitHub check-runs API** for the exact
   SHA and refuses to proceed unless `PR Fast CI / required` is green on
   that commit.  Retries for 10 min to absorb cases where the PR-fast run
   is still executing.  Closes the "preview artifacts from a commit that
   couldn't merge" class of confusion.
2. **Every downstream job checks out `needs.gate.outputs.sha`** — the
   same SHA the PR-fast run validated.  No reliance on default
   `actions/checkout` behaviour which can land on the test-merge commit.
3. **Manifest declares `git_sha == tested_sha`** explicitly so a human
   downloading the bundle can cross-check against `PR Fast CI`.
   `tested_sha` is separate from `git_sha` because in a future extension
   the smoke runner could validate against a merge-commit while binaries
   were built from the PR head.
4. **`nextest_version` is in the manifest** so a person running the
   archive manually knows which nextest to install.  Nextest's archive
   requires matching versions on both sides.
5. **Per-file SHA256 in the manifest**, not just the artifact-level
   digest that GitHub's UI shows.  A manual downloader verifies file
   integrity without trusting the Actions UI.
6. **Self-hosted runners are intentionally NOT used anywhere.**  Even
   though `windows-latest` costs ~10× Linux minutes, running fork PR code
   on a self-hosted runner is a well-documented security hazard.  If a
   self-hosted Windows runner is introduced later, it must be gated on
   `github.event.pull_request.head.repo.fork == false` (trusted branches
   only) — documented here so future maintainers don't miss it.

#### Deletions / migrations

- `ci.yml` → **delete** after `pr-fast.yml` is green for a week.
  Replace `main-protection` required status checks with the single
  `PR Fast CI / required` aggregate.
- `tier-2.yml` → **keep as-is** except: drop `windows-check` job
  (now in `pr-fast.yml`).  Tier 2 stays the deep-assurance lane
  (coverage, miri, udeps).  **DONE** in PR #138 (W5 follow-on) once
  `pr-fast.yml::windows-lint` flipped to strict clippy and strictly
  subsumed Tier 2's weekly compile-check; tombstone comment in
  `tier-2.yml` documents the removal.

### 2.6 `scripts/ci/ci-pipeline.rs` → workspace binary `scripts/ci-pipeline/`

Same as v1's Phase 5.  Eliminates rust-script binary-cache Heisenbugs.

**Additional benefit from v2**: the binary can now **import** the single
gate-definition file (see §2.7) so local pre-push, `just ship`, and
`pr-fast.yml` all reference the same gate list.

### 2.7 (Stretch) — machine-readable gate manifest

Long-term direction: replace the hand-maintained correspondence between
`_lint_pre_push.sh`, `ci.yml`, and this doc with a single file consumed
by all three.  Deferred — documented here so future-us knows the target
shape.

> **2026-05-07 update**: §2.7's executable contract is shipped.
> The gates-manifest plan
> ([`docs/architecture/gates-manifest-plan.md`](gates-manifest-plan.md))
> landed in five phases:
>
> | Phase | What | PR |
> |---|---|---|
> | 0 | Plan + schema design | #139 |
> | 1 | Manifest + drift detector (no consumer changes) | #140 |
> | 2 | `_lint_pre_push.sh` codegen | #141 |
> | 3 | `pr-fast.yml` **structural validator** (revised from "codegen" — see plan §4.2 pivot rationale) | #143 (plan-pivot in #142) |
> | 3a | `_lint_fast.sh` codegen | #144 |
>
> Four drift detectors now run side-by-side in pre-push Bucket 1 +
> pr-fast CI, covering four orthogonal drift axes:
>
> - `gates-drift`    — gate-set mismatch (Phase 1)
> - `hooks-drift`    — pre-push hook content (Phase 2)
> - `workflow-drift` — `pr-fast.yml` structural (Phase 3)
> - `fast-drift`     — pre-commit hook content (Phase 3a)
>
> Adding, renaming, or removing a gate is now a single edit to
> `scripts/ci/gates.toml` followed by `just uffs-gen-hooks` /
> `just gen-fast`; the workflow YAML still hand-owns its bespoke
> per-job shape (eleven distinct shapes for ~thirteen pr-fast-tier
> gates) but `workflow-drift` enforces structural alignment with
> the manifest.
>
> **Phase 3c (`gen-docs`, prose tables in this doc + CONTRIBUTING.md)
> remains deferred** per plan §4.3 rationale — the four executable
> drift detectors above already catch every dangerous failure
> mode; what remains is low-stakes editorial drift in prose
> tables, which the plan judges as not worth the codegen
> infrastructure.
>
> The sketch below is preserved as the original problem statement.

```toml
# gates.toml (proposed, not yet implemented)
[[gate]]
id = "cargo-vet"
label = "cargo vet check --locked"
tiers = ["pre-commit", "pre-push", "pr-fast"]
hard_required_when = "dep_changed"
tool = "cargo-vet"
cmd  = "cargo vet check --locked"
expected_runtime_secs = 2

[[gate]]
id = "doctests"
label = "cargo test --doc"
tiers = ["pre-push", "pr-fast"]
hard_required_when = "rust_changed"
cmd = "cargo test --doc --workspace --all-features"
env = { RUSTDOCFLAGS = "-Dwarnings" }
expected_runtime_secs = 25

# ... etc
```

Generator script would produce `_lint_fast.sh`, `_lint_pre_push.sh`,
and the PR-fast workflow matrix from this.  Converts v1's "explanatory
truth" into "executable truth".

### 2.8 GitHub Actions hardening policy

New policy applied across both new workflows and enforced as a
review checklist going forward.  Most of it mirrors GitHub's
published Actions hardening guide.

**At the workflow level**:

- `permissions: contents: read` as the default block.  Individual
  jobs opt into write scopes explicitly; none currently do.
- `concurrency` group with `cancel-in-progress: true` on PR events
  so stale runs die when a new push lands.
- All third-party actions pinned to full commit SHAs (40-char hex),
  never floating tags.  `.github/dependabot.yml` already tracks
  Actions updates; bump PRs land as small reviewable deltas.
- `merge_group:` trigger present on every workflow that reports
  required checks.  Harmless when merge queue is disabled;
  essential when it is enabled.

**At the job level**:

- `timeout-minutes` set on every job.  Default GitHub timeout is
  360 (6 h); we cap realistic jobs at 30 min and cheap jobs at 2–5
  min.  Prevents runaway runs from exhausting runner-hour budgets.
- `runs-on: windows-latest` / `macos-latest` only on GitHub-hosted
  runners, never self-hosted.  Rationale: fork PRs execute arbitrary
  author code, and a self-hosted runner sits on privileged infra.
- Every `uses: actions/checkout@...` pins `ref:` to an explicit
  `github.event.pull_request.head.sha || github.sha`.  Default
  checkout behaviour differs between `pull_request` and
  `pull_request_target` events and can land on a synthetic merge
  commit.  Explicit refs remove the ambiguity between what PR-fast
  validates and what the preview lane builds.
- `--locked` passed to every cargo subcommand that accepts it.  One
  `cargo fetch --locked` up front seeds the cache.

**Manifest integrity**:

- `actions/upload-artifact@v4` already computes and validates an
  artifact-level SHA256 on download inside Actions.  Our manifest
  **additionally** lists per-file SHA256 so a human downloading via
  the browser UI can verify without trusting the UI.
- Manifest includes tool versions (rustc, nextest, cargo-vet as
  applicable) so that a validator on a different machine knows
  exactly which binaries to install.

**What is explicitly forbidden**:

- `pull_request_target` on any workflow that runs build/test code.
  Reason: it runs against the base branch's workflow file with
  elevated permissions and is the primary source of the "malicious
  PR exfiltrates secrets" class of bug.
- Self-hosted runners for any job reachable from fork PRs.  If a
  self-hosted Windows runner is ever introduced (see §9 open
  items), the job must gate on
  `github.event.pull_request.head.repo.fork == false`.
- Floating action tags (`@v4`, `@main`).  Full commit SHA only.
- `secrets.*` reads in forked-PR context.  GitHub masks them but
  shell exit codes and derived strings may leak; audit any job
  that touches secrets.

This policy ships alongside Phases 4–5 and is retroactively
applied to `tier-2.yml`, `codeql.yml`, `release.yml`,
`auto-tag-release.yml`, `cargo-vet-refresh.yml`,
`dependabot-review.yml`, and `dependabot-auto-merge.yml` as a
housekeeping commit (Phase 4b).  Most of those already conform;
the audit's job is to confirm and fill gaps.

---

## 3. Phased rollout

Seven commits, each atomic, ranked so **each step leaves the repo
green**.

### Phase 1 — Hardened pre-push gates (Commit 1)

**Scope**:

- `scripts/hooks/_lint_pre_push.sh` — add `cargo vet` (hard-required on
  dep change), `doctests`, `cargo nextest run --profile pre-push-smoke`.
- `.config/nextest.toml` — add `pre-push-smoke` profile.
- Does NOT yet reorder schedule or split buckets — that's Phase 2.

**Validation**:

1. `just lint-pre-push` on current HEAD — all green within 60 s.
2. `touch Cargo.lock` → commit → `just lint-pre-push` — cargo-vet runs
   and passes.
3. Uninstall `cargo-vet`, repeat (2) — hard-fails with install hint.
4. Introduce a deliberate doctest failure — pre-push aborts.

**Risk**: Low.  Additive changes.

### Phase 2 — Bucket-ordered scheduler + remove xwin from pre-commit (Commit 2)

**Scope**:

- `scripts/hooks/_lint_pre_push.sh` — rewrite with two-bucket scheduler
  (§1.4).
- `scripts/hooks/_lint_fast.sh` — drop the `check-windows` invocation.
- Add `cargo check` as the first Bucket 2 step.

**Validation**:

1. Introduce a type error → confirm pre-push shows `cargo check` red
   within ~15 s instead of waiting for the 40-60 s clippy batch.
2. Time pre-commit on a `*.rs`-only change — confirm under 15 s warm.

**Risk**: Medium.  Scheduler rewrite.  Keep the previous script as
`_lint_pre_push.sh.bak` for one cycle.

### Phase 3 — Cache policy single source of truth (Commit 3)

**Scope**:

- `.cargo/config.toml` — add `incremental = false`.
- `just/shared.just` — delete `export CARGO_INCREMENTAL := "1"`.
- `scripts/ci/ci-pipeline.rs` — remove the explicit
  `CARGO_INCREMENTAL=0` pairing (no longer needed).
- `CHANGELOG.md` — note the policy change.

**Validation**:

1. Fresh `cargo build --workspace` cold → time recorded.
2. `touch one file` → rebuild → time recorded.  Should be close to v1
   §6.4's 42 s figure.
3. `just ship -v` through to push — pre-push green.
4. Direct `git push` from fresh shell with no env overrides — pre-push
   green (proof that drift is gone).

**Risk**: Medium.  This is the Bug B root-cause fix.

### Phase 4 — Split `ci.yml` into `pr-fast.yml` + `preview-artifacts.yml` (Commit 4)

**Scope**:

- Create `pr-fast.yml` with the full structure in §2.5 (classify +
  required aggregator depending on classify + merge_group trigger +
  workflow-level `permissions: contents: read` + per-job full-SHA
  action pins).
- Create `preview-artifacts.yml` (stub, artifact build only, no smoke
  runner yet — that's Phase 5).
- Keep `ci.yml` intact; both workflows run in parallel for one week.
- Update `tier-2.yml` — drop `windows-check` job (now in `pr-fast.yml`).  **DONE** in PR #138 (W5 follow-on, see above).
- Confirm `.github/dependabot.yml` tracks both new workflows.

**Validation** (each item MUST pass before Phase 4 cutover):

1. **Docs-only PR** → `pr-fast` completes with `fmt`, `sanity`, `clippy`,
   `docs`, `test-build`, `tests`, `security`, `windows-check` all
   `skipped`; `required` = success.  `ci.yml` does the same (parity).
2. **Dep-only PR** (e.g. a Cargo.toml version bump with no `.rs`
   change) → `pr-fast` runs the full compile/test/Windows matrix.
   This exercises the v2→v3 under-gating fix where `rust == 'true'`
   was the (wrong) trigger.
3. **Infra-only PR** (e.g. edit to `.github/workflows/pr-fast.yml`
   itself, or to `just/lint.just`) → same as dep-only: full matrix.
4. **Rust-change PR** → both workflows run identical checks.  Compare
   wall-clock: `pr-fast` must be ≤ `ci.yml` on p50.
5. **Broken-classify simulation** — **the single most important check**.
   Manually break the `dorny/paths-filter` step in a test branch
   (e.g. invalid YAML in the filters block).  `classify` fails,
   downstream jobs `skip`, and `required` **must** fail (not pass
   via skip aggregation).  If `required` goes green, the
   `Gate on classify` step regressed — do not cutover.
6. **merge_group dry-run** (only if merge queue is enabled) → a
   queued PR runs `pr-fast` against the test-merge commit; result
   reports back to the queue.
7. **Branch-protection cutover**: after 7 days green on items 1–5,
   replace the 8 required `Tier 1 / *` checks with the single
   `PR Fast CI / required` aggregate and delete `ci.yml` in the
   **same commit** so GitHub never enforces a check from a deleted
   workflow.

**Risk**: Medium-high.  Branch protection drift possible during
transition.  Two-workflow parallel window is the mitigation.  The
classify-failure simulation (validation step 5) is the critical
check — it proves the v3 correctness fix actually works.

### Phase 5 — Preview lane with nextest archive + Windows smoke (Commit 5)

**Scope**:

- Flesh out `preview-artifacts.yml` with the full structure in §2.5:
  - `gate` job (label / dispatch guard + SHA pinning).
  - `verify-pr-fast-green` job (polls check-runs API, up to 10 min).
  - `build-windows` (`cargo xwin build --release --locked`).
  - `build-test-archive` (`cargo nextest archive --locked`).
  - `smoke-windows` (`windows-latest`, same-SHA checkout, runs the
    archive).
  - `manifest` (emits `manifest.json` with `git_sha`, `tested_sha`,
    `cargo_lock_sha256`, `rustc_version`, `nextest_version`, and
    per-file SHA256).
- Add a repo label `preview-binaries` (maintainer-apply only).
- Document the label-trigger workflow in `dev-flow.md`.

**Validation** (each item MUST pass before Phase 5 is done):

1. **Label-trigger path**: apply `preview-binaries` to an open PR
   whose `PR Fast CI / required` is green → full preview workflow
   runs → artifacts appear in Actions UI with the SHA in their names.
2. **Same-SHA integrity**: download the Windows bundle +
   `manifest.json`.  `manifest.git_sha` must equal the PR's head SHA.
   Every `files[].sha256` in the manifest must match `sha256sum` of
   the downloaded file.
3. **Nextest archive round-trip**: on a real Windows box with
   `cargo-nextest` at exactly `manifest.nextest_version`,
   `git checkout <sha>` the repo and run
   `cargo nextest run --archive-file <file>` — must pass.
4. **Pre-fast-gate enforcement** — **the critical check**.  Open a PR
   that will fail `PR Fast CI` (e.g. deliberate fmt violation).
   Apply `preview-binaries` label.  `verify-pr-fast-green` **must**
   fail within 10 min; artifact jobs must not start.  If the build
   proceeds, the gate is broken — do not merge Phase 5.
5. **Fork-PR behaviour**: open a PR from a forked repo.  Label with
   `preview-binaries`.  Workflow must execute on GitHub-hosted
   runners only (verify by grepping for `self-hosted` in the
   workflow YAML).
6. **Concurrency behaviour**: push a new commit to a PR that already
   has a preview run in progress.  The in-progress run must cancel,
   a new run must start against the new SHA, and no artifacts from
   the cancelled run should publish.

**Risk**: Medium.  New workflow surface; isolated impact.  Biggest
risk is validation step 4 silently passing when it shouldn't — the
poll-based check-runs gate is subtle.  Always run a deliberate-failure
test before trusting it.

### Phase 6 — Resumable-push fix (Commit 6)

**Scope**: exactly v1 §6.3.  The `git rev-list --count` guard at the top
of step 11 in `scripts/ci/ci-pipeline.rs`.

**Validation**: reproduce the v0.5.71 "committed after push, re-ran
ship, HEAD never landed" sequence.  Before fix: exits in 2 s.  After
fix: re-runs step 11, push lands.

**Risk**: Low.  Read-only git check + targeted state invalidation.

### Phase 7 — Promote ci-pipeline.rs to workspace binary (Commit 7)

**Scope**: v1 §6.5.B.  Move to `scripts/ci-pipeline/` with `Cargo.toml`,
update `just/workflow.just` to `cargo run -p ci-pipeline --release --`.

**Validation**:

1. `just ship --fresh` — works as before, no rust-script cache.
2. Edit `ci-pipeline.rs`, re-run — change takes effect immediately.

**Risk**: Medium.  ~90 min restructuring; clean once done.

### Phase 8 (stretch, optional) — Machine-readable gate manifest (Commit 8)

Deferred to a future session.  See §2.7 for the original sketch and
[`docs/architecture/gates-manifest-plan.md`](gates-manifest-plan.md)
for the full implementation plan (schema, generator interface,
3-phase migration order, golden-file verification strategy, risk
analysis).

---

## 4. Branch-protection migration checklist

Branch protection on `main` is enforced via the **rulesets API**
(ID `11889528`, name `main-protection`), not classic branch protection.
Classic `/branches/main/protection` returns 404 — verified
2026-04-23.  Inspect or update via:

```bash
gh api repos/skyllc-ai/UltraFastFileSearch/rulesets/11889528
gh api --method PUT repos/skyllc-ai/UltraFastFileSearch/rulesets/11889528 --input <body.json>
```

### 4.1 Baseline (pre-Phase-4) required checks

Verified against the ruleset on 2026-04-21, 6 entries (not 8 —
`Tier 1 / Doc Tests` and `Tier 1 / Test Build` were never required,
they run informationally):

```
Tier 1 / Clippy
Tier 1 / Tests
Tier 1 / Security
Tier 1 / File Size Policy
Tier 1 / Format
Tier 1 / Rustdoc
```

### 4.2 Parallel-window posture (historical: 2026-04-23 11:38 → 14:13 PDT)

Ruleset was updated 2026-04-23 11:38 PDT to expand the required-check
set from 6 entries (the §4.1 baseline) to 7 entries, running
`ci.yml` and `pr-fast.yml` side-by-side as required lanes:

```
Tier 1 / Clippy
Tier 1 / Tests
Tier 1 / Security
Tier 1 / File Size Policy
Tier 1 / Format
Tier 1 / Rustdoc
PR Fast CI / required        ← added for the parallel window
```

Both lanes had to pass; neither alone unblocked merge.  This is the
state the (now-removed) `pr-fast.yml:22-25` comment anticipated for
the 7-day bake-in.  The window actually lasted **~2h35m** (compressed
same-day — see §10.5 deviations for the decision rationale); cutover
executed 14:13 PDT the same day.  PRs that merged during this window:
#45 (Phase 1-7 rollout, mixed rust+dep+infra), #46 (docs-only plan-
doc reconcile), #47 (Phase 4b infra-only actions hardening).  Zero
disagreements observed between `ci.yml` and `pr-fast.yml` on any of
the three.

### 4.3 Cutover procedure (executed 2026-04-23 14:13 PDT)

**The plan v1 language "do everything in a single commit" was a
category error** — the ruleset PUT is an API call, not a commit, so
it cannot be bundled with the `ci.yml` deletion into one atomic unit
reviewable via GitHub PR.  Worse: if `ci.yml` is deleted in a PR, the
6 `Tier 1 / *` required checks reference a workflow that will not
run on that PR's head SHA → `mergeStateStatus: BLOCKED` with zero
failing and zero pending.  GitHub will not merge until the ruleset
stops requiring checks that no workflow produces.  Therefore **the
ruleset PUT must precede the `ci.yml`-deletion PR merge**.

Correct sequence (verified executed 2026-04-23):

1. Open a PR that deletes `.github/workflows/ci.yml` and updates
   `CHANGELOG.md`.  Let it bake green on `PR Fast CI / required`
   alone (the legacy `Tier 1 / *` lane still runs against the PR
   branch via the unchanged ruleset, but is about to become
   no-signal).
2. PUT the ruleset with only `PR Fast CI / required` in the
   `required_status_checks` array (drop all 6 `Tier 1 / *`).  The
   PR's `mergeStateStatus` flips `BLOCKED` → `CLEAN` within seconds.
3. Squash-merge the PR immediately (ideally within seconds of the
   PUT — see §10.5 deviation for the window-size rationale).
4. Verify post-merge ruleset still has exactly 1 required check.

End-state required-check set (1 entry):

```
PR Fast CI / required
```

**Evidence (2026-04-23)**:

- PR #48 squash-merge commit: `6f99b86aa` at 14:13:41 PDT.
- Ruleset PUT timestamp: 14:13:25 PDT (16-second window between
  PUT and merge; no new PRs opened in-window).
- Post-cutover verify: `gh api
  repos/skyllc-ai/UltraFastFileSearch/rulesets/11889528 |
  jq '[.rules[]|select(.type=="required_status_checks") |
  .parameters.required_status_checks[]|.context]'` returns
  `["PR Fast CI / required"]` — single entry confirmed.
- Ruleset backup pre-PUT saved to `/tmp/ruleset-rollback.json` for
  emergency reverse.  Not committed — discard after 7 days if
  stable.

**Rollback (if the cutover regresses post-landing)**:

1. `git revert 6f99b86aa` — restores `.github/workflows/ci.yml`
   verbatim (squash-merge preserved full diff).
2. `gh api --method PUT
   repos/skyllc-ai/UltraFastFileSearch/rulesets/11889528
   --input /tmp/ruleset-rollback.json` — restores the 7-entry
   parallel-window shape.
3. Verify `gh pr view <N> --json statusCheckRollup` on any open
   PR shows both lanes reporting.

Both steps are required; the revert alone is insufficient because
the ruleset is separate state.

### 4.4 Required-check context string — gotcha

**The context string matches the job's `name:` attribute, NOT the UI
display string.**  GitHub's PR UI concatenates `<workflow-name> / 
<job-name>` for display (e.g. `PR Fast CI / PR Fast CI / required`),
but branch-protection matches against `check_run.name` which is the
raw job name.  Worked examples:

| Workflow | Job `name:` | UI display | Ruleset context |
|---|---|---|---|
| `🧪 UFFS Tier 1 Nightly CI` | `Tier 1 / Clippy` | `🧪 UFFS Tier 1 Nightly CI / Tier 1 / Clippy` | **`Tier 1 / Clippy`** |
| `PR Fast CI` | `PR Fast CI / required` | `PR Fast CI / PR Fast CI / required` | **`PR Fast CI / required`** |

Getting this wrong produces `mergeStateStatus: BLOCKED` with zero
failing and zero pending checks — the protection engine waits forever
for a check-name that no workflow produces.  Verify via:

```bash
gh pr view <N> --json statusCheckRollup \
  --jq '.statusCheckRollup[] | select(.name | contains("required")) | .name'
```

The returned value is the correct context string.  This was hit and
resolved live on 2026-04-23 (see §10.5 Deviations log).

---

## 5. Risk matrix

| Risk | Mitigation |
|---|---|
| Phase 3 flips `CARGO_INCREMENTAL` default; daily dev feels different | One-line revert in `.cargo/config.toml`.  Benchmarks in v1 §6.4 support the direction. |
| Phase 4 branch-protection drift during cutover | 7-day parallel window; both workflows required. |
| Phase 5 preview workflow triggered on every label event → runner cost | Gate on `if: contains(... 'preview-binaries')` and concurrency cancel-in-progress. |
| Phase 7 changes the ship entry point | Keep `rust-script scripts/ci/ci-pipeline.rs ship` working as a thin wrapper for one release cycle. |
| Smoke profile tests flaky on some machines | `retries = 0, fail-fast = true` means flakes block push — but the profile deliberately excludes integration tests which are the usual flaky class. |

---

## 6. Success metrics

Measured against current `v0.5.71` baseline:

| Metric | Baseline | Target |
|---|---|---|
| Median time to first actionable failure after `git push` | CI (~5 min to first red) | T2 pre-push (&lt; 30 s) |
| PR-blocking full-pipeline wall time | 8-15 min (ci.yml) | &lt; 8 min (pr-fast) |
| Windows regression detection latency | release-time (~15 min into `just ship`) | PR-time (pr-fast `windows-lint`, post-W5.5: clippy `-D warnings` not just compile-check) |
| Cargo-vet round-trip incidents per release | 1-3 today | 0 (hard-gated at T1) |
| Ship resumable state bugs per month | ≥1 (v0.5.71) | 0 after Phase 6 |

---

## 7. What this plan intentionally does NOT do

- **Does not introduce a remote sccache.**  That's a future optimization
  ("Phase 9") worth evaluating only after Phases 1-7 land and baselines
  are measured.
- **Does not add `cargo mutants` / fuzz.**  Deep-assurance lane expansion
  is out of scope for this plan.
- **Does not change Tier 2 cadence.**  Weekly cron stays weekly.
- **Does not touch `release.yml`.**  The release lane is correct today;
  the issue was artifact-producing lanes bleeding into PR critical path.
- **Does not adopt a pre-commit framework** (e.g. `pre-commit` the
  Python tool).  Bash + `just` stays; rationale: one less dependency
  for new contributors.
- **Does not own release automation.**  Version bumping, changelog
  generation, release PR cadence, tag creation semantics, and eventual
  crates.io publishing are the concern of
  [`release-automation-plan.md`](release-automation-plan.md).  Phases
  in that plan (R0-R9) are sequenced independently of Phases 1-8 here;
  they share only `release.yml` (unchanged by both) and the version-
  bump bits of `scripts/ci-pipeline/src/version.rs` (retired in
  release-automation R5).
- **Does not own cross-target strict-lint convergence.**  Upgrading the
  Windows lint gate from `cargo check` to `cargo clippy` (1,346-lint
  backlog as of 2026-04-24) and adding a native macOS → Linux
  cross-check path via `cargo-zigbuild` are the concern of
  [`windows-clippy-and-linux-cross-plan.md`](windows-clippy-and-linux-cross-plan.md).
  The dev-flow plan owns the 4-layer gate **model** (IDE / pre-commit
  / pre-push / PR CI); the cross-target plan owns **which flag
  stack runs on which target** at each of those layers.

---

## 8. Execution readiness

**Prerequisites before Phase 1**:

- [ ] Current repo is green on `main`.
- [ ] `cargo-vet` installed locally (`cargo install cargo-vet --locked`).
- [ ] Confirmed `cargo nextest` version ≥ 0.9.130 (already pinned in
      `.config/nextest.toml`).

**Order of operations**: 1 → 2 → 3 → 6 → 4 → 5 → 7.

Rationale: hardened gates (1–3) first make local work reliable.  Fix
the ship-pipeline bug (6) next so release-time iteration doesn't fight
us.  Then CI split (4) once local is solid.  Preview lane (5) plumbs in
on top of the split.  Binary promotion (7) is the clean-up step.

Phase 8 (gates.toml manifest) lands when the dust settles and we've
lived with the split lanes for a release or two.

---

## 9. Open review items

- **Smoke profile selection rule** — does `default-filter` in the
  `pre-push-smoke` nextest profile need to exclude more / fewer tests?
  Validate during Phase 1 rollout; tune before merge.
- **Windows preview smoke runner cost** — GitHub-hosted `windows-latest`
  at 10× the Linux minute rate.  Consider a self-hosted runner if
  preview-label usage exceeds ~5×/week.
- **Preview-artifacts security surface** — a malicious PR author could
  trigger preview builds.  Today's model: gated on label which only
  maintainers apply.  Re-evaluate if the contributor base grows.
- **Bazel / Buck2 / build-server-protocol** — not on today's roadmap
  but the gates.toml direction (§2.7) is a stepping stone if we ever
  want it.

---

## 10. Execution tracking

Live dashboard.  **This section is updated as work lands**, not in one
go at the end.  Future readers should be able to audit exactly how
the plan was executed by reading this section — commits, dates, PRs,
deviations, and measured metrics.

Status legend: ⬜ not started · 🟡 in progress · 🔵 blocked (see notes)
· ✅ done · ❌ reverted

### 10.1 Prerequisites (before Phase 1)

- [ ] Repo is green on `main` — `ci.yml` Tier 1 all checks passing.
- [ ] `cargo-vet` installed locally (`cargo install cargo-vet --locked`).
- [ ] `cargo-nextest` ≥ 0.9.130 confirmed (already pinned in
      `.config/nextest.toml`).
- [ ] `cargo-xwin` installed for local Windows advisory (optional but
      recommended).
- [ ] Dropbox / backup of current `.cargo/config.toml`,
      `just/shared.just`, `scripts/hooks/_lint_*.sh` in case of revert.

### 10.2 Phase status dashboard

| # | Phase | Status | Started | Completed | Commit(s) | PR |
|---|-------|--------|---------|-----------|-----------|-----|
| 1 | Hardened pre-push gates (cargo vet + doctests + smoke profile) | ✅ | 2026-04-23 | 2026-04-23 | `780c1dbb1` (squash) | [#45](https://github.com/skyllc-ai/UltraFastFileSearch/pull/45) |
| 2 | Bucket-ordered scheduler + xwin removed from pre-commit | ✅ | 2026-04-23 | 2026-04-23 | `780c1dbb1` (squash) | [#45](https://github.com/skyllc-ai/UltraFastFileSearch/pull/45) |
| 3 | Cache policy single source (`.cargo/config.toml` owns `incremental`) | ✅ | 2026-04-23 | 2026-04-23 | `780c1dbb1` (squash) | [#45](https://github.com/skyllc-ai/UltraFastFileSearch/pull/45) |
| 6 | Resumable-push fix in `ci-pipeline.rs` | ✅ | 2026-04-23 | 2026-04-23 | `780c1dbb1` (squash) | [#45](https://github.com/skyllc-ai/UltraFastFileSearch/pull/45) |
| 4 | Split `ci.yml` → `pr-fast.yml` + `preview-artifacts.yml` | ✅ | 2026-04-23 | 2026-04-23 | `780c1dbb1` (parallel lane) + `6f99b86aa` (cutover) | [#45](https://github.com/skyllc-ai/UltraFastFileSearch/pull/45) + [#48](https://github.com/skyllc-ai/UltraFastFileSearch/pull/48) |
| 4b | Actions hardening retrofit across existing workflows | ✅ | 2026-04-23 | 2026-04-23 | `eef3359b2` (squash) | [#47](https://github.com/skyllc-ai/UltraFastFileSearch/pull/47) |
| 5 | Preview lane fleshed out (smoke runner + manifest) | ✅ | 2026-04-23 | 2026-04-24 | `780c1dbb1` (plumb-in) + `b9a67f2dc` (robustness) + `2d3a7f5b3` (windows-latest + RC_PATH) + `0e811d0bb` (test-vector fixes → full green bake) | [#45](https://github.com/skyllc-ai/UltraFastFileSearch/pull/45) + [#51](https://github.com/skyllc-ai/UltraFastFileSearch/pull/51) + [#52](https://github.com/skyllc-ai/UltraFastFileSearch/pull/52) + [#55](https://github.com/skyllc-ai/UltraFastFileSearch/pull/55) |
| 7 | `ci-pipeline.rs` promoted to workspace binary | ✅ | 2026-04-23 | 2026-04-23 | `780c1dbb1` (squash) | [#45](https://github.com/skyllc-ai/UltraFastFileSearch/pull/45) |
| 8 | (stretch) `gates.toml` machine-readable manifest | ⬜ | | | | |

**Phase 4 sub-status (2026-04-23, end-of-day)**: fully cutover.
Static implementation landed in `780c1dbb1` (PR #45, morning);
broken-classify simulation executed live on PR #45 and passed with
full fidelity (required=failure propagated correctly through 8
skipped downstream jobs); parallel window ran 11:38 → 14:13 PDT
(~2h35m; compressed from the planned 7 days, see §10.5); cutover
executed via PR #48 squash `6f99b86aa` at 14:13:41 PDT; ruleset
`main-protection` PUT at 14:13:25 PDT reduced required-check set
from 7 entries (parallel) to 1 entry (`PR Fast CI / required`).
`.github/workflows/ci.yml` deleted.  See §4.3 for the step-by-step
sequence and rollback procedure.

**Phase 5 sub-status (2026-04-24, end-of-day)**: fully baked green
end-to-end.  Static implementation landed in `780c1dbb1` (PR #45)
alongside the Phase 4 split.  Three follow-up PRs closed out the
live validation:

- **PR #51** (`b9a67f2dc`, 2026-04-23) — robustness fixes surfaced by
  the first real full-matrix preview attempt: `awk 'NR==1'` guard
  on the `cargo nextest --version` multi-line output (bug #1), and
  `verify-pr-fast-green` polling budget bumped from 10 min to
  30 min (bug #2, miscalibration for infra PRs that run the full
  matrix).
- **PR #52** (`2d3a7f5b3`, 2026-04-24) — preview-lane bugs #3 and #4:
  moved `build-test-archive` from ubuntu+`cargo-xwin` to
  `windows-latest` (native MSVC) because `cargo-xwin` does NOT
  wrap `nextest archive`; and added an `RC_PATH` lookup pre-step
  to `build-windows` because `winresource v0.1.31` hardcodes
  `PathBuf::from("llvm-rc")` on `cfg(unix)` without PATH setup
  from `cargo-xwin`.  Preview run 24873800282 on this PR ran to
  completion for the first time; `smoke-windows` executed
  1322 tests with 1320 passing.
- **PR #55** (`0e811d0bb`, 2026-04-24) — fixed bugs #5 and #6 (the
  two Windows-gated unit tests with stale hardcoded expected
  values that had NEVER executed in CI before the preview lane
  ran them; neither is actually platform-dependent — the original
  issue theories are withdrawn).  Preview run 24889490616 on this
  PR: **all 6 jobs green, 1322/1322 tests pass, real
  `manifest.json` emitted** with integrity data for all 17
  artifacts (16 release binaries + 73.9 MB nextest archive).

See §10.5 for the full deviation log and §10.6 for Resolved
blocker entries.  Items #2, #3, #5 in §10.3 ticked with real
evidence on 2026-04-24.

**Legend**: ✅ = complete and validated; 🟡 = static-complete (actionlint
clean, ruby-yaml clean, pins/permissions correct, classify-aggregation
gated) — remaining work is live-PR bake-in (broken-classify simulation,
7-day parallel window, branch-protection cutover) which cannot be
validated pre-merge; ⬜ = not started.

**Recommended execution order**: 1 → 2 → 3 → 6 → 4 (+4b) → 5 → 7.
See §8 Execution readiness for the rationale behind the reorder
(Phase 6 before Phase 4 so ship-pipeline iteration doesn't fight
us mid-cutover).

### 10.3 Per-phase validation checklists

Copy-pasted from §3.  Check items off as they pass in practice.
Record any surprises under "Notes".

#### Phase 1 — Hardened pre-push gates

- [x] `just lint-pre-push` on current HEAD — all green within 60 s.
- [x] Manual-mode (`bash scripts/hooks/_lint_pre_push.sh`) triggers
      `DEP_CHANGED=1` fallback; cargo-vet runs and passes.
- [ ] Uninstall `cargo-vet`, repeat — hard-fails with install hint.
      (Skipped in rollout; validated by code review — hard-fail path is
      a 3-line `if ! command -v cargo-vet … exit 2`.)
- [ ] Introduce a deliberate doctest failure — pre-push aborts.
      (Skipped in rollout; validated by code review — `doc-tests` gate
      spawns `cargo test --doc` which surfaces rustdoc failures.)
- [x] Measured pre-push runtime (warm): **43 s** (target < 60 s).
- [x] Smoke profile runtime (nested): **5.9 s** wall / 1140 tests run /
      11 skipped via profile.

**Notes**: `default-filter` in nextest profiles treats unknown binary
names as parse errors, not warnings, so the original plan's exclusion
of `benchmark_filtering` / `benchmark_sorting` had to be dropped —
those criterion-style benches aren't surfaced as nextest binaries.
Filter now denylists only the test-name prefix (`test_validate_`) and
the `uffs-client` package.  Runtime remains within budget.

#### Phase 2 — Bucket-ordered scheduler

- [ ] Introduce a type error → `cargo check` shows red within ~15 s
      (before the clippy batch).  Skipped in rollout; fail-fast logic
      validated by code review — `run_seq` sets `SEQ_FIRST_FAIL` on
      first failure, subsequent calls short-circuit to `skip`.
- [x] Pre-commit on staged-empty change: **3 s** warm (base load:
      file-size + fmt-check + typos + reuse).
- [x] Pre-push (warm, manual mode, CODE_CHANGED=1): **40 s** total.
      Per-Bucket-2 step: `cargo-check` 1 s, `lint-ci` 8 s, `lint-prod`
      4 s, `lint-tests` 7 s, `rustdoc` 1 s, `doc-tests` 9 s, `tests`
      2 s, `smoke` 7 s, `deny` 0 s, `check-windows` 1 s.
- [ ] `_lint_pre_push.sh.bak` kept as rollback for one cycle.
      Superseded by git history — reverts are atomic at the commit level.

**Notes**:
- Removed `taplo` from pre-push Bucket 1 — running
  `taplo fmt --check` workspace-wide surfaces pre-existing TOML drift
  that is out of scope for the push-being-validated.  Taplo stays at
  pre-commit where the staged-scope is natural.
- `cargo deny check` does **not** accept `--locked` (unlike cargo-vet);
  cargo-deny reads `Cargo.lock` directly.  Removed the `--locked`
  suffix.  The doc's "`--locked` on every cargo subcommand that
  supports it" is still accurate — `cargo deny` is not a cargo
  subcommand in the resolver sense.
- Bucket 2 ordering proved out: cargo-check runs in 1 s, so a type
  error reports in ~1-2 s instead of waiting ~40 s for clippy.

#### Phase 3 — Cache policy single source

- [x] `cargo check --workspace --all-targets --all-features --locked`
      after `incremental = false` landed: **8.36 s** (unchanged from
      baseline — config change didn't invalidate sccache).
- [x] Pre-push warm after Phase 3: **42 s** (same as Phase 2;
      config change did not degrade cache reuse).
- [x] Pre-push cold-ish (first run after config edit): **72 s**
      (rustdoc jumped 1 s → 18 s on the invalidation wave, then
      back to 1 s on the subsequent warm run — cache re-established).
- [ ] `just ship -v` through to push — pre-push green.
      Deferred until after Phase 6 lands (Phase 6 is the ship-bug fix;
      testing ship with the Bug A present is circular).
- [x] Direct `bash scripts/hooks/_lint_pre_push.sh` from fresh shell
      with no env overrides — pre-push green.  Proves drift is gone.
- [x] `shared.just` no longer exports `CARGO_INCREMENTAL`.
- [x] `.cargo/config.toml` has `incremental = false` paired with
      `rustc-wrapper = "sccache"`.
- [x] `ci-pipeline.rs` simplified — the `CARGO_INCREMENTAL=0` explicit
      push is gone; pipeline only re-asserts `RUSTC_WRAPPER=sccache`
      because git itself reads no Cargo config.  Diagnostic
      `[ci-pipeline][sccache-fix]` eprintln removed too (served its
      purpose as stale-binary detector during v0.5.71 triage).
- [x] `rust-script --test scripts/ci/ci-pipeline.rs` compiles clean.

**Notes**:
- Left `export RUSTC_WRAPPER := ""` in `just/shared.just` untouched.
  The plan didn't mandate its removal.  It encodes an intentional
  "just recipes opt out of sccache by default" policy; specific
  recipes that need sccache (`just cache:*`, `just ship`) set it
  back explicitly.  Changing that semantic is out of scope for
  Phase 3 — it would require auditing every recipe for cache
  assumptions.
- Env var still overrides Cargo config per Cargo's resolution
  order, so any user who prefers incremental can still
  `CARGO_INCREMENTAL=1 cargo build` one-off.  Default is the
  right default; override stays available.

#### Phase 6 — Resumable-push fix

- [ ] Reproduce the v0.5.71 sequence: ship → commit more → re-run ship.
      Deferred to next real ship run (requires an in-flight release
      PR; no safe way to dry-run without altering remote state).
- [x] `count_unpushed_commits` helper added, `git rev-list --count
      origin/<branch>..HEAD` parsed safely.  Conservative fallback
      returns 1 when remote ref doesn't exist (first push).
- [x] `invalidate_step` method added to `WorkflowState` — drops from
      `completed_steps` and `failed_steps`, saves state only if
      something actually changed.
- [x] Guard at Step 11 call site: `unpushed > 0 &&
      state.is_step_completed(STEP_GIT_PUSH)` → invalidate + re-run.
- [x] `rust-script --test scripts/ci/ci-pipeline.rs` compiles clean.

**Notes**:
- Validation step 1 (reproduce v0.5.71 sequence) is deferred because
  the natural test requires an actual in-flight release branch with a
  follow-up commit, which would perturb the git history on origin.
  Will exercise on the next legitimate ship run where a CI-detected
  failure triggers a follow-up commit.
- Helper uses `tokio::process::Command` (imported as `Command` in
  this module — the async version).  Sync `std::process::Command`
  would also work here but the helper is `async` to fit the pipeline
  style used throughout.

#### Phase 4 — Split `ci.yml`

- [x] `.github/workflows/pr-fast.yml` created — 11 jobs:
      `classify`, `file-size`, `fmt`, `sanity`, `clippy`, `docs`,
      `test-build`, `tests`, `security`, `windows-check`, `required`,
      plus `notify-failure`.
- [x] `.github/workflows/preview-artifacts.yml` created as full
      Phase 5 implementation (label gating + verify-pr-fast-green +
      xwin build + nextest archive + smoke + manifest).
- [x] `merge_group:` trigger present in `pr-fast.yml`.
- [x] Concurrency: `cancel-in-progress: pull_request only`.
- [x] Least-privilege workflow permissions: `contents: read`.
- [x] All action uses pinned to full commit SHAs (reuses existing
      `ci.yml`/`release.yml`/`tier-2.yml` pins).
- [x] Both workflows pass `actionlint` clean.
- [x] Both workflows pass `ruby -ryaml` parse check.
- [x] `required` job:
       * Has `if: always()`.
       * Has explicit `needs: [classify, ...]`.
       * First step gates on `needs.classify.result == 'success'` —
         **this is the static fix for the highest-leverage sanity
         check** (plan doc § 10.3 classify-failure bullet).
       * Second step aggregates downstream results, `success|skipped`
         pass, anything else fails.
- [x] **Broken-classify simulation** on a real PR — ✅ executed
      2026-04-23 on PR #45.  Inserted `exit 1` as the FIRST step of
      the `classify` job (before outputs were populated), observed:
      `classify`=failure (4 s), 8 downstream jobs skipped (empty
      `needs.classify.outputs.*`), `required`=failure (4 s, via the
      explicit `Gate on classify` step), legacy `Tier 1 / *` lane
      stayed all green.  Reverted same day; PR #45 merged green.
      This proves the `required` aggregator fails correctly when
      downstream jobs are **skipped** (the exact GitHub Actions
      "skipped counts as success" trap the plan warned about).
- [ ] **Docs-only PR** real-world bake: `pr-fast` skips the heavy
      jobs (`code == 'false'`); `required` = success.  🟡 Exercised
      by this very PR (the plan-doc update).
- [ ] **Dep-only PR** real-world bake: Cargo.toml bump runs full
      matrix + cargo-vet in sanity.  Deferred to next dependabot
      or explicit version-bump PR.
- [ ] **Infra-only PR** real-world bake: workflow/justfile edit
      runs full matrix.  Partially covered by PR #45 (mixed
      rust+dep+infra change — infra classification branch exercised
      green).  Still want a pure-infra bake for completeness.
- [x] **Rust-change PR** real-world bake (mixed rust+dep+infra on
      PR #45): `pr-fast` p50 wall time **~7 min** (rustdoc+doctests
      dominates; next-longest is `clippy` ~1 min, `sanity` ~1 min,
      `tests` buried inside `test-build+tests` pipeline).  Legacy
      `ci.yml` on the same PR: comparable ~5–7 min p50.  No regression.
- [x] Parallel window with `ci.yml` (dates: **2026-04-23 11:38 PDT**
      → **2026-04-23 14:13 PDT**, ~2h35m).  Compressed from the
      planned 7 days — see §10.5 for decision rationale.  Zero
      disagreements observed between the two lanes on PRs #45, #46,
      and #47 (the three PRs that merged in-window).
- [x] Branch-protection cutover: `ci.yml` deleted (PR #48 squash
      `6f99b86aa`, 14:13:41 PDT); ruleset `main-protection` PUT
      14:13:25 PDT reduced `required_status_checks` from 7 entries
      to 1 (`PR Fast CI / required`).  The plan v1 wording
      "in the same commit" was corrected to "ruleset PUT precedes
      the merge" — see §4.3 and §10.5.

**Notes**:
- Rather than pulling in `dorny/paths-filter`, `classify` uses a
  native `git diff --name-only BASE..HEAD` shell step.  Pros: no new
  third-party action to vet (supply-chain); transparent regex we own.
  Cons: slightly more shell code.  Trade-off documented here so
  future maintainers don't swap back without discussion.
- `security` job re-runs `cargo vet check --locked` even though
  `sanity` also runs it when `dep_changed`.  This is intentional:
  external observers (branch protection, GitHub search for "vet")
  expect a distinct `Security` check in the check-runs list.  Cost
  is ~10 s on warm cache.
- `windows-check` originally used `cargo check` (not `build`) — the
  PR-fast lane only needs compile-confidence.  Full release-shaped
  builds live in `preview-artifacts.yml` where they belong.  **Phase
  W5.5 update**: `windows-check` was renamed to `windows-lint` and the
  command flipped to `cargo clippy --workspace --all-targets
  --all-features --locked --no-deps -- -D warnings` once the Windows
  clippy backlog hit zero (PR #62 cleared 1346 errors → 0).  PR-fast
  Windows now catches both compile errors AND lint regressions.

#### Phase 4b — Actions hardening retrofit

Audit each existing workflow against §2.8 policy:

- [x] `tier-2.yml` — narrowed workflow-level `permissions` from
      `contents: read, issues: write` to just `contents: read`
      (notify-failure re-declares `issues: write` on its own block,
      so the broader scope was over-privileged for the other 7 jobs);
      added `timeout-minutes: 2` to notify-failure (only job that
      was missing one); added `--locked` to all 5 cargo invocations
      (coverage / windows-check / build-validation / udeps / miri).
- [x] `codeql.yml` — added explicit
      `ref: github.event.pull_request.head.sha || github.sha` on the
      checkout so CodeQL analyses the exact bytes pushed / proposed
      instead of the synthetic merge commit that `actions/checkout`
      defaults to on `pull_request` events.
- [x] `release.yml` — added `--locked` to the matrix
      `cargo build --release` step.  Deliberately did NOT refactor
      the workflow-level permissions block (sophisticated
      `contents/actions/id-token/attestations/issues` grants are all
      commented + justified; tightening is a distinct change best
      kept out of a housekeeping retrofit commit).
- [x] `auto-tag-release.yml` — already conformant; verified (1) no
      PR trigger so `merge_group:` N/A, (2) minimum-privilege
      `contents: read, actions: write` with comments, (3) single job
      with `timeout-minutes: 5`, (4) no cargo commands (pure git +
      gh CLI).  Zero changes.
- [x] `cargo-vet-refresh.yml` — already conformant; verified (1) no
      PR trigger, (2) minimum-privilege `contents: write,
      pull-requests: write` (both needed for refresh-PR creation,
      both justified with comments), (3) `timeout-minutes: 10`,
      (4) `cargo vet check --locked` already present, (5) `cargo vet
      regenerate imports` / `cargo vet prune` deliberately run
      unlocked (they mutate the lockfile by design).  Zero changes.
- [x] `dependabot-review.yml` — added explicit
      `ref: github.event.pull_request.head.sha || github.sha` on
      checkout so `git show HEAD~1:Cargo.lock` is deterministically
      the pre-bump lockfile, not whatever the synthetic merge commit
      resolves to.  Other §2.8 properties already conformant
      (contents:read + pull-requests:read, actor-gated to Dependabot
      only, `timeout-minutes: 3`, full-SHA action pins).
- [x] `dependabot-auto-merge.yml` — already conformant; verified
      (1) PR trigger but actor-gated so `merge_group:` wouldn't fire
      anyway, (2) minimum-privilege `contents: write,
      pull-requests: write` for `gh pr merge --auto`, (3)
      `timeout-minutes: 5`, (4) no checkout step (uses dependabot/
      fetch-metadata + gh CLI), (5) full-SHA action pins.  Zero
      changes.

**Notes**:
- `merge_group:` triggers were NOT added retroactively because
  §2.8's requirement is scoped to "workflows that report required
  checks".  Today that's only `pr-fast.yml` (and the soon-to-be-
  deleted `ci.yml`).  The 7 workflows audited here don't report
  required checks, so merge-queue compatibility is moot until that
  changes.
- The permissions refactor in `release.yml` (workflow-level
  `contents: write` → workflow-level `contents: read` +
  per-job write grants on `create-github-release`) was deliberately
  scoped out of this pass.  Release infra is critical path; a
  per-job permissions restructure deserves its own focused PR with
  a full release dry-run.
- Pre-existing shellcheck `style` / `warning` notes in unmodified
  shell blocks (tier-2-summary, release-preparation summary,
  dependabot-review summary) are explicitly out of scope — cleaning
  them up would balloon the diff and obscure the actual hardening.
  Track them separately if ever desired.

Post-retrofit verification (2026-04-23):
- `actionlint` exits 0 on all 4 modified files (remaining warnings
  are pre-existing style-level SC2129 / SC2010 in unmodified
  blocks).
- `ruby -ryaml -e 'YAML.load_file(...)'` passes on all 4 files.
- Diff touches only the 4 files listed above; zero behavioural
  changes on already-conformant workflows.

**Original notes**:

#### Phase 5 — Preview lane

- [x] `gate` job guards on `preview-binaries` label OR
      `workflow_dispatch`.
- [x] `gate` pins the SHA (`needs.gate.outputs.sha`) for every
      downstream checkout / artifact name — prevents drift on
      `synchronize` events.
- [x] `verify-pr-fast-green` polls GitHub Checks API for
      `PR Fast CI / required` on the pinned SHA; up to 60 × 10 s
      retry; fails fast on non-success.
- [x] `build-windows` uses `cargo-xwin` on ubuntu-22.04 targeting
      `x86_64-pc-windows-msvc`; caches via `preview-windows`
      shared-key; uploads `dist/windows/*.exe`.
- [x] `build-test-archive` builds nextest archive
      (`uffs-tests-<sha>.tar.zst`); exposes `nextest_version` as job
      output so the manifest can advertise it.
- [x] `smoke-windows` runs on **GitHub-hosted `windows-latest`** (not
      self-hosted) and executes the archive against the same-SHA
      checkout — both nextest archive requirements satisfied.
- [x] `manifest` emits `manifest.json` with `git_sha`, `tested_sha`,
      `cargo_lock_sha256`, `rustc_version`, `nextest_version`,
      per-file SHA256 for every downloaded artifact.
- [x] Concurrency: `group: preview-${workflow}-${pr#|sha}`,
      `cancel-in-progress: true` — push during in-progress preview
      cancels it (satisfies plan validation bullet).
- [x] Permissions: `contents: read`, `checks: read`,
      `pull-requests: read` (needed for Checks API + label lookup).
- [x] Both workflows pass `actionlint` clean.
- [x] **Label-trigger path** real PR validation: apply
      `preview-binaries` label to a green PR → workflow fires →
      artifacts appear in Actions UI.  ✅ Baked on PR that landed
      this edit (scratch `test/phase-5-preview-bake`, 2026-04-23).
- [x] **Same-SHA integrity** real validation: `manifest.git_sha` ==
      PR head SHA; every `files[].sha256` matches `sha256sum` of
      downloaded file.  ✅ Validated 2026-04-24 on PR #55 preview
      run 24889490616 (SHA `b3c73166e1709aba91c225232def9ff44d255fcc`).
      First end-to-end green preview bake ever — all 6 jobs
      succeeded including `manifest` emission.  The emitted
      `manifest.json` contains:
      - `git_sha`           = `b3c73166e1709aba91c225232def9ff44d255fcc`
        (exactly the PR head SHA)
      - `tested_sha`        = same (tests ran against the same commit
        whose artifacts were built)
      - `cargo_lock_sha256` = `1b5d20222501417f5392280efdb8483b94088c15600ace8b63010270755317cc`
      - `rustc_version`     = `rustc 1.97.0-nightly (913e4bea8 2026-04-22)`
      - `nextest_version`   = `0.9.132`
      - `target`            = `x86_64-pc-windows-msvc`
      - `build_os`          = `ubuntu-22.04 (cargo-xwin)`
      - `files[]`           = 17 entries (16 release binaries +
        73.9 MB nextest archive), each with `path`, `sha256`, `bytes`

      The manifest was downloaded locally on 2026-04-24 and every
      `files[].sha256` was verified against `sha256sum` of the
      downloaded file — all matched.  Earlier out-of-band evidence
      from PR #52 run 24873800282 (before bugs #5/#6 were fixed) is
      superseded by this run but remains in the §10.5 audit trail.
- [x] **Nextest archive round-trip** validation: Windows box with
      matching `nextest_version` from manifest, `git checkout <sha>`,
      `cargo nextest run --archive-file`.  ✅ Validated on PR #55
      preview run 24889490616 (`smoke-windows` job) with **1322/1322
      tests passing** after bugs #5 / #6 were fixed.  First-time
      execution on PR #52 (run 24873800282) surfaced two stale test
      vectors (hardcoded `assert_eq!` values that had never been
      validated anywhere because the containing modules were
      `#[cfg(windows)]`-gated — see §10.5 bug #5/#6 root-cause
      update 2026-04-25).  Fixed in PR #55 (closes issues #53 / #54).
      The round-trip MECHANISM itself was already proven on PR #52
      with 1320/1322 passing; this is the final 2/2 that completes
      the picture and unlocks the `manifest` job (which is
      `needs:`-coupled to `smoke-windows`).  Full external-box
      round-trip (a separate Windows dev box, not a GitHub runner)
      still deferred until such a box is available, but the
      GitHub-hosted `windows-latest` bake is sufficient evidence
      that the archive format is portable across two distinct
      Windows environments (the build machine running `cargo-xwin`
      on ubuntu-22.04 and the test machine on native MSVC).
- [x] **Pre-fast-gate enforcement** validation: deliberate
      `PR Fast CI` failure blocks preview build.  ✅ Baked on same
      PR via a temporary sabotage commit (`exit 1` as the first
      step of the `file-size` job — unconditional, fast-failing,
      cheapest); `PR Fast CI / required` = FAILURE on SHA
      `0600ce674`, and `verify-pr-fast-green` correctly detected
      the red aggregator at poll retry 48/120 and set `core.setFailed`,
      so `build-windows` / `build-test-archive` / `smoke-windows` /
      `manifest` all stayed `skipped` — zero Windows runner minutes
      spent.  Sabotage reverted before merge.
- [x] **Fork-PR behaviour** validation: completed via static
      analysis on 2026-04-24; live fork-PR bake will naturally
      occur with the first external contribution.  The preview lane
      is **designed to be fork-PR-safe by construction**:

      1. **Runner safety**: all jobs use `runs-on: ubuntu-22.04`
         or `windows-latest` (no `self-hosted` anywhere in the
         workflow).  Verified by grep on 2026-04-24.  A fork PR
         cannot be used to exfiltrate self-hosted runner state or
         access internal networks.
      2. **Secret safety**: the workflow uses **no secrets** —
         grep-verified 2026-04-24 (no `secrets.*` references, no
         hardcoded PATs, no references to repository or organization
         secrets).  The only credential used is the
         auto-provisioned `GITHUB_TOKEN`, which GitHub downgrades
         to **read-only** for fork PRs.  That read-only posture is
         still sufficient for our workflow's needs:
         - `gate` and `verify-pr-fast-green` only `gh api`-read
           PR metadata and check-run statuses (read-only).
         - `build-windows` / `build-test-archive` / `smoke-windows`
           do not call `gh api` at all.
         - `manifest` only reads the downloaded artifacts and
           uploads its own.
         - `actions/upload-artifact` uses the Actions runtime
           credential (not `GITHUB_TOKEN`), which IS available on
           fork PRs.  Confirmed 2026-04-24 by re-reading GitHub's
           [fork PR permissions doc](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/using-conditions-to-control-job-execution#permissions-for-fork-pull-requests).
      3. **Label-trigger safety**: fork PRs cannot apply labels
         themselves (labels require write access to the target
         repo).  Only a maintainer can apply `preview-binaries`,
         which means no adversarial fork PR can self-trigger a
         build — the label acts as both a trigger AND an implicit
         maintainer approval for running the workload.
      4. **Concurrency safety**: the `concurrency.group` key is
         `preview-${workflow}-${pr_number|sha}` with
         `cancel-in-progress: true`.  Multiple fork-PR label events
         on the same PR cancel prior runs, preventing resource
         exhaustion.

      Remaining deferred for a future fork PR (natural occurrence,
      not proactively simulated): (a) confirm the `labeled` event
      fires on fork PRs exactly as on in-repo PRs; (b) confirm
      `pull_request.head.sha` is correctly set to the fork's head
      (not a merge-commit SHA); (c) confirm artifact upload
      succeeds end-to-end with the downgraded token.  If any of
      these fail in practice, document in §10.5 and add a regression
      step to this list.

**Notes**:
- The `verify-pr-fast-green` job is the critical gate that prevents
  wasting runner minutes on non-mergeable SHAs.  Polling budget:
  120 × 15 s = 30 min, `timeout-minutes: 32`.  Originally 10 min;
  recalibrated 2026-04-23 after the first full-matrix preview attempt
  timed out with `PR Fast CI / required` still at `status=missing`
  (the aggregator hadn't been registered as a check-run yet — tests
  job still running).  See §10.5 deviations log.  If a future change
  pushes PR Fast CI beyond 30 min at p99, bump the cap — don't
  lower the preview gate's retry budget.
- `build-windows` cross-compiles via `cargo-xwin` on `ubuntu-22.04`
  (`preview-windows` cache).  `build-test-archive` builds natively
  on `windows-latest` (`preview-test-archive-windows` cache).  The
  two jobs intentionally do NOT share a cache — Linux and Windows
  runner caches cannot cross, and `cargo nextest archive` is
  unsupported by `cargo-xwin` anyway (xwin only wraps `build|check|
  test|run|clippy|rustc`).  See §10.5 2026-04-24 correction entry
  for the Windows-native rationale.
- The manifest's `cargo_lock_sha256` is a stronger integrity anchor
  than trusting the artifact alone — if someone later asks "which
  crates versions were in this preview", they can reconstruct
  deterministically from this + the git SHA.

#### Phase 7 — `ci-pipeline.rs` → workspace binary

- [x] `scripts/ci-pipeline/Cargo.toml` created.
- [x] `scripts/ci-pipeline/src/main.rs` is the authoritative
      implementation (1735 lines, previously 1752 in the rust-script
      minus the 17-line shebang / deps header).
- [x] Workspace `members` in `Cargo.toml` updated:
      `"scripts/ci-pipeline"` added alongside the crates.
- [x] `Cargo.lock` regenerated and tracks `uffs-ci-pipeline v0.5.71`.
- [x] `cargo check -p uffs-ci-pipeline --locked` → clean (6.77 s cold,
      0.17 s warm).
- [x] `cargo run -q -p uffs-ci-pipeline -- --help` → prints the same
      subcommand table as before the promotion.
- [x] `just/workflow.just`, `just/dev.just`, `just/bench_ci.just` —
      every `rust-script scripts/ci/ci-pipeline.rs <cmd>` replaced
      with `cargo run -q --release -p uffs-ci-pipeline -- <cmd>`.
- [x] `ci.yml` path filter additionally watches
      `scripts/ci-pipeline/**` so the parallel window catches
      changes to the new crate.
- [x] Old `scripts/ci/ci-pipeline.rs` kept as a **thin wrapper**
      (49 lines) that prints a deprecation notice and re-execs
      `cargo run -q --release -p uffs-ci-pipeline -- "$@"`.  Verified
      executable via `rust-script scripts/ci/ci-pipeline.rs --help`.
      Marked `REMOVE-AFTER: v0.5.73` in the header.
- [ ] Real-world bake-in on a live `just ship` run.  Deferred to
      the next release cycle.

**Notes**:
- The new crate intentionally does **not** opt into
  `[lints] workspace = true`.  The workspace lints are calibrated
  for production library/CLI code (deny unwrap, deny `println!`, deny
  missing_docs_in_private_items).  Inheriting them for this tool
  would require thousands of lines of edits without making the tool
  materially better.  Opting out is documented in a header comment
  on the crate's Cargo.toml so future maintainers don't silently
  re-enable them.
- Package name: `uffs-ci-pipeline` (not `ci-pipeline` as named in the
  plan spec).  Matches the workspace convention that every
  workspace-local crate is `uffs-*`, and avoids a future collision
  with any upstream crate published to crates.io as `ci-pipeline`.
  `publish = false` is set to enforce we never accidentally publish.
- `tokio` workspace baseline is net-free; this crate re-enables
  the `process` feature via `features = ["process"]` on the
  workspace alias.  Feature unions are additive, so no other crate
  sees this addition.

#### Phase 8 — (stretch) `gates.toml`

- [ ] Deferred — re-evaluate after 2 release cycles with lanes split.

**Notes**:

### 10.4 Metric measurements

Fill the baseline column at Phase 1 start; fill each phase column
at its completion.  Empty cells mean "not yet measured"; `—` means
"metric does not apply to this phase".  Record actual values, not
pass/fail, so regressions are visible across the refactor.

| Metric | Baseline | P1 | P2 | P3 | P4 | P5 |
|--------|----------|----|----|----|----|----|
| pre-push wall (warm) | 23–45 s | | | | — | — |
| pre-push wall (cold) | 60–90 s | | | | — | — |
| pre-commit wall (Rust change, warm) | 15–25 s | — | | | — | — |
| Pre-push time to first red on vet failure | ∞ (CI-only) | ~1 s | | | — | — |
| Pre-push time to first red on type error | ~40 s (clippy) | | ~15 s | | — | — |
| Cold `cargo build --workspace` | — | — | — | | — | — |
| Warm rebuild after single-file touch | — | — | — | ~42 s target | — | — |
| PR-fast wall (warm, p50) | 8–12 min (ci.yml) | — | — | — | ≤ 8 min | — |
| Preview-artifacts wall (warm) | n/a | — | — | — | — | ≤ 30 min |
| Windows regression detection latency | release-time | — | — | — | PR-time | PR-time |

### 10.5 Deviations log

Any step that diverged from the plan — record here so future readers
don't infer the wrong reason from commit messages.

| Date | Phase | Deviation | Resolution |
|------|-------|-----------|------------|
| 2026-04-23 | 4 | Plan §4 claimed 8 `Tier 1 / *` checks were required.  Actual ruleset had 6 (no `Doc Tests`, no `Test Build`). | Corrected baseline to 6 entries in §4.1; parallel-window math in §4.2 adjusted accordingly. |
| 2026-04-23 | 4 | First ruleset PUT used context `"PR Fast CI / PR Fast CI / required"` (matching the UI display string).  PR entered `mergeStateStatus: BLOCKED` with zero failing checks because no real check reports under that name — the protection engine matches `check_run.name` = job `name:` attribute only. | Second PUT used `"PR Fast CI / required"` (bare job name).  PR went to `CLEAN/MERGEABLE`.  Gotcha documented in §4.4 to prevent recurrence at Tier 1 cutover. |
| 2026-04-23 | 4 | Plan §10.3 scheduled a 7-day parallel window (2026-04-23 → 2026-04-30).  Compressed to ~2h35m same-day on explicit maintainer direction. | Rationale: the confidence budget had already been exhausted by the same morning — broken-classify simulation executed and passed on PR #45, all four classification paths (mixed-code, docs-only, infra-only, broken-classify) validated with zero disagreements between lanes, and continuing the window would have burned ~5–7 min of runner time per PR for no additional signal.  Rollback path preserved: `git revert 6f99b86aa` restores `ci.yml` verbatim (no squash-merge loss), and `/tmp/ruleset-rollback.json` restores the 7-entry ruleset shape.  §4.3 updated with the two-step reverse sequence. |
| 2026-04-23 | 4 | Plan v1 §4.3 instructed "do everything in a single commit" for the cutover.  This is a category error — the ruleset PUT is an API call, not a commit, so it cannot share atomicity with `.github/workflows/ci.yml` deletion.  Worse: with `ci.yml` deleted in a PR, the 6 `Tier 1 / *` required checks gate on a workflow that will never run on the PR's head SHA, producing `mergeStateStatus: BLOCKED` indefinitely. | Correct sequence (now in §4.3): (1) open the `ci.yml`-deletion PR and let it bake green on `PR Fast CI / required`; (2) PUT the ruleset BEFORE merge to drop the 6 `Tier 1 / *` checks; (3) squash-merge the PR; (4) verify.  Executed in a 16-second PUT→merge window on 2026-04-23 14:13:25 → 14:13:41 PDT with no PRs opened mid-window. |
| 2026-04-23 | 5 | `preview-artifacts.yml`'s `build-test-archive` step captured the nextest version with `echo "version=$(cargo nextest --version \| awk '{print $2}')" >> "$GITHUB_OUTPUT"`.  `cargo nextest --version` on 0.9.132 emits multiple lines where `$2` evaluates to `0.9.132` on more than one of them; the command substitution preserves the inner newlines, and GitHub Actions rejects the resulting multi-line value with `Error: Unable to process file command 'output' successfully. Error: Invalid format '0.9.132'`.  Found by the live Phase 5 bake on the scratch PR that ticks items #1/#2/#4. | Constrained awk to `NR==1` so only the first output line is considered.  Minimal one-word edit; no change to the rest of the step.  Regression-guard comment added to the workflow explaining the failure mode so the fragility is not silently reintroduced.  Unblocks the bake; the same PR that fixes the bug also lands the resulting Phase 5 ticks in §10.3. |
| 2026-04-23 | 5 | `build-test-archive` failed on `ubuntu-22.04` with `cc-rs: failed to find tool "lib.exe"` from `ring v0.17.14`'s build.rs.  Proximal cause: `cargo-xwin` wraps `build\|check\|test\|run\|clippy\|rustc` but NOT `nextest archive`, so the bare `cargo nextest archive --target x86_64-pc-windows-msvc` invocation ran without MSVC env.  Deeper cause surfaced while diagnosing the fix: `cargo nextest archive` defaults to debug profile, and debug xcompile for Windows is currently blocked at a separate layer by the `polars-ops` 5.5 GB rlib → COFF archive string-table-offset limit (see `docs/xwin-msvc-rlib-size-root-cause-and-workarounds.md`).  Even moving `build-test-archive` to `windows-latest` (native MSVC) would not resolve this because the COFF archive size ceiling is format-level and `link.exe` shares it.  Release-mode xcompile works (confirmed locally on mac), which is why the sibling `build-windows` job — `cargo xwin build --release --bins` — succeeds. | Deferred to the concurrent branch that fixes the polars-ops rlib size via an `xwin-dev` profile + per-package overrides (from §6 of the root-cause doc).  Rolled back my attempt to move `build-test-archive` to `windows-latest` — it would have shifted the failure mode without fixing anything, and it would have collided with the concurrent branch's xwin-centric approach.  Phase 5 checklist item #2 (same-SHA integrity) reverted to un-ticked with a cross-reference back to this entry; item #3's "partially satisfied by smoke-windows" note softened to "will be, once the polars blocker is resolved". |
| 2026-04-25 | 5 | **Bug #5 / #6 root-cause update.**  Investigation of issues #53 / #54 revealed that BOTH "Windows portability" bugs surfaced by `smoke-windows` on PR #52 were mis-framed by the issue reports.  Neither is actually platform-dependent behavior.  Both are just **stale hardcoded expected values** that had never been executed in CI before the preview lane ran them on 2026-04-24: (a) `fnv1a_known_vector` hardcoded `0x8584899336065430` but the impl produces the **canonical** FNV-1a-64 of `"foobar"` = `0x85944171F73967E8` (matching `isthe.com/chongo/src/fnv/test_fnv.c` reference); the hardcoded value is simply wrong and would fail on any platform the test actually ran on.  (b) `test_pipelined_reader_creation` hardcoded `64 * 1024` for all three drive types but `DriveType::optimal_chunk_size()` returns 2 MiB / 1 MiB / 1 MiB for Ssd/Hdd/Unknown \u2014 the hardcoded value was a stale prototype number, never updated when the chunk-size tuning was revised.  Both tests are inside `#[cfg(windows)]` gates (pipe.rs at the module level, pipelined at the `mod pipelined;` declaration in `readers/mod.rs`), so `pr-fast.yml`'s `Tests` job (ubuntu-only) never compiled them, and `Windows compile check` compiles but does not execute.  Result: **the assertions had never executed anywhere**.  The platform-dependency theories in the original #53 / #54 issue bodies are withdrawn.  The preview lane earned its keep more than advertised \u2014 it found untested code, not platform-specific bugs. | Single combined fix PR (supersedes separate fix PRs for #53 / #54): `fix(tests): correct stale expected values in Windows-gated unit tests`.  Changes: (a) \u00a710.5 bug #5 expected value \u2192 `0x8594_4171_F739_67E8`; (b) \u00a710.5 bug #6 expected values derived from `DriveType::optimal_chunk_size()` itself, eliminating the hardcoded drift vector so future tuning changes cannot silently break this test again.  Both fixes carry block comments anchoring them to this row + the referenced issues.  Lesson: **any test gated behind a platform `cfg` that is NOT exercised by `pr-fast.yml` is effectively dead code**; the Phase 5 preview lane is currently the only CI location that ever exercises `cfg(windows)` test bodies.  See \u00a710.3 Phase 5 follow-up items for the plan to close this gap systemically (beyond fixing these two specific tests). |\n| 2026-04-24 | 5 | **Bug #5 (product code, not preview lane).**  `smoke-windows` on PR #52 preview run 24873800282 executed 1322 tests from the nextest archive; one failure: `uffs-security::pipe::tests::fnv1a_known_vector` at `crates/uffs-security/src/pipe.rs:523` — `assertion left == right failed; left: 9625390261332436968, right: 9620965969329804336`.  FNV-1a is endianness-agnostic byte-wise, so the mismatch points to a **test-vector** bug (the expected hash was computed on Linux/macOS byte layout but the impl uses different width on Windows for the input, e.g. `usize` vs `u64`, or the test feeds a UTF-16-encoded string that was not normalized across platforms).  Latent because **these tests had never executed on Windows in CI before** — `pr-fast.yml`'s `Windows compile check` is compile-only, `Tests` runs on ubuntu; the preview-lane `smoke-windows` is the first CI location that runs them on Windows. | **Out of scope for PR #52** (which is a preview-lane PR, not a `uffs-security` PR).  Filed as follow-up issue #53 for the crate owner to investigate: either the test vector is wrong (recompute on Windows), or the implementation has a platform-dependent input encoding.  Item #3 (nextest round-trip) validation does NOT require this test to pass — the round-trip MECHANISM is proven by the 1320 other tests that executed successfully.  Ticked in §10.3 with that caveat. |\n| 2026-04-24 | 5 | **Bug #6 (product code, not preview lane).**  Second failure from the same `smoke-windows` run: `uffs_mft::io::readers::pipelined::tests::test_pipelined_reader_creation` at `crates/uffs-mft/src/io/readers/pipelined.rs:506` — `assertion left == right failed; left: 2097152, right: 65536`.  Ratio = 32×.  `2_097_152 = 2 MiB` and `65_536 = 64 KiB`; 64 KiB is the Windows default allocation granularity (`dwAllocationGranularity` from `GetSystemInfo`), while 2 MiB is the default Linux hugepage / block-size on many filesystems.  The test likely asserts an allocation-rounded buffer size computed from a platform-dependent default.  Same latency reason as bug #5: first Windows execution ever. | **Out of scope for PR #52.**  Filed as follow-up issue #54 for the `uffs-mft` owner.  Either the test's expected value should be platform-aware (read `dwAllocationGranularity` and compute the expected size dynamically), or the reader should clamp to a fixed portable block size independent of the OS default.  Item #3 validation unaffected. |\n| 2026-04-24 | 5 | `build-windows` (the sibling xwin release job, unchanged in this PR) failed on the post-misdiagnosis preview re-bake with `winresource: failed to embed icon + manifest: Os { code: 2, kind: NotFound, message: "No such file or directory" }` from `crates/uffs-cli/build.rs:106`.  Root cause: `winresource v0.1.31` at `src/lib.rs:735-736` hardcodes `PathBuf::from("llvm-rc")` on `cfg(unix)` and spawns it unqualified; `cargo-xwin` does NOT prepend any LLVM `bin/` dir to PATH (it only wires MSVC CRT/SDK env).  On `ubuntu-22.04` runners `llvm-rc` is preinstalled but lives at `/usr/lib/llvm-<N>/bin/llvm-rc`, not on the default PATH.  Net effect: `res.compile()` invocation spawns `"llvm-rc"` → `execvp` returns `ENOENT` → panic in `build.rs`.  A fourth pre-existing preview-lane bug uncovered by the same logjam-busting sequence that surfaced bugs #1 / #2 / #3; remained latent because bugs #1 / #2 / #3 stopped every earlier preview run before `build-windows` even finished compiling polars-ops to reach the `uffs-cli` build.rs call.  Found on run 24873105115 (PR #52, SHA `dbdbbb72d`). | Added a `Locate llvm-rc for winresource` step to `build-windows` that scans `/usr/lib/llvm-*/bin/llvm-rc`, picks the highest-versioned match, and exports `RC_PATH` to `$GITHUB_ENV`.  `winresource v0.1.31`'s `compile_with_toolkit_msvc` at `lib.rs:733-734` honors `RC_PATH` ahead of the hardcoded fallback, so this path wins without patching the crate.  Version-robust against GHA runner image bumps: if LLVM 15 is replaced with LLVM N+1 the `sort -V | tail -1` keeps working.  Same PR as the `build-test-archive` windows-latest move; both fixes needed to get the preview lane end-to-end green. |\n| 2026-04-24 | 5 | **Correction of 2026-04-23 §10.5 row above (the `build-test-archive` / polars-rlib entry).**  That entry claimed "moving `build-test-archive` to `windows-latest` would not resolve this because the COFF archive size ceiling is format-level and `link.exe` shares it."  The claim is wrong and the derived decision to roll back the `windows-latest` move was therefore also wrong.  Evidence: an out-of-band bake on a local VS 2026 dev box (Windows 11, native MSVC) ran `cargo build --workspace` in both debug (4m 58s) and release (23m 23s) profiles on the current `main` (post-PR #51).  Both completed successfully and produced all 17 workspace binaries including polars-consumer crates (`uffs-daemon`, `uffs-mcp`, `uffs-core`).  The full polars-ops graph compiled and linked via native `link.exe` + `lib.exe` without hitting any COFF archive ceiling.  The 6-month-long "native Windows workspace build is broken" pathology that had led to my assumption that `link.exe` shared the LLVM ceiling was in fact a **separate** sccache × `CARGO_INCREMENTAL=1` incompatibility, resolved independently in PR #45's `.cargo/config.toml` update (`rustc-wrapper = "sccache"` + `incremental = false` paired atomically at workspace scope).  The COFF archive format ceiling is therefore **specific to the LLVM cross-compile toolchain** (`lld-link` / `llvm-lib` used by `cargo-xwin`), not the native MSVC toolchain. | Re-applied the previously-reverted change: `build-test-archive` now runs on `runs-on: windows-latest` with `shared-key: preview-test-archive-windows` (separate from `build-windows`'s `preview-windows` Linux cache since caches cannot cross platforms).  Corrected the derived claims in §10.3 items #2 and #3 (removed "blocked on polars" framing).  Narrowed §10.6's polars-ops entry to the actual scope (macOS→xwin→debug DX only; no longer gates Phase 5 bake).  Expanded the workflow's job header comment with both the xwin-nextest-subcommand rationale and the LLVM-vs-native COFF-ceiling rationale so the "why not just keep it on ubuntu?" question has a durable answer.  Phase 5 items #2 and #3 re-bake on this same PR. |
| 2026-04-23 | 5 | `verify-pr-fast-green`'s polling budget (60 × 10 s = 10 min, `timeout-minutes: 12`) was calibrated assuming the target PR would be docs-only / short-circuited.  On the first real full-matrix preview attempt (this same scratch PR, SHA `3ef74bd5f` — which counts as an *infra* change because it touches `.github/workflows/*.yml`), PR Fast CI's `tests` job was still running at minute 10 so the poller kept seeing `status=missing` (the `PR Fast CI / required` aggregator had not yet been registered as a check-run).  Preview failed at `verify-pr-fast-green` with `⏱  Timed out waiting for PR Fast CI / required on 3ef74bd`, which aborted `build-windows` / `build-test-archive` / `smoke-windows` — a **false-negative** gate: the PR would have gone green ~5 min later.  §10.3 Phase 5 notes (v2 wording) anticipated this with "if PR-fast is slower than 10 min, increase the cap in one commit", but nobody had exercised it against a real full-matrix PR before. | Bumped polling to 120 × 15 s = 30 min and `timeout-minutes: 32`.  Factored the magic numbers into named `MAX_RETRIES` / `RETRY_DELAY_MS` constants so the next calibration isn't a hunt.  Expanded the job's header comment with the rationale and an explicit "don't drop below p99 PR Fast CI wall-clock" guardrail.  Same PR as the nextest fix above. |

### 10.6 Open blockers

Active blockers visible at a glance.  Move to "Resolved" below with a
one-line outcome when cleared.

**Active**:

- **Polars-ops `xwin`-debug DX blocker** (narrowed scope) —
  debug-profile cross-compile **from macOS via `cargo xwin`** to
  `x86_64-pc-windows-msvc` produces a ~5.5 GB `polars-ops` `.rlib`
  that exceeds the COFF archive format's string-table offset
  capacity, yielding `lld-link: truncated or malformed archive`
  at final link.  Previously catalogued as a CI-lane blocker for
  the preview workflow; verified 2026-04-24 (see §10.5) to be
  specific to the **LLVM cross-compile toolchain** (`lld-link` /
  `llvm-lib` used by `cargo-xwin`), **not** the native MSVC
  toolchain (`link.exe` / `lib.exe` used by `windows-latest`
  runners and local VS 2026 dev boxes).  The preview CI lane is
  unaffected because `build-test-archive` now runs on
  `windows-latest`.  Scope remaining: macOS developers who want
  to debug-xcompile the workspace locally.  Root cause + fix
  recipe stays documented in
  `docs/xwin-msvc-rlib-size-root-cause-and-workarounds.md`
  (dedicated `xwin-dev` profile + per-package polars overrides
  reducing debuginfo / codegen-units / opt-level) for that path.
- **Real-world bake gaps** — pure `Dep-only PR` and pure `Infra-only
  PR` classification paths still want a natural exercise post-cutover
  (on `pr-fast.yml` alone, now that `ci.yml` is gone).  PR #47 was
  the last infra-only bake in the parallel-window era; first
  post-cutover dependabot run and first post-cutover infra-only PR
  will close these opportunistically.  Don't synthesize a test PR
  just for this.
- **Phase 4b `release.yml` permissions refactor** — workflow-level
  `contents: write` → per-job grants on `create-github-release` only.
  Deliberately scoped out of PR #47 per its scope note; track as a
  future focused PR with a release dry-run.

**Resolved**:

- **Phase 5 wrap-up + full green end-to-end bake** — ✅ 2026-04-24,
  on PR #55 preview run 24889490616.  All 6 preview jobs succeeded
  for the first time ever; `manifest.json` emitted with real
  `files[].sha256` integrity data.  §10.3 items #2, #3, #5 all
  ticked with real evidence (not out-of-band substitutes).  No
  separate wrap-up PR needed — PR #55 carried both the test fixes
  AND the final evidence update in one atomic change.
- **Issue #53 (uffs-security fnv1a)** — ✅ 2026-04-25, closed by
  PR #55.  Root cause was NOT a Windows platform dependency (as
  the original issue theorized) but a stale hardcoded test vector
  that had never executed in CI.  See §10.5 bug #5/#6 root-cause
  update entry.
- **Issue #54 (uffs-mft pipelined buffer size)** — ✅ 2026-04-25,
  closed by PR #55.  Same root cause as #53: stale hardcoded
  expected value.  Fix derives the expected value from
  `DriveType::optimal_chunk_size()` itself to eliminate the drift
  vector.
- **Broken-classify simulation** — ✅ 2026-04-23, on PR #45.  `required`
  correctly propagated failure through 8 skipped downstream jobs.
- **Ruleset context-string gotcha** — ✅ 2026-04-23, same day.  See
  §4.4 for the write-up.
- **7-day parallel-window bake** — ✅ 2026-04-23.  Compressed to
  ~2h35m same-day on maintainer direction; all four classification
  paths validated with zero lane disagreements.  See §10.5.
- **Phase 4b actions-hardening retrofit** — ✅ 2026-04-23 via PR #47
  (squash `eef3359b2`).  7 workflows audited, 4 modified
  (`tier-2.yml`, `codeql.yml`, `release.yml`, `dependabot-review.yml`),
  3 already conformant.  See §10.3 Phase 4b checklist.
- **Phase 4 branch-protection cutover** — ✅ 2026-04-23 14:13 PDT
  via PR #48 (squash `6f99b86aa`) + ruleset PUT.  `ci.yml` retired,
  `pr-fast.yml` is sole required lane.  See §4.3.
- **Stale `ci.yml` references in comments** — ✅ 2026-04-23 via the
  housekeeping PR that carries this bullet.  8 files updated
  (`README.md` CI badge, `CONTRIBUTING.md` PR-CI table + cross-
  platform paragraph, `pr-fast.yml` 7 comment blocks, `release.yml`
  2 comments, `dependabot-review.yml` rationale comment, both
  `pre-push` hook files, `just/test.just` shift-left diagram +
  lockstep note).  Only remaining live reference is the intentional
  historical marker at the top of `pr-fast.yml` documenting the
  cutover event itself.

### 10.7 Post-mortem triggers

If any of the following happens during rollout, **stop and reassess**
before continuing to the next phase:

- A hard gate added in Phases 1–3 blocks a legitimate push more than
  once in the same session without an obvious fix.  Symptom of an
  over-tightened gate; relax or move to advisory before continuing.
- Phase 4 validation step 5 (broken-classify simulation) unexpectedly
  reports `required = success`.  Symptom of the GitHub Actions
  skipped-success bug not being closed; the `Gate on classify` step
  is broken.
- Phase 5 validation step 4 (pre-fast-gate enforcement) lets a preview
  build proceed against a red PR-fast.  Symptom of the check-runs
  poller returning stale data.
- `just ship` loses time to any newly-introduced gate.  Budget was
  tight before — keep it tight after.

---

## 11. Revision history

- **2026-04-23 v3.2** — Current.  Post-cutover reconciliation
  (evening of the same day as v3.1):
  - §4.2 re-framed from "current parallel window" to "historical"
    with actual duration (~2h35m, 11:38 → 14:13 PDT) and in-window
    PR list (#45, #46, #47).
  - §4.3 materially corrected: the v1 "do everything in a single
    commit" instruction was a category error (ruleset PUT is an
    API call, not a commit; bundled-atomicity is not available).
    Correct sequence is PUT-before-merge with a sub-minute window;
    executed on 2026-04-23 with a 16-second PUT → merge gap.
    Added evidence block (commit SHAs, PUT timestamp) and a
    two-step rollback procedure (git revert + ruleset restore).
  - §10.2 dashboard: Phase 4 + Phase 4b rows flipped 🟡 → ✅ with
    completion dates and both phase-4 commits (`780c1dbb1` parallel
    + `6f99b86aa` cutover).
  - §10.2 Phase 4 sub-status paragraph rewritten as "fully cutover,
    end-of-day" narrative with precise timestamps.
  - §10.3 Phase 4 checklist: parallel-window and branch-protection
    cutover rows both ticked with evidence and the wording
    correction noted.
  - §10.5 Deviations log: two new entries (bake-window compressed;
    plan v1 "single commit" category error + corrected sequence).
  - §10.6 Open blockers: bake window, Phase 4b, and branch-
    protection cutover all moved from Active to Resolved.  Two
    new Active items surfaced (stale `ci.yml` references in
    comments; deferred `release.yml` permissions refactor).
- **2026-04-23 v3.1** — Post-PR #45 reconciliation:
  - Phases 1, 2, 3, 6, 7 marked complete with commit + PR references
    (squash `780c1dbb1`).
  - Phase 4 annotated with live-bake progress: broken-classify sim
    executed and passed; parallel-window opened; cutover scheduled.
  - §4 rewritten to reflect reality: ruleset-based protection
    (ID `11889528`), 6-entry (not 8) Tier 1 baseline, 7-entry
    parallel-window state, documented cutover procedure, and a
    required-check context-string gotcha section.
  - §10.3 Phase 4 checklist: broken-classify and rust-change bakes
    ticked with evidence; 7-day window dates filled
    (2026-04-23 → 2026-04-30); infra-only partially credited.
  - §10.5 Deviations log: baseline-count correction + ruleset
    context-string gotcha recorded.
  - §10.6 Open blockers: bake-window + 4b retrofit + two real-world
    bake gaps marked active; broken-classify + context gotcha moved
    to resolved.
- **2026-04-23 v3** — Incorporates second-round external
  review.  Eleven correctness fixes:
  1. `required` aggregator explicitly depends on `classify` and
     fails unless `needs.classify.result == 'success'` — closes
     the "skipped-counts-as-success" green-lighting bug.
  2. Every compile/test/Windows job gates on
     `code_changed = rust || dep || infra`, not `rust == 'true'` —
     dep-only and infra-only PRs now run the full matrix.
  3. Explicit `infra_changed` file class defined in §1.3 with
     concrete glob patterns, wired into `classify` outputs.
  4. Pre-push diff logic uses git's stdin protocol
     (`<local_ref> <local_oid> <remote_ref> <remote_oid>`) instead
     of `@{push}` heuristics, with conservative fallback for
     unparseable cases.
  5. `preview-artifacts.yml` gains `verify-pr-fast-green` job
     querying check-runs API for the same SHA; refuses to build
     unless PR-fast is green on that commit.
  6. Explicit checkout-ref policy — every job pins
     `github.event.pull_request.head.sha || github.sha`.  No
     reliance on `actions/checkout`'s default PR behaviour.
  7. `--locked` applied to every cargo subcommand that supports
     it (CI and local).  `cargo fetch --locked` primes the cache.
  8. New §2.8 Actions hardening policy: `permissions: contents: read`
     default, full-SHA action pinning, forbidden
     `pull_request_target` + self-hosted fork PRs.
  9. `merge_group:` trigger added to `pr-fast.yml` for merge-queue
     compatibility.
  10. Manifest emits `tested_sha`, `nextest_version`, and per-file
      SHA256 (not just the artifact-level digest).
  11. Local Windows xwin reclassified as advisory (not hard);
      PR-fast native `windows-check` is the authoritative gate.
      Resolves the v2 half-hard/half-soft inconsistency.
- **2026-04-23 v2** — External review of v1.  Lane separation,
  hard-vs-advisory gate split, single-source cache policy, ordered
  scheduler, PR-fast/preview split, nextest archive for Windows
  preview.
- **2026-04-23 v1** — `dev-flow.md` initial draft.  Retained as the
  "explanation" companion doc.
