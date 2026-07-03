# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025-2026 SKY, LLC.

# Watch mode development.
dev:
    @printf "\033[0;34m🔄 Starting watch mode...\033[0m\n"
    @if command -v cargo-watch >/dev/null 2>&1; then \
        cargo watch -x "nextest run --workspace --jobs 16" -x "clippy --workspace --all-targets --all-features --no-deps -- {{ test_flags }}"; \
    else \
        printf "\033[1;33mInstalling cargo-watch...\033[0m\n"; \
        just _install-if-missing cargo-watch cargo-watch; \
        cargo watch -x "nextest run --workspace --jobs 16" -x "clippy --workspace --all-targets --all-features --no-deps -- {{ test_flags }}"; \
    fi

# Clean build artifacts.
clean:
    @printf "\033[0;34m🧹 Cleaning build artifacts...\033[0m\n"
    cargo clean

# Emergency killswitch.
kill:
    @printf "\033[0;31m🚨 EMERGENCY: Killing all cargo processes...\033[0m\n"
    @pkill -f "cargo" 2>/dev/null || true
    @pkill -f "rustc" 2>/dev/null || true
    @printf "\033[0;32m✅ All cargo processes terminated\033[0m\n"

# Find and kill orphan `uffs` processes left behind by aborted CLI runs,
# crashed test harnesses, or Ctrl-C'd validation scripts.  The
# legitimate long-running daemon is identified via `uffs daemon status`
# and explicitly preserved.  Pass `--dry-run` to list orphans without
# killing them, or `--bin <path>` to use a specific uffs binary for
# the daemon-PID lookup.
#
# Pulled out of the validation suites
# (`scripts/windows/{api,cli,mcp}-validation.rs`) so those scripts only
# observe daemon state — they never mutate the host process table.
orphan *ARGS:
    @rust-script scripts/dev/orphan-cleanup.rs {{ ARGS }}

# Daemon-readiness end-to-end verification.
#
# Exercises every meaningful daemon lifecycle (clean start/stop, kill
# recovery, double-start, restart, auto-start), the Phase 5/6/7 stats
# accumulation, COLD→WARM→HOT timing capture, AND the Phase 8 / 9
# operator-driven memory-tiering surface (status_drives, hibernate,
# preload --pin-minutes, forget --force, full round-trip cycle, and
# the Phase 9 promotions_total counter contract).  Renders a per-RPC
# timing summary at the end so an operator can see where time is
# spent across the operator commands.
#
# Pass `~/uffs_data` (or any data dir / MFT file) on macOS / Linux;
# omit on Windows for live NTFS auto-discovery.  Use `--forget-drive Z`
# (default) to avoid actually deleting any cache files; override with
# a small test drive (e.g. `M`) to exercise the destructive path.
#
# Examples:
#   just readiness ~/uffs_data
#   just readiness ~/uffs_data --skip-phase8
#   just readiness ~/uffs_data --forget-drive Z --pattern '*.txt'
readiness *ARGS:
    @rust-script scripts/dev/daemon-readiness.rs {{ ARGS }}

# Tier-load A/B benchmark — Cold vs Parked worst-case.
#
# Empirically validates that worst-case re-promote wall-clock is
# **identical** between the `Cold` and `Parked` source tiers when
# every drive's bloom hits the query (the broadest possible filter).
# The bloom optimisation in `ensure_warm_for_dispatch` only helps
# when some blooms *miss* — under a broad filter every drive must
# body-load regardless of source tier, and the per-drive decrypt
# cost is shared by the same `load_or_join_in_flight` primitive on
# both code paths.
#
# Runs N iterations (default 3) of each phase with a hard 15 %
# parity assertion at the end.  Total wall-clock ~3 min for N=3
# (driven by the 35 s warm→parked TTL wait per Phase B iteration).
#
# Pass `~/uffs_data` (or any data dir / MFT file) on macOS / Linux;
# omit on Windows for live NTFS auto-discovery.  The script self-
# manages the daemon TTL env vars (`UFFS_WARM_TO_PARKED_IDLE_SECS=5`,
# `UFFS_PARKED_TO_COLD_IDLE_SECS=900`) so callers don't have to.
#
# Examples:
#   just tier-compare ~/uffs_data
#   just tier-compare ~/uffs_data --pattern '*.dll' --iterations 5
#   just tier-compare ~/uffs_data --max-delta-percent 5     # tighter
#   just tier-compare ~/uffs_data --pattern 'xyzzy.log'     # narrow query — expect FAIL
tier-compare *ARGS:
    @rust-script scripts/dev/tier-load-compare.rs {{ ARGS }}

# 24h Windows-host validation soaks (Phase 6 / Phase 7 / WS-trace).
#
# Closes the three Windows-host gates for the v0.6.0 memory-tiering
# epic.  Subcommands:
#
#   phase6   — `min_tier="Warm"` 24h idle soak.  Writes a temporary
#              daemon.toml with the per-drive override, soaks idle
#              for 24h, captures hourly per-drive tier snapshots,
#              then drives a 5-min synthetic load and validates:
#              (1) drive C never demotes below Warm, (2) peer drives
#              demote normally, (3) `chosen_ttl_sec` differs between
#              high-rate (C) and idle drives.
#
#   phase7   — Per-shard USN-journal continuous-churn 24h soak.
#              Spawns a background create/modify/delete worker in
#              `%USERPROFILE%\uffs-soak\churn` (or `--churn-dir`),
#              captures hourly snapshots including encrypted-cache
#              file sizes, then validates: new-file latency ≤ 2s,
#              no `uffsd.exe` Working-Set growth > 1.5×, encrypted-
#              cache refresh fired during the soak, no panic / OOM /
#              unexpected demote-to-Parked.
#
#   ws-trace — 24h Working-Set trajectory.  OBSERVE-ONLY — does NOT
#              manage the daemon's lifecycle (the daemon must already
#              be Ready).  Spawns a keep-warm worker that fires a
#              quick search every 5 min so drives stay in WARM (not
#              decay to PARKED/COLD) across the trace; observes WS
#              hourly; validates PID stable and WS ≤ 1.5× over the
#              window.  Closes the bake-criteria §1.7 leak gate.
#
# All subcommands accept `--dev` for an abbreviated 5-min shake-out
# (1-min snapshot interval, relaxed validation) so the harness can
# be sanity-checked on Mac without burning 24h.
#
# Output: $HOME/uffs_soak/<gate>-<YYYYMMDD-HHMMSS>/
#   - daemon.log                   (full RUST_LOG-filtered tee — phase6 / phase7 only)
#   - snapshots/<NN>h-*.{txt,json} (per-snapshot artifacts)
#   - validation/*.{pass,fail}     (one breadcrumb per assertion)
#   - summary.txt                  (human-readable PASS/FAIL roll-up)
#   - keep-warm.log                (probe timeline — ws-trace only)
#   - wstrace.csv                  (combined per-snapshot CSV — ws-trace only)
#
# Examples:
#   just soak phase6                          # 24h idle soak, drive C
#   just soak phase6 --drive D                # apply min_tier=Warm to D instead
#   just soak phase6 --dev                    # 5-min Mac shake-out
#   just soak phase7                          # 24h churn soak, default churn dir
#   just soak phase7 --churn-rate 20          # 20 files/sec churn rate
#   just soak phase7 --duration 1h            # 1-hour smoke run on real Windows
#   just soak ws-trace                        # 24h WS trajectory, keep-warm every 5 min
#   just soak ws-trace --keep-warm-interval 10min   # less aggressive keep-warm
#   just soak ws-trace --keep-warm-interval 0       # disable keep-warm (idle-decay observation)
soak *ARGS:
    @rust-script scripts/dev/long-soak.rs {{ ARGS }}

# Daily bake-period check — the operator-facing wrapper around
# `just readiness` + the §1.3 tracing-log audit from
# docs/architecture/memory-tiering-bake-criteria.md.
#
# Runs the same command on both platforms:
#   just bake-day
#
# Each invocation:
#   1. Creates $HOME/uffs_bake/ if missing.
#   2. Runs `just readiness`, tee'd to $HOME/uffs_bake/<date>-<platform>.log.
#   3. Asserts exit 0 + the `150/150 steps passed` final line.
#   4. Greps the log for red-flag patterns (panic / OutOfMemoryError / FATAL
#      / abort / `BackgroundIoPriority...begin failed`).
#   5. Prints a PASS/FAIL summary plus a copy-pasteable row for §4 of the
#      bake-criteria doc, with the other platform's column marked
#      `(pending)` so a Mac + Windows run on the same day merges cleanly.
#
# Exit 0 on green, 1 on any failure.  Re-runs are idempotent — the day's
# log is overwritten so the latest pass-attempt is always the recorded one.
[unix]
bake-day:
    #!/usr/bin/env bash
    set -uo pipefail
    DATE=$(date +%Y-%m-%d)
    case "$(uname)" in
        Darwin) PLATFORM=mac ;;
        Linux)  PLATFORM=linux ;;
        *)      PLATFORM=$(uname | tr '[:upper:]' '[:lower:]') ;;
    esac
    BAKE_DIR="$HOME/uffs_bake"
    LOG="$BAKE_DIR/${DATE}-${PLATFORM}.log"
    mkdir -p "$BAKE_DIR"
    printf "\033[0;34m🎂 Bake-day check — %s — %s\033[0m\n" "$PLATFORM" "$DATE"
    printf "\033[0;34m   Log: %s\033[0m\n\n" "$LOG"
    just readiness 2>&1 | tee "$LOG"
    READINESS_EXIT=${PIPESTATUS[0]}
    PASS=1
    REASONS=()
    if [ "$READINESS_EXIT" -ne 0 ]; then
        PASS=0
        REASONS+=("readiness exit $READINESS_EXIT")
    fi
    if ! grep -F -q '150/150 steps passed' "$LOG"; then
        PASS=0
        REASONS+=("missing '150/150 steps passed' line")
    fi
    RED_FLAGS=$(grep -E '\b(panic|OutOfMemoryError|FATAL|abort)\b' "$LOG" || true)
    BG_IO_FAIL=$(grep -E 'BackgroundIoPriority.*begin failed' "$LOG" || true)
    if [ -n "$RED_FLAGS" ]; then
        PASS=0
        REASONS+=("red-flag patterns found")
        printf "\n\033[1;31m❌ Red-flag patterns:\033[0m\n%s\n" "$RED_FLAGS"
    fi
    if [ -n "$BG_IO_FAIL" ]; then
        PASS=0
        REASONS+=("BackgroundIoPriority begin failed")
        printf "\n\033[1;31m❌ BackgroundIoPriority:\033[0m\n%s\n" "$BG_IO_FAIL"
    fi
    printf "\n\033[0;34m── Bake-day summary ─────────────────────────────────\033[0m\n"
    if [ "$PASS" -eq 1 ]; then
        printf "\033[1;32m✅ %s %s — ALL GREEN (150/150)\033[0m\n" "$PLATFORM" "$DATE"
        RESULT="150/150 ✅"
    else
        REASONS_STR=$(IFS=', '; echo "${REASONS[*]}")
        printf "\033[1;31m❌ %s %s — FAILED: %s\033[0m\n" "$PLATFORM" "$DATE" "$REASONS_STR"
        printf "\033[1;31m   Full log: %s\033[0m\n" "$LOG"
        RESULT="FAIL"
    fi
    printf "\n\033[0;34m── Paste row into docs/architecture/memory-tiering-bake-criteria.md §4 ─\033[0m\n"
    printf "|  ?  | %s | full readiness | %s | full readiness | (pending) |       |\n" "$DATE" "$RESULT"
    [ "$PASS" -eq 1 ]

[windows]
bake-day:
    #!powershell
    $ErrorActionPreference = 'Continue'
    $Date = Get-Date -Format 'yyyy-MM-dd'
    $Platform = 'windows'
    $BakeDir = Join-Path $HOME 'uffs_bake'
    $Log = Join-Path $BakeDir "$Date-$Platform.log"
    New-Item -ItemType Directory -Path $BakeDir -Force | Out-Null
    Write-Host "[bake-day] check - $Platform - $Date" -ForegroundColor Blue
    Write-Host "   Log: $Log`n" -ForegroundColor Blue
    just readiness *>&1 | Tee-Object -FilePath $Log
    $ReadinessExit = $LASTEXITCODE
    $Pass = $true
    $Reasons = @()
    if ($ReadinessExit -ne 0) {
        $Pass = $false
        $Reasons += "readiness exit $ReadinessExit"
    }
    if (-not (Select-String -Path $Log -SimpleMatch -Pattern '150/150 steps passed' -Quiet)) {
        $Pass = $false
        $Reasons += "missing '150/150 steps passed' line"
    }
    $RedFlags = Select-String -Path $Log -Pattern '\b(panic|OutOfMemoryError|FATAL|abort)\b'
    $BgIoFail = Select-String -Path $Log -Pattern 'BackgroundIoPriority.*begin failed'
    if ($RedFlags) {
        $Pass = $false
        $Reasons += "red-flag patterns found"
        Write-Host "`n[FAIL] Red-flag patterns:" -ForegroundColor Red
        $RedFlags | ForEach-Object { Write-Host $_.Line }
    }
    if ($BgIoFail) {
        $Pass = $false
        $Reasons += "BackgroundIoPriority begin failed"
        Write-Host "`n[FAIL] BackgroundIoPriority:" -ForegroundColor Red
        $BgIoFail | ForEach-Object { Write-Host $_.Line }
    }
    Write-Host "`n--- Bake-day summary ---------------------------------" -ForegroundColor Blue
    if ($Pass) {
        Write-Host "[OK] $Platform $Date - ALL GREEN (150/150)" -ForegroundColor Green
        $Result = '150/150 OK'
    } else {
        Write-Host "[FAIL] $Platform $Date - FAILED: $($Reasons -join ', ')" -ForegroundColor Red
        Write-Host "   Full log: $Log" -ForegroundColor Red
        $Result = 'FAIL'
    }
    Write-Host "`n--- Paste row into docs/architecture/memory-tiering-bake-criteria.md Section 4 ---" -ForegroundColor Blue
    Write-Host "|  ?  | $Date | full readiness | (pending) | full readiness | $Result |       |"
    if (-not $Pass) { exit 1 }

# Install cross-compilation targets for GitHub Actions compatibility.
setup-cross:
    @printf "\033[0;34m Installing cross-compilation targets...\033[0m\n"
    rustup target add x86_64-unknown-linux-gnu
    rustup target add aarch64-unknown-linux-gnu
    rustup target add x86_64-pc-windows-msvc
    @printf "\033[0;32m✅ Cross-compilation targets installed\033[0m\n"

# Cross-compile check for GitHub Actions compatibility.
check-cross:
    @printf "\033[0;34m Cross-compilation validation using CI pipeline...\033[0m\n"
    cargo run -q --release -p uffs-ci-pipeline -- cross-check

# Type-check all #[cfg(windows)] code paths from macOS using cargo-xwin.
#
# Catches missing imports, wrong types, and dead code in Windows-only blocks
# that `cargo check` on macOS silently skips — including `#[cfg(windows)]`
# tests, benches, and `std::os::windows::*` usage.  CI today only runs on
# Linux (`ubuntu-22.04`), so this recipe is the ONLY pre-PR gate that
# exercises Windows-specific code.
#
# Uses `--all-targets --all-features` so tests and benches are checked
# alongside libs and bins (this is how the Windows-only bench / test bugs
# that motivated this gate were surfaced).  Runs in ~2–5 s warm once
# xwin has cached the MSVC SDK under `~/Library/Caches/xwin/`.
check-windows:
    @printf "\033[0;34m🪟 Windows cross-check (cargo xwin check, all-targets all-features)...\033[0m\n"
    cargo xwin check --workspace --all-targets --all-features --target x86_64-pc-windows-msvc
    @printf "\033[0;32m✅ Windows cross-check passed\033[0m\n"

# Cross-platform compile check across all three supported targets.
#
# Runs native (host) + Linux (via cargo-zigbuild when `zig` is on PATH,
# else Docker `lint-ci-linux`) + Windows (via xwin, through
# `check-windows`).  Intended as a manual "pre-PR sweep"; the pre-push
# hook runs the host + Windows subset only (Linux is too slow for a
# commit-time gate — CI covers it).
#
# Linux path order (Phase L1.4 of windows-clippy-and-linux-cross-plan.md):
#   1. Prefer `just lint-ci-linux-zig` (native, ~10–20 s warm) when
#      `zig` and `cargo-zigbuild` are both available.
#   2. Fall back to `just lint-ci-linux` (Docker, authoritative —
#      mirrors CI's `rust:latest` image exactly).
#   3. Skip with a hint when neither is available.
#
# Skips silently if a prerequisite tool (cargo-xwin, zig, docker) is
# missing, but reports which targets were exercised so you know the
# coverage.
check-all-targets:
    #!/usr/bin/env bash
    set -euo pipefail
    printf "\033[0;34m🌐 Cross-platform compile check (macOS + Linux + Windows)...\033[0m\n"
    printf "\033[0;36m   ── macOS (native host) ──\033[0m\n"
    cargo check --workspace --all-targets --all-features
    printf "\033[0;32m   ✅ native host\033[0m\n\n"
    printf "\033[0;36m   ── Windows x86_64-pc-windows-msvc (xwin) ──\033[0m\n"
    if command -v cargo-xwin >/dev/null 2>&1; then
        cargo xwin check --workspace --all-targets --all-features --target x86_64-pc-windows-msvc
        printf "\033[0;32m   ✅ Windows (xwin)\033[0m\n\n"
    else
        printf "\033[1;33m   ⚠  cargo-xwin not installed — skipping; install with: \033[0;36mcargo install cargo-xwin\033[0m\n\n"
    fi
    printf "\033[0;36m   ── Linux x86_64-unknown-linux-gnu ──\033[0m\n"
    if command -v zig >/dev/null 2>&1 && command -v cargo-zigbuild >/dev/null 2>&1; then
        printf "\033[0;36m   · using cargo-zigbuild (native, no Docker)\033[0m\n"
        just lint-ci-linux-zig
    elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        printf "\033[0;36m   · using Docker (authoritative; install \033[0;36mzig\033[0m + \033[0;36mcargo-zigbuild\033[0m for the faster path)\033[0m\n"
        just lint-ci-linux
    else
        printf "\033[1;33m   ⚠  Neither zigbuild nor Docker available — skipping; install one via \033[0;36mjust install-dev-tools\033[0m\n"
    fi
    printf "\033[0;32m✅ Cross-platform check complete\033[0m\n"

# Update everything: Rust toolchain, cargo tools, system packages.
# Uses cargo-binstall (pre-built binaries) when available for ~100× faster installs.
# Run before `just go` or `just ship` to stay cutting-edge.
[unix]
update-tools:
    #!/usr/bin/env bash
    set -euo pipefail
    printf "\033[1;34m🔄 Updating all development tools\033[0m\n"
    echo "========================================================"

    # ── 1. Rust toolchain ──────────────────────────────────────
    printf "\n\033[0;34m🦀 Step 1/3: Rust toolchain\033[0m\n"
    if command -v brew >/dev/null 2>&1 && brew list rustup 2>/dev/null | grep -q rustup; then
        printf "  → rustup managed by Homebrew\n"
        brew upgrade rustup 2>/dev/null || true
    else
        rustup self update 2>/dev/null || true
    fi
    rustup update
    just toolchain-sync
    printf "\033[0;32m  ✅ Rust toolchain up to date\033[0m\n"

    # ── 2. Cargo tools ─────────────────────────────────────────
    printf "\n\033[0;34m📦 Step 2/3: Cargo tools\033[0m\n"
    TOOLS=(
        cargo-nextest
        cargo-llvm-cov
        cargo-deny
        cargo-xwin
        sccache
        cargo-machete
        cargo-outdated
        cargo-semver-checks
        cargo-mutants
        cargo-insta
        rust-script
        flamegraph
        samply
    )
    TOOL_LIST="${TOOLS[*]}"
    if command -v cargo-binstall >/dev/null 2>&1; then
        printf "  → Using cargo-binstall (fast, pre-built binaries)\n"
        cargo binstall -y --no-confirm $TOOL_LIST
    else
        printf "  → Using cargo install (compiling from source — slower)\n"
        printf "  💡 Install cargo-binstall for ~100× faster updates:\n"
        printf "     curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash\n"
        cargo install $TOOL_LIST
    fi
    printf "\033[0;32m  ✅ Cargo tools up to date\033[0m\n"

    # ── 3. System packages ─────────────────────────────────────
    printf "\n\033[0;34m🍺 Step 3/3: System packages\033[0m\n"
    if command -v brew >/dev/null 2>&1; then
        brew upgrade just 2>/dev/null || printf "  → just already up to date\n"
    else
        printf "  → No Homebrew detected, skipping system packages\n"
    fi
    printf "\033[0;32m  ✅ System packages up to date\033[0m\n"

    echo ""
    printf "\033[1;32m🎉 All tools updated!\033[0m\n"
    printf "  rustc:    $(rustc --version)\n"
    printf "  nextest:  $(cargo nextest --version 2>/dev/null | head -1)\n"
    printf "  llvm-cov: $(cargo llvm-cov --version 2>/dev/null)\n"

[windows]
update-tools:
    #!powershell
    Write-Host "`n[update-tools] Updating all development tools" -ForegroundColor Blue
    Write-Host "========================================================"

    # --- 1. Rust toolchain ------------------------------------
    Write-Host "`n[Rust] Step 1/3: Rust toolchain" -ForegroundColor Blue
    rustup self update 2>$null
    rustup update
    just toolchain-sync
    Write-Host "  [OK] Rust toolchain up to date" -ForegroundColor Green

    # --- 2. Cargo tools ---------------------------------------
    Write-Host "`n[Pkg] Step 2/3: Cargo tools" -ForegroundColor Blue
    $tools = @(
        "cargo-nextest"
        "cargo-llvm-cov"
        "cargo-deny"
        "sccache"
        "cargo-machete"
        "cargo-outdated"
        "cargo-semver-checks"
        "cargo-mutants"
        "cargo-insta"
        "rust-script"
    )
    $toolList = $tools -join " "
    if (Get-Command cargo-binstall -ErrorAction SilentlyContinue) {
        Write-Host "  -> Using cargo-binstall (fast, pre-built binaries)"
        Invoke-Expression "cargo binstall -y --no-confirm $toolList"
    } else {
        Write-Host "  -> Using cargo install (compiling from source - slower)"
        Write-Host "  [TIP] Install cargo-binstall for faster updates:" -ForegroundColor Yellow
        Invoke-Expression "cargo install $toolList"
    }
    Write-Host "  [OK] Cargo tools up to date" -ForegroundColor Green

    # --- 3. System packages -----------------------------------
    Write-Host "`n[Pkg] Step 3/3: System packages" -ForegroundColor Blue
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget upgrade Casey.Just 2>$null
    } elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
        scoop update just 2>$null
    } else {
        Write-Host "  -> No winget/scoop detected, skipping system packages"
    }
    Write-Host "  [OK] System packages up to date" -ForegroundColor Green

    Write-Host "`n[DONE] All tools updated!" -ForegroundColor Green
    Write-Host "  rustc:    $(rustc --version)"
    Write-Host "  nextest:  $(cargo nextest --version 2>$null | Select-Object -First 1)"



# Quick deploy to Windows: version bump → xcompile → commit → push.
# Skips tests, lint, coverage, and macOS native builds. For debug iteration only.
# Alias: just q
[unix]
q: quick-deploy

[unix]
quick-deploy:
    #!/usr/bin/env bash
    set -euo pipefail
    TOTAL_START=$(date +%s)
    printf "\033[1;34m⚡ Quick Deploy to Windows (skip CI)\033[0m\n"
    printf "\033[1;33m⚠️  No tests, no linting — debug iteration only!\033[0m\n"
    echo "========================================================"

    # Version bump retired in Phase R5 — using current version
    NEW_VERSION=$(awk '/^\[workspace\.package\]/{flag=1; next} flag && /^version/{print $3; exit}' Cargo.toml | tr -d '"')
    printf "\n\033[0;34m📋 Using current version: v%s\033[0m\n" "$NEW_VERSION"

    # Sync workflow state so build-cross-all.rs uses the correct version
    STATE_FILE="build/.uffs-workflow-state.json"
    if [ -f "$STATE_FILE" ]; then
        # Update current_version in-place using portable sed
        sed -i.bak "s/\"current_version\": *\"[^\"]*\"/\"current_version\": \"${NEW_VERSION}\"/" "$STATE_FILE"
        rm -f "${STATE_FILE}.bak"
        printf "\033[0;36m  → Synced workflow state to v%s\033[0m\n" "$NEW_VERSION"
    fi

    # 1. Cross-compile for Windows (build-cross-all.rs uploads to GitHub Release)
    printf "\n\033[0;34m🔨 Step 1/3: Cross-compile for Windows...\033[0m\n"
    START=$(date +%s)
    rust-script scripts/ci/build-cross-all.rs
    END=$(date +%s)
    printf "\033[0;32m  → Build completed in %ds\033[0m\n" $((END - START))

    # 2. Git commit
    #
    # Uses `git commit -S` (force-sign) because this commit is
    # pushed directly to `main`, which has the GitHub branch-
    # protection rule "Require signed commits".  Bypassing signing
    # here used to silently break the merge gate on PRs that
    # touched the same files later (PR #130, 2026-05-05).  Inherits
    # the user's `user.signingkey`; fails loudly if no key is
    # configured (correct: the commit cannot land on `main`
    # without one).
    printf "\n\033[0;34m📝 Step 2/3: Git commit...\033[0m\n"
    git add .
    git commit -S -m "debug: quick-deploy v${NEW_VERSION} [skip ci]"
    printf "\033[0;32m  → Committed\033[0m\n"

    # 3. Git push
    printf "\n\033[0;34m🚀 Step 3/3: Git push...\033[0m\n"
    git pull origin main --rebase
    git push origin main
    printf "\033[0;32m  → Pushed\033[0m\n"

    TOTAL_END=$(date +%s)
    ELAPSED=$((TOTAL_END - TOTAL_START))
    MINS=$((ELAPSED / 60))
    SECS=$((ELAPSED % 60))
    printf "\n\033[1;32m⚡ Quick deploy complete: v%s in %dm %ds\033[0m\n" "$NEW_VERSION" "$MINS" "$SECS"
    printf "\033[0;34m💡 On Windows: git pull && just use\033[0m\n"

# Capture a workspace baseline snapshot under `docs/dev/baseline/<date>/`.
#
# Companion to `docs/dev/architecture/code_clean/phase_0_baseline_implementation_plan.md`
# and `docs/dev/architecture/code_clean/world_class_rust_workspace_refactor_playbook.md`
# (Phase 0).  The recipe captures the cheap (sub-5-minute) inventory
# artifacts — workspace metadata, per-crate risk markers, unsafe blocks,
# feature flags, API surface, CI inventory, dependency graph, supply-chain
# checks.  Compile-bound baselines (`cargo check`, `cargo test`,
# `cargo clippy`, `cargo doc`, `cargo build --timings`) are intentionally
# skipped because they're already published by `pr-fast.yml` on every PR;
# running them locally duplicates ~45 min of CI work with no new info.
#
# The output directory lives under `docs/dev/baseline/` which is
# gitignored (see `.gitignore:135` — "internal dev docs, local only"),
# so the snapshots stay on the local filesystem and never pollute git
# history.
#
# Usage:
#   just baseline-snapshot              # today's date (UTC)
#   just baseline-snapshot 2026-05-12   # specific date
#
# Re-running on the same date overwrites the snapshot's contents.

# Capture a workspace baseline snapshot under docs/dev/baseline/<date>/ (Phase-0 inventory).
baseline-snapshot DATE=`date -u +%Y-%m-%d`:
    #!/usr/bin/env bash
    # `set -eu` only: rg returns exit-1 when a pattern has no matches in a
    # directory, which is a normal outcome for inventory greps (e.g. an
    # async-marker grep over a sync-only crate).  Enabling `pipefail` would
    # propagate every such "no match" as a recipe failure.
    set -eu
    B="docs/dev/baseline/{{ DATE }}"
    mkdir -p "$B"
    printf "\033[0;34m📸 Capturing UFFS workspace baseline → %s\033[0m\n" "$B"

    # ── Pre-flight: env + commit ──────────────────────────────────────────
    git rev-parse HEAD > "$B/_commit.txt"
    git log -1 --oneline >> "$B/_commit.txt"
    {
      echo "## Captured: $(date -u +%FT%TZ)"
      echo
      echo "### Host"; uname -mrsv
      sw_vers 2>/dev/null || true
      echo
      echo "### Toolchain"; rustc --version --verbose
      echo
      echo "### Cargo tooling"
      cargo --version
      cargo nextest --version 2>&1 | head -1 || echo "(cargo-nextest not on PATH)"
      cargo xwin --version    2>/dev/null   || echo "(cargo-xwin not on PATH)"
      cargo deny --version    2>/dev/null   || echo "(cargo-deny not on PATH)"
      cargo vet --version     2>/dev/null   || echo "(cargo-vet not on PATH)"
      cargo audit --version   2>/dev/null   || echo "(cargo-audit not on PATH)"
      just --version          2>&1 | head -1
      gh --version            2>&1 | head -1 || echo "(gh not on PATH)"
    } > "$B/_env.txt"

    # ── Workspace metadata ────────────────────────────────────────────────
    cargo metadata --format-version 1 --no-deps --frozen > "$B/_metadata.json" 2>/dev/null

    # ── Per-crate risk markers (production paths only) ────────────────────
    printf "  • risk_markers.md "
    {
      echo "# Per-crate dimension probes (UFFS baseline)"
      echo
      echo "Captured: $(date -u +%FT%TZ)  ·  commit $(git rev-parse --short HEAD)"
      echo
      printf "| crate | LOC src | unsafe { blocks | async sites | win FFI | unix FFI | pub@root | cast suppress | unwrap prod | expect prod | panic prod | build.rs | crate-doc //! |\n"
      printf "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:-:|:-:|\n"
      for c in crates/uffs-polars crates/uffs-security crates/uffs-text crates/uffs-time \
               crates/uffs-mft crates/uffs-format crates/uffs-core crates/uffs-daemon \
               crates/uffs-client crates/uffs-mcp crates/uffs-broker crates/uffs-cli \
               crates/uffs-diag scripts/ci-pipeline scripts/ci/uffs-gen-hooks scripts/ci/uffs-gen-workflow; do
        name=$(basename "$c")
        src="$c/src"
        [ -d "$src" ] || { printf "| %s | (no src/) | | | | | | | | | | | |\n" "$name"; continue; }
        loc=$(find "$src" -name '*.rs' -not -name '*test*.rs' -not -path '*/tests/*' 2>/dev/null | xargs wc -l 2>/dev/null | awk 'END{print $1+0}')
        # Multi-line `unsafe {` (real blocks only, not doc-comment text)
        unsafe_n=$(rg --count-matches -U --multiline '^[^/]*\bunsafe\s*\{' "$src" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
        async_n=$(rg --count-matches 'async fn|impl .*Future\b' "$src" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
        winff=$(rg --count-matches '#\[cfg\(windows\)\]|windows::Win32' "$src" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
        unixff=$(rg --count-matches '#\[cfg\(unix\)\]|libc::' "$src" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
        pubroot=$(rg --count-matches '^pub ' "$src/lib.rs" 2>/dev/null | awk -F: '{print $NF+0}')
        [ -z "$pubroot" ] && pubroot=0
        # Multi-line attribute support: clippy::cast_* lint names
        cast=$(rg --count-matches -U --multiline 'clippy::cast_possible_truncation|clippy::cast_sign_loss|clippy::cast_possible_wrap|clippy::cast_precision_loss|clippy::cast_lossless' "$src" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
        unwrap_p=$(rg --count-matches '\.unwrap\(\)' "$src" -g '!*test*.rs' -g '!tests/' 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
        expect_p=$(rg --count-matches '\.expect\(' "$src" -g '!*test*.rs' -g '!tests/' 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
        panic_p=$(rg --count-matches 'panic!\(|todo!\(|unimplemented!\(|unreachable!\(' "$src" -g '!*test*.rs' -g '!tests/' 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
        build=$([ -f "$c/build.rs" ] && echo "✅" || echo "")
        # Look for `//!` in first 15 lines of lib.rs or main.rs (window large
        # enough to skip SPDX + Copyright + blank line).
        docs=""
        for entry in "$src/lib.rs" "$src/main.rs"; do
          if [ -f "$entry" ] && head -15 "$entry" | grep -q '^//!'; then docs="✅"; break; fi
        done
        printf "| \`%s\` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n" \
          "$name" "$loc" "$unsafe_n" "$async_n" "$winff" "$unixff" "$pubroot" "$cast" "$unwrap_p" "$expect_p" "$panic_p" "$build" "$docs"
      done
    } > "$B/risk_markers.md"
    printf "✓\n"

    # ── Unsafe inventory ──────────────────────────────────────────────────
    printf "  • unsafe_inventory.md "
    {
      echo "# Unsafe-block inventory"
      echo
      echo "Captured: $(date -u +%FT%TZ)  ·  commit $(git rev-parse --short HEAD)"
      echo
      total=$(rg -nU --multiline '^[^/]*\bunsafe\s*\{' crates/ scripts/ 2>/dev/null | wc -l | xargs)
      echo "**Total real \`unsafe {\` blocks (excludes doc-comment matches): $total**"
      echo
      echo "## Per-crate density"
      echo
      echo "| crate | unsafe { blocks | SAFETY comments | coverage |"
      echo "|---|---:|---:|---:|"
      for c in crates/uffs-* scripts/ci-pipeline scripts/ci/uffs-gen-hooks scripts/ci/uffs-gen-workflow; do
        name=$(basename "$c"); src="$c/src"; [ -d "$src" ] || continue
        nbl=$(rg --count-matches -U --multiline '^[^/]*\bunsafe\s*\{' "$src" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
        nsa=$(rg --count-matches 'SAFETY:' "$src" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
        ratio="—"; if [ "$nbl" -gt 0 ]; then ratio=$(awk -v s="$nsa" -v b="$nbl" 'BEGIN { printf "%.2f", s/b }'); fi
        [ "$nbl" -gt 0 ] && printf "| %s | %d | %d | %s |\n" "$name" "$nbl" "$nsa" "$ratio"
      done | sort -t'|' -k3 -rn
    } > "$B/unsafe_inventory.md"
    printf "✓\n"

    # ── Feature inventory ─────────────────────────────────────────────────
    printf "  • feature_inventory.md "
    {
      echo "# Feature flag inventory"
      echo
      echo "Captured: $(date -u +%FT%TZ)  ·  commit $(git rev-parse --short HEAD)"
      echo
      for c in crates/*/Cargo.toml scripts/*/Cargo.toml scripts/ci/*/Cargo.toml; do
        name=$(awk -F'"' '/^name *=/ {print $2; exit}' "$c")
        block=$(awk '/^\[features\]/{f=1;next} /^\[/{f=0} f' "$c")
        if [ -n "$block" ]; then echo "### \`$name\`"; echo '```toml'; echo "$block"; echo '```'; fi
      done
    } > "$B/feature_inventory.md"
    printf "✓\n"

    # ── API surface ───────────────────────────────────────────────────────
    printf "  • api_surface.md "
    {
      echo "# Public API surface — root-level \`pub\` items per crate"
      echo
      echo "Captured: $(date -u +%FT%TZ)  ·  commit $(git rev-parse --short HEAD)"
      echo
      echo "| crate | total pub | pub use | pub mod | pub fn | pub struct | pub enum | pub trait | pub const |"
      echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|"
      # Helper: count matches of a pattern in a file, returning 0 when no
      # matches (rg exits 1 on no-match, which would trip `set -e`).
      count_in() { rg --count-matches "$1" "$2" 2>/dev/null || echo 0; }
      for c in crates/uffs-*/; do
        name=$(basename "$c"); lib="$c/src/lib.rs"; [ -f "$lib" ] || continue
        n=$(count_in '^pub '         "$lib")
        u=$(count_in '^pub use '     "$lib")
        m=$(count_in '^pub mod '     "$lib")
        f=$(count_in '^pub fn '      "$lib")
        s=$(count_in '^pub struct '  "$lib")
        e=$(count_in '^pub enum '    "$lib")
        t=$(count_in '^pub trait '   "$lib")
        k=$(count_in '^pub const '   "$lib")
        printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n" \
          "$name" "$n" "$u" "$m" "$f" "$s" "$e" "$t" "$k"
      done
    } > "$B/api_surface.md"
    printf "✓\n"

    # ── CI workflow inventory ─────────────────────────────────────────────
    printf "  • ci_inventory.md "
    {
      echo "# CI workflow inventory"
      echo
      echo "Captured: $(date -u +%FT%TZ)  ·  commit $(git rev-parse --short HEAD)"
      echo
      echo "## Workflows under \`.github/workflows/\`"
      echo
      echo "| workflow | trigger | jobs | runs-on (primary) |"
      echo "|---|---|---:|---|"
      for f in .github/workflows/*.yml; do
        name=$(basename "$f")
        trig=$(awk '/^on:/{in_on=1; next} in_on && /^[a-z]/{print; exit}' "$f" | head -1 | tr -d ':' | xargs)
        jobs=$(awk '/^jobs:/{in_j=1; next} in_j && /^  [a-z]/{c++} END{print c+0}' "$f")
        ros=$(grep -m1 'runs-on:' "$f" | sed 's/.*runs-on: *//' | tr -d "'\"")
        printf "| \`%s\` | %s | %s | %s |\n" "$name" "$trig" "$jobs" "$ros"
      done
      echo
      echo "Total workflow files: $(ls .github/workflows/*.yml | wc -l | xargs)"
    } > "$B/ci_inventory.md"
    printf "✓\n"

    # ── Dependency graph ──────────────────────────────────────────────────
    #
    # Source of truth: `Cargo.lock` (static file, sub-second grep/awk).
    # We DO NOT use `cargo tree --workspace --prefix none --no-dedupe |
    # sort -u | wc -l` — that pattern materialises every occurrence of
    # every crate in the resolved graph (~10 MB of text for this workspace)
    # only to throw most of it away.  The lockfile already encodes the
    # resolved (deduplicated) graph: one `[[package]] name = "…"` block
    # per crate-version.  Two grep/awk passes give identical numbers in
    # < 100 ms — see PR #186 review thread for the perf comparison.
    #
    # `cargo tree --workspace -d` is still invoked, but only for the
    # human-readable `duplicate_deps.txt` artifact (which shows the
    # call-graph paths that pull in each duplicated crate).  The COUNTS
    # come from the lockfile, not from grepping the cargo-tree output.
    printf "  • duplicate_deps.md "
    cv=$(grep -c '^name = ' Cargo.lock)
    dn=$(awk -F'"' '/^name = /{print $2}' Cargo.lock | sort -u | wc -l | xargs)
    dup=$(awk -F'"' '/^name = /{print $2}' Cargo.lock | sort | uniq -d | wc -l | xargs)
    wsm=$(jq -r '.packages | length' "$B/_metadata.json" 2>/dev/null || echo 0)
    cargo tree --workspace -d --edges normal,build --color never \
      > "$B/duplicate_deps.txt" 2>&1 || true
    {
      echo "# Dependency baseline"
      echo
      echo "Captured: $(date -u +%FT%TZ)  ·  commit $(git rev-parse --short HEAD)"
      echo
      echo "Counts derived from \`Cargo.lock\` (sub-second).  See"
      echo "\`duplicate_deps.txt\` (\`cargo tree -d\`) for the human-readable"
      echo "call-graph paths."
      echo
      echo "| metric | value |"
      echo "|---|---:|"
      echo "| crate-versions in Cargo.lock | $cv |"
      echo "| distinct crate names         | $dn |"
      echo "| workspace members            | $wsm |"
      echo "| external crate-versions      | $((cv - wsm)) |"
      echo "| external distinct names      | $((dn - wsm)) |"
      echo "| crates with ≥2 versions      | $dup |"
    } > "$B/duplicate_deps.md"
    printf "✓\n"

    # ── Test enumeration (no compile) ─────────────────────────────────────
    printf "  • test_count.txt "
    cargo nextest list --workspace 2>/dev/null > "$B/_tests_full.txt" || true
    total_tests=$(grep -cE '^[a-z][a-z0-9_-]+ ' "$B/_tests_full.txt" || echo 0)
    {
      echo "# Test inventory (cargo nextest list --workspace)"
      echo
      echo "Captured: $(date -u +%FT%TZ)  ·  commit $(git rev-parse --short HEAD)"
      echo
      echo "**Total unit + integration tests: $total_tests**"
      echo
      echo "| crate suite | tests |"
      echo "|---|---:|"
      grep -E '^[a-z][a-z0-9_-]+ ' "$B/_tests_full.txt" | awk '{print $1}' | \
        sort | uniq -c | sort -rn | awk '{printf "| %s | %d |\n", $2, $1}'
    } > "$B/test_count.txt"
    printf "✓\n"

    # ── Supply chain ──────────────────────────────────────────────────────
    printf "  • supply chain (deny/vet/audit) "
    cargo deny  check 2>&1 | tee "$B/deny_baseline.txt"  > /dev/null || true
    cargo vet         2>&1 | tee "$B/vet_baseline.txt"   > /dev/null || true
    cargo audit --quiet 2>&1 | tee "$B/audit_baseline.txt" > /dev/null || true
    printf "✓\n"

    # ── README index ──────────────────────────────────────────────────────
    {
      echo "# Workspace baseline snapshot — {{ DATE }}"
      echo
      echo "| Field | Value |"
      echo "|---|---|"
      echo "| Captured (UTC) | $(date -u +%FT%TZ) |"
      echo "| Commit | \`$(git rev-parse --short HEAD)\` |"
      echo "| Recipe | \`just baseline-snapshot {{ DATE }}\` |"
      echo
      echo "Companion plan: \`docs/dev/architecture/code_clean/phase_0_baseline_implementation_plan.md\`"
      echo
      echo "## Contents"
      echo
      ls -1 "$B" | grep -v '^README\.md$' | awk '{printf "- \x60%s\x60\n", $1}'
    } > "$B/README.md"

    printf "\033[0;32m✓ Snapshot complete → %s\033[0m\n" "$B"