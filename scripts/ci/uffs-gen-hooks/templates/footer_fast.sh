
# ── Wait on all, collect failures ──────────────────────────────────────
FAILED=()
for i in "${!PIDS[@]}"; do
    if ! wait "${PIDS[$i]}"; then
        FAILED+=("${NAMES[$i]}")
    fi
done

# ── Per-job status line ────────────────────────────────────────────────
for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"
    failed=0
    for f in "${FAILED[@]+"${FAILED[@]}"}"; do
        [[ "$f" == "$name" ]] && { failed=1; break; }
    done
    if (( failed )); then
        printf '  %s❌%s %s\n' "$C_RED" "$C_RESET" "$name"
    else
        printf '  %s✅%s %s\n' "$C_GREEN" "$C_RESET" "$name"
    fi
done

# ── Optional-tool hint (once, at the end) ──────────────────────────────
missing=()
command -v typos >/dev/null 2>&1 || missing+=("typos-cli")
command -v taplo >/dev/null 2>&1 || missing+=("taplo-cli")
command -v reuse >/dev/null 2>&1 || missing+=("reuse (pipx install reuse)")
if (( ${#missing[@]} > 0 )); then
    # NOTE: no backticks around `just install-dev-tools` — the cyan
    # ANSI codes already emphasise the command, and literal backticks
    # inside a single-quoted printf format string trip shellcheck
    # SC2016 ("expressions don't expand in single quotes") even
    # though they are harmless literal bytes in this context.
    printf '  %s💡%s optional tools missing: %s — run %sjust install-dev-tools%s\n' \
        "$C_CYAN" "$C_RESET" "${missing[*]}" "$C_CYAN" "$C_RESET"
fi

# ── Dump failing output ────────────────────────────────────────────────
if (( ${#FAILED[@]} > 0 )); then
    for name in "${FAILED[@]}"; do
        printf '\n%s==== %s output ====%s\n' "$C_RED" "$name" "$C_RESET"
        cat "$TMP/$name.out"
    done
    DUR=$(( $(date +%s) - START ))
    printf '\n%s❌ lint-fast FAILED (%ss)%s\n' "$C_RED" "$DUR" "$C_RESET" >&2
    exit 1
fi

DUR=$(( $(date +%s) - START ))
printf '%s✅ lint-fast passed (%ss)%s\n' "$C_GREEN" "$DUR" "$C_RESET"
