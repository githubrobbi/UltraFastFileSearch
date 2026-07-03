# UFFS Lint Posture

UFFS runs one of the strictest lint configurations of any public Rust
project.  This document is the project's **lint contract**: it
explains *what* we enforce, *why*, and how the trade-offs were chosen
to keep 13 application crates plus 3 tooling crates clean under a
single shared lint config.

The scope covers every lint layer:

- **rustfmt** — formatting baseline (CI gate `cargo fmt --check`).
- **rustc lints** — `unreachable_pub`, `unused_lifetimes`,
  `unsafe_code`, etc.
- **Clippy lints** — `pedantic` + `nursery` + `cargo` groups at
  `deny`, with curated additions from the `restriction` group.
- **rustdoc lints** — `unescaped_backticks`,
  `redundant_explicit_links`, and friends.
- **`cargo-deny`** — license / advisory / source policies (covered
  in detail in `../security/supply-chain-posture.md`).

It is **both** a description of the policy we enforce today and a
roadmap for the policy we are evolving toward.  Sections 1–10
describe current reality.  Section 11 lists evaluated-but-not-yet-
applied enhancements with evidence and acceptance criteria.  Section
12 is an append-only Decisions Log — including decisions we have
explicitly *declined*, so future contributors do not re-litigate
them.

For the broader CI/CD context (where each gate runs, the four-tier
T1–T4 budget model), see [`../dev-flow.md`](../dev-flow.md).  For
supply-chain hygiene (which uses many of the same enforcement
surfaces), see
[`../security/supply-chain-posture.md`](../security/supply-chain-posture.md).

---

## 1  The Two Files

All lint configuration lives in exactly two places:

| File | What it controls |
|------|-----------------|
| `Cargo.toml` `[workspace.lints]` | Which lints are enabled and at what level (`deny` / `warn` / `allow`) |
| `clippy.toml` | Numeric thresholds, test-mode relaxations, and behavioural toggles |

No individual crate has its own `[lints.clippy]` section.  Every
crate inherits `[lints] workspace = true`.  This is the **single
source of truth** invariant, established by the 2026-04-11 lint-
consolidation pass (see §12 Decisions Log entries dated 2026-04-11).
Per-crate overrides were the historic root cause of inconsistent
enforcement; eliminating them is what makes the rest of this
contract enforceable.

A small **belt-and-suspenders** layer lives in `just/shared.just` as
`prod_flags` / `test_flags`, which re-assert the strictest groups on
the command line so a corrupted `Cargo.toml` cannot silently weaken the
gate.  These flags are *redundant by design* with `[workspace.lints]`.

---

## 2  The Four Tiers

```
┌──────────────────────────────────────────────────────────────────┐
│  Tier 1: Lint Groups (deny)                                      │
│  pedantic · nursery · cargo — entire groups at deny level        │
├──────────────────────────────────────────────────────────────────┤
│  Tier 2: Restriction Lints (cherry-picked, deny)                 │
│  ~95 hand-picked lints from clippy::restriction                  │
│  NOT the whole group — each one chosen for a specific reason     │
├──────────────────────────────────────────────────────────────────┤
│  Tier 3: Rust Compiler Lints (deny/warn)                         │
│  unsafe_code · missing_docs · unreachable_pub · future_incompat  │
│  rust_2024_compatibility · nonstandard_style · unexpected_cfgs   │
├──────────────────────────────────────────────────────────────────┤
│  Tier 4: Rustdoc Lints (deny/warn)                               │
│  broken links · invalid code blocks · bare URLs · crate-level    │
└──────────────────────────────────────────────────────────────────┘
```

Tier 1's group-level `deny` already covers every lint in `pedantic`,
`nursery`, and `cargo`.  `Cargo.toml` *also* lists ~80 of those
group-members individually at `deny` level — this is redundant by
intent.  The explicit list gives a reader of `Cargo.toml` a scannable
inventory of the lints we care about (e.g. `unwrap_used`,
`indexing_slicing`, `cognitive_complexity`) without having to
memorise which group each one belongs to.  When a Clippy release
moves a lint between groups, the explicit listing stops the
renaming from silently changing our enforcement level.

### Why deny, not warn?

Warnings get ignored.  CI passes with warnings.  A `warn` that nobody
fixes for a month becomes a `warn` that nobody fixes ever.  We use
`-D warnings` in CI to promote every warning to an error, but setting
the lint level to `deny` directly makes the intent explicit in the
config file — you don't need to know the CI flags to understand the
contract.

The exceptions are lints where false positives exist but the signal is
still valuable: `unreachable_pub`, `elided_lifetimes_in_paths`,
`explicit_outlives_requirements`, `variant_size_differences`,
`unused_crate_dependencies`, `unexpected_cfgs`.  These stay at `warn`.
`rust_2024_compatibility` and `nonstandard_style` are warn-level
*groups* with `priority = -1` so individual lints inside them can be
overridden case-by-case.

---

## 3  Production vs Test Code

UFFS treats production and test code as two different contexts with
different rules:

| Behaviour | Production | Tests |
|-----------|-----------|-------|
| `unwrap()` / `expect()` | **denied** — use `?` or `ok_or()` | **allowed** — tests should crash loudly |
| `panic!()` | **denied** | **allowed** |
| `dbg!()` | **denied** | **allowed** |
| `print!()` / `eprintln!()` | **denied** — use `tracing` | **allowed** |
| `assert!(r.is_ok())` | **denied** — use `r.unwrap()` | **denied** — same rule, use `r.unwrap()` for better diagnostics |
| `#[expect]` without reason | **denied** | **denied** |

This split is implemented via `clippy.toml`:

```toml
allow-unwrap-in-tests = true
allow-expect-in-tests = true
allow-panic-in-tests  = true
allow-dbg-in-tests    = true
allow-print-in-tests  = true
```

### The `#[expect]` rule

Every suppression must use `#[expect]` (not `#[allow]`) and must carry
a `reason = "..."` string:

```rust
// ✗ rejected — stale suppressions go unnoticed
#[allow(clippy::too_many_lines)]
fn big_function() { ... }

// ✗ rejected — no reason
#[expect(clippy::too_many_lines)]
fn big_function() { ... }

// ✓ accepted
#[expect(
    clippy::too_many_lines,
    reason = "NTFS attribute dispatch — 12 match arms, linear and readable"
)]
fn big_function() { ... }
```

`#[expect]` warns when the suppressed lint stops firing (the violation
was fixed but the attribute was left behind).  `#[allow]` silently
stays forever.  The `allow_attributes = "deny"` lint enforces this.

---

## 4  Restriction Lints — The Cherry-Pick Strategy

The `clippy::restriction` group contains ~200 lints (and grows with
every Clippy release).  Enabling the entire group is impractical — many
conflict with each other (e.g. `implicit_return` vs `needless_return`).
The Rust community consensus, followed by projects like Cargo,
rust-analyzer, and Rolldown, is to cherry-pick individually.  Clippy
itself emits `blanket_clippy_restriction_lints` when you try.

UFFS enables ~100 restriction lints, organised into the following
buckets (counts match `[workspace.lints.clippy]` headings in
`Cargo.toml`):

| Bucket | Count | Representative lints |
|--------|------:|---------------------|
| Suppression discipline | 2 | `allow_attributes`, `allow_attributes_without_reason` |
| Casting & pointer hygiene | 5 | `as_pointer_underscore`, `as_underscore`, `deref_by_slicing`, `ptr_as_ptr`, `ptr_cast_constness` |
| Diagnostic & doc hygiene | 5 | `dbg_macro`, `empty_line_after_doc_comments`, `empty_line_after_outer_attr`, `four_forward_slashes`, `cfg_not_test` |
| Iterator & collection refinements | 5 | `iter_filter_is_ok`, `iter_filter_is_some`, `manual_is_power_of_two`, `set_contains_or_insert`, `unnecessary_map_or` / `unnecessary_result_map_or_else` |
| Path & API hygiene | 3 | `pathbuf_init_then_push`, `pub_underscore_fields`, `renamed_function_params` |
| Error handling & safety | 12 | `assertions_on_result_states`, `error_impl_error`, `exit`, `get_unwrap`, `let_underscore_must_use`, `map_err_ignore`, `mem_forget`, `missing_assert_message`, `missing_asserts_for_indexing`, `try_err`, `unused_result_ok`, `unwrap_in_result` |
| Memory & allocation | 6 | `assigning_clones`, `rc_buffer`, `rc_mutex`, `read_zero_byte_vec`, `significant_drop_in_scrutinee`, `significant_drop_tightening` |
| Concurrency & performance | 3 | `mutex_atomic`, `stable_sort_primitive`, `infinite_loop` |
| Iterator patterns | 6 | `collection_is_never_read`, `iter_on_empty_collections`, `iter_on_single_items`, `iter_over_hash_type`, `needless_collect`, `needless_for_each` |
| String & formatting | 5 | `format_push_string`, `manual_string_new`, `needless_raw_string_hashes`, `needless_raw_strings`, `string_lit_chars_any` |
| Numeric & type precision | 4 | `default_numeric_fallback`, `float_arithmetic`, `suspicious_xor_used_as_pow`, `unreadable_literal` |
| Idiomatic patterns | 10 | `equatable_if_let`, `if_then_some_else_none`, `manual_assert`, `manual_instant_elapsed`, `manual_is_ascii_check`, `manual_let_else`, `manual_ok_or`, `non_zero_suggestions`, `option_if_let_else`, `verbose_file_reads` |
| Control flow & logic | 3 | `debug_assert_with_mut_call`, `mixed_read_write_in_expression`, `same_functions_in_if_condition` |
| Code style & structure | 17 | `empty_drop`, `empty_structs_with_brackets`, `impl_trait_in_params`, `let_underscore_untyped`, `min_ident_chars`, `no_effect_underscore_binding`, `nonstandard_macro_braces`, `partial_pub_fields`, `pub_without_shorthand`, `redundant_type_annotations`, `ref_patterns`, `rest_pat_in_fully_bound_structs`, `semicolon_inside_block`, `semicolon_outside_block`, `unnecessary_self_imports`, `unnecessary_struct_initialization`, `unneeded_field_pattern` |
| Filesystem | 3 | `doc_include_without_cfg`, `filetype_is_file`, `large_include_file` |
| Output discipline | 3 | `print_stderr`, `print_stdout`, `use_debug` |
| Portability | 3 | `host_endian_bytes`, `std_instead_of_alloc`, `std_instead_of_core` |
| Testing hygiene | 2 | `tests_outside_test_module`, `redundant_test_prefix` |
| Unused / dead code | 4 | `unused_async`, `unused_peekable`, `unused_rounding`, `unused_trait_names` |

When proposing a new restriction lint, locate it in one of these
buckets (or argue for a new bucket) and pin its `# ─────` heading in
`Cargo.toml` so the inventory stays scannable.

### What we intentionally do NOT enable

| Lint | Why skipped |
|------|-------------|
| `as_conversions` | Too noisy — `as` is idiomatic for infallible widening casts (`u32` → `u64`). We use `as_underscore` to catch only the dangerous inferred-type variant. |
| `arithmetic_side_effects` | Would require wrapping every `+` in `.checked_add()`. Not practical for index arithmetic. We rely on `default_numeric_fallback` + code review. |
| `absolute_paths` | Conflicts with `use` hygiene in large modules. |
| `implicit_return` | Conflicts with `needless_return`. Rust idiom is implicit returns. |
| `missing_inline_in_public_items` | We are not a published library — inlining is handled by LTO. |
| `single_call_fn` | Intentionally allowed — helper functions improve readability even if called once. |
| `redundant_pub_crate` | Conflicts directly with `unreachable_pub`. See §6 below. |
| `multiple_crate_versions` | Polars and tokio pull transitive version conflicts we cannot resolve. |
| `arbitrary_source_item_ordering` | Too invasive for an established 13-crate layout. |
| `mod_module_files` / `self_named_module_files` | Either-or; pick exactly one. Cost of choosing exceeds benefit. |
| `single_char_lifetime_names` | Fights idiomatic `'a`. |
| `pattern_type_mismatch` / `question_mark_used` / `else_if_without_else` | Universally regarded as over-strict. |

---

## 5  Rustc & Rustdoc Lints

Beyond Clippy, the `[workspace.lints.rust]` section enables several
rustc-level lints that Clippy cannot catch.  Group entries use
`priority = -1` so individual group members can be overridden without
fighting the group level.

### `[workspace.lints.rust]`

| Lint | Level | Why |
|------|-------|-----|
| `unsafe_code` | deny | No `unsafe` without explicit `#[allow(unsafe_code)]` + safety comment |
| `missing_docs` | deny | Every public item must be documented |
| `unsafe_op_in_unsafe_fn` | deny | Even inside `unsafe fn`, each operation must be in its own `unsafe {}` block |
| `future_incompatible` (group) | deny | Catch breaking changes before the next edition |
| `rust_2024_compatibility` (group) | warn | Ensure code compiles cleanly on edition 2024 (we already build on it) |
| `nonstandard_style` (group) | warn | Consistent naming conventions (`snake_case`, `UpperCamelCase`, `SCREAMING_SNAKE_CASE`) |
| `unexpected_cfgs` | warn | Catch typos / stale `cfg(...)` attributes that would silently never fire |
| `unused_crate_dependencies` | warn | Surface deps declared in `Cargo.toml` that the crate no longer uses |
| `unreachable_pub` | warn | Flag `pub` items in private modules — should be `pub(crate)` |
| `elided_lifetimes_in_paths` | warn | Make `Frame<'_>` explicit instead of `Frame` |
| `explicit_outlives_requirements` | warn | Remove redundant `where T: 'a` bounds |
| `single_use_lifetimes` | warn | Catch `fn foo<'a>(x: &'a T)` where `'a` is used exactly once — sibling of already-deny `unused_lifetimes` |
| `variant_size_differences` | warn | Surface large enum variants for boxing review |
| `unused_lifetimes` | deny | Remove unnecessary lifetime parameters |
| `unused_import_braces` | deny | Clean import style |
| `unused_macro_rules` | deny | Remove unused arms inside `macro_rules!` |
| `unused_qualifications` | deny | Remove unnecessary path prefixes |

### `[workspace.lints.rustdoc]`

Doc quality is enforced at compile time — broken links break the
build, not just `cargo doc`.

| Lint | Level | Why |
|------|-------|-----|
| `broken_intra_doc_links` | deny | A broken `[Foo]` link is an API rename we forgot to follow |
| `private_intra_doc_links` | warn | Linking to a private item from public docs is usually a mistake |
| `missing_crate_level_docs` | warn | Every crate gets a `//! crate-level explanation` |
| `invalid_codeblock_attributes` | warn | Catch typos like `rust,no-run` (should be `no_run`) in code-fence attributes |
| `invalid_html_tags` | warn | Doc comments are rendered as HTML; invalid tags break the output |
| `invalid_rust_codeblocks` | warn | Doc-test code must at least parse |
| `bare_urls` | warn | Use `[label](url)` instead of pasting a bare URL |
| `unescaped_backticks` | warn | Catch mismatched ` ` pairs in doc comments (stable since 1.78) |
| `redundant_explicit_links` | warn | Detect `[Foo](Foo)`-style links where the intra-doc link alone suffices |

---

## 6  The `unreachable_pub` vs `redundant_pub_crate` Conflict

These two lints directly contradict each other:

```
unreachable_pub (rustc):
  "this `pub` in a private module is unreachable — use `pub(crate)`"

redundant_pub_crate (clippy nursery):
  "this `pub(crate)` is inside a private module — plain `pub` suffices"
```

You cannot satisfy both.  UFFS follows the Rust team's recommendation:
**prefer `unreachable_pub`** and suppress `redundant_pub_crate`:

```toml
# Cargo.toml
unreachable_pub = "warn"           # rustc lint — catches overly broad visibility
redundant_pub_crate = "allow"      # clippy — conflicts with the above
```

The rationale: `unreachable_pub` catches real API-design issues (items
accidentally exposed wider than needed).  `redundant_pub_crate` is purely
cosmetic — `pub(crate)` inside a private module is semantically correct
even if technically redundant.

---

## 7  clippy.toml — Thresholds and Toggles

The `clippy.toml` file tunes Clippy's behaviour where `Cargo.toml`
cannot.  Our standing policy:

> **All numeric thresholds stay at Clippy's defaults.  Violations are
> handled by per-item `#[expect(lint, reason = "...")]` — never by
> raising the threshold globally.**

Rationale:

- A blanket raise hides every future regression past the new ceiling.
- A scoped `#[expect]` documents *which* function we accepted, *why*,
  and *warns* when the function falls back under the limit (the
  suppression becomes dead code and is removed).
- The 2026-04-11 lint-consolidation pass recorded **37 functions**
  across the workspace that carry scoped
  `#[expect(clippy::cognitive_complexity)]` — every one of them is
  an NTFS attribute dispatcher, a request router, or a parser
  orchestrator where extraction would worsen readability.

Currently set in `clippy.toml`:

| Setting | Value | Default | Why |
|---------|-------|--------:|-----|
| (`msrv` / `check-incompatible-msrv-in-tests`) | — | unset | **Intentionally unset** as of 2026-05-18 (refs issue #267).  The workspace has no `[workspace.package].rust-version` claim because `uffs-polars` enables `polars/nightly` unconditionally → transitively requires nightly Rust.  With no MSRV contract, the MSRV-aware lints have nothing to enforce.  See `clippy.toml`'s rationale block + `dev-flow.md §4.7` for the full audit. |
| `allow-unwrap-in-tests` | `true` | false | Tests should crash loudly on assertion-style failures |
| `allow-expect-in-tests` | `true` | false | Same |
| `allow-panic-in-tests` | `true` | false | Same |
| `allow-dbg-in-tests` | `true` | false | Acceptable while a test is being iterated on |
| `allow-print-in-tests` | `true` | false | Tests use `eprintln!` for ad-hoc diagnostics |
| `avoid-breaking-exported-api` | `false` | true | We are not a published library — internal refactoring should not be blocked |
| `check-private-items` | `false` | false | Re-enabling triggers 70+ `missing_errors_doc` false positives on private helpers (kept explicit so the choice is visible) |
| `suppress-restriction-lint-in-const` | `true` | false | Panics in `const` evaluation are compile-time errors, not runtime risks |
| `check-inconsistent-struct-field-initializers` | `true` | false | Clippy's own repo enables this — initializer order must match the struct definition |
| `max-include-file-size` | `200_000` | 1_000_000 | Companion to `large_include_file = "deny"`. The only legitimate in-binary asset today is the 128 KB `$UpCase` table in `uffs-text/src/case_fold.rs`; 200 000 bytes (≈ 195 KiB) gives headroom while catching accidental megabyte assets. |
| `accept-comment-above-statement` | `true` | false | Allow `// allow: <reason>` above a statement to silence `uninlined_format_args` and similar style nits without forcing a scoped `#[expect]` for one-line cases. |
| `accept-comment-above-attributes` | `true` | false | Same, but above an attribute block. Removes a small but constant noise floor without weakening real signal. |

Notable settings we leave at default on purpose:

| Setting | Default | Why we keep the default |
|---------|--------:|-------------------------|
| `cognitive-complexity-threshold` | 25 | Violations get per-function `#[expect]` (see Phase 2D inventory). |
| `too-many-lines-threshold` | 100 | Same — only NTFS pipelines exceed it, and they are documented. |
| `type-complexity-threshold` | 250 | Polars expressions hit this rarely; we suppress per-binding. |
| `enum-variant-size-threshold` | 200 | Forces protocol/event enums to box large payloads or justify in-line storage. |
| `min-ident-chars-threshold` | 1 | A trial bump to 2 produced only false positives on idiomatic names (`ch`, `cp`, `io`, `fs`). The clippy.toml comment captures the experiment. |

### Settings we have not yet set but should consider

Remaining clippy.toml candidates worth evaluating are tracked in §11 under R3/R4 (tooling and project-specific bans). All R2-era clippy.toml toggles are now applied.

---

## 8  CI & Local Gates — the lint matrix

UFFS lints the **same code three times** to defend against
platform-specific drift:

| Surface | Platform | Driver | Local recipe | CI job |
|---------|----------|--------|--------------|--------|
| Native | Host (macOS/Linux) | `cargo clippy` | `just lint-prod` / `lint-tests` / `lint-ci` | `pr-fast.yml` → `clippy` |
| Windows | `x86_64-pc-windows-msvc` | `cargo xwin clippy` (local) / native (CI) | `just lint-ci-windows` | `pr-fast.yml` → `windows-lint` |
| Linux  | `x86_64-unknown-linux-gnu` | `cargo zigbuild clippy` (fast path) / Docker `rust:latest` (authoritative) | `just lint-ci-linux-zig` / `lint-ci-linux` | (host job in `pr-fast.yml` is Linux) |

The justfile defines two complementary flag stacks in
`just/shared.just`:

```just
common_flags := "-D clippy::pedantic -D clippy::nursery -D clippy::cargo \
                 -A clippy::multiple_crate_versions -A clippy::redundant_pub_crate \
                 -W clippy::panic -W clippy::todo -W clippy::unimplemented -D warnings"
prod_flags  := common_flags + " -W clippy::unwrap_used -W clippy::expect_used \
                                -W clippy::missing_docs_in_private_items"
test_flags  := common_flags + " -A clippy::unwrap_used -A clippy::expect_used"
```

These flags duplicate `[workspace.lints]` by design — if someone
accidentally weakens `Cargo.toml`, the CLI gate still catches it.
`panic` / `todo` / `unimplemented` are downgraded to `warn` here so
stray markers surface as advisories during development without
breaking the build.

### Pre-commit and pre-push

The git hooks in `scripts/hooks/` (generated from `scripts/ci/gates.toml`)
run a staged-scoped fast gate at commit time and a full bucket-1 +
bucket-2 gate at push time.  The pre-push gate runs `lint-prod`,
`lint-tests`, `lint-ci`, `lint-ci-windows`, doc tests, and a smoke
nextest profile *before* anything reaches CI — so a Windows-only lint
failure is caught locally without waiting on `pr-fast.yml`.

---

## 9  Adding a New Suppression — The Checklist

When you need to suppress a lint, follow this process:

1. **Use `#[expect]`, not `#[allow]`** — so it warns when stale
2. **Add a `reason = "..."`** — explain *why*, not *what*
3. **Scope as tightly as possible** — prefer per-expression over per-function over per-module
4. **Never use `#![allow]` at crate level** — use `#[expect]` at the narrowest scope
5. **Fix the root cause first** — the canonical example is the
   2026-Q2 cast/truncation hygiene pass, which replaced 105
   `#[expect(clippy::cast_*)]` suppressions with typed conversion
   helpers (purpose-built `try_into_*` wrappers per value domain).
   Attribute spam is a code smell; typed conversions document the
   precondition the attribute was hiding.

```rust
// ✗ Too broad — suppresses the lint for the entire function
#[expect(clippy::indexing_slicing, reason = "...")]
fn parse_record(data: &[u8]) -> Record { ... }

// ✓ Narrow — only the specific expression is suppressed
fn parse_record(data: &[u8]) -> Record {
    #[expect(
        clippy::indexing_slicing,
        reason = "offset validated by bounds check on line 42"
    )]
    let header = &data[..HEADER_SIZE];
    ...
}
```

`allow_attributes_without_reason = "deny"` machine-enforces step 2.
`allow_attributes = "deny"` machine-enforces step 1.

---

## 10  Verification

The full workspace must pass clean with zero errors, zero warnings on
the pinned toolchain (`rust-toolchain.toml`, currently
`nightly-2026-05-09`, `clippy 0.1.97`):

```bash
# Production code (lib + bins) — strictest
just lint-prod          # cargo clippy --workspace --lib --bins --all-features --no-deps -- {{ prod_flags }}

# Test code — unwrap/expect allowed
just lint-tests         # cargo clippy --workspace --tests --all-features --no-deps -- {{ test_flags }}

# CI mirror — exactly what pr-fast.yml runs
just lint-ci            # cargo clippy --workspace --all-targets --all-features --no-deps -- -D warnings

# Windows mirror — authoritative cross-target gate
just lint-ci-windows    # cargo xwin clippy --workspace --all-targets --all-features --target x86_64-pc-windows-msvc --no-deps -- -D warnings

# Optional: Linux mirror (zigbuild fast path)
just lint-ci-linux-zig

# Convenience: prod + tests + ci + fmt in sequence
just lint-all

# Tests
cargo nextest run --workspace
```

The most recent fully-green baseline was established on 2026-04-11
with the lint-consolidation pass (see §12 Decisions Log).  Every
subsequent change to `[workspace.lints]` ships as a green-baseline
delta — the workspace is required to pass `cargo clippy --workspace
--all-targets --all-features --locked --no-deps -- -D warnings` at
the time of merge.

---

## 11  Roadmap — Enhancements under evaluation

Every item below was evaluated against the current Clippy `master`
lint index (~814 lints in `clippy 0.1.97`) and the active toolchain
pin.  Each entry carries:

- **What** — the lint or config to add.
- **Why** — the specific signal we expect.
- **Effort** — rough touch-points; everything is `Cargo.toml` /
  `clippy.toml` only unless noted.
- **Acceptance criteria** — observable state once applied.

Items are ordered by ROI.  When an item is applied, move it out of
§11 and into the corresponding §3 / §4 / §5 / §7 table, then add a
dated line to §12.

### Tier R1 — Applied 2026-05-11

All R1 items have shipped; see the 2026-05-11 entries in §12.  The
resulting state is reflected in §4 (restriction-lint buckets) and §7
(`clippy.toml` settings).  Summary:

- ~~**MSRV pin** — `msrv = "1.91"` + `check-incompatible-msrv-in-tests = true` in `clippy.toml` (now active on all three lint gates).~~ **Reverted 2026-05-18 via issue #267** — the workspace is structurally nightly-only (`uffs-polars` enables `polars/nightly` unconditionally), so the MSRV contract was unverifiable.  Both settings have been removed from `clippy.toml`; see §12 entry for the audit and §7 above for the current empty-by-design state.
- **Endianness portability** — `host_endian_bytes = "deny"` (workspace clean; no NTFS code was using host-endian helpers).
- **Discarded-result hygiene** — `unused_result_ok = "deny"` (drove ~50 surgical conversions from `expr.ok();` to `_ = expr;`).
- **Trait-import hygiene** — `unused_trait_names = "deny"` (drove ~80 conversions from `use Trait;` to `use Trait as _;`).
- **§7 doc / config alignment** — the rule that the doc and config ship together is now machine-enforced by the PR review pattern recorded in §13.

### Tier R2 — Applied 2026-05-11 / 2026-05-12

Eight of the nine R2 candidates have shipped: seven on 2026-05-11
(see the 2026-05-11 entries in §12) and the ninth (`redundant_test_prefix`)
on 2026-05-12 via PR #167 — deferred off the main R2 commit for clean
bisection because it carried a 363-function mechanical rename.  The
resulting state is reflected in §4 (restriction-lint buckets), §5
(rustc/rustdoc tables), and §7 (`clippy.toml` settings).  Summary:

- **Bundled-asset cap** — `large_include_file = "deny"` (clippy) + `max-include-file-size = 200_000` (clippy.toml). Verified clean against the only existing site (128 KB `$UpCase` table).
- **`NonZero` ergonomics** — `non_zero_suggestions = "deny"`. Workspace was already clean.
- **Single-use lifetimes** — `single_use_lifetimes = "warn"` (rustc). Workspace was already clean (0 violations).
- **Doc backticks** — `unescaped_backticks = "warn"` (rustdoc). `cargo doc --workspace` ran with 0 warnings.
- **Redundant explicit doc links** — `redundant_explicit_links = "warn"` (rustdoc). Also 0 hits.
- **Comment-driven suppression positions** — `accept-comment-above-statement = true` + `accept-comment-above-attributes = true` (clippy.toml). Config-only; eliminates a class of false positives.
- **Redundant test prefix** — `redundant_test_prefix = "deny"` (restriction). R2-05, landed 2026-05-12 via PR #167. Drove the `fn test_foo` → `fn foo` mechanical rename across 363 test functions in 36 files inside `#[cfg(test)] mod tests` / `#[cfg(test)]` modules.
- **`string_to_string` not adopted** — Clippy has *renamed-and-removed* this lint in favour of `clippy::implicit_clone`, which is already part of `pedantic` (denied workspace-wide). No action needed.

The remaining item, still under audit:

| Item | What | Why | First check |
|------|------|-----|-------------|
| **`field_scoped_visibility_modifiers = "deny"`** | Flag `pub(super)` / `pub(crate)` on **fields** in favour of fully `pub` or private-with-accessors | Visibility scoping clarity | Probe on 2026-05-11 measured **44 fields** flagged. The pattern is widely-used idiomatic Rust for crate-internal contracts; adoption requires a design discussion before the surgical refactor (44 fields → ~44+ accessor methods). |

### Tier R3 — Tooling / CI additions

| Item | What | Why | Where | Status |
|------|------|-----|-------|--------|
| **`cargo-machete` in pre-push** | Faster, AST-based sibling of `cargo-udeps` (which already runs in Tier 2) | Sub-second local detection of unused deps | `scripts/ci/gates.toml` Bucket-1 + `pr-fast.yml::security` job step | ✅ **Applied 2026-05-12** — see §12 |
| **`cargo-hack` feature-matrix in Tier 2** | Run `cargo hack --each-feature check` across feature-bearing crates (`uffs-client::async`, `uffs-mcp::streamable-http`, `uffs-cli::mcp-http-probe`).  `uffs_mft::zstd` was the original audit anchor but got retired in PR #175 — see decisions-log entry | We currently only test `--all-features`; single-feature breakage is invisible until release | Tier-2 weekly is the right home | ✅ **Applied 2026-05-12** — see §12 |
| **`cargo-mutants` in Tier 2 nightly** | Mutation testing on `uffs-security` (audit-scoped — not `uffs-mft`; see decision-log entry) | High signal for safety-critical paths | Tier-2 weekly job; `mutants.toml` at repo root supplies shared config (timeout, exclusions, `--locked`) | ✅ **Applied 2026-05-12 (advisory)** — see §12 |
| **`cargo-careful`** | Debug-build hardened-std runner | Complement to existing miri coverage | Tier-2 weekly job; scoped to `uffs-security` + `uffs-mft` (the two unsafe-density hotspots) | ✅ **Applied 2026-05-12** — see §12 |
| **`cargo-semver-checks` in `crates-io-dry-run.yml`** | `check-release` diffs current rustdoc JSON against the latest crates.io version per publishable crate.  Catches SemVer-breaking API changes (removed pub items, signature changes, new required generics, etc.) shipped under a non-major bump | Pre-publish safety net for the R6→R9 publish roadmap.  Dormant pre-R8 (no crates.io baseline yet); activates automatically once first publish lands | `crates-io-dry-run.yml` weekly + dispatch — runs alongside `cargo publish --dry-run`; advisory until `FAIL_ON_SEMVER_BREAK=true` flipped post-R8 | ✅ **Applied 2026-05-12** — see §12 |

> **Note on installation paths**: `just install-dev-tools` (in
> `just/test.just`) is the *canonical* onboarding recipe for the gates
> enforced by the pre-push / pr-fast hooks.  `just update-tools` (in
> `just/dev.just`) is a broader "keep everything fresh" recipe that
> already installs `cargo-machete`, `cargo-mutants`,
> `cargo-semver-checks`, `cargo-insta`, etc. — used by maintainers, not
> required for contributors.  When a Tier R3 candidate is promoted to
> a hard gate, it must be added to `install-dev-tools` so any
> contributor running the onboarding recipe gets it; `update-tools`
> alone is insufficient.

### Tier R4 — Project-specific bans (optional, requires intent)

> **Status: ✅ Audit closed 2026-05-12 — NO adoption.**
> All five candidates probed against the workspace; each found
> either redundant with an existing mechanism or unable to be
> expressed cleanly in Clippy.  See §12 Decisions Log entry
> "2026-05-12 — Tier R4 audit closed without adoption" for the
> per-candidate rationale.  Re-open with a new dated entry if a
> future Clippy release adds the missing expressiveness or if a
> concrete bug-class emerges that one of these bans would have
> caught.

Empty configuration entries are worse than no entry — declare these
only when a concrete ban list exists.  Candidates considered (all
declined; see decisions log):

- `disallowed-methods` — `std::env::set_var` / `remove_var` (now
  `unsafe` in Rust 2024), `Path::is_file` (returns `false` for
  symlinks — we already deny `filetype_is_file`, but a method-level
  ban is sharper).
- `disallowed-types` — `Box<dyn Error>` if we want to keep typed
  errors via `thiserror` (which we use workspace-wide).
- `enforced-import-renames` — e.g. force consistent aliasing of
  `tokio::time::Duration` vs `std::time::Duration` if either is
  preferred at call sites.
- `excessive-nesting-threshold = 10` — early signal in deep parser
  code (likely a no-op given the current code, but cheap insurance).

---

## 12  Decisions Log

Append-only.  Each entry: date, decision, rationale, link to PR/commit
if applicable.  Re-opening a decision requires a new dated entry that
references and supersedes the earlier one.

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-11 | All Clippy thresholds left at upstream defaults; violations get scoped `#[expect]` | Blanket threshold raises hide regressions; scoped suppressions warn when stale and document intent.  See §9 for how `#[expect]` cooperates with the lint engine. |
| 2026-04-11 | `pedantic` + `nursery` + `cargo` groups all at `deny`, not `warn` | CI `-D warnings` already promotes `warn → error` on every PR; making the workspace manifest authoritative removes the "but locally it only warns" gap and matches developer-machine behaviour to CI. |
| 2026-04-11 | Single source of truth: `[workspace.lints] workspace = true`; no crate-level overrides | Per-crate overrides were the historic root cause of inconsistent enforcement.  Removing them is what makes every other entry in this log enforceable workspace-wide. |
| 2026-04-11 | `redundant_pub_crate = "allow"` (Clippy) in favour of `unreachable_pub = "warn"` (rustc) | Direct conflict — see §6. The rustc lint catches real API mistakes; the Clippy lint is cosmetic. |
| 2026-04-11 | `multiple_crate_versions = "allow"` | Polars + tokio transitive graph is outside our control; deferred to `cargo-vet` / `cargo-deny` for risk management. |
| 2026-04-11 | `min-ident-chars-threshold` stays at 1 | Trial bump to 2 produced only false positives on `ch`, `cp`, `io`, `fs`. Recorded in `clippy.toml`. |
| 2026-04-11 | `check-private-items = false` | Re-enabling triggered 70+ `missing_errors_doc` false positives on private helpers. Re-evaluate when Clippy gains finer-grained control. |
| 2026-05-11 | Doc §7 thresholds claim corrected; Roadmap + Decisions Log added | This document was previously claiming raised thresholds (30 / 150 / 300 / 256) that were never actually set. Fixed in this rewrite. |
| 2026-05-11 | `msrv = "1.91"` + `check-incompatible-msrv-in-tests = true` in `clippy.toml` | R1 — explicit MSRV pin unlocks ~80 MSRV-aware Clippy lints under all three cross-target drivers (`cargo clippy`, `cargo xwin clippy`, `cargo zigbuild clippy`); test-side gate prevents tests from silently relying on newer compiler APIs. |
| 2026-05-11 | `host_endian_bytes = "deny"` (restriction) | R1 — NTFS on-disk format is little-endian; banning `to_ne_bytes` / `from_ne_bytes` makes the silent endian bug class unreachable. Workspace was already clean. |
| 2026-05-11 | `unused_result_ok = "deny"` (restriction) | R1 — complements existing `let_underscore_must_use`; `.ok();` discards are converted to the idiomatic `_ = expr;` form, which discards `#[must_use]` results without losing the must-use annotation. |
| 2026-05-11 | `unused_trait_names = "deny"` (restriction) | R1 — surfaces `use Trait;` imports that are only consumed through method-resolution and converts them to `use Trait as _;`. Catches accidental name-binding of traits that are never referenced as names. |
| 2026-05-11 | `.ok();` and `let _ = expr;` discards converted to `_ = expr;` form, not gated via `#[allow]` | The idiomatic discard `_ = expr;` satisfies both `unused_result_ok` (not `.ok()`) and `let_underscore_must_use` (not a `let` binding). Per the no-suppression-hacks rule — we never reach for `#[allow]` when the language already offers a correct construct. |
| 2026-05-11 | `large_include_file = "deny"` (restriction) + `max-include-file-size = 200_000` (clippy.toml) | R2 — cheap structural guard against accidentally bundling a megabyte asset into a release binary. Only legitimate site today is the 128 KB `$UpCase` table in `uffs-text/src/case_fold.rs`; 200 000 bytes (≈ 195 KiB) is generous headroom for that file while still catching accidents. |
| 2026-05-11 | `non_zero_suggestions = "deny"` (restriction) | R2 — composes with the already-denied `unwrap_used` to steer `NonZeroU64::new(x).unwrap()` patterns toward `?` / `ok_or` / `unwrap_or_default()`. Workspace was already clean. |
| 2026-05-11 | `single_use_lifetimes = "warn"` (rustc) | R2 — sibling of already-denied `unused_lifetimes`; surfaces `fn foo<'a>(x: &'a T)` where `'a` is used exactly once. Workspace probe found 0 violations — the elision rules already cover all current code. |
| 2026-05-11 | `unescaped_backticks = "warn"` + `redundant_explicit_links = "warn"` (rustdoc) | R2 — catch mismatched ` ` in doc comments and `[Foo](Foo)`-style redundant explicit links. Both lints have been stable since rustdoc 1.78. `cargo doc --workspace --all-features --no-deps` ran with 0 total warnings on adoption. |
| 2026-05-11 | `accept-comment-above-statement = true` + `accept-comment-above-attributes = true` (clippy.toml) | R2 — lets a `// allow: <reason>` comment placed above a statement or attribute silence one-line style nits like `uninlined_format_args` without forcing a scoped `#[expect]` for a single expression. Removes a class of false-positive noise without weakening any real signal. |
| 2026-05-11 | `string_to_string` (R2 candidate) **not adopted** | Clippy has *renamed-and-removed* this lint (`note: \`clippy::string_to_string\` has been removed: \`clippy::implicit_clone\` covers those cases`). `implicit_clone` is already denied via the workspace-wide `pedantic` group, so no action is needed and adopting the deprecated name would only produce a `renamed_and_removed_lints` warning. |
| 2026-05-12 | `redundant_test_prefix = "deny"` (restriction) | R2-05, landed via PR #167 as a standalone commit per the original R2 plan.  Drove 363 `fn test_foo` → `fn foo` renames across 36 test files inside `#[cfg(test)]` modules.  Kept off the main R2 commit so bisection could isolate a pure-rename change from the lint-level additions in the 2026-05-11 batch. |
| 2026-05-12 | `cargo-machete` promoted to a hard gate at pre-push + pr-fast | R3-01.  Fast (~1 s) AST-based unused-dependency detector — complements `cargo-udeps` (Tier 2 weekly; multi-minute, nightly-only) by catching the common case (`[dependencies]` entry with no remaining `use` in the workspace) at PR time instead of a week later.  Wired as `[[gate]] id = "machete"` in `scripts/ci/gates.toml` (`code_changed`, Bucket 1 / `bg`, hard), regenerated `_lint_pre_push.sh` via `just uffs-gen-hooks`, and bundled into `pr-fast.yml`'s existing `security` job step list (display name kept stable to preserve check-run history).  Added to `just install-dev-tools` so the canonical onboarding recipe installs the gate's required binary.  Workspace was already clean against `cargo machete --skip-target-dir` at adoption (verified locally before landing). |
| 2026-05-12 | Doc correction — Tier R3 `cargo-mutants` install claim | The R3 candidate table previously claimed `cargo-mutants` is "Already installed by `install-dev-tools`".  Verified false: `install-dev-tools` (in `just/test.just`) installs only `typos`, `taplo`, `cargo-machete` (added today), `cargo-xwin`, and on macOS `zig` + `cargo-zigbuild`.  `cargo-mutants` lives in `just update-tools`'s broader tool list (`just/dev.just`), which is a maintainer-facing recipe, not a contributor onboarding gate.  Doc updated with an explicit "Note on installation paths" callout explaining the two recipes' distinct roles. |
| 2026-05-12 | `cargo-hack --each-feature` adopted as Tier 2 weekly job | R3-02.  Audit probed `cargo hack --workspace --each-feature check` and surfaced **three E0432/E0425/E0433 errors** in `uffs-mft` when built with `--no-default-features` — un-gated `use zstd::*` calls hidden by the `default = ["zstd"]` feature flag and the workspace-wide `features = ["zstd"]` pins on every consumer.  Fixed in precursor PR #175 by retiring the `uffs-mft.zstd` feature entirely (promoted to a hard dependency since every consumer enabled it).  With `uffs-mft` clean, this job catches the *next* such regression: any future un-gated `use <crate-behind-feature>` against `uffs-client::async`, `uffs-mcp::streamable-http`, or `uffs-cli::mcp-http-probe`.  Wired as the `hack` job in `tier-2.yml` (between `udeps` and `miri`) running `cargo hack --workspace --exclude uffs-polars --each-feature --keep-going check --all-targets --locked`.  `--exclude uffs-polars` matches the existing polars/chrono cross-compile exclusion in `release-automation-plan.md §8.1` (re-enable when polars upstream ships chrono-compat).  `tier-2-summary.needs` and `notify-failure.needs` lists extended.  Not added to `install-dev-tools` — Tier 2 is the canonical home; the per-feature check rebuilds add up to multi-minute even on warm cache, and PR-time cargo clippy `--all-features` covers the common case. |
| 2026-05-12 | `cargo-semver-checks check-release` adopted as second pre-publish guard in `crates-io-dry-run.yml` | R3-05.  Runs alongside the existing `cargo publish --dry-run` step over the same enumerated publishable-crate set, but answers a different question — "does the current API match SemVer expectations vs the latest crates.io release?" instead of "would crates.io accept this package?".  Pre-R8 (no baseline on crates.io yet) `check-release` exits success for every crate (nothing to compare against), so the guard is informational right now.  Activates automatically once the first publish lands at R8 — no workflow edit needed.  Hard-fail toggle `FAIL_ON_SEMVER_BREAK=true` lives in the workflow `env:` block, independent of `FAIL_ON_DRY_RUN_ERROR` so the SemVer gate can be promoted to required without waiting for crate-name reservations to fix the dry-run failures.  Workflow renamed `📦 crates.io dry-run` → `📦 crates.io dry-run + semver-checks` so check-run history reflects the new scope.  Summary table now surfaces BOTH per-crate result tables (semver-checks first because it's the cheaper guard). |
| 2026-05-12 | `cargo-mutants` adopted as Tier 2 weekly job scoped to `uffs-security` (advisory rollout) | R3-04.  Mutation testing measures **test-suite quality**: how many small source mutations (operator swaps, return-value flips, etc.) the test suite catches.  Missed mutations indicate either dead code or test gaps — both worth surfacing in safety-critical paths.  Scoped to `uffs-security` (~198 generated mutations) and NOT `uffs-mft` despite the original audit suggestion: `uffs-mft` test runtime is ~30 s baseline × ~600 mutations would push the Tier 2 budget past 60 min on a 4-core runner, while `uffs-security` lands at 10-15 min and produces the higher-value signal (crypto / keystore / runtime-dir privileges).  `uffs-mft` can be added later if the budget allows; `mutants.toml` at repo root supplies shared config (`--locked`, `timeout_multiplier = 2.0`, exclusion globs).  Job is **advisory** in the initial rollout: `continue-on-error: true` plus `mutants` deliberately omitted from `tier-2-summary`'s required-set check and from `notify-failure.needs`.  The 30-day `cargo-mutants-output-*` artifact preserves `mutants.out/outcomes.json` for offline triage; once a numerical baseline ("X missed out of 198") is recorded, a follow-up PR can promote the gate to hard-fail-on-regression. |
| 2026-05-12 | Tier R4 audit closed without adoption | All five R4 candidates probed against the actual workspace; each declined for a specific reason: **(a) `disallowed-methods` for `std::env::set_var` / `remove_var`** — workspace is `edition = "2024"`, so the compiler already requires `unsafe { }` for these methods at language level.  The 8 existing call sites (test-isolated env-var setting in `uffs-client/src/connect_sync_platform.rs` and `daemon_ctl.rs`) already carry surgical `#[expect(unsafe_code, reason = "std::env::set_var is unsafe in Rust 2024")]` wrappers.  Adding a `disallowed-methods` ban on top would force a second `#[allow]` at every legitimate site (suppression-hack violation) since `set_var` is structurally required there — there is no alternative for test-isolated env-var setting.  Pure noise on top of an already-enforced edition-2024 contract. **(b) `disallowed-methods` for `Path::is_file`** — 3 real call sites (`cache_cleaner.rs`, `daemon_load.rs`, `discovery.rs`).  The closely-related `clippy::filetype_is_file` is already denied workspace-wide and catches the `metadata.file_type().is_file()` form.  The symlink-resolution semantic distinction between `Path::is_file()` and `metadata().is_file()` is real but hypothetical here (broken symlinks aren't a known failure mode in this codebase), and migration would require `?`-style propagation rewrites plus a second mechanism for distinguishing "doesn't exist" from "exists but isn't a file".  Marginal value vs concrete migration noise. **(c) `disallowed-types` for `Box<dyn Error>`** — zero current usages (only one doc-example string in `uffs-core/src/lib.rs:23`), so the ban would be cheap insurance IF Clippy could express it.  It can't: `disallowed_types` matches resolved type paths (e.g. `std::error::Error`), not generic-parameter constraints like "ban `Box<dyn T>` for trait T".  Banning `std::error::Error` outright is too broad (would flag legitimate `dyn Error` trait bounds in third-party signatures we consume).  Insurance without a clean expression mechanism. **(d) `enforced-import-renames` for `Duration`** — workspace is already organically converged: 125 `core::time::Duration` references, 1 `std::time::Duration` reference, 0 `tokio::time::Duration` references.  Enforcement would catch a problem that hasn't existed in practice; the one outlier is trivially fixable in a future change without needing a lint to drive it. **(e) `excessive-nesting-threshold = 10`** — workspace probe found two `uffs-mft/src/parse/` files at ~11 indentation levels (`direct_index.rs`, `io/parser/index.rs`).  Threshold 10 would flag them and demand a refactor of deeply-nested NTFS structural deserialisation — real work for marginal gain since the nesting reflects the domain's multi-level conditional layout.  Threshold 12+ would be a no-op above current code.  Re-open R4 with a new dated entry if a future Clippy release adds the generic-parameter expressiveness needed for the `Box<dyn Error>` ban, OR if a concrete bug-class emerges that one of these bans would have caught. |
| 2026-05-12 | `cargo-careful` adopted as Tier 2 weekly job scoped to `uffs-security` + `uffs-mft` | R3-03.  `cargo-careful` rebuilds `std` with extra debug assertions (slice / iterator bounds, integer overflow, `RefCell` borrow violations) and runs tests against the augmented `std`.  Catches UB classes in std-using code that Miri can't reach because Miri's interpretation cost limits it to narrow scope (4 specific raw-persistence tests today).  Scoped to the two unsafe-density hotspots (`uffs-security` cryptography / keystore, `uffs-mft` NTFS raw parsing) because the other workspace crates are mostly safe Rust and would inflate runtime ~3× for marginal added signal.  Wired as the `careful` job in `tier-2.yml` between `miri` and `tier-2-summary`; `needs:` list extended in `tier-2-summary` and `notify-failure`.  Installed via `taiki-e/install-action`; not added to `install-dev-tools` because Tier 2 weekly is the canonical home and the build-std rebuild is multi-minute even with warm cache (Tier 1 + pre-push already give the inner-loop signal). |
| 2026-05-18 | MSRV verification + `[workspace.package].rust-version` claim **dropped** (refs issue #267) | The inaugural run of the `tier-2.yml::msrv` job (added 2026-05-12 in the row immediately below) failed on commit `e8b6bdf` with `error[E0554]` inside `foldhash-0.2.0/src/lib.rs`.  Root cause is structural: `crates/uffs-polars/Cargo.toml` enables `polars/nightly` unconditionally, which transitively activates `foldhash/nightly` → `#![feature(hasher_prefixfree_extras)]` → invalid on any stable toolchain.  No cargo invocation can break this chain (the enablement is at the dep-declaration level, and every consumer crate transitively depends on `uffs-polars`).  The `rust-version = "1.91"` claim was therefore unverifiable from the moment `uffs-polars` was introduced.  Resolution (one atomic PR): drop the workspace `rust-version` claim, remove `rust-version.workspace = true` from all 15 per-crate manifests, remove the `tier-2.yml::msrv` job + summary wiring, remove `msrv = "1.91"` + `check-incompatible-msrv-in-tests = true` from `clippy.toml`, retire `uffs-manifest-audit`'s invariant 3.4 (`rust-version` consistency) and update its test fixtures, reclassify `dev-flow.md §4.7 GAP 7` as `·N/A·`.  `rust-toolchain.toml` (pinned nightly) is the single source of truth for the required channel.  Forward-looking path: per-crate `[package.rust-version]` on a publishable leaf (e.g. `uffs-time`) + a focused `cargo +stable check -p <crate>` job — do NOT resurrect the workspace-wide claim. |
| 2026-05-12 | MSRV verification adopted as Tier 2 weekly job (hard gate) | R3-06.  Closes `dev-flow.md §4.7 GAP 7`.  `Cargo.toml::workspace.package.rust-version = "1.91"` declares the contract surface downstream consumers see, but `rust-toolchain.toml` pins **nightly**, so every other dev/CI build runs there.  Without an independent stable-1.91 check, any clippy::incompatible_msrv false-negative (new trait impls, deref coercion changes, new `const fn` qualifications, inference improvements — all classes the lint is known to under-cover) ships silently.  New `msrv` job in `tier-2.yml` sits between `mutants` and `tier-2-summary`: installs stable 1.91 via `rustup toolchain install 1.91 --profile minimal --no-self-update`, runs `cargo +1.91 check --workspace --locked --all-features` *and* `--no-default-features` (the two cases bound the feature-combination space without running `cargo-hack`'s full N² matrix — that stays in `tier-2.yml::hack`).  Hard gate (not advisory like `mutants`) because MSRV regressions have a binary correctness signal: either the 1.91 compiler accepts the workspace or it doesn't.  Wired into `tier-2-summary.needs` + success-check and `notify-failure.needs`.  Dedicated cache key `tier-2-msrv` (the 1.91-stable target-dir layout is binary-incompatible with the nightly target-dir every other job uses).  Pre-R8 this catches developer-visible regressions; post-R8 it's a direct SemVer guard \u2014 promote to a hard pre-publish gate (release-time, alongside `cargo-semver-checks`) once the first crates.io publish lands. |
| 2026-05-14 | CI-tooling crates (`uffs-gen-hooks`, `uffs-gen-workflow`, `uffs-ci-pipeline`) brought under the workspace lint contract (issue #212) | The three `scripts/` dev-tool crates inherited `[lints] workspace = true` but had accumulated 270+ violations because they were never audited under the post-R1 / R2 strictness. Resolved without weakening any lint level by combining three patterns: **(1) Surgical root-cause refactors** — all `to_string()` on `&str` → `.to_owned()`; all `let _ = expr;` discards → `_ = expr;` (Rust 2024 idiom satisfying both `let_underscore_must_use` and `unused_result_ok`); `std::collections::*` → `alloc::collections::*` for `BTreeMap` / `BTreeSet` (with `extern crate alloc;` in the bin's `main.rs`); `std::future::Future` / `std::time::Duration` → `core::*`; all `use Trait;` imports consumed only via methods (`Context`, `Colorize`, `Write`, `Parser`) renamed to `Trait as _`; all `string_slice` byte-index slices in version / cargo-toml parsing rewritten as `split_once`-based parsing (eliminates UTF-8 boundary panic risk and is more idiomatic); `arc.clone()` → `Arc::clone(&arc)`; shadowed bindings renamed (`permit_source`, `env_vars_template`, `task_env`); wildcard `_ => {...}` match arms over `WorkflowPhase` replaced with exhaustive enumeration so a new phase requires updating the match. **(2) CLI output discipline via file-level `#[expect]`** — these binaries are operational tools producing user-facing banners, step progress, completion footers, and Debug-formatted state dumps. For the three output-class lints (`print_stdout`, `print_stderr`, `use_debug`) we apply **file-level** `#![expect(...)]` with `reason = "..."` per file that prints. Narrow enough to fail-loud if a file stops printing entirely (lint is `expect`, not `allow` — stale suppressions warn); broad enough to avoid scattering 130+ per-call attributes inside a single CLI dispatcher. Same pattern as `uffs-diag` and `uffs-cli`. **(3) Test-mode idioms via mod-scoped `#[expect]`** — `uffs-gen-hooks` / `uffs-gen-workflow` test modules use single-char fixture bindings (`let q = &workflow.jobs["q"]`) and positional indexing against fixed-shape fixtures; carry mod-scoped `#[expect(clippy::min_ident_chars, clippy::indexing_slicing, reason = "...")]` rather than 200+ per-line attributes. Workspace `cargo clippy --workspace --all-targets` (and `lint-prod` / `lint-tests` / `lint-ci`) ends with 0 errors / 0 warnings on the pinned toolchain; all 64 tests across the two test-bearing crates pass. |
| 2026-05-12 | `cargo-fuzz` adopted as Tier 2 weekly job scoped to `uffs-mft` (advisory rollout) | R3-07.  Closes `dev-flow.md §4.8 GAP 8`.  Two libfuzzer-sys harnesses live in `crates/uffs-mft/fuzz/fuzz_targets/` (committed 2026-04-24 during the security hardening sprint but never wired into recurring schedule): `fuzz_parse_record` exercises `uffs_mft::parse::{parse_record,parse_record_full,parse_record_zero_alloc}` with various FRS values; `fuzz_apply_fixup` exercises the NTFS Update Sequence Array fixup applicator.  Both target real public APIs that process untrusted on-disk bytes — the workspace's primary attack surface for external filesystem images.  Complement to Miri (UB on known inputs), cargo-careful (broad UB coverage on known inputs), and cargo-mutants (test-suite quality on known inputs): fuzz generates *unknown* adversarial inputs.  Scoped to `uffs-mft` and NOT `uffs-security` because `uffs-security` doesn't parse untrusted external bytes (keystore / runtime-dir APIs have bounded inputs already covered by cargo-mutants for test-suite quality); other crates either consume already-parsed values (`uffs-core`) or wrap I/O around `uffs-mft`.  New `fuzz` job in `tier-2.yml` sits between `msrv` and `tier-2-summary`: `cargo +nightly fuzz run <target> -- -max_total_time=900` (15 min per target, 30 min total, well under 60 min job timeout).  Time-budget chosen over run-count budget because libfuzzer coverage discovery rate varies wildly (fast on day 1 with no corpus, slow on day 30 with saturated corpus) — wall-clock budget keeps Tier 2 predictable.  **Advisory rollout** (`continue-on-error: true`): the harnesses have never run, so no corpus seed exists and the first run starts from zero coverage; may find immediate crashes from uninitialised edge cases the existing test suite doesn't reach.  Crashes surface in the weekly summary + `cargo-fuzz-output-*` artifact (90-day retention, includes both `crashes/` reproducers AND `corpus/` coverage seeds) without blocking the workflow.  Once a corpus baseline is established and known crashes are triaged, a follow-up PR can promote to hard-fail-on-regression and switch corpus storage from artifact upload to `actions/cache` for incremental seeded runs.  OSS-Fuzz integration is the next tier beyond that if the project scales there. |

---

## 13  Maintenance Cadence

This document is part of the lint contract.  Keeping it accurate is
how the project stays "world-class strict, machine-enforced".

**On every toolchain bump** (`rust-toolchain.toml` channel change):

1. Update §10's pinned `clippy X.Y.Z` and `nightly-YYYY-MM-DD` strings.
2. Skim Clippy's release notes for new `restriction` lints; route any
   candidates through §11 with a Tier assignment.
3. Skim rustc release notes for new lints; same.
4. Re-run `just lint-all` and `just lint-ci-windows`.  If a previously
   green code path now fails, decide between (a) fixing the code,
   (b) scoping an `#[expect]` with a `reason`, or (c) downgrading the
   lint in §11's Decisions Log.

**On every PR that touches `Cargo.toml [workspace.lints]` or
`clippy.toml`:**

1. The corresponding section here must update in the same PR.
2. If the change is "elevate a Roadmap item", move the row from §11
   into §4 / §5 / §7 and append a row to §12.
3. If the change is "drop a lint we previously enforced", append a row
   to §12 explaining why.  We do not silently weaken the gate.

**On every release** (Tier 2 weekly):

- `cargo-udeps`, miri, and coverage runs are advisory but visible.
  When any becomes consistently red, escalate to a Roadmap item or a
  Decisions Log entry — not silent allow.

The single rule that makes all of the above work: **the doc and the
config land together, or not at all.**
