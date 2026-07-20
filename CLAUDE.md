# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

UFFS (Ultra Fast File Search) is a Windows-only, high-performance file search tool written in Rust. It bypasses Windows file enumeration APIs and reads the NTFS Master File Table (MFT) directly, loading data into Polars DataFrames for fast in-memory querying. **MFT reading requires Windows with Administrator privileges.** Non-Windows platforms can build and test index-reading/querying logic, but not live MFT access.

## Build & Development Commands

The primary workflow tool is `just` (justfile). Use `just` to see all commands.

```bash
# Safe-by-default validation (no version bump / deploy / commit / push)
just go

# Explicit ship lane (version bump / build / deploy / commit / push)
just phase2-ship

# Quick check during development (no coverage)
just check

# Format code (rustfmt only)
just fmt

# Run all tests with nextest
just test

# Run a single test or test filter
cargo nextest run -p uffs-mft -- tree
cargo test -p uffs-core -- path_resolver --nocapture

# Run tests in a specific crate
cargo test -p uffs-mft --lib -- --nocapture

# Lint production code (ultra-strict)
just lint-prod

# Lint test code (allows unwrap/expect)
just lint-tests

# Build release binary
just build

# Run coverage report
just coverage-report

# Security audit
just audit

# Full CI pipeline via rust-script (alternative to justfile)
rust-script scripts/ci/ci-pipeline.rs go -v
```

## Architecture

This is a Cargo workspace with a strict compilation isolation strategy:

```
crates/
├── uffs-polars/           Polars facade — all other crates depend on this, NOT polars
│                          directly. Caches Polars compilation (~4 min → ~25 sec rebuilds).
├── uffs-broker-protocol/  Cross-platform broker wire-protocol types (1-byte drive request,
│                          9-byte status+handle response). Pure logic, zero unsafe.
├── uffs-mft/              Core MFT reading library. Windows-only I/O (#[cfg(windows)]).
│                          Reads raw NTFS MFT → Polars DataFrame. Key types: MftReader,
│                          MftIndex, VolumeHandle. Holds the Access Broker handle registry
│                          (register/try_adopt_broker_handle).
├── uffs-core/             Query engine using Polars lazy API. Platform-agnostic.
│                          Key types: MftQuery (builder), FastPathResolver, IndexSearch.
├── uffs-client/           Client-side daemon connect/spawn + broker-presence probe.
├── uffs-daemon/           Resident index server (`uffsd`). Loads MFTs, serves clients over
│                          IPC, runs the per-shard USN journal loop + memory tiering.
│                          Adopts broker handles for non-elevated MFT reads.
├── uffs-broker/           Windows-only LocalSystem service (`uffs-broker.exe`). Vends
│                          elevated, duplicated NTFS volume handles to the non-elevated
│                          daemon over a named pipe, so searches run with zero UAC. bin-only.
├── uffs-mcp/              MCP server (`uffsmcp`) exposing UFFS search as model tools.
├── uffs-cli/              CLI binary (`uffs`). Built on clap. Subcommands: search, index, …
└── uffs-diag/             Diagnostic tools (temporarily in workspace members for analysis).
```

> Support crates (`uffs-security`, `uffs-format`, `uffs-text`, `uffs-time`) and the full
> layered dependency table live in `docs/architecture/crate-graph.md`.
> **Note:** `uffs-tui` and `uffs-gui` have moved to the private `uffs-products` repo.

**Dependency graph (read path):** `uffs-polars` ← `uffs-mft` ← `uffs-core` ← `uffs-cli`.
The service tier sits on top: `uffs-daemon` ← `uffs-core` + `uffs-broker-protocol`;
`uffs-broker` ← `uffs-broker-protocol` + `uffs-mft`; `uffs-client` ← `uffs-broker-protocol`.

**Never import `polars` directly** — always use `uffs-polars` as the dependency.

## Key Architectural Patterns

### MFT DataFrame Schema
The MFT is read into a DataFrame with columns: `frs` (UInt64), `parent_frs` (UInt64), `name` (String), `size` (UInt64), `flags` (UInt32), `created`/`written`/`accessed` (Int64 timestamps), `allocated_size` (UInt64). Column name constants live in `uffs-polars::columns`.

### Path Resolution
Full paths are not stored in the MFT — only `name` and `parent_frs`. The `FastPathResolver` in `uffs-core` reconstructs paths by walking the parent chain using `NameArena` (string interning). This is a critical, performance-sensitive component.

### I/O Pipeline (Windows only)
MFT reading supports multiple modes auto-selected by drive type:
- **SSD** → `ParallelMftReader` (8MB chunks, rayon parallel parse)
- **HDD** → `PrefetchMftReader` (4MB double-buffered, overlapped I/O)
- **Low memory** → `StreamingMftReader`

Records are parsed with `parse_record_zero_alloc` (thread-local buffers, zero heap allocation per record). Output uses SoA (Struct-of-Arrays) layout — parse directly into column vectors, not `Vec<ParsedRecord>`.

### Extension Record Merging
The default record parsers (`io::parser::unified::process_record`, `parse::direct_index::parse_record_to_index` + `direct_index_extension.rs`) always merge extension MFT records (hard links/ADS beyond what fits in the base record) into their base record in the same pass — there is no fast/full toggle on this path; that split was a pre-unification legacy behavior and no longer exists in the CLI or the live query pipeline.

### Access Broker (Windows — non-elevated MFT reads)
Reading the live MFT normally needs Administrator. The **Access Broker** (`uffs-broker`, a `LocalSystem` Windows service) lets the daemon run **non-elevated**: the broker opens the volume, `DuplicateHandle`s an elevated, `FILE_FLAG_OVERLAPPED` handle into the daemon over a named pipe (after verifying the client is `uffsd` + Authenticode via `WinVerifyTrust`), and the daemon adopts a duplicate of it for every MFT/USN/`$MFT`-extent read. The handle registry + `try_adopt_broker_handle` live in `uffs-mft::platform::volume`; the daemon warms up handles in `warm_up_broker_handles` only when **not** already elevated. On the broker handle, use overlapped-offset reads (`read_handle_at`), not `SetFilePointerEx` (which has no synchronous file pointer there). One-time setup: `uffs-broker --install` → no UAC on any later search. Full design + the production follow-ups (all landed) are in `docs/architecture/access-broker-followups.md`.

### Cross-Compilation
Binaries for Windows are cross-compiled from macOS using `cargo xwin`. The `xwin-dev` profile reduces Polars debug info to stay under COFF archive size limits. See `docs/xwin-msvc-rlib-size-root-cause-and-workarounds.md`.

## Linting Standards

The workspace enforces extremely strict Clippy settings in `Cargo.toml` `[workspace.lints]`:
- `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `unreachable` are all **denied**
- All code must be documented (`missing_docs_in_private_items = "deny"`)
- `unsafe_code = "deny"` at the Rust lint level (use `#[allow(unsafe_code)]` + safety comments only when absolutely required)
- Test code gets relaxed rules via `just lint-tests` (allows `unwrap`/`expect`)

## Testing Notes

- Most unit tests run cross-platform (mocked/fixture-based data)
- Tests requiring live MFT access are `#[ignore]` — run with `cargo test -- --ignored` on Windows (elevated)
- Windows-specific code is gated with `#[cfg(windows)]`
- Prefer focused fixture, golden-output, or regression tests when validating parser and query behavior

## Scripts

- `scripts/ci/ci-pipeline.rs` — Full async CI pipeline (rust-script)
- `scripts/dev/build-local.rs` — Local release build helper
- `scripts/trial_run.ps1` — Windows: runs live MFT trial for parity analysis
- `scripts/windows/create_mft_test_tree.ps1` — Windows: generates test directory structures
