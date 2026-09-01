# uffs-cli

**The `uffs` command-line client for Ultra Fast File Search.**

[![Crates.io](https://img.shields.io/crates/v/uffs-cli.svg)](https://crates.io/crates/uffs-cli)
[![Documentation](https://docs.rs/uffs-cli/badge.svg)](https://docs.rs/uffs-cli)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](../../LICENSE)
[![Repository](https://img.shields.io/badge/repo-skyllc--ai%2FUltraFastFileSearch-blue)](https://github.com/skyllc-ai/UltraFastFileSearch)

`uffs-cli` ships the **`uffs`** binary — the thin command-line client
for the [UFFS][uffs-repo] search engine.  The CLI itself does no
indexing or query work: all heavy lifting (MFT reading, index build,
query execution) happens in the [UFFS daemon][uffsd], and the CLI is
a stateless front-end that connects over a Unix domain socket
(Linux / macOS) or named pipe (Windows), issues JSON-RPC, and prints
results.

[uffs-repo]: https://github.com/skyllc-ai/UltraFastFileSearch
[uffsd]: https://github.com/skyllc-ai/UltraFastFileSearch

## Why a thin CLI?

The "thin client" design has three concrete consequences:

1. **Cold-start floor stays low.**  The CLI drops `tokio` and (on
   Windows) `ws2_32.dll` from its binary by using the sync-only
   `uffs-client` API.  Process-launch time is ~28 ms post-Phase-1.
2. **All complexity lives in one place.**  The daemon owns the
   million-line MFT reader, the columnar index, the cache, the
   query planner.  The CLI is a few thousand lines of arg parsing,
   IPC plumbing, and stdout formatting.
3. **Auto-spawn is transparent.**  On the first `uffs` invocation the
   CLI auto-spawns the daemon if it isn't already running; subsequent
   invocations reuse the daemon over the warm socket.

### Why the fast path parses its arguments by hand

`uffs-cli` has no `clap` dependency, on purpose.  The cross-tool
benchmark (`docs/research/cross-tool-benchmark-analysis.md`, §4.1.1)
measured Windows process creation at **~12 ms + ~2.7 ms per MB of
binary**: the original 52.7 MB fat client took 152 ms to start, 136 ms
of it before `main()` ran.  Parsing was never the cost — a clap
`Cli::parse()` is ~1 ms — the *weight* was.  So the thin client dropped
Polars, tokio, tracing and clap together and went from 52.7 MB to
~774 KB (Phase 1, v0.5.x).  What is left is a handful of `--flag`
matches in `src/args.rs` and `src/commands/search/args.rs`; the real
search-grammar validation is `SearchParams::from_cli_args` in
`uffs-client`, shared with the daemon, so the CLI never re-implements
it.

clap stays where startup does not matter: `uffs-mft`, `uffs-daemon`,
`uffs-mcp` and `uffs-bench`.

To re-measure on a release box (PowerShell, elevated shell not needed):

```powershell
(Get-Item (Get-Command uffs).Source).Length / 1KB      # binary size, KB
1..10 | ForEach-Object { (Measure-Command { uffs --version }).TotalMilliseconds }
```

## Install

```bash
# Recommended (after the polars-upstream unblock — see deep-dive doc).
cargo install uffs-cli

# Meanwhile, GitHub Releases ships pre-built binaries:
# https://github.com/skyllc-ai/UltraFastFileSearch/releases
```

The published binary is **`uffs`** (not `uffs-cli`).  Add it to your
shell `PATH`; the daemon binary (`uffsd`) ships alongside in the same
release tarball.

## Quick examples

```bash
# Search every loaded drive for Rust source files.
uffs "*.rs"

# Constrain the scope by drive.
uffs "*.rs" --drive C

# Combined system status (daemon + broker + MCP) and version.
uffs --status
uffs --version

# Daemon lifecycle.
uffs --daemon start
uffs --daemon stop
uffs --daemon status

# Index management is daemon-managed (load / preload / forget).
uffs --daemon load --drive C     # hot-load a drive into the running daemon
uffs --daemon preload C          # promote + pin a drive in RAM
uffs --daemon forget D --force   # evict + delete a drive's on-disk cache

# Output redirection (CSV to disk; byte-identical with daemon's
# native --out=file path).
uffs "*.rs" --out-dir /tmp/results
```

Run `uffs --help` for the full command reference.

## Configuration

The CLI inherits its data directory and socket-path conventions from
the daemon — there is no separate CLI config file.  Override at the
daemon level with `--data-dir`, then run the CLI as usual.

## Features

| Feature | Default | Effect |
|---|---|---|
| `mcp-http-probe` | ❌ | Enables `uffs system-status` to probe the MCP HTTP gateway via `std::net::TcpStream`.  Disabled by default because it unconditionally links `ws2_32.dll` on Windows, adding measurable launch overhead. |

Build with the probe feature only if you actively run the MCP HTTP
gateway and want `system-status` to verify its `/status` endpoint:

```bash
cargo install uffs-cli --features mcp-http-probe
```

## Properties

- **No `tokio` in the published binary** — the CLI uses the
  `uffs-client` crate with `default-features = false`, which drops
  the async API and its runtime.  The hot-path IPC client is
  `UffsClientSync`.
- **No `polars` in the published binary** — formatting and CSV
  emission go through the slim `uffs-format` crate (canonical writer
  shared with the daemon).
- **`asInvoker` Windows manifest** — the CLI does not request UAC
  elevation.  The elevated MFT read happens in `uffsd` / `uffs-broker`
  (the latter on Windows-only deployments that need direct volume
  access).
- **PE icon + DPI manifest embedded** — `build.rs` uses
  [`winresource`][winresource] to embed `assets/brand/icons/uffs.ico`
  and the `app.manifest` (PerMonitor V2 DPI, long-path aware) into
  `uffs.exe` on MSVC targets.

[winresource]: https://crates.io/crates/winresource

## What this crate does *not* do

- **Read MFT or build indexes.**  That's `uffs-mft` (the library) and
  `uffsd` (the daemon).
- **Provide a library API.**  This crate is a `[[bin]]` only — its
  internal modules are not part of any SemVer contract.  Library
  consumers should depend on `uffs-client` directly.
- **Run MCP / HTTP servers.**  See `uffs-mcp` for the AI-host bridge.

## Relationship to the UFFS workspace

```
uffs (CLI) ──UffsClientSync (sync)──▶ uffsd
```

The CLI is the front-most layer of the UFFS stack: every other
component (the daemon, the MFT reader, the indexer, the MCP server)
is invisible to the end user.  It is published independently so an
end user can `cargo install uffs-cli` without pulling the entire
workspace.

## License

Licensed under the [Mozilla Public License 2.0](../../LICENSE).
