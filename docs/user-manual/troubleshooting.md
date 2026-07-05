# Troubleshooting

Common issues and solutions when using UFFS.

> **See also:** [Installation](installation.md) · [Daemon](daemon.md) ·
> [Advanced Diagnostics](advanced-diagnostics.md)

---

## 1  "Connection refused" or "Daemon not running"

**Cause:** The daemon is not running, or a stale PID file exists from
a crashed daemon.

**Fix:**

```bash
# Let auto-start handle it — just run a search
uffs '*.txt'

# Or start manually
uffs --daemon start --data-dir ~/uffs_data

# If stale files are blocking startup
uffs --daemon kill
uffs '*.txt'
```

---

## 2  "Permission denied" (Windows)

**Cause:** Reading the NTFS MFT requires Administrator privileges.

**Fix:**

- Right-click your terminal → **"Run as administrator"**
- Or install [gsudo](https://github.com/gerardog/gsudo) and prefix
  commands with `gsudo`:

```bash
gsudo uffs '*.dll'
```

Without elevation, UFFS can still search offline MFT captures via
`--mft-file` or `--data-dir`.

---

## 3  First Search Is Slow

**Not a bug.** The first search loads the MFT into memory and builds
the in-memory index (~7 s from cache, or ~66 s cold for a large system).
Every subsequent search completes in ~200 ms end-to-end.

If the first search is *always* slow (even when the daemon is running),
the daemon may be restarting each time:

```bash
# Check if daemon is running
uffs --daemon status

# Long view — uptime, restart count, and performance counters
uffs --daemon status -v
```

---

## 4  No Results Returned

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Zero results for any pattern | Wrong data source | Check `--data-dir` path; verify MFT files exist |
| Missing files from specific drives | Drive not loaded | Check `uffs --daemon status` for loaded drives |
| Missing hidden/system files | Filtered by default | Use `--attr hidden` or `--attr system` |
| Missing `$` files | System files hidden | Use `--hide-system false` or search `$*` |
| Missing directories | `--files-only` active | Remove `--files-only` or use `--dirs-only` |

---

## 5  Stale Results

**Cause:** The daemon's in-memory index was loaded from a cached
`.iocp` file that is older than the current MFT state.

**Fix:**

```bash
# Force re-parse of raw MFT data (bypass cache)
uffs --daemon restart --no-cache

# On Windows (re-read live MFT)
uffs --daemon restart
```

The daemon does not watch the filesystem for changes.  If files have
been created or deleted since the daemon started, restart it.

---

## 6  Build Failures

### "error: requires nightly compiler"

UFFS requires Rust nightly (pinned in `rust-toolchain.toml`).

```bash
rustup install nightly
rustup default nightly
# Or just build — rustup reads rust-toolchain.toml automatically
cargo build --release
```

### Polars compilation takes forever

Polars is a large dependency.  The first build compiles it from
source (~4 minutes).  Subsequent builds are incremental (~25 seconds).

The `uffs-polars` facade crate exists specifically to cache Polars
compilation.  Do not import `polars` directly in other crates.

---

## 7  macOS / Linux: "No MFT data found"

macOS and Linux cannot read NTFS drives directly.  You need offline
MFT captures.

```bash
# Check your data directory
ls ~/uffs_data/drive_c/

# Make sure it contains .bin, .mft, or .iocp files
# See: cache-and-data.md for setup instructions
```

> **Full guide:** [Cache & Data Sources](cache-and-data.md)

---

## 8  High Memory Usage

The daemon holds the entire MFT index in memory.  A machine with 7
NTFS drives and 25 million files uses roughly 4–6 GB of RAM.

**Reduce memory:**

- Use `--drives C,D` to load only the drives you need.
- The daemon retires after 2 hours idle (releases memory).

---

## 9  Getting Help

```bash
# Show all available flags
uffs --help

# Show subcommand help
uffs --daemon --help
uffs --agg --help

# Verbose mode for diagnostic output
uffs '*.txt' -v
```

If you are still stuck, include the output of these commands when
reporting an issue:

```bash
uffs --version
uffs --daemon status -v
uffs --status --json
```
