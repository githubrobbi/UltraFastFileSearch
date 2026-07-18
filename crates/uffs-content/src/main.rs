// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! UFFS Content Service — unprivileged content-coordinator binary for
//! downstream consumers (e.g. Docenta).
//!
//! # Status
//!
//! Job intake, manifest construction, and protocol framing are
//! implemented (`uffs_content::job`), but only against the cross-platform
//! `std::fs`-based candidate/content sources, not real VSS snapshots yet.
//! This bin is still a thin `--version`-only entry point — it does not
//! yet parse a job spec off the command line and dispatch it. See
//! Docenta's `uffs-ingest-protocol-v2-vss.md` for the target contract
//! (the authoritative spec this tool is built against) and
//! `docs/dev/architecture/` (local-only) for the surrounding design
//! review.
//!
//! # Usage
//!
//! ```bash
//! uffs-content --version                        # Print version (also -V)
//! uffs-content --serve                           # Run the two-pipe transport server
//!                                                 # (the real entry point for a
//!                                                 # downstream consumer, e.g. Docenta)
//! uffs-content --self-test-vss-playback <dir>    # Elevated smoke test: real VSS
//!                                                 # snapshot + real Reader playback
//! uffs-content --self-test-vss-query <root> <ext> # Elevated smoke test: real
//!                                                 # extension-filtered query against
//!                                                 # an existing directory, verified
//!                                                 # against a ground-truth disk walk
//! uffs-content --self-test-reader-benchmark [query] [--drive C,D,E] # Elevated:
//!                                                 # measure real content-read throughput.
//!                                                 # [query] defaults to "*"; --drive takes
//!                                                 # a comma-separated list (C or C: form,
//!                                                 # matching uffs.exe's own --drive flag)
//!                                                 # and defaults to every local NTFS drive
//!                                                 # when omitted
//! ```

// Reserved for the wire types the bin will emit once job intake is wired
// up as a real CLI entry point; not yet used from this thin bin.
// Dev-dependencies used by `uffs_content`'s tests, not by this bin.
// Used by `uffs_content::job::snapshot_client` (the real Snapshot
// Manager pipe client), not by this thin entry point directly.
#[cfg(windows)]
use anyhow as _;
#[cfg(test)]
use blake3 as _;
// Used by `uffs_content::job::workflow`'s pipelined content reader and
// `uffs_content::job::reader_client`'s per-drive connection pool, not
// by this thin entry point directly.
use crossbeam_channel as _;
// Used by `uffs_content::run` (failure log + summary serialization), not
// by this thin entry point directly.
use serde as _;
use serde_json as _;
#[cfg(test)]
use tempfile as _;
// Used by `uffs_content::serve`'s two-pipe transport server, not by this
// thin entry point directly.
#[cfg(windows)]
use tokio as _;
// Used directly by `init_tracing()` on Windows; on every other platform
// that function doesn't exist, so `tracing` (an unconditional
// dependency — see `Cargo.toml`) goes unused by this bin directly.
#[cfg(not(windows))]
use tracing as _;
#[cfg(windows)]
use uffs_broker_protocol as _;
// Used to spawn/query the ephemeral `uffsd` instance (not by this thin
// entry point directly).
#[cfg(windows)]
use uffs_client as _;
use uffs_content_protocol as _;
// Used by `uffs_content::job::reader_client`/`content_source::VssContentSource`,
// not by this thin entry point directly.
#[cfg(windows)]
use uffs_content_reader_protocol as _;
// Used by `uffs_content::job::vss_job` (default-to-all-drives root
// resolution), not by this thin entry point directly.
#[cfg(windows)]
use uffs_mft as _;
// Used by `uffs_content::serve`'s named-pipe owner-only DACL helpers,
// not by this thin entry point directly.
#[cfg(windows)]
use uffs_security as _;
// Used by `uffs_content::job::workflow`, not by this thin entry point
// directly.
use uuid as _;

/// Install the `tracing` subscriber every `--self-test-*`/`--serve` entry
/// point relies on for diagnostic output (job/lease/daemon/reader
/// lifecycle events across `uffs_content::job`) — mirrors
/// `uffs-broker`/`uffs-content-reader`'s own `fmt()` init exactly
/// (`with_target(false)`, `INFO` by default) so a foreground `--serve`
/// run's log looks the same shape as the Broker's.
///
/// Uses `try_init` so a test harness embedding this crate that already
/// installed a subscriber doesn't panic.
#[cfg(windows)]
fn init_tracing() {
    let init_result = tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .try_init();
    drop(init_result);
}

#[expect(
    clippy::print_stderr,
    reason = "the final ready/scaffold status lines below run whether or not a job intake \
              flag matched, and are plain one-line user-facing status text rather than \
              diagnostic logging — every diagnostic-logging path (self-test/benchmark/serve) \
              now has a real tracing subscriber via init_tracing()"
)]
fn main() {
    // `--version` / `-V` is handled here, before any job dispatch, so it
    // works on every platform and exits 0 — matches `uffs-broker` and
    // `uffsd` so the self-update version probe can parse it uniformly.
    uffs_version::handle_version!("uffs-content");

    #[cfg(windows)]
    init_tracing();
    #[cfg(windows)]
    tracing::info!(
        pid = std::process::id(),
        version = %uffs_version::version_short!("uffs-content"),
        "uffs-content starting"
    );

    let args: Vec<String> = std::env::args().collect();
    if let Some(test_dir) = self_test_vss_playback_dir(&args) {
        std::process::exit(run_self_test_vss_playback(&test_dir));
    }
    if let Some((root, extension)) = self_test_vss_query_args(&args) {
        std::process::exit(run_self_test_vss_query(&root, &extension));
    }
    match self_test_reader_benchmark_args(&args) {
        Some(Ok((roots, query))) => {
            std::process::exit(run_self_test_reader_benchmark(&roots, &query));
        }
        Some(Err(positionals)) => {
            tracing::error!(
                ?positionals,
                "--self-test-reader-benchmark takes exactly one bare [query] argument; \
                 got more than one (this flag no longer takes an \"all\"/roots positional — \
                 use --drive instead, or omit --drive entirely for every local NTFS drive)"
            );
            std::process::exit(1);
        }
        None => {}
    }
    if args.iter().any(|arg| arg == "--serve") {
        std::process::exit(run_serve());
    }

    if uffs_content::is_implemented() {
        eprintln!("uffs-content: ready.");
    } else {
        eprintln!("uffs-content: scaffold only, job intake is not yet implemented.");
    }
}

/// Run [`uffs_content::serve`] and report a fatal startup error, if any.
/// Does not return under normal operation — the server runs for the
/// process's whole lifetime. Returns the process exit code (`1`) only
/// if the server failed to start at all.
#[cfg(windows)]
#[expect(
    clippy::print_stderr,
    reason = "one-shot CLI diagnostic invoked before any tracing subscriber exists"
)]
fn run_serve() -> i32 {
    match uffs_content::serve() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("FAIL: {err:#}");
            1
        }
    }
}

/// Non-Windows stub: the two-pipe transport server only ever serves
/// VSS-backed jobs, which don't exist on this platform.
#[cfg(not(windows))]
#[expect(
    clippy::print_stderr,
    reason = "one-shot CLI diagnostic invoked before any tracing subscriber exists"
)]
fn run_serve() -> i32 {
    eprintln!(
        "uffs-content: --serve is Windows-only (VSS-backed jobs don't exist on this platform)"
    );
    1
}

/// Return the directory argument following `--self-test-vss-playback`,
/// if present.
#[cfg(windows)]
fn self_test_vss_playback_dir(args: &[String]) -> Option<std::path::PathBuf> {
    let flag_index = args
        .iter()
        .position(|arg| arg == "--self-test-vss-playback")?;
    args.get(flag_index + 1).map(std::path::PathBuf::from)
}

/// Non-Windows stub: `--self-test-vss-playback` needs a real VSS
/// snapshot, which doesn't exist on this platform.
#[cfg(not(windows))]
const fn self_test_vss_playback_dir(_args: &[String]) -> Option<std::path::PathBuf> {
    None
}

/// Run [`uffs_content::job::self_test::self_test_vss_playback`] and
/// print a PASS/FAIL result — a manual, elevated smoke test proving the
/// real VSS-snapshot + privileged-Reader content pipeline works at
/// runtime on this machine. Returns the process exit code (`0` pass,
/// `1` fail).
#[cfg(windows)]
#[expect(
    clippy::print_stderr,
    reason = "one-shot CLI diagnostic invoked before any tracing subscriber exists"
)]
fn run_self_test_vss_playback(test_dir: &std::path::Path) -> i32 {
    match uffs_content::job::self_test::self_test_vss_playback(test_dir) {
        Ok(()) => {
            eprintln!(
                "PASS: VSS snapshot + Reader playback round trip succeeded ({})",
                test_dir.display()
            );
            0
        }
        Err(err) => {
            eprintln!("FAIL: {err:#}");
            1
        }
    }
}

/// Non-Windows stub, matching [`self_test_vss_playback_dir`] always
/// returning `None` there (so this is unreachable in practice, but kept
/// for a symmetrical `#[cfg]` shape).
#[cfg(not(windows))]
const fn run_self_test_vss_playback(_test_dir: &std::path::Path) -> i32 {
    1
}

/// Return the `(root, extension)` arguments following
/// `--self-test-vss-query`, if present.
#[cfg(windows)]
fn self_test_vss_query_args(args: &[String]) -> Option<(std::path::PathBuf, String)> {
    let flag_index = args.iter().position(|arg| arg == "--self-test-vss-query")?;
    let root = args.get(flag_index + 1).map(std::path::PathBuf::from)?;
    let extension = args.get(flag_index + 2).cloned()?;
    Some((root, extension))
}

/// Non-Windows stub: `--self-test-vss-query` needs a real VSS snapshot,
/// which doesn't exist on this platform.
#[cfg(not(windows))]
const fn self_test_vss_query_args(_args: &[String]) -> Option<(std::path::PathBuf, String)> {
    None
}

/// Run [`uffs_content::job::self_test::self_test_vss_query_metadata`] and
/// print a PASS/FAIL result. Returns the process exit code (`0` pass, `1`
/// fail).
#[cfg(windows)]
#[expect(
    clippy::print_stderr,
    reason = "one-shot CLI diagnostic invoked before any tracing subscriber exists"
)]
fn run_self_test_vss_query(root: &std::path::Path, extension: &str) -> i32 {
    match uffs_content::job::self_test::self_test_vss_query_metadata(root, extension) {
        Ok(()) => {
            eprintln!(
                "PASS: query metadata/content totals matched ground truth ({}, *.{extension})",
                root.display()
            );
            0
        }
        Err(err) => {
            eprintln!("FAIL: {err:#}");
            1
        }
    }
}

/// Non-Windows stub, matching [`self_test_vss_query_args`] always
/// returning `None` there (so this is unreachable in practice, but kept
/// for a symmetrical `#[cfg]` shape).
#[cfg(not(windows))]
const fn run_self_test_vss_query(_root: &std::path::Path, _extension: &str) -> i32 {
    1
}

/// Success case: `(roots, query)`. Error case: every bare positional
/// argument found, when there was more than the one `[query]` this flag
/// accepts — see [`self_test_reader_benchmark_args`]'s doc comment.
type ReaderBenchmarkArgs = Result<(Vec<std::path::PathBuf>, String), Vec<String>>;

/// Return the `(roots, query)` arguments following
/// `--self-test-reader-benchmark`, if present. `query` is the one bare
/// (non-`--drive`) positional argument, defaulting to `"*"` if omitted.
/// `--drive` takes a comma-separated drive-letter list — each entry in
/// `C` or `C:` form, exactly matching `uffs.exe`'s own `--drive` flag
/// (see [`parse_drive_list`]) — resolved to `<letter>:\\` roots.
/// Omitting `--drive` resolves to an empty `Vec` — every local NTFS
/// drive, see [`uffs_content::job::vss_job::run_vss_job`].
///
/// A *second* bare positional argument (e.g. a leftover `all` from the
/// pre-`--drive` syntax this flag used to have) is a usage error, not
/// silently dropped: `Some(Err(_))` tells [`main`] to `tracing::error!`
/// and exit `1` itself (this function must not call `std::process::exit`
/// directly — `clippy::exit` reserves that to `main`), rather than
/// quietly running the wrong query, which is exactly what used to
/// happen here.
#[cfg(windows)]
fn self_test_reader_benchmark_args(args: &[String]) -> Option<ReaderBenchmarkArgs> {
    let flag_index = args
        .iter()
        .position(|arg| arg == "--self-test-reader-benchmark")?;
    let rest = args.get(flag_index + 1..)?;

    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    let mut positionals: Vec<String> = Vec::new();
    let mut rest_iter = rest.iter();
    while let Some(arg) = rest_iter.next() {
        if arg == "--drive" {
            if let Some(value) = rest_iter.next() {
                roots.extend(parse_drive_list(value));
            }
        } else {
            positionals.push(arg.clone());
        }
    }

    if positionals.len() > 1 {
        return Some(Err(positionals));
    }

    let query = positionals
        .into_iter()
        .next()
        .unwrap_or_else(|| "*".to_owned());
    Some(Ok((roots, query)))
}

/// Parse a comma-separated drive-letter list (each entry `C` or `C:`,
/// case-insensitive, matching `uffs.exe`'s own `--drive` flag) into
/// `<LETTER>:\\` roots. Entries that aren't exactly one ASCII letter
/// (once a trailing `:` is stripped) are silently skipped, matching
/// `uffs.exe`'s own tolerant `--drive` parsing.
#[cfg(windows)]
fn parse_drive_list(value: &str) -> Vec<std::path::PathBuf> {
    value
        .split(',')
        .filter_map(|part| {
            let trimmed = part.trim();
            let letter = trimmed.strip_suffix(':').unwrap_or(trimmed);
            let mut chars = letter.chars();
            let ch = chars.next()?;
            (chars.next().is_none() && ch.is_ascii_alphabetic())
                .then(|| std::path::PathBuf::from(format!("{}:\\", ch.to_ascii_uppercase())))
        })
        .collect()
}

/// Non-Windows stub: `--self-test-reader-benchmark` needs a real VSS
/// snapshot, which doesn't exist on this platform.
#[cfg(not(windows))]
const fn self_test_reader_benchmark_args(_args: &[String]) -> Option<ReaderBenchmarkArgs> {
    None
}

/// Run [`uffs_content::job::self_test::self_test_reader_benchmark`] and
/// print the measured content-read throughput. Returns the process exit
/// code (`0` pass, `1` fail).
#[cfg(windows)]
#[expect(
    clippy::print_stderr,
    reason = "one-shot CLI diagnostic invoked before any tracing subscriber exists"
)]
fn run_self_test_reader_benchmark(roots: &[std::path::PathBuf], query: &str) -> i32 {
    match uffs_content::job::self_test::self_test_reader_benchmark(roots, query) {
        Ok(report) => {
            #[expect(
                clippy::cast_precision_loss,
                reason = "diagnostic-only display value, not computed against further"
            )]
            #[expect(
                clippy::float_arithmetic,
                reason = "diagnostic-only unit conversion for a printed benchmark report"
            )]
            let content_mib = report.content_bytes as f64 / (1_024.0_f64 * 1_024.0_f64);
            eprintln!(
                "PASS: {} candidates ({} succeeded) — {:.2} MiB content-read in {} ms \
                 ({:.2} MiB/s); enumeration+manifest: {} ms",
                report.candidate_count,
                report.succeeded_count,
                content_mib,
                report.content_read_ms,
                report.throughput_mib_per_sec,
                report.enumeration_ms,
            );
            0
        }
        Err(err) => {
            eprintln!("FAIL: {err:#}");
            1
        }
    }
}

/// Non-Windows stub, matching [`self_test_reader_benchmark_args`] always
/// returning `None` there (so this is unreachable in practice, but kept
/// for a symmetrical `#[cfg]` shape).
#[cfg(not(windows))]
const fn run_self_test_reader_benchmark(_roots: &[std::path::PathBuf], _query: &str) -> i32 {
    1
}
