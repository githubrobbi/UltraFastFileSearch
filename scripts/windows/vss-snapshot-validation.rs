#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! colored = "2.0"
//! ```
// =============================================================================
// scripts/windows/vss-snapshot-validation — Broker VSS Snapshot Smoke Test
// =============================================================================
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.
//
// Real, runnable proof that the whole VSS snapshot pipeline (native
// vss_shim.cpp -> uffs-vss-requestor helper process -> uffs-broker's
// Snapshot Manager lease bookkeeping -> Job Object cleanup) actually
// works at runtime on this machine, not just compiles and links.
//
// This is a thin wrapper: it spawns `uffs-broker --self-test-vss <dir>`
// and reports its exit status. The round-trip logic itself
// (create snapshot -> read a marker file back through the snapshot
// device path -> verify -> delete snapshot) lives once, in production
// code, at crates/uffs-broker/src/broker/snapshot_manager/vss_helper.rs
// (`self_test_round_trip`) — the exact same function this script's
// target and `cargo test -p uffs-broker -- --ignored` both exercise, so
// none of the three ever drift apart.
//
// Requirements:
//   - Windows with NTFS
//   - Administrator privileges (VSS_CTX_FILE_SHARE_BACKUP snapshot creation,
//     and reading a shadow-copy device path back, both need it)
//   - uffs-broker.exe and uffs-vss-requestor.exe built and sitting in the same
//     directory (production install layout, or `cargo build --release` output:
//     both land in target/release/)
//
// Usage:

//   rust-script scripts/windows/vss-snapshot-validation.rs

//   rust-script scripts/windows/vss-snapshot-validation.rs
// C:\Temp\uffs-vss-test

//   rust-script scripts/windows/vss-snapshot-validation.rs --bin
// path\to\uffs-broker.exe

//   rust-script scripts/windows/vss-snapshot-validation.rs --timeout-secs 10

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use colored::Colorize;

/// How long to wait for `--self-test-vss` before killing it and
/// reporting a timeout, absent a `--timeout-secs` override. Both halves
/// of the round trip observed so far (snapshot creation, deletion) take
/// low single-digit seconds; 30s is generous headroom without leaving
/// a genuine hang sitting unreported for minutes.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// How often the helper-process watchdog re-checks `tasklist`.
const WATCHDOG_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Parsed script arguments.
struct ScriptArgs {
    /// Path to the `uffs-broker` binary to exercise.
    bin: String,
    /// Directory the self-test creates its marker file under.
    test_dir: String,
    /// How long to wait before killing the child and reporting a timeout.
    timeout: Duration,
}

/// Parse CLI args.
///
/// Usage: `rust-script vss-snapshot-validation [test-dir] [--bin <path>]
/// [--timeout-secs <n>]`
fn parse_script_args() -> ScriptArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut test_dir: Option<String> = None;
    let mut bin_override: Option<String> = None;
    let mut timeout_secs = DEFAULT_TIMEOUT_SECS;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bin" | "--binary" => {
                bin_override = args.get(i + 1).cloned();
                i += 2;
            }
            "--timeout-secs" => {
                if let Some(value) = args.get(i + 1).and_then(|value| value.parse().ok()) {
                    timeout_secs = value;
                }
                i += 2;
            }
            other if !other.starts_with('-') && test_dir.is_none() => {
                test_dir = Some(other.to_string());
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    ScriptArgs {
        bin: bin_override.unwrap_or_else(default_binary),
        test_dir: test_dir.unwrap_or_else(default_test_dir),
        timeout: Duration::from_secs(timeout_secs),
    }
}

/// Locate an existing `uffs-broker` binary; do **not** auto-build.
///
/// Search order (deliberately the reverse of the other
/// `scripts/windows/*.rs` validation scripts, which prefer the
/// installed `~\bin\` copy to test "whatever's released"): this script
/// exercises `--self-test-vss`, a brand-new flag that has never shipped
/// in any release, so an installed broker predating it would silently
/// fall through to the Service-Control-Manager dispatch path and hang
/// waiting for an SCM that never arrives — confusing to debug. Prefer
/// the just-built dev binary instead:
///   1. `target\release\uffs-broker.exe`   — `cargo build --release` output
///   2. `$USERPROFILE\bin\uffs-broker.exe` — `just use` install location
///   3. Bare `uffs-broker.exe`             — falls through to PATH lookup
fn default_binary() -> String {
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string());
    let candidates = [
        PathBuf::from("target")
            .join("release")
            .join("uffs-broker.exe"),
        PathBuf::from(&home).join("bin").join("uffs-broker.exe"),
    ];
    for candidate in &candidates {
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    "uffs-broker.exe".to_string()
}

/// Default self-test directory: `%TEMP%\uffs-vss-self-test`, or
/// `.\uffs-vss-self-test` if `TEMP` isn't set.
fn default_test_dir() -> String {
    let temp = std::env::var("TEMP")
        .or_else(|_| std::env::var("TMP"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(temp)
        .join("uffs-vss-self-test")
        .to_string_lossy()
        .into_owned()
}

/// The expected `uffs-vss-requestor.exe` path: alongside `bin`,
/// mirroring `helper_exe_path()`'s production lookup in
/// crates/uffs-broker/src/broker/snapshot_manager/vss_helper.rs (it
/// must be a sibling of the running `uffs-broker.exe`).
fn helper_binary_path(bin: &str) -> PathBuf {
    PathBuf::from(bin).parent().map_or_else(
        || PathBuf::from("uffs-vss-requestor.exe"),
        |dir| dir.join("uffs-vss-requestor.exe"),
    )
}

/// Print `<path> --version -v` (the long, build-fingerprinted form
/// every UFFS binary supports) before running anything.
///
/// This exists because a stale binary is exactly what caused a silent,
/// indefinite hang once already: an installed `uffs-broker.exe`
/// predating `--self-test-vss` fell through to the Service-Control-
/// Manager dispatch path instead of running the self-test, with zero
/// output to say so. Printing the git-sha/commit-date fingerprint for
/// *both* binaries up front makes a version mismatch (or a
/// `uffs-vss-requestor.exe` that's older than the `uffs-broker.exe`
/// spawning it) obvious before the test even starts, instead of
/// something you have to reverse-engineer from a hang.
fn print_binary_version(label: &str, path: &std::path::Path) {
    match Command::new(path).args(["--version", "-v"]).output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            for (i, line) in text.lines().enumerate() {
                if i == 0 {
                    eprintln!("  {label}  {}", line.cyan());
                } else {
                    eprintln!("  {}  {line}", " ".repeat(label.len()));
                }
            }
        }
        Ok(output) => {
            eprintln!(
                "  {label}  {} exited {} — {}",
                "?".yellow(),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Err(err) => {
            eprintln!(
                "  {label}  {} not found at {}: {err}",
                "✗".red(),
                path.display()
            );
        }
    }
}

/// Whether any `uffs-vss-requestor.exe` process currently exists,
/// checked via `tasklist` (the same manual check we kept asking for by
/// hand while diagnosing a hang) — folded into the script itself so a
/// hang shows *live* whether the helper is still alive or already gone,
/// without a second terminal.
fn helper_process_running() -> bool {
    Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq uffs-vss-requestor.exe", "/NH"])
        .output()
        .is_ok_and(|output| {
            String::from_utf8_lossy(&output.stdout)
                .to_lowercase()
                .contains("uffs-vss-requestor.exe")
        })
}

/// Spawn a background thread that logs `uffs-vss-requestor.exe: RUNNING`
/// / `NOT RUNNING` to the terminal every time its liveness changes,
/// until `stop` is set. Returns the thread's `JoinHandle` so the caller
/// can `stop` then `join` it once the round trip finishes.
fn spawn_helper_watchdog(stop: &Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    let stop = Arc::clone(stop);
    std::thread::spawn(move || {
        let mut last_seen_running: Option<bool> = None;
        while !stop.load(Ordering::Relaxed) {
            let running = helper_process_running();
            if last_seen_running != Some(running) {
                if running {
                    eprintln!("  [watchdog] {} uffs-vss-requestor.exe", "RUNNING".green());
                } else {
                    eprintln!(
                        "  [watchdog] {} uffs-vss-requestor.exe",
                        "NOT RUNNING".yellow()
                    );
                }
                last_seen_running = Some(running);
            }
            std::thread::sleep(WATCHDOG_POLL_INTERVAL);
        }
    })
}

fn main() {
    let script_start = Instant::now();
    let args = parse_script_args();

    eprintln!();
    eprintln!("╔═══════════════════════════════════════════════════════════════╗");
    eprintln!("║  UFFS Broker VSS Snapshot Smoke Test                             ║");
    eprintln!("╚═══════════════════════════════════════════════════════════════╝");
    eprintln!("  Binary:    {}", args.bin.cyan());
    eprintln!("  Test dir:  {}", args.test_dir.cyan());
    eprintln!();

    if !cfg!(windows) {
        eprintln!(
            "  {} uffs-broker's VSS snapshot pipeline is Windows-only — nothing to test on this platform.",
            "⚠".yellow()
        );
        std::process::exit(1);
    }

    print_binary_version("uffs-broker:       ", std::path::Path::new(&args.bin));
    print_binary_version("uffs-vss-requestor:", &helper_binary_path(&args.bin));
    eprintln!();

    eprintln!(
        "  Running: {} --self-test-vss {} (timeout: {}s)",
        args.bin,
        args.test_dir,
        args.timeout.as_secs()
    );
    eprintln!("  ─────────────────────────────────────────────────────────────────");

    // `Stdio::inherit()` + `.spawn()` — deliberately NOT `.output()`.
    // `.output()` buffers the child's entire stdout/stderr and only
    // hands it back once the process exits, which silently swallowed
    // every `tracing::info!` progress line the Broker prints while a
    // snapshot is being created: the whole point of that instrumentation
    // is to show which step a hang is stuck on *while it's stuck*, not
    // after the fact. Inheriting stdio streams the Broker's own output
    // straight to this terminal in real time instead. `.spawn()` (not
    // `.status()`) so the loop below can poll and kill on timeout — a
    // hung helper connection previously blocked this script forever.
    // This script only ever runs for diagnostics — the Broker inherits
    // this env var to the uffs-vss-requestor.exe it spawns, enabling its
    // otherwise-off-by-default debug log (see run.rs's DEBUG_LOG_ENV_VAR
    // doc comment) automatically, with no manual step needed.
    let mut child = match Command::new(&args.bin)
        .arg("--self-test-vss")
        .arg(&args.test_dir)
        .env("UFFS_VSS_DEBUG_LOG", "1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            eprintln!("  {} failed to spawn {}: {err}", "✗".red(), args.bin);
            eprintln!(
                "    (build it first: cargo build --release -p uffs-broker -p uffs-vss-requestor)"
            );
            std::process::exit(1);
        }
    };

    let watchdog_stop = Arc::new(AtomicBool::new(false));
    let watchdog = spawn_helper_watchdog(&watchdog_stop);

    let deadline = Instant::now() + args.timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(err) => {
                eprintln!("  {} failed to poll child process: {err}", "✗".red());
                std::process::exit(1);
            }
        }
        if Instant::now() >= deadline {
            eprintln!(
                "  {} timed out after {}s — killing the Broker process",
                "✗".red(),
                args.timeout.as_secs()
            );
            if let Err(err) = child.kill() {
                eprintln!("  {} failed to kill timed-out process: {err}", "✗".red());
            }
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(200));
    };

    watchdog_stop.store(true, Ordering::Relaxed);
    let _ = watchdog.join();

    let elapsed_ms = script_start.elapsed().as_millis();

    eprintln!("  ─────────────────────────────────────────────────────────────────");
    match status {
        Some(status) if status.success() => {
            eprintln!(
                "  {} VSS create/read/delete round trip passed ({elapsed_ms}ms)",
                "✓".green()
            );
            eprintln!();
            std::process::exit(0);
        }
        Some(status) => {
            eprintln!(
                "  {} VSS create/read/delete round trip failed ({elapsed_ms}ms)",
                "✗".red()
            );
            eprintln!();
            std::process::exit(status.code().unwrap_or(1));
        }
        None => {
            eprintln!(
                "  {} VSS create/read/delete round trip timed out ({elapsed_ms}ms) — the last \
                 \"vss: ...\"/\"self-test: ...\" line printed above is where it was stuck",
                "✗".red()
            );
            eprintln!();
            std::process::exit(124);
        }
    }
}
