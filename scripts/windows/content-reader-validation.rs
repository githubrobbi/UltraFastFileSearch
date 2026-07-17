#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! colored = "2.0"
//! ```
// =============================================================================
// scripts/windows/content-reader-validation — Content Reader Playback Smoke Test
// =============================================================================
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.
//
// Real, runnable proof that the whole content pipeline (Broker VSS
// lease -> ephemeral target-selection uffsd -> candidate enumeration ->
// privileged uffs-content-reader -> streamed content) actually works at
// runtime on this machine, not just compiles and links: creates a
// uniquely-named sample file, runs the real job pipeline against it,
// and asserts the played-back bytes exactly match what was written.
//
// This is a thin wrapper: it spawns `uffs-content --self-test-vss-playback
// <dir>` and reports its exit status. The round-trip logic itself
// (create snapshot -> spawn ephemeral daemon -> enumerate candidate ->
// spawn Reader -> stream content -> verify -> tear down) lives once, in
// production code, at crates/uffs-content/src/job/self_test.rs
// (`self_test_vss_playback`) — the exact same function this script's
// target and `cargo test -p uffs-content -- --ignored` both exercise,
// so none of the three ever drift apart. Mirrors
// scripts/windows/vss-snapshot-validation.rs's own shape.
//
// Requirements:
//   - Windows with NTFS
//   - Administrator privileges (VSS snapshot creation, and the Reader's
//     OpenFileById device-path open, both need it)
//   - uffs-content.exe, uffsd.exe, and uffs-content-reader.exe built and
//     sitting in the same directory (production install layout, or
//     `cargo build --release` output: all three land in target/release/)
//   - uffs-broker --install already run once on this host
//
// Usage:
//   rust-script scripts/windows/content-reader-validation.rs
//   rust-script scripts/windows/content-reader-validation.rs C:\Temp\uffs-content-test
//   rust-script scripts/windows/content-reader-validation.rs --bin path\to\uffs-content.exe
//   rust-script scripts/windows/content-reader-validation.rs --timeout-secs 60

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use colored::Colorize;

/// How long to wait for `--self-test-vss-playback` before killing it and
/// reporting a timeout, absent a `--timeout-secs` override. The round
/// trip involves a real VSS snapshot create/delete plus spawning two
/// extra child processes (`uffsd`, `uffs-content-reader`), so this is
/// more generous than `vss-snapshot-validation.rs`'s own 30s budget.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// How often the child-process watchdog re-checks `tasklist`.
const WATCHDOG_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Every child-process image name the pipeline may spawn, watched by
/// the watchdog so a hang shows *which* stage it's stuck in.
const WATCHED_IMAGES: &[&str] = &["uffsd.exe", "uffs-content-reader.exe"];

/// Parsed script arguments.
struct ScriptArgs {
    /// Path to the `uffs-content` binary to exercise.
    bin: String,
    /// Directory the self-test creates its sample file under.
    test_dir: String,
    /// How long to wait before killing the child and reporting a timeout.
    timeout: Duration,
}

/// Parse CLI args.
///
/// Usage: `rust-script content-reader-validation [test-dir] [--bin <path>]
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

/// Locate an existing `uffs-content` binary; do **not** auto-build.
///
/// Search order:
///   1. `target\release\uffs-content.exe`   — `cargo build --release` output
///   2. `$USERPROFILE\bin\uffs-content.exe` — `just use` install location
///   3. Bare `uffs-content.exe`             — falls through to PATH lookup
fn default_binary() -> String {
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string());
    let candidates = [
        PathBuf::from("target")
            .join("release")
            .join("uffs-content.exe"),
        PathBuf::from(&home).join("bin").join("uffs-content.exe"),
    ];
    for candidate in &candidates {
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    "uffs-content.exe".to_string()
}

/// Default self-test directory: `%TEMP%\uffs-content-self-test`, or
/// `.\uffs-content-self-test` if `TEMP` isn't set.
fn default_test_dir() -> String {
    let temp = std::env::var("TEMP")
        .or_else(|_| std::env::var("TMP"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(temp)
        .join("uffs-content-self-test")
        .to_string_lossy()
        .into_owned()
}

/// The expected sibling binary paths (`uffsd.exe`, `uffs-content-reader.exe`),
/// mirroring `uffs-content`'s own spawn-a-sibling-binary lookup
/// (`job::ephemeral_daemon::find_daemon_exe` /
/// `job::reader_client::find_reader_exe`) — both must sit next to `bin`.
fn sibling_binary_paths(bin: &str) -> Vec<PathBuf> {
    let dir = PathBuf::from(bin)
        .parent()
        .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);
    WATCHED_IMAGES
        .iter()
        .map(|name| dir.join(name))
        .collect()
}

/// Print `<path> --version -v` (the long, build-fingerprinted form
/// every UFFS binary supports) before running anything — makes a stale-
/// binary mismatch across the three cooperating processes obvious up
/// front instead of something to reverse-engineer from a hang, matching
/// `vss-snapshot-validation.rs`'s own rationale.
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

/// Whether a process with the given image name currently exists,
/// checked via `tasklist`.
fn process_running(image_name: &str) -> bool {
    Command::new("tasklist")
        .args(["/FI", &format!("IMAGENAME eq {image_name}"), "/NH"])
        .output()
        .is_ok_and(|output| {
            String::from_utf8_lossy(&output.stdout)
                .to_lowercase()
                .contains(&image_name.to_lowercase())
        })
}

/// Spawn a background thread that logs each watched image's RUNNING /
/// NOT RUNNING transitions to the terminal, until `stop` is set.
/// Returns the thread's `JoinHandle` so the caller can `stop` then
/// `join` it once the round trip finishes.
fn spawn_process_watchdog(stop: &Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    let stop = Arc::clone(stop);
    std::thread::spawn(move || {
        let mut last_seen: Vec<Option<bool>> = vec![None; WATCHED_IMAGES.len()];
        while !stop.load(Ordering::Relaxed) {
            for (index, image_name) in WATCHED_IMAGES.iter().enumerate() {
                let running = process_running(image_name);
                if last_seen.get(index).copied().flatten() != Some(running) {
                    if running {
                        eprintln!("  [watchdog] {} {image_name}", "RUNNING".green());
                    } else {
                        eprintln!("  [watchdog] {} {image_name}", "NOT RUNNING".yellow());
                    }
                    if let Some(slot) = last_seen.get_mut(index) {
                        *slot = Some(running);
                    }
                }
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
    eprintln!("║  UFFS Content Reader Playback Smoke Test                         ║");
    eprintln!("╚═══════════════════════════════════════════════════════════════╝");
    eprintln!("  Binary:    {}", args.bin.cyan());
    eprintln!("  Test dir:  {}", args.test_dir.cyan());
    eprintln!();

    if !cfg!(windows) {
        eprintln!(
            "  {} uffs-content's real VSS + Reader pipeline is Windows-only — nothing to test on this platform.",
            "⚠".yellow()
        );
        std::process::exit(1);
    }

    print_binary_version("uffs-content:       ", std::path::Path::new(&args.bin));
    for sibling in sibling_binary_paths(&args.bin) {
        let label = format!(
            "{}:",
            sibling.file_stem().map_or_else(
                || "sibling".to_string(),
                |stem| stem.to_string_lossy().into_owned()
            )
        );
        print_binary_version(&format!("{label:<20}"), &sibling);
    }
    eprintln!();

    eprintln!(
        "  Running: {} --self-test-vss-playback {} (timeout: {}s)",
        args.bin,
        args.test_dir,
        args.timeout.as_secs()
    );
    eprintln!("  ─────────────────────────────────────────────────────────────────");

    // `Stdio::inherit()` + `.spawn()` — deliberately NOT `.output()`, and
    // `.spawn()` (not `.status()`) so the loop below can poll and kill
    // on timeout. Same rationale as `vss-snapshot-validation.rs`.
    let mut child = match Command::new(&args.bin)
        .arg("--self-test-vss-playback")
        .arg(&args.test_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            eprintln!("  {} failed to spawn {}: {err}", "✗".red(), args.bin);
            eprintln!(
                "    (build it first: cargo build --release -p uffs-content -p uffs-daemon -p uffs-content-reader)"
            );
            std::process::exit(1);
        }
    };

    let watchdog_stop = Arc::new(AtomicBool::new(false));
    let watchdog = spawn_process_watchdog(&watchdog_stop);

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
                "  {} timed out after {}s — killing uffs-content",
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
                "  {} VSS snapshot + Reader playback round trip passed ({elapsed_ms}ms)",
                "✓".green()
            );
            eprintln!();
            std::process::exit(0);
        }
        Some(status) => {
            eprintln!(
                "  {} VSS snapshot + Reader playback round trip failed ({elapsed_ms}ms)",
                "✗".red()
            );
            eprintln!();
            std::process::exit(status.code().unwrap_or(1));
        }
        None => {
            eprintln!(
                "  {} VSS snapshot + Reader playback round trip timed out ({elapsed_ms}ms) — the \
                 last line printed above (and the watchdog log) show where it was stuck",
                "✗".red()
            );
            eprintln!();
            std::process::exit(124);
        }
    }
}
