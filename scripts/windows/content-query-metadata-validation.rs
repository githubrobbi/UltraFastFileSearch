#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! colored = "2.0"
//! ```
// =============================================================================
// scripts/windows/content-query-metadata-validation — Query Metadata Smoke Test
// =============================================================================
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.
//
// Real, runnable proof that a complex (extension-filtered) query against
// the real VSS + ephemeral-daemon pipeline reports correct metadata and
// streams correct content for an *arbitrary, pre-existing* directory of
// real files — not just the single-synthetic-file case
// `content-reader-validation.rs` covers. Runs `uffs-content
// --self-test-vss-query <root> <ext>`, which leases a real VSS snapshot
// of `root`'s drive, spawns the real ephemeral target-selection daemon,
// evaluates a real `ext:<ext>` query against it, streams every matching
// candidate's content through the real privileged `uffs-content-reader`,
// and asserts three independent totals against a ground-truth `std::fs`
// walk of the same directory: candidate count, the manifest's own
// `logical_size` sum, and the bytes actually streamed over CONTENT_CHUNK
// frames.
//
// This is a thin wrapper: the round-trip + verification logic lives once,
// in production code, at
// crates/uffs-content/src/job/self_test.rs (`self_test_vss_query_metadata`)
// — the exact same function this script's target and
// `cargo test -p uffs-content -- --ignored` both exercise, so none of the
// three ever drift apart. Mirrors content-reader-validation.rs's own shape.
//
// Requirements:
//   - Windows with NTFS
//   - Administrator privileges (VSS snapshot creation, and the Reader's
//     OpenFileById device-path open, both need it)
//   - uffs-content.exe, uffsd.exe, and uffs-content-reader.exe built and
//     sitting in the same directory (production install layout, or
//     `cargo build --release` output: all three land in target/release/)
//   - uffs-broker --install already run once on this host
//   - `root` must already exist and contain at least one file with the
//     given extension
//
// Usage:
//   rust-script scripts/windows/content-query-metadata-validation.rs G:\ txt
//   rust-script scripts/windows/content-query-metadata-validation.rs D:\logs log --bin path\to\uffs-content.exe
//   rust-script scripts/windows/content-query-metadata-validation.rs G:\ txt --timeout-secs 120

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use colored::Colorize;

/// How long to wait for `--self-test-vss-query` before killing it and
/// reporting a timeout. Streaming an arbitrary, possibly large, real
/// corpus of files (not one synthetic file) can take much longer than
/// `content-reader-validation.rs`'s 60s budget.
const DEFAULT_TIMEOUT_SECS: u64 = 180;

/// How often the child-process watchdog re-checks `tasklist`.
const WATCHDOG_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Every child-process image name the pipeline may spawn, watched by
/// the watchdog so a hang shows *which* stage it's stuck in.
const WATCHED_IMAGES: &[&str] = &["uffsd.exe", "uffs-content-reader.exe"];

/// Parsed script arguments.
struct ScriptArgs {
    /// Path to the `uffs-content` binary to exercise.
    bin: String,
    /// Existing directory to query.
    root: String,
    /// Extension to filter on (no leading dot, e.g. `"txt"`).
    extension: String,
    /// How long to wait before killing the child and reporting a timeout.
    timeout: Duration,
}

/// Parse CLI args.
///
/// Usage: `rust-script content-query-metadata-validation <root> <ext>
/// [--bin <path>] [--timeout-secs <n>]`
fn parse_script_args() -> ScriptArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut positional: Vec<String> = Vec::new();
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
            other if !other.starts_with('-') => {
                positional.push(other.to_string());
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    if positional.len() < 2 {
        eprintln!(
            "{} usage: content-query-metadata-validation <root> <ext> [--bin <path>] \
             [--timeout-secs <n>]",
            "✗".red()
        );
        eprintln!("  example: rust-script scripts/windows/content-query-metadata-validation.rs G:\\ txt");
        std::process::exit(1);
    }

    ScriptArgs {
        bin: bin_override.unwrap_or_else(default_binary),
        root: positional[0].clone(),
        extension: positional[1].clone(),
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
/// front instead of something to reverse-engineer from a hang.
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
    eprintln!("║  UFFS Content Query Metadata Smoke Test                          ║");
    eprintln!("╚═══════════════════════════════════════════════════════════════╝");
    eprintln!("  Binary:     {}", args.bin.cyan());
    eprintln!("  Root:       {}", args.root.cyan());
    eprintln!("  Extension:  {}", args.extension.cyan());
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
        "  Running: {} --self-test-vss-query {} {} (timeout: {}s)",
        args.bin,
        args.root,
        args.extension,
        args.timeout.as_secs()
    );
    eprintln!("  ─────────────────────────────────────────────────────────────────");

    // `Stdio::inherit()` + `.spawn()` — deliberately NOT `.output()`, and
    // `.spawn()` (not `.status()`) so the loop below can poll and kill
    // on timeout. Same rationale as `content-reader-validation.rs`.
    let mut child = match Command::new(&args.bin)
        .arg("--self-test-vss-query")
        .arg(&args.root)
        .arg(&args.extension)
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
                "  {} query metadata/content totals matched ground truth ({elapsed_ms}ms)",
                "✓".green()
            );
            eprintln!();
            std::process::exit(0);
        }
        Some(status) => {
            eprintln!(
                "  {} query metadata/content verification failed ({elapsed_ms}ms)",
                "✗".red()
            );
            eprintln!();
            std::process::exit(status.code().unwrap_or(1));
        }
        None => {
            eprintln!(
                "  {} query metadata/content verification timed out ({elapsed_ms}ms) — the \
                 last line printed above (and the watchdog log) show where it was stuck",
                "✗".red()
            );
            eprintln!();
            std::process::exit(124);
        }
    }
}
