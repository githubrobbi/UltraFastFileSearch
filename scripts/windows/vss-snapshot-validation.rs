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
// C:\Temp\uffs-vss-test   rust-script
// scripts/windows/vss-snapshot-validation.rs --bin path\to\uffs-broker.exe

use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use colored::Colorize;

/// Parsed script arguments.
struct ScriptArgs {
    /// Path to the `uffs-broker` binary to exercise.
    bin: String,
    /// Directory the self-test creates its marker file under.
    test_dir: String,
}

/// Parse CLI args.
///
/// Usage: `rust-script vss-snapshot-validation [test-dir] [--bin <path>]`
fn parse_script_args() -> ScriptArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut test_dir: Option<String> = None;
    let mut bin_override: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bin" | "--binary" => {
                bin_override = args.get(i + 1).cloned();
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

    eprintln!("  Running: {} --self-test-vss {}", args.bin, args.test_dir);
    eprintln!("  ─────────────────────────────────────────────────────────────────");

    let output = Command::new(&args.bin)
        .arg("--self-test-vss")
        .arg(&args.test_dir)
        .output();

    let elapsed_ms = script_start.elapsed().as_millis();

    let output = match output {
        Ok(output) => output,
        Err(err) => {
            eprintln!("  {} failed to spawn {}: {err}", "✗".red(), args.bin);
            eprintln!(
                "    (build it first: cargo build --release -p uffs-broker -p uffs-vss-requestor)"
            );
            std::process::exit(1);
        }
    };

    // Relay the broker's own PASS/FAIL line and any tracing output
    // verbatim — it already carries the diagnosis on failure.
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));

    eprintln!("  ─────────────────────────────────────────────────────────────────");
    if output.status.success() {
        eprintln!(
            "  {} VSS create/read/delete round trip passed ({elapsed_ms}ms)",
            "✓".green()
        );
    } else {
        eprintln!(
            "  {} VSS create/read/delete round trip failed ({elapsed_ms}ms)",
            "✗".red()
        );
    }
    eprintln!();

    std::process::exit(output.status.code().unwrap_or(1));
}
