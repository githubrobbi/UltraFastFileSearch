#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! colored = "2.0"
//! serde = { version = "1.0", features = ["derive"] }
//! serde_json = "1.0"
//! toml = "0.8"
//! dirs-next = "2.0"
//! uds_windows = "1.1"
//! ```
// =============================================================================
// scripts/windows/cli-validation — CLI Flag Validation Suite
// =============================================================================
//
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.
//
// ALL tests are real CLI process spawns against a running daemon.
// Every test exercises the full stack:
//   clap arg parsing → config → daemon connect → query → output.
//
// Startup timing (COLD → WARM → HOT) has been moved to
// scripts/dev/daemon-readiness.rs (Scenario K).
//
// Usage:
//   rust-script scripts/windows/cli-validation [path-to-uffs-binary]
//
// Requirements:
//   - Windows with NTFS drives (tests reference real drive letters)
//   - Administrator privileges (MFT reading)

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use colored::Colorize;

// ── Process-level lock ────────────────────────────────────────────────────────

/// RAII lock guard.  Only one validation script (CLI *or* API) can run
/// at a time because they share the daemon.
///
/// Uses a PID-file at `/tmp/uffs-validation.lock`.  If a stale lock is
/// detected (owner PID no longer alive), it is forcibly removed.
struct ValidationLock {
    path: PathBuf,
}

impl ValidationLock {
    const LOCK_PATH: &'static str = "/tmp/uffs-validation.lock";
    const MAX_WAIT_SECS: u64 = 120;
    const POLL_MS: u64 = 500;

    /// Acquire the lock, waiting up to `MAX_WAIT_SECS`.
    fn acquire() -> Self {
        let path = PathBuf::from(Self::LOCK_PATH);
        let my_pid = std::process::id();
        let start = Instant::now();
        let mut warned = false;

        loop {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(owner_pid) = contents.trim().parse::<u32>() {
                    if Self::pid_alive(owner_pid) {
                        if !warned {
                            eprintln!(
                                "  {} Another validation script (PID {}) is running — waiting...",
                                "⏳".yellow(), owner_pid
                            );
                            warned = true;
                        }
                        if start.elapsed().as_secs() >= Self::MAX_WAIT_SECS {
                            eprintln!(
                                "  {} Timed out waiting for lock (PID {} held it for {}s)",
                                "❌".red(), owner_pid, Self::MAX_WAIT_SECS
                            );
                            std::process::exit(1);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(Self::POLL_MS));
                        continue;
                    }
                    eprintln!(
                        "  {} Removing stale lock (PID {} is no longer running)",
                        "🔓".yellow(), owner_pid
                    );
                }
                let _ = std::fs::remove_file(&path);
            }

            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut f) => {
                    let _ = write!(f, "{my_pid}");
                    if warned {
                        eprintln!("  {} Lock acquired after {}s",
                            "🔒".green(), start.elapsed().as_secs());
                    }
                    return Self { path };
                }
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(Self::POLL_MS));
                }
            }
        }
    }

    fn pid_alive(pid: u32) -> bool {
        libc_kill(pid as i32, 0) == 0
    }
}

impl Drop for ValidationLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
extern "C" { fn kill(pid: i32, sig: i32) -> i32; }
#[cfg(unix)]
fn libc_kill(pid: i32, sig: i32) -> i32 { unsafe { kill(pid, sig) } }
#[cfg(not(unix))]
fn libc_kill(_pid: i32, _sig: i32) -> i32 { -1 }


// ── Configuration ────────────────────────────────────────────────────────────

/// Parsed script arguments.
struct ScriptArgs {
    bin: String,
    /// `"--data-dir"` or `"--mft-file"`, or `None` for Windows live drives.
    source_flag: Option<&'static str>,
    /// The path value for the flag.
    source_path: String,
    /// Optional test filter: e.g. "T1,T2,T3" → only run matching tests.
    /// Matches against the test ID prefix (case-insensitive).
    test_filter: Vec<String>,
}

/// Detect whether the user passed a file or directory and return the
/// appropriate uffs CLI flag + value.
fn detect_data_source(path: &str) -> (&'static str, String) {
    let p = std::path::Path::new(path);
    if !p.exists() {
        eprintln!("Error: Path does not exist: {path}");
        std::process::exit(1);
    }
    if p.is_file() {
        ("--mft-file", path.to_owned())
    } else if p.is_dir() {
        ("--data-dir", path.to_owned())
    } else {
        eprintln!("Error: Path is neither a file nor a directory: {path}");
        std::process::exit(1);
    }
}

/// Parse CLI args.
///
/// Usage:
///   rust-script cli-validation PATH [--bin <path>] [--tests T1,T2,T88h]
///
/// PATH is required on non-Windows (a directory → --data-dir, a file → --mft-file).
/// On Windows, PATH is optional — omit to auto-discover live NTFS drives.
fn parse_script_args() -> ScriptArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut path: Option<String> = None;
    let mut bin_override: Option<String> = None;
    let mut test_filter: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bin" | "--binary" => { bin_override = args.get(i + 1).cloned(); i += 2; }
            "--tests" => {
                if let Some(val) = args.get(i + 1) {
                    test_filter = val.split(',')
                        .map(|s| s.trim().to_uppercase())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                i += 2;
            }
            other if !other.starts_with('-') && path.is_none() => {
                path = Some(other.to_string());
                i += 1;
            }
            _ => { i += 1; }
        }
    }

    let (source_flag, source_path) = match path {
        Some(ref p) => {
            let (flag, val) = detect_data_source(p);
            (Some(flag), val)
        }
        None if !cfg!(windows) => {
            // Default to ~/uffs_data on non-Windows.
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let default = format!("{home}/uffs_data");
            if std::path::Path::new(&default).is_dir() {
                eprintln!("  (defaulting to {default})");
                (Some("--data-dir"), default)
            } else {
                eprintln!("Error: No PATH given and ~/uffs_data not found.\n");
                eprintln!("Usage:");
                eprintln!("  rust-script scripts/windows/cli-validation ~/uffs_data");
                eprintln!("  rust-script scripts/windows/cli-validation /path/to/C_mft.iocp");
                std::process::exit(1);
            }
        }
        None => {
            // Windows: auto-discover live NTFS drives.
            (None, String::new())
        }
    };

    let bin = bin_override.unwrap_or_else(default_binary);

    ScriptArgs { bin, source_flag, source_path, test_filter }
}

/// Find the workspace root by walking up from cwd looking for Cargo.toml + .cargo.
fn find_workspace_root() -> std::path::PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let mut dir = cwd.as_path();
    loop {
        if dir.join("Cargo.toml").exists() && dir.join(".cargo").exists() {
            return dir.to_path_buf();
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }
    cwd
}

/// Locate an existing uffs binary; do **not** auto-build.
///
/// Validation scripts run against whatever artifact is on disk so the
/// user can control which build is being exercised (release tag,
/// local `cargo build --release`, or installed `just use` payload).
/// Auto-rebuilding from inside the script masks the very mismatch
/// these suites are meant to detect.
///
/// Search order (cross-platform):
///   1. `$HOME/bin/uffs[.exe]`           — `just use` install location
///   2. `target/release/uffs[.exe]`      — `cargo build --release` output
///   3. Bare `uffs[.exe]`                — falls through to PATH lookup
///
/// If none exists, the first `Command::new(bin).output()` call surfaces
/// the OS's "executable not found" error with the path-search
/// diagnostic — clearer than a fabricated panic from this layer.
fn default_binary() -> String {
    let bin_name = if cfg!(windows) { "uffs.exe" } else { "uffs" };
    let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let home = std::env::var(home_var).unwrap_or_else(|_| ".".to_string());
    let candidates = [
        std::path::PathBuf::from(&home).join("bin").join(bin_name),
        std::path::PathBuf::from("target").join("release").join(bin_name),
    ];
    for candidate in &candidates {
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    bin_name.to_string()
}

/// Run `<bin> daemon status` and extract the daemon's reported
/// version string for inclusion in the validation-summary block.
///
/// Returns the trimmed value of the `Version:` line printed by
/// `uffs --daemon status` on uffs ≥ 0.5.79.  Pre-0.5.79 daemons emit
/// `<unknown> (daemon) / X.Y.Z (cli)` via the CLI's back-compat
/// renderer; pre-this-feature daemons (no `Version:` line at all)
/// surface as `<line not found>`.  When the daemon is unreachable
/// the helper reports `<not running>` instead of erroring — the
/// version line is informational, not load-bearing.
fn capture_daemon_version(bin: &str) -> String {
    match Command::new(bin).args(["--daemon", "status"]).output() {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("Version:") {
                    return rest.trim().to_owned();
                }
            }
            "<line not found>".to_owned()
        }
        _ => "<not running>".to_owned(),
    }
}

// ── Validation Helpers ───────────────────────────────────────────────────────

/// Count non-empty, non-header CSV lines.
fn csv_row_count(stdout: &str) -> usize {
    stdout.lines().filter(|l| !l.is_empty()).count().saturating_sub(1)
}

/// Split a single CSV line respecting double-quote quoting.
///
/// Handles quoted fields that may contain commas (e.g. paths with commas).
/// Does NOT handle escaped quotes inside quoted fields (not needed for UFFS).
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    fields.push(current);
    fields
}

/// Parse CSV: returns (headers, data_rows).
fn parse_csv(stdout: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let mut lines = stdout.lines().filter(|l| !l.is_empty());
    let headers = split_csv_line(lines.next().unwrap_or(""));
    let rows: Vec<Vec<String>> = lines.map(|line| split_csv_line(line)).collect();
    (headers, rows)
}

/// Find column index by name (case-insensitive).
fn col_idx(headers: &[String], name: &str) -> Option<usize> {
    headers.iter().position(|h| h.eq_ignore_ascii_case(name))
}

/// Get column value from a row by column name.
fn col_val<'a>(row: &'a [String], headers: &[String], name: &str) -> &'a str {
    col_idx(headers, name)
        .and_then(|i| row.get(i))
        .map(|s| s.as_str())
        .unwrap_or("")
}

/// Assert row count is within expected range.
// ── TOML Test Definitions ──────────────────────────────────────────────────
//
// Shared test definitions loaded from `scripts/tests/test-definitions.toml`.
// Each entry describes a test declaratively — CLI args, RPC params, and
// validation assertions.  The loader converts each entry into a `TestSpec`
// with a generated validator closure.

/// Root of the TOML test-definitions file.
#[derive(serde::Deserialize)]
struct TestDefsFile {
    test: Vec<TestDef>,
}

/// A single test definition (TOML `[[test]]`).
#[derive(Clone, serde::Deserialize)]
struct TestDef {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    group: String,
    name: String,
    #[allow(dead_code)]
    title: String,
    #[allow(dead_code)]
    short_desc: String,
    #[allow(dead_code)]
    long_desc: Option<String>,

    #[serde(default)]
    cli_args: Vec<String>,
    #[allow(dead_code)]
    cli_format: Option<String>,
    #[allow(dead_code)]
    rpc_method: Option<String>,
    #[allow(dead_code)]
    rpc_params: Option<String>,

    // ── Shared assertions (validated by ALL targets) ──────────────
    expect_min_rows: Option<usize>,
    expect_max_rows: Option<usize>,
    expect_columns_all: Option<bool>,

    #[serde(default)]
    column_checks: Vec<ColumnCheck>,
    #[serde(default)]
    sort_checks: Vec<SortCheck>,

    validator: Option<String>,
    #[serde(default = "default_targets")]
    targets: Vec<String>,
    skip: Option<bool>,
    #[serde(default)]
    #[allow(dead_code)]
    tags: Vec<String>,

    // ── Per-target checks ────────────────────────────────────────
    /// CLI-specific output checks (stdout/stderr text matching).
    #[serde(default)]
    cli_checks: CliChecks,
    /// API-specific response checks (JSON-RPC result validation).
    #[serde(default)]
    #[allow(dead_code)]
    api_checks: ApiChecks,
    /// MCP-specific checks (future).
    #[serde(default)]
    #[allow(dead_code)]
    mcp_checks: McpChecks,

    // ── Legacy flat fields (still read for backward compat) ──────
    #[serde(default)]
    stdout_contains: Vec<String>,
    #[serde(default)]
    stdout_not_contains: Vec<String>,
    #[serde(default)]
    stderr_contains: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    expect_exit_code: Option<i32>,
    #[serde(default)]
    #[allow(dead_code)]
    json_checks: Vec<JsonCheck>,
}

fn default_targets() -> Vec<String> { vec!["cli".into(), "api".into()] }

/// CLI-specific output checks.
#[derive(Clone, Default, serde::Deserialize)]
#[allow(dead_code)]
struct CliChecks {
    #[serde(default)]
    stdout_contains: Vec<String>,
    #[serde(default)]
    stdout_not_contains: Vec<String>,
    #[serde(default)]
    stderr_contains: Vec<String>,
    #[serde(default)]
    expect_exit_code: Option<i32>,
    /// CLI-only row count (for agg-only tests where API rows=0 but CLI CSV has rows).
    #[serde(default)]
    expect_min_rows: Option<usize>,
    #[serde(default)]
    expect_max_rows: Option<usize>,
}

/// API-specific JSON-RPC response checks (parsed but not used by CLI validator).
#[derive(Clone, Default, serde::Deserialize)]
#[allow(dead_code)]
struct ApiChecks {
    /// Minimum number of aggregation result blocks.
    #[serde(default)]
    expect_agg_results: Option<usize>,
    /// Keys that must exist in the top-level JSON-RPC result.
    #[serde(default)]
    result_has_key: Vec<String>,
    /// Aggregation result labels that must appear.
    #[serde(default)]
    agg_label_contains: Vec<String>,
    /// Minimum total buckets across all agg results.
    #[serde(default)]
    bucket_min_count: Option<usize>,
}

/// MCP-specific checks (future expansion).
#[derive(Clone, Default, serde::Deserialize)]
struct McpChecks {
    #[serde(default)]
    #[allow(dead_code)]
    tool_name: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    response_contains: Vec<String>,
}

/// Per-row column assertion.
#[derive(Clone, serde::Deserialize)]
struct ColumnCheck {
    column: String,
    op: String,
    value: String,
    case: Option<String>,
}

/// Sort-order assertion.
#[derive(Clone, serde::Deserialize)]
struct SortCheck {
    column: String,
    order: String,
    #[serde(rename = "type", default = "default_sort_type")]
    sort_type: String,
}

fn default_sort_type() -> String { "u64".to_string() }

/// JSON output assertion.
#[derive(Clone, serde::Deserialize)]
#[allow(dead_code)]
struct JsonCheck {
    path: String,
    op: String,
    value: Option<String>,
}

/// Apply a single column check to a row value.
fn apply_column_check(
    row_idx: usize, val: &str, check: &ColumnCheck, col_name: &str,
) -> Result<()> {
    let v = match check.case.as_deref() {
        Some("lower") => val.to_lowercase(),
        _ => val.to_string(),
    };
    let expected = match check.case.as_deref() {
        Some("lower") => check.value.to_lowercase(),
        _ => check.value.clone(),
    };
    match check.op.as_str() {
        "eq"  => { if v != expected { bail!("Row {row_idx}: {col_name}={val}, expected {}", check.value); } }
        "ne"  => { if v == expected { bail!("Row {row_idx}: {col_name}={val}, expected != {}", check.value); } }
        "contains" => { if !v.contains(&expected) { bail!("Row {row_idx}: {col_name}={val}, expected contains {}", check.value); } }
        "not_contains" => { if v.contains(&expected) { bail!("Row {row_idx}: {col_name}={val}, expected not contains {}", check.value); } }
        "starts_with" => { if !v.starts_with(&expected) { bail!("Row {row_idx}: {col_name}={val}, expected starts_with {}", check.value); } }
        "not_starts_with" => { if v.starts_with(&expected) { bail!("Row {row_idx}: {col_name}={val}, expected not starts_with {}", check.value); } }
        "ends_with" => { if !v.ends_with(&expected) { bail!("Row {row_idx}: {col_name}={val}, expected ends_with {}", check.value); } }
        "gt"  => { let n: u64 = v.parse().unwrap_or(0); let e: u64 = expected.parse().unwrap_or(0); if n <= e { bail!("Row {row_idx}: {col_name}={n}, expected > {e}"); } }
        "gte" => { let n: u64 = v.parse().unwrap_or(0); let e: u64 = expected.parse().unwrap_or(0); if n <  e { bail!("Row {row_idx}: {col_name}={n}, expected >= {e}"); } }
        "lt"  => { let n: u64 = v.parse().unwrap_or(u64::MAX); let e: u64 = expected.parse().unwrap_or(0); if n >= e { bail!("Row {row_idx}: {col_name}={n}, expected < {e}"); } }
        "lte" => { let n: u64 = v.parse().unwrap_or(u64::MAX); let e: u64 = expected.parse().unwrap_or(0); if n >  e { bail!("Row {row_idx}: {col_name}={n}, expected <= {e}"); } }
        other => bail!("Unknown column_check op: {other}"),
    }
    Ok(())
}

// ── JSON helpers for custom validators ─────────────────────────────────────

/// Parse stdout as a JSON array of result objects.
fn parse_json_results(stdout: &str) -> Result<Vec<serde_json::Value>> {
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| anyhow::anyhow!("Invalid JSON: {e}"))?;
    parsed.as_array().cloned()
        .ok_or_else(|| anyhow::anyhow!("Expected JSON array"))
}

/// Parse stdout as NDJSON (one JSON object per line).
fn parse_ndjson(stdout: &str) -> Result<Vec<serde_json::Value>> {
    stdout.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(|e| anyhow::anyhow!("Invalid JSON line: {e}")))
        .collect()
}

/// Find first result with given kind in a JSON results array.
fn find_kind<'a>(results: &'a [serde_json::Value], kind: &str) -> Result<&'a serde_json::Value> {
    results.iter()
        .find(|r| r.get("kind").and_then(|k| k.as_str()) == Some(kind))
        .ok_or_else(|| anyhow::anyhow!("No result with kind={kind}"))
}

/// Extract buckets array from a result object.
fn get_buckets(result: &serde_json::Value) -> Result<&Vec<serde_json::Value>> {
    result.get("buckets")
        .and_then(|b| b.as_array())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'buckets' array"))
}

/// Verify a descending sort order on a CSV column (u64).
fn assert_csv_sorted_desc(stdout: &str, col: &str) -> Result<usize> {
    let (h, rows) = parse_csv(stdout);
    if rows.len() >= 2 {
        let vals: Vec<u64> = rows.iter().map(|r| col_val(r, &h, col).parse().unwrap_or(0)).collect();
        for w in vals.windows(2) {
            if w[0] < w[1] { bail!("Not descending on {col}: {} < {}", w[0], w[1]); }
        }
    }
    Ok(rows.len())
}

/// Dispatch a named custom validator.
///
/// Tests that need logic beyond declarative column/sort/row-count checks
/// register a `validator = "name"` in the TOML.  This function maps names
/// to Rust closures.
fn run_custom_validator(name: &str, stdout: &str, stderr: &str) -> Result<String> {
    let _ = stderr;
    match name {
        // ── General / filters ────────────────────────────────────────────
        "ext_multi_check" => {
            let (h, rows) = parse_csv(stdout);
            if rows.is_empty() { bail!("No rows"); }
            let exts = ["jpg", "png", "gif"];
            for (i, row) in rows.iter().enumerate() {
                let n = col_val(row, &h, "Name").to_lowercase();
                if !exts.iter().any(|e| n.ends_with(&format!(".{e}"))) {
                    bail!("Row {i}: {n} not in {{jpg,png,gif}}");
                }
            }
            Ok(format!("{} rows, all image extensions", rows.len()))
        }

        // ── JSON format ──────────────────────────────────────────────────
        "T20" => {
            let items = parse_ndjson(stdout)?;
            if items.is_empty() { bail!("No JSON items"); }
            if items.len() > 5 { bail!("Expected ≤ 5 items, got {}", items.len()); }
            let f = &items[0];
            if f.get("Name").is_none() && f.get("name").is_none() {
                bail!("JSON item missing 'Name' field: {f}");
            }
            Ok(format!("{} NDJSON items", items.len()))
        }

        // ── Combined stress test ─────────────────────────────────────────
        "T34" => {
            let (h, rows) = parse_csv(stdout);
            if rows.len() >= 2 {
                let sizes: Vec<u64> = rows.iter().map(|r| col_val(r, &h, "Size").parse().unwrap_or(0)).collect();
                for w in sizes.windows(2) { if w[0] < w[1] { bail!("Not descending: {} < {}", w[0], w[1]); } }
            }
            for (i, row) in rows.iter().enumerate() {
                let s: u64 = col_val(row, &h, "Size").parse().unwrap_or(0);
                if s < 1_048_576 { bail!("Row {i}: size={s} < 1MB"); }
            }
            Ok(format!("{} rows, size desc ≥ 1MB", rows.len()))
        }

        // ── Sort validators ──────────────────────────────────────────────
        "T65" => { let n = assert_csv_sorted_desc(stdout, "Descendants")?; Ok(format!("{n} rows, sorted desc by descendants")) }
        "T67a" => { let n = assert_csv_sorted_desc(stdout, "Tree Size")?; Ok(format!("{n} rows, sorted by treesize desc")) }
        "T67b" => { let n = assert_csv_sorted_desc(stdout, "Tree Allocated")?; Ok(format!("{n} rows, sorted by treeallocated desc")) }
        "T94" => { let n = assert_csv_sorted_desc(stdout, "Size")?; Ok(format!("{n} code files sorted by size desc")) }

        // ── Combined filter + sort validators ────────────────────────────
        "T75" => {
            let (h, rows) = parse_csv(stdout);
            for (i, row) in rows.iter().enumerate() {
                let n = col_val(row, &h, "Name").to_lowercase();
                if !n.ends_with(".exe") && !n.ends_with(".dll") { bail!("Row {i}: {n} not exe/dll"); }
                let s: u64 = col_val(row, &h, "Size").parse().unwrap_or(0);
                if s < 1_048_576 { bail!("Row {i}: size={s} < 1MB"); }
            }
            if rows.len() >= 2 {
                let sizes: Vec<u64> = rows.iter().map(|r| col_val(r, &h, "Size").parse().unwrap_or(0)).collect();
                for w in sizes.windows(2) { if w[0] < w[1] { bail!("Not descending: {} < {}", w[0], w[1]); } }
            }
            Ok(format!("{} rows, exe/dll ≥1MB sorted desc", rows.len()))
        }
        "T76" => {
            let (h, rows) = parse_csv(stdout);
            for (i, row) in rows.iter().enumerate() {
                let d: u64 = col_val(row, &h, "Descendants").parse().unwrap_or(0);
                if d < 10 || d > 1000 { bail!("Row {i}: desc={d} outside 10..1000"); }
            }
            if rows.len() >= 2 {
                let vals: Vec<u64> = rows.iter().map(|r| col_val(r, &h, "Descendants").parse().unwrap_or(0)).collect();
                for w in vals.windows(2) { if w[0] < w[1] { bail!("Not descending: {} < {}", w[0], w[1]); } }
            }
            Ok(format!("{} dirs, desc range 10..1000 sorted desc", rows.len()))
        }

        // ── Projection + JSON ────────────────────────────────────────────
        "T79" => {
            let items = parse_ndjson(stdout)?;
            if items.is_empty() { bail!("No JSON items"); }
            let f = &items[0];
            if f.get("Name").is_none() && f.get("name").is_none() {
                bail!("Missing 'Name' field in projected JSON");
            }
            Ok(format!("{} projected JSON items", items.len()))
        }

        // ── Path search validators ───────────────────────────────────────
        "T88a" => {
            let (h, rows) = parse_csv(stdout);
            if rows.is_empty() { bail!("No rows"); }
            for (i, row) in rows.iter().enumerate() {
                let path = col_val(row, &h, "Path Only").to_lowercase();
                let name = col_val(row, &h, "Name").to_lowercase();
                let full = format!("{path}{name}");
                if !full.contains("windows") {
                    bail!("Row {i}: '{full}' doesn't contain 'windows'");
                }
            }
            Ok(format!("{} rows, all paths contain 'windows'", rows.len()))
        }
        "T88i" => {
            let (h, rows) = parse_csv(stdout);
            for (i, row) in rows.iter().enumerate() {
                let path = col_val(row, &h, "Path Only").to_lowercase();
                let name = col_val(row, &h, "Name").to_lowercase();
                let full = format!("{path}{name}");
                if !full.contains("notepad") {
                    bail!("Row {i}: '{full}' doesn't contain 'notepad'");
                }
            }
            Ok(format!("{} rows, all contain 'notepad'", rows.len()))
        }
        "T88k" => {
            let (h, rows) = parse_csv(stdout);
            for (i, row) in rows.iter().enumerate() {
                if col_val(row, &h, "Directory Flag") != "1" {
                    bail!("Row {i}: dir: prefix returned non-directory");
                }
            }
            let n = assert_csv_sorted_desc(stdout, "Tree Size")?;
            Ok(format!("{n} dirs, sorted by treesize desc"))
        }

        // ── Aggregation JSON validators ──────────────────────────────────
        "T126" => {
            let r = parse_json_results(stdout)?;
            let c = find_kind(&r, "count")?;
            let v = c.get("value").and_then(|v| v.as_u64()).unwrap_or(0);
            if v == 0 { bail!("Count value is 0"); }
            Ok(format!("JSON count = {v}"))
        }
        "T127" => {
            let r = parse_json_results(stdout)?;
            if r.len() < 3 { bail!("Overview should produce ≥3 results, got {}", r.len()); }
            let kinds: Vec<&str> = r.iter().filter_map(|v| v.get("kind").and_then(|k| k.as_str())).collect();
            Ok(format!("overview: {} results, kinds={kinds:?}", r.len()))
        }
        "T136" => {
            let r = parse_json_results(stdout)?;
            if r.is_empty() { bail!("Empty top_folders"); }
            let kind = r[0].get("kind").and_then(|k| k.as_str()).unwrap_or("");
            if kind != "rollup" && kind != "buckets" { bail!("Expected rollup/buckets, got {kind}"); }
            Ok(format!("{} results from top_folders", r.len()))
        }
        "T137" => {
            let r = parse_json_results(stdout)?;
            if r.len() < 3 { bail!("Expected ≥3 results from cleanup, got {}", r.len()); }
            Ok(format!("{} results from cleanup", r.len()))
        }
        "T146" => {
            let r = parse_json_results(stdout)?;
            let br = find_kind(&r, "buckets")?;
            let b = get_buckets(br)?;
            if b.is_empty() { bail!("No buckets in by_extension"); }
            Ok(format!("{} buckets from by_extension", b.len()))
        }
        "T147" => {
            let r = parse_json_results(stdout)?;
            if r.is_empty() { bail!("No results from duplicates"); }
            Ok(format!("{} result(s) from duplicates", r.len()))
        }
        "T149" => {
            let r = parse_json_results(stdout)?;
            if r.is_empty() { bail!("No results from by_size"); }
            let has = r.iter().any(|v| v.get("buckets").and_then(|b| b.as_array()).map_or(false, |a| !a.is_empty()));
            if !has { bail!("by_size missing non-empty buckets"); }
            Ok(format!("{} results from by_size", r.len()))
        }
        "T150" => {
            let r = parse_json_results(stdout)?;
            let br = find_kind(&r, "buckets")?;
            let b = get_buckets(br)?;
            if b.is_empty() { bail!("No buckets"); }
            let has_sample = b.iter().any(|bk| bk.get("sample_rows").and_then(|s| s.as_array()).map_or(false, |a| !a.is_empty()));
            if !has_sample { bail!("No sample_rows in any bucket"); }
            Ok(format!("{} buckets with sample_rows", b.len()))
        }
        "T151" => {
            let r = parse_json_results(stdout)?;
            let br = find_kind(&r, "buckets")?;
            let b = get_buckets(br)?;
            if b.is_empty() { bail!("No buckets"); }
            let has_dd = b.iter().any(|bk| bk.get("drilldown").is_some());
            if !has_dd { bail!("No drilldown in any bucket"); }
            Ok(format!("{} buckets with drilldown", b.len()))
        }
        "T153" => {
            let r = parse_json_results(stdout)?;
            let br = find_kind(&r, "buckets")?;
            let b = get_buckets(br)?;
            if b.is_empty() { bail!("No buckets"); }
            // Without sample, sample_rows should be empty/absent.
            for bk in b {
                let sr = bk.get("sample_rows").and_then(|s| s.as_array());
                if sr.map_or(false, |a| !a.is_empty()) { bail!("Unexpected sample_rows without sample="); }
            }
            Ok(format!("{} buckets, no sample_rows", b.len()))
        }
        "T154" => {
            let r = parse_json_results(stdout)?;
            let rl = find_kind(&r, "rollup")?;
            let b = get_buckets(rl)?;
            if b.is_empty() { bail!("No rollup buckets"); }
            Ok(format!("{} rollup:drive buckets", b.len()))
        }
        "T155" => {
            let r = parse_json_results(stdout)?;
            let rl = find_kind(&r, "rollup")?;
            let b = get_buckets(rl)?;
            if b.is_empty() { bail!("No rollup buckets"); }
            Ok(format!("{} rollup:path,depth=2 buckets", b.len()))
        }
        "T156" => {
            let r = parse_json_results(stdout)?;
            if r.len() < 2 { bail!("Expected ≥2 results from two --agg flags, got {}", r.len()); }
            let has_count = r.iter().any(|v| v.get("kind").and_then(|k| k.as_str()) == Some("count"));
            let has_buckets = r.iter().any(|v| v.get("kind").and_then(|k| k.as_str()) == Some("buckets"));
            if !has_count || !has_buckets { bail!("Missing count or buckets in multi-agg"); }
            Ok(format!("{} results from multi-agg", r.len()))
        }
        "T157" => {
            let r = parse_json_results(stdout)?;
            let br = find_kind(&r, "buckets")?;
            let b = get_buckets(br)?;
            if b.is_empty() { bail!("No buckets from filtered agg"); }
            Ok(format!("{} buckets from --agg + filter", b.len()))
        }
        "T158" => {
            let r = parse_json_results(stdout)?;
            let br = find_kind(&r, "buckets")?;
            let b = get_buckets(br)?;
            if b.is_empty() { bail!("No buckets"); }
            let has_sample = b.iter().any(|bk| bk.get("sample_rows").and_then(|s| s.as_array()).map_or(false, |a| !a.is_empty()));
            if !has_sample { bail!("No sample_rows with content"); }
            Ok(format!("{} buckets, sample row fields verified", b.len()))
        }
        "T160" => {
            let r = parse_json_results(stdout)?;
            let h = find_kind(&r, "buckets")?;
            let b = get_buckets(h)?;
            if b.is_empty() { bail!("No histogram buckets"); }
            Ok(format!("{} hist:size buckets", b.len()))
        }
        "T161" => {
            let r = parse_json_results(stdout)?;
            let s = find_kind(&r, "stats")?;
            let inner = s.get("stats").or_else(|| s.get("value"));
            if inner.is_none() { bail!("No stats data in stats result"); }
            Ok("stats:size present".into())
        }
        "T162" => {
            let r = parse_json_results(stdout)?;
            let dh = find_kind(&r, "buckets")?;
            let b = get_buckets(dh)?;
            if b.is_empty() { bail!("No datehist buckets"); }
            Ok(format!("{} datehist:modified buckets", b.len()))
        }
        "T163" => {
            let r = parse_json_results(stdout)?;
            let rng = find_kind(&r, "buckets")?;
            let b = get_buckets(rng)?;
            if b.is_empty() { bail!("No range buckets"); }
            Ok(format!("{} range:size buckets", b.len()))
        }
        "T164" => {
            let r = parse_json_results(stdout)?;
            let h = find_kind(&r, "buckets")?;
            let b = get_buckets(h)?;
            if b.is_empty() { bail!("No histogram buckets"); }
            Ok(format!("{} histogram buckets", b.len()))
        }
        "T165" => {
            let r = parse_json_results(stdout)?;
            if r.is_empty() { bail!("No results from missing:extension"); }
            Ok(format!("{} results from missing:extension", r.len()))
        }
        "T166" => {
            let r = parse_json_results(stdout)?;
            if r.is_empty() { bail!("No results from distinct:extension"); }
            Ok(format!("{} results from distinct:extension", r.len()))
        }
        "T167" => {
            let r = parse_json_results(stdout)?;
            let br = find_kind(&r, "buckets")?;
            let b = get_buckets(br)?;
            if b.is_empty() { bail!("No buckets for sample_sort"); }
            Ok(format!("{} buckets with sample_sort", b.len()))
        }
        "T173" => {
            let r = parse_json_results(stdout)?;
            if r.is_empty() { bail!("Empty by_age JSON"); }
            let _ = find_kind(&r, "buckets")?;
            Ok(format!("{} results from by_age", r.len()))
        }
        "T174" => {
            let r = parse_json_results(stdout)?;
            if r.is_empty() { bail!("Empty storage JSON"); }
            Ok(format!("{} results from storage", r.len()))
        }
        "T175" => {
            let r = parse_json_results(stdout)?;
            if r.is_empty() { bail!("Empty activity JSON"); }
            Ok(format!("{} results from activity", r.len()))
        }
        "T176" => {
            let r = parse_json_results(stdout)?;
            if r.is_empty() { bail!("Empty media JSON"); }
            Ok(format!("{} results from media", r.len()))
        }

        // ── S3A: Cursor pagination ───────────────────────────────────────
        "S3A.1" => {
            let r = parse_json_results(stdout)?;
            let br = find_kind(&r, "buckets")?;
            let cursor = br.get("next_cursor");
            if cursor.is_none() || cursor.map_or(false, |v| v.is_null()) {
                bail!("Expected next_cursor for page_size=2 on extensions");
            }
            let b = get_buckets(br)?;
            if b.len() > 2 { bail!("Expected ≤ 2 buckets, got {}", b.len()); }
            Ok(format!("{} buckets, next_cursor present", b.len()))
        }
        "S3A.3" => {
            let r = parse_json_results(stdout)?;
            let br = find_kind(&r, "buckets")?;
            let b = get_buckets(br)?;
            if b.len() > 3 { bail!("Expected ≤ 3 buckets with page_size=3, got {}", b.len()); }
            Ok(format!("{} buckets, page_size=3", b.len()))
        }
        "S3A.4" => {
            let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
                .map_err(|e| anyhow::anyhow!("Invalid JSON: {e}"))?;
            if parsed.is_null() { bail!("Null aggregate output"); }
            Ok("aggregate subcommand with --agg-page-size OK".into())
        }

        // ── S3C: Nested rollup ───────────────────────────────────────────
        "S3C.1" => {
            let r = parse_json_results(stdout)?;
            let rl = find_kind(&r, "rollup")?;
            let b = get_buckets(rl)?;
            if b.is_empty() { bail!("No rollup buckets"); }
            let first = &b[0];
            let subs = first.get("sub_buckets").and_then(|s| s.as_array());
            if subs.is_none() || subs.map_or(false, |a| a.is_empty()) {
                bail!("No sub_buckets on first rollup bucket");
            }
            let sub = &subs.unwrap()[0];
            if sub.get("key").is_none() { bail!("Sub-bucket missing 'key'"); }
            if sub.get("count").is_none() { bail!("Sub-bucket missing 'count'"); }
            Ok(format!("{} rollup buckets with sub_buckets", b.len()))
        }

        // ── S3D: Truncation metadata ─────────────────────────────────────
        "S3D.3" => {
            let r = parse_json_results(stdout)?;
            let br = find_kind(&r, "buckets")?;
            let vc = br.get("values_complete");
            if vc.is_none() { bail!("Missing values_complete field"); }
            Ok(format!("values_complete = {}", vc.unwrap()))
        }
        "S3D.4" => {
            let r = parse_json_results(stdout)?;
            let br = find_kind(&r, "buckets")?;
            let exact = br.get("exact").and_then(|v| v.as_bool());
            if exact.is_none() { bail!("Missing or non-bool 'exact' field"); }
            Ok(format!("exact = {}", exact.unwrap()))
        }

        // ── S3G: Sample sort ─────────────────────────────────────────────
        "S3G.1" => {
            let r = parse_json_results(stdout)?;
            let br = find_kind(&r, "buckets")?;
            let b = get_buckets(br)?;
            if b.is_empty() { bail!("No buckets for sample_sort desc"); }
            Ok(format!("{} buckets, sample_sort desc", b.len()))
        }
        "S3G.8" => {
            let r = parse_json_results(stdout)?;
            if r.len() < 3 { bail!("Expected ≥ 3 results from 3 agg specs, got {}", r.len()); }
            let kinds: Vec<String> = r.iter().filter_map(|v| v.get("kind").and_then(|k| k.as_str()).map(String::from)).collect();
            Ok(format!("{} results, kinds={kinds:?}", r.len()))
        }

        // ── Multi-extension validators ──────────────────────────────────
        "T87" => {
            let (h, rows) = parse_csv(stdout);
            let exts = ["txt", "log", "md"];
            for (i, row) in rows.iter().enumerate() {
                let n = col_val(row, &h, "Name").to_lowercase();
                if !exts.iter().any(|e| n.ends_with(&format!(".{e}"))) {
                    bail!("Row {i}: {n} not in {{txt,log,md}}");
                }
            }
            Ok(format!("{} rows, ext filtered + sorted", rows.len()))
        }
        "T88" => {
            let (h, rows) = parse_csv(stdout);
            for (i, row) in rows.iter().enumerate() {
                let n = col_val(row, &h, "Name").to_lowercase();
                if !n.contains("config") { bail!("Row {i}: {n} doesn't contain 'config'"); }
                if n.starts_with('$') { bail!("Row {i}: {n} starts with $ despite hide-system"); }
            }
            Ok(format!("{} rows", rows.len()))
        }
        "T88j" => {
            let (h, rows) = parse_csv(stdout);
            for (i, row) in rows.iter().enumerate() {
                let n = col_val(row, &h, "Name").to_lowercase();
                if !n.contains("update") { bail!("Row {i}: {n} doesn't contain 'update'"); }
                if n.contains("old") { bail!("Row {i}: {n} contains 'old' despite --not-contains"); }
            }
            Ok(format!("{} rows, contains 'update' but not 'old'", rows.len()))
        }
        "T88l" => {
            let (h, rows) = parse_csv(stdout);
            for (i, row) in rows.iter().enumerate() {
                let n = col_val(row, &h, "Name").to_lowercase();
                if !n.starts_with("win") { bail!("Row {i}: {n} doesn't start with 'win'"); }
                if !n.ends_with(".exe") && !n.ends_with(".dll") { bail!("Row {i}: {n} not .exe/.dll"); }
            }
            Ok(format!("{} rows, begins-with + ext", rows.len()))
        }
        "T67d" => {
            let (h, rows) = parse_csv(stdout);
            if rows.len() >= 2 {
                let lens: Vec<usize> = rows.iter().map(|r| col_val(r, &h, "Name").chars().count()).collect();
                for w in lens.windows(2) {
                    if w[0] < w[1] { bail!("Not desc: {} < {}", w[0], w[1]); }
                }
            }
            Ok(format!("{} rows, sorted by name length desc", rows.len()))
        }
        "T67f2" => {
            // Mirror of the same-named validator in api-validation.rs.
            //
            // PathOnly sort must honour Windows Explorer's `Folder`
            // column convention: when two rows share the same parent
            // directory (case-insensitive), the secondary tiebreaker
            // is filename ASC.  Mirrored by
            // `search_index_path_only_sort_name_asc_within_same_folder`
            // in crates/uffs-core/src/search/backend_tests.rs.
            //
            // This validator *only* checks the tiebreaker invariant —
            // it intentionally does NOT re-validate primary
            // `path_only` ASC ordering (that's T67f's job via the
            // generic sort_checks framework).  The daemon's sort uses
            // NTFS $UpCase (upper-fold), while the generic framework
            // uses `.to_lowercase()`; the two conventions disagree on
            // characters between `Z` (0x5A) and `a` (0x61) — notably
            // `_` (0x5F) — so a primary check here would spuriously
            // fail on inputs like `pmf_ryzenaimax` vs `pmf_ryzen_ai`.
            // Same-folder siblings share identical case-folded
            // prefixes so the ambiguity cannot surface for the
            // tiebreaker comparison.
            let (h, rows) = parse_csv(stdout);
            if rows.len() < 2 {
                bail!(
                    "Need ≥ 2 rows to validate path_only+name sort, got {}",
                    rows.len()
                );
            }
            let pairs: Vec<(String, String)> = rows
                .iter()
                .map(|r| {
                    let path = col_val(r, &h, "Path");
                    let name = col_val(r, &h, "Name");
                    let dir = path
                        .strip_suffix(&name)
                        .unwrap_or(&path)
                        .trim_end_matches('\\')
                        .to_owned();
                    (dir, name.to_owned())
                })
                .collect();
            let mut saw_tiebreaker = false;
            for w in pairs.windows(2) {
                let (po0, n0) = &w[0];
                let (po1, n1) = &w[1];
                if po0.eq_ignore_ascii_case(po1) {
                    saw_tiebreaker = true;
                    let n0_fold = n0.to_lowercase();
                    let n1_fold = n1.to_lowercase();
                    if n0_fold > n1_fold {
                        bail!(
                            "Not asc (name tiebreaker within '{}'): '{}' > '{}'",
                            po0, n0, n1
                        );
                    }
                }
            }
            if !saw_tiebreaker {
                bail!(
                    "Test vacuous: {} rows all have distinct path_only \
                     values — no adjacent pair with equal path_only to \
                     exercise the name tiebreaker.  Expand the search or \
                     raise --limit so rows from the same folder appear \
                     together.",
                    rows.len()
                );
            }
            Ok(format!(
                "{} rows, name-ASC tiebreaker verified for same-folder siblings",
                rows.len()
            ))
        }
        "T78" => {
            let (h, rows) = parse_csv(stdout);
            for (i, row) in rows.iter().enumerate() {
                let n = col_val(row, &h, "Name").to_lowercase();
                if n.starts_with("debug") { bail!("Row {i}: {n} matches exclude"); }
                let s: u64 = col_val(row, &h, "Size").parse().unwrap_or(u64::MAX);
                if s > 1_048_576 { bail!("Row {i}: size={s} > 1MB"); }
            }
            Ok(format!("{} rows, all constraints met", rows.len()))
        }

        // ── File output ──────────────────────────────────────────────────
        "T31" => {
            let path = std::path::Path::new("test_cli_validation_out.csv");
            if !path.exists() { bail!("Output file not created"); }
            let content = std::fs::read_to_string(path).unwrap_or_default();
            let _ = std::fs::remove_file(path);
            let lines = content.lines().filter(|l| !l.is_empty()).count();
            if lines < 2 { bail!("Output file has {lines} lines, expected at least 2"); }
            Ok(format!("{lines} lines written to file"))
        }

        // ── S3B: facet_values (CLI has no facet_values subcommand) ────
        "S3B.1" | "S3B.2" => Ok("(facet_values: API-only test, skipped in CLI)".into()),

        // ── S3misc: Aggregation variants ─────────────────────────────
        "S3misc.1" => {
            // terms:extension,top=5,sample=2,sort=size → buckets with samples
            let r = parse_json_results(stdout)?;
            let agg = r.first()
                .ok_or_else(|| anyhow::anyhow!("Expected at least one agg result"))?;
            let kind = agg.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if kind != "buckets" { bail!("Expected kind='buckets', got '{kind}'"); }
            let buckets = agg.get("buckets").and_then(|v| v.as_array())
                .ok_or_else(|| anyhow::anyhow!("Missing buckets array"))?;
            if buckets.is_empty() { bail!("No buckets returned"); }
            for (i, b) in buckets.iter().enumerate() {
                if b.get("key").is_none() { bail!("Bucket {i}: missing key field"); }
                let count = b.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                if count == 0 { bail!("Bucket {i}: count=0"); }
                let samples = b.get("sample_rows").and_then(|v| v.as_array());
                match samples {
                    Some(s) if !s.is_empty() => {}
                    _ => bail!("Bucket {i}: missing or empty sample_rows"),
                }
            }
            Ok(format!("{} buckets, all have key+count+samples", buckets.len()))
        }
        "S3misc.2" => {
            // count agg → single count result
            let r = parse_json_results(stdout)?;
            let agg = r.first()
                .ok_or_else(|| anyhow::anyhow!("Expected at least one agg result"))?;
            let kind = agg.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if kind != "count" { bail!("Expected kind='count', got '{kind}'"); }
            let count = agg.get("value").and_then(|v| v.as_u64()).unwrap_or(0);
            if count == 0 { bail!("value=0, expected >0 for *.exe"); }
            Ok(format!("count={count}"))
        }
        "S3misc.3" => {
            // terms:extension,top=5 → buckets, no rows expected
            let r = parse_json_results(stdout)?;
            let agg = r.first()
                .ok_or_else(|| anyhow::anyhow!("Expected at least one agg result"))?;
            let kind = agg.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if kind != "buckets" { bail!("Expected kind='buckets', got '{kind}'"); }
            let buckets = agg.get("buckets").and_then(|v| v.as_array())
                .ok_or_else(|| anyhow::anyhow!("Missing buckets array"))?;
            if buckets.is_empty() { bail!("No buckets returned"); }
            for (i, b) in buckets.iter().enumerate() {
                // key can be "" for files with no extension — that's valid
                if b.get("key").is_none() { bail!("Bucket {i}: missing key field"); }
                let count = b.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                if count == 0 { bail!("Bucket {i}: count=0"); }
            }
            Ok(format!("{} buckets with key+count", buckets.len()))
        }
        "S3misc.4" => {
            // *.exe --limit 5 --agg terms:extension,top=3 → rows + buckets
            let r = parse_json_results(stdout)?;
            let agg = r.first()
                .ok_or_else(|| anyhow::anyhow!("Expected at least one agg result"))?;
            let kind = agg.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if kind != "buckets" { bail!("Expected kind='buckets', got '{kind}'"); }
            let buckets = agg.get("buckets").and_then(|v| v.as_array())
                .ok_or_else(|| anyhow::anyhow!("Missing buckets array"))?;
            if buckets.is_empty() { bail!("No buckets returned"); }
            for (i, b) in buckets.iter().enumerate() {
                if b.get("key").is_none() { bail!("Bucket {i}: missing key field"); }
                let count = b.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                if count == 0 { bail!("Bucket {i}: count=0"); }
            }
            Ok(format!("{} buckets with key+count", buckets.len()))
        }

        // ── T32: Benchmark (output goes to stderr) ─────────────────
        "T32" => {
            if !stderr.contains("PROFILE") {
                bail!("stderr missing PROFILE benchmark output");
            }
            if !stderr.contains("Search") {
                bail!("stderr missing Search timing");
            }
            Ok("benchmark profile output present in stderr".to_owned())
        }

        // ── T139/T140: JSON agg with samples ────────────────────────
        "T139" => {
            // terms:extension with sample=3 → JSON with "buckets" kind + samples
            let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
                .map_err(|e| anyhow::anyhow!("Invalid JSON: {e}"))?;
            let results = parsed.as_array()
                .ok_or_else(|| anyhow::anyhow!("Expected JSON array"))?;
            if results.is_empty() { bail!("Empty agg results"); }
            let bkt = results.iter().find(|r|
                r.get("kind").and_then(|k| k.as_str()) == Some("buckets")
            ).ok_or_else(|| anyhow::anyhow!("No 'buckets' result found"))?;
            let buckets = bkt.get("buckets").and_then(|b| b.as_array())
                .ok_or_else(|| anyhow::anyhow!("Missing buckets array"))?;
            if buckets.is_empty() { bail!("Empty buckets"); }
            // Each bucket should have sample_rows from sample=3
            let has_samples = buckets[0].get("sample_rows")
                .and_then(|s| s.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            if !has_samples { bail!("First bucket has no sample_rows"); }
            Ok(format!("{} buckets with samples", buckets.len()))
        }
        "T140" => {
            // duplicates with sample=2 → JSON with "duplicates" kind
            let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
                .map_err(|e| anyhow::anyhow!("Invalid JSON: {e}"))?;
            let results = parsed.as_array()
                .ok_or_else(|| anyhow::anyhow!("Expected JSON array"))?;
            if results.is_empty() { bail!("Empty agg results"); }
            let dup = results.iter().find(|r|
                r.get("kind").and_then(|k| k.as_str()) == Some("duplicates")
            ).ok_or_else(|| anyhow::anyhow!("No 'duplicates' result found"))?;
            let buckets = dup.get("buckets").and_then(|b| b.as_array())
                .ok_or_else(|| anyhow::anyhow!("Missing buckets array"))?;
            Ok(format!("{} duplicate groups", buckets.len()))
        }

        // ── S4C: Duplicate verification ─────────────────────────────
        "S4C.1" | "S4C.2" | "S4C.3" => {
            // verify=first_bytes / sha256 / first_bytes+verify_bytes
            // Must produce valid JSON agg output without error.
            let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
                .map_err(|e| anyhow::anyhow!("Invalid JSON: {e}"))?;
            if parsed.is_null() { bail!("Null output from verified duplicates"); }
            let results = parsed.as_array()
                .ok_or_else(|| anyhow::anyhow!("Expected JSON array"))?;
            if results.is_empty() { bail!("Empty agg results"); }
            // Check that we got a duplicates result.
            let has_dup = results.iter().any(|r|
                r.get("kind").and_then(|k| k.as_str()) == Some("duplicates")
            );
            if !has_dup { bail!("No duplicates-kind result in output"); }
            Ok(format!("{} agg results from verified duplicates", results.len()))
        }
        "S4C.4" => {
            // Default (no verify) — JSON should not have "verified":true
            // on any bucket.
            let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
                .map_err(|e| anyhow::anyhow!("Invalid JSON: {e}"))?;
            if parsed.is_null() { bail!("Null output from duplicates"); }
            let json_str = stdout.trim();
            // "verified":true should NOT appear (unverified groups omit the field
            // via skip_serializing_if).
            if json_str.contains("\"verified\":true") {
                bail!("verified:true present in non-verified duplicates output");
            }
            Ok("duplicates without verify: no verified:true in output".to_owned())
        }
        "S4C.5" => {
            // verify=hash should be accepted (alias for sha256).
            // Verify that the output is valid JSON and doesn't error out.
            let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
                .map_err(|e| anyhow::anyhow!("verify=hash rejected or invalid JSON: {e}"))?;
            if parsed.is_null() { bail!("Null output from verify=hash"); }
            Ok("verify=hash alias accepted".to_owned())
        }

        // ── T178: --case (case-sensitive) ─────────────────────────
        "T178" => {
            let (headers, rows) = parse_csv(stdout);
            if rows.is_empty() { bail!("No output rows"); }
            let name_idx = headers.iter().position(|h| h == "Name")
                .ok_or_else(|| anyhow::anyhow!("No 'Name' column in headers: {headers:?}"))?;
            for (i, row) in rows.iter().enumerate() {
                let name = row.get(name_idx).map(|s| s.as_str()).unwrap_or("");
                if !name.starts_with("README") {
                    bail!("Row {i}: name '{name}' doesn't start with 'README' (case-sensitive)");
                }
            }
            Ok(format!("{} rows, all case-sensitive match", rows.len()))
        }

        // ── T180: --exact-size 0 (zero-byte files) ─────────────────
        "T180" => {
            let (headers, rows) = parse_csv(stdout);
            if rows.is_empty() { bail!("No output rows"); }
            let size_idx = headers.iter().position(|h| h == "Size")
                .ok_or_else(|| anyhow::anyhow!("No 'Size' column in headers: {headers:?}"))?;
            for (i, row) in rows.iter().enumerate() {
                let size = row.get(size_idx).and_then(|s| s.parse::<u64>().ok()).unwrap_or(u64::MAX);
                if size != 0 {
                    bail!("Row {i}: size={size}, expected 0 for --exact-size 0");
                }
            }
            Ok(format!("{} rows, all size=0", rows.len()))
        }

        // ── T181: --exact-descendants 0 (empty dirs) ────────────────
        "T181" => {
            let (_, rows) = parse_csv(stdout);
            if rows.is_empty() { bail!("No output rows"); }
            Ok(format!("{} empty directory rows", rows.len()))
        }

        // ── T184: --case negative (lowercase 'readme*') ────────────
        "T184" => {
            let (headers, rows) = parse_csv(stdout);
            let name_idx = headers.iter().position(|h| h == "Name")
                .ok_or_else(|| anyhow::anyhow!("No 'Name' column"))?;
            // All results should match 'readme*' exactly (lowercase),
            // NOT 'README*' (case-sensitive means only lowercase matches).
            for (i, row) in rows.iter().enumerate() {
                let name = row.get(name_idx).map(|s| s.as_str()).unwrap_or("");
                if name.starts_with("README") {
                    bail!("Row {i}: name '{name}' starts with uppercase README — case-sensitive should only match lowercase 'readme*'");
                }
            }
            Ok(format!("{} rows, none start with uppercase README", rows.len()))
        }

        // ── Daemon subcommand validators ─────────────────────────────────
        "RPC.1" => {
            // daemon status: must show PID and Ready
            if !stdout.contains("Daemon PID:") { bail!("Missing 'Daemon PID:' in output"); }
            if !stdout.contains("Ready") { bail!("Daemon not Ready"); }
            // Extract PID
            let pid = stdout.lines()
                .find(|l| l.contains("Daemon PID:"))
                .and_then(|l| l.split(':').nth(1))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            Ok(format!("pid={pid}, status=Ready"))
        }
        "RPC.2" => {
            // daemon status shows drives with record counts
            let drive_count = stdout.lines()
                .filter(|l| l.contains("records"))
                .count();
            if drive_count == 0 { bail!("No drives shown in daemon status"); }
            Ok(format!("{drive_count} drives loaded"))
        }
        "RPC.4" => {
            // daemon stats: must show performance metrics
            if !stdout.contains("Total records:") { bail!("Missing 'Total records:' in output"); }
            let records = stdout.lines()
                .find(|l| l.contains("Total records:"))
                .and_then(|l| l.split(':').nth(1))
                .map(|s| s.trim().replace(',', ""))
                .unwrap_or_default();
            Ok(format!("total_records={records}"))
        }

        // ── Type validators ───────────────────────────────────────────
        v @ ("type_code" | "type_document" | "type_executable" | "type_picture" | "type_system") => {
            let (h, rows) = parse_csv(stdout);
            if rows.is_empty() { bail!("{v}: 0 rows returned"); }

            let allowed: &[&str] = match v {
                "type_code"       => &["rs","py","js","ts","c","cpp","h","hpp","cs","java","go",
                                       "rb","php","swift","kt","scala","r","lua","pl","sh","bash",
                                       "zsh","fish","ps1","psm1","psd1","vue","svelte","jsx","tsx",
                                       "mjs","cjs","coffee","dart","zig","nim","v","hs","ml","ex",
                                       "exs","erl","clj","lisp","scm","asm","s","f90","f","for",
                                       "vb","vbs","m","mm","d","ada","adb","ads","cob","cbl",
                                       "cmd","bat"],
                "type_document"   => &["pdf","doc","docx","xls","xlsx","ppt","pptx","odt","ods",
                                       "odp","rtf","txt","csv","tsv","md","rst","epub","mobi",
                                       "tex","latex","pages","numbers","key"],
                "type_executable" => &["exe","msi","bat","cmd","ps1","com","scr"],
                "type_picture"    => &["jpg","jpeg","png","gif","bmp","tif","tiff","ico","svg",
                                       "webp","heic","heif","raw","cr2","nef","dng","psd","ai",
                                       "eps","pcx","tga"],
                "type_system"     => &["sys","drv","dll","ocx","cpl","inf","cat","mum","man",
                                       "evt","evtx","etl","reg"],
                _ => unreachable!(),
            };

            let mut bad = Vec::new();
            for (i, row) in rows.iter().enumerate() {
                let name = col_val(row, &h, "Name").to_lowercase();
                if v == "type_system" && name.starts_with('$') { continue; }
                let ext = name.rsplit('.').next().unwrap_or("");
                if !allowed.contains(&ext) {
                    bad.push(format!("row {i}: {name} (ext={ext})"));
                    if bad.len() >= 3 { break; }
                }
            }
            if !bad.is_empty() {
                bail!("{v}: unexpected extensions: {}", bad.join(", "));
            }
            Ok(format!("{v}: {}/{} rows valid", rows.len(), rows.len()))
        }

        // ── Drive filter validator ───────────────────────────────────────
        "drives_cd" => {
            let (h, rows) = parse_csv(stdout);
            if rows.is_empty() { bail!("drives_cd: 0 rows returned"); }
            for (i, row) in rows.iter().enumerate() {
                let path = col_val(row, &h, "Path");
                if !path.starts_with("C:") && !path.starts_with("D:") {
                    bail!("drives_cd: row {i} path not C: or D:: {path}");
                }
            }
            Ok(format!("drives_cd: all {} rows on C: or D:", rows.len()))
        }

        // ── Shmem negative check ─────────────────────────────────────────
        "no_shmem" => {
            // CLI reads shmem transparently; just verify we got rows.
            let (_h, rows) = parse_csv(stdout);
            Ok(format!("{} rows (shmem transparent to CLI)", rows.len()))
        }

        // ── Help / version validators ────────────────────────────────────
        "H1" => {
            // Main help: verify structure has key sections.
            let sections = ["COMMANDS:", "COMMON OPTIONS:", "EXAMPLES:"];
            for section in &sections {
                if !stdout.contains(section) {
                    bail!("Missing section: {section}");
                }
            }
            // Verify all expected `--command`s are listed (search-first grammar).
            let subcommands = ["--search", "--stats", "--agg", "--daemon", "--mcp", "--update", "--status"];
            for sub in &subcommands {
                if !stdout.contains(sub) {
                    bail!("Missing command in help: {sub}");
                }
            }
            // Verify key flags are documented.
            let key_flags = ["--drive", "--limit", "--format", "--sort", "--ext", "--columns",
                             "--mft-file", "--data-dir", "--newer", "--older",
                             "--type", "--min-size", "--max-size"];
            let mut missing: Vec<&str> = Vec::new();
            for flag in &key_flags {
                if !stdout.contains(flag) { missing.push(flag); }
            }
            if !missing.is_empty() {
                bail!("Missing flags in help: {}", missing.join(", "));
            }
            Ok(format!("{} sections, {} subcommands, {} flags verified",
                sections.len(), subcommands.len(), key_flags.len()))
        }
        "H2" => {
            // Daemon help: verify lifecycle actions including 'load'.
            let actions = ["start", "status", "stats", "stop", "kill", "restart", "load"];
            let mut missing: Vec<&str> = Vec::new();
            for action in &actions {
                if !stdout.contains(action) { missing.push(action); }
            }
            if !missing.is_empty() {
                bail!("Missing daemon actions: {}", missing.join(", "));
            }
            // Verify load-specific flags are documented.
            if !stdout.contains("--mft-file") || !stdout.contains("--data-dir") {
                bail!("Daemon help missing --mft-file or --data-dir for load");
            }
            Ok(format!("{} daemon actions verified", actions.len()))
        }
        "H3" => {
            // MCP help: verify server management commands.
            let commands = ["start", "status", "stop", "kill", "restart", "reload"];
            let mut missing: Vec<&str> = Vec::new();
            for cmd in &commands {
                if !stdout.contains(cmd) { missing.push(cmd); }
            }
            if !missing.is_empty() {
                bail!("Missing MCP subcommands: {}", missing.join(", "));
            }
            Ok(format!("{} MCP subcommands verified", commands.len()))
        }
        "H7" => {
            // Version: should contain "uffs" and a semver-like version string.
            if !stdout.contains("uffs") {
                bail!("Version output missing 'uffs': {stdout}");
            }
            // Check for a version pattern like "0.5.16" or similar.
            let has_version = stdout.trim().split_whitespace()
                .any(|word| word.chars().next().map_or(false, |c| c.is_ascii_digit())
                    && word.contains('.'));
            if !has_version {
                bail!("No version number found in: {}", stdout.trim());
            }
            Ok(format!("version: {}", stdout.trim()))
        }

        // ── Fallback — fail loudly so unimplemented validators are noticed ──
        other => {
            bail!("custom validator '{other}' not yet implemented — implement it or remove validator field")
        }
    }
}

/// Build the declarative validator closure for one `TestDef`.
fn build_declarative_validator(def: &TestDef) -> Box<dyn Fn(&str, &str) -> Result<String> + Send + Sync> {
    let def = def.clone();
    Box::new(move |stdout: &str, stderr: &str| {
        let mut details: Vec<String> = Vec::new();

        // ── Row count checks (shared + cli_checks merged) ────────────────
        let row_count = csv_row_count(stdout);
        // cli_checks.expect_min_rows overrides shared if present.
        let eff_min = def.cli_checks.expect_min_rows.or(def.expect_min_rows);
        let eff_max = def.cli_checks.expect_max_rows.or(def.expect_max_rows);
        if let Some(min) = eff_min {
            if row_count < min {
                bail!("Expected >= {min} rows, got {row_count}");
            }
        }
        if let Some(max) = eff_max {
            if row_count > max {
                bail!("Expected <= {max} rows, got {row_count}");
            }
        }
        details.push(format!("{row_count} rows"));

        // ── Column checks ────────────────────────────────────────────────
        if !def.column_checks.is_empty() {
            let (h, rows) = parse_csv(stdout);
            if rows.is_empty() && eff_min.unwrap_or(0) > 0 {
                bail!("No rows for column checks");
            }
            for (i, row) in rows.iter().enumerate() {
                for check in &def.column_checks {
                    let val = col_val(row, &h, &check.column);
                    apply_column_check(i, val, check, &check.column)?;
                }
            }
            if !def.column_checks.is_empty() {
                let check_names: Vec<&str> = def.column_checks.iter()
                    .map(|c| c.column.as_str()).collect();
                details.push(format!("checked {}", check_names.join(",")));
            }
        }

        // ── Sort checks ──────────────────────────────────────────────────
        for sc in &def.sort_checks {
            let (h, rows) = parse_csv(stdout);
            if rows.len() < 2 { details.push("< 2 rows, skip sort".into()); continue; }
            let col = &sc.column;
            match sc.sort_type.as_str() {
                "u64" => {
                    let vals: Vec<u64> = rows.iter()
                        .map(|r| col_val(r, &h, col).parse().unwrap_or(0))
                        .collect();
                    for w in vals.windows(2) {
                        match sc.order.as_str() {
                            "asc"  => { if w[0] > w[1] { bail!("Not ascending: {} > {}", w[0], w[1]); } }
                            "desc" => { if w[0] < w[1] { bail!("Not descending: {} < {}", w[0], w[1]); } }
                            _ => bail!("Unknown sort order: {}", sc.order),
                        }
                    }
                }
                "string" => {
                    // Case-insensitive comparison — NTFS sorts are
                    // case-insensitive (e.g. extension sort: avi < BIN).
                    let vals: Vec<String> = rows.iter()
                        .map(|r| col_val(r, &h, col).to_lowercase())
                        .collect();
                    for w in vals.windows(2) {
                        match sc.order.as_str() {
                            "asc"  => { if w[0] > w[1] { bail!("Not ascending: {} > {}", w[0], w[1]); } }
                            "desc" => { if w[0] < w[1] { bail!("Not descending: {} < {}", w[0], w[1]); } }
                            _ => bail!("Unknown sort order: {}", sc.order),
                        }
                    }
                }
                other => bail!("Unknown sort type: {other}"),
            }
            details.push(format!("sorted {} {}", sc.column, sc.order));
        }

        // ── Stdout substring checks ──────────────────────────────────────
        // Merge legacy flat fields + cli_checks.* (both are checked).
        for s in def.stdout_contains.iter().chain(def.cli_checks.stdout_contains.iter()) {
            if !stdout.contains(s.as_str()) {
                let preview: String = stdout.lines().take(10).collect::<Vec<_>>().join("\n");
                bail!(
                    "stdout missing expected substring: {s}\n  stdout len={}, first 10 lines:\n{preview}",
                    stdout.len()
                );
            }
        }
        for s in def.stdout_not_contains.iter().chain(def.cli_checks.stdout_not_contains.iter()) {
            if stdout.contains(s.as_str()) {
                bail!("stdout contains forbidden substring: {s}");
            }
        }

        // ── Stderr substring checks ──────────────────────────────────────
        for s in def.stderr_contains.iter().chain(def.cli_checks.stderr_contains.iter()) {
            if !stderr.contains(s.as_str()) {
                bail!("stderr missing expected substring: {s}");
            }
        }

        // ── Custom validator ─────────────────────────────────────────────
        if let Some(ref name) = def.validator {
            let custom_result = run_custom_validator(name, stdout, stderr)?;
            details.push(custom_result);
        }

        Ok(details.join(", "))
    })
}

/// Locate the TOML test definitions file relative to the workspace root.
/// Return the directory containing per-group test definition files.
fn find_test_defs_dir() -> PathBuf {
    let ws = find_workspace_root();
    ws.join("scripts").join("tests").join("definitions")
}

/// Load all `[[test]]` entries from `definitions/*.toml` files, sorted
/// lexicographically (00-warmup first, 11-rpc last).
fn load_all_test_defs() -> Vec<TestDef> {
    let dir = find_test_defs_dir();
    if !dir.is_dir() {
        eprintln!("  ❌ Test definitions directory not found: {}", dir.display());
        std::process::exit(1);
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| { eprintln!("  ❌ Cannot read {}: {e}", dir.display()); std::process::exit(1); })
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map_or(false, |ext| ext == "toml"))
        .collect();
    files.sort();

    let mut all_defs: Vec<TestDef> = Vec::new();
    let mut file_count = 0;
    for path in &files {
        let content = std::fs::read_to_string(path)
            .unwrap_or_else(|e| { eprintln!("  ❌ Cannot read {}: {e}", path.display()); std::process::exit(1); });
        let defs: TestDefsFile = toml::from_str(&content)
            .unwrap_or_else(|e| { eprintln!("  ❌ Cannot parse {}: {e}", path.display()); std::process::exit(1); });
        all_defs.extend(defs.test);
        file_count += 1;
    }
    eprintln!("  Loaded {} test definitions from {} files in definitions/",
        all_defs.len(), file_count);
    all_defs
}

/// Load test definitions from TOML and convert to `Vec<TestSpec>`.
///
/// Returns `(cli_specs, api_only_ids)` — the second vec contains test IDs
/// that are api-only, so the caller can inform the user when their filter
/// matches one of these.
fn load_tests_from_toml() -> (Vec<TestSpec>, Vec<String>) {
    let all_defs = load_all_test_defs();

    let mut specs = Vec::with_capacity(all_defs.len());
    let mut api_only_ids: Vec<String> = Vec::new();
    let mut skipped = 0;
    let mut filtered_out = 0;
    for def in &all_defs {
        if def.skip.unwrap_or(false) { skipped += 1; continue; }
        if !def.targets.iter().any(|t| t == "cli") {
            filtered_out += 1;
            api_only_ids.push(def.id.clone());
            continue;
        }
        let display_name = def.name.clone();
        let mut args = def.cli_args.clone();
        // Inject --columns all if the test needs full CSV output.
        if def.expect_columns_all.unwrap_or(false)
            && !args.iter().any(|a| a == "--columns")
        {
            args.push("--columns".into());
            args.push("all".into());
        }
        let validator = build_declarative_validator(def);
        specs.push(TestSpec {
            name: display_name,
            args,
            validate: validator,
        });
    }
    if skipped > 0 || filtered_out > 0 {
        eprintln!("  ({} cli tests, {} api-only skipped, {} disabled)",
            specs.len(), filtered_out, skipped);
    }
    (specs, api_only_ids)
}

// ── Test Runner ──────────────────────────────────────────────────────────────

struct TestResult {
    name: String,
    /// The `uffs.exe` CLI command to reproduce (always present).
    cli: String,
    /// The daemon JSON-RPC params (only for direct/socket tests).
    api: String,
    passed: bool,
    duration_ms: u128,
    detail: String,
}

/// A test specification: name + args + validator closure.
struct TestSpec {
    name: String,
    args: Vec<String>,
    validate: Box<dyn Fn(&str, &str) -> Result<String> + Send + Sync>,
}

// ── Daemon socket communication (used only for startup probe) ────────────

/// Resolve the daemon socket path.
///
/// Priority: `data_dir` → platform default via `dirs_next`.
/// Must match `IpcServer::socket_path()` in the daemon crate.
/// Resolve the daemon socket path.
///
/// The daemon ALWAYS creates its socket at the platform default location
/// (`dirs_next::data_local_dir()/uffs/daemon.sock`), regardless of
/// `--data-dir` (which only controls where MFT index data lives).
fn daemon_socket_path() -> PathBuf {
    let base = dirs_next::data_local_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join("uffs").join("daemon.sock")
}


/// Run uffs with given args, return (exit_code, stdout, stderr).
/// Maximum time (seconds) any single CLI test process may run before being killed.
/// Aggregate tests that auto-start a daemon may need up to 30s for connection +
/// index loading, so 90s gives ample margin.
const CLI_TIMEOUT_SECS: u64 = 90;

fn run_uffs(bin: &str, args: &[String]) -> Result<(i32, String, String)> {
    use std::io::Read;

    let mut child = Command::new(bin)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to spawn: {} {}", bin, args.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ")))?;

    // Drain stdout/stderr in background threads to avoid pipe deadlock
    // (child blocks on write if pipe buffer fills while we wait for exit).
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stdout_handle = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = stdout_pipe {
            let _ = pipe.read_to_end(&mut bytes);
        }
        String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
    });
    let stderr_handle = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = stderr_pipe {
            let _ = pipe.read_to_end(&mut bytes);
        }
        String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(CLI_TIMEOUT_SECS);

    // Poll until done or timeout.
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_handle.join().unwrap_or_default();
                let stderr = stderr_handle.join().unwrap_or_default();
                return Ok((status.code().unwrap_or(-1), stdout, stderr));
            }
            Ok(None) => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait(); // reap
                    bail!("Process timed out after {CLI_TIMEOUT_SECS}s (killed)");
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => bail!("Error waiting for process: {e}"),
        }
    }
}

/// Build the CLI string for display/reproduction.
fn cli_string(bin: &str, args: &[String]) -> String {
    let mut parts = vec![bin.to_string()];
    for a in args {
        if a.contains(' ') || a.contains('*') || a.contains('>') || a.contains('<') {
            parts.push(format!("\"{a}\""));
        } else {
            parts.push(a.clone());
        }
    }
    parts.join(" ")
}

/// `--command`s that do NOT accept `--data-dir` (pure management — they
/// don't read a data source). Search-first grammar: commands are `--<name>`.
const SUBCOMMANDS_NO_DATA_DIR: &[&str] = &["--daemon", "--status", "--mcp", "--update"];

/// Flags whose presence means we should NOT inject `--columns all`.
const OUTPUT_SHAPING_FLAGS: &[&str] = &[
    "--columns", "--format", "--name-only", "--benchmark",
];

/// Run a single test via CLI process spawn.
fn run_one_test_cli(bin: &str, spec: &TestSpec, source_flag: Option<&str>, source_path: &str) -> TestResult {
    let mut args = spec.args.clone();
    let first = args.first().map(String::as_str).unwrap_or("");

    // Commands (`--agg`, `--stats`, `--daemon`, …) don't accept search flags.
    let is_subcommand = SUBCOMMANDS_NO_DATA_DIR.iter().any(|s| first.eq_ignore_ascii_case(s))
        || matches!(first.to_lowercase().as_str(), "--agg" | "--aggregate" | "--stats");

    if !is_subcommand {
        if let Some(flag) = source_flag {
            args.push(flag.to_string());
            args.push(source_path.to_string());
        }

        // Inject `--columns all` so validators see the full CSV output
        // (matching the format that direct/socket tests previously used).
        let has_output_flag = args.iter().any(|a|
            OUTPUT_SHAPING_FLAGS.iter().any(|f| a == f)
        );
        if !has_output_flag {
            args.push("--columns".to_string());
            args.push("all".to_string());
        }
    } else if !SUBCOMMANDS_NO_DATA_DIR.iter().any(|s| first.eq_ignore_ascii_case(s)) {
        // Subcommand that still needs source flag (agg, stats, etc.)
        if let Some(flag) = source_flag {
            args.push(flag.to_string());
            args.push(source_path.to_string());
        }
    }

    let cli = cli_string(bin, &args);
    let start = Instant::now();
    let result = run_uffs(bin, &args);
    let duration_ms = start.elapsed().as_millis();

    let (passed, detail) = match result {
        Ok((code, stdout, stderr)) => {
            if code != 0 {
                (false, format!("Exit code {code}. stderr: {}", stderr.lines().next().unwrap_or("")))
            } else {
                match (spec.validate)(&stdout, &stderr) {
                    Ok(msg) => (true, format!("{msg} [cli]")),
                    Err(e) => (false, format!("{e}")),
                }
            }
        }
        Err(e) => (false, format!("Execution failed: {e}")),
    };

    TestResult { name: spec.name.clone(), cli, api: String::new(), passed, duration_ms, detail }
}

/// Concurrency limit for parallel process spawning.
///
/// Spawning 141 `uffs.exe` processes at once crushes Windows (process creation
/// + Defender scanning + DLL loading).  Cap to CPU core count for optimal
/// throughput without resource starvation.
fn max_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
}

/// Run all test specs via CLI process spawn with bounded parallelism.
///
/// Every test spawns a real `uffs` process to validate the full stack:
/// arg parsing → config → daemon connect → query → output formatting.
fn run_tests_parallel(bin: &str, specs: &[TestSpec], source_flag: Option<&str>, source_path: &str) -> (Vec<TestResult>, u128) {
    let max_par = max_parallelism();
    let wall_start = Instant::now();

    eprintln!("  → {} CLI tests (process spawn, parallelism: {max_par})", specs.len());
    eprintln!();

    let mut results: Vec<TestResult> = Vec::with_capacity(specs.len());

    for chunk in specs.chunks(max_par) {
        let chunk_results: Vec<TestResult> = std::thread::scope(|s| {
            let handles: Vec<_> = chunk.iter().map(|spec| {
                s.spawn(|| run_one_test_cli(bin, spec, source_flag, source_path))
            }).collect();
            handles.into_iter().map(|h| h.join().unwrap_or_else(|_| TestResult {
                name: "???".into(), cli: "???".into(), api: String::new(), passed: false, duration_ms: 0,
                detail: "thread panicked".into(),
            })).collect()
        });
        for r in &chunk_results {
            let status = if r.passed { "PASS".green().bold() } else { "FAIL".red().bold() };
            let timing = format!("{:>5}ms", r.duration_ms).dimmed();
            eprintln!("  [{status}] {timing}  {}: {}", r.name, r.detail);
        }
        results.extend(chunk_results);
    }

    let wall_ms = wall_start.elapsed().as_millis();
    (results, wall_ms)
}

// ── Legacy define_tests removed — all 219 tests now in test-definitions.toml ──

fn print_results(results: &[TestResult]) {
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;

    eprintln!();
    if failed == 0 {
        eprintln!("  {} {passed}/{total} passed", "✅".green());
    } else {
        eprintln!("  {} {failed}/{total} FAILED", "❌".red());
        eprintln!();
        eprintln!("  ┌─ Failed Tests ──────────────────────────────────────────────────────┐");
        for r in results {
            if !r.passed {
                eprintln!("  │");
                eprintln!("  │  {} {}", "❌".red(), r.name);
                eprintln!("  │  {}: {}", "Error".red().bold(), r.detail);
                eprintln!("  │  {}:   {}", "CLI".yellow().bold(), r.cli);
                if !r.api.is_empty() {
                    // Indent each line of the pretty-printed JSON.
                    eprintln!("  │  {}:   {}", "API".cyan().bold(), r.api.lines().next().unwrap_or(""));
                    for line in r.api.lines().skip(1) {
                        eprintln!("  │         {line}");
                    }
                }
            }
        }
        eprintln!("  │");
        eprintln!("  └──────────────────────────────────────────────────────────────────────┘");
    }

    // When running a small number of tests (e.g. --tests filter), show
    // full CLI command for every test — same info shown on failure, so
    // users can replay or inspect.  Skip when every test already
    // appeared in the failure box to avoid duplicate output.
    if total <= 10 && total > 0 && passed > 0 {
        eprintln!();
        eprintln!("  ┌─ Test Details ───────────────────────────────────────────────────────┐");
        for r in results {
            let icon = if r.passed { "✅" } else { "❌" };
            eprintln!("  │");
            eprintln!("  │  {icon} {} ({}ms)", r.name, r.duration_ms);
            eprintln!("  │  {}: {}", "Result".bold(), r.detail);
            eprintln!("  │  {}:    {}", "CLI".yellow().bold(), r.cli);
        }
        eprintln!("  │");
        eprintln!("  └──────────────────────────────────────────────────────────────────────┘");
    }
}

/// Ensure daemon is running and ready before tests.
///
/// Returns the time spent waiting for the daemon to become ready (ms).
///
/// 1. Run `uffs --daemon status` — if "Ready", done.
/// 2. If "not running", run `uffs --daemon start --data-dir ...` (blocks
///    until "Daemon started and ready." is printed, then returns).
fn ensure_daemon_ready(args: &ScriptArgs) -> u128 {
    let bin = &args.bin;
    let t0 = Instant::now();

    // Step 1: Check status.
    eprintln!("  Checking daemon status...");
    match run_uffs(bin, &["--daemon".to_string(), "status".to_string()]) {
        Ok((_code, stdout, stderr)) => {
            let combined = format!("{stdout}{stderr}");
            let lower = combined.to_lowercase();

            if lower.contains("ready") {
                // Check whether drives are actually loaded.
                // Status output contains "Drives: (none loaded)" or "Drives: N".
                let has_drives = !lower.contains("none loaded")
                    && !lower.contains("drives:        0")
                    && !lower.contains("drives: 0");

                if has_drives {
                    let ms = t0.elapsed().as_millis();
                    eprintln!("  Daemon: {} ✓ ({ms}ms)", "Ready".green().bold());
                    for line in combined.lines() {
                        eprintln!("    {line}");
                    }
                    return ms;
                }

                // Daemon is Ready but has zero drives — stale/useless.
                eprintln!("  Daemon is {} but has {} — restarting with data source...",
                    "Ready".yellow(), "zero drives loaded".red().bold());
                for line in combined.lines() {
                    eprintln!("    {line}");
                }
                // Stop the stale daemon so we can restart with the data source.
                eprintln!("  Stopping stale daemon...");
                let _ = run_uffs(bin, &["--daemon".to_string(), "stop".to_string()]);
                // Brief pause to let the socket close.
                std::thread::sleep(std::time::Duration::from_millis(500));
            } else if lower.contains("not running") {
                eprintln!("  Daemon is not running, starting...");
            } else {
                eprintln!("  Daemon status unclear, attempting start...");
                for line in combined.lines() {
                    eprintln!("    {line}");
                }
            }
        }
        Err(e) => {
            eprintln!("  Cannot check daemon status: {e}");
            eprintln!("  Attempting start...");
        }
    }

    // Step 2: Start daemon.
    let mut start_args = vec!["--daemon".to_string(), "start".to_string()];
    if let Some(flag) = args.source_flag {
        start_args.push(flag.to_string());
        start_args.push(args.source_path.clone());
    }
    let cli_str = format!("{bin} {}", start_args.join(" "));
    eprintln!("    ↳ {}", cli_str.dimmed());
    match run_uffs(bin, &start_args) {
        Ok((_code, stdout, stderr)) => {
            let ms = t0.elapsed().as_millis();
            let combined = format!("{stdout}{stderr}");
            eprintln!("  Daemon: {} ({ms}ms)", "Spawned".green().bold());
            for line in combined.lines() {
                eprintln!("    {line}");
            }
        }
        Err(e) => {
            let ms = t0.elapsed().as_millis();
            eprintln!("  Daemon start {} — {e} ({ms}ms)", "FAILED".red().bold());
            return ms;
        }
    }

    // Step 3: Poll `daemon status` until "Ready" (all drives loaded).
    // Without this, each test's `uffs` process wastes ~20s in await_ready().
    eprintln!("  Waiting for all drives to load...");
    let mut delay_ms = 500_u64;
    let max_wait = std::time::Duration::from_secs(120);
    loop {
        if t0.elapsed() > max_wait {
            eprintln!("  {} Timed out waiting for daemon Ready after {}s",
                "⚠".yellow(), max_wait.as_secs());
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        match run_uffs(bin, &["--daemon".to_string(), "status".to_string()]) {
            Ok((_code, stdout, stderr)) => {
                let combined = format!("{stdout}{stderr}");
                let lower = combined.to_lowercase();
                if lower.contains("ready") {
                    let ms = t0.elapsed().as_millis();
                    eprintln!("  Daemon: {} ✓ — all drives loaded ({ms}ms)", "Ready".green().bold());
                    for line in combined.lines() {
                        eprintln!("    {line}");
                    }
                    return ms;
                }
                // Show loading progress.
                if lower.contains("loading") {
                    let progress = combined.lines()
                        .find(|l| l.to_lowercase().contains("loading") || l.contains("records"))
                        .unwrap_or("loading...");
                    eprint!("\r  Daemon: {} — {progress}    ", "Loading".yellow());
                }
            }
            Err(_) => {}
        }
        delay_ms = (delay_ms * 2).min(2000);
    }
    t0.elapsed().as_millis()
}


// ── Main ─────────────────────────────────────────────────────────────────────

/// Find the longest common prefix of a set of strings.
///
/// Used by the failure-summary block to suggest a single `--tests <prefix>`
/// re-run command when every failed test ID shares a common stem (e.g.
/// all `T88a`, `T88b`, `T88c` failures collapse to `T88`).  Mirrors
/// `mcp-validation.rs::common_prefix` byte-for-byte so the three
/// validation suites behave identically on this output.
fn common_prefix(strings: &[&str]) -> String {
    if strings.is_empty() { return String::new(); }
    let first = strings[0];
    let mut len = first.len();
    for s in &strings[1..] {
        len = len.min(s.len());
        for (i, (a, b)) in first.bytes().zip(s.bytes()).enumerate() {
            if a != b { len = len.min(i); break; }
        }
    }
    first[..len].to_string()
}

/// Extract the test ID (e.g. "T88H") from a test name like "T88h --in-path + pattern".
fn test_id(name: &str) -> String {
    // Take everything up to the first space.
    name.split_whitespace()
        .next()
        .unwrap_or(name)
        .to_uppercase()
}

/// Filter test specs by the --tests filter. Empty filter = run all.
/// Filter supports both exact match and prefix match (e.g. "S4C" matches "S4C.1", "S4C.2").
fn filter_tests(specs: Vec<TestSpec>, filter: &[String]) -> Vec<TestSpec> {
    if filter.is_empty() { return specs; }
    specs.into_iter().filter(|s| {
        let id = test_id(&s.name);
        filter.iter().any(|f| id == *f || id.starts_with(f))
    }).collect()
}

fn main() {
    let _lock = ValidationLock::acquire();
    let script_start = Instant::now();
    let args = parse_script_args();
    eprintln!();
    eprintln!("╔═══════════════════════════════════════════════════════════════╗");
    eprintln!("║  UFFS CLI Flag Validation Suite                              ║");
    eprintln!("╚═══════════════════════════════════════════════════════════════╝");
    let sock = daemon_socket_path();
    eprintln!("  Binary:  {}", args.bin.cyan());
    if let Some(flag) = args.source_flag {
        eprintln!("  Source:  {} {}", flag, args.source_path.cyan());
    } else {
        eprintln!("  Source:  {}", "(live NTFS drives)".cyan());
    }
    eprintln!("  Socket:  {}", sock.display().to_string().cyan());
    if !args.test_filter.is_empty() {
        eprintln!("  Filter:  {}", args.test_filter.join(", ").cyan());
    }
    eprintln!();

    let has_filter = !args.test_filter.is_empty();

    // ═══ Ensure daemon is running before tests ═════════════════════════
    let daemon_ms = ensure_daemon_ready(&args);

    // ═══ Load & filter test definitions ═════════════════════════════════
    let (all_specs, api_only_ids) = load_tests_from_toml();
    eprintln!();
    let specs = filter_tests(all_specs, &args.test_filter);

    // Show which filtered tests are api-only (run via api-validation.rs).
    if !args.test_filter.is_empty() {
        let matched_api: Vec<&String> = api_only_ids.iter().filter(|id| {
            let upper = id.to_uppercase();
            args.test_filter.iter().any(|f| upper == *f || upper.starts_with(f))
        }).collect();
        if !matched_api.is_empty() {
            for id in &matched_api {
                eprintln!("  {} {} — api-only test, run with: rust-script scripts/windows/api-validation.rs --tests {}",
                    "ℹ".cyan(), id, id);
            }
            eprintln!();
        }
    }

    if specs.is_empty() {
        eprintln!("  {} No CLI tests matched filter: {:?}", "⚠".yellow(), args.test_filter);
        eprintln!("  Available test IDs: T00, T01, ..., T128, T130-T149");
        std::process::exit(1);
    }

    let test_count = specs.len();
    let max_par = max_parallelism();

    eprintln!("┌───────────────────────────────────────────────────────────────┐");
    if has_filter {
        eprintln!("│  Running {} selected test(s)                                  │", test_count);
    } else {
        eprintln!("│  Parallel Validation ({test_count} tests, HOT daemon)                 │");
    }
    eprintln!("└───────────────────────────────────────────────────────────────┘");
    eprintln!("  Launching {test_count} tests (parallelism: {max_par})...");
    eprintln!();

    // ═══ Run tests ══════════════════════════════════════════════════════
    let (results, test_wall_ms) = run_tests_parallel(&args.bin, &specs, args.source_flag, &args.source_path);
    print_results(&results);

    // ═══ Final timing summary ══════════════════════════════════════════
    let script_total_ms = script_start.elapsed().as_millis();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.len() - passed;
    let test_sum_ms: u128 = results.iter().map(|r| r.duration_ms).sum();
    let test_avg_ms = if !results.is_empty() { test_sum_ms / results.len() as u128 } else { 0 };
    let slowest = results.iter().max_by_key(|r| r.duration_ms);
    let fastest = results.iter().filter(|r| r.duration_ms > 0).min_by_key(|r| r.duration_ms);

    let daemon_version = capture_daemon_version(&args.bin);
    eprintln!();
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("  {} Timing Breakdown", "⏱".dimmed());
    eprintln!("  ─────────────────────────────────────────────────────");
    eprintln!("  Daemon version:       {daemon_version}");
    eprintln!("  Daemon ready:         {:>7}ms  (status check + start + drive load)", daemon_ms);
    eprintln!("  ─────────────────────────────────────────────────────");
    eprintln!("  Tests wall time:      {:>7}ms  ({test_count} tests, parallelism: {max_par})", test_wall_ms);
    eprintln!("  Tests sum time:       {:>7}ms  (total CPU across all tests)", test_sum_ms);
    eprintln!("  Tests avg time:       {:>7}ms  (per test)", test_avg_ms);
    if let Some(s) = slowest {
        eprintln!("  Slowest test:         {:>7}ms  {}", s.duration_ms, s.name.dimmed());
    }
    if let Some(f) = fastest {
        eprintln!("  Fastest test:         {:>7}ms  {}", f.duration_ms, f.name.dimmed());
    }
    eprintln!("  ─────────────────────────────────────────────────────");
    eprintln!("  Script total:         {:>7}ms", script_total_ms);
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // ═══ Daemon STATUS + STATS — observe-only post-run snapshot ═════════
    //
    // The validation suite is a strict observer: it does not kill orphan
    // processes or mutate the host in any way.  Those concerns live in
    // `scripts/dev/orphan-cleanup.rs` (callable via `just orphan`).
    print_uffs_command_block(&args.bin, &["--daemon", "status"], "═══ Daemon STATUS ═══");
    print_uffs_command_block(&args.bin, &["--daemon", "status", "-v"],  "═══ Daemon STATUS -v (perf) ═══");

    if failed > 0 {
        // Build retest command with failed test IDs.  Same shape as
        // `mcp-validation.rs` so the three validation suites give the
        // operator a one-line copy-pasteable replay.
        let failed_ids: Vec<String> = results.iter()
            .filter(|r| !r.passed)
            .map(|r| test_id(&r.name))
            .collect();
        eprintln!();
        eprintln!("  Retest failed using:");
        let joined = failed_ids.join(",");
        eprintln!("    rust-script scripts/windows/cli-validation.rs --tests {joined}");
        if failed_ids.len() > 1 {
            // Suggest a prefix shortcut when every failed ID shares one
            // (e.g. T88a / T88b / T88c → T88).
            let id_refs: Vec<&str> = failed_ids.iter().map(String::as_str).collect();
            let prefix = common_prefix(&id_refs);
            if !prefix.is_empty() && prefix.len() >= 2 {
                eprintln!();
                eprintln!("  Or by prefix:");
                eprintln!("    rust-script scripts/windows/cli-validation.rs --tests {prefix}");
            }
        }
    }

    // Exit code: fail if any test failed.
    std::process::exit(if failed == 0 { 0 } else { 1 });
}

// ── Post-run STATUS / STATS rendering ───────────────────────────────────────

/// Run `<bin> <args...>` and render its stdout under a 2-space-indented
/// `<header>` so the validation summary embeds the daemon's own
/// `daemon status` / `daemon stats` output verbatim.
///
/// The CLI already formats these views nicely (Index heap, RSS, mimalloc,
/// per-drive breakdown, agg-cache hit-rate, etc.), so re-formatting here
/// would just diverge them over time.  Failures are surfaced inline
/// rather than aborting — the STATUS block is observability, not a gate.
fn print_uffs_command_block(bin: &str, args: &[&str], header: &str) {
    eprintln!();
    eprintln!("  {header}");
    match Command::new(bin).args(args).output() {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                eprintln!("    {line}");
            }
        }
        Ok(out) => {
            eprintln!("    (command failed: exit {})", out.status.code().unwrap_or(-1));
            let stderr = String::from_utf8_lossy(&out.stderr);
            for line in stderr.lines() {
                eprintln!("    {line}");
            }
        }
        Err(e) => {
            eprintln!("    (failed to run: {e})");
        }
    }
}