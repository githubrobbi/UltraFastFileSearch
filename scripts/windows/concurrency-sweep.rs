#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! colored = "2"
//! regex = "1"
//! ```
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.
//!
//! concurrency-sweep.rs — Sweep `UFFS_SEARCH_MAX_CONCURRENCY` values and
//! measure each with the api-validation harness.
//!
//! For each value `N` in the sweep list this script runs the *exact*
//! sequence the user drives manually in PowerShell, one step at a time,
//! waiting for each process to return before moving on:
//!
//! 1. `Remove-Item` the on-disk caches (`%LOCALAPPDATA%\uffs\cache` and
//!    `%TEMP%\uffs_index_cache`) to force a clean start.
//! 2. `uffs --mcp kill`
//! 3. `uffs --daemon kill`
//! 4. Set `UFFS_SEARCH_MAX_CONCURRENCY=N` and run `uffs --daemon start`.
//!    On Windows this call blocks until the daemon reports `Ready`
//!    (typical cold-load time: ~80 s for 26 M records over 7 drives).
//!    No polling is needed — we just wait for the process to return.
//! 5. Read the `search concurrency retuned` line from `uffsd.log` and
//!    verify `source="env"` and `target=N`.
//! 6. Run one warm-up api-validation (populates the agg cache).
//! 7. Run one measured api-validation and parse its Timing Breakdown.
//! 8. Capture `uffs --daemon status -v` for cache hit-rate and avg query time.
//!
//! A summary table is printed at the end.
//!
//! Usage:
//!   rust-script scripts/windows/concurrency-sweep.rs
//!   rust-script scripts/windows/concurrency-sweep.rs 3 6 12
//!   rust-script scripts/windows/concurrency-sweep.rs --skip-warmup 6 12
//!   rust-script scripts/windows/concurrency-sweep.rs --no-wipe 6 12

use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use colored::Colorize;
use regex::Regex;

// ── Configuration ────────────────────────────────────────────────────────────

/// Default sweep values when no positional args are supplied.
const DEFAULT_SWEEP: &[usize] = &[3, 6, 8, 12, 16, 24];

/// Seconds to sleep after `daemon kill` so the socket / PID file are gone
/// before we spawn a new daemon.
const KILL_SETTLE_SECS: u64 = 2;

// ── Environment helpers ──────────────────────────────────────────────────────

/// Resolve `~/bin/uffs[.exe]` — the canonical user-installed binary path
/// on both Windows and Unix.
fn uffs_bin() -> PathBuf {
    let home = env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(PathBuf::from)
        .expect("USERPROFILE or HOME must be set");
    if cfg!(windows) {
        home.join("bin").join("uffs.exe")
    } else {
        home.join("bin").join("uffs")
    }
}

/// Directory we force the daemon to log into for this sweep.  We own
/// this path (rather than using the platform default) because we want
/// to *guarantee* `uffsd.log` exists — the daemon runs with
/// `log_file = None` by default, so the tune-line grep would have
/// nothing to read otherwise.
fn sweep_log_dir(repo_root: &PathBuf) -> PathBuf {
    repo_root.join("build").join("sweep-logs")
}

/// Full path to the daemon log we grep for `search concurrency retuned`.
fn uffsd_log_path(log_dir: &PathBuf) -> PathBuf {
    log_dir.join("uffsd.log")
}

/// Paths that should be wiped before each iteration to force a cold start.
fn cache_paths_to_wipe() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if cfg!(windows) {
        if let Some(p) = env::var_os("LOCALAPPDATA") {
            v.push(PathBuf::from(p).join("uffs").join("cache"));
        }
        if let Some(p) = env::var_os("TEMP") {
            v.push(PathBuf::from(p).join("uffs_index_cache"));
        }
    } else {
        if let Some(p) = env::var_os("HOME") {
            v.push(PathBuf::from(p).join(".uffs").join("cache"));
        }
    }
    v
}

// ── Subprocess helpers ───────────────────────────────────────────────────────

/// Run `uffs <subcmd> kill`, inheriting stdout/stderr so the user sees
/// the same messages they would see running it manually.  Errors are
/// swallowed because an already-dead process is a normal precondition.
fn kill(subcmd: &str) {
    let _ = Command::new(uffs_bin())
        .args([subcmd, "kill"])
        .status();
}

/// Run `uffs --daemon start` with `UFFS_SEARCH_MAX_CONCURRENCY=N` in the
/// environment.  This call inherits stdout/stderr and **blocks until
/// the daemon reports `Ready`** (or the CLI gives up).  No polling —
/// the child `uffs` process does the wait internally and prints
/// "Daemon started and ready." when the MFT load is complete.
///
/// Also sets `UFFS_LOG_DIR` to `log_dir` so the daemon writes
/// `uffsd.log` there; this is the **only** way the sweep can grep the
/// `search concurrency retuned` line and confirm the env override took
/// effect (without it, the daemon runs with `log_file = None` and
/// nothing ever hits disk).
///
/// # Errors
/// Returns an error if `uffs --daemon start` exits non-zero.
fn start_daemon(n: usize, log_dir: &PathBuf) -> Result<()> {
    let status = Command::new(uffs_bin())
        .args(["--daemon", "start"])
        .env("UFFS_SEARCH_MAX_CONCURRENCY", n.to_string())
        .env("UFFS_LOG_DIR", log_dir)
        .status()
        .context("failed to spawn `uffs --daemon start`")?;
    if !status.success() {
        bail!("`uffs --daemon start` exited with status {status}");
    }
    Ok(())
}

// ── As-found run-state snapshot/restore ──────────────────────────────────────
// The sweep hard-kills BOTH the MCP gateway and the daemon on every iteration
// and restarts the daemon with a concurrency override — leaving MCP dead and
// the daemon on a non-default state afterwards.  Snapshot the as-found state up
// front (a `RunStateGuard` whose `Drop` restores it) so the host is returned to
// exactly how we found it, even on an early `?` error return.

/// The host's UFFS run-state captured before the sweep mutates anything.
struct RunState {
    /// Drive letters the daemon had loaded, or `None` if it was not running.
    daemon_drives: Option<Vec<String>>,
    /// Whether the MCP HTTP gateway was running.
    mcp_running: bool,
}

/// Whether a `Status:` value reads as "running" (`"not running"` contains
/// `"running"`, so it is excluded first).
fn status_is_running(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    !lower.contains("not running") && !lower.contains("not responding") && lower.contains("running")
}

/// Extract a drive letter from a `uffs --status` line like `"[W] G:  … records"`.
fn status_drive_letter(line: &str) -> Option<String> {
    let after = line.strip_prefix('[')?.split_once(']')?.1.trim_start();
    let mut chars = after.chars();
    let letter = chars.next()?;
    (letter.is_ascii_alphabetic() && chars.next() == Some(':'))
        .then(|| letter.to_ascii_uppercase().to_string())
}

/// Parse `uffs --status` stdout into a [`RunState`], scoping `Status:` and the
/// `[T] L:` drive lines to their section.
fn parse_run_state(stdout: &str) -> RunState {
    let (mut section, mut daemon_running, mut daemon_seen, mut mcp_running) = (0_u8, false, false, false);
    let mut drives: Vec<String> = Vec::new();
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.contains("── Daemon") { section = 1; daemon_seen = true; continue; }
        if line.contains("MCP HTTP Gateway") { section = 2; continue; }
        if line.contains("MCP Stdio") { section = 3; continue; }
        match section {
            1 => {
                if let Some(rest) = line.strip_prefix("Status:") { daemon_running = status_is_running(rest); }
                else if let Some(d) = status_drive_letter(line) { drives.push(d); }
            }
            2 => if let Some(rest) = line.strip_prefix("Status:") { mcp_running = status_is_running(rest); },
            _ => {}
        }
    }
    RunState {
        daemon_drives: if daemon_seen && daemon_running { Some(drives) } else { None },
        mcp_running,
    }
}

/// Capture the as-found daemon + MCP state via `uffs --status`.
fn capture_run_state() -> RunState {
    match Command::new(uffs_bin()).arg("--status").output() {
        Ok(out) => parse_run_state(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => RunState { daemon_drives: None, mcp_running: false },
    }
}

/// Restore the daemon + MCP to the captured `state` with production defaults
/// (no `UFFS_SEARCH_MAX_CONCURRENCY` / `UFFS_LOG_DIR` sweep overrides).
fn restore_run_state(state: &RunState) {
    println!("{}", "── Restoring UFFS run-state to as-found ──".bold().cyan());
    kill("daemon"); // hard-kill whatever the sweep left running
    match &state.daemon_drives {
        None => println!("  daemon was stopped at start — leaving it stopped"),
        Some(drives) => {
            let scope = if drives.is_empty() { "(all)".to_string() } else { drives.join(",") };
            println!("  restarting daemon on as-found drives: {scope}");
            let mut args: Vec<String> = vec!["--daemon".into(), "start".into()];
            for d in drives { args.push("--drive".into()); args.push(d.clone()); }
            let _ = Command::new(uffs_bin()).args(&args).status();
        }
    }
    if state.mcp_running {
        println!("  restarting MCP gateway (was up at start)");
        let _ = Command::new(uffs_bin()).args(["--mcp", "start"]).status();
    }
}

/// RAII guard: captures the as-found run-state on construction and restores it
/// on `Drop`, so the sweep leaves the host as it found it even on an early
/// error return.
struct RunStateGuard {
    /// The as-found state to restore on teardown.
    state: RunState,
}

impl RunStateGuard {
    /// Capture the current run-state and announce it.
    fn install() -> Self {
        let state = capture_run_state();
        match &state.daemon_drives {
            None => println!("  As-found     : daemon stopped, mcp {}",
                if state.mcp_running { "up" } else { "down" }),
            Some(drives) => println!("  As-found     : daemon on {}, mcp {}",
                if drives.is_empty() { "(all)".to_string() } else { drives.join(",") },
                if state.mcp_running { "up" } else { "down" }),
        }
        Self { state }
    }
}

impl Drop for RunStateGuard {
    fn drop(&mut self) {
        restore_run_state(&self.state);
    }
}

/// Run the api-validation harness and capture its combined stdout + stderr.
fn run_validation(repo_root: &PathBuf) -> Result<String> {
    let script = repo_root
        .join("scripts")
        .join("windows")
        .join("api-validation.rs");
    let out = Command::new("rust-script")
        .arg(&script)
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("failed to spawn rust-script {}", script.display()))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok(text)
}

/// Capture `uffs --daemon status -v` as plain text (perf stats folded in).
fn daemon_stats_text() -> String {
    Command::new(uffs_bin())
        .args(["--daemon", "status", "-v"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Find the workspace root by walking up from `cwd` looking for a folder
/// that contains both `Cargo.toml` and a `crates/` directory.
fn find_repo_root() -> Result<PathBuf> {
    let start = env::current_dir()?;
    for anc in start.ancestors() {
        if anc.join("Cargo.toml").exists() && anc.join("crates").is_dir() {
            return Ok(anc.to_path_buf());
        }
    }
    bail!(
        "could not find repo root from {} (expected Cargo.toml + crates/)",
        start.display()
    )
}

// ── Output parsing ───────────────────────────────────────────────────────────

#[derive(Default, Debug)]
struct RunMetrics {
    wall_ms: Option<u64>,
    sum_ms: Option<u64>,
    avg_ms: Option<u64>,
    slowest_ms: Option<u64>,
    slowest_name: Option<String>,
    passed: Option<u32>,
    total: Option<u32>,
}

fn parse_metrics(output: &str) -> RunMetrics {
    // These regexes target the "Timing Breakdown" block produced by
    // api-validation.rs — they are stable across Windows/Mac.
    let re_wall = Regex::new(r"Tests wall time:\s+(\d+)ms").unwrap();
    let re_sum = Regex::new(r"Tests sum time:\s+(\d+)ms").unwrap();
    let re_avg = Regex::new(r"Tests avg time:\s+(\d+)ms").unwrap();
    let re_slow = Regex::new(r"Slowest test:\s+(\d+)ms\s+(.+)").unwrap();
    // api-validation prints either "<P>/<T> passed" on success or
    // "<F>/<T> FAILED" on failure — handle both.
    let re_pass = Regex::new(r"(\d+)/(\d+)\s+passed").unwrap();
    let re_fail = Regex::new(r"(\d+)/(\d+)\s+FAILED").unwrap();

    let mut m = RunMetrics::default();
    if let Some(c) = re_wall.captures(output) {
        m.wall_ms = c[1].parse().ok();
    }
    if let Some(c) = re_sum.captures(output) {
        m.sum_ms = c[1].parse().ok();
    }
    if let Some(c) = re_avg.captures(output) {
        m.avg_ms = c[1].parse().ok();
    }
    if let Some(c) = re_slow.captures(output) {
        m.slowest_ms = c[1].parse().ok();
        m.slowest_name = Some(c[2].trim().to_owned());
    }
    if let Some(c) = re_pass.captures(output) {
        m.passed = c[1].parse().ok();
        m.total = c[2].parse().ok();
    } else if let Some(c) = re_fail.captures(output) {
        // Failed path: derive passed as total - failed.
        let failed: Option<u32> = c[1].parse().ok();
        let total: Option<u32> = c[2].parse().ok();
        m.total = total;
        m.passed = match (total, failed) {
            (Some(t), Some(f)) => Some(t.saturating_sub(f)),
            _ => None,
        };
    }
    m
}

fn parse_cache_line(stats_text: &str) -> Option<String> {
    stats_text
        .lines()
        .find(|l| l.contains("Agg cache:"))
        .map(|s| s.trim().to_owned())
}

fn parse_avg_query(stats_text: &str) -> Option<String> {
    stats_text
        .lines()
        .find(|l| l.contains("Avg query time:"))
        .map(|s| s.trim().to_owned())
}

/// Read the last `search concurrency retuned` line from the daemon log.
fn last_tune_line(log_path: &PathBuf) -> Option<String> {
    let text = std::fs::read_to_string(log_path).ok()?;
    text.lines()
        .filter(|l| l.contains("search concurrency retuned"))
        .last()
        .map(|s| s.to_owned())
}

// ── Argument parsing ─────────────────────────────────────────────────────────

#[derive(Debug)]
struct Args {
    values: Vec<usize>,
    skip_warmup: bool,
    wipe: bool,
}

fn parse_args() -> Args {
    let mut raw: Vec<String> = env::args().skip(1).collect();

    let mut skip_warmup = false;
    let mut wipe = true;

    // Extract flags in a small state machine; positional args remain in raw.
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--skip-warmup" => {
                skip_warmup = true;
                raw.remove(i);
            }
            "--no-wipe" => {
                wipe = false;
                raw.remove(i);
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            _ => i += 1,
        }
    }

    let mut values: Vec<usize> = raw.iter().filter_map(|s| s.parse().ok()).collect();
    if values.is_empty() {
        values = DEFAULT_SWEEP.to_vec();
    }

    Args {
        values,
        skip_warmup,
        wipe,
    }
}

fn print_usage() {
    println!("Usage: rust-script scripts/windows/concurrency-sweep.rs [FLAGS] [N ...]");
    println!();
    println!("Flags:");
    println!("  --skip-warmup      Skip the warm-up validation run per iteration");
    println!("  --no-wipe          Do not delete the on-disk cache dirs between runs");
    println!("  -h, --help         Print this help and exit");
    println!();
    println!("Positional args are the sweep values (default: {:?}).", DEFAULT_SWEEP);
}

// ── Rendering ────────────────────────────────────────────────────────────────

fn fmt_ms(v: Option<u64>) -> String {
    v.map_or_else(|| "   -".to_owned(), |n| format!("{:>5}", n))
}

fn print_summary(rows: &[(usize, RunMetrics, String, String)]) {
    println!();
    println!("{}", "═══════════════════ SUMMARY ═══════════════════".yellow().bold());
    println!(
        "{:>4}  {:>7}  {:>7}  {:>7}  {:>7}  {:>7}  {}",
        "N".bold(),
        "wall".bold(),
        "sum".bold(),
        "avg".bold(),
        "slow".bold(),
        "pass".bold(),
        "cache".bold(),
    );
    println!("{}", "─".repeat(85));
    for (n, m, cache, _avg_q) in rows {
        let pass = match (m.passed, m.total) {
            (Some(p), Some(t)) => format!("{}/{}", p, t),
            _ => "-".to_owned(),
        };
        println!(
            "{:>4}  {}ms  {}ms  {}ms  {}ms  {:>7}  {}",
            n,
            fmt_ms(m.wall_ms),
            fmt_ms(m.sum_ms),
            fmt_ms(m.avg_ms),
            fmt_ms(m.slowest_ms),
            pass,
            cache.replace("Agg cache:", "").trim(),
        );
    }
    println!("{}", "─".repeat(85));
}

// ── Main sweep loop ──────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = parse_args();
    let repo_root = find_repo_root()?;

    let log_dir = sweep_log_dir(&repo_root);
    std::fs::create_dir_all(&log_dir).with_context(|| {
        format!(
            "failed to create sweep log directory {}",
            log_dir.display()
        )
    })?;
    let log_path = uffsd_log_path(&log_dir);

    println!("{}", "UFFS concurrency sweep".bold().cyan());
    println!("  Binary       : {}", uffs_bin().display());
    println!("  Repo root    : {}", repo_root.display());
    println!("  Sweep values : {:?}", args.values);
    println!("  Wipe caches  : {}", args.wipe);
    println!("  Skip warm-up : {}", args.skip_warmup);
    println!("  Daemon log   : {}", log_path.display());

    // Snapshot the as-found daemon + MCP state BEFORE the first kill; its Drop
    // restores the host (daemon drives + MCP) when the sweep returns, including
    // on an early `?` error.
    let _restore_guard = RunStateGuard::install();

    let mut rows: Vec<(usize, RunMetrics, String, String)> = Vec::new();

    for (idx, &n) in args.values.iter().enumerate() {
        println!();
        println!(
            "{}",
            format!(
                "═══════════════ N={n} ({}/{}) ═══════════════",
                idx + 1,
                args.values.len()
            )
            .cyan()
            .bold()
        );

        // 1. Wipe caches.
        if args.wipe {
            for p in cache_paths_to_wipe() {
                let _ = std::fs::remove_dir_all(&p);
                println!("  wiped  : {}", p.display());
            }
        } else {
            println!("  wipe   : skipped (--no-wipe)");
        }

        // 2. Kill mcp + daemon (ignore errors; may already be down).
        kill("mcp");
        kill("daemon");
        thread::sleep(Duration::from_secs(KILL_SETTLE_SECS));

        // 3. Start daemon with UFFS_SEARCH_MAX_CONCURRENCY=N.
        //    `uffs --daemon start` blocks until the daemon reports Ready
        //    (or gives up), so we just wait for the child process to
        //    return — no polling loop required.
        // Truncate the daemon log before each iteration so `last_tune_line`
        // sees only this iteration's retune record (not a stale one from
        // the previous N).
        let _ = std::fs::write(&log_path, "");
        println!("  start  : UFFS_SEARCH_MAX_CONCURRENCY={n}");
        let t0 = Instant::now();
        if let Err(err) = start_daemon(n, &log_dir) {
            println!("  {}", format!("FAILED: {err}").red());
            println!("  {} N={n}", "skipping".yellow());
            continue;
        }
        println!(
            "  {} ({:.1}s)",
            "daemon Ready".green(),
            t0.elapsed().as_secs_f64()
        );

        // 4. Confirm the env override landed in the daemon.
        if let Some(tune) = last_tune_line(&log_path) {
            println!("  tune   : {}", tune.trim().dimmed());
            let env_ok = tune.contains("source=\"env\"") && tune.contains(&format!("target={n}"));
            if !env_ok {
                println!(
                    "  {}",
                    "WARNING: tune log does not confirm env override — result may not reflect N".yellow()
                );
            }
        } else {
            println!("  {}", "tune   : (log line not found — env confirmation skipped)".yellow());
        }

        // 5. Warm-up run (populates agg cache).
        if !args.skip_warmup {
            print!("  warm-up: ");
            std::io::Write::flush(&mut std::io::stdout()).ok();
            let t0 = Instant::now();
            match run_validation(&repo_root) {
                Ok(text) => {
                    let m = parse_metrics(&text);
                    println!(
                        "done in {:.1}s (wall={}ms)",
                        t0.elapsed().as_secs_f64(),
                        m.wall_ms.map_or_else(|| "?".to_owned(), |v| v.to_string())
                    );
                }
                Err(err) => {
                    println!("{}", format!("FAILED: {err}").red());
                    continue;
                }
            }
        }

        // 6. Measured run.
        print!("  measure: ");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let t0 = Instant::now();
        let output = match run_validation(&repo_root) {
            Ok(o) => o,
            Err(err) => {
                println!("{}", format!("FAILED: {err}").red());
                continue;
            }
        };
        let metrics = parse_metrics(&output);
        println!(
            "done in {:.1}s",
            t0.elapsed().as_secs_f64()
        );

        // 7. Stats.
        let stats_text = daemon_stats_text();
        let cache = parse_cache_line(&stats_text).unwrap_or_default();
        let avg_q = parse_avg_query(&stats_text).unwrap_or_default();

        if let (Some(w), Some(a), Some(s), Some(name)) = (
            metrics.wall_ms,
            metrics.avg_ms,
            metrics.slowest_ms,
            metrics.slowest_name.as_ref(),
        ) {
            println!(
                "  result : wall={}ms  avg={}ms  slowest={}ms ({})",
                w, a, s, name
            );
        }
        if !avg_q.is_empty() {
            println!("  {}", avg_q.dimmed());
        }
        if !cache.is_empty() {
            println!("  {}", cache.dimmed());
        }

        rows.push((n, metrics, cache, avg_q));
    }

    print_summary(&rows);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_run_state;

    #[test]
    fn parses_drives_and_mcp_state() {
        let out = "\
── Daemon ──
  Status:      running (PID 62036)
    [W] G:     15,162 records
    [H] D:  7,066,038 records

── MCP HTTP Gateway ──
  Status:      not running
";
        let state = parse_run_state(out);
        assert_eq!(state.daemon_drives.as_deref(), Some(["G", "D"].map(str::to_owned).as_slice()));
        assert!(!state.mcp_running);
    }

    #[test]
    fn stopped_daemon_reads_as_none() {
        let state = parse_run_state("── Daemon ──\n  Status:      not running\n");
        assert!(state.daemon_drives.is_none());
    }
}
