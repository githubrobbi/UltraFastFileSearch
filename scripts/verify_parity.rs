#!/usr/bin/env rust-script
//! Cross-platform parity verification for UFFS (Mac + Windows).
//!
//! Two modes of operation:
//!
//! **Offline** (Mac or Windows): Reads pre-captured MFT artifacts from disk,
//! regenerates Rust output, compares against C++ golden baseline.
//!
//! **Live** (Windows, elevated): Runs both `uffs.com` (C++) and `uffs.exe`
//! (Rust) against live NTFS drives, compares outputs directly. Includes
//! retry logic for sharing violations and performance timing table.
//!
//! # Usage
//!
//! ```bash
//! # Offline: verify all drives from captured MFT data
//! rust-script scripts/verify_parity.rs ~/uffs_data --regenerate
//! rust-script scripts/verify_parity.rs ~/uffs_data --drive G --regenerate
//!
//! # Offline from bundles: drop drive_<x>.tar.zst files in a dir; each is
//! # temp-expanded, validated, then removed (no uncompressed copies kept).
//! rust-script scripts/verify_parity.rs ~/bundles --regenerate
//!
//! # Live: run both tools on Windows (elevated), auto-detect NTFS drives
//! rust-script scripts/verify_parity.rs --live
//! rust-script scripts/verify_parity.rs --live --drive C --keep
//! rust-script scripts/verify_parity.rs --live --drive C,D,F --out-dir D:\parity
//!
//! # Live + transport bundle: also capture the MFT + metafiles and pack each
//! # drive dir (MFT + metafiles + manifest + cpp/rust outputs) → drive_<x>.tar.zst
//! # for offline `--regenerate` on the Mac. Needs uffs-mft (--mft-bin or auto).
//! # (ustar+zstd, no PowerShell 2 GB Compress-Archive limit.)
//! rust-script scripts/verify_parity.rs --live --drive C --bundle
//! ```
//!
//! # Parity contract
//!
//! Three-tier comparison (first match wins):
//!
//! 1. **Strict match**: ordered full-file SHA256 identical.
//! 2. **Sorted match**: line-sorted SHA256 identical (row order differs).
//! 3. **Superset match**: filter both outputs (strip ADS + footer/header),
//!    then verify every C++ data line appears in Rust output. Extra Rust
//!    lines are hardlinks that C++ silently drops (known LIFO/name_index
//!    bug in the C++ Matcher). This matches Everything (voidtools) behavior:
//!    all hardlinks should appear in output.
//!
//! Only tier 3 failure (C++ lines missing from Rust) is a true mismatch.
//!
//! ```cargo
//! [dependencies]
//! sha2 = "0.10"
//! ```

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use std::{env, fs};

use sha2::{Digest, Sha256};

/// LCG (Linear Congruential Generator) multiplier - Knuth's MMIX constant.
const LCG_MULTIPLIER: u64 = 6_364_136_223_846_793_005;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyResult {
    StrictMatch,
    SortedMatch,
    /// Rust is a strict superset of C++ (C++ drops hardlinks due to known bug).
    /// All C++ data lines appear in Rust output after filtering ADS/footer.
    SupersetMatch,
    Mismatch,
    Skipped,
}

#[derive(Debug)]
struct DriveResult {
    drive_letter: String,
    result: VerifyResult,
    baseline_lines: usize,
    rust_lines: usize,
    /// Number of extra lines Rust has vs C++ (hardlinks C++ drops).
    extra_rust_lines: usize,
    mft_size_bytes: u64,
    parse_duration: Option<Duration>,
}

/// Result from running uffs to regenerate output
#[derive(Debug)]
struct RegenerateResult {
    output_path: PathBuf,
    parse_duration: Duration,
    mft_size_bytes: u64,
}

/// Streaming file stats computed in a single pass (no full file in memory).
#[derive(Debug)]
struct StreamingFileStats {
    /// SHA256 of lines in original order.
    ordered_hash: String,
    /// Number of lines.
    line_count: usize,
    /// Order-independent fingerprint: XOR of per-line FNV-1a hashes.
    xor_fingerprint: u64,
    /// Order-independent fingerprint: sum of per-line FNV-1a hashes (wrapping).
    sum_fingerprint: u128,
}

#[derive(Debug)]
struct UffsReleaseArtifact {
    workspace_root: PathBuf,
    cargo_target_dir: PathBuf,
    binary_path: PathBuf,
    target_dir_warning: Option<&'static str>,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // Detect mode
    let is_live = args.iter().any(|a| a == "--live");

    if is_live {
        // Live mode: run both C++ and Rust binaries, then compare
        // Works on Windows (live MFT) or any platform with pre-built binaries
        run_live_mode(&args);
        return;
    }

    // Offline mode: compare pre-captured artifacts (Mac or Windows)
    // On macOS, always rebuild the release binary before verification
    #[cfg(target_os = "macos")]
    ensure_fresh_release_build();

    if args.len() < 3 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    let base_dir = PathBuf::from(&args[1]);

    // Check if this is legacy mode (second arg is a drive letter)
    let is_legacy_mode = args.len() >= 4
        && args[2].len() == 1
        && args[2].chars().next().is_some_and(|c| c.is_ascii_alphabetic());

    if is_legacy_mode {
        // Legacy single-drive mode
        run_legacy_mode(&args, &base_dir);
    } else {
        // New multi-drive mode
        run_multi_drive_mode(&args, &base_dir);
    }
}

/// Ensure a fresh release build exists (macOS only).
///
/// Builds both `uffs` (thin CLI) and `uffsd` (daemon) explicitly.
/// A workspace-wide `cargo build --release` can sometimes skip `uffs-daemon`
/// when cargo's fingerprint cache thinks it's up-to-date (especially with
/// sccache).  Building both packages explicitly avoids stale-binary issues
/// where the CLI sends `search_cli` but the daemon doesn't recognise it.
#[cfg(target_os = "macos")]
fn ensure_fresh_release_build() {
    let workspace_root = find_workspace_root();

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  Building fresh release binaries (uffs + uffsd)...              ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("Workspace: {}", workspace_root.display());
    println!();

    let start_time = Instant::now();

    // Build both packages explicitly — workspace-wide builds can miss uffs-daemon
    // due to cargo fingerprint/sccache caching issues.
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "uffs-cli", "-p", "uffs-daemon"])
        .current_dir(&workspace_root)
        .status();

    let elapsed = start_time.elapsed();

    match status {
        Ok(s) if s.success() => {
            println!();
            println!(
                "✅ Release build completed in {}",
                format_duration(elapsed)
            );
            println!();
        }
        Ok(s) => {
            eprintln!("ERROR: cargo build --release failed with status {s}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("ERROR: Failed to run cargo build --release: {e}");
            std::process::exit(1);
        }
    }
}

/// Legacy single-drive mode for backwards compatibility
fn run_legacy_mode(args: &[String], base_dir: &Path) {
    let drive_letter = args[2].to_uppercase();
    let drive_lower = drive_letter.to_lowercase();

    // Resolve the actual drive data directory
    let drive_dir = resolve_drive_dir(base_dir, &drive_lower);

    // Parse optional arguments
    let explicit_tz = parse_tz_offset(args);
    let custom_bin = parse_bin_path(args);
    let pattern = parse_pattern(args);
    let pipeline = parse_pipeline(args);

    // Determine mode
    let mode = &args[3];
    let (rust_output, parse_duration, mft_size) = match mode.as_str() {
        "--regenerate" => {
            let golden_baseline = find_golden_baseline_file(&drive_dir, &drive_lower);
            let tz_offset =
                explicit_tz.unwrap_or_else(|| detect_tz_from_baseline(&golden_baseline));
            let regen = regenerate_rust_output(
                &drive_dir,
                &drive_letter,
                &drive_lower,
                tz_offset,
                custom_bin.as_deref(),
                &pattern,
                pipeline.as_deref(),
            );
            (regen.output_path, Some(regen.parse_duration), regen.mft_size_bytes)
        }
        "--rust" => {
            if args.len() < 5 {
                eprintln!("ERROR: --rust requires a path argument");
                print_usage(&args[0]);
                std::process::exit(1);
            }
            (PathBuf::from(&args[4]), None, 0)
        }
        _ => {
            eprintln!("ERROR: Unknown mode: {mode}");
            print_usage(&args[0]);
            std::process::exit(1);
        }
    };

    let result = verify_single_drive(base_dir, &drive_dir, &drive_letter, &rust_output, parse_duration, mft_size);

    // Everything comparison — DISABLED (2026-03-27)
    // Everything 1.4 has a 2GB IPC limit; es.exe can't export large drives.
    // Re-enable when Everything 1.5 ships with IPC memory fix.
    // try_everything_comparison(&drive_dir, &drive_letter, &rust_output);

    // Print timing for single drive if available
    if let Some(duration) = result.parse_duration {
        println!();
        println!("⏱️  MFT Parse Time: {}", format_duration(duration));
        if result.mft_size_bytes > 0 {
            #[allow(clippy::cast_precision_loss)] // File sizes don't need full u64 precision
            let mb = result.mft_size_bytes as f64 / (1024.0 * 1024.0);
            let throughput = mb / duration.as_secs_f64();
            println!("   MFT Size: {mb:.1} MB, Throughput: {throughput:.1} MB/s");
        }
    }

    std::process::exit(i32::from(result.result == VerifyResult::Mismatch));
}

/// New multi-drive discovery mode
fn run_multi_drive_mode(args: &[String], base_dir: &Path) {
    // Parse optional arguments
    let explicit_tz = parse_tz_offset(args);
    let custom_bin = parse_bin_path(args);
    let specific_drive = parse_drive_filter(args);
    let rust_output_path = parse_rust_path(args);
    let pattern = parse_pattern(args);
    let pipeline = parse_pipeline(args);
    let regenerate = args.iter().any(|a| a == "--regenerate");

    if !regenerate && rust_output_path.is_none() {
        eprintln!("ERROR: Must specify either --regenerate or --rust <path>");
        print_usage(&args[0]);
        std::process::exit(1);
    }

    if rust_output_path.is_some() && specific_drive.is_none() {
        eprintln!("ERROR: --rust mode requires --drive to specify which drive");
        print_usage(&args[0]);
        std::process::exit(1);
    }

    // Expand any drive_<x>.tar.zst transport bundles into temp drive dirs so a
    // dropped-in archive can be validated without keeping the uncompressed copy
    // around. Extracted dirs are removed again once verification finishes.
    let mut temp_dirs: Vec<PathBuf> = Vec::new();
    for (drive_lower, archive) in discover_archives(base_dir, specific_drive.as_deref()) {
        let target = base_dir.join(format!("drive_{drive_lower}"));
        if target.exists() {
            println!(
                "ℹ️  {} already exists — using it (not expanding {})",
                target.display(),
                archive.display()
            );
            continue;
        }
        print!("Expanding {} → {} ...", archive.display(), target.display());
        io::stdout().flush().ok();
        match extract_archive(&archive, &target) {
            Ok(()) => {
                println!(" ✅");
                temp_dirs.push(target);
            }
            Err(e) => println!(" ❌ {e}"),
        }
    }

    // Discover all drive directories
    let drives = discover_drives(base_dir, specific_drive.as_deref());

    if drives.is_empty() {
        eprintln!("ERROR: No drive directories found in {}", base_dir.display());
        eprintln!("  Expected directories like: drive_d, drive_e, drive_f, ...");
        eprintln!("  (or drive_<x>.tar.zst bundles to expand)");
        std::process::exit(1);
    }

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║         UFFS Multi-Drive Parity Verification                     ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("Base directory: {}", base_dir.display());
    println!("Drives found:   {} ({:?})", drives.len(), drives);
    if pattern != "*" {
        println!("Pattern:        {}", pattern);
    }
    if let Some(ref pl) = pipeline {
        println!("Pipeline:       {}", pl);
    }
    println!();

    let mut results: Vec<DriveResult> = Vec::new();

    for (index, drive_lower) in drives.iter().enumerate() {
        let drive_letter = drive_lower.to_uppercase();
        let drive_dir = base_dir.join(format!("drive_{drive_lower}"));

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!(
            "  [{}/{}] DRIVE {} - {}",
            index + 1,
            drives.len(),
            drive_letter,
            drive_dir.display()
        );
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!();

        // Check if this drive has the necessary files
        let Some(golden_baseline) = find_golden_baseline_file_optional(&drive_dir, drive_lower)
        else {
            eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
            eprintln!("  ║  ⚠️  SKIPPED: No baseline file found for drive {}             ", drive_letter);
            eprintln!("  ║     Directory: {}", drive_dir.display());
            eprintln!("  ║     Run test_runs.ps1 on Windows to collect artifacts.       ║");
            eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
            println!();
            results.push(DriveResult {
                drive_letter: drive_letter.clone(),
                result: VerifyResult::Skipped,
                baseline_lines: 0,
                rust_lines: 0,
                extra_rust_lines: 0,
                mft_size_bytes: 0,
                parse_duration: None,
            });
            continue;
        };

        // Generate or use provided rust output
        let (rust_output, parse_duration, mft_size) = if let Some(ref path) = rust_output_path {
            (PathBuf::from(path), None, 0u64)
        } else {
            let tz_offset =
                explicit_tz.unwrap_or_else(|| detect_tz_from_baseline(&golden_baseline));
            let regen = regenerate_rust_output(
                &drive_dir,
                &drive_letter,
                drive_lower,
                tz_offset,
                custom_bin.as_deref(),
                &pattern,
                pipeline.as_deref(),
            );
            (regen.output_path, Some(regen.parse_duration), regen.mft_size_bytes)
        };

        let result = verify_single_drive(base_dir, &drive_dir, &drive_letter, &rust_output, parse_duration, mft_size);

        // Everything comparison — DISABLED (2026-03-27)
        // Everything 1.4 has a 2GB IPC limit; es.exe can't export large drives.
        // Re-enable when Everything 1.5 ships with IPC memory fix.
        // try_everything_comparison(&drive_dir, &drive_letter, &rust_output);

        results.push(result);
        println!();
    }

    // Print summary
    print_summary(&results);

    // Dump the temp dirs we expanded from .tar.zst bundles.
    for temp in &temp_dirs {
        if fs::remove_dir_all(temp).is_ok() {
            println!("🧹 removed expanded {}", temp.display());
        }
    }

    // Exit with failure if any drive mismatched
    let any_mismatch = results.iter().any(|r| r.result == VerifyResult::Mismatch);
    std::process::exit(i32::from(any_mismatch));
}

// ─────────────────────────────────────────────────────────────────────────────
// Live mode: run Rust (cold disk) then C++ (warm cache), then compare outputs
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum retries for transient sharing-violation errors (Windows MFT access)
const LIVE_MAX_RETRIES: u32 = 3;
/// Delay between retries in milliseconds
const LIVE_RETRY_DELAY_MS: u64 = 3000;

/// Result from a live scan of a single drive
#[derive(Debug)]
struct LiveDriveResult {
    drive_letter: String,
    result: VerifyResult,
    baseline_lines: usize,
    rust_lines: usize,
    extra_rust_lines: usize,
    cpp_time: Duration,
    rust_time: Duration,
}

/// Run live parity checks: execute both C++ and Rust binaries, then compare
fn run_live_mode(args: &[String]) {
    let cpp_bin = parse_live_arg(args, "--cpp-bin")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // Auto-detect: look for uffs.com in standard locations
            let mut candidates = vec![
                PathBuf::from("uffs.com"),
                find_workspace_root().join("bin").join("uffs.com"),
            ];
            // $USERPROFILE\bin\uffs.com (standard deploy location on Windows)
            if let Ok(home) = env::var("USERPROFILE") {
                candidates.push(PathBuf::from(home).join("bin").join("uffs.com"));
            }
            if let Ok(home) = env::var("HOME") {
                candidates.push(PathBuf::from(home).join("bin").join("uffs.com"));
            }
            candidates
                .iter()
                .find(|p| p.exists())
                .cloned()
                .unwrap_or_else(|| {
                    eprintln!("ERROR: Cannot find uffs.com (C++ binary). Use --cpp-bin <path>");
                    std::process::exit(1);
                })
        });

    let rust_bin = parse_live_arg(args, "--bin")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // Auto-detect: $USERPROFILE\bin\uffs.exe first, then workspace release
            let home_candidates: Vec<PathBuf> = ["USERPROFILE", "HOME"]
                .iter()
                .filter_map(|var| env::var(var).ok())
                .map(|h| PathBuf::from(h).join("bin").join(uffs_binary_name()))
                .filter(|p| p.exists())
                .collect();
            if let Some(p) = home_candidates.into_iter().next() {
                return p;
            }
            let artifact = find_workspace_release_artifact();
            artifact.binary_path
        });

    // Everything CLI (es.exe) — gold-standard reference
    let es_bin: Option<PathBuf> = parse_live_arg(args, "--es-bin")
        .map(PathBuf::from)
        .or_else(|| find_es_exe());

    // Explicit --out-dir wins; otherwise land under the shared bench tree's
    // `parity/` namespace (NOT the cwd — keeps parity artifacts off scattered
    // working dirs and beside the rest of the bench output).
    let out_dir = parse_live_arg(args, "--out-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| shared_bench_root().join("parity"));

    let pattern = parse_pattern(args);
    let pipeline = parse_pipeline(args);
    let keep_files = args.iter().any(|a| a == "--keep");
    let name_only = args.iter().any(|a| a == "--name-only");

    // --bundle: after each live compare, capture the MFT + metafiles and zip
    // the drive dir (MFT + metafiles + manifest + cpp/rust outputs) for offline
    // transport. Needs the uffs-mft binary (--mft-bin or auto-detected).
    let bundle = args.iter().any(|a| a == "--bundle");
    let mft_bin: Option<PathBuf> = parse_live_arg(args, "--mft-bin")
        .map(PathBuf::from)
        .or_else(find_uffs_mft_bin);
    if bundle {
        match mft_bin {
            Some(ref p) => println!("  Bundle:      ON — uffs-mft: {}", p.display()),
            None => println!("  Bundle:      ON — ⚠️  uffs-mft not found (use --mft-bin <path>)"),
        }
    }

    // Determine drives
    let drives: Vec<String> = if let Some(d) = parse_drive_filter(args) {
        vec![d.to_uppercase()]
    } else {
        detect_ntfs_drives()
    };

    if drives.is_empty() {
        eprintln!("ERROR: No NTFS drives detected. Use --drive <letter>");
        std::process::exit(1);
    }

    // Ensure output directory exists
    fs::create_dir_all(&out_dir).unwrap_or_else(|e| {
        eprintln!("ERROR: Cannot create output dir {}: {e}", out_dir.display());
        std::process::exit(1);
    });

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║          UFFS Live Parity Verification                           ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  C++ binary:  {}", cpp_bin.display());
    println!("  Rust binary: {}", rust_bin.display());
    println!(
        "  Everything:  {} (pre-captured data or IPC fallback)",
        es_bin
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(not found)".into())
    );
    println!("  Output dir:  {}", out_dir.display());
    println!("  Pattern:     {}", pattern);
    println!("  Pipeline:    {}", pipeline.as_deref().unwrap_or("(default)"));
    println!("  Drives:      {:?}", drives);
    println!();

    let mut results: Vec<LiveDriveResult> = Vec::new();

    for (i, drive) in drives.iter().enumerate() {
        let result = run_live_drive_parity(
            drive,
            &pattern,
            name_only,
            &cpp_bin,
            &rust_bin,
            es_bin.as_deref(),
            &out_dir,
            keep_files,
            bundle,
            mft_bin.as_deref(),
            pipeline.as_deref(),
            i + 1,
            drives.len(),
        );
        results.push(result);
    }

    // Print summary with timing table
    print_live_summary(&results);

    let any_mismatch = results.iter().any(|r| r.result == VerifyResult::Mismatch);
    std::process::exit(i32::from(any_mismatch));
}

/// Run a binary with retry logic for transient Windows sharing violations.
/// Captures stdout to `output_file`, returns Ok on success.
fn run_with_retry(
    bin: &Path,
    args: &[&str],
    output_file: &Path,
    label: &str,
) -> Result<(), String> {
    for attempt in 0..LIVE_MAX_RETRIES {
        let output = Command::new(bin)
            .args(args)
            .stdout(
                fs::File::create(output_file)
                    .map_err(|e| format!("Cannot create {}: {e}", output_file.display()))?,
            )
            .stderr(std::process::Stdio::piped())
            .output();

        match output {
            Ok(out) if out.status.success() => return Ok(()),
            Ok(out) => {
                let code = out.status.code().unwrap_or(-1);
                let stderr_msg = String::from_utf8_lossy(&out.stderr);
                let is_sharing_violation = stderr_msg.contains("sharing violation")
                    || stderr_msg.contains("access denied")
                    || stderr_msg.contains("Access is denied")
                    || code == 32; // ERROR_SHARING_VIOLATION

                if is_sharing_violation && attempt + 1 < LIVE_MAX_RETRIES {
                    eprintln!(
                        "  ⚠️  {} failed (sharing violation), retry {}/{}...",
                        label,
                        attempt + 2,
                        LIVE_MAX_RETRIES
                    );
                    std::thread::sleep(Duration::from_millis(LIVE_RETRY_DELAY_MS));
                    continue;
                }

                let mut msg = format!("exit code {code}");
                if !stderr_msg.is_empty() {
                    msg.push_str(&format!(" — {}", stderr_msg.trim()));
                }
                return Err(msg);
            }
            Err(e) => return Err(format!("failed to execute {}: {e}", bin.display())),
        }
    }
    Err("max retries exceeded".into())
}

/// Run live parity check for a single drive
#[allow(clippy::too_many_arguments)]
fn run_live_drive_parity(
    drive: &str,
    pattern: &str,
    name_only: bool,
    cpp_bin: &Path,
    rust_bin: &Path,
    es_bin: Option<&Path>,
    out_dir: &Path,
    keep_files: bool,
    bundle: bool,
    mft_bin: Option<&Path>,
    pipeline: Option<&str>,
    drive_index: usize,
    total_drives: usize,
) -> LiveDriveResult {
    let drive_upper = drive.to_uppercase();
    let drive_lower = drive.to_lowercase();

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(
        "  [{}/{}] DRIVE {} — Live MFT Scan",
        drive_index, total_drives, drive_upper
    );
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    // Create drive subdirectory
    let drive_dir = out_dir.join(format!("drive_{drive_lower}"));
    fs::create_dir_all(&drive_dir).unwrap_or_else(|e| {
        eprintln!("ERROR: Cannot create {}: {e}", drive_dir.display());
        std::process::exit(1);
    });

    let cpp_raw = drive_dir.join(format!("cpp_{drive_lower}.txt"));
    let rust_raw = drive_dir.join(format!("rust_{drive_lower}.txt"));
    let es_raw_path = drive_dir.join(format!("es_{drive_lower}.txt"));

    println!("  Drive dir:     {}", drive_dir.display());
    println!("  C++ output:    {}", cpp_raw.display());
    println!("  Rust output:   {}", rust_raw.display());
    if es_bin.is_some() {
        println!("  Everything:    {}", es_raw_path.display());
    }
    println!();

    let skipped = |_msg: &str, cpp_ms, rust_ms| LiveDriveResult {
        drive_letter: drive_upper.clone(),
        result: VerifyResult::Skipped,
        baseline_lines: 0,
        rust_lines: 0,
        extra_rust_lines: 0,
        cpp_time: cpp_ms,
        rust_time: rust_ms,
    };

    // 1. VERY COLD start: kill daemon + delete all cache files before Rust run.
    //    Without this the daemon may serve in-memory results from a previous
    //    drive or session, and --no-cache only skips the MFT cache file — it
    //    doesn't prevent the daemon from using its hot in-memory index.
    print!("  [1/5] Purging daemon + cache for cold Rust run...");
    io::stdout().flush().ok();
    let _ = Command::new(rust_bin)
        .args(["--daemon", "kill"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
    std::thread::sleep(Duration::from_secs(1));
    // Delete compact cache files.
    if let Ok(local) = env::var("LOCALAPPDATA") {
        let cache_dir = PathBuf::from(&local).join("uffs").join("cache");
        if cache_dir.exists() {
            let _ = fs::remove_dir_all(&cache_dir);
        }
    }
    if let Ok(tmp) = env::var("TEMP") {
        let legacy = PathBuf::from(&tmp).join("uffs_index_cache");
        if legacy.exists() {
            let _ = fs::remove_dir_all(&legacy);
        }
    }
    println!(" ✅");

    // 2. Explicit single-drive daemon start.
    //    The search CLI's autospawn path already forwards `--drive <L>` via
    //    `extract_spawn_args`, so in practice the daemon only loads the
    //    requested drive.  But we want the single-drive invariant pinned
    //    explicitly — matching what C++ (`uffs.com`) does on every run —
    //    so a future regression in `extract_spawn_args` (e.g. a forgotten
    //    flag) can never silently widen the measurement to "all NTFS
    //    drives".  `uffs --daemon start` blocks until the drive's MFT is
    //    fully indexed (await_ready, 2 min timeout).
    //
    //    We start timing *before* `daemon start` so `rust_elapsed` captures
    //    the full cold-start cost (daemon spawn + MFT load + search),
    //    matching C++ end-to-end semantics.
    print!("  [2/5] Starting daemon with --drive {drive_upper} only...");
    io::stdout().flush().ok();
    let rust_start = Instant::now();
    let daemon_start_output = Command::new(rust_bin)
        .args(["--daemon", "start", "--drive", &drive_upper, "--no-cache"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output();
    match daemon_start_output {
        Ok(out) if out.status.success() => println!(" ✅"),
        Ok(out) => {
            let stderr_msg = String::from_utf8_lossy(&out.stderr);
            let msg = format!(
                "daemon start --drive {drive_upper} failed (exit {}): {}",
                out.status.code().unwrap_or(-1),
                stderr_msg.trim()
            );
            println!(" ❌ SKIPPED — {msg}");
            return skipped(&msg, Duration::ZERO, rust_start.elapsed());
        }
        Err(e) => {
            let msg = format!("daemon start --drive {drive_upper} failed to execute: {e}");
            println!(" ❌ SKIPPED — {msg}");
            return skipped(&msg, Duration::ZERO, rust_start.elapsed());
        }
    }

    // 3. Run Rust search against the single-drive daemon just spawned.
    print!("  [3/5] Running Rust search (cold MFT, single drive)...");
    io::stdout().flush().ok();
    let drive_arg = drive_upper.clone();
    let mut rust_args: Vec<&str> = vec![
        pattern,
        "--drive",
        &drive_arg,
        "--no-cache",
        "--format",
        "custom",
        "--parity-compat",
    ];
    if name_only {
        rust_args.push("--name-only");
    }
    // NOTE: --pipeline flag removed from uffs binary (Step 4: legacy pipeline
    // eliminated).  The `pipeline` parameter is accepted for CLI compat but
    // no longer forwarded.
    let _ = pipeline;
    let rust_result = run_with_retry(rust_bin, &rust_args, &rust_raw, "Rust");
    let rust_elapsed = rust_start.elapsed();
    match rust_result {
        Ok(()) => println!(" ✅ ({})", format_duration(rust_elapsed)),
        Err(msg) => {
            println!(" ❌ SKIPPED — {msg}");
            return skipped(&msg, Duration::ZERO, rust_elapsed);
        }
    }

    // Kill daemon after Rust run — next drive must also start cold.
    let _ = Command::new(rust_bin)
        .args(["--daemon", "kill"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();

    // 4. Run C++ (warm-disk read — MFT already in OS cache from Rust)
    print!("  [4/5] Running C++ scan (warm)...");
    io::stdout().flush().ok();
    let cpp_start = Instant::now();
    let cpp_drives_arg = format!("--drives={drive_upper}");
    let cpp_result = run_with_retry(cpp_bin, &[pattern, &cpp_drives_arg], &cpp_raw, "C++");
    let cpp_elapsed = cpp_start.elapsed();
    match cpp_result {
        Ok(()) => println!(" ✅ ({})", format_duration(cpp_elapsed)),
        Err(msg) => {
            println!(" ❌ SKIPPED — {msg}");
            return skipped(&msg, cpp_elapsed, rust_elapsed);
        }
    }

    // 3. Everything — DISABLED (2026-03-27)
    // Everything 1.4 has a 2GB IPC memory limit that prevents es.exe from
    // exporting data on drives with >2M entries. Both -export-efu and CSV
    // stdout hit this wall (even path-only output OOMs on 4.7M files).
    // Everything can INDEX the MFT fine — the limit is purely in the IPC
    // data transfer between Everything.exe and es.exe.
    // Benchmark timing (start → index ready) is still available via benchmark.ps1.
    // Re-enable when Everything 1.5 ships with the IPC memory fix.
    // See: https://www.voidtools.com/forum/viewtopic.php?t=15249
    //
    // let es_collected = if let Some(es) = es_bin {
    //     run_everything_live_collect(es, &drive_upper, &es_raw_path)
    // } else {
    //     println!("  [3/4] Everything: skipped (es.exe not found)");
    //     false
    // };
    println!("  Everything: disabled (es.exe 2GB IPC limit — see benchmark.ps1 for timing)");

    // 5. Compare using the same streaming comparison as offline mode
    let step = "5/5";
    println!("  [{}] Comparing outputs...", step);
    println!();

    let golden_stats = compute_streaming_stats(&cpp_raw);
    let rust_stats = compute_streaming_stats(&rust_raw);

    println!(
        "  C++ output:  {} ({} lines)",
        golden_stats.ordered_hash, golden_stats.line_count
    );
    println!(
        "  Rust output: {} ({} lines)",
        rust_stats.ordered_hash, rust_stats.line_count
    );
    println!();

    // Determine C++ vs Rust parity result
    let parity_result = if golden_stats.ordered_hash == rust_stats.ordered_hash {
        println!("  ✅ STRICT MATCH — Ordered outputs identical");
        (VerifyResult::StrictMatch, 0usize)
    } else if is_sorted_match(&golden_stats, &rust_stats) {
        println!("  ✅ SORTED MATCH — Content identical (different traversal order)");
        (VerifyResult::SortedMatch, 0usize)
    } else {
        // Streaming comparison — no filtering except header/footer
        println!("  Fingerprints differ; running streaming line comparison...");
        let t_diff = Instant::now();
        let mut diff = compute_streaming_diff(&cpp_raw, &rust_raw);
        // LIVE MODE: the C++ (warm) and Rust (cold) reads happen seconds apart
        // on a mutating volume, so reconcile differences that are read-time
        // skew (accessed-time, directory subtree aggregates, NTFS-volatile
        // paths) rather than parser disagreements. Offline (frozen capture)
        // never does this, so real parser bugs still surface.
        let (tolerated, skew_samples) = reconcile_live_skew(&mut diff);
        let diff_elapsed = t_diff.elapsed();

        println!();
        println!(
            "  Streaming diff: {:.1}s",
            diff_elapsed.as_secs_f64()
        );
        println!("     Only in C++:  {}", diff.only_in_baseline.len());
        println!("     Only in Rust: {}", diff.only_in_rust.len());
        if tolerated > 0 {
            println!();
            println!(
                "  ⏱️  Tolerated {tolerated} live-read-skew diff(s) \
                 (NTFS volatile: accessed-time / dir-aggregate / churning paths):"
            );
            for (path, reason) in &skew_samples {
                println!("       {path}  [{reason}]");
            }
            if tolerated > skew_samples.len() {
                println!("       … and {} more", tolerated - skew_samples.len());
            }
        }

        if diff.only_in_baseline.is_empty() {
            let extra = diff.only_in_rust.len();
            println!();
            if tolerated > 0 {
                println!(
                    "  ✅ SUPERSET MATCH (Rust ⊇ C++) — after tolerating {tolerated} live-read-skew diff(s)"
                );
            } else {
                println!("  ✅ SUPERSET MATCH (Rust ⊇ C++)");
            }
            println!("     Extra Rust lines: {extra}");

            if !diff.only_in_rust.is_empty() {
                verify_hardlinks_from_file(&cpp_raw, &diff.only_in_rust);
            }
            (VerifyResult::SupersetMatch, extra)
        } else {
            println!();
            println!("  ❌ MISMATCH");
            println!(
                "     C++ has {} lines not in Rust, Rust has {} lines not in C++",
                diff.only_in_baseline.len(),
                diff.only_in_rust.len()
            );
            if !diff.only_in_baseline.is_empty() {
                println!();
                println!("  ── Lines MISSING from Rust ({} total) ──",
                    diff.only_in_baseline.len());
                show_diff_lines(&diff.only_in_baseline);
            }
            if !diff.only_in_rust.is_empty() {
                println!();
                println!("  ── Extra lines in Rust ({} total) ──",
                    diff.only_in_rust.len());
                show_diff_lines(&diff.only_in_rust);
            }
            if !diff.only_in_baseline.is_empty() && !diff.only_in_rust.is_empty() {
                println!();
                show_paired_diffs(&diff.only_in_baseline, &diff.only_in_rust);
            }
            (VerifyResult::Mismatch, diff.only_in_rust.len())
        }
    };

    // Everything comparison — DISABLED (2026-03-27)
    // Everything 1.4 has a 2GB IPC limit; es.exe can't export large drives.
    // Re-enable when Everything 1.5 ships with IPC memory fix.
    // if es_raw_path.exists() {
    //     println!();
    //     compare_with_everything(&es_raw_path, &rust_raw, &drive_upper);
    // }

    // Build the offline transport bundle (capture MFT + metafiles into the same
    // drive dir, then zip it with the cpp/rust outputs). Bundling implies keep.
    if bundle {
        create_transport_bundle(&drive_upper, &drive_lower, out_dir, mft_bin);
    }

    cleanup_live_files(keep_files || bundle, &[&cpp_raw, &rust_raw, &es_raw_path]);

    LiveDriveResult {
        drive_letter: drive_upper,
        result: parity_result.0,
        baseline_lines: golden_stats.line_count,
        rust_lines: rust_stats.line_count,
        extra_rust_lines: parity_result.1,
        cpp_time: cpp_elapsed,
        rust_time: rust_elapsed,
    }
}

/// Auto-detect the `uffs-mft` binary (MFT capture tool).
///
/// Looks in `$USERPROFILE\bin` / `$HOME/bin` first (the standard deploy
/// location), then the workspace `target/release`.
fn find_uffs_mft_bin() -> Option<PathBuf> {
    let name = if cfg!(windows) { "uffs-mft.exe" } else { "uffs-mft" };
    for var in ["USERPROFILE", "HOME"] {
        if let Ok(home) = env::var(var) {
            let candidate = PathBuf::from(home).join("bin").join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    let workspace = find_workspace_root().join("target").join("release").join(name);
    workspace.exists().then_some(workspace)
}

/// Capture the MFT + metafiles into the drive dir and pack it for transport.
///
/// A single `uffs-mft capture --out <out_dir> --zip` writes into
/// `<out_dir>/drive_<x>/` — the same dir the live cpp/rust outputs already live
/// in — then packs the whole dir into `<out_dir>/drive_<x>.tar.zst`. That
/// bundler is ustar + zstd, so unlike PowerShell `Compress-Archive` (which
/// silently fails past ~2 GB — e.g. a large drive's `<DRIVE>_mft.bin`) it has no
/// size limit. On the Mac: `tar --zstd -xf drive_<x>.tar.zst`, then
/// `verify_parity.rs <dir> --regenerate`.
fn create_transport_bundle(
    drive_upper: &str,
    drive_lower: &str,
    out_dir: &Path,
    mft_bin: Option<&Path>,
) {
    println!();
    println!("  [bundle] Building transport bundle for drive {drive_upper}...");

    let Some(mft_bin) = mft_bin else {
        println!("  [bundle] ⚠️  skipped: uffs-mft binary not found (pass --mft-bin <path>)");
        return;
    };

    // Capture MFT + metafiles alongside the cpp/rust outputs, then --zip packs
    // the whole drive dir into drive_<x>.tar.zst.
    print!("  [bundle] uffs-mft capture --drive {drive_upper} --zip...");
    io::stdout().flush().ok();
    let capture = Command::new(mft_bin)
        .args([
            "capture",
            "--drive",
            drive_upper,
            "--out",
            &out_dir.to_string_lossy(),
            "--zip",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output();
    match capture {
        Ok(out) if out.status.success() => println!(" ✅"),
        Ok(out) => println!(
            " ⚠️  exited {}: {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => {
            println!(" ❌ failed to run: {e}");
            return;
        }
    }

    // Verify the archive actually landed (never trust exit code alone).
    let archive = out_dir.join(format!("drive_{drive_lower}.tar.zst"));
    match fs::metadata(&archive) {
        Ok(meta) if meta.len() > 0 => {
            #[allow(clippy::cast_precision_loss)] // display only
            let mb = meta.len() as f64 / (1024.0 * 1024.0);
            println!("  [bundle] ✅ {} ({mb:.1} MB)", archive.display());
        }
        _ => println!(
            "  [bundle] ❌ archive not produced: {}",
            archive.display()
        ),
    }
}

/// Auto-detect es.exe (Everything CLI) on the system.
fn find_es_exe() -> Option<PathBuf> {
    // Check PATH first
    if let Ok(output) = Command::new("where").arg("es.exe").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                let p = PathBuf::from(path.lines().next().unwrap_or(""));
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }

    // Check common install locations
    let candidates = [
        "es.exe",
        "C:\\Program Files\\Everything\\es.exe",
        "C:\\Program Files (x86)\\Everything\\es.exe",
    ];
    for c in &candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Auto-detect Everything.exe on the system.
#[allow(dead_code)]
fn find_everything_exe() -> Option<PathBuf> {
    let candidates = [
        "C:\\Program Files\\Everything\\Everything.exe",
        "C:\\Program Files (x86)\\Everything\\Everything.exe",
    ];
    // Also check user bin dir
    let home_bin = env::var("USERPROFILE")
        .ok()
        .map(|h| PathBuf::from(h).join("bin").join("Everything.exe"));

    for c in &candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    if let Some(ref hb) = home_bin {
        if hb.exists() {
            return Some(hb.clone());
        }
    }
    None
}

/// Find the Everything APPDATA ini path.
#[allow(dead_code)]
fn find_everything_ini() -> Option<PathBuf> {
    env::var("APPDATA").ok().map(|appdata| {
        PathBuf::from(appdata).join("Everything").join("Everything.ini")
    }).filter(|p| p.exists())
}

// ── BEGIN DISABLED EVERYTHING LIVE COLLECTION (2026-03-27) ──
// Everything 1.4 has a 2GB IPC memory limit that prevents es.exe from
// exporting data on drives with >2M entries. Both -export-efu and CSV
// stdout hit this wall (even path-only output OOMs on 4.7M files).
// Everything can INDEX the MFT fine — the limit is purely in the IPC
// data transfer between Everything.exe and es.exe.
// Re-enable when Everything 1.5 ships with the IPC memory fix.
// See: https://www.voidtools.com/forum/viewtopic.php?t=15249

/// Live-collect Everything data for a single drive using ini-editing approach.
///
/// Flow:
/// 1. Stop any running Everything
/// 2. Backup ini
/// 3. Edit ini: enable only target drive, enable all index fields
/// 4. Start Everything (indexes only target drive MFT)
/// 5. Poll es.exe until index is ready
/// 6. Query with es.exe (all columns) → output file
/// 7. Stop Everything
/// 8. Restore ini from backup
///
/// Returns true if data was collected successfully.
#[allow(dead_code)]
fn run_everything_live_collect(es_exe: &Path, drive_upper: &str, output_path: &Path) -> bool {
    let everything_exe = match find_everything_exe() {
        Some(p) => p,
        None => {
            println!("  [3/4] Everything: skipped (Everything.exe not found)");
            return false;
        }
    };
    let ini_path = match find_everything_ini() {
        Some(p) => p,
        None => {
            println!("  [3/4] Everything: skipped (Everything.ini not found in %APPDATA%)");
            return false;
        }
    };

    println!("  [3/4] Everything: configuring for {drive_upper}: only...");

    // 1. Stop any running Everything
    kill_everything_processes();
    std::thread::sleep(Duration::from_secs(2));

    // 2. Backup ini
    let ini_bak = ini_path.with_extension("ini.uffs_bak");
    if !ini_bak.exists() {
        if let Err(e) = fs::copy(&ini_path, &ini_bak) {
            println!("  [3/4] Everything: failed to backup ini: {e}");
            return false;
        }
    }

    // 3. Edit ini: enable only target drive
    let success = edit_everything_ini(&ini_path, drive_upper);
    if !success {
        restore_everything_ini(&ini_path, &ini_bak);
        return false;
    }

    // 4. Start Everything
    println!("  [3/4] Everything: starting (MFT index of {drive_upper}: only)...");
    let start_result = Command::new(&everything_exe)
        .args(["-startup", "-minimized"])
        .spawn();
    if let Err(e) = start_result {
        println!("  [3/4] Everything: failed to start: {e}");
        restore_everything_ini(&ini_path, &ini_bak);
        return false;
    }

    // 5. Poll for readiness (up to 120s for large drives)
    let mut ready = false;
    for attempt in 1..=60 {
        std::thread::sleep(Duration::from_secs(2));
        if let Ok(output) = Command::new(es_exe).arg("-get-result-count").output() {
            if output.status.success() {
                let count_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if let Ok(count) = count_str.parse::<u64>() {
                    if count > 0 {
                        println!(
                            "  [3/4] Everything: indexed {} entries ({}s)",
                            count,
                            attempt * 2
                        );
                        ready = true;
                        break;
                    }
                }
            }
        }
    }

    let collected = if ready {
        // 6. Export via EFU (avoids 2GB IPC stdout limit on Everything 1.4)
        print!("  [3/4] Everything: exporting {drive_upper}: ...");
        io::stdout().flush().ok();
        let es_start = Instant::now();
        let es_path_arg = format!("{drive_upper}:\\");
        let output_str = output_path.to_string_lossy().to_string();
        let es_result = Command::new(es_exe)
            .args([
                "-path", &es_path_arg,
                "-sort", "path",
                "-export-efu", &output_str,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let es_elapsed = es_start.elapsed();
        match es_result {
            Ok(status) if status.success() && output_path.exists() => {
                println!(" ✅ ({})", format_duration(es_elapsed));
                true
            }
            Ok(status) => {
                println!(" ❌ (exit: {:?})", status.code());
                // Fallback: path + size + attributes (~150B/entry, under 2GB IPC limit)
                println!("  [3/4] Everything: retrying with path+size+attributes...");
                let lite_result = run_with_retry(
                    es_exe,
                    &[
                        "-path", &es_path_arg,
                        "-sort", "path",
                        "-name", "-path-column", "-size", "-attributes",
                        "-no-digit-grouping", "-csv",
                    ],
                    output_path,
                    "Everything lite",
                );
                match lite_result {
                    Ok(()) => { println!("       ✅ lite fallback succeeded"); true }
                    Err(msg) => { println!("       ❌ lite fallback: {msg}"); false }
                }
            }
            Err(e) => {
                println!(" ❌ {e}");
                false
            }
        }
    } else {
        println!("  [3/4] Everything: indexing timed out (120s) — skipping");
        false
    };

    // 7. Stop Everything
    kill_everything_processes();
    std::thread::sleep(Duration::from_secs(1));

    // 8. Restore ini
    restore_everything_ini(&ini_path, &ini_bak);

    collected
}

/// Kill all running Everything.exe processes.
#[allow(dead_code)]
fn kill_everything_processes() {
    // Use taskkill on Windows
    let _ = Command::new("taskkill")
        .args(["/F", "/IM", "Everything.exe"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Edit Everything.ini to enable only the target drive with all index fields.
#[allow(dead_code)]
fn edit_everything_ini(ini_path: &Path, target_drive: &str) -> bool {
    let content = match fs::read_to_string(ini_path) {
        Ok(c) => c,
        Err(e) => {
            println!("  Everything: failed to read ini: {e}");
            return false;
        }
    };

    // Find ntfs_volume_paths to determine the drive's position
    let vol_paths_line = content.lines().find(|l| l.starts_with("ntfs_volume_paths="));
    let vol_paths_line = match vol_paths_line {
        Some(l) => l,
        None => {
            println!("  Everything: ntfs_volume_paths not found in ini");
            return false;
        }
    };

    let paths_str = &vol_paths_line["ntfs_volume_paths=".len()..];
    let volumes: Vec<&str> = paths_str.split(',').map(|s| s.trim().trim_matches('"')).collect();
    let target_with_colon = format!("{target_drive}:");

    let drive_idx = volumes.iter().position(|v| v.eq_ignore_ascii_case(&target_with_colon));
    let drive_idx = match drive_idx {
        Some(i) => i,
        None => {
            println!("  Everything: drive {target_drive}: not found in ntfs_volume_paths");
            return false;
        }
    };

    // Build includes string: 0 for all except target
    let includes: String = (0..volumes.len())
        .map(|i| if i == drive_idx { "1" } else { "0" })
        .collect::<Vec<_>>()
        .join(",");

    // Apply replacements
    let mut result = content.clone();
    let includes_line = format!("ntfs_volume_includes={includes}");
    let replacements: Vec<(&str, &str)> = vec![
        ("ntfs_volume_includes=", &includes_line),
        ("auto_include_fixed_volumes=", "auto_include_fixed_volumes=0"),
        ("auto_include_removable_volumes=", "auto_include_removable_volumes=0"),
        ("index_date_created=", "index_date_created=1"),
        ("index_date_accessed=", "index_date_accessed=1"),
        ("index_date_modified=", "index_date_modified=1"),
        ("index_attributes=", "index_attributes=1"),
        ("index_size=", "index_size=1"),
    ];

    for (prefix, replacement) in &replacements {
        if let Some(line_start) = result.find(prefix) {
            let line_end = result[line_start..].find('\n')
                .map(|i| line_start + i)
                .unwrap_or(result.len());
            // Handle \r\n
            let line_end_trim = if line_end > 0 && result.as_bytes().get(line_end - 1) == Some(&b'\r') {
                line_end - 1
            } else {
                line_end
            };
            result.replace_range(line_start..line_end_trim, replacement);
        }
    }

    match fs::write(ini_path, &result) {
        Ok(()) => true,
        Err(e) => {
            println!("  Everything: failed to write ini: {e}");
            false
        }
    }
}

/// Restore Everything.ini from backup.
#[allow(dead_code)]
fn restore_everything_ini(ini_path: &Path, backup_path: &Path) {
    if backup_path.exists() {
        if let Err(e) = fs::copy(backup_path, ini_path) {
            eprintln!("  ⚠️  Everything: failed to restore ini: {e}");
        } else {
            let _ = fs::remove_file(backup_path);
            println!("  [3/4] Everything: ini restored from backup");
        }
    }
}
// ── END DISABLED EVERYTHING LIVE COLLECTION ──


/// Verify extra Rust lines are hardlinks using fingerprints from a baseline file.
/// Streams the baseline file to build fingerprints, then checks extras.
fn verify_hardlinks_from_file(baseline_path: &Path, only_in_rust: &[String]) {
    let common_fingerprints: HashSet<String> = {
        let file = fs::File::open(baseline_path).unwrap_or_else(|e| {
            panic!("Failed to open {}: {e}", baseline_path.display())
        });
        let reader = BufReader::with_capacity(256 * 1024, file);
        reader
            .lines()
            .filter_map(|line| {
                let line = line.unwrap_or_else(|e| panic!("Read error: {e}"));
                if is_footer_or_header_line(&line) {
                    return None;
                }
                extract_data_fingerprint(&line)
            })
            .collect()
    };
    let mut extra_fps: HashMap<String, usize> = HashMap::new();
    for line in only_in_rust {
        if let Some(fp) = extract_data_fingerprint(line) {
            *extra_fps.entry(fp).or_insert(0) += 1;
        }
    }
    let verified = only_in_rust
        .iter()
        .filter(|line| {
            extract_data_fingerprint(line).is_some_and(|fp| {
                common_fingerprints.contains(&fp)
                    || extra_fps.get(&fp).copied().unwrap_or(0) > 1
            })
        })
        .count();
    let unverified = only_in_rust.len() - verified;
    println!(
        "     Hardlink verification: {} verified, {} unverified",
        verified, unverified
    );
    if unverified > 0 {
        println!("     ⚠️  {} unverified extras — investigate!", unverified);
    }
}

/// Everything file record (parsed from EFU or es.exe CSV).
#[allow(dead_code)]
#[derive(Debug)]
struct EverythingRecord {
    /// File size in bytes.
    size: String,
    /// Date Modified (FILETIME i64 or formatted string).
    date_modified: String,
    /// Date Created (FILETIME i64 or formatted string).
    date_created: String,
    /// Raw NTFS attributes value.
    attributes: String,
}

/// Rust parity record (parsed from parity-compat CSV).
#[allow(dead_code)]
#[derive(Debug)]
struct RustParityRecord {
    /// File size in bytes (column index 3).
    size: String,
    /// Created timestamp (column index 5).
    created: String,
    /// Modified/Written timestamp (column index 6).
    modified: String,
    /// Raw attributes value (last numeric column).
    attributes: String,
}

/// Compare Rust output against Everything output — field by field.
///
/// Everything is the gold standard for MFT-based file enumeration.
/// EFU format: `Filename,Size,Date Modified,Date Created,Attributes`
/// Rust parity-compat: `"Path","Name","PathOnly","Size","SizeOnDisk","Created","Modified","Accessed",...`
///
/// Comparison levels:
/// 1. Path coverage (what's missing, what's extra)
/// 2. Size match for common paths
/// 3. Created/Modified timestamp match
/// 4. Attributes match
#[allow(dead_code)]
fn compare_with_everything(es_file: &Path, rust_file: &Path, _drive: &str) {
    println!("  ── Everything vs Rust — field-by-field comparison ──");
    println!();

    // 1. Load Everything records keyed by normalized path
    let t_es = Instant::now();
    let es_records = stream_everything_records(es_file);
    let es_elapsed = t_es.elapsed();
    println!(
        "  Everything: {} entries ({:.1}s)",
        es_records.len(),
        es_elapsed.as_secs_f64()
    );

    // 2. Load Rust records keyed by normalized path
    let t_rust = Instant::now();
    let rust_records = stream_rust_records(rust_file);
    let rust_elapsed = t_rust.elapsed();
    println!(
        "  Rust:       {} entries ({:.1}s)",
        rust_records.len(),
        rust_elapsed.as_secs_f64()
    );

    // 3. Path-level comparison
    let only_in_es: Vec<&String> = es_records.keys().filter(|p| !rust_records.contains_key(*p)).collect();
    let only_in_rust: Vec<&String> = rust_records.keys().filter(|p| !es_records.contains_key(*p)).collect();
    let common_count = es_records.len() - only_in_es.len();

    println!();
    println!("  ┌─────────────────────────────────────────────────┐");
    println!("  │  PATH COVERAGE                                  │");
    println!("  ├─────────────────────────────────────────────────┤");
    println!("  │  Common paths:       {:>10}                │", common_count);
    println!("  │  Only in Everything: {:>10}                │", only_in_es.len());
    println!("  │  Only in Rust:       {:>10}                │", only_in_rust.len());
    println!("  └─────────────────────────────────────────────────┘");

    // 4. Field-by-field comparison on common paths
    let mut size_match: usize = 0;
    let mut size_mismatch: usize = 0;
    let mut created_match: usize = 0;
    let mut created_mismatch: usize = 0;
    let mut modified_match: usize = 0;
    let mut modified_mismatch: usize = 0;
    let mut attr_match: usize = 0;
    let mut attr_mismatch: usize = 0;

    let mut size_diffs: Vec<(String, String, String)> = Vec::new();
    let mut created_diffs: Vec<(String, String, String)> = Vec::new();
    let mut modified_diffs: Vec<(String, String, String)> = Vec::new();
    let mut attr_diffs: Vec<(String, String, String)> = Vec::new();

    for (path, es_rec) in &es_records {
        if let Some(rust_rec) = rust_records.get(path) {
            // Size
            if es_rec.size == rust_rec.size {
                size_match += 1;
            } else {
                size_mismatch += 1;
                if size_diffs.len() < 20 {
                    size_diffs.push((path.clone(), es_rec.size.clone(), rust_rec.size.clone()));
                }
            }
            // Created
            if timestamps_match(&es_rec.date_created, &rust_rec.created) {
                created_match += 1;
            } else {
                created_mismatch += 1;
                if created_diffs.len() < 20 {
                    created_diffs.push((path.clone(), es_rec.date_created.clone(), rust_rec.created.clone()));
                }
            }
            // Modified
            if timestamps_match(&es_rec.date_modified, &rust_rec.modified) {
                modified_match += 1;
            } else {
                modified_mismatch += 1;
                if modified_diffs.len() < 20 {
                    modified_diffs.push((path.clone(), es_rec.date_modified.clone(), rust_rec.modified.clone()));
                }
            }
            // Attributes
            if attributes_match(&es_rec.attributes, &rust_rec.attributes) {
                attr_match += 1;
            } else {
                attr_mismatch += 1;
                if attr_diffs.len() < 20 {
                    attr_diffs.push((path.clone(), es_rec.attributes.clone(), rust_rec.attributes.clone()));
                }
            }
        }
    }

    // Print field comparison results
    println!();
    println!("  ┌─────────────────────────────────────────────────┐");
    println!("  │  FIELD COMPARISON ({} common paths)      │", common_count);
    println!("  ├───────────────┬────────────┬────────────────────┤");
    println!("  │  Field        │  Match     │  Mismatch          │");
    println!("  ├───────────────┼────────────┼────────────────────┤");
    println!("  │  Size         │ {:>10} │ {:>10}         │", size_match, size_mismatch);
    println!("  │  Created      │ {:>10} │ {:>10}         │", created_match, created_mismatch);
    println!("  │  Modified     │ {:>10} │ {:>10}         │", modified_match, modified_mismatch);
    println!("  │  Attributes   │ {:>10} │ {:>10}         │", attr_match, attr_mismatch);
    println!("  └───────────────┴────────────┴────────────────────┘");

    let total_mismatches = size_mismatch + created_mismatch + modified_mismatch + attr_mismatch;

    // Show sample mismatches
    if !size_diffs.is_empty() {
        println!();
        println!("  Size mismatches (first {}):", size_diffs.len());
        for (path, es_val, rust_val) in &size_diffs {
            println!("    {} — Everything: {} / Rust: {}", path, es_val, rust_val);
        }
    }
    if !created_diffs.is_empty() {
        println!();
        println!("  Created timestamp mismatches (first {}):", created_diffs.len());
        for (path, es_val, rust_val) in &created_diffs {
            println!("    {} — Everything: {} / Rust: {}", path, es_val, rust_val);
        }
    }
    if !modified_diffs.is_empty() {
        println!();
        println!("  Modified timestamp mismatches (first {}):", modified_diffs.len());
        for (path, es_val, rust_val) in &modified_diffs {
            println!("    {} — Everything: {} / Rust: {}", path, es_val, rust_val);
        }
    }
    if !attr_diffs.is_empty() {
        println!();
        println!("  Attribute mismatches (first {}):", attr_diffs.len());
        for (path, es_val, rust_val) in &attr_diffs {
            println!("    {} — Everything: {} / Rust: {}", path, es_val, rust_val);
        }
    }

    // Summary verdict
    println!();
    if only_in_es.is_empty() && total_mismatches == 0 {
        if only_in_rust.is_empty() {
            println!("  ✅ EVERYTHING MATCH — Identical paths and all fields match");
        } else {
            println!(
                "  ✅ EVERYTHING SUPERSET — Rust ⊇ Everything, all fields match (+{} extra in Rust)",
                only_in_rust.len()
            );
        }
    } else if only_in_es.is_empty() && total_mismatches > 0 {
        println!(
            "  ⚠️  EVERYTHING FIELD DIFFS — Paths match but {} field mismatches",
            total_mismatches
        );
    } else {
        println!(
            "  ❌ EVERYTHING GAPS — {} missing from Rust, {} field mismatches",
            only_in_es.len(),
            total_mismatches
        );
    }

    // Show path-level diffs
    if !only_in_es.is_empty() {
        println!();
        println!("  Missing from Rust (Everything has them):");
        for (i, path) in only_in_es.iter().enumerate().take(30) {
            println!("    {:>3}. {}", i + 1, path);
        }
        if only_in_es.len() > 30 {
            println!("    ... and {} more", only_in_es.len() - 30);
        }
    }
    if !only_in_rust.is_empty() {
        println!();
        println!("  Extra in Rust (not in Everything, likely ADS/hardlinks):");
        for (i, path) in only_in_rust.iter().enumerate().take(20) {
            println!("    {:>3}. {}", i + 1, path);
        }
        if only_in_rust.len() > 20 {
            println!("    ... and {} more", only_in_rust.len() - 20);
        }
    }
}

/// Stream Everything output into a map of normalized path → record.
/// Supports two formats:
///   - EFU (from -create-file-list): `Filename,Size,Date Modified,Date Created,Attributes`
///   - es.exe CSV (from IPC query): `Name,Path,Size,DateCreated,DateModified,DateAccessed`
#[allow(dead_code)]
fn stream_everything_records(es_file: &Path) -> HashMap<String, EverythingRecord> {
    let file = fs::File::open(es_file)
        .unwrap_or_else(|e| panic!("Failed to open {}: {e}", es_file.display()));
    let reader = BufReader::with_capacity(256 * 1024, file);
    let mut records = HashMap::new();
    let mut is_first_line = true;
    let mut is_efu = false;

    for line in reader.lines() {
        let line = line.unwrap_or_else(|e| panic!("Read error: {e}"));
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if is_first_line {
            is_first_line = false;
            if trimmed.starts_with("Filename,") {
                is_efu = true;
                continue; // skip header
            }
        }

        let fields = split_csv_fields(trimmed);
        if is_efu {
            // EFU: Filename,Size,Date Modified,Date Created,Attributes
            if fields.len() >= 5 {
                let path = normalize_path(fields[0].trim_matches('"'));
                records.insert(path, EverythingRecord {
                    size: fields[1].trim_matches('"').to_string(),
                    date_modified: fields[2].trim_matches('"').to_string(),
                    date_created: fields[3].trim_matches('"').to_string(),
                    attributes: fields[4].trim_matches('"').to_string(),
                });
            }
        } else {
            // es.exe: Name,Path,Size,DateCreated,DateModified,DateAccessed
            if fields.len() >= 5 {
                let name = fields[0].trim_matches('"');
                let dir = fields[1].trim_matches('"');
                let full = if dir.ends_with('\\') || dir.ends_with('/') {
                    format!("{dir}{name}")
                } else {
                    format!("{dir}\\{name}")
                };
                let path = normalize_path(&full);
                records.insert(path, EverythingRecord {
                    size: fields[2].trim_matches('"').to_string(),
                    date_modified: fields[4].trim_matches('"').to_string(),
                    date_created: fields[3].trim_matches('"').to_string(),
                    attributes: String::new(), // es.exe doesn't output attributes
                });
            }
        }
    }
    records
}

/// Stream Rust parity-compat output into a map of normalized path → record.
/// Parity-compat CSV columns (from `PARITY_COLUMN_ORDER`):
///   0: "Path" (full path, quoted)
///   1: "Name" (quoted)
///   2: "PathOnly" (quoted)
///   3: "Size"
///   4: "SizeOnDisk"
///   5: "Created" (FILETIME i64)
///   6: "Modified" (FILETIME i64)
///   7: "Accessed" (FILETIME i64)
///   ... more columns follow (flags, booleans, etc.)
#[allow(dead_code)]
fn stream_rust_records(rust_file: &Path) -> HashMap<String, RustParityRecord> {
    let file = open_file_with_retry(rust_file, 3, std::time::Duration::from_secs(2));
    let reader = BufReader::with_capacity(256 * 1024, file);
    let mut records = HashMap::new();

    for line in reader.lines() {
        let line = line.unwrap_or_else(|e| panic!("Read error: {e}"));
        let trimmed = line.trim();
        if trimmed.is_empty() || is_footer_or_header_line(trimmed) {
            continue;
        }

        let fields = split_csv_fields(trimmed);
        if fields.len() >= 8 {
            let path = normalize_path(fields[0].trim_matches('"'));
            // Find the attributes field — it's typically the last numeric field
            // or we look for the flags/attributes column
            let attributes = if fields.len() > 8 {
                fields[8].trim_matches('"').to_string()
            } else {
                String::new()
            };
            records.insert(path, RustParityRecord {
                size: fields[3].trim_matches('"').to_string(),
                created: fields[5].trim_matches('"').to_string(),
                modified: fields[6].trim_matches('"').to_string(),
                attributes,
            });
        }
    }
    records
}

/// Compare timestamps from Everything (FILETIME i64) and Rust (FILETIME i64).
/// Both should be raw FILETIME values (100-nanosecond intervals since 1601-01-01).
/// Returns true if they match exactly, or if either is empty/zero.
#[allow(dead_code)]
fn timestamps_match(es_ts: &str, rust_ts: &str) -> bool {
    if es_ts.is_empty() || rust_ts.is_empty() {
        return true; // can't compare missing data
    }
    // Both should be raw FILETIME i64 values
    let es_val = es_ts.trim().parse::<i64>().unwrap_or(-1);
    let rust_val = rust_ts.trim().parse::<i64>().unwrap_or(-2);
    if es_val < 0 || rust_val < 0 {
        // If either failed to parse, fall back to string comparison
        return es_ts.trim() == rust_ts.trim();
    }
    es_val == rust_val
}

/// Compare attributes from Everything (raw NTFS u32) and Rust (raw NTFS u32).
/// Returns true if they match, or if either is empty.
#[allow(dead_code)]
fn attributes_match(es_attr: &str, rust_attr: &str) -> bool {
    if es_attr.is_empty() || rust_attr.is_empty() {
        return true; // can't compare missing data
    }
    let es_val = es_attr.trim().parse::<u32>().unwrap_or(u32::MAX);
    let rust_val = rust_attr.trim().parse::<u32>().unwrap_or(u32::MAX - 1);
    es_val == rust_val
}


/// Normalize a path for comparison: uppercase drive letter, consistent backslashes.
fn normalize_path(path: &str) -> String {
    let mut result = path.replace('/', "\\");
    // Uppercase drive letter (first char)
    if result.len() >= 2 && result.as_bytes()[1] == b':' {
        let upper = result[..1].to_uppercase();
        result = format!("{upper}{}", &result[1..]);
    }
    result
}

/// Check for Everything (es.exe) output in the drive directory and compare if found.
/// Looks for `es_<drive>.txt` in the drive dir. Skips silently if not found.
/// DISABLED (2026-03-27): Everything 1.4 has a 2GB IPC limit; es.exe can't export large drives.
#[allow(dead_code)]
fn try_everything_comparison(drive_dir: &Path, drive_letter: &str, rust_output: &Path) {
    let drive_lower = drive_letter.to_lowercase();
    let es_file = drive_dir.join(format!("es_{drive_lower}.txt"));
    if es_file.exists() {
        println!();
        compare_with_everything(&es_file, rust_output, drive_letter);
    }
}

/// Detect NTFS drives on Windows using wmic. Returns empty vec on non-Windows.
/// Includes both fixed (DriveType=3) and removable (DriveType=2) NTFS drives
/// so that USB NTFS drives (like G:) are not missed.
fn detect_ntfs_drives() -> Vec<String> {
    if !cfg!(windows) {
        return Vec::new();
    }

    // Query all local + removable drives, filter by NTFS filesystem
    let output = Command::new("wmic")
        .args(["logicaldisk", "where", "DriveType=2 or DriveType=3", "get", "DeviceID,FileSystem"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout
                .lines()
                .filter(|line| line.contains("NTFS"))
                .filter_map(|line| line.chars().next())
                .filter(|c| c.is_ascii_alphabetic())
                .map(|c| c.to_string().to_uppercase())
                .collect()
        }
        _ => vec!["C".to_string()],
    }
}

/// Clean up temporary files unless --keep was specified
fn cleanup_live_files(keep: bool, files: &[&Path]) {
    if keep {
        return;
    }
    for file in files {
        fs::remove_file(file).ok();
    }
}

/// Parse a named argument from the command line
fn parse_live_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Resolve the consolidated bench-artifact root, mirroring the `_bench-dir`
/// helper in `just/bench_uffs.just` and `resolve_bench_dir` in
/// `cross-tool-benchmark.rs` so every bench tool writes under ONE tree.
///
/// Precedence: `$UFFS_BENCH_DIR` > `%LOCALAPPDATA%\uffs-bench` >
/// `$XDG_CACHE_HOME|~/.cache` + `/uffs-bench`.  An explicit `--out-dir` flag
/// still wins over this (handled at the call site).
fn shared_bench_root() -> PathBuf {
    if let Ok(v) = env::var("UFFS_BENCH_DIR") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    if let Ok(v) = env::var("LOCALAPPDATA") {
        if !v.is_empty() {
            return PathBuf::from(v).join("uffs-bench");
        }
    }
    let base = env::var("XDG_CACHE_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".into())).join(".cache")
        });
    base.join("uffs-bench")
}

/// Print live mode summary with timing table
fn print_live_summary(results: &[LiveDriveResult]) {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                         SUMMARY                                  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    let mut strict = 0;
    let mut sorted = 0;
    let mut superset = 0;
    let mut mismatch = 0;
    let mut skipped = 0;

    for r in results {
        let (icon, status) = match r.result {
            VerifyResult::StrictMatch => { strict += 1; ("✅", "STRICT MATCH") }
            VerifyResult::SortedMatch => { sorted += 1; ("✅", "SORTED MATCH") }
            VerifyResult::SupersetMatch => { superset += 1; ("✅", "SUPERSET MATCH") }
            VerifyResult::Mismatch => { mismatch += 1; ("❌", "MISMATCH") }
            VerifyResult::Skipped => { skipped += 1; ("⏭️", "SKIPPED") }
        };
        let extra = if r.extra_rust_lines > 0 {
            format!(" (+{} hardlinks)", r.extra_rust_lines)
        } else {
            String::new()
        };
        println!(
            "  {} Drive {}: {} ({} / {} lines{})",
            icon, r.drive_letter, status, r.baseline_lines, r.rust_lines, extra
        );
    }

    println!();
    println!("  Strict:   {strict}");
    println!("  Sorted:   {sorted}");
    println!("  Superset: {superset}  (Rust ⊇ C++)");
    println!("  Mismatch: {mismatch}");
    println!("  Skipped:  {skipped}");

    if mismatch == 0 && skipped == 0 {
        println!("  🎉 ALL DRIVES VERIFIED SUCCESSFULLY!");
    } else if mismatch == 0 {
        println!("  ✅ All tested drives passed ({skipped} skipped)");
    } else {
        println!("  ⚠️  {mismatch} drive(s) had mismatches");
    }

    // Timing table
    print_timing_table(results);
    println!();
}

/// Print scan performance comparison table
fn print_timing_table(results: &[LiveDriveResult]) {
    println!();
    println!("╔══════════╦════════════════╦════════════════╦═════════════╦═══════════════════╗");
    println!("║  Drive   ║  C++ (warm)    ║  Rust (cold)   ║  Speedup    ║  Files/sec (Rust) ║");
    println!("╠══════════╬════════════════╬════════════════╬═════════════╬═══════════════════╣");

    let mut total_cpp = Duration::ZERO;
    let mut total_rust = Duration::ZERO;
    let mut total_files: usize = 0;

    for r in results {
        if r.result == VerifyResult::Skipped {
            println!(
                "║    {}     ║ {:>14} ║ {:>14} ║  SKIPPED    ║                   ║",
                r.drive_letter, "—", "—"
            );
            continue;
        }

        let cpp_str = format_duration(r.cpp_time);
        let rust_str = format_duration(r.rust_time);

        #[allow(clippy::cast_precision_loss)]
        let speedup = if r.rust_time.as_millis() > 0 {
            r.cpp_time.as_secs_f64() / r.rust_time.as_secs_f64()
        } else {
            0.0
        };

        let speedup_str = if speedup >= 1.0 {
            format!("{speedup:.2}x faster")
        } else if speedup > 0.0 {
            format!("{:.2}x slower", 1.0 / speedup)
        } else {
            "N/A".to_string()
        };

        #[allow(clippy::cast_precision_loss)]
        let files_per_sec = if r.rust_time.as_millis() > 0 {
            r.rust_lines as f64 / r.rust_time.as_secs_f64()
        } else {
            0.0
        };

        total_cpp += r.cpp_time;
        total_rust += r.rust_time;
        total_files += r.rust_lines;

        println!(
            "║    {}     ║ {:>14} ║ {:>14} ║ {:>11} ║ {:>15.0}/s ║",
            r.drive_letter, cpp_str, rust_str, speedup_str, files_per_sec
        );
    }

    if results.len() > 1 {
        println!("╠══════════╬════════════════╬════════════════╬═════════════╬═══════════════════╣");

        #[allow(clippy::cast_precision_loss)]
        let total_speedup = if total_rust.as_millis() > 0 {
            total_cpp.as_secs_f64() / total_rust.as_secs_f64()
        } else {
            0.0
        };
        let speedup_str = if total_speedup >= 1.0 {
            format!("{total_speedup:.2}x faster")
        } else if total_speedup > 0.0 {
            format!("{:.2}x slower", 1.0 / total_speedup)
        } else {
            "N/A".to_string()
        };
        #[allow(clippy::cast_precision_loss)]
        let avg_fps = if total_rust.as_millis() > 0 {
            total_files as f64 / total_rust.as_secs_f64()
        } else {
            0.0
        };

        println!(
            "║  TOTAL   ║ {:>14} ║ {:>14} ║ {:>11} ║ {:>15.0}/s ║",
            format_duration(total_cpp),
            format_duration(total_rust),
            speedup_str,
            avg_fps
        );
    }

    println!("╚══════════╩════════════════╩════════════════╩═════════════╩═══════════════════╝");
}


/// Discover all drive_* directories in the base directory
fn discover_drives(base_dir: &Path, filter: Option<&str>) -> Vec<String> {
    let mut drives = Vec::new();

    let Ok(entries) = fs::read_dir(base_dir) else {
        return drives;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if let Some(letter) = name.strip_prefix("drive_") {
            if letter.len() == 1 && letter.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            {
                // Apply filter if specified
                if let Some(f) = filter {
                    if letter.to_lowercase() != f.to_lowercase() {
                        continue;
                    }
                }
                drives.push(letter.to_lowercase());
            }
        }
    }

    drives.sort();
    drives
}

/// Discover `drive_<x>.tar.zst` transport bundles in `base_dir`, honoring the
/// optional single-drive filter. Returns `(drive_lower, archive_path)` pairs.
fn discover_archives(base_dir: &Path, filter: Option<&str>) -> Vec<(String, PathBuf)> {
    let mut archives = Vec::new();

    let Ok(entries) = fs::read_dir(base_dir) else {
        return archives;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(letter) = name
            .strip_prefix("drive_")
            .and_then(|rest| rest.strip_suffix(".tar.zst"))
        else {
            continue;
        };
        if letter.len() != 1 || !letter.chars().all(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        if let Some(f) = filter {
            if !letter.eq_ignore_ascii_case(f) {
                continue;
            }
        }
        archives.push((letter.to_lowercase(), path));
    }

    archives.sort();
    archives
}

/// Extract a `.tar.zst` bundle into `target` (created if absent).
///
/// Tries `tar --zstd -xf` first, then plain `tar -xf` (libarchive on macOS /
/// bsdtar auto-detects zstd on extraction).
fn extract_archive(archive: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|e| format!("mkdir {}: {e}", target.display()))?;
    let archive_str = archive.to_string_lossy().to_string();
    let target_str = target.to_string_lossy().to_string();

    let attempts: [Vec<&str>; 2] = [
        vec!["--zstd", "-xf", &archive_str, "-C", &target_str],
        vec!["-xf", &archive_str, "-C", &target_str],
    ];
    let mut last_err = String::from("tar not found");
    for args in &attempts {
        match Command::new("tar").args(args).output() {
            Ok(out) if out.status.success() => return Ok(()),
            Ok(out) => last_err = String::from_utf8_lossy(&out.stderr).trim().to_string(),
            Err(e) => last_err = e.to_string(),
        }
    }
    let _ = fs::remove_dir_all(target);
    Err(format!("tar extract failed: {last_err}"))
}

/// Verify a single drive and return the result
fn verify_single_drive(
    base_dir: &Path,
    drive_dir: &Path,
    drive_letter: &str,
    rust_output: &Path,
    parse_duration: Option<Duration>,
    mft_size_bytes: u64,
) -> DriveResult {
    let drive_lower = drive_letter.to_lowercase();
    let golden_baseline_file = find_golden_baseline_file(drive_dir, &drive_lower);

    // Validate baseline: warn if not a real C++ baseline, error if too small
    let baseline_type = warn_if_not_cpp_baseline(&golden_baseline_file, &drive_lower);

    // Validate Rust output: must exist and be >1 KB
    validate_rust_output(rust_output, drive_letter);

    let baseline_label = match baseline_type {
        BaselineType::Golden => "golden (curated)",
        BaselineType::Cpp => "C++ scan",
        BaselineType::RustLive => "⚠️  Rust live (NOT C++ parity!)",
    };

    println!("  Base dir:       {}", base_dir.display());
    println!("  Drive dir:      {}", drive_dir.display());
    println!("  Drive letter:   {drive_letter}");
    println!("  Baseline file:  {}", golden_baseline_file.display());
    println!("  Baseline type:  {baseline_label}");
    println!("  Rust output:    {}", rust_output.display());
    println!();

    println!("  Computing streaming SHA256 + order-independent fingerprints...");
    let t_hash = Instant::now();
    // The golden baseline (cpp_*.txt) is immutable across reruns, so its hash
    // is cached in a sidecar keyed on (size, mtime).  Only the regenerated Rust
    // output is hashed every run.
    let (golden_stats, golden_cached) = compute_streaming_stats_cached(&golden_baseline_file);
    let rust_stats = compute_streaming_stats(rust_output);
    let hash_elapsed = t_hash.elapsed();

    println!(
        "  Golden baseline: {} ({} lines) [{:.1}s{}]",
        golden_stats.ordered_hash,
        golden_stats.line_count,
        hash_elapsed.as_secs_f64(),
        if golden_cached { ", golden cached" } else { "" }
    );
    println!(
        "  Rust output:     {} ({} lines)",
        rust_stats.ordered_hash, rust_stats.line_count
    );
    println!();

    if golden_stats.ordered_hash == rust_stats.ordered_hash {
        println!("  ✅ RESULT: STRICT FULL OUTPUT MATCH");
        println!("     Golden baseline verified for drive {}.", drive_letter);
        return DriveResult {
            drive_letter: drive_letter.to_string(),
            result: VerifyResult::StrictMatch,
            baseline_lines: golden_stats.line_count,
            rust_lines: rust_stats.line_count,
            extra_rust_lines: 0,
            mft_size_bytes,
            parse_duration,
        };
    }

    // Order-independent match: same lines, different order (no sort needed!)
    if is_sorted_match(&golden_stats, &rust_stats) {
        println!("  ✅ RESULT: FULL OUTPUT MATCH (order-independent fingerprint)");
        println!("     Exact line order differs (different traversal order), but content matches.");
        println!("     This is acceptable — C++ and Rust walk the MFT/tree in different orders.");
        return DriveResult {
            drive_letter: drive_letter.to_string(),
            result: VerifyResult::SortedMatch,
            baseline_lines: golden_stats.line_count,
            rust_lines: rust_stats.line_count,
            extra_rust_lines: 0,
            mft_size_bytes,
            parse_duration,
        };
    }

    // ─── Streaming diff (no filtering except header/footer) ────────────
    // All lines participate equally — ADS, data, everything.
    // If baseline has lines Rust doesn't → those are flagged.
    // If Rust has extra lines baseline doesn't → usually hardlinks (OK).
    println!("  Fingerprints differ; running streaming line comparison...");

    let t_diff = Instant::now();
    let diff = compute_streaming_diff(&golden_baseline_file, rust_output);
    let diff_elapsed = t_diff.elapsed();

    // ── Line count breakdown ──
    println!();
    println!("  ┌─────────────────────────────────────────────────────────────┐");
    println!("  │  LINE COUNT BREAKDOWN                                       │");
    println!("  ├──────────────────────────┬──────────────┬───────────────────┤");
    println!("  │  Category                │   Baseline   │       Rust        │");
    println!("  ├──────────────────────────┼──────────────┼───────────────────┤");
    println!(
        "  │  Raw lines (total)       │ {:>12} │ {:>17} │",
        golden_stats.line_count, rust_stats.line_count
    );
    println!(
        "  │  Header/footer (skipped) │ {:>12} │ {:>17} │",
        diff.baseline_header_footer_filtered, diff.rust_header_footer_filtered
    );
    println!(
        "  │  Data lines (compared)   │ {:>12} │ {:>17} │",
        diff.baseline_data_lines, diff.rust_data_lines
    );
    println!("  └──────────────────────────┴──────────────┴───────────────────┘");

    println!();
    println!(
        "  Streaming diff completed in {:.1}s:",
        diff_elapsed.as_secs_f64()
    );
    println!("     Only in baseline: {}", diff.only_in_baseline.len());
    println!("     Only in Rust:     {}", diff.only_in_rust.len());

    // ── Decision ──
    if diff.only_in_baseline.is_empty() {
        // All baseline lines found in Rust — Rust is a superset
        let extra = diff.only_in_rust.len();
        println!();
        println!("  ✅ RESULT: SUPERSET MATCH (Rust ⊇ baseline)");
        println!("     All baseline lines found in Rust output.");
        if extra > 0 {
            println!("     Extra Rust lines: {extra}");
        }

        // Verify extra lines are hardlinks
        if !diff.only_in_rust.is_empty() {
            verify_hardlinks_inline(&golden_baseline_file, &diff.only_in_rust);
        }

        return DriveResult {
            drive_letter: drive_letter.to_string(),
            result: VerifyResult::SupersetMatch,
            baseline_lines: golden_stats.line_count,
            rust_lines: rust_stats.line_count,
            extra_rust_lines: extra,
            mft_size_bytes,
            parse_duration,
        };
    }

    // Baseline has lines Rust doesn't — MISMATCH
    println!();
    println!("  ❌ RESULT: MISMATCH");
    println!(
        "     Lines only in baseline (MISSING from Rust): {}",
        diff.only_in_baseline.len()
    );
    println!(
        "     Lines only in Rust (extra):                 {}",
        diff.only_in_rust.len()
    );
    println!(
        "     Raw:  {} (baseline) vs {} (Rust)",
        golden_stats.line_count, rust_stats.line_count
    );
    println!(
        "     Data: {} (baseline) vs {} (Rust)",
        diff.baseline_data_lines, diff.rust_data_lines
    );

    // Show ALL missing lines (up to MAX_DIFF_DISPLAY)
    if !diff.only_in_baseline.is_empty() {
        println!();
        println!("  ── Lines MISSING from Rust ({} total) ──",
            diff.only_in_baseline.len());
        show_diff_lines(&diff.only_in_baseline);
    }
    if !diff.only_in_rust.is_empty() {
        println!();
        println!("  ── Extra lines in Rust ({} total) ──",
            diff.only_in_rust.len());
        show_diff_lines(&diff.only_in_rust);
    }

    // Show paired diffs only when both sides have unmatched lines
    // (otherwise the single-side listing above already covers it)
    if !diff.only_in_baseline.is_empty() && !diff.only_in_rust.is_empty() {
        println!();
        show_paired_diffs(&diff.only_in_baseline, &diff.only_in_rust);
    }
    println!();

    DriveResult {
        drive_letter: drive_letter.to_string(),
        result: VerifyResult::Mismatch,
        baseline_lines: golden_stats.line_count,
        rust_lines: rust_stats.line_count,
        extra_rust_lines: diff.only_in_rust.len(),
        mft_size_bytes,
        parse_duration,
    }
}

/// Print final summary of all drive results
fn print_summary(results: &[DriveResult]) {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                         SUMMARY                                  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    let mut strict_match = 0;
    let mut sorted_match = 0;
    let mut superset_match = 0;
    let mut mismatch = 0;
    let mut skipped = 0;

    for result in results {
        let (icon, status) = match result.result {
            VerifyResult::StrictMatch => {
                strict_match += 1;
                ("✅", "STRICT MATCH")
            }
            VerifyResult::SortedMatch => {
                sorted_match += 1;
                ("✅", "SORTED MATCH")
            }
            VerifyResult::SupersetMatch => {
                superset_match += 1;
                ("✅", "SUPERSET MATCH")
            }
            VerifyResult::Mismatch => {
                mismatch += 1;
                ("❌", "MISMATCH")
            }
            VerifyResult::Skipped => {
                skipped += 1;
                ("⚠️ ", "SKIPPED")
            }
        };
        let extra_info = if result.extra_rust_lines > 0 {
            format!(" (+{} hardlinks)", result.extra_rust_lines)
        } else {
            String::new()
        };
        println!(
            "  {} Drive {}: {} ({} / {} lines{})",
            icon, result.drive_letter, status, result.baseline_lines, result.rust_lines, extra_info
        );
    }

    println!();
    let total_drives = results.len();
    println!("  Total drives:    {total_drives}");
    println!("  Strict matches:  {strict_match}");
    println!("  Sorted matches:  {sorted_match}");
    println!("  Superset matches:{superset_match}  (Rust ⊇ C++, extra hardlinks)");
    println!("  Mismatches:      {mismatch}");
    println!("  Skipped:         {skipped}");
    println!();

    if mismatch == 0 && skipped == 0 {
        println!("  🎉 ALL DRIVES VERIFIED SUCCESSFULLY!");
    } else if mismatch == 0 {
        println!("  ✅ All verified drives passed (some skipped)");
    } else {
        println!("  ⚠️  {mismatch} drive(s) had mismatches");
    }

    // Print timing table if any drives have timing data
    let timed_results: Vec<_> = results.iter().filter(|r| r.parse_duration.is_some()).collect();
    if !timed_results.is_empty() {
        print_offline_timing_table(&timed_results);
    }
    println!();
}

/// Print a timing table for MFT parsing performance (offline mode)
fn print_offline_timing_table(results: &[&DriveResult]) {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                      MFT PARSING PERFORMANCE                                 ║");
    println!("╠═══════════╦══════════════╦═══════════════╦═══════════════╦══════════════════╣");
    println!("║   Drive   ║   MFT Size   ║  Parse Time   ║  Throughput   ║   Files/sec      ║");
    println!("╠═══════════╬══════════════╬═══════════════╬═══════════════╬══════════════════╣");

    let mut total_bytes: u64 = 0;
    let mut total_duration = Duration::ZERO;
    let mut total_files: usize = 0;

    for result in results {
        if let Some(duration) = result.parse_duration {
            #[allow(clippy::cast_precision_loss)] // File sizes don't need full precision
            let mft_mb = result.mft_size_bytes as f64 / (1024.0 * 1024.0);
            let secs = duration.as_secs_f64();
            let throughput_mb = if secs > 0.0 { mft_mb / secs } else { 0.0 };
            #[allow(clippy::cast_precision_loss)] // Line counts don't need full precision
            let files_per_sec = if secs > 0.0 { result.rust_lines as f64 / secs } else { 0.0 };

            total_bytes += result.mft_size_bytes;
            total_duration += duration;
            total_files += result.rust_lines;

            let drive = &result.drive_letter;
            let time_str = format_duration(duration);
            println!(
                "║     {drive}     ║ {mft_mb:>10.1} MB ║ {time_str:>13} ║ {throughput_mb:>10.1} MB/s ║ {files_per_sec:>14.0}/s ║",
            );
        }
    }

    // Print totals
    if results.len() > 1 {
        println!("╠═══════════╬══════════════╬═══════════════╬═══════════════╬══════════════════╣");
        #[allow(clippy::cast_precision_loss)] // File sizes don't need full precision
        let total_mb = total_bytes as f64 / (1024.0 * 1024.0);
        let total_secs = total_duration.as_secs_f64();
        let avg_throughput = if total_secs > 0.0 { total_mb / total_secs } else { 0.0 };
        #[allow(clippy::cast_precision_loss)] // Line counts don't need full precision
        let avg_files_per_sec = if total_secs > 0.0 { total_files as f64 / total_secs } else { 0.0 };

        let time_str = format_duration(total_duration);
        println!(
            "║   TOTAL   ║ {total_mb:>10.1} MB ║ {time_str:>13} ║ {avg_throughput:>10.1} MB/s ║ {avg_files_per_sec:>14.0}/s ║",
        );
    }

    println!("╚═══════════╩══════════════╩═══════════════╩═══════════════╩══════════════════╝");
}

/// Format a Duration as a human-readable string
fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs_f64();
    if total_secs < 1.0 {
        let ms = duration.as_millis();
        format!("{ms:.0}ms")
    } else if total_secs < 60.0 {
        format!("{total_secs:.2}s")
    } else {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let mins = (total_secs / 60.0).floor() as u64;
        let secs = total_secs % 60.0;
        format!("{mins}m {secs:.1}s")
    }
}

/// Resolves the drive data directory.
///
/// Supports two directory structures:
/// 1. New: `<base>/drive_<letter>/` (e.g., `~/uffs_data/drive_d/`)
/// 2. Legacy: `<base>/` with files directly in base (e.g.,
///    `~/uffs_data/D_mft.bin`)
fn resolve_drive_dir(base_dir: &Path, drive_lower: &str) -> PathBuf {
    // Try new structure first: base/drive_<letter>/
    let new_style = base_dir.join(format!("drive_{drive_lower}"));
    if new_style.exists() && new_style.is_dir() {
        return new_style;
    }
    // Fall back to legacy: files directly in base_dir
    base_dir.to_path_buf()
}

/// Classifies the type of baseline file found, so callers can warn when
/// the comparison is not a true C++ parity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaselineType {
    /// `golden_<drive>.txt` — curated golden reference (best)
    Golden,
    /// `cpp_<drive>.txt` — C++ scan output (true parity comparison)
    Cpp,
    /// `rust_live_<drive>.txt` — Rust live scan output (NOT a C++ parity
    /// check — this is a self-comparison that only tests offline vs live
    /// consistency). Using this as a "golden baseline" masks real parity
    /// issues.
    RustLive,
}

/// Minimum size (bytes) for a baseline or output file to be considered valid.
/// An MFT scan on even a nearly-empty NTFS volume produces >1 KB of output.
const MIN_ARTIFACT_SIZE: u64 = 1024;

/// Find the golden baseline file for a drive, or exit with a clear error.
fn find_golden_baseline_file(data_dir: &Path, drive_lower: &str) -> PathBuf {
    if let Some((path, _)) = find_golden_baseline_file_typed(data_dir, drive_lower) {
        return path;
    }
    let candidates = baseline_candidates(drive_lower);
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║  ❌ FATAL: Golden baseline file not found                    ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!();
    eprintln!("  Drive:     {}", drive_lower.to_uppercase());
    eprintln!("  Directory: {}", data_dir.display());
    eprintln!("  Checked:");
    for (name, _) in &candidates {
        eprintln!("    - {name}");
    }
    eprintln!();
    eprintln!("  Run test_runs.ps1 on Windows to collect C++ baseline artifacts.");
    std::process::exit(1);
}

/// Try to find a golden baseline file, returning None if not found
fn find_golden_baseline_file_optional(data_dir: &Path, drive_lower: &str) -> Option<PathBuf> {
    find_golden_baseline_file_typed(data_dir, drive_lower).map(|(path, _)| path)
}

/// Find baseline and return both path and type, or None if nothing found.
fn find_golden_baseline_file_typed(
    data_dir: &Path,
    drive_lower: &str,
) -> Option<(PathBuf, BaselineType)> {
    let candidates = baseline_candidates(drive_lower);

    for (name, btype) in &candidates {
        let path = data_dir.join(name);
        if path.exists() {
            return Some((path, *btype));
        }
    }
    None
}

/// List of candidate baseline filenames to check, in priority order.
fn baseline_candidates(drive_lower: &str) -> [(String, BaselineType); 3] {
    [
        (format!("golden_{drive_lower}.txt"), BaselineType::Golden),
        (format!("cpp_{drive_lower}.txt"), BaselineType::Cpp),
        (
            format!("rust_live_{drive_lower}.txt"),
            BaselineType::RustLive,
        ),
    ]
}

/// Print a loud warning banner when using rust_live as baseline (not a real
/// C++ parity check). Returns the baseline type for downstream decisions.
fn warn_if_not_cpp_baseline(baseline_path: &Path, drive_lower: &str) -> BaselineType {
    let (_, btype) = find_golden_baseline_file_typed(
        baseline_path.parent().unwrap_or(Path::new(".")),
        drive_lower,
    )
    .unwrap_or_else(|| {
        // Shouldn't happen — we already found the file — but be safe
        (baseline_path.to_path_buf(), BaselineType::RustLive)
    });

    match btype {
        BaselineType::RustLive => {
            eprintln!();
            eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
            eprintln!("  ║  ⚠️  WARNING: Using Rust live output as baseline             ║");
            eprintln!("  ║                                                              ║");
            eprintln!("  ║  This is NOT a C++ parity check! The comparison is:          ║");
            eprintln!("  ║    Rust offline  vs  Rust live  (self-consistency only)       ║");
            eprintln!("  ║                                                              ║");
            eprintln!("  ║  For true parity, collect C++ baseline with test_runs.ps1     ║");
            eprintln!("  ║  on Windows (needs uffs.com / C++ binary).                   ║");
            eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
            eprintln!("  Baseline file: {}", baseline_path.display());
            eprintln!();
        }
        BaselineType::Golden | BaselineType::Cpp => {
            // These are legitimate baselines — no warning needed
        }
    }

    // Validate baseline file size regardless of type
    if let Ok(meta) = fs::metadata(baseline_path) {
        if meta.len() < MIN_ARTIFACT_SIZE {
            eprintln!();
            eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
            eprintln!("  ║  ❌ FATAL: Baseline file is too small ({} bytes)     ", meta.len());
            eprintln!("  ║     Minimum: {} bytes                                ", MIN_ARTIFACT_SIZE);
            eprintln!("  ║     File: {}", baseline_path.display());
            eprintln!("  ║                                                              ║");
            eprintln!("  ║  The baseline file appears empty or corrupt.                 ║");
            eprintln!("  ║  Re-run test_runs.ps1 on Windows to regenerate.              ║");
            eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
            eprintln!();
            std::process::exit(1);
        }
    }

    btype
}

/// Validate that a Rust output file exists and is large enough to be real.
/// Exits with a clear error if validation fails.
fn validate_rust_output(rust_output: &Path, drive_letter: &str) {
    if !rust_output.exists() {
        eprintln!();
        eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
        eprintln!("  ║  ❌ FATAL: Rust output file not found                       ║");
        eprintln!("  ║     Drive: {}                                               ", drive_letter);
        eprintln!("  ║     Path:  {}", rust_output.display());
        eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
        eprintln!();
        std::process::exit(1);
    }
    if let Ok(meta) = fs::metadata(rust_output) {
        if meta.len() < MIN_ARTIFACT_SIZE {
            eprintln!();
            eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
            eprintln!("  ║  ❌ FATAL: Rust output file is too small ({} bytes) ", meta.len());
            eprintln!("  ║     Minimum: {} bytes                                ", MIN_ARTIFACT_SIZE);
            eprintln!("  ║     Drive: {}                                        ", drive_letter);
            eprintln!("  ║     File:  {}", rust_output.display());
            eprintln!("  ║                                                              ║");
            eprintln!("  ║  The scan produced no meaningful output.                     ║");
            eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
            eprintln!();
            std::process::exit(1);
        }
    }
}

fn print_usage(prog: &str) {
    eprintln!("UFFS Parity Verification (cross-platform)");
    eprintln!();
    eprintln!("OFFLINE MODE (Mac or Windows — compare against pre-captured MFT artifacts):");
    eprintln!("  {prog} <base_dir> --regenerate                   # Verify all drives");
    eprintln!("  {prog} <base_dir> --drive D --regenerate         # Verify drive D only");
    eprintln!("  {prog} <base_dir> --drive D --rust <path>        # Compare existing output");
    eprintln!();
    eprintln!("LIVE MODE (Windows — run Rust cold, then C++ warm, then compare):");
    eprintln!("  {prog} --live                                    # All NTFS drives, auto-detect");
    eprintln!("  {prog} --live --drive C                          # Single drive");
    eprintln!("  {prog} --live --drive C,D,F                      # Multiple drives");
    eprintln!("  {prog} --live --cpp-bin path\\uffs.com             # Custom C++ binary");
    eprintln!();
    eprintln!("Offline Options:");
    eprintln!("  --regenerate       Run uffs to generate fresh output, then compare");
    eprintln!("  --rust <path>      Compare existing Rust output (requires --drive)");
    eprintln!("  --drive <letter>   Verify only the specified drive");
    eprintln!("  --tz <offset>      Timezone offset in hours (default: auto-detect)");
    eprintln!("                     Use -7 for PDT (Mar-Nov), -8 for PST (Nov-Mar)");
    eprintln!("  --bin <path>       Path to uffs binary (default: auto-detect)");
    eprintln!();
    eprintln!("Live Options:");
    eprintln!("  --live             Run both C++ and Rust live, compare outputs");
    eprintln!("  --cpp-bin <path>   Path to uffs.com (C++ binary)");
    eprintln!("  --bin <path>       Path to uffs.exe (Rust binary)");
    eprintln!("  --out-dir <path>   Output directory.  Default: <bench-root>/parity,");
    eprintln!("                     where bench-root = $UFFS_BENCH_DIR >");
    eprintln!("                     %LOCALAPPDATA%\\uffs-bench > ~/.cache/uffs-bench.");
    eprintln!("  --keep             Keep output files after comparison");
    eprintln!("  --name-only        Pass --name-only to Rust binary");
    eprintln!("  --pattern <pat>    Search pattern (default: *)");
    eprintln!();
    eprintln!("Common Options (offline + live):");
    eprintln!("  --pipeline <mode>  (deprecated, ignored — only unified pipeline remains)");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  # Offline: verify all drives from captured MFT data");
    eprintln!("  {prog} ~/uffs_data --regenerate");
    eprintln!();
    eprintln!("  # Live: run both tools on Windows, auto-detect NTFS drives");
    eprintln!("  {prog} --live --keep");
    eprintln!();
    eprintln!("  # Live: single drive with custom paths");
    eprintln!("  {prog} --live --drive C --cpp-bin bin\\uffs.com --bin bin\\uffs.exe");
}

/// Parse --drive argument from command line
fn parse_drive_filter(args: &[String]) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == "--drive" && i + 1 < args.len() {
            return Some(args[i + 1].to_lowercase());
        }
    }
    None
}

/// Parse --rust argument from command line
fn parse_rust_path(args: &[String]) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == "--rust" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}

/// Parse --pattern argument from command line. Defaults to "*" (full scan).
fn parse_pattern(args: &[String]) -> String {
    for i in 0..args.len() {
        if args[i] == "--pattern" && i + 1 < args.len() {
            return args[i + 1].clone();
        }
    }
    "*".to_string()
}

/// Parse `--pipeline unified|legacy` from command line.
/// Returns `None` when not specified (uffs uses its own default).
fn parse_pipeline(args: &[String]) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == "--pipeline" && i + 1 < args.len() {
            let val = args[i + 1].to_lowercase();
            if val != "unified" && val != "legacy" {
                eprintln!("ERROR: --pipeline must be 'unified' or 'legacy', got '{val}'");
                std::process::exit(1);
            }
            return Some(val);
        }
    }
    None
}

/// Parse --tz argument from command line. Returns None if not specified
/// (auto-detect).
fn parse_tz_offset(args: &[String]) -> Option<i32> {
    for i in 0..args.len() {
        if args[i] == "--tz" && i + 1 < args.len() {
            return Some(args[i + 1].parse().unwrap_or(-7));
        }
    }
    None // Auto-detect from baseline
}

/// Auto-detect timezone offset from trial_run.md metadata file.
/// Falls back to baseline file scanning if trial_run.md not found.
/// trial_run.md contains: **Started:** 2026-03-11T22:18:32.7876612-07:00
fn detect_tz_from_baseline(baseline_path: &Path) -> i32 {
    // First, try to read test_runs.md or trial_run.md in the same directory
    let drive_dir = baseline_path.parent().unwrap_or(baseline_path);

    // Try test_runs.md first (current script name), then trial_run.md (legacy)
    for name in &["test_runs.md", "trial_run.md"] {
        let path = drive_dir.join(name);
        if let Some(offset) = detect_tz_from_trial_run(&path) {
            return offset;
        }
    }

    // Fallback: scan baseline for most recent date
    detect_tz_from_baseline_fallback(baseline_path)
}

/// Parse trial_run.md for the Started timestamp with explicit timezone.
/// Format: **Started:** 2026-03-11T22:18:32.7876612-07:00
fn detect_tz_from_trial_run(path: &Path) -> Option<i32> {
    let content = std::fs::read_to_string(path).ok()?;

    // Look for pattern: **Started:** YYYY-MM-DDTHH:MM:SS...+/-HH:00
    for line in content.lines() {
        if line.contains("**Started:**") {
            // Find the timezone offset at the end: -07:00 or -08:00
            if let Some(tz_pos) = line.rfind('-') {
                let tz_part = &line[tz_pos..];
                if tz_part.starts_with("-07:00") {
                    println!("Auto-detected from trial_run.md: -7 (PDT)");
                    println!("  {}", line.trim());
                    return Some(-7);
                } else if tz_part.starts_with("-08:00") {
                    println!("Auto-detected from trial_run.md: -8 (PST)");
                    println!("  {}", line.trim());
                    return Some(-8);
                }
            }
            // Also check for positive offsets (unlikely for Pacific but be safe)
            if let Some(tz_pos) = line.rfind('+') {
                let tz_part = &line[tz_pos..];
                if let Ok(hours) = tz_part[1..3].parse::<i32>() {
                    println!("Auto-detected from trial_run.md: +{}", hours);
                    println!("  {}", line.trim());
                    return Some(hours);
                }
            }
        }
    }
    None
}

/// Fallback: determine timezone from when the baseline file was **created/modified**.
///
/// The C++ tool applies the system's *current* timezone when formatting timestamps,
/// so the correct offset is based on the **capture date** (file modification time),
/// NOT the dates inside the CSV content (which reflect when the files on disk were
/// created — potentially months earlier in a different DST season).
fn detect_tz_from_baseline_fallback(baseline_path: &Path) -> i32 {
    // Primary strategy: use the baseline file's own modification time
    if let Ok(meta) = std::fs::metadata(baseline_path) {
        if let Ok(modified) = meta.modified() {
            // Convert SystemTime to a (year, month, day) in UTC, then apply pacific offset
            let duration = modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let secs = duration.as_secs() as i64;

            // Simple civil-date calculation from unix timestamp (UTC)
            let days = (secs / 86400) as i32;
            let (year, month, day) = civil_from_days(days);

            let offset = pacific_tz_offset(year, month as u32, day as u32);
            let tz_name = if offset == -7 { "PDT" } else { "PST" };
            println!(
                "Auto-detected from baseline file date {}-{:02}-{:02}: {} ({}) [file mtime]",
                year, month, day, offset, tz_name
            );
            return offset;
        }
    }

    // Last resort: scan CSV content dates (legacy behavior)
    let file = match std::fs::File::open(baseline_path) {
        Ok(f) => f,
        Err(_) => return -7,
    };
    let reader = std::io::BufReader::new(file);

    let mut most_recent_date: Option<(i32, u32, u32)> = None;

    for line in std::io::BufRead::lines(reader).take(20).flatten() {
        for (year, month, day, _hour) in extract_all_datetimes_from_line(&line) {
            if let Some((cy, cm, cd)) = most_recent_date {
                if year > cy
                    || (year == cy && month > cm)
                    || (year == cy && month == cm && day > cd)
                {
                    most_recent_date = Some((year, month, day));
                }
            } else {
                most_recent_date = Some((year, month, day));
            }
        }
    }

    if let Some((year, month, day)) = most_recent_date {
        let offset = pacific_tz_offset(year, month, day);
        let tz_name = if offset == -7 { "PDT" } else { "PST" };
        println!(
            "Auto-detected from baseline content date {}-{:02}-{:02}: {} ({}) [content fallback]",
            year, month, day, offset, tz_name
        );
        return offset;
    }

    println!("Could not auto-detect timezone, defaulting to -7 (PDT)");
    -7
}

/// Convert a day count (days since 1970-01-01) to (year, month, day).
/// Algorithm from Howard Hinnant's `chrono`-compatible civil_from_days.
fn civil_from_days(days: i32) -> (i32, i32, i32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as i32, d as i32)
}

/// Extract ALL (year, month, day, hour) tuples from a CSV line.
fn extract_all_datetimes_from_line(line: &str) -> Vec<(i32, u32, u32, u32)> {
    let mut results = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    // Pattern: YYYY-MM-DD HH:MM:SS (19 chars)
    while i + 19 <= bytes.len() {
        if bytes[i].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
            && bytes[i + 4] == b'-'
            && bytes[i + 5].is_ascii_digit()
            && bytes[i + 6].is_ascii_digit()
            && bytes[i + 7] == b'-'
            && bytes[i + 8].is_ascii_digit()
            && bytes[i + 9].is_ascii_digit()
            && bytes[i + 10] == b' '
            && bytes[i + 11].is_ascii_digit()
            && bytes[i + 12].is_ascii_digit()
            && bytes[i + 13] == b':'
        {
            if let (Ok(year), Ok(month), Ok(day), Ok(hour)) = (
                line[i..i + 4].parse::<i32>(),
                line[i + 5..i + 7].parse::<u32>(),
                line[i + 8..i + 10].parse::<u32>(),
                line[i + 11..i + 13].parse::<u32>(),
            ) {
                if (2000..=2100).contains(&year)
                    && (1..=12).contains(&month)
                    && (1..=31).contains(&day)
                    && hour <= 23
                {
                    results.push((year, month, day, hour));
                }
            }
            i += 19;
        } else {
            i += 1;
        }
    }
    results
}

/// Extract ALL (year, month, day) tuples from a CSV line.
#[allow(dead_code)]
fn extract_all_dates_from_line(line: &str) -> Vec<(i32, u32, u32)> {
    let mut dates = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 10 <= bytes.len() {
        if bytes[i].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
            && bytes[i + 4] == b'-'
            && bytes[i + 5].is_ascii_digit()
            && bytes[i + 6].is_ascii_digit()
            && bytes[i + 7] == b'-'
            && bytes[i + 8].is_ascii_digit()
            && bytes[i + 9].is_ascii_digit()
        {
            if let (Ok(year), Ok(month), Ok(day)) = (
                line[i..i + 4].parse::<i32>(),
                line[i + 5..i + 7].parse::<u32>(),
                line[i + 8..i + 10].parse::<u32>(),
            ) {
                if (2000..=2100).contains(&year)
                    && (1..=12).contains(&month)
                    && (1..=31).contains(&day)
                {
                    dates.push((year, month, day));
                }
            }
            i += 10; // Skip past this date
        } else {
            i += 1;
        }
    }
    dates
}

/// Extract first (year, month, day) from a CSV line (kept for compatibility).
#[allow(dead_code)]
fn extract_date_from_line(line: &str) -> Option<(i32, u32, u32)> {
    // Look for pattern: YYYY-MM-DD (4 digits, dash, 2 digits, dash, 2 digits)
    let bytes = line.as_bytes();
    for i in 0..bytes.len().saturating_sub(10) {
        if bytes[i].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
            && bytes[i + 4] == b'-'
            && bytes[i + 5].is_ascii_digit()
            && bytes[i + 6].is_ascii_digit()
            && bytes[i + 7] == b'-'
            && bytes[i + 8].is_ascii_digit()
            && bytes[i + 9].is_ascii_digit()
        {
            let year: i32 = line[i..i + 4].parse().ok()?;
            let month: u32 = line[i + 5..i + 7].parse().ok()?;
            let day: u32 = line[i + 8..i + 10].parse().ok()?;
            if (2000..=2100).contains(&year)
                && (1..=12).contains(&month)
                && (1..=31).contains(&day)
            {
                return Some((year, month, day));
            }
        }
    }
    None
}

/// Determine Pacific timezone offset for a given date.
/// Returns -7 for PDT (Daylight), -8 for PST (Standard).
/// Pacific DST: 2nd Sunday of March 2:00 AM to 1st Sunday of November 2:00 AM
fn pacific_tz_offset(_year: i32, month: u32, day: u32) -> i32 {
    // Simple rule: March 15 - November 1 is approximately PDT
    // More precise would calculate exact Sunday transitions, but this is close
    // enough
    let dst_start = (3, 8); // March 8 (earliest 2nd Sunday)
    let dst_end = (11, 1); // November 1 (earliest 1st Sunday)

    if month > dst_start.0 && month < dst_end.0 {
        -7 // PDT: April through October
    } else if month == dst_start.0 && day >= 8 {
        -7 // PDT: March 8+ (approx 2nd Sunday)
    } else if month == dst_end.0 && day < 8 {
        -7 // PDT: November 1-7 (before 1st Sunday ends DST)
    } else {
        -8 // PST: November 8+ through early March
    }
}

/// Parse --bin argument from command line. Returns None if not specified.
fn parse_bin_path(args: &[String]) -> Option<PathBuf> {
    for i in 0..args.len() {
        if args[i] == "--bin" && i + 1 < args.len() {
            return Some(PathBuf::from(&args[i + 1]));
        }
    }
    None
}

/// Kill any running daemon and purge on-disk caches so the next `uffs` run
/// starts from a clean slate, loading only the drive we ask for.
///
/// Offline `--regenerate` uses `uffs --mft-file` via autospawn; if a daemon
/// from a previous drive/session is still resident it serves that stale
/// in-memory index instead (`--no-cache` only skips the cache *file*, not the
/// hot daemon). We don't know which drive/version a running daemon holds, so we
/// reset it.
fn purge_daemon_and_cache(uffs_bin: &Path) {
    let _ = Command::new(uffs_bin)
        .args(["--daemon", "kill"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
    std::thread::sleep(Duration::from_secs(1));

    // Best-effort cache removal across platforms.
    let mut cache_dirs: Vec<PathBuf> = Vec::new();
    if let Ok(local) = env::var("LOCALAPPDATA") {
        cache_dirs.push(PathBuf::from(local).join("uffs").join("cache")); // Windows
    }
    if let Ok(tmp) = env::var("TEMP") {
        cache_dirs.push(PathBuf::from(tmp).join("uffs_index_cache")); // Windows legacy
    }
    if let Ok(home) = env::var("HOME") {
        cache_dirs.push(PathBuf::from(&home).join("Library/Caches/uffs")); // macOS
        cache_dirs.push(PathBuf::from(&home).join(".cache/uffs")); // Linux
    }
    if let Ok(xdg) = env::var("XDG_CACHE_HOME") {
        cache_dirs.push(PathBuf::from(xdg).join("uffs"));
    }
    for dir in cache_dirs {
        if dir.exists() {
            let _ = fs::remove_dir_all(&dir);
        }
    }
}

fn regenerate_rust_output(
    data_dir: &Path,
    drive_letter: &str,
    drive_lower: &str,
    tz_offset: i32,
    custom_bin: Option<&Path>,
    pattern: &str,
    pipeline: Option<&str>,
) -> RegenerateResult {
    let tz_str = format!("{tz_offset}");
    let tz_label = match tz_offset {
        -7 => "PDT (Pacific Daylight)",
        -8 => "PST (Pacific Standard)",
        _ => "custom",
    };

    println!("Mode: --regenerate");
    println!("Using --tz-offset {tz_offset} ({tz_label}) to match the golden baseline timezone.");
    println!();

    // Locate MFT file - prefer IOCP capture (.iocp) over raw MFT (.bin)
    let iocp_file = data_dir.join(format!("{drive_letter}_mft.iocp"));
    let bin_file = data_dir.join(format!("{drive_letter}_mft.bin"));

    let (mft_file, mft_format) = if iocp_file.exists() {
        (iocp_file, "IOCP capture (Windows IOCP order replay)")
    } else if bin_file.exists() {
        (bin_file, "Raw MFT (sequential)")
    } else {
        eprintln!("╔══════════════════════════════════════════════════════════════╗");
        eprintln!("║  ❌ FATAL: No MFT file found for drive {}                    ", drive_letter);
        eprintln!("╚══════════════════════════════════════════════════════════════╝");
        eprintln!("  Looked for:");
        eprintln!("  - {} (IOCP capture, preferred)", iocp_file.display());
        eprintln!("  - {} (raw MFT, fallback)", bin_file.display());
        eprintln!();
        eprintln!("  Run test_runs.ps1 on Windows to collect MFT artifacts.");
        std::process::exit(1);
    };

    // Validate MFT file size (even the smallest NTFS MFT is >100 KB)
    if let Ok(meta) = fs::metadata(&mft_file) {
        if meta.len() < MIN_ARTIFACT_SIZE {
            eprintln!("╔══════════════════════════════════════════════════════════════╗");
            eprintln!("║  ❌ FATAL: MFT file is too small ({} bytes)           ", meta.len());
            eprintln!("║     File: {}", mft_file.display());
            eprintln!("║     Re-run test_runs.ps1 on Windows to regenerate.         ║");
            eprintln!("╚══════════════════════════════════════════════════════════════╝");
            std::process::exit(1);
        }
    }

    // Get MFT file size
    let mft_size_bytes = fs::metadata(&mft_file).map(|m| m.len()).unwrap_or(0);
    #[allow(clippy::cast_precision_loss)] // File sizes don't need full u64 precision
    let mft_mb = mft_size_bytes as f64 / (1024.0 * 1024.0);

    println!("MFT file:     {} ({mft_mb:.1} MB)", mft_file.display());
    println!("MFT format:   {mft_format}");

    // Determine which binary to use
    let binary_path = if let Some(custom) = custom_bin {
        println!("Using custom binary:   {}", custom.display());
        if !custom.exists() {
            eprintln!("ERROR: Custom binary not found: {}", custom.display());
            std::process::exit(1);
        }
        custom.to_path_buf()
    } else {
        // Locate authoritative workspace release artifact
        let artifact = find_workspace_release_artifact();
        println!(
            "Workspace root:        {}",
            artifact.workspace_root.display()
        );
        println!(
            "Cargo target dir:      {}",
            artifact.cargo_target_dir.display()
        );
        println!("UFFS release artifact: {}", artifact.binary_path.display());
        println!(
            "Artifact provenance:   cargo metadata target_directory → release/{}",
            uffs_binary_name()
        );
        if let Some(target_dir_warning) = artifact.target_dir_warning {
            println!("Target dir note:       {target_dir_warning}");
        }
        artifact.binary_path
    };
    println!();

    // Generate output
    let rust_output = data_dir.join(format!("verify_rust_{drive_lower}.txt"));
    println!("Running uffs scan (baseline-compatible algorithms)...");

    // Time the uffs execution
    let start_time = Instant::now();

    // Check for reserved_allocated.txt sidecar (C++ parity: root tree_allocated adjustment)
    let reserved_alloc_file = data_dir.join("reserved_allocated.txt");
    let reserved_alloc_value = if reserved_alloc_file.exists() {
        let content = fs::read_to_string(&reserved_alloc_file)
            .unwrap_or_default()
            .trim()
            .to_string();
        if content.is_empty() { None } else { Some(content) }
    } else {
        None
    };
    if let Some(ref val) = reserved_alloc_value {
        println!("Reserved allocated: {val} bytes (from {})", reserved_alloc_file.display());
    }

    let mut args = vec![
        pattern.to_string(),
        "--mft-file".to_string(),
        mft_file.to_string_lossy().to_string(),
        "--drive".to_string(),
        drive_letter.to_string(),
        "--tz-offset".to_string(),
        tz_str.clone(),
        "--no-cache".to_string(),  // Deterministic: always parse fresh MFT
        "--format".to_string(),
        "custom".to_string(), // Match C++ baseline format (includes footer)
        "--parity-compat".to_string(), // 25 C++ columns + masked attributes
        "--out".to_string(),
        rust_output.to_string_lossy().to_string(),
    ];
    if let Some(ref val) = reserved_alloc_value {
        args.push("--reserved-allocated".to_string());
        args.push(val.clone());
    }
    // NOTE: --pipeline flag removed from uffs binary (Step 4).
    let _ = pipeline;
    println!("Pipeline: unified (only pipeline)");

    // Clean slate: reset any daemon (it may hold a different drive/version from
    // an earlier run) so uffs loads only this drive's MFT via autospawn.
    print!("Resetting daemon + cache for a clean single-drive load...");
    io::stdout().flush().ok();
    purge_daemon_and_cache(&binary_path);
    println!(" ✅");

    let status = Command::new(&binary_path)
        .args(&args)
        .status();

    let parse_duration = start_time.elapsed();

    match status {
        Ok(s) if s.success() => {
            let throughput = mft_mb / parse_duration.as_secs_f64();
            println!(
                "  ✅ uffs scan completed in {} ({throughput:.1} MB/s)",
                format_duration(parse_duration),
            );
            println!();
        }
        Ok(s) => {
            eprintln!("ERROR: uffs exited with status {s}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("ERROR: Failed to run uffs: {e}");
            std::process::exit(1);
        }
    }

    RegenerateResult {
        output_path: rust_output,
        parse_duration,
        mft_size_bytes,
    }
}

/// Find the authoritative workspace release artifact via Cargo metadata.
fn find_workspace_release_artifact() -> UffsReleaseArtifact {
    let workspace_root = find_workspace_root();
    let cargo_target_dir = cargo_target_directory(&workspace_root);
    let target_dir_warning = literal_tilde_target_dir_warning(&cargo_target_dir);
    let release_artifact = cargo_target_dir.join("release").join(uffs_binary_name());
    if release_artifact.exists() {
        return UffsReleaseArtifact {
            workspace_root,
            cargo_target_dir,
            binary_path: release_artifact,
            target_dir_warning,
        };
    }

    eprintln!("ERROR: Fresh workspace release artifact not found.");
    eprintln!("  Workspace root: {}", workspace_root.display());
    eprintln!("  Cargo target dir: {}", cargo_target_dir.display());
    eprintln!(
        "  Expected release artifact: {}",
        release_artifact.display()
    );
    if let Some(target_dir_warning) = target_dir_warning {
        eprintln!("  Target dir note: {target_dir_warning}");
        eprintln!(
            "  Fix the checked-in config or set CARGO_TARGET_DIR to an explicit absolute path before rebuilding."
        );
    }
    eprintln!("  Build it first with: cargo build --release -p uffs-cli --bin uffs");
    std::process::exit(1);
}

fn literal_tilde_target_dir_warning(target_dir: &Path) -> Option<&'static str> {
    path_has_literal_tilde_component(target_dir).then_some(
        "literal `~` path component detected; Cargo config paths are config-relative, not home-directory expansions",
    )
}

fn path_has_literal_tilde_component(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "~")
}

fn cargo_target_directory(workspace_root: &Path) -> PathBuf {
    let output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(workspace_root)
        .output()
        .unwrap_or_else(|error| {
            eprintln!("ERROR: Failed to run cargo metadata: {error}");
            std::process::exit(1);
        });

    if !output.status.success() {
        eprintln!("ERROR: cargo metadata failed with status {}", output.status);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            eprintln!("  stderr: {}", stderr.trim());
        }
        std::process::exit(1);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let raw_target_dir =
        extract_json_string_field(&stdout, "target_directory").unwrap_or_else(|| {
            eprintln!("ERROR: cargo metadata output did not contain target_directory");
            std::process::exit(1);
        });

    let target_dir = PathBuf::from(raw_target_dir);
    if target_dir.is_absolute() {
        target_dir
    } else {
        workspace_root.join(target_dir)
    }
}

fn extract_json_string_field(json: &str, field_name: &str) -> Option<String> {
    let needle = format!("\"{field_name}\":\"");
    let start = json.find(&needle)? + needle.len();
    let mut result = String::new();
    let mut escaped = false;

    for ch in json[start..].chars() {
        if escaped {
            match ch {
                '"' | '\\' | '/' => result.push(ch),
                'b' => result.push('\u{0008}'),
                'f' => result.push('\u{000C}'),
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                _ => return None,
            }
            escaped = false;
            continue;
        }

        match ch {
            '\\' => escaped = true,
            '"' => return Some(result),
            _ => result.push(ch),
        }
    }

    None
}

const fn uffs_binary_name() -> &'static str {
    if cfg!(windows) {
        "uffs.exe"
    } else {
        "uffs"
    }
}

/// Find the workspace root by looking for Cargo.toml starting from the script
/// location.
fn find_workspace_root() -> PathBuf {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
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

/// Open a file with retry logic for race conditions (e.g. concurrent builds).
///
/// Retries up to `max_retries` times with `delay` between attempts.
/// On final failure, prints a clean error and exits instead of panicking.
fn open_file_with_retry(path: &Path, max_retries: u32, delay: std::time::Duration) -> fs::File {
    let mut last_err = String::new();
    for attempt in 0..=max_retries {
        match fs::File::open(path) {
            Ok(f) => {
                if attempt > 0 {
                    eprintln!(
                        "  ℹ️  File appeared after {} retries: {}",
                        attempt,
                        path.display()
                    );
                }
                return f;
            }
            Err(e) => {
                last_err = format!("{e}");
                if attempt < max_retries {
                    eprintln!(
                        "  ⏳ File not ready (attempt {}/{}): {} — retrying in {}s...",
                        attempt + 1,
                        max_retries,
                        path.display(),
                        delay.as_secs()
                    );
                    std::thread::sleep(delay);
                }
            }
        }
    }
    eprintln!(
        "\n  ❌ Could not open file after {} retries: {}\n     Error: {}\n",
        max_retries,
        path.display(),
        last_err
    );
    std::process::exit(1);
}


/// FNV-1a hash of a byte slice (fast, non-cryptographic, for fingerprinting).
fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Compute streaming file stats in a single pass (no full file in memory).
/// Returns ordered SHA256, line count, and order-independent fingerprints.
///
/// Uses `open_file_with_retry` for resilience against race conditions.
fn compute_streaming_stats(path: &Path) -> StreamingFileStats {
    let file = open_file_with_retry(path, 3, std::time::Duration::from_secs(2));
    let reader = BufReader::with_capacity(256 * 1024, file);

    let mut ordered_hasher = Sha256::new();
    let mut line_count: usize = 0;
    let mut xor_fp: u64 = 0;
    let mut sum_fp: u128 = 0;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "  ❌ Read error at line {} of {}: {e}",
                    line_count + 1,
                    path.display()
                );
                break;
            }
        };
        // Ordered hash: feed each line + newline
        ordered_hasher.update(line.as_bytes());
        ordered_hasher.update(b"\n");
        // Order-independent: FNV-1a per line, XOR and sum
        let h = fnv1a_64(line.as_bytes());
        xor_fp ^= h;
        sum_fp = sum_fp.wrapping_add(h as u128);
        line_count += 1;
    }

    StreamingFileStats {
        ordered_hash: format!("{:x}", ordered_hasher.finalize()),
        line_count,
        xor_fingerprint: xor_fp,
        sum_fingerprint: sum_fp,
    }
}

/// File identity used to validate a cached fingerprint: (size_bytes, mtime_nanos).
fn file_identity(path: &Path) -> Option<(u64, u128)> {
    let meta = fs::metadata(path).ok()?;
    let mtime_ns = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some((meta.len(), mtime_ns))
}

/// Sidecar path holding the cached streaming stats for a baseline file.
fn parity_hash_sidecar(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".parityhash");
    path.with_file_name(name)
}

/// Load cached `StreamingFileStats` for `path`, but only if the sidecar's
/// recorded (size, mtime) matches the current file (else the baseline changed).
fn load_cached_stats(path: &Path, identity: (u64, u128)) -> Option<StreamingFileStats> {
    let contents = fs::read_to_string(parity_hash_sidecar(path)).ok()?;
    let (mut size, mut mtime_ns): (Option<u64>, Option<u128>) = (None, None);
    let (mut ordered_hash, mut line_count): (Option<String>, Option<usize>) = (None, None);
    let (mut xor_fp, mut sum_fp): (Option<u64>, Option<u128>) = (None, None);
    for line in contents.lines() {
        let mut parts = line.splitn(2, ' ');
        let key = parts.next().unwrap_or("");
        let val = parts.next().unwrap_or("");
        match key {
            "size" => size = val.parse().ok(),
            "mtime_ns" => mtime_ns = val.parse().ok(),
            "ordered_hash" => ordered_hash = Some(val.to_string()),
            "line_count" => line_count = val.parse().ok(),
            "xor_fingerprint" => xor_fp = val.parse().ok(),
            "sum_fingerprint" => sum_fp = val.parse().ok(),
            _ => {}
        }
    }
    if size? != identity.0 || mtime_ns? != identity.1 {
        return None;
    }
    Some(StreamingFileStats {
        ordered_hash: ordered_hash?,
        line_count: line_count?,
        xor_fingerprint: xor_fp?,
        sum_fingerprint: sum_fp?,
    })
}

/// Persist `StreamingFileStats` to the sidecar cache (best-effort; failures
/// just mean the next run recomputes).
fn store_cached_stats(path: &Path, identity: (u64, u128), stats: &StreamingFileStats) {
    let body = format!(
        "parityhash v1\nsize {}\nmtime_ns {}\nordered_hash {}\nline_count {}\nxor_fingerprint {}\nsum_fingerprint {}\n",
        identity.0,
        identity.1,
        stats.ordered_hash,
        stats.line_count,
        stats.xor_fingerprint,
        stats.sum_fingerprint,
    );
    let _ = fs::write(parity_hash_sidecar(path), body);
}

/// Like `compute_streaming_stats`, but caches the result in a `.parityhash`
/// sidecar keyed on (size, mtime).  Intended for the immutable golden baseline:
/// reruns skip rehashing the multi-GB `cpp_*.txt` unless it actually changes.
/// Returns `(stats, cache_hit)`.
fn compute_streaming_stats_cached(path: &Path) -> (StreamingFileStats, bool) {
    let Some(identity) = file_identity(path) else {
        // Could not stat the file → fall back to an uncached compute.
        return (compute_streaming_stats(path), false);
    };
    if let Some(cached) = load_cached_stats(path, identity) {
        return (cached, true);
    }
    let stats = compute_streaming_stats(path);
    store_cached_stats(path, identity, &stats);
    (stats, false)
}

/// Check if two files have the same lines (order-independent) using streaming stats.
fn is_sorted_match(a: &StreamingFileStats, b: &StreamingFileStats) -> bool {
    a.line_count == b.line_count
        && a.xor_fingerprint == b.xor_fingerprint
        && a.sum_fingerprint == b.sum_fingerprint
}

/// Compute the symmetric difference between two files using HashMap<u64_hash, count>.
/// Returns (only_in_a_hashes, only_in_b_hashes).
/// For display, returns the actual line strings of the differences (re-reads files).
/// Memory: O(n) with u64 keys (~16 bytes per entry) instead of full strings.
/// Detailed result from a streaming diff comparison, including filter
/// statistics so callers can detect when filtering is hiding real gaps.
/// Maximum number of diff lines to display per category.
const MAX_DIFF_DISPLAY: usize = 100;

struct DiffResult {
    /// Lines only in baseline (Rust is MISSING these — ALL types, no filtering
    /// except header/footer). ADS entries are treated as regular data.
    only_in_baseline: Vec<String>,
    /// Lines only in Rust (extra entries — usually hardlinks or ADS).
    only_in_rust: Vec<String>,
    /// Total data lines in baseline (excluding header/footer).
    baseline_data_lines: usize,
    /// Total data lines in Rust (excluding header/footer).
    rust_data_lines: usize,
    /// Header/footer lines filtered from baseline.
    baseline_header_footer_filtered: usize,
    /// Header/footer lines filtered from Rust.
    rust_header_footer_filtered: usize,
}

fn compute_streaming_diff(
    baseline_path: &Path,
    rust_path: &Path,
) -> DiffResult {
    // Phase 1: Build HashMap<u64, i64> from baseline (positive counts).
    // ADS lines are included as regular data — classification happens post-diff.
    let mut counts: HashMap<u64, i64> = HashMap::new();
    let mut baseline_data_lines: usize = 0;
    let mut baseline_header_footer_filtered: usize = 0;
    {
        let file = fs::File::open(baseline_path)
            .unwrap_or_else(|e| panic!("Failed to open {}: {e}", baseline_path.display()));
        let reader = BufReader::with_capacity(256 * 1024, file);
        for line in reader.lines() {
            let line = line.unwrap_or_else(|e| panic!("Read error: {e}"));
            if is_footer_or_header_line(&line) {
                baseline_header_footer_filtered += 1;
                continue;
            }
            baseline_data_lines += 1;
            let h = fnv1a_64(line.as_bytes());
            *counts.entry(h).or_insert(0) += 1;
        }
    }

    // Phase 2: Stream Rust file, decrement matching counts
    let mut only_in_rust_hashes: HashSet<u64> = HashSet::new();
    let mut rust_data_lines: usize = 0;
    let mut rust_header_footer_filtered: usize = 0;
    {
        let file = open_file_with_retry(rust_path, 3, std::time::Duration::from_secs(2));
        let reader = BufReader::with_capacity(256 * 1024, file);
        for line in reader.lines() {
            let line = line.unwrap_or_else(|e| panic!("Read error: {e}"));
            if is_footer_or_header_line(&line) {
                rust_header_footer_filtered += 1;
                continue;
            }
            rust_data_lines += 1;
            let h = fnv1a_64(line.as_bytes());
            let count = counts.entry(h).or_insert(0);
            if *count > 0 {
                *count -= 1;
            } else {
                only_in_rust_hashes.insert(h);
            }
        }
    }

    // Collect hashes only in baseline (count still > 0)
    let only_in_baseline_hashes: HashSet<u64> = counts
        .iter()
        .filter(|(_, &count)| count > 0)
        .map(|(&h, _)| h)
        .collect();

    // Phase 3: Re-read files to collect actual diff lines (only header/footer filtered).
    let only_in_baseline: Vec<String> = if only_in_baseline_hashes.is_empty() {
        Vec::new()
    } else {
        let file = fs::File::open(baseline_path)
            .unwrap_or_else(|e| panic!("Failed to open {}: {e}", baseline_path.display()));
        let reader = BufReader::with_capacity(256 * 1024, file);
        reader
            .lines()
            .filter_map(|line| {
                let line = line.unwrap_or_else(|e| panic!("Read error: {e}"));
                if is_footer_or_header_line(&line) {
                    return None;
                }
                let h = fnv1a_64(line.as_bytes());
                if only_in_baseline_hashes.contains(&h) {
                    Some(line)
                } else {
                    None
                }
            })
            .collect()
    };

    let only_in_rust: Vec<String> = if only_in_rust_hashes.is_empty() {
        Vec::new()
    } else {
        let file = open_file_with_retry(rust_path, 3, std::time::Duration::from_secs(2));
        let reader = BufReader::with_capacity(256 * 1024, file);
        reader
            .lines()
            .filter_map(|line| {
                let line = line.unwrap_or_else(|e| panic!("Read error: {e}"));
                if is_footer_or_header_line(&line) {
                    return None;
                }
                let h = fnv1a_64(line.as_bytes());
                if only_in_rust_hashes.contains(&h) {
                    Some(line)
                } else {
                    None
                }
            })
            .collect()
    };

    DiffResult {
        only_in_baseline,
        only_in_rust,
        baseline_data_lines,
        rust_data_lines,
        baseline_header_footer_filtered,
        rust_header_footer_filtered,
    }
}

fn read_lines(path: &Path) -> Vec<String> {
    let file =
        fs::File::open(path).unwrap_or_else(|e| panic!("Failed to open {}: {e}", path.display()));
    let reader = BufReader::new(file);
    reader
        .lines()
        .map(|line| line.unwrap_or_else(|e| panic!("Failed to read line: {e}")))
        .collect()
}

// --- Legacy functions (used by tests) ---

#[allow(dead_code)]
fn ordered_sha256(lines: &[String]) -> String {
    sha256_for_lines(lines.iter().map(String::as_str))
}

#[allow(dead_code)]
fn sorted_sha256(lines: &[String]) -> String {
    let mut indexed: Vec<(usize, &str)> = lines.iter().map(String::as_str).enumerate().collect();
    // Stable sort with byte-level comparison for cross-platform consistency
    indexed.sort_by(|(idx_a, a), (idx_b, b)| {
        match a.as_bytes().cmp(b.as_bytes()) {
            std::cmp::Ordering::Equal => idx_a.cmp(idx_b),
            other => other,
        }
    });
    sha256_for_lines(indexed.into_iter().map(|(_, s)| s))
}

#[allow(dead_code)]
fn sha256_for_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    for line in lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

/// Check if a line is a C++ footer/header line (not a data row).
/// Footer lines include: "Drives?", "MMMmmm that was FAST", "Search path",
/// blank lines, and the column header line.
fn is_footer_or_header_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty()
        || trimmed.starts_with("Drives?")
        || trimmed.starts_with("MMMmmm that was FAST")
        || trimmed.starts_with("Search path")
        || trimmed.starts_with("\"Path\"")  // CSV header
        || trimmed.starts_with("Path\t")    // TSV header
}

/// Filter lines to data rows (no footer/header).
/// Returns sorted filtered lines for subset comparison.
#[allow(dead_code)]
fn filter_data_lines(lines: &[String]) -> Vec<String> {
    let mut filtered: Vec<String> = lines
        .iter()
        .filter(|line| !is_footer_or_header_line(line))
        .cloned()
        .collect();
    filtered.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    filtered
}

/// Check if `subset` lines are all contained in `superset` lines.
/// Both inputs must be sorted. Returns lines only in subset (should be empty
/// for a valid superset) and lines only in superset (extra Rust hardlinks).
#[allow(dead_code)]
fn check_sorted_subset(subset: &[String], superset: &[String]) -> (Vec<String>, Vec<String>) {
    let mut only_in_subset = Vec::new();
    let mut only_in_superset = Vec::new();

    let mut is = 0;
    let mut ip = 0;

    while is < subset.len() && ip < superset.len() {
        match subset[is].as_bytes().cmp(superset[ip].as_bytes()) {
            Ordering::Equal => {
                is += 1;
                ip += 1;
            }
            Ordering::Less => {
                only_in_subset.push(subset[is].clone());
                is += 1;
            }
            Ordering::Greater => {
                only_in_superset.push(superset[ip].clone());
                ip += 1;
            }
        }
    }

    while is < subset.len() {
        only_in_subset.push(subset[is].clone());
        is += 1;
    }
    while ip < superset.len() {
        only_in_superset.push(superset[ip].clone());
        ip += 1;
    }

    (only_in_subset, only_in_superset)
}



/// Show paired diffs: match by path, display BASELINE vs RUST side by side.
/// Display diff lines (up to MAX_DIFF_DISPLAY), truncating long lines.
fn show_diff_lines(lines: &[String]) {
    let show = lines.len().min(MAX_DIFF_DISPLAY);
    for (i, line) in lines.iter().enumerate().take(show) {
        let display = if line.len() > 200 {
            format!("{}…", &line[..200])
        } else {
            line.clone()
        };
        println!("       {:>3}. {display}", i + 1);
    }
    if lines.len() > show {
        println!("       ... and {} more", lines.len() - show);
    }
}

/// Verify that extra Rust data lines are hardlinks (inline version for
/// verify_single_drive).
fn verify_hardlinks_inline(golden_baseline_file: &Path, only_in_rust_data: &[String]) {
    let common_fingerprints: HashSet<String> = {
        let file = fs::File::open(golden_baseline_file)
            .unwrap_or_else(|e| panic!("Failed to open {}: {e}", golden_baseline_file.display()));
        let reader = BufReader::with_capacity(256 * 1024, file);
        reader
            .lines()
            .filter_map(|line| {
                let line = line.unwrap_or_else(|e| panic!("Read error: {e}"));
                if is_footer_or_header_line(&line) {
                    return None;
                }
                extract_data_fingerprint(&line)
            })
            .collect()
    };

    let mut extra_fingerprints: HashMap<String, usize> = HashMap::new();
    for line in only_in_rust_data {
        if let Some(fp) = extract_data_fingerprint(line) {
            *extra_fingerprints.entry(fp).or_insert(0) += 1;
        }
    }

    let mut verified_hardlinks = Vec::new();
    let mut unverified_extras = Vec::new();

    for line in only_in_rust_data {
        let path = extract_path(line);
        if let Some(fp) = extract_data_fingerprint(line) {
            if common_fingerprints.contains(&fp)
                || extra_fingerprints.get(&fp).copied().unwrap_or(0) > 1
            {
                verified_hardlinks.push((path, fp));
            } else {
                unverified_extras.push((path, fp));
            }
        } else {
            unverified_extras.push((path, String::from("(unparseable)")));
        }
    }

    println!();
    println!(
        "     Hardlink verification: {} verified, {} unverified",
        verified_hardlinks.len(),
        unverified_extras.len()
    );

    if !verified_hardlinks.is_empty() {
        println!();
        println!("     ✅ Verified hardlinks (same size+timestamps as another entry):");
        for (i, (path, _fp)) in verified_hardlinks.iter().enumerate().take(20) {
            println!("       {:>3}. {}", i + 1, path);
        }
        if verified_hardlinks.len() > 20 {
            println!("       ... and {} more", verified_hardlinks.len() - 20);
        }
    }

    if !unverified_extras.is_empty() {
        println!();
        println!("     ⚠️  UNVERIFIED extra Rust lines (NOT confirmed as hardlinks):");
        for (i, (path, fp)) in unverified_extras.iter().enumerate().take(20) {
            println!("       {:>3}. {} [fingerprint: {}]", i + 1, path, fp);
        }
        if unverified_extras.len() > 20 {
            println!("       ... and {} more", unverified_extras.len() - 20);
        }
    }
}


/// CSV column indices (0-based) in the DisplayRow output:
/// 0=path 1=name 2=parent 3=size 4=allocated 5=created 6=modified
/// 7=accessed 8=descendant-count …
const COL_SIZE: usize = 3;
const COL_ALLOCATED: usize = 4;
const COL_ACCESSED: usize = 7;
const COL_COUNT: usize = 8;

/// NTFS / OS "master" view of paths that mutate constantly, so two independent
/// live reads of the same volume legitimately disagree there: NTFS metafiles
/// (`$Extend`/`$UsnJrnl`/`$LogFile`/`$MFT`…), the recycle bin, VSS snapshots,
/// paging files, AV sandboxes, and this harness's own scratch dirs.
fn is_ntfs_volatile_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    const VOLATILE_SUBSTR: &[&str] = &[
        r"\$recycle.bin\",
        r"\system volume information\",
        r"\$extend\",        // $UsnJrnl, $RmMetadata, $TxfLog, $Repair, …
        r"\norton sandbox\", // Norton AV live sandbox churn
        "idx-delta-verify",  // this script's own scratch directories
    ];
    if VOLATILE_SUBSTR.iter().any(|s| p.contains(s)) {
        return true;
    }
    // Root-level NTFS metafiles + OS paging files (e.g. C:\$MFT, C:\pagefile.sys).
    const VOLATILE_LEAF: &[&str] = &[
        r"\$mft",
        r"\$mftmirr",
        r"\$logfile",
        r"\$volume",
        r"\$attrdef",
        r"\$bitmap",
        r"\$boot",
        r"\$badclus",
        r"\$secure",
        r"\$upcase",
        r"\$extend",
        r"\pagefile.sys",
        r"\hiberfil.sys",
        r"\swapfile.sys",
        r"\dumpstack.log.tmp",
    ];
    let trimmed = p.trim_end_matches('\\');
    VOLATILE_LEAF.iter().any(|leaf| trimmed.ends_with(leaf))
}

/// Classify a same-path (baseline, rust) line pair from a LIVE run. Returns
/// `Some(reason)` when the only differences are ones a live volume mutates
/// between two reads — read-time skew, not a parser disagreement — and `None`
/// when a structural field differs (a real diff).
///
/// Tolerated: the accessed timestamp always (directory atime bumps on
/// traversal), and — for a directory — the subtree size/count aggregates
/// (derived from children that may have changed in the gap between the two
/// reads). Any path NTFS treats as volatile is tolerated wholesale.
fn classify_live_skew(baseline: &str, rust: &str) -> Option<&'static str> {
    let bf = split_csv_fields(baseline);
    let rf = split_csv_fields(rust);
    if bf.is_empty() || bf.len() != rf.len() {
        return None;
    }
    let path = bf[0].trim_matches('"');
    if is_ntfs_volatile_path(path) {
        return Some("volatile NTFS/OS path");
    }
    let is_dir = path.ends_with('\\');
    let mut accessed_only = true;
    let mut any_diff = false;
    for (i, (b, r)) in bf.iter().zip(rf.iter()).enumerate() {
        if b == r {
            continue;
        }
        any_diff = true;
        if i == COL_ACCESSED {
            continue;
        }
        if is_dir && (i == COL_SIZE || i == COL_ALLOCATED || i == COL_COUNT) {
            // Size, size-on-disk, and descendant count are all subtree
            // aggregates that move when a child changes between the two reads.
            accessed_only = false;
            continue;
        }
        return None; // a structural field differs — real diff
    }
    if !any_diff {
        return None;
    }
    Some(if accessed_only {
        "accessed-time only"
    } else {
        "dir aggregate + accessed-time"
    })
}

/// Reconcile benign live-read skew in place: pair `only_in_baseline` with
/// `only_in_rust` by path and drop pairs that are read-time skew per
/// [`classify_live_skew`]. Returns `(tolerated_count, samples)` where `samples`
/// is a capped `(path, reason)` list for the report. Hardlink-only paths
/// (present on one side only) are untouched, so a genuine superset stays a
/// superset.
///
/// LIVE MODE ONLY — offline reads a frozen capture, where such a diff would be
/// a real parser bug worth surfacing (e.g. the C: / F: known issues), so the
/// offline verdict deliberately does NOT call this.
fn reconcile_live_skew(diff: &mut DiffResult) -> (usize, Vec<(String, &'static str)>) {
    if diff.only_in_baseline.is_empty() || diff.only_in_rust.is_empty() {
        return (0, Vec::new());
    }
    let mut rust_by_path: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, line) in diff.only_in_rust.iter().enumerate() {
        rust_by_path.entry(extract_path(line)).or_default().push(i);
    }
    let mut drop_baseline = vec![false; diff.only_in_baseline.len()];
    let mut drop_rust = vec![false; diff.only_in_rust.len()];
    let mut samples: Vec<(String, &'static str)> = Vec::new();
    let mut tolerated = 0_usize;
    for (bi, bline) in diff.only_in_baseline.iter().enumerate() {
        let path = extract_path(bline);
        let Some(idxs) = rust_by_path.get(&path) else {
            continue;
        };
        for &ri in idxs {
            if drop_rust[ri] {
                continue;
            }
            if let Some(reason) = classify_live_skew(bline, &diff.only_in_rust[ri]) {
                drop_baseline[bi] = true;
                drop_rust[ri] = true;
                tolerated += 1;
                if samples.len() < 20 {
                    samples.push((path.clone(), reason));
                }
                break;
            }
        }
    }
    if tolerated == 0 {
        return (0, Vec::new());
    }
    let mut bi = 0;
    diff.only_in_baseline.retain(|_| {
        let keep = !drop_baseline[bi];
        bi += 1;
        keep
    });
    let mut ri = 0;
    diff.only_in_rust.retain(|_| {
        let keep = !drop_rust[ri];
        ri += 1;
        keep
    });
    (tolerated, samples)
}

/// For lines that share the same path but differ in field values (size, timestamps,
/// flags), shows them paired. Lines only in one side are shown separately.
fn show_paired_diffs(only_in_baseline: &[String], only_in_rust: &[String]) {
    // Index both sides by path (first quoted field)
    let mut baseline_by_path: HashMap<String, Vec<&str>> = HashMap::new();
    for line in only_in_baseline {
        let path = extract_path(line);
        baseline_by_path.entry(path).or_default().push(line);
    }
    let mut rust_by_path: HashMap<String, Vec<&str>> = HashMap::new();
    for line in only_in_rust {
        let path = extract_path(line);
        rust_by_path.entry(path).or_default().push(line);
    }

    // Categorize: paired (same path, different data) vs one-side-only
    let mut paired: Vec<(&str, &str)> = Vec::new(); // (baseline_line, rust_line)
    let mut only_baseline: Vec<&str> = Vec::new();
    let mut only_rust: Vec<&str> = Vec::new();

    for (path, b_lines) in &baseline_by_path {
        if let Some(r_lines) = rust_by_path.get(path) {
            // Pair them up (usually 1:1)
            let count = b_lines.len().max(r_lines.len());
            for i in 0..count {
                let b = b_lines.get(i).copied().unwrap_or("(missing)");
                let r = r_lines.get(i).copied().unwrap_or("(missing)");
                paired.push((b, r));
            }
        } else {
            for line in b_lines {
                only_baseline.push(line);
            }
        }
    }
    for (path, r_lines) in &rust_by_path {
        if !baseline_by_path.contains_key(path) {
            for line in r_lines {
                only_rust.push(line);
            }
        }
    }

    // Sort for consistent output
    paired.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    only_baseline.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    only_rust.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    // === Paired diffs (same path, different field values) ===
    if !paired.is_empty() {
        let total = paired.len();
        let head = 50.min(total);
        let tail = 50.min(total);

        println!("     ── FIELD DIFFERENCES ({} paths with different values) ──", total);
        println!();

        // First 50
        for (_i, (b, r)) in paired.iter().enumerate().take(head) {
            println!("       BASELINE: {}", b);
            println!("       RUST:     {}", r);
            println!();
        }

        // 100 random from middle
        if total > head + tail + 10 {
            let mid_start = head;
            let mid_end = total.saturating_sub(tail);
            let mid_count = mid_end - mid_start;
            let sample_count = 100.min(mid_count);
            println!(
                "     ── {} RANDOM DIFFERENCES FROM MIDDLE ({} middle diffs) ──",
                sample_count, mid_count
            );
            println!();
            let step = if sample_count < mid_count {
                let mut s = mid_count / sample_count;
                if s < 2 { s = 2; }
                if s % 2 == 0 { s += 1; }
                s
            } else {
                1
            };
            let mut idx = mid_start;
            let mut shown = 0;
            while shown < sample_count && idx < mid_end {
                let (b, r) = &paired[idx];
                println!("       BASELINE: {}", b);
                println!("       RUST:     {}", r);
                println!();
                idx += step;
                shown += 1;
            }
        }

        // Last 50
        if total > head {
            let tail_start = total.saturating_sub(tail);
            println!("     ── Last {} ──", total - tail_start);
            println!();
            for i in tail_start..total {
                let (b, r) = &paired[i];
                println!("       BASELINE: {}", b);
                println!("       RUST:     {}", r);
                println!();
            }
        }
    }

    // === Lines only in baseline (C++ has, Rust doesn't — even after ADS filter) ===
    if !only_baseline.is_empty() {
        println!(
            "     ── ONLY IN BASELINE ({} lines — missing from Rust) ──",
            only_baseline.len()
        );
        println!();
        for (i, line) in only_baseline.iter().enumerate().take(50) {
            println!("       {:>5}. {}", i + 1, line);
        }
        if only_baseline.len() > 50 {
            println!("       ... and {} more", only_baseline.len() - 50);
        }
        println!();
    }

    // === Lines only in Rust (extra entries — hardlinks, ADS, etc.) ===
    if !only_rust.is_empty() {
        println!(
            "     ── ONLY IN RUST ({} lines — extra entries) ──",
            only_rust.len()
        );
        println!();
        for (i, line) in only_rust.iter().enumerate().take(50) {
            println!("       {:>5}. {}", i + 1, line);
        }
        if only_rust.len() > 50 {
            println!("       ... and {} more", only_rust.len() - 50);
        }
        println!();
    }
}

/// Extract the path (first quoted field) from a CSV line for display.
/// E.g. `"G:\path\file.txt","file.txt",...` → `"G:\path\file.txt"`
fn extract_path(line: &str) -> String {
    line.find("\",")
        .map(|pos| line[..pos + 1].to_string())
        .unwrap_or_else(|| line.to_string())
}

/// Extract a data fingerprint from a CSV line: Size + Created + Modified + Accessed.
///
/// Parity-compat CSV format:
/// `"Path","Name","PathOnly",Size,SizeOnDisk,Created,Modified,Accessed,...`
///  col 0   col 1  col 2    col3  col4       col5    col6     col7
///
/// Hardlinks share the same MFT file record, so they have identical
/// Size, SizeOnDisk, Created, Modified, and Accessed values.
/// If two lines have different paths but the same fingerprint, they're hardlinks.
fn extract_data_fingerprint(line: &str) -> Option<String> {
    // Split CSV respecting quotes. Fields 3-7 are: Size, SizeOnDisk, Created, Modified, Accessed
    let fields = split_csv_fields(line);
    if fields.len() >= 8 {
        // Fingerprint = Size|SizeOnDisk|Created|Modified|Accessed
        Some(format!(
            "{}|{}|{}|{}|{}",
            fields[3], fields[4], fields[5], fields[6], fields[7]
        ))
    } else {
        None
    }
}

/// Split a CSV line into fields, respecting quoted fields.
fn split_csv_fields(line: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let bytes = line.as_bytes();

    for i in 0..bytes.len() {
        if bytes[i] == b'"' {
            in_quotes = !in_quotes;
        } else if bytes[i] == b',' && !in_quotes {
            fields.push(&line[start..i]);
            start = i + 1;
        }
    }
    // Last field
    if start <= line.len() {
        fields.push(&line[start..]);
    }
    fields
}

// Note: ordered diff functions kept for debugging but not used in main flow.
// Sorted comparison is the meaningful one since C++ and Rust walk differently.

#[allow(dead_code)]
fn collect_ordered_diffs(
    file_a: &Path,
    file_b: &Path,
) -> Vec<(usize, Option<String>, Option<String>)> {
    let lines_a = read_lines(file_a);
    let lines_b = read_lines(file_b);
    let max_len = lines_a.len().max(lines_b.len());
    let mut diffs = Vec::new();

    for index in 0..max_len {
        match (lines_a.get(index), lines_b.get(index)) {
            (Some(a), Some(b)) if a == b => {}
            (Some(a), Some(b)) => diffs.push((index + 1, Some(a.clone()), Some(b.clone()))),
            (Some(a), None) => diffs.push((index + 1, Some(a.clone()), None)),
            (None, Some(b)) => diffs.push((index + 1, None, Some(b.clone()))),
            (None, None) => {}
        }
    }
    diffs
}

#[allow(dead_code)]
fn show_first_ordered_diffs(file_a: &Path, file_b: &Path) {
    let diffs = collect_ordered_diffs(file_a, file_b);

    if diffs.is_empty() {
        println!("No ordered differences found.");
        return;
    }

    println!("Total ordered differences: {}", diffs.len());
    println!();

    // First 5
    let first_n = 5.min(diffs.len());
    println!("=== FIRST {first_n} DIFFERENCES ===");
    for (line_num, baseline, rust) in diffs.iter().take(first_n) {
        print_diff_pair(*line_num, baseline.as_deref(), rust.as_deref());
    }

    if diffs.len() <= 10 {
        return; // Already showed everything
    }

    // Last 5
    let last_start = diffs.len().saturating_sub(5);
    println!("\n=== LAST 5 DIFFERENCES ===");
    for (line_num, baseline, rust) in diffs.iter().skip(last_start) {
        print_diff_pair(*line_num, baseline.as_deref(), rust.as_deref());
    }

    // 10 random from middle (if enough diffs)
    if diffs.len() > 10 {
        let middle_start = first_n;
        let middle_end = last_start;
        if middle_end > middle_start {
            println!("\n=== 10 RANDOM MIDDLE DIFFERENCES ===");
            let middle: Vec<_> = diffs[middle_start..middle_end].to_vec();
            let sample_count = 10.min(middle.len());
            let mut rng_seed = diffs.len() as u64; // deterministic seed
            let mut indices: Vec<usize> = (0..middle.len()).collect();
            // Simple shuffle with LCG
            for i in (1..indices.len()).rev() {
                rng_seed = rng_seed.wrapping_mul(LCG_MULTIPLIER).wrapping_add(1);
                #[allow(clippy::cast_possible_truncation)]
                let j = (rng_seed as usize) % (i + 1);
                indices.swap(i, j);
            }
            for &idx in indices.iter().take(sample_count) {
                let (line_num, baseline, rust) = &middle[idx];
                print_diff_pair(*line_num, baseline.as_deref(), rust.as_deref());
            }
        }
    }
}

#[allow(dead_code)]
fn print_diff_pair(line_num: usize, baseline: Option<&str>, rust: Option<&str>) {
    match (baseline, rust) {
        (Some(b), Some(r)) => {
            println!("  Line {line_num}:");
            println!("    BASELINE: {b}");
            println!("    RUST:     {r}");
        }
        (Some(b), None) => {
            println!("  Line {line_num} BASELINE ONLY:");
            println!("    {b}");
        }
        (None, Some(r)) => {
            println!("  Line {line_num} RUST ONLY:");
            println!("    {r}");
        }
        (None, None) => {}
    }
}

/// Collect all sorted multiset differences.
#[allow(dead_code)]
fn collect_sorted_diffs(file_a: &Path, file_b: &Path) -> (Vec<String>, Vec<String>) {
    let lines_a = read_sorted_lines(file_a);
    let lines_b = read_sorted_lines(file_b);

    let mut only_a = Vec::new();
    let mut only_b = Vec::new();

    let mut ia = 0;
    let mut ib = 0;

    while ia < lines_a.len() && ib < lines_b.len() {
        match lines_a[ia].cmp(&lines_b[ib]) {
            Ordering::Equal => {
                ia += 1;
                ib += 1;
            }
            Ordering::Less => {
                only_a.push(lines_a[ia].clone());
                ia += 1;
            }
            Ordering::Greater => {
                only_b.push(lines_b[ib].clone());
                ib += 1;
            }
        }
    }
    while ia < lines_a.len() {
        only_a.push(lines_a[ia].clone());
        ia += 1;
    }
    while ib < lines_b.len() {
        only_b.push(lines_b[ib].clone());
        ib += 1;
    }
    (only_a, only_b)
}

/// Show side-by-side comparison of DIFFERENT lines from sorted files.
/// Only shows lines where baseline != rust. First 5 diffs, last 5 diffs, 10
/// random from middle.
#[allow(dead_code)]
fn show_first_sorted_diffs(file_a: &Path, file_b: &Path) {
    let sorted_baseline = read_sorted_lines(file_a);
    let sorted_rust = read_sorted_lines(file_b);

    let n = sorted_baseline.len().min(sorted_rust.len());
    if n == 0 {
        println!("No lines to compare.");
        return;
    }

    // Collect indices of lines that differ.
    // With --parity-compat, uffs outputs exactly 25 C++ baseline columns
    // with masked attributes (15 bits), so direct comparison is correct.
    let diff_indices: Vec<usize> = (0..n)
        .filter(|&i| sorted_baseline[i] != sorted_rust[i])
        .collect();

    println!("\n=== SORTED SIDE-BY-SIDE COMPARISON (differences only) ===");
    println!("  Baseline lines: {}", sorted_baseline.len());
    println!("  Rust lines:     {}", sorted_rust.len());
    println!("  Lines that differ: {}", diff_indices.len());

    if diff_indices.is_empty() {
        println!("\n  ✅ All lines match!");
        return;
    }

    let total_diffs = diff_indices.len();
    let first_n = 50.min(total_diffs);
    let last_n = 50.min(total_diffs);
    let middle_sample = 100;

    // First 50 differences
    println!("\n--- FIRST {first_n} DIFFERENCES ---");
    for &idx in diff_indices.iter().take(first_n) {
        let line_num = idx + 1;
        println!("  Line {line_num}:");
        println!("    BASELINE: {}", sorted_baseline[idx]);
        println!("    RUST:     {}", sorted_rust[idx]);
    }

    // Last 50 differences (if different from first 50)
    if total_diffs > first_n + last_n {
        let last_start = total_diffs.saturating_sub(last_n);
        println!("\n--- LAST {last_n} DIFFERENCES ---");
        for &idx in diff_indices.iter().skip(last_start) {
            let line_num = idx + 1;
            println!("  Line {line_num}:");
            println!("    BASELINE: {}", sorted_baseline[idx]);
            println!("    RUST:     {}", sorted_rust[idx]);
        }
    }

    // 100 random from middle differences
    if total_diffs > first_n + last_n {
        let middle_start = first_n;
        let middle_end = total_diffs.saturating_sub(last_n);
        if middle_end > middle_start {
            let middle_diff_indices: Vec<usize> = diff_indices[middle_start..middle_end].to_vec();
            let sample_count = middle_sample.min(middle_diff_indices.len());
            let middle_count = middle_diff_indices.len();

            println!("\n--- {sample_count} RANDOM DIFFERENCES FROM MIDDLE ({middle_count} middle diffs) ---");

            // Deterministic shuffle using LCG
            let mut rng_seed = total_diffs as u64;
            let mut shuffled: Vec<usize> = middle_diff_indices;
            for i in (1..shuffled.len()).rev() {
                rng_seed = rng_seed.wrapping_mul(LCG_MULTIPLIER).wrapping_add(1);
                #[allow(clippy::cast_possible_truncation)]
                let j = (rng_seed as usize) % (i + 1);
                shuffled.swap(i, j);
            }

            for &idx in shuffled.iter().take(sample_count) {
                let line_num = idx + 1;
                println!("  Line {line_num}:");
                println!("    BASELINE: {}", sorted_baseline[idx]);
                println!("    RUST:     {}", sorted_rust[idx]);
            }
        }
    }
}

/// Read file and sort lines using robust byte-level comparison.
///
/// Uses stable sort with explicit byte comparison for cross-platform consistency:
/// - Primary: byte-level lexicographic comparison (UTF-8 bytes, not Unicode codepoints)
/// - Secondary: original line index (stable tie-break for identical lines)
///
/// This ensures identical output regardless of locale settings, UTF-8/UTF-16
/// collation differences, or unstable sort reorderings.
fn read_sorted_lines(path: &Path) -> Vec<String> {
    let all_lines = read_lines(path);
    let mut indexed: Vec<(usize, String)> = all_lines.into_iter().enumerate().collect();

    // Stable sort with byte-level comparison + index tie-break
    indexed.sort_by(|(idx_a, a), (idx_b, b)| {
        match a.as_bytes().cmp(b.as_bytes()) {
            std::cmp::Ordering::Equal => idx_a.cmp(idx_b),
            other => other,
        }
    });

    indexed.into_iter().map(|(_, line)| line).collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        extract_json_string_field, ordered_sha256, path_has_literal_tilde_component, sorted_sha256,
        uffs_binary_name,
    };

    fn lines(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn sorted_full_file_hash_still_detects_missing_footer_lines() {
        let baseline = lines(&["header", "", "row-a", "row-b", "", "Drives?\t1\tD:", ""]);
        let rust = lines(&["header", "", "row-b", "row-a"]);

        assert_ne!(ordered_sha256(&baseline), ordered_sha256(&rust));
        assert_ne!(sorted_sha256(&baseline), sorted_sha256(&rust));
    }

    #[test]
    fn sorted_full_file_hash_allows_row_reordering_when_full_line_set_matches() {
        let baseline = lines(&["header", "", "row-a", "row-b", "", "Drives?\t1\tD:", ""]);
        let rust = lines(&["header", "", "row-b", "row-a", "", "Drives?\t1\tD:", ""]);

        assert_ne!(ordered_sha256(&baseline), ordered_sha256(&rust));
        assert_eq!(sorted_sha256(&baseline), sorted_sha256(&rust));
    }

    #[test]
    fn extracts_target_directory_from_cargo_metadata_json() {
        let metadata = r#"{"target_directory":"/tmp/workspace/~/Library/Caches/uffs/target"}"#;

        assert_eq!(
            extract_json_string_field(metadata, "target_directory"),
            Some("/tmp/workspace/~/Library/Caches/uffs/target".to_string())
        );
    }

    #[test]
    fn extracts_escaped_windows_target_directory_from_cargo_metadata_json() {
        let metadata = r#"{"target_directory":"C:\\rust-target\\uffs"}"#;

        assert_eq!(
            extract_json_string_field(metadata, "target_directory"),
            Some(r"C:\rust-target\uffs".to_string())
        );
    }

    #[test]
    fn detects_literal_tilde_path_component() {
        assert!(path_has_literal_tilde_component(Path::new(
            "/workspace/~/Library/Caches/uffs/target"
        )));
        assert!(!path_has_literal_tilde_component(Path::new(
            "/Users/test/Library/Caches/uffs/target"
        )));
    }

    #[test]
    fn uffs_binary_name_matches_platform_expectation() {
        let expected_suffix = if cfg!(windows) { "uffs.exe" } else { "uffs" };
        assert_eq!(uffs_binary_name(), expected_suffix);
        assert_eq!(
            Path::new("release")
                .join(uffs_binary_name())
                .file_name()
                .and_then(|name| name.to_str()),
            Some(expected_suffix)
        );
    }
}
