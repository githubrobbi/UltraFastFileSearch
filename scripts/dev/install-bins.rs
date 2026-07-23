#!/usr/bin/env rust-script
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.
//!
//! install-bins.rs — build the workspace and install **every** binary it
//! produces to `~/bin`.
//!
//! The binary list is not hardcoded: after building, the same build is
//! re-run with `--message-format=json` (instant from cache) and every
//! `compiler-artifact` message's `executable` path is installed. A new
//! `[[bin]]` anywhere in the workspace is picked up automatically.
//!
//! Called by `just use-local` as
//! `rust-script scripts/dev/install-bins.rs`. A rust-script on purpose:
//!
//! - a just shebang recipe dies on Windows (just hands bash a raw
//!   `C:\...` temp path whose backslashes bash eats, exit 127);
//! - a plain `bash script.sh` line dies too when `bash` on PATH resolves
//!   to WSL's `System32\bash.exe`, which has no cargo ("cargo: command
//!   not found").
//!
//! rust-script runs identically under just's unix shell and its
//! powershell windows-shell, and spawns `cargo` from the real PATH.
//!
//! Usage:
//!   rust-script scripts/dev/install-bins.rs

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn main() {
    let build_args: &[&str] = &["build", "--release", "--workspace"];

    eprintln!("📦 Build (release) + install UFFS binaries to ~/bin");
    eprintln!("========================================================");

    // Stop the running daemon + MCP first (best effort), mirroring the
    // previous [unix] bash recipe: the old binaries release their file
    // locks (Windows can't overwrite a running .exe at all) and no stale
    // in-memory index shadows the freshly installed build.
    stop_running_services();

    eprintln!();
    eprintln!("🔨 cargo {}", build_args.join(" "));

    let started = Instant::now();
    let status = Command::new("cargo").args(build_args).status();
    match status {
        Ok(code) if code.success() => {
            eprintln!("  → Built in {}s", started.elapsed().as_secs());
        }
        Ok(code) => {
            eprintln!("❌ build failed with {code:?}");
            std::process::exit(1);
        }
        Err(err) => {
            eprintln!("❌ failed to launch cargo: {err}");
            std::process::exit(1);
        }
    }

    // EVERY binary the workspace just built — discovered from cargo, not
    // a hardcoded list, so a new bin target is picked up automatically and
    // nothing is ever silently missed. `--message-format=json` re-emits
    // one `compiler-artifact` message per crate straight from the build
    // cache (instant, since the real build above already ran), and each
    // binary target carries a non-null `"executable"` path. Libraries
    // carry `"executable":null` and are skipped.
    let executables = workspace_executables(build_args);
    if executables.is_empty() {
        eprintln!("❌ cargo reported no workspace binaries to install");
        std::process::exit(1);
    }

    let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let Ok(home) = std::env::var(home_var) else {
        eprintln!("❌ {home_var} is not set — nowhere to install to");
        std::process::exit(1);
    };
    let bin_dir = PathBuf::from(&home).join("bin");
    if let Err(err) = std::fs::create_dir_all(&bin_dir) {
        eprintln!("❌ cannot create {}: {err}", bin_dir.display());
        std::process::exit(1);
    }

    let mut installed = 0_u32;
    let mut skipped = 0_u32;
    eprintln!();
    eprintln!("📦 Installing {} binaries to {}", executables.len(), bin_dir.display());
    for src in &executables {
        let Some(file_name) = src.file_name() else {
            continue;
        };
        let dest = bin_dir.join(file_name);
        let name = file_name.to_string_lossy();
        if !src.is_file() {
            eprintln!("  ⚠️  {name:<28} not found at {} (skipping)", src.display());
            skipped += 1;
            continue;
        }
        // Remove first so the copy gets a fresh inode — overwrites in place
        // share the inode, which lets macOS re-use a path-cached Launch
        // Services deny verdict against an earlier broken copy.
        if dest.is_dir() {
            let _ = std::fs::remove_dir_all(&dest);
        }
        let _ = std::fs::remove_file(&dest);
        match std::fs::copy(src, &dest) {
            Ok(bytes) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    let _ = std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(0o755),
                    );
                }
                eprintln!("  ✅ {name:<28} {:.1} MB", bytes as f64 / 1_048_576.0);
                installed += 1;
            }
            Err(err) => {
                eprintln!("  ❌ {name:<28} copy failed: {err}");
                skipped += 1;
            }
        }
    }

    eprintln!();
    eprintln!("✅ Installed {installed} binaries ({skipped} skipped)");
    let on_path = std::env::var("PATH")
        .map(|path| std::env::split_paths(&path).any(|entry| entry == bin_dir))
        .unwrap_or(false);
    if !on_path {
        eprintln!("⚠️  {} is not on PATH", bin_dir.display());
    }
    if skipped > 0 {
        std::process::exit(1);
    }
}

/// Best-effort shutdown of the resident daemon + MCP before installing.
///
/// `uffs --daemon kill` is given 10 seconds (a wedged daemon must not
/// hang the install), then any survivors are hard-killed by image name —
/// `pkill -x` on Unix, `taskkill /IM … /F` on Windows. Every step is
/// best-effort: on a machine with nothing running (or no `uffs` on PATH
/// yet), all of this silently no-ops.
fn stop_running_services() {
    eprintln!();
    eprintln!("🔪 Stopping daemon + MCP (best effort)...");
    if let Ok(mut child) = Command::new("uffs")
        .args(["--daemon", "kill"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                _ => {
                    let _ = child.kill();
                    break;
                }
            }
        }
    }
    for name in ["uffsd", "uffsmcp"] {
        let status = if cfg!(windows) {
            Command::new("taskkill")
                .args(["/IM", &format!("{name}.exe"), "/F"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        } else {
            Command::new("pkill")
                .args(["-x", name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        };
        let _ = status;
    }
}

/// Every binary the workspace build produced, as absolute paths.
///
/// Re-runs the same build with `--message-format=json` — instant, since
/// the real build already populated the cache — and collects each
/// `compiler-artifact` message's non-null `executable` path. This is the
/// authoritative "what did we build" list: no name guessing, no `.exe`
/// handling, no missed target when a new `[[bin]]` is added.
fn workspace_executables(build_args: &[&str]) -> Vec<PathBuf> {
    let mut args: Vec<&str> = build_args.to_vec();
    args.push("--message-format=json");
    let output = Command::new("cargo")
        .args(&args)
        .stderr(Stdio::inherit())
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    let Ok(text) = String::from_utf8(output.stdout) else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    for line in text.lines() {
        if let Some(exe) = json_executable(line) {
            paths.push(PathBuf::from(exe));
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

/// The non-null `"executable"` path from one cargo JSON message line, if
/// present. `"executable":null` (a library artifact) yields `None`.
fn json_executable(line: &str) -> Option<String> {
    let key = "\"executable\":";
    let after = &line[line.find(key)? + key.len()..];
    // Value is either `null` or `"<escaped path>"`.
    let rest = after.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(unescape_json_path(&rest[..end]))
}

/// Undo JSON string escaping in a path (`\\` → `\`, `\/` → `/`).
fn unescape_json_path(escaped: &str) -> String {
    let mut out = String::with_capacity(escaped.len());
    let mut chars = escaped.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('/') => out.push('/'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}
