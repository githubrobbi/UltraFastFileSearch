// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Stats command implementation.
//!
//! **Daemon mode** (no path): `run_stats` synthesises an aggregate-only
//! `overview` search and re-enters through
//! [`crate::commands::search::run_search`] — reusing the full search
//! daemon lifecycle (auto-start, await_ready, data-dir forwarding).
//!
//! Legacy parquet-mode stats have been removed from the thin CLI.
//! Use `uffsd` directly or `uffs --stats` (daemon mode) instead.

use std::path::Path;

use anyhow::Result;

use crate::args;
use crate::commands::search::run_search;

/// Handle `uffs --stats [path] [--top N] [--data-dir ...] [--mft-file ...]`.
///
/// # Errors
///
/// Returns an error for a malformed `--top`, for a path argument (legacy
/// parquet stats are no longer supported), or when the synthesised
/// overview search fails.
pub(crate) fn run_stats(args: &[String]) -> Result<()> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        args::print_stats_help();
        return Ok(());
    }
    // Simple arg extraction for stats subcommand.
    let mut path: Option<std::path::PathBuf> = None;
    let mut top: u32 = 10;
    let mut data_dir: Option<std::path::PathBuf> = None;
    let mut mft_file: Vec<std::path::PathBuf> = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--top" => {
                if let Some(val) = iter.next() {
                    top = val
                        .parse()
                        .map_err(|err| anyhow::anyhow!("Bad --top: {err}"))?;
                }
            }
            "--data-dir" => {
                if let Some(val) = iter.next() {
                    data_dir = Some(val.into());
                }
            }
            "--mft-file" => {
                if let Some(val) = iter.next() {
                    mft_file = val.split(',').map(|part| part.trim().into()).collect();
                }
            }
            other if !other.starts_with('-') && path.is_none() => {
                path = Some(other.into());
            }
            _ => {}
        }
    }

    if let Some(stats_path) = path {
        stats(Some(&stats_path), top)?;
    } else {
        // Synthesise search args for an aggregate-only overview query.
        let mut synth_args = vec![
            "*".to_owned(),
            "--agg".to_owned(),
            "overview".to_owned(),
            "--format".to_owned(),
            "table".to_owned(),
            "--limit".to_owned(),
            "0".to_owned(),
        ];
        if let Some(dir) = data_dir {
            synth_args.extend(["--data-dir".to_owned(), dir.to_string_lossy().into_owned()]);
        }
        for mf in &mft_file {
            synth_args.extend(["--mft-file".to_owned(), mf.to_string_lossy().into_owned()]);
        }
        run_search(&synth_args)?;
    }
    Ok(())
}

/// Show statistics.
///
/// Daemon-mode stats (no path) are handled by [`run_stats`] via the search
/// path.  Parquet-mode stats (path given) are no longer supported by the
/// thin CLI.
///
/// # Errors
///
/// Returns an error if a path is given (no longer supported) or if
/// daemon routing fails.
pub fn stats(path: Option<&Path>, _top: u32) -> Result<()> {
    match path {
        None => {
            anyhow::bail!("stats without a path should be routed through `run_stats`'s search path")
        }
        Some(dir) => {
            anyhow::bail!(
                "Legacy parquet stats for '{}' are no longer supported by the thin CLI.\n\
                 Use `uffs --stats` (daemon mode) instead.",
                dir.display()
            )
        }
    }
}
