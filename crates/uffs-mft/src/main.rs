// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! # `uffs-mft`: MFT Command-Line Tool
//!
//! Low-level tool for reading and exporting NTFS Master File Table data.
//!
//! ## Usage
//!
//! ```bash
//! # Read MFT from C: drive and export to Parquet
//! uffs-mft read --drive C --output c_drive.parquet
//!
//! # Show MFT information for a drive
//! uffs-mft info --drive C
//!
//! # List all NTFS drives
//! uffs-mft drives
//! ```
//!
//! ## Logging

//! Use `-v` / `--verbose` for debug-level terminal output:
//! ```bash
//! uffs-mft -v info --drive C
//! ```
//!
//! For finer control, use environment variables:
//! - `RUST_LOG`: Terminal log level (default: `info`, or `debug` with `-v`)
//! - `RUST_LOG_FILE`: File log level (default: `info`)
//! - `UFFS_LOG_DIR`: Log directory (default: `~/bin/uffs/logs`)
//!
//! **Note**: This tool requires Administrator privileges on Windows.

// CLI binaries have single-call functions by design (one per command)
#![expect(
    clippy::single_call_fn,
    reason = "CLI command functions are called once from dispatch"
)]

// Dev-dependencies used by the library but not by this binary.
use anyhow::Result;
use bitflags as _;
use bytemuck as _;
use clap::Parser as _;
// Dev-dependencies (used in benchmarks and tests only)
#[cfg(test)]
use criterion as _;
// Pipelining / chaos-test dependencies (used cross-platform)
use crossbeam_channel as _;
// `dirs_next` is used only by the library (`cache.rs` cache-dir lookup);
// the binary's logging now routes through `uffs_security::log_dir`, so
// acknowledge the dep here to keep `unused-crate-dependencies` quiet.
use dirs_next as _;
#[cfg(test)]
use hex as _;
// Platform-gated dependencies (used on Windows only)
#[cfg(not(windows))]
use indicatif as _;
// `libc` is used only by the library (`is_elevated` on Unix); acknowledge
// the dep here so `unused-crate-dependencies` stays quiet in the binary.
#[cfg(unix)]
use libc as _;
#[cfg(test)]
use proptest as _;
// Chaos test harness uses rand (ChaosMftReader is public, not test-only)
use rand as _;
use rand_chacha as _;
use rayon as _;
use rustc_hash as _;
// `serde` is used only by the library (DriveLetter Serialize/Deserialize);
// the binary doesn't reference it directly.  Acknowledge to keep
// `unused-crate-dependencies` quiet.
use serde as _;
#[cfg(test)]
use sha2 as _;
// SmallVec for path chain building (used in index.rs PathResolver)
use smallvec as _;
#[cfg(test)]
use tempfile as _;
use thiserror as _;
#[cfg(not(windows))]
use tracing as _;
#[cfg(not(windows))]
use uffs_mft as _;
use uffs_polars as _;
use uffs_security as _;
use uffs_text as _;
use zerocopy as _;
use zstd as _;
// Benchmark dependencies (used by bench/bench-all commands on Windows)
#[cfg(not(windows))]
use {chrono as _, hostname as _};

/// CLI definitions for the `uffs-mft` binary.
mod cli;
/// Command dispatch and handlers for the `uffs-mft` binary.
mod commands;
/// Formatting and display helpers shared by command handlers.
mod display;
/// Logging initialization support.
mod logging;
/// Progress display support for long-running commands.
mod progress;

use crate::cli::Cli;

/// Operation label used for `uffs-mft` shutdown classification.
const MFT_BINARY_OPERATION: &str = "uffs-mft";

/// Maps spawned binary task failures onto the approved cancellation taxonomy.
#[must_use]
fn classify_binary_task_error(
    operation: &'static str,
    error: &tokio::task::JoinError,
) -> uffs_mft::MftError {
    if error.is_cancelled() {
        return uffs_mft::MftError::Cancelled {
            operation,
            reason: error.to_string(),
        };
    }

    uffs_mft::MftError::WaitFailed {
        operation,
        reason: error.to_string(),
    }
}

/// Builds the explicit cancellation outcome for a Ctrl+C shutdown request.
#[must_use]
fn shutdown_requested_error(operation: &'static str) -> uffs_mft::MftError {
    uffs_mft::MftError::Cancelled {
        operation,
        reason: "shutdown requested by Ctrl+C".to_owned(),
    }
}

/// Builds a wait failure when the binary cannot install a Ctrl+C listener.
#[must_use]
fn ctrl_c_listener_error(operation: &'static str, error: &std::io::Error) -> uffs_mft::MftError {
    uffs_mft::MftError::WaitFailed {
        operation,
        reason: format!("failed to listen for Ctrl+C: {error}"),
    }
}

#[tokio::main]
#[expect(
    clippy::print_stderr,
    reason = "intentional user-facing error output in main"
)]
async fn main() {
    uffs_version::handle_version!("uffs-mft");
    let verbose = std::env::args().any(|arg| arg == "-v" || arg == "--verbose");
    let _guard = logging::init_logging(verbose);

    if let Err(err) = run_until_shutdown().await {
        eprintln!("Error: {err}");
        for cause in err.chain().skip(1) {
            eprintln!("  Caused by: {cause}");
        }
        std::process::exit(1);
    }
}

/// Main application logic, separated from `main()` for clean error handling.
async fn run() -> Result<()> {
    let cli = Cli::parse();
    commands::dispatch_command(cli.command).await
}

/// Runs the binary while listening for Ctrl+C so shutdown reaches long-running
/// command flows started from the binary entrypoint.
#[expect(
    clippy::single_call_fn,
    reason = "entrypoint wrapper exists solely to propagate shutdown into the spawned command task"
)]
async fn run_until_shutdown() -> Result<()> {
    let mut run_task = tokio::spawn(run());

    tokio::select! {
        result = &mut run_task => {
            match result {
                Ok(outcome) => outcome,
                Err(error) => Err(classify_binary_task_error(MFT_BINARY_OPERATION, &error).into()),
            }
        }
        signal = tokio::signal::ctrl_c() => {
            run_task.abort();

            match signal {
                Ok(()) => Err(shutdown_requested_error(MFT_BINARY_OPERATION).into()),
                Err(error) => Err(ctrl_c_listener_error(MFT_BINARY_OPERATION, &error).into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_binary_task_error, ctrl_c_listener_error, shutdown_requested_error};

    #[tokio::test]
    async fn classify_binary_task_error_maps_cancelled_joins() {
        let handle = tokio::spawn(async {
            core::future::pending::<()>().await;
        });
        handle.abort();

        let outcome = handle.await;
        assert!(outcome.is_err(), "aborted task unexpectedly completed");
        let Err(join_error) = outcome else {
            return;
        };

        let error = classify_binary_task_error("uffs-mft", &join_error);

        assert!(matches!(error, uffs_mft::MftError::Cancelled {
            operation: "uffs-mft",
            ..
        }));
    }

    #[test]
    fn shutdown_requested_error_is_cancelled() {
        let error = shutdown_requested_error("uffs-mft");

        assert!(matches!(error, uffs_mft::MftError::Cancelled {
            operation: "uffs-mft",
            ..
        }));
    }

    #[test]
    fn ctrl_c_listener_error_is_wait_failed() {
        let error =
            ctrl_c_listener_error("uffs-mft", &std::io::Error::other("listener unavailable"));

        assert!(matches!(error, uffs_mft::MftError::WaitFailed {
            operation: "uffs-mft",
            ..
        }));
    }
}
