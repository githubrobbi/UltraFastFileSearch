// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `uffs-bench` binary entry point — a thin shim over the library.
//!
//! All behavior lives in the [`uffs_bench`] library (parsed flags in
//! [`uffs_bench::Cli`], orchestration in [`uffs_bench::run`]) so it is
//! unit-testable under the `MockHost` on any OS. This binary only wires the
//! real [`SystemHost`] to the parsed CLI and propagates any error through the
//! process [`std::process::Termination`] path (which prints the `Debug` form to
//! stderr and exits non-zero) — keeping the shim free of ad-hoc `eprintln!`.

// Suppress `unused_crate_dependencies` for deps consumed by the library crate
// (`lib.rs` and its modules) rather than this thin binary, in line with the
// workspace convention (see `uffs-daemon`/`uffs-mcp` `main.rs`).
use chrono as _;
use clap::Parser as _;
use hex as _;
use serde as _;
use serde_json as _;
use sha2 as _;
#[cfg(test)]
use tempfile as _;
use thiserror as _;
use toml as _;
use uffs_bench::host::SystemHost;
use uffs_bench::{Cli, Result, run};

/// Parse the CLI and run the orchestrator against the real operating system.
///
/// # Errors
/// Propagates any [`uffs_bench::BenchError`] from bundle creation, state
/// load/save, or a Stage 0 artifact write. An operator abort/back is a graceful
/// stop, not an error.
fn main() -> Result<()> {
    uffs_version::handle_version!("uffs-bench");
    let cli = Cli::parse();
    let host = SystemHost::new();
    run(&host, &cli)
}
