// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `sysinfo` command — capture-host environment probe.
//!
//! Runs **before** a capture to record the machine the capture is taken on and
//! to pick the best-effort strategy (§2.1 of
//! `docs/architecture/mft-full-capture.md`). It reports the OS class
//! (`InstallationType` = client/server — the VSS/shadow discriminator),
//! elevation, VSS availability, host resources, NTFS capture targets, and every
//! mounted volume (type / format / size / used%), then emits a human-readable
//! `capture_host.txt` (and, on Windows, `--json`).
//!
//! This is deliberately distinct from the daemon's runtime
//! `status`/`uffs_status` (health/uptime). Layout:
//! - [`capture_mode`]: pure OS-class → best-effort strategy logic
//!   (unit-tested).
//! - [`report`]: the report data model, rendering, and the shared host builder.
//! - `windows` / `unix`: the platform-specific collectors.
#![expect(
    clippy::print_stdout,
    reason = "intentional user-facing CLI capture-host report output"
)]

mod capture_mode;
mod report;
#[cfg(not(windows))]
mod unix;
#[cfg(windows)]
mod windows;

use std::path::Path;

use anyhow::{Context as _, Result};

use self::report::Report;

/// Run the `sysinfo` probe: print the report and optionally write it to `out`.
///
/// # Errors
///
/// Returns an error if the report cannot be serialised (`--json`) or the output
/// file cannot be written.
pub(crate) fn run(out: Option<&Path>, json: bool) -> Result<()> {
    let report = collect();
    let rendered = render(&report, json)?;
    if let Some(path) = out {
        std::fs::write(path, rendered.as_bytes())
            .with_context(|| format!("writing capture-host report to {}", path.display()))?;
    }
    println!("{rendered}");
    Ok(())
}

/// Build the report using the platform-specific collector.
#[cfg(windows)]
fn collect() -> Report {
    windows::collect()
}

/// Build the report using the platform-specific collector.
#[cfg(not(windows))]
fn collect() -> Report {
    unix::collect()
}

/// Render the report as text, or JSON on Windows.
#[cfg(windows)]
fn render(report: &Report, json: bool) -> Result<String> {
    if json {
        return serde_json::to_string_pretty(report).context("serialising sysinfo report to JSON");
    }
    Ok(report.to_string())
}

/// Render the report as text (JSON is Windows-only in this crate).
#[cfg(not(windows))]
fn render(report: &Report, json: bool) -> Result<String> {
    if json {
        anyhow::bail!("--json output is only available on the Windows build");
    }
    Ok(report.to_string())
}
