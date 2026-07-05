// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! CLI command implementations.
//!
//! This module provides the public command surface for the UFFS CLI and shared
//! helpers used by the split command modules.

/// Aggregate analytics subcommand.
pub mod aggregate;
/// `uffs --daemon load` — hot-load MFT file(s) into a running daemon.
///
/// Split off `daemon_mgmt` so the lifecycle file stays under the
/// 800-LOC policy ceiling without a file-size exception (mirrors
/// the `daemon_tiering` decomposition for the Phase 8 commands).
pub(crate) mod daemon_load;
/// Daemon management subcommands.
pub(crate) mod daemon_mgmt;
pub(crate) mod daemon_status;
/// Memory-tiering operator commands (`hibernate` / `preload`).
///
/// Phase 8-B / 8-C — split off `daemon_mgmt` so each cluster stays
/// under the 800-LOC policy ceiling.  Forward-looking: 8-D `forget`
/// and 8-E `status_drives` will land their shims here as well.
pub(crate) mod daemon_tiering;
// Index and info subcommands were merged into other modules.
/// MCP server management subcommands.
pub(crate) mod mcp_mgmt;
/// Output helpers for search results.
pub mod output;
/// Search command implementation.
pub mod search;
/// Stats subcommand implementation.
pub mod stats;
/// Combined `uffs --status` command.
pub(crate) mod system_status;
/// `uffs --uninstall` — full UFFS removal (see
/// `docs/dev/architecture/UFFS-Uninstall-Implementation-Plan.md`).
pub(crate) mod uninstall;
/// `uffs --update` — self-update detection (Phase A of the self-update design).
pub(crate) mod update;

/// Render a one-line version summary suitable for `daemon status`
/// and `uffs --status` output.
///
/// `daemon_version` is the daemon-reported `env!("CARGO_PKG_VERSION")`
/// from [`uffs_client::protocol::response::StatusResponse::version`]
/// (or `StatsResponse::version`).  The CLI's own compile-time version
/// is read locally; when the two differ we surface both with a
/// `MISMATCH` flag so a stale long-running daemon paired with a
/// freshly-upgraded CLI binary (or vice versa) is visible at a glance
/// instead of being inferred from the existing mtime-based stale-binary
/// heuristic in `system_status::print_daemon_status`.
///
/// Pre-0.5.79 daemons send no version; rendered as `<unknown>`.
///
/// The function returns the value portion only — callers prepend
/// their own label/indentation (`Version:`, `  Version:`, etc.) so a
/// single helper covers both indented and non-indented layouts.
pub(crate) fn version_summary(daemon_version: &str) -> String {
    let cli_version = env!("CARGO_PKG_VERSION");
    if daemon_version.is_empty() {
        format!("<unknown> (daemon) / {cli_version} (cli)")
    } else if daemon_version == cli_version {
        cli_version.to_owned()
    } else {
        format!("{daemon_version} (daemon) / {cli_version} (cli)  ⚠ MISMATCH")
    }
}

/// Format a number with comma separators.
fn format_number(num: u64) -> String {
    let num_str = num.to_string();
    let mut result = String::with_capacity(num_str.len() + num_str.len() / 3);
    for (idx, ch) in num_str.chars().rev().enumerate() {
        if idx > 0 && idx % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

/// Format file size in human-readable format.
///
/// Boundary thresholds are typed as `u64` to compare against the input
/// without a cast; the human-readable divisors are typed as `f64`
/// directly so the only remaining f64 conversion is the input byte
/// count via [`u64_to_display_f64`] (which carries the single
/// `cast_precision_loss` justification this function needs).
#[expect(
    clippy::float_arithmetic,
    reason = "division for human-readable size formatting"
)]
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;
    const KB_F: f64 = 1024.0_f64;
    const MB_F: f64 = KB_F * 1024.0_f64;
    const GB_F: f64 = MB_F * 1024.0_f64;
    const TB_F: f64 = GB_F * 1024.0_f64;

    let bytes_f64 = u64_to_display_f64(bytes);
    if bytes >= TB {
        format!("{:.2} TB", bytes_f64 / TB_F)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes_f64 / GB_F)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes_f64 / MB_F)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes_f64 / KB_F)
    } else {
        format!("{bytes} B")
    }
}

/// Lossy `u64 -> f64` conversion for human-readable telemetry output.
///
/// Values above `2^53` lose low bits, which is acceptable for the
/// `{:.2}` MB/GB/TB display format used by `format_size`.
#[inline]
#[expect(
    clippy::cast_precision_loss,
    reason = "display-only `format!(\"{:.2} ...\")` byte counts; ±1 byte rounding is invisible at MB resolution"
)]
const fn u64_to_display_f64(value: u64) -> f64 {
    value as f64
}
