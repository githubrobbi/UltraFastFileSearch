// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `metafile-info` command — offline inspection of a captured NTFS metafile.
//!
//! Cross-platform: reads a file written by `metafile` / `capture`, validates
//! its header, and prints a kind-specific summary (e.g. `$Boot` geometry). Runs
//! on the offline machine (macOS/Linux) as well as Windows — the reconstitute /
//! validate side of the capture flow.
#![expect(
    clippy::print_stdout,
    reason = "intentional user-facing CLI metafile summary output"
)]

use std::path::Path;

use anyhow::{Context as _, Result};

/// Inspect a captured metafile: load it and print its header + summary.
///
/// # Errors
///
/// Returns an error if the file cannot be read or lacks a valid metafile
/// header.
pub(crate) fn cmd_metafile_info(input: &Path) -> Result<()> {
    use uffs_mft::platform::{metafile, metafile_decode};

    let (header, payload) = metafile::load_metafile_from_file(input)
        .with_context(|| format!("loading metafile {}", input.display()))?;
    print!("{}", metafile_decode::summarize(&header, &payload));
    Ok(())
}
