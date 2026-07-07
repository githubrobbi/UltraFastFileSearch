// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `extract-mft` command — extract the raw `$MFT` from a captured `.bin`.
//!
//! Cross-platform: decompresses a UFFS-MFT `.bin` (or passes a headerless raw
//! dump straight through) and writes the byte-exact `$MFT` records — the format
//! other MFT tools (analyzeMFT, MFT2CSV, ntfstool) consume. Runs on the
//! transfer target too, so a `.bin` moved to a Mac yields a tool-ready `$MFT`
//! with no re-capture.
#![expect(
    clippy::print_stdout,
    reason = "intentional user-facing CLI extract summary"
)]

use std::path::Path;

use anyhow::{Context as _, Result};

/// Extract the raw `$MFT` bytes from a captured `.bin` to `output`.
///
/// # Errors
///
/// Returns an error if the input cannot be loaded/decompressed or the output
/// cannot be written.
pub(crate) fn cmd_extract_mft(input: &Path, output: &Path) -> Result<()> {
    use uffs_mft::raw::{LoadRawOptions, load_raw_mft};

    let raw = load_raw_mft(input, &LoadRawOptions::default())
        .with_context(|| format!("loading {}", input.display()))?;
    std::fs::write(output, &raw.data).with_context(|| format!("writing {}", output.display()))?;

    println!("✅ Extracted raw $MFT (tool-ready: analyzeMFT / MFT2CSV / ntfstool)");
    println!(
        "  Input:  {} ({})",
        input.display(),
        if raw.header.is_compressed() {
            "compressed UFFS-MFT"
        } else {
            "raw / uncompressed"
        }
    );
    println!(
        "  Output: {} ({} bytes, {} records × {} B)",
        output.display(),
        raw.data.len(),
        raw.header.record_count,
        raw.header.record_size,
    );
    Ok(())
}
