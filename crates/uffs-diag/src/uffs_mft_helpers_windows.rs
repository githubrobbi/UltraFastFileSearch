// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Windows-only helpers for inspecting the full uffs-mft raw->fixup->parse
//! pipeline for a single FRS.
//!
//! This module is used by the `uffs-inspect-mft-record-flow` diagnostic binary
//! on Windows. Keeping it as a regular module (not a bin target) avoids extra
//! `main`/lint noise while still exercising the real `apply_fixup` +
//! `parse_record_full` pipeline.

#![cfg(windows)]
#![expect(
    clippy::print_stdout,
    clippy::use_debug,
    reason = "diagnostic helper — stdout / Debug formatting is intentional"
)]
#![expect(
    clippy::let_underscore_must_use,
    reason = "writeln! into a heap String never fails; ignoring its result is safe"
)]

use core::fmt::Write as _;

use uffs_mft::RawMftData;
use uffs_mft::io::{apply_fixup, parse_record_full};

/// Run `apply_fixup` + `parse_record_full` for a single FRS from a
/// `RawMftData`, printing a compact diagnostic line.
pub fn run_fixup_and_parse_for_frs(raw: &RawMftData, frs: u64) {
    let Some(record) = raw.get_record(frs) else {
        println!(
            "[WIN] FRS {frs}: out of range (max FRS = {})",
            raw.header.record_count.saturating_sub(1)
        );
        return;
    };

    let mut buf = record.to_vec();

    // Apply multi-sector fixup.
    if !apply_fixup(&mut buf) {
        println!("[WIN] FRS {frs}: apply_fixup() failed (non-FILE magic or USA mismatch)");
        return;
    }

    // Parse the record.
    let result = parse_record_full(&buf, frs);

    let mut out = String::new();
    let _ = writeln!(
        &mut out,
        "[WIN] FRS {frs}: parse_record_full() => {result:?}"
    );
    print!("{out}");
}
