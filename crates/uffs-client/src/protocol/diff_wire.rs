// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Wire types for the `diff` method (snapshot delete-visibility diff).
//!
//! The CLI sends [`DiffParams`] naming a baseline snapshot + the drive it
//! covers; the daemon loads that baseline, diffs it against the live in-memory
//! index for the drive (`uffs_core::diff`), resolves every changed row to a
//! full path, and returns a [`DiffResultWire`]. Split into its own module (per
//! the 800-LOC policy and to keep `mod.rs` focused on the JSON-RPC envelope).

use serde::{Deserialize, Serialize};

/// Parameters for the `diff` method.
///
/// "What changed on `drive` between the `baseline` snapshot and now" — the
/// deletion-visible companion to `--newer`, which can only see
/// creates/modifies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffParams {
    /// Path to the baseline snapshot to diff against — a raw MFT capture
    /// (`.bin`) the daemon can load into a compact index. The live index for
    /// `drive` is the "current" side.
    pub baseline: String,
    /// Drive letter the baseline covers and whose live index is the current
    /// side of the diff.
    pub drive: uffs_mft::platform::DriveLetter,
    /// Maximum entries returned **per class** (added / deleted / modified).
    /// `0` = unlimited. When a class is capped, [`DiffResultWire::truncated`]
    /// is set so the caller can tell a capped list from a complete one.
    #[serde(default)]
    pub limit: u32,
}

/// One changed file in a [`DiffResultWire`]: a full path plus render metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffEntryWire {
    /// Full path (`C:\Users\…\file.ext`).
    pub path: String,
    /// Logical size in bytes (current size for a modify; last-known baseline
    /// size for a delete).
    pub size: u64,
    /// Last-write time in Unix microseconds, from the same snapshot as `path`.
    pub modified: i64,
}

/// Result of the `diff` method: the classified, path-resolved delta.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DiffResultWire {
    /// Files present now but not in the baseline (created since it).
    pub added: Vec<DiffEntryWire>,
    /// Files present in the baseline but gone now (deleted since it).
    pub deleted: Vec<DiffEntryWire>,
    /// Files in both whose size or last-write time changed.
    pub modified: Vec<DiffEntryWire>,
    /// `true` when `limit` capped at least one class (more changes exist than
    /// were returned).
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::{DiffEntryWire, DiffParams, DiffResultWire};

    #[test]
    fn diff_params_round_trip_through_json() {
        let params = DiffParams {
            baseline: r"D:\snapshots\c_2026-07-01.bin".to_owned(),
            drive: uffs_mft::platform::DriveLetter::C,
            limit: 500,
        };
        let json = serde_json::to_value(&params).expect("serialize DiffParams");
        let back: DiffParams = serde_json::from_value(json).expect("deserialize DiffParams");
        assert_eq!(params, back);
    }

    #[test]
    fn diff_params_limit_defaults_to_zero_when_absent() {
        // The CLI omits `limit` for an unlimited diff; it must default to 0.
        let json = serde_json::json!({ "baseline": "x.bin", "drive": "C" });
        let params: DiffParams = serde_json::from_value(json).expect("deserialize");
        assert_eq!(params.limit, 0, "missing limit → unlimited (0)");
    }

    #[test]
    fn diff_result_round_trips_through_json() {
        let result = DiffResultWire {
            added: vec![DiffEntryWire {
                path: r"C:\new.txt".to_owned(),
                size: 10,
                modified: 9,
            }],
            deleted: vec![DiffEntryWire {
                path: r"C:\gone.txt".to_owned(),
                size: 200,
                modified: 6,
            }],
            modified: vec![],
            truncated: true,
        };
        let json = serde_json::to_value(&result).expect("serialize DiffResultWire");
        let back: DiffResultWire = serde_json::from_value(json).expect("deserialize");
        assert_eq!(result, back);
    }
}
