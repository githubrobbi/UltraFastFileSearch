// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Snapshot delete-visibility diff for [`IndexManager`], surfaced through the
//! **full search pipeline** (RPC `search` with a `diff_baseline`).
//!
//! A diff answers "what was deleted on a drive since a baseline snapshot" — the
//! deletion-visible companion to `--newer`. Rather than a bespoke output, it
//! reuses everything a normal search does: pattern, `--ext`,
//! `--newer`/`--older`, `--min-size`, sort, projection, and every output format
//! all filter/shape the deleted set. The mechanism:
//!
//! 1. Load the baseline MFT capture into a compact index (off the async
//!    runtime).
//! 2. Diff it against the drive's **live** in-memory index by File Reference
//!    ([`uffs_core::diff::diff_indexes`]) to find the rows that vanished.
//! 3. Mark those baseline rows with the `DELETED` flag.
//! 4. Run the normal search pipeline ([`IndexManager::run_search_over`]) over
//!    the marked baseline, with a forced `deleted-only` filter.

use alloc::sync::Arc;
use std::path::PathBuf;

use uffs_client::protocol::SearchParams;
use uffs_client::protocol::response::SearchResponse;
use uffs_core::compact::MftSource;
use uffs_core::search::backend::DriveIndex;
use uffs_mft::platform::DriveLetter;

use super::IndexManager;

/// UFFS-internal "deleted tombstone" bit — mirrors
/// `uffs_mft::flags::FileFlags::DELETED` (0x8000, bit 15, reserved in NTFS) and
/// `uffs_core::search::filters`'s `DELETED_TOMBSTONE_FLAG`. Set on a baseline
/// record whose File Reference vanished from the current index.
const DELETED_FLAG: u32 = 0x8000;

/// Why a `diff` request could not be served. Mapped to a JSON-RPC error by the
/// handler; kept data-only here so this module stays free of wire concerns.
pub(crate) enum DiffError {
    /// No `--drive` was supplied, so there is no live index to diff against.
    NoDrive,
    /// The requested drive is not currently loaded in the live index.
    DriveNotLoaded(DriveLetter),
    /// The baseline snapshot at `path` could not be loaded into a compact
    /// index.
    BaselineLoad {
        /// The baseline path the caller supplied (echoed back in the message).
        path: String,
        /// The underlying load failure.
        source: anyhow::Error,
    },
}

impl IndexManager {
    /// Run a snapshot-diff search: diff `params.diff_baseline` against the live
    /// index for `params.drives[0]`, then search the deleted set with the full
    /// filter/sort/output pipeline.
    ///
    /// # Errors
    ///
    /// [`DiffError::NoDrive`] when no drive is given,
    /// [`DiffError::DriveNotLoaded`] when it has no live index, or
    /// [`DiffError::BaselineLoad`] when the baseline path cannot be loaded.
    pub(crate) async fn diff_search(
        &self,
        params: &SearchParams,
    ) -> Result<SearchResponse, DiffError> {
        let drive = *params.drives.first().ok_or(DiffError::NoDrive)?;
        let baseline_path = params.diff_baseline.clone().unwrap_or_default();

        // Current side: the live, hot in-memory index for the drive.
        let snapshot = self.snapshot().await;
        let Some(current) = snapshot
            .drives
            .iter()
            .find(|dr| dr.letter == drive)
            .map(Arc::clone)
        else {
            return Err(DiffError::DriveNotLoaded(drive));
        };
        drop(snapshot);

        // Load the baseline, diff it against the live index, and mark the
        // vanished rows — all off the async runtime (MFT parse + a hash-diff).
        let load_path = baseline_path.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let source = MftSource::File(PathBuf::from(&load_path), Some(drive));
            let (mut baseline, _timing) = uffs_core::compact::load_drive(&source, true)?;
            let report = uffs_core::diff::diff_indexes(&baseline, &current);
            let records = baseline.records.as_mut_slice();
            for &idx in &report.deleted {
                if let Some(record) = records.get_mut(idx as usize) {
                    record.flags |= DELETED_FLAG;
                }
            }
            anyhow::Ok(baseline)
        })
        .await;

        let baseline = match outcome {
            Ok(Ok(index)) => index,
            Ok(Err(source)) => {
                return Err(DiffError::BaselineLoad {
                    path: baseline_path,
                    source,
                });
            }
            Err(join_err) => {
                return Err(DiffError::BaselineLoad {
                    path: baseline_path,
                    source: join_err.into(),
                });
            }
        };

        // Search the marked baseline through the normal pipeline; the override
        // forces the deleted-only filter (see `run_search_over`).
        let index = Arc::new(DriveIndex {
            drives: vec![Arc::new(baseline)],
        });
        Ok(self.run_search_over(params, Some(index)).await)
    }
}
