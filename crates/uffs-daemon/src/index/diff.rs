// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Snapshot delete-visibility diff for [`IndexManager`] (RPC `diff`).
//!
//! The `diff` RPC answers "what was created, deleted, or modified on a drive
//! since a baseline snapshot" — the deletion-visible companion to `--newer`,
//! which is structurally blind to deletes. It loads the caller's baseline MFT
//! capture off-thread, diffs it against the **live in-memory index** for the
//! drive via [`uffs_core::diff::resolve_delta`] (so the "current" side is the
//! hot index the daemon already serves searches from), and returns the
//! classified, path-resolved delta.
//!
//! All the classification + path-resolution logic lives in `uffs_core::diff`
//! and is unit-tested there; this module is the daemon glue — snapshot the
//! registry, load the baseline, hand both to the engine, map the result onto
//! the wire type.

use alloc::sync::Arc;
use std::path::PathBuf;

use uffs_client::protocol::{DiffEntryWire, DiffParams, DiffResultWire};
use uffs_core::compact::MftSource;
use uffs_core::diff::{DeltaEntry, ResolvedDelta, resolve_delta};
use uffs_mft::platform::DriveLetter;

use super::IndexManager;

/// Why a `diff` request could not be served. Mapped to a JSON-RPC error by the
/// handler; kept data-only here so this module stays free of wire concerns.
pub(crate) enum DiffError {
    /// The requested drive is not currently loaded in the live index, so there
    /// is no "current" side to diff the baseline against.
    DriveNotLoaded(DriveLetter),
    /// The baseline snapshot at `path` could not be loaded into a compact
    /// index (missing file, unreadable, not a valid MFT capture, …).
    BaselineLoad {
        /// The baseline path the caller supplied (echoed back in the message).
        path: String,
        /// The underlying load failure.
        source: anyhow::Error,
    },
}

impl IndexManager {
    /// Diff a baseline snapshot against the live index for `params.drive`.
    ///
    /// # Errors
    ///
    /// Returns [`DiffError::DriveNotLoaded`] when the drive has no live index,
    /// or [`DiffError::BaselineLoad`] when the baseline path cannot be loaded.
    pub(crate) async fn diff_snapshot(
        &self,
        params: &DiffParams,
    ) -> Result<DiffResultWire, DiffError> {
        // Current side: the live, hot in-memory index for the drive.
        let snap = self.snapshot().await;
        let Some(current) = snap
            .drives
            .iter()
            .find(|dr| dr.letter == params.drive)
            .map(Arc::clone)
        else {
            return Err(DiffError::DriveNotLoaded(params.drive));
        };
        drop(snap); // We hold the one Arc we need; release the registry snapshot.

        // Baseline side: load the caller's capture and diff, both off the async
        // runtime — the MFT parse is I/O + CPU heavy and the diff hashes over
        // the whole record array. `no_cache = true` forces a fresh read of the
        // baseline rather than reusing any persisted cache for that path.
        let baseline_path = PathBuf::from(&params.baseline);
        let drive = params.drive;
        let limit = uffs_mft::u32_as_usize(params.limit);
        let current_for_task = Arc::clone(&current);
        let outcome = tokio::task::spawn_blocking(move || {
            let source = MftSource::File(baseline_path, Some(drive));
            let (baseline, _timing) = uffs_core::compact::load_drive(&source, true)?;
            anyhow::Ok(resolve_delta(&baseline, &current_for_task, limit))
        })
        .await;

        match outcome {
            Ok(Ok(resolved)) => Ok(to_wire(resolved)),
            Ok(Err(source)) => Err(DiffError::BaselineLoad {
                path: params.baseline.clone(),
                source,
            }),
            Err(join_err) => Err(DiffError::BaselineLoad {
                path: params.baseline.clone(),
                source: join_err.into(),
            }),
        }
    }
}

/// Map the engine's [`ResolvedDelta`] onto the JSON-RPC wire result.
fn to_wire(resolved: ResolvedDelta) -> DiffResultWire {
    DiffResultWire {
        added: resolved.added.into_iter().map(entry_to_wire).collect(),
        deleted: resolved.deleted.into_iter().map(entry_to_wire).collect(),
        modified: resolved.modified.into_iter().map(entry_to_wire).collect(),
        truncated: resolved.truncated,
    }
}

/// Map one resolved [`DeltaEntry`] onto its wire form.
fn entry_to_wire(entry: DeltaEntry) -> DiffEntryWire {
    DiffEntryWire {
        path: entry.path,
        size: entry.size,
        modified: entry.modified,
    }
}

#[cfg(test)]
mod tests {
    use uffs_core::diff::{DeltaEntry, ResolvedDelta};

    use super::{entry_to_wire, to_wire};

    #[test]
    fn to_wire_preserves_every_class_and_the_truncated_flag() {
        let resolved = ResolvedDelta {
            added: vec![DeltaEntry {
                path: r"C:\new.txt".to_owned(),
                size: 10,
                modified: 9,
            }],
            deleted: vec![DeltaEntry {
                path: r"C:\gone.txt".to_owned(),
                size: 200,
                modified: 6,
            }],
            modified: vec![],
            truncated: true,
        };
        let wire = to_wire(resolved);
        assert_eq!(wire.added.len(), 1);
        assert_eq!(wire.deleted.len(), 1);
        assert!(wire.modified.is_empty());
        assert!(wire.truncated);
        let added = wire.added.first().expect("one add");
        assert_eq!(added.path, r"C:\new.txt");
        assert_eq!(added.size, 10);
    }

    #[test]
    fn entry_to_wire_is_a_faithful_field_copy() {
        let wire = entry_to_wire(DeltaEntry {
            path: r"C:\a.txt".to_owned(),
            size: 42,
            modified: 7,
        });
        assert_eq!(wire.path, r"C:\a.txt");
        assert_eq!(wire.size, 42);
        assert_eq!(wire.modified, 7);
    }
}
