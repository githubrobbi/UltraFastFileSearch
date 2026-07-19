// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Optional post-search reordering by true on-disk physical location
//! (LCN), for `SearchParams::resolve_lcn_order` — the read-order
//! optimization for `uffs-content`'s bulk content-read jobs.
//!
//! Deliberately a plain post-processing pass over the already-built
//! `Vec<SearchRow>`, run only when the flag is set, so every other
//! search request's code path (the overwhelming majority: interactive
//! CLI queries) is completely unaffected — no per-record cost, no new
//! branch in the hot per-row loop that builds `rows` in the first
//! place.

#[cfg(windows)]
use std::collections::HashMap;

use uffs_client::protocol::SearchParams;
use uffs_client::protocol::response::SearchRow;
#[cfg(windows)]
use uffs_core::compact::CompactRecord;
use uffs_mft::platform::DriveLetter;

use super::IndexManager;

impl IndexManager {
    /// If `params.resolve_lcn_order` is set, resolves each row's true
    /// on-disk physical location and returns `rows` re-sorted by
    /// ascending LCN (grouped per drive — LCN only means something
    /// within one volume; groups are concatenated back in order of
    /// first appearance, since cross-drive ordering has no physical
    /// meaning either way). Otherwise returns `rows` unchanged.
    ///
    /// Never fails the search: if a drive's volume can't be opened or
    /// its LCNs can't be resolved, that drive's rows are appended in
    /// their original relative order and a warning is logged — the same
    /// posture as every other best-effort daemon-side optimization.
    pub(crate) async fn reorder_rows_by_physical_location(
        &self,
        params: &SearchParams,
        rows: Vec<SearchRow>,
    ) -> Vec<SearchRow> {
        if !params.resolve_lcn_order || rows.is_empty() {
            return rows;
        }
        #[cfg(windows)]
        {
            self.reorder_impl(rows).await
        }
        #[cfg(not(windows))]
        {
            // Non-Windows builds have no `VolumeHandle`/live-MFT access at
            // all -- the flag is a no-op here rather than a compile
            // error, since the wire-protocol field itself is
            // cross-platform. The `.await` on an already-ready future is
            // deliberate: keeps this function genuinely `async` on every
            // platform rather than needing a separate sync twin the
            // caller would have to branch on.
            tracing::warn!(
                "physical-location ordering was requested but is Windows-only; \
                 returning rows in original order"
            );
            core::future::ready(rows).await
        }
    }

    /// Windows implementation: real `VolumeHandle`/MFT-record access.
    /// See [`Self::reorder_rows_by_physical_location`] for the contract.
    #[cfg(windows)]
    async fn reorder_impl(&self, rows: Vec<SearchRow>) -> Vec<SearchRow> {
        let drive_order = first_appearance_order(&rows);

        let mut by_drive: HashMap<DriveLetter, Vec<SearchRow>> = HashMap::new();
        for row in rows {
            by_drive.entry(row.drive).or_default().push(row);
        }

        // Clone into an owned map up front so the `RwLock` read guard is
        // released immediately, not held across the whole (potentially
        // slow, per-drive-I/O) loop below.
        let device_paths: HashMap<DriveLetter, String> = self.device_paths.read().await.clone();
        let mut output = Vec::with_capacity(by_drive.values().map(Vec::len).sum());

        for drive in drive_order {
            let Some(mut group) = by_drive.remove(&drive) else {
                continue;
            };

            let opened = device_paths.get(&drive).map_or_else(
                || uffs_mft::VolumeHandle::open(drive),
                |device_path| uffs_mft::VolumeHandle::open_device_path(device_path, drive),
            );
            let volume = match opened {
                Ok(volume) => volume,
                Err(err) => {
                    tracing::warn!(
                        %drive,
                        error = %err,
                        "physical-location ordering: failed to open volume, \
                         leaving this drive's rows in original order"
                    );
                    output.extend(group);
                    continue;
                }
            };

            let frs_list: Vec<u64> = group
                .iter()
                .map(|row| CompactRecord::unpack_frs(row.file_reference))
                .collect();

            match uffs_mft::resolve_frs_to_lcn(&volume, &frs_list) {
                Ok(lcns) => {
                    group.sort_by_key(|row| {
                        let frs = CompactRecord::unpack_frs(row.file_reference);
                        lcns.get(&frs).copied().flatten()
                    });
                }
                Err(err) => {
                    tracing::warn!(
                        %drive,
                        error = %err,
                        "physical-location ordering: LCN resolution failed, \
                         leaving this drive's rows in original order"
                    );
                }
            }

            output.extend(group);
        }

        output
    }
}

/// The distinct drives appearing in `rows`, in order of first
/// appearance — used so `IndexManager::reorder_impl` (Windows-only — not
/// in scope on this platform's rustdoc build) can concatenate each
/// drive's (independently sorted) group back in a stable, deterministic
/// order.
#[cfg_attr(
    not(windows),
    expect(dead_code, reason = "only consumed by the Windows reorder_impl")
)]
fn first_appearance_order(rows: &[SearchRow]) -> Vec<DriveLetter> {
    let mut seen = Vec::new();
    for row in rows {
        if !seen.contains(&row.drive) {
            seen.push(row.drive);
        }
    }
    seen
}
