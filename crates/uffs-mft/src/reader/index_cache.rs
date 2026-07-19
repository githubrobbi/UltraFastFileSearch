// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Cached lean-index read helpers.

use super::MftReader;
#[cfg(not(windows))]
use crate::error::MftError;
use crate::error::Result;

impl MftReader {
    /// Read MFT into lean `MftIndex` with automatic caching.
    ///
    /// This is the **recommended primary method** for CLI usage. It:
    /// 1. Checks if a fresh cache exists (within TTL)
    /// 2. If fresh, loads from cache and applies USN Journal updates
    /// 3. If stale/missing, reads MFT fresh and saves to cache
    ///
    /// Use `read_all_index()` directly only when you need to bypass caching.
    ///
    /// # Arguments
    ///
    /// * `ttl_seconds` - Cache TTL in seconds (use `INDEX_TTL_SECONDS` for
    ///   default)
    ///
    /// # Errors
    ///
    /// Returns an error if MFT reading fails.
    #[cfg(windows)]
    #[tracing::instrument(
        level = "info",
        skip(self),
        fields(
            volume = %self.volume,
            ttl_seconds,
            mode = %self.mode,
            use_bitmap = self.use_bitmap,
            merge_extensions = self.merge_extensions,
            expand_links = self.expand_links
        )
    )]
    pub async fn read_index_cached(&self, ttl_seconds: u64) -> Result<crate::index::MftIndex> {
        use tracing::info;

        use crate::cache::{CacheStatus, check_cache_status};

        let drive = self.volume;
        tracing::debug!(drive = %drive, ttl_seconds, "[TRIP] reader::read_index_cached ENTER");

        // Fast path for read-only volumes: cache can never go stale since
        // nothing can change on the drive.  Skip TTL, skip USN, skip
        // VolumeHandle — just load from disk and return.
        let read_only = crate::platform::is_volume_read_only(drive);
        if read_only {
            if let Some((index, _header)) = crate::cache::load_cached_index(drive, u64::MAX) {
                info!(
                    drive = %drive,
                    records = index.len(),
                    "📦 Read-only volume — using cached index (no TTL)"
                );
                return Ok(index);
            }
            // No cache yet — fall through to build one.
            info!(drive = %drive, "🆕 Read-only volume — no cache, building index");
            return self.read_and_cache_index().await;
        }

        // Check cache status
        match check_cache_status(drive, ttl_seconds) {
            CacheStatus::Fresh {
                index,
                header,
                age_seconds,
            } => {
                tracing::debug!(drive = %drive, age_seconds, "[TRIP] reader::read_index_cached -> CACHE_HIT path");
                info!(
                    drive = %drive,
                    age_seconds,
                    records = index.len(),
                    "📦 Cache HIT - checking for USN updates"
                );
                self.apply_usn_updates_to_fresh_index(index, header, age_seconds)
                    .await
            }
            CacheStatus::Stale { age_seconds } => {
                tracing::debug!(drive = %drive, "[TRIP] reader::read_index_cached -> CACHE_STALE path");
                info!(
                    drive = %drive,
                    age_seconds = ?age_seconds,
                    "🔄 Cache STALE - rebuilding index"
                );
                self.read_and_cache_index().await
            }
            CacheStatus::Missing => {
                tracing::debug!(drive = %drive, "[TRIP] reader::read_index_cached -> CACHE_MISS path");
                info!(drive = %drive, "🆕 Cache MISS - building index");
                self.read_and_cache_index().await
            }
        }
    }

    /// Apply USN-Journal updates to a freshly loaded cache index, then save
    /// the updated cache back to disk.  Falls back to a full rebuild via
    /// [`Self::read_and_cache_index`] when the journal has been recreated or
    /// has wrapped past our checkpoint.
    ///
    /// `age_seconds` is the cache file's age as reported by
    /// [`crate::cache::check_cache_status`]; it drives the no-journal
    /// resilience decision: when the drive's USN journal is unavailable a
    /// cache older than [`crate::reader::usn_apply::no_journal_max_age_secs`]
    /// is rebuilt rather than served stale.
    ///
    /// Extracted from [`Self::read_index_cached`] so each function stays
    /// under the cyclomatic / line-count caps.
    #[cfg(windows)]
    async fn apply_usn_updates_to_fresh_index(
        &self,
        mut index: crate::index::MftIndex,
        header: crate::index::IndexHeader,
        age_seconds: u64,
    ) -> Result<crate::index::MftIndex> {
        use tracing::warn;

        use crate::platform::VolumeHandle;
        use crate::reader::usn_apply::{UsnDecision, classify_usn_state, classify_without_journal};
        use crate::usn::query_usn_journal;

        let drive = self.volume;

        // Open volume handle once — used for reserved_allocated_bytes,
        // targeted MFT reads, and cache save.
        let handle = VolumeHandle::open(drive)?;

        // Restore reserved_allocated_bytes from live volume data.  This
        // field is not serialized in the cache; it is needed for correct
        // root tree_allocated when tree metrics are recomputed (e.g. after
        // USN updates).
        index.reserved_allocated_bytes = handle.volume_data().reserved_allocated_bytes();

        let current_info = match query_usn_journal(drive) {
            Ok(info) => info,
            Err(err) => {
                warn!(
                    drive = %drive,
                    error = %err,
                    "⚠️ USN Journal unavailable - evaluating cache age"
                );
                return match classify_without_journal(drive, age_seconds) {
                    UsnDecision::Rebuild => self.read_and_cache_index().await,
                    UsnDecision::UseCached | UsnDecision::Apply { .. } => Ok(index),
                };
            }
        };

        match classify_usn_state(drive, &header, &current_info) {
            UsnDecision::UseCached => Ok(index),
            UsnDecision::Rebuild => self.read_and_cache_index().await,
            UsnDecision::Apply {
                journal_id,
                start_usn,
            } => Ok(Self::apply_or_skip_usn_changes(
                drive, index, &handle, journal_id, start_usn,
            )),
        }
    }

    /// Read the USN journal from `start_usn` and either apply the resulting
    /// changes (and persist the index back to cache) or return the index
    /// unchanged when there is nothing to apply.
    ///
    /// Mirrors
    /// [`crate::reader::multi_drive::MultiDriveMftReader::apply_or_skip_usn_changes`]
    /// but reuses the caller-supplied [`crate::platform::VolumeHandle`] instead
    /// of opening a fresh one — the cached single-drive path already holds
    /// a live handle from `apply_usn_updates_to_fresh_index`.
    #[cfg(windows)]
    fn apply_or_skip_usn_changes(
        drive: crate::platform::DriveLetter,
        index: crate::index::MftIndex,
        handle: &crate::platform::VolumeHandle,
        journal_id: u64,
        start_usn: crate::usn::Usn,
    ) -> crate::index::MftIndex {
        use tracing::{debug, warn};

        use crate::usn::read_usn_journal;

        let (records, next_usn) = match read_usn_journal(drive, journal_id, start_usn) {
            Ok(result) => result,
            Err(err) => {
                warn!(
                    drive = %drive,
                    error = %err,
                    "⚠️ Failed to read USN Journal - using cached index as-is"
                );
                return index;
            }
        };

        if records.is_empty() {
            debug!(drive = %drive, "✅ No USN changes since last cache");
            return index;
        }

        Self::apply_usn_changes_and_save(drive, index, handle, &records, journal_id, next_usn)
    }

    /// Apply aggregated USN changes to `index` and persist the result.
    ///
    /// Splits into three phases:
    /// 1. Delete records covered by USN deletes.
    /// 2. Issue targeted MFT reads for the non-delete FRSes.
    /// 3. Rebuild the extension index + tree metrics if anything changed, then
    ///    save the updated index back to cache.
    #[cfg(windows)]
    fn apply_usn_changes_and_save(
        drive: crate::platform::DriveLetter,
        mut index: crate::index::MftIndex,
        handle: &crate::platform::VolumeHandle,
        records: &[crate::usn::UsnRecord],
        journal_id: u64,
        next_usn: crate::usn::Usn,
    ) -> crate::index::MftIndex {
        use tracing::info;

        use crate::reader::usn_apply::{
            apply_targeted_usn_reads, persist_usn_checkpoint, rebuild_derived_after_usn,
        };
        use crate::usn::aggregate_changes;

        let changes_map = aggregate_changes(records);
        let changes: Vec<_> = changes_map.into_values().collect();
        info!(
            drive = %drive,
            usn_records = changes.len(),
            "📝 Applying USN updates to cached index"
        );

        // Phase 1: apply deletes and collect FRS values needing targeted reads
        let (mut stats, frs_to_read) = index.apply_usn_deletes(&changes);

        // Phase 2: targeted MFT reads for non-delete changes
        apply_targeted_usn_reads(drive, handle, &mut index, &frs_to_read, &mut stats);

        // Phase 3: rebuild derived structures + persist
        rebuild_derived_after_usn(drive, &mut index, &stats);
        persist_usn_checkpoint(drive, handle, &index, journal_id, next_usn);

        index
    }

    /// Read MFT with caching (non-Windows stub).
    ///
    /// # Errors
    ///
    /// Always returns `MftError::PlatformNotSupported` on non-Windows
    /// platforms.
    #[cfg(not(windows))]
    #[expect(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "async signature mirrors the Windows impl for cross-cfg API parity"
    )]
    pub async fn read_index_cached(&self, _ttl_seconds: u64) -> Result<crate::index::MftIndex> {
        Err(MftError::PlatformNotSupported)
    }

    /// Internal helper: read MFT fresh and save to cache.
    #[cfg(windows)]
    #[tracing::instrument(
        level = "info",
        skip(self),
        fields(
            volume = %self.volume,
            mode = %self.mode,
            use_bitmap = self.use_bitmap,
            merge_extensions = self.merge_extensions,
            expand_links = self.expand_links
        )
    )]
    async fn read_and_cache_index(&self) -> Result<crate::index::MftIndex> {
        use crate::platform::VolumeHandle;
        use crate::usn::query_usn_journal;

        let drive = self.volume;
        tracing::debug!(drive = %drive, "[TRIP] reader::read_and_cache_index ENTER");
        let index = self.read_all_index().await?;
        tracing::debug!(drive = %drive, records = index.len(), "[TRIP] reader::read_and_cache_index -> read_all_index done");

        // Get volume info for caching (quick syscalls).
        let volume_serial =
            VolumeHandle::open(drive).map_or(0, |handle| handle.volume_data().volume_serial_number);

        let (usn_journal_id, next_usn) = query_usn_journal(drive)
            .map_or((0, crate::usn::Usn::ZERO), |info| {
                (info.journal_id, info.next_usn)
            });

        // Delegate to the single save_to_cache() implementation.
        // This handles: serialize → zstd → AES-256-GCM → atomic_write,
        // plus compact cache invalidation and [CACHE_PROFILE] profiling.
        //
        // This is the cold path (no cache exists) — serialize+compress is
        // CPU-bound (~1-2s) but we must complete it before returning so the
        // cache is guaranteed to exist for subsequent runs.
        if let Err(err) =
            crate::cache::save_to_cache(&index, drive, volume_serial, usn_journal_id, next_usn)
        {
            tracing::warn!(drive = %drive, error = %err, "⚠️ Failed to save cache (non-fatal)");
        }

        tracing::debug!(drive = %drive, "[TRIP] reader::read_and_cache_index EXIT");
        Ok(index)
    }
}
