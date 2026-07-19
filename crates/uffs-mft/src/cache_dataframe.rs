// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Cached `DataFrame` loading (Windows-only).
//!
//! Extracted from `cache.rs` for file-size policy compliance.
//! These functions combine MFT reading with cache management to produce
//! Polars `DataFrame`s.

#[cfg(windows)]
use super::{load_cached_index, save_to_cache_background};

/// Loads a cached index and converts to `DataFrame`, or builds fresh if cache
/// miss.
///
/// This is the recommended way to get a `DataFrame` with caching support.
/// It uses the lean `MftIndex` cache format and converts to `DataFrame` on
/// demand.
///
/// # Arguments
///
/// * `drive` - Drive letter to read
/// * `ttl_seconds` - TTL in seconds for cache freshness
///
/// # Returns
///
/// A `DataFrame` with all MFT records for the drive.
///
/// # Errors
///
/// Returns an error if MFT reading or `DataFrame` conversion fails.
///
/// # Note
///
/// This function uses `spawn_blocking` internally to avoid nested tokio runtime
/// issues. Polars uses tokio internally for some operations, and calling polars
/// from within a tokio async context can cause "Cannot start a runtime from
/// within a runtime" panics. By running all MFT reading and polars operations
/// on a dedicated blocking thread, we avoid this issue.
#[cfg(windows)]
pub async fn load_or_build_dataframe_cached(
    drive: crate::platform::DriveLetter,
    ttl_seconds: u64,
) -> crate::Result<uffs_polars::DataFrame> {
    tracing::debug!(drive = %drive, ttl_seconds, "Entering cached DataFrame load/build");
    let result = tokio::task::spawn_blocking(move || {
        tracing::debug!(
            drive = %drive,
            ttl_seconds,
            "Running cached DataFrame load/build on blocking thread"
        );
        load_or_build_dataframe_cached_sync(drive, ttl_seconds)
    })
    .await
    .map_err(|error| crate::MftError::from_join_error("load_or_build_dataframe_cached", &error))?;
    tracing::debug!(
        drive = %drive,
        ttl_seconds,
        success = result.is_ok(),
        "Completed cached DataFrame load/build"
    );
    result
}

/// Synchronous version of [`load_or_build_dataframe_cached`].
///
/// This is the actual implementation that runs on a blocking thread.
/// It performs all MFT reading and polars operations synchronously.
#[cfg(windows)]
fn load_or_build_dataframe_cached_sync(
    drive: crate::platform::DriveLetter,
    ttl_seconds: u64,
) -> crate::Result<uffs_polars::DataFrame> {
    tracing::debug!(
        drive = %drive,
        ttl_seconds,
        "Entering synchronous cached DataFrame load/build"
    );

    if let Some(df) = load_cached_dataframe(drive, ttl_seconds) {
        return df;
    }

    build_fresh_dataframe(drive)
}

/// Try to load and convert the cached index for `drive`.  Returns
/// `Some(_)` whenever the cache lookup hit (the inner `Result` carries
/// any conversion failure); returns `None` only on cache miss.
#[cfg(windows)]
fn load_cached_dataframe(
    drive: crate::platform::DriveLetter,
    ttl_seconds: u64,
) -> Option<crate::Result<uffs_polars::DataFrame>> {
    let (index, _header) = load_cached_index(drive, ttl_seconds)?;
    tracing::info!(
        drive = %drive,
        records = index.records.len(),
        "📦 Cache hit - converting to DataFrame"
    );
    let df = index.to_dataframe();
    log_conversion_result(drive, &df, "cached");
    Some(df)
}

/// Read the MFT fresh, kick off a background cache save, and convert the
/// resulting index into a [`uffs_polars::DataFrame`].  Used after a cache miss.
#[cfg(windows)]
fn build_fresh_dataframe(
    drive: crate::platform::DriveLetter,
) -> crate::Result<uffs_polars::DataFrame> {
    let index = read_fresh_index(drive)?;
    spawn_cache_save(drive, &index)?;

    tracing::debug!(
        drive = %drive,
        records = index.len(),
        "Converting fresh index to DataFrame"
    );
    let df = index.to_dataframe();
    log_conversion_result(drive, &df, "fresh");
    df
}

/// Open the MFT reader for `drive` and synchronously read every record
/// into an [`crate::index::MftIndex`].  Wraps the tracing pair around the slow
/// read.
#[cfg(windows)]
fn read_fresh_index(drive: crate::platform::DriveLetter) -> crate::Result<crate::index::MftIndex> {
    use crate::reader::MftReader;

    tracing::info!(drive = %drive, "📖 Cache miss - reading MFT fresh");
    let reader = MftReader::open(drive)?;
    tracing::debug!(drive = %drive, "Opened MFT reader; reading fresh index");
    let index = reader.read_all_index_sync()?;
    tracing::debug!(
        drive = %drive,
        records = index.len(),
        "Completed fresh index read"
    );
    Ok(index)
}

/// Pull volume / USN-journal metadata for `drive` and hand the index off
/// to the background cache writer.  `VolumeHandle` failures propagate to
/// the caller (matching pre-refactor semantics); cache-save failures are
/// logged at warn so the surrounding [`build_fresh_dataframe`] flow can
/// still hand the freshly-built [`uffs_polars::DataFrame`] back to the user.
#[cfg(windows)]
fn spawn_cache_save(
    drive: crate::platform::DriveLetter,
    index: &crate::index::MftIndex,
) -> crate::Result<()> {
    use crate::VolumeHandle;
    use crate::usn::query_usn_journal;

    let handle = VolumeHandle::open(drive)?;
    let volume_serial = handle.volume_data().volume_serial_number;
    let (usn_journal_id, next_usn) = query_usn_journal(drive)
        .map_or((0, crate::usn::Usn::ZERO), |info| {
            (info.journal_id, info.next_usn)
        });

    if let Err(err) =
        save_to_cache_background(index, drive, volume_serial, usn_journal_id, next_usn)
    {
        tracing::warn!(drive = %drive, error = %err, "Failed to start cache save");
    }
    Ok(())
}

/// Common tracing for `to_dataframe` outcomes, parameterised on whether
/// the index came from the cache or a fresh MFT read.
#[cfg(windows)]
fn log_conversion_result(
    drive: crate::platform::DriveLetter,
    df: &crate::Result<uffs_polars::DataFrame>,
    source: &'static str,
) {
    match df {
        Ok(dataframe) => tracing::debug!(
            drive = %drive,
            source,
            rows = dataframe.height(),
            columns = dataframe.width(),
            "Converted index to DataFrame"
        ),
        Err(error) => tracing::debug!(
            drive = %drive,
            source,
            error = %error,
            "Index DataFrame conversion failed"
        ),
    }
}
