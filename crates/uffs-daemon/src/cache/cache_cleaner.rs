// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Per-drive cache-file cleanup hook for the Phase 8-D `forget` RPC.
//!
//! `IndexManager::forget_drive` removes a shard from the registry
//! **and** purges every per-drive artefact from the platform cache
//! directory (encrypted compact body, USN cursor, MFT index, lock).
//! The on-disk side effect is wrapped in this trait so:
//!
//! * Production gets [`PlatformCacheCleaner`] which calls
//!   [`uffs_core::compact_cache::compact_cache_path`] and friends to resolve
//!   the real platform paths and unlinks them via [`std::fs::remove_file`].
//! * Tests inject `CountingCacheCleaner` (and the temp-dir-backed helper
//!   [`delete_drive_cache_files`] is unit-tested directly with a
//!   `tempfile::TempDir`) so the registry-eviction behaviour can be verified
//!   without ever touching the host's real cache directory — which would
//!   otherwise be a destructive operation when a test asks the daemon to
//!   "forget drive C".
//!
//! Mirrors the [`super::body_loader::BodyLoader`] /
//! [`super::working_set::WorkingSetTrim`] hook pattern (Phase 5):
//! one `Arc<dyn Trait>` field on
//! `LifecycleHooks`, the production
//! impl is wired in [`super::body_loader::DiskBodyLoader`]-style at
//! daemon bootstrap, and the test escape hatches stay narrow.

use std::io;
use std::path::{Path, PathBuf};

/// Per-drive cache cleanup operation.
///
/// Used by [`crate::index::IndexManager::forget_drives`] to delete
/// every on-disk artefact tied to a specific drive letter once the
/// shard has been evicted from the in-memory registry.
///
/// Implementations report a `(freed_bytes, errors)` pair: the byte
/// total is summed across every successfully-unlinked file, and the
/// errors vector carries one prefixed string per failure (`"<path>:
/// <io::Error>"`).  Missing files are **not** errors — `forget` is
/// idempotent on already-absent caches so a re-run after a partial
/// failure makes progress instead of looping.
pub(crate) trait CacheCleaner: Send + Sync + 'static {
    /// Delete every per-drive cache file for `letter`.
    ///
    /// Returns `(freed_bytes, errors)`.  `freed_bytes` is the sum of
    /// `metadata.len()` over every file actually removed; `errors`
    /// is empty on full success and one entry per non-`NotFound`
    /// `io::Error` otherwise.
    fn forget(&self, letter: uffs_mft::platform::DriveLetter) -> (u64, Vec<String>);
}

/// Production implementation that resolves the four canonical
/// per-drive paths via the public helpers in
/// [`uffs_core::compact_cache`] and [`uffs_mft::cache`], then
/// unlinks each via [`std::fs::remove_file`].
///
/// The four paths cover every on-disk artefact a daemon writes per
/// drive:
///
/// 1. `<cache_dir>/<lower>_compact.uffs` — encrypted compact body (the
///    Cold-tier source-of-truth for re-promote).
/// 2. `<cache_dir>/<lower>_usn.cursor` — Phase 7 USN cursor used by the
///    per-shard journal loop on Windows.
/// 3. `<cache_dir>/<UPPER>_index.uffs` — full MFT index cache (used by the
///    loader on cold boot).
/// 4. `<cache_dir>/<UPPER>_index.lock` — fcntl lock file paired with
///    `_index.uffs`.
pub(crate) struct PlatformCacheCleaner;

impl CacheCleaner for PlatformCacheCleaner {
    fn forget(&self, letter: uffs_mft::platform::DriveLetter) -> (u64, Vec<String>) {
        let paths = drive_cache_paths(letter);
        delete_drive_cache_files(&paths)
    }
}

/// The four canonical cache-file paths a daemon owns per drive.
///
/// Exposed at module scope so the unit test in this file's `tests`
/// submodule can drive [`delete_drive_cache_files`] against a
/// `tempfile::TempDir` without dragging the platform paths into
/// the test fixture.
fn drive_cache_paths(letter: uffs_mft::platform::DriveLetter) -> [PathBuf; 4] {
    [
        uffs_core::compact_cache::compact_cache_path(letter),
        uffs_core::compact_cache::usn_cursor_path(letter),
        uffs_mft::cache::cache_file_path(letter),
        uffs_mft::cache::cache_lock_path(letter),
    ]
}

/// Unlink every regular-file path in `paths`, returning the total
/// byte count of successfully-removed files plus any per-path
/// errors.
///
/// Behaviour:
///
/// * Missing paths are silent no-ops (idempotent re-runs).
/// * Non-file entries (directories, sockets, …) are skipped — the daemon only
///   writes regular files into its cache directory, so a non-file at one of
///   these paths is structural and the safer action is "leave it for the
///   operator" rather than recurse.
/// * `permission denied` and other genuine errors land in the returned
///   `Vec<String>` prefixed with the offending path's `Display` form.
fn delete_drive_cache_files(paths: &[PathBuf]) -> (u64, Vec<String>) {
    let mut freed: u64 = 0;
    let mut errors: Vec<String> = Vec::new();
    for path in paths {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.is_file() => {
                let size = meta.len();
                match std::fs::remove_file(path) {
                    Ok(()) => freed = freed.saturating_add(size),
                    Err(err) => errors.push(format_path_error(path, &err)),
                }
            }
            // Non-file (dir / symlink / fifo) — leave alone.  The
            // daemon's writers (`atomic_write` + `save_compact_cache`)
            // only ever produce regular files at these paths; anything
            // else is a structural surprise the operator should
            // investigate manually.
            Ok(_) => {}
            // Idempotent: missing file is success.
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => errors.push(format_path_error(path, &err)),
        }
    }
    (freed, errors)
}

/// Render a single `(path, error)` pair into the
/// `"<path>: <io::Error>"` string format documented on
/// [`CacheCleaner::forget`].
fn format_path_error(path: &Path, err: &io::Error) -> String {
    format!("{}: {err}", path.display())
}

// ── Test fakes ─────────────────────────────────────────────────────

/// Counting test fake.  Records every `forget(letter)` call so the
/// integration tests in `crate::index::tests::forget_status` can
/// assert on the per-letter call sequence without touching the
/// host filesystem.
///
/// Reports a fixed `freed_per_call` byte count and an empty error
/// vector — the daemon-side error-aggregation paths are exercised
/// separately by an `ErroringCacheCleaner` in the same test module.
#[cfg(test)]
pub(crate) struct CountingCacheCleaner {
    calls: std::sync::Mutex<Vec<uffs_mft::platform::DriveLetter>>,
    freed_per_call: u64,
}

#[cfg(test)]
impl CountingCacheCleaner {
    /// Create a fresh counter with `freed_per_call` reported on
    /// every successful `forget`.
    #[must_use]
    pub(crate) fn new(freed_per_call: u64) -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            freed_per_call,
        }
    }

    /// Snapshot the per-letter call sequence.  Cloned out of the
    /// internal `Mutex` so the assertion site doesn't have to hold
    /// the lock.
    pub(crate) fn calls(&self) -> Vec<uffs_mft::platform::DriveLetter> {
        self.calls
            .lock()
            .expect("CountingCacheCleaner::calls — mutex poisoned in test fixture")
            .clone()
    }
}

#[cfg(test)]
impl CacheCleaner for CountingCacheCleaner {
    fn forget(&self, letter: uffs_mft::platform::DriveLetter) -> (u64, Vec<String>) {
        self.calls
            .lock()
            .expect("CountingCacheCleaner::forget — mutex poisoned in test fixture")
            .push(letter);
        (self.freed_per_call, Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::{fs, io};

    use tempfile::TempDir;

    use super::{delete_drive_cache_files, format_path_error};

    /// `delete_drive_cache_files` returns `(0, [])` when every path
    /// in the input slice is missing (idempotent re-run after a
    /// previous `forget` call).
    #[test]
    fn missing_files_yield_zero_freed_and_no_errors() {
        let tmp = TempDir::new().expect("tempdir");
        let paths = [
            tmp.path().join("a.uffs"),
            tmp.path().join("b.cursor"),
            tmp.path().join("c.lock"),
        ];

        let (freed, errors) = delete_drive_cache_files(&paths);

        assert_eq!(freed, 0);
        assert_eq!(errors, Vec::<String>::new());
    }

    /// `delete_drive_cache_files` sums file sizes correctly across
    /// a mix of present and missing paths.
    #[test]
    fn freed_bytes_sum_across_present_files() {
        let tmp = TempDir::new().expect("tempdir");
        let path_a = tmp.path().join("a.uffs");
        let path_b = tmp.path().join("b.cursor");
        let path_missing = tmp.path().join("missing.lock");
        fs::write(&path_a, vec![0_u8; 17]).expect("seed a");
        fs::write(&path_b, vec![0_u8; 23]).expect("seed b");

        let (freed, errors) =
            delete_drive_cache_files(&[path_a.clone(), path_b.clone(), path_missing]);

        assert_eq!(freed, 40, "17 + 23 = 40 freed bytes");
        assert!(
            errors.is_empty(),
            "missing file is not an error; got: {errors:?}"
        );
        assert!(!path_a.exists(), "a.uffs must be unlinked");
        assert!(!path_b.exists(), "b.cursor must be unlinked");
    }

    /// Directories and other non-file entries at the cache paths
    /// are skipped without an error — the daemon only writes
    /// regular files, so a directory there is structural and left
    /// alone.
    #[test]
    fn non_file_entries_are_skipped_silently() {
        let tmp = TempDir::new().expect("tempdir");
        let path_dir = tmp.path().join("subdir");
        fs::create_dir(&path_dir).expect("seed subdir");

        let (freed, errors) = delete_drive_cache_files(core::slice::from_ref(&path_dir));

        assert_eq!(freed, 0);
        assert_eq!(errors, Vec::<String>::new());
        assert!(path_dir.exists(), "non-file entry must be left in place");
    }

    /// `format_path_error` produces the `"<path>: <error>"` format
    /// the wire schema documents, so the CLI can grep an `errors`
    /// list and match drive-letter prefixes consistently.
    #[test]
    fn format_path_error_includes_display_and_message() {
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let path = Path::new("/var/cache/uffs/Z_compact.uffs");

        let rendered = format_path_error(path, &err);

        assert!(rendered.contains("/var/cache/uffs/Z_compact.uffs"));
        assert!(rendered.contains("denied"));
    }
}
