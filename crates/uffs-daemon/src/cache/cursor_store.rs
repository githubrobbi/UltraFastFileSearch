// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Disk-backed [`CursorStore`] for the Phase 7 activation commit.
//!
//! Persists each drive's last-applied USN cursor to
//! `<cache_dir>/<letter>_usn.cursor` (8 bytes little-endian) so a
//! daemon restart can resume the per-shard journal loop from where
//! it left off rather than re-streaming every change since `0`.
//!
//! ## Atomicity
//!
//! Writes go through [`uffs_security::fs::atomic_write`] (the same
//! tempfile-rename + fsync helper the compact-cache writer uses),
//! so a partial / interrupted write can never leave a torn cursor
//! on disk.  Reads return `0` for missing OR malformed files —
//! `0` is the loop's "rebuild from journal head" sentinel which is
//! the correct fallback for a never-saved or corrupted cursor.
//!
//! ## Mac / Linux fallback
//!
//! Production on macOS / Linux uses
//! [`crate::cache::journal_loop::sources::NullCursorStore`] instead — there is
//! no NTFS USN journal, so there is no cursor to persist.  `DiskCursorStore` is
//! built and wired only on Windows but its implementation is platform-agnostic
//! so Mac tests can drive every code path against a `tempdir` root.
//!
//! [`CursorStore`]: super::journal_loop::CursorStore

use std::path::PathBuf;

/// Disk-backed implementation of [`super::journal_loop::CursorStore`].
///
/// Construction takes the **cache root directory** rather than
/// computing it from `uffs_mft::cache::cache_dir()` so tests can
/// drive the round-trip semantics against a `tempfile::TempDir`
/// without colliding with the host's real cache directory.
#[derive(Debug)]
pub(crate) struct DiskCursorStore {
    /// Directory under which `<letter>_usn.cursor` files live.
    /// Production passes the result of `uffs_mft::cache::cache_dir()`;
    /// tests pass a per-test `TempDir` path.
    cache_root: PathBuf,
}

impl DiskCursorStore {
    /// Construct a store rooted at `cache_root`.
    ///
    /// `cache_root` is created lazily by
    /// [`crate::cache::journal_loop::CursorStore::store`] on the first save
    /// (matching the existing compact-cache writer's `create_secure_dir`
    /// pattern), so passing a not-yet-existing path is fine.
    #[must_use]
    pub(crate) const fn new(cache_root: PathBuf) -> Self {
        Self { cache_root }
    }

    /// Path to the cursor file for `letter`.
    fn cursor_path(&self, letter: uffs_mft::platform::DriveLetter) -> PathBuf {
        self.cache_root.join(format!("{letter}_usn.cursor"))
    }
}

impl super::journal_loop::CursorStore for DiskCursorStore {
    /// Load the persisted cursor for `letter`.
    ///
    /// Returns `0` for any of: file missing, wrong size,
    /// permission denied, I/O error.  The journal loop treats `0`
    /// as "start from journal head" which is the correct fallback
    /// for a never-saved or corrupted cursor — better to re-replay
    /// than to silently start from a stale or invalid USN.
    fn load(&self, letter: uffs_mft::platform::DriveLetter) -> u64 {
        let path = self.cursor_path(letter);
        match std::fs::read(&path) {
            Ok(bytes) => <[u8; 8]>::try_from(bytes.as_slice()).map_or_else(
                |_| {
                    tracing::warn!(
                        target: "shard.journal.cursor",
                        drive = %letter,
                        path = %path.display(),
                        bytes = bytes.len(),
                        "Cursor file has unexpected size; falling back to 0",
                    );
                    0
                },
                u64::from_le_bytes,
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
            Err(err) => {
                tracing::warn!(
                    target: "shard.journal.cursor",
                    drive = %letter,
                    path = %path.display(),
                    error = %err,
                    "Cursor file read failed; falling back to 0",
                );
                0
            }
        }
    }

    /// Persist `cursor` for `letter` via atomic tempfile + rename.
    ///
    /// Failures are tracing-logged but never propagate — the loop
    /// must remain resilient to a transient disk-full / permission
    /// glitch (the next save tick will retry, and an unsaved
    /// cursor is recoverable via journal-head re-replay).
    fn store(&self, letter: uffs_mft::platform::DriveLetter, cursor: u64) {
        let path = self.cursor_path(letter);
        // Ensure the cache directory exists with owner-only DACL —
        // matches the existing compact-cache writer's pattern.
        if let Err(err) = uffs_mft::cache::create_secure_dir(&self.cache_root) {
            tracing::warn!(
                target: "shard.journal.cursor",
                drive = %letter,
                path = %self.cache_root.display(),
                error = %err,
                "Failed to ensure cache dir for cursor write; skipping",
            );
            return;
        }
        let bytes = cursor.to_le_bytes();
        if let Err(err) = uffs_mft::cache::atomic_write(&path, &bytes) {
            tracing::warn!(
                target: "shard.journal.cursor",
                drive = %letter,
                path = %path.display(),
                cursor,
                error = %err,
                "Atomic cursor write failed; cursor not persisted this tick",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::journal_loop::CursorStore as _;
    use super::*;

    /// Round-trip: persist a cursor, then load and confirm equality.
    /// Pins the canonical happy path that the journal loop drives
    /// every save tick.
    #[test]
    fn round_trip_through_store_and_load() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = DiskCursorStore::new(tmp.path().to_path_buf());

        store.store(uffs_mft::platform::DriveLetter::C, 0x1234_5678_9ABC_DEF0);
        let loaded = store.load(uffs_mft::platform::DriveLetter::C);

        assert_eq!(loaded, 0x1234_5678_9ABC_DEF0);
    }

    /// Missing cursor file → `load` returns `0` so the loop falls
    /// back to journal head — the correct semantics for a
    /// never-saved drive (cold-boot, freshly-attached volume).
    #[test]
    fn missing_cursor_file_returns_zero() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = DiskCursorStore::new(tmp.path().to_path_buf());

        assert_eq!(store.load(uffs_mft::platform::DriveLetter::C), 0);
    }

    /// Corrupt cursor file (wrong byte count) → `load` returns `0`
    /// rather than panicking or returning a partial read.  The
    /// journal loop's zero-fallback semantics ensures correctness
    /// is preserved at the cost of one extra journal replay.
    #[test]
    fn corrupt_cursor_file_returns_zero() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("C_usn.cursor");
        // 4 bytes (not 8) — truncated write.
        std::fs::write(&path, [0x01, 0x02, 0x03, 0x04]).expect("write corrupt cursor");

        let store = DiskCursorStore::new(tmp.path().to_path_buf());
        assert_eq!(store.load(uffs_mft::platform::DriveLetter::C), 0);
    }

    /// `store` must create the cache directory if it doesn't yet
    /// exist (cold-boot first-save scenario).  The existing
    /// `create_secure_dir` helper handles owner-only DACL so the
    /// cursor file inherits the right posture.
    #[test]
    fn store_creates_cache_dir_if_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Point the store at a not-yet-existing subdirectory.
        let nested = tmp.path().join("brand_new_cache_root");
        assert!(!nested.exists(), "precondition: nested dir doesn't exist");
        let store = DiskCursorStore::new(nested.clone());

        store.store(uffs_mft::platform::DriveLetter::C, 42);

        assert!(nested.exists(), "cache dir must be created on first store");
        let loaded = store.load(uffs_mft::platform::DriveLetter::C);
        assert_eq!(loaded, 42);
    }

    /// Multiple drives under the same root must not interfere.
    /// Pins that the per-letter file naming (`<letter>_usn.cursor`)
    /// keeps each drive's cursor isolated.
    #[test]
    fn distinct_drives_have_independent_cursors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = DiskCursorStore::new(tmp.path().to_path_buf());

        store.store(uffs_mft::platform::DriveLetter::C, 100);
        store.store(uffs_mft::platform::DriveLetter::D, 200);
        store.store(uffs_mft::platform::DriveLetter::E, 300);

        assert_eq!(store.load(uffs_mft::platform::DriveLetter::C), 100);
        assert_eq!(store.load(uffs_mft::platform::DriveLetter::D), 200);
        assert_eq!(store.load(uffs_mft::platform::DriveLetter::E), 300);
    }

    /// Overwriting an existing cursor must succeed atomically and
    /// the new value must be loadable.  Pins the happy-path save
    /// trigger contract: every `trigger_save` produces a fresh
    /// `store(letter, cursor)` call that supersedes the previous
    /// persisted value.
    #[test]
    fn overwriting_cursor_replaces_previous_value() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = DiskCursorStore::new(tmp.path().to_path_buf());

        store.store(uffs_mft::platform::DriveLetter::C, 100);
        assert_eq!(store.load(uffs_mft::platform::DriveLetter::C), 100);
        store.store(uffs_mft::platform::DriveLetter::C, 200);
        assert_eq!(store.load(uffs_mft::platform::DriveLetter::C), 200);
        store.store(uffs_mft::platform::DriveLetter::C, u64::MAX);
        assert_eq!(store.load(uffs_mft::platform::DriveLetter::C), u64::MAX);
    }
}
