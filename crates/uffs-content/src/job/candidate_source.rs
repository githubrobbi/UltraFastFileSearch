// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Candidate enumeration: turns a job's root directory into the flat list
//! of files that will become manifest candidates.

use std::path::{Path, PathBuf};
use std::{fs, io};

/// One enumerated candidate, before it's assigned a `candidate_id` and
/// turned into a `CandidateRecord` (see [`super::manifest_builder`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateEntry {
    /// Path relative to the job's root.
    pub relative_path: PathBuf,
    /// Absolute path a [`super::content_source::ContentSource`] can open.
    pub absolute_path: PathBuf,
    /// Logical file size in bytes.
    pub logical_size: u64,
    /// Modification time, Unix milliseconds.
    pub mtime_unix_ms: i64,
    /// Filesystem-assigned unique identity for this file. In production
    /// this is the NTFS file reference; this crate's cross-platform
    /// source uses the OS's native per-volume file identifier, which is
    /// stable across hard links the same way an NTFS file reference is.
    pub file_reference: u64,
}

/// Produces the candidate list for a job.
///
/// The production implementation (not yet built — UFI.1/UFI.2) evaluates
/// the job's UFFS query against an `MftIndex` built from a VSS snapshot.
/// [`DirWalkCandidateSource`] is a real, correct, but non-privileged
/// stand-in used until that lands: it walks the live filesystem directly,
/// which is exactly right for testing the Coordinator's own logic (this
/// is `uffs-ingest-implementation-plan.md` §9.5's "fast" harness) but is
/// not how a shipped job runs against NTFS.
pub trait CandidateSource {
    /// Enumerate every regular file under `root`.
    ///
    /// # Errors
    /// Propagates the underlying [`io::Error`] from directory traversal.
    fn enumerate(&self, root: &Path) -> io::Result<Vec<CandidateEntry>>;
}

/// Enumerates candidates by walking the live filesystem with `std::fs`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirWalkCandidateSource;

impl CandidateSource for DirWalkCandidateSource {
    fn enumerate(&self, root: &Path) -> io::Result<Vec<CandidateEntry>> {
        let mut entries = Vec::new();
        walk(root, root, &mut entries)?;
        Ok(entries)
    }
}

/// Recursively walks `dir` (rooted at `root`), appending one
/// [`CandidateEntry`] per regular file found, in deterministic
/// (path-sorted) order.
fn walk(root: &Path, dir: &Path, out: &mut Vec<CandidateEntry>) -> io::Result<()> {
    let mut dir_entries: Vec<fs::DirEntry> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    dir_entries.sort_by_key(fs::DirEntry::path);

    for entry in dir_entries {
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            walk(root, &path, out)?;
        } else if metadata.is_file() {
            let relative_path = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            out.push(CandidateEntry {
                relative_path,
                absolute_path: path,
                logical_size: metadata.len(),
                mtime_unix_ms: mtime_unix_ms(&metadata),
                file_reference: file_identity(&metadata),
            });
        }
    }
    Ok(())
}

/// Extracts a file's modification time as Unix milliseconds, defaulting
/// to `0` if the platform can't report one or it predates the epoch.
fn mtime_unix_ms(metadata: &fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

/// The file's inode number — stable across hard links to the same file.
#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    metadata.ino()
}

/// The file's NTFS file index — stable across hard links to the same
/// file, the Windows analogue of a Unix inode number.
#[cfg(windows)]
fn file_identity(metadata: &fs::Metadata) -> u64 {
    use std::os::windows::fs::MetadataExt as _;
    metadata.file_index().unwrap_or(0)
}

/// No native per-volume file identity is available on this platform;
/// hard-link detection simply won't apply here.
#[cfg(not(any(unix, windows)))]
const fn file_identity(_metadata: &fs::Metadata) -> u64 {
    0
}
