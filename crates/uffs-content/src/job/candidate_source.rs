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
    /// Which VSS snapshot lease (see `super::snapshot_client::SnapshotLease`)
    /// this candidate's device path/file reference resolve against — a
    /// job may lease more than one drive. `0` (never a real lease id,
    /// which the Broker assigns starting from 1) for
    /// [`DirWalkCandidateSource`], which has no snapshot at all.
    pub snapshot_lease_id: u64,
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
///
/// `Sync`: `run_job` enumerates every root concurrently (one thread per
/// root via `std::thread::scope`, mirroring the same shape as
/// [`super::content_source::ContentSource`]'s own `Sync` bound) — real-hardware
/// benchmarking found root-by-root enumeration strictly sequential today,
/// even though each `enumerate` call opens its own independent connection
/// to the daemon and shares no mutable state with any other call.
pub trait CandidateSource: Sync {
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
                snapshot_lease_id: 0,
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

/// Evaluates a job's query against the ephemeral, VSS-snapshot-backed
/// `uffsd` instance `prepare_ephemeral_daemon_for_roots`
/// ([`super::vss_orchestrator`]) spawned — the real production
/// `CandidateSource`.
///
/// Windows-only: VSS snapshots, and the ephemeral daemon that queries
/// them, don't exist on any other platform — matching
/// [`super::ephemeral_daemon`]'s own scoping.
#[cfg(windows)]
pub struct VssCandidateSource<'a> {
    /// UFFS name/path pattern (`JobRequest::query`), forwarded verbatim
    /// to the daemon as `SearchParams::pattern`.
    pattern: String,
    // Remaining filter fields, forwarded verbatim to the matching
    // `SearchParams` field — see `JobRequest`'s doc comment for why
    // this is a deliberately curated subset, not the full daemon
    // filter surface.
    /// Mirrors `SearchParams::ext`.
    ext: Option<String>,
    /// Mirrors `SearchParams::min_size`.
    min_size: Option<u64>,
    /// Mirrors `SearchParams::max_size`.
    max_size: Option<u64>,
    /// Mirrors `SearchParams::newer`.
    newer: Option<String>,
    /// Mirrors `SearchParams::older`.
    older: Option<String>,
    /// Mirrors `SearchParams::exclude`.
    exclude: Option<String>,
    /// Mirrors `SearchParams::attr`.
    attr: Option<String>,
    /// The already-spawned, already-`Ready` ephemeral daemon covering
    /// every drive this job leased.
    daemon: &'a super::ephemeral_daemon::EphemeralDaemon,
    /// Drive letter -> lease id, so each result row (which only carries
    /// a drive letter) can be tagged with the lease
    /// [`super::content_source::VssContentSource`] will need to read it
    /// back afterward.
    drive_to_lease: std::collections::HashMap<char, u64>,
}

#[cfg(windows)]
impl<'a> VssCandidateSource<'a> {
    /// Wrap an already-spawned, already-`Ready` ephemeral daemon,
    /// copying every filter field off `request`.
    #[must_use]
    pub(crate) fn new(
        request: &super::intake::JobRequest,
        daemon: &'a super::ephemeral_daemon::EphemeralDaemon,
        drive_to_lease: std::collections::HashMap<char, u64>,
    ) -> Self {
        Self {
            pattern: request.query.clone(),
            ext: request.ext.clone(),
            min_size: request.min_size,
            max_size: request.max_size,
            newer: request.newer.clone(),
            older: request.older.clone(),
            exclude: request.exclude.clone(),
            attr: request.attr.clone(),
            daemon,
            drive_to_lease,
        }
    }
}

#[cfg(windows)]
impl CandidateSource for VssCandidateSource<'_> {
    fn enumerate(&self, root: &Path) -> io::Result<Vec<CandidateEntry>> {
        tracing::info!(root = %root.display(), "candidate enumeration: connecting to ephemeral daemon");
        let mut client = self.daemon.connect().map_err(|err| {
            tracing::warn!(root = %root.display(), error = %err, "candidate enumeration: connect failed");
            io::Error::other(err.to_string())
        })?;

        // Scope the search to this job's root: `path_contains` is a
        // directory-path glob matched against each record's directory
        // portion — `<root>*` restricts results to the subtree without
        // needing this crate to walk anything itself.
        let root_glob = format!("{}*", root.display());
        let params = uffs_client::protocol::SearchParams {
            pattern: self.pattern.clone(),
            filter_mode: Some(uffs_client::protocol::SearchFilterMode::Files),
            path_contains: Some(root_glob),
            limit: None,
            ext: self.ext.clone(),
            min_size: self.min_size,
            max_size: self.max_size,
            newer: self.newer.clone(),
            older: self.older.clone(),
            exclude: self.exclude.clone(),
            attr: self.attr.clone(),
            // Real-hardware benchmarking found reading candidates in
            // match order (or even ascending-FRS order) leaves most of
            // the achievable seek-distance reduction on the table for a
            // volume that's been reorganized over years -- see
            // docs/architecture/content-stream-tool-design.md. Bulk
            // content reads are exactly the workload that benefits from
            // this; interactive CLI searches never set it.
            resolve_lcn_order: true,
            ..Default::default()
        };
        tracing::info!(
            root = %root.display(),
            params = %serde_json::to_string(&params).unwrap_or_else(|err| format!("<undeserializable: {err}>")),
            "candidate enumeration: sending search request"
        );
        let response = client.search(&params).map_err(|err| {
            tracing::warn!(root = %root.display(), error = %err, "candidate enumeration: search request failed");
            io::Error::other(err.to_string())
        })?;

        let rows = resolve_rows(response.payload)?;
        let row_count = rows.len();
        log_first_rows(root, &rows);
        let deduped = dedup_rows_by_file_reference_and_path(rows);
        tracing::info!(
            root = %root.display(),
            rows = row_count,
            deduped = deduped.len(),
            "candidate enumeration: search response received"
        );

        let mut entries = Vec::with_capacity(deduped.len());
        for row in deduped {
            let letter = row.drive.as_char();
            let Some(&lease_id) = self.drive_to_lease.get(&letter) else {
                return Err(io::Error::other(format!(
                    "search result on drive {letter} has no matching lease for this job"
                )));
            };
            let path = PathBuf::from(&row.path);
            let relative_path = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            entries.push(CandidateEntry {
                relative_path,
                absolute_path: path,
                logical_size: row.size,
                // `SearchRow::modified` is Unix *microseconds*;
                // `CandidateEntry::mtime_unix_ms` is Unix milliseconds.
                mtime_unix_ms: row.modified / 1000,
                file_reference: row.file_reference,
                snapshot_lease_id: lease_id,
            });
        }
        Ok(entries)
    }
}

/// Log the first 20 raw rows exactly as the daemon returned them —
/// *before* [`dedup_rows_by_file_reference_and_path`] touches anything —
/// one full JSON row per log line so duplicates/corruption are visible
/// by eye without reconstructing them from a single giant blob.
/// Diagnostic aid for the row-count-inflation investigation (real
/// hardware has shown search returning far more rows than the true file
/// count for some drives, in ways the existing exact-duplicate dedup
/// doesn't catch).
#[cfg(windows)]
fn log_first_rows(root: &Path, rows: &[uffs_client::protocol::response::SearchRow]) {
    for (index, row) in rows.iter().take(20).enumerate() {
        tracing::info!(
            root = %root.display(),
            index,
            row = %serde_json::to_string(row).unwrap_or_else(|err| format!("<undeserializable: {err}>")),
            "candidate enumeration: raw row"
        );
    }
}

/// Resolve a `SearchPayload` into its `SearchRow` list, reading a
/// shmem-backed result set from disk if the daemon chose that delivery
/// channel — a job-scoped query is usually small enough to stay inline,
/// but a job matching many files could still cross the daemon's shmem
/// threshold.
#[cfg(windows)]
fn resolve_rows(
    payload: uffs_client::protocol::response::SearchPayload,
) -> io::Result<Vec<uffs_client::protocol::response::SearchRow>> {
    use uffs_client::protocol::response::SearchPayload;
    match payload {
        SearchPayload::Empty => Ok(Vec::new()),
        SearchPayload::InlineRows(rows) => Ok(rows),
        SearchPayload::ShmemRows { path, .. } => {
            uffs_client::shmem::read_search_results(Path::new(&path))
                .map(|response| response.payload.into_inline_rows().unwrap_or_default())
        }
        SearchPayload::InlineBlob(_) | SearchPayload::ShmemBlob(_) => Err(io::Error::other(
            "daemon returned a pre-formatted text blob instead of structured rows",
        )),
    }
}

/// Collapse exact-duplicate rows the daemon's search occasionally returns
/// for the same physical file. Seen on real hardware: a fresh, uncached
/// VSS-device MFT parse returned two byte-for-byte identical rows (same
/// `file_reference`, same path, same everything) for files that have no
/// NTFS extension record and (for 3 of the 4 observed) only a single
/// on-disk `$FILE_NAME` attribute — ruling out extension-record/attribute-
/// list double-counting as the cause. Root cause not yet pinned down
/// (suspected: a chunk-scheduling double-read in the sliding-window I/O
/// reader); this dedup is a defensive guard on this crate's own
/// consumption of the daemon's response, independent of wherever the
/// duplication actually originates.
///
/// Keyed on `(file_reference, path)`, not `file_reference` alone: a
/// genuine hard link shares the same `file_reference` across multiple
/// *different* paths, and those must stay as separate candidates (that's
/// the whole point of `expand_links`). Only a row that is identical in
/// both file identity *and* path — which is what a spurious double-count
/// produces — gets collapsed. Preserves input order (first occurrence of
/// each key wins).
#[cfg(windows)]
fn dedup_rows_by_file_reference_and_path(
    rows: Vec<uffs_client::protocol::response::SearchRow>,
) -> Vec<uffs_client::protocol::response::SearchRow> {
    let mut seen: std::collections::HashSet<(u64, String)> = std::collections::HashSet::new();
    rows.into_iter()
        .filter(|row| seen.insert((row.file_reference, row.path.clone())))
        .collect()
}
