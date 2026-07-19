// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Content reading: turns a candidate + byte range into logical bytes.

use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom};

use super::candidate_source::CandidateEntry;

/// Reads a bounded range of a candidate's logical content.
///
/// The production implementation is `uffs-content`'s IPC client to
/// `uffs-content-reader` (`VssContentSource`, Windows-only — not in
/// scope on this platform's rustdoc build), which resolves and reads
/// against a VSS snapshot device, never the live volume.
/// [`FsContentSource`] is a real, correct, but unprivileged stand-in: it
/// reads the live file directly with `std::fs`. See
/// [`super::candidate_source::CandidateSource`] for why that's the right
/// trade-off for this crate's own fast, cross-platform test harness.
///
/// `Sync`: `workflow::run_job` reads several candidates' content
/// concurrently (one `std::thread::scope` thread each, sharing one
/// `&dyn ContentSource` — see that module's "Concurrent reads,
/// sequential emission" doc section), so any implementation must
/// tolerate concurrent `begin_read` calls from different threads. The
/// [`ReadSession`] a single `begin_read` call produces is used from
/// exactly one thread for its whole lifetime, so it carries no such
/// bound itself.
pub trait ContentSource: Sync {
    /// Begin a session for reading one candidate's *entire* content,
    /// pinning whatever connection/handle state that read needs for the
    /// session's whole lifetime rather than re-establishing it per
    /// chunk.
    ///
    /// This exists because `VssContentSource`'s production
    /// counterpart, `uffs-content-reader`, caches its open NTFS file
    /// handle per connection across consecutive requests for the same
    /// file (real-hardware benchmarking found the alternative — a fresh
    /// `OpenFileById` on every chunk — dominates read time on large
    /// files far more than actual disk throughput does). That cache
    /// only helps if a candidate's chunks all land on the *same*
    /// connection, which is exactly what pinning one session to one
    /// connection for the read's whole duration guarantees.
    ///
    /// `candidate_id` is the same id `manifest_builder::build_manifest`
    /// assigned this candidate (the caller already has it — see
    /// `workflow::run_job`'s `entries.iter().zip(&built.candidate_ids)`)
    /// — the production implementation needs it to correlate every read
    /// in the session against the finalized manifest over the Reader's
    /// wire protocol; [`FsContentSource`] ignores it entirely.
    ///
    /// # Errors
    /// Propagates the underlying [`io::Error`] from whatever
    /// establishing a session requires (e.g. opening the file, or
    /// checking out a pooled connection).
    fn begin_read(
        &self,
        candidate: &CandidateEntry,
        candidate_id: u64,
    ) -> io::Result<Box<dyn ReadSession>>;
}

/// One candidate's whole sequential read session, opened by
/// [`ContentSource::begin_read`]. Ends (releases whatever connection/
/// handle it pinned) when dropped.
pub trait ReadSession {
    /// Read up to `max_len` bytes starting at `offset`, continuing this
    /// session.
    ///
    /// Returns fewer than `max_len` bytes only at EOF (matching a normal
    /// [`std::io::Read::read`] short-read contract at end of file); an
    /// empty result means `offset` was at or past EOF.
    ///
    /// # Errors
    /// Propagates the underlying [`io::Error`] from seeking/reading.
    fn read_at(&mut self, offset: u64, max_len: u32) -> io::Result<Vec<u8>>;
}

/// Reads content directly from the live filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct FsContentSource;

impl ContentSource for FsContentSource {
    fn begin_read(
        &self,
        candidate: &CandidateEntry,
        _candidate_id: u64,
    ) -> io::Result<Box<dyn ReadSession>> {
        let file = File::open(&candidate.absolute_path)?;
        Ok(Box::new(FsReadSession { file }))
    }
}

/// [`FsContentSource`]'s session: just the one already-open file, kept
/// open for the candidate's whole read instead of reopened per chunk —
/// mirrors `VssContentSource`'s real optimization even though a local
/// `std::fs::File` open is cheap enough that it wouldn't matter much on
/// its own; keeping the two implementations' shapes symmetric is the
/// point.
struct FsReadSession {
    /// The candidate's already-open file handle.
    file: File,
}

impl ReadSession for FsReadSession {
    fn read_at(&mut self, offset: u64, max_len: u32) -> io::Result<Vec<u8>> {
        self.file.seek(SeekFrom::Start(offset))?;

        let capacity = usize::try_from(max_len).unwrap_or(usize::MAX);
        let mut buffer = vec![0_u8; capacity];
        let mut total_read = 0_usize;
        while total_read < buffer.len() {
            let remaining = buffer.get_mut(total_read..).unwrap_or(&mut []);
            let read = self.file.read(remaining)?;
            if read == 0 {
                break;
            }
            total_read += read;
        }
        buffer.truncate(total_read);
        Ok(buffer)
    }
}

/// Reads content from a VSS snapshot via the privileged
/// `uffs-content-reader` process (see [`super::reader_client`]).
///
/// Windows-only: VSS snapshots, and the Reader that reads them, don't
/// exist on any other platform — matching [`super::ephemeral_daemon`]'s
/// and [`super::vss_orchestrator`]'s own scoping.
#[cfg(windows)]
pub struct VssContentSource {
    /// The spawned Reader process + its live connection for this job.
    reader: super::reader_client::ContentReader,
}

#[cfg(windows)]
impl VssContentSource {
    /// Wrap an already-spawned [`super::reader_client::ContentReader`].
    #[must_use]
    pub(crate) const fn new(reader: super::reader_client::ContentReader) -> Self {
        Self { reader }
    }

    /// Tear down the wrapped Reader process. Explicit (rather than
    /// relying on `Drop`) so a failed teardown is observable, mirroring
    /// how [`super::vss_orchestrator::EphemeralJobResources::teardown`]
    /// handles the ephemeral daemon.
    ///
    /// # Errors
    /// Returns an error if the Reader process couldn't be killed.
    pub(crate) fn shutdown(self) -> anyhow::Result<()> {
        self.reader.shutdown()
    }
}

#[cfg(windows)]
impl ContentSource for VssContentSource {
    fn begin_read(
        &self,
        candidate: &CandidateEntry,
        candidate_id: u64,
    ) -> io::Result<Box<dyn ReadSession>> {
        let session = self
            .reader
            .begin_read(
                candidate.snapshot_lease_id,
                candidate_id,
                candidate.file_reference,
                candidate.logical_size,
            )
            .map_err(|err| io::Error::other(err.to_string()))?;
        Ok(Box::new(session))
    }
}
