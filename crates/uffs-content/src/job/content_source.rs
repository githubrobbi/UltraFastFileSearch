// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Content reading: turns a candidate + byte range into logical bytes.

use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom};

use super::candidate_source::CandidateEntry;

/// Reads a bounded range of a candidate's logical content.
///
/// The production implementation (not yet built — UFI.2) is
/// `uffs-content`'s IPC client to `uffs-content-reader`, which resolves
/// and reads against a VSS snapshot device, never the live volume.
/// [`FsContentSource`] is a real, correct, but unprivileged stand-in: it
/// reads the live file directly with `std::fs`. See
/// [`super::candidate_source::CandidateSource`] for why that's the right
/// trade-off for this crate's own fast, cross-platform test harness.
///
/// `Sync`: `workflow::run_job` reads several candidates' content
/// concurrently (one `std::thread::scope` thread each, sharing one
/// `&dyn ContentSource` — see that module's "Concurrent reads,
/// sequential emission" doc section), so any implementation must
/// tolerate concurrent `read_at` calls from different threads.
pub trait ContentSource: Sync {
    /// Read up to `max_len` bytes starting at `offset` from `candidate`.
    ///
    /// `candidate_id` is the same id `manifest_builder::build_manifest`
    /// assigned this candidate (the caller already has it — see
    /// `workflow::run_job`'s `entries.iter().zip(&built.candidate_ids)`)
    /// — the production implementation needs it to correlate this read
    /// against the finalized manifest over the Reader's wire protocol;
    /// [`FsContentSource`] ignores it entirely.
    ///
    /// Returns fewer than `max_len` bytes only at EOF (matching a normal
    /// [`std::io::Read::read`] short-read contract at end of file); an
    /// empty result means `offset` was at or past EOF.
    ///
    /// # Errors
    /// Propagates the underlying [`io::Error`] from opening/seeking/
    /// reading the file.
    fn read_at(
        &self,
        candidate: &CandidateEntry,
        candidate_id: u64,
        offset: u64,
        max_len: u32,
    ) -> io::Result<Vec<u8>>;
}

/// Reads content directly from the live filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct FsContentSource;

impl ContentSource for FsContentSource {
    fn read_at(
        &self,
        candidate: &CandidateEntry,
        _candidate_id: u64,
        offset: u64,
        max_len: u32,
    ) -> io::Result<Vec<u8>> {
        let mut file = File::open(&candidate.absolute_path)?;
        file.seek(SeekFrom::Start(offset))?;

        let capacity = usize::try_from(max_len).unwrap_or(usize::MAX);
        let mut buffer = vec![0_u8; capacity];
        let mut total_read = 0_usize;
        while total_read < buffer.len() {
            let remaining = buffer.get_mut(total_read..).unwrap_or(&mut []);
            let read = file.read(remaining)?;
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
    fn read_at(
        &self,
        candidate: &CandidateEntry,
        candidate_id: u64,
        offset: u64,
        max_len: u32,
    ) -> io::Result<Vec<u8>> {
        self.reader
            .read_at(
                candidate.snapshot_lease_id,
                candidate_id,
                candidate.file_reference,
                offset,
                max_len,
            )
            .map_err(|err| io::Error::other(err.to_string()))
    }
}
