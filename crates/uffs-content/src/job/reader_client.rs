// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Coordinator-side client for `uffs-content-reader-protocol`.
//!
//! Spawns `uffs-content-reader --device <path>=<snapshot_lease_id> ...`
//! once per job — mirrors [`super::ephemeral_daemon`]'s spawn model, but
//! for the content-reading phase rather than target selection — and
//! opens **a pool of persistent connections per leased drive** to its
//! fixed `READER_PIPE_NAME`, sending framed `ReadRequest`/`ReadResponse`
//! messages over whichever pool matches a read's `snapshot_lease_id`.
//!
//! Each pool's *size* is chosen by the caller (`vss_job.rs`), not fixed
//! here — see `CONNECTIONS_PER_DRIVE`'s doc comment for why an
//! HDD-backed drive gets exactly one connection (real read concurrency
//! of 1, preserving the enumeration/MFT order candidates were collected
//! in) while an NVMe/SSD-backed drive gets many. Keying pools by
//! `snapshot_lease_id` means reads for different drives never contend
//! on each other's pool regardless of size.
//!
//! Each pool is a bounded [`crossbeam_channel`] of already-open
//! connections: checking one out is a blocking `recv` (waits for a
//! connection to free up rather than erroring), and a connection that
//! survives its round trip unscathed is sent back for reuse. A
//! connection that errors mid-round-trip (frame desync, pipe reset) is
//! deliberately *not* returned — better to shrink that drive's pool by
//! one than serve subsequent reads over a connection in an unknown
//! framing state.
//!
//! Mirrors [`super::snapshot_client`]'s connect style (plain
//! `std::fs::OpenOptions` + `Read`/`Write`) and wire framing
//! (`[u32 LE length][payload]`) exactly — see that module's doc comment
//! for the rationale.

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::process::{Child, Command, Stdio};
use std::time::Instant;

use anyhow::{Context as _, Result};
use crossbeam_channel::{Receiver, Sender};
use uffs_content_reader_protocol::codec::Reader as WireReader;
use uffs_content_reader_protocol::{
    MAX_RESPONSE_PAYLOAD_BYTES, READER_PIPE_NAME, ReadRequest, ReadResponse, RequestedReadMode,
    StreamKind, VolumeIdentity,
};

/// How long to retry connecting to the freshly spawned Reader's pipe
/// while it finishes binding it.
const CONNECT_RETRY_BUDGET: Duration = Duration::from_secs(10);

/// Delay between connect retries.
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// Connections given to an NVMe/SSD-backed drive's pool.
///
/// Each connection is a plain, unpipelined request/response round trip
/// over a named pipe, so this is that drive's real read concurrency —
/// see the module doc comment. Reads here are small files (an
/// IPC-round-trip-bound workload, not a bytes/sec-bound one), so a
/// value well above typical disk queue depth is appropriate for a
/// no-seek-penalty medium designed around deep concurrent queues.
///
/// An HDD (or removable/virtual/unknown — anything
/// [`uffs_mft::platform::DriveType::is_high_performance`] doesn't claim)
/// gets exactly 1 connection instead, chosen by the caller
/// (`vss_job.rs`) — not this constant. Racing multiple concurrent reads
/// against the same spinning disk scatters its head across every
/// in-flight read's location instead of letting it sweep through
/// candidates in the order they were enumerated (which, since
/// candidates come off the MFT roughly in on-disk order, approximates
/// sequential access) — pure seek-time waste for a medium where seeks,
/// not bandwidth, are the bottleneck.
pub(crate) const CONNECTIONS_PER_DRIVE: usize = 8;

/// A running `uffs-content-reader` process + its live pipe connection
/// pools (one per leased drive, sized by the caller — see
/// `CONNECTIONS_PER_DRIVE`), held for the whole job's content-reading
/// phase.
pub(crate) struct ContentReader {
    /// The spawned `uffs-content-reader` child process. Killed on
    /// [`Self::shutdown`]/[`Drop`] — this process spawned it, so a
    /// direct kill is simplest and correct (mirrors
    /// [`super::ephemeral_daemon::EphemeralDaemon::shutdown`]).
    child: Child,
    /// One connection pool per leased drive, keyed by
    /// `snapshot_lease_id` — see the module doc comment.
    connections: HashMap<u64, ConnectionPool>,
    /// This job's id, echoed into every `ReadRequest`.
    job_id: [u8; 16],
    /// Monotonically increasing nonce for request/response correlation.
    next_nonce: AtomicU64,
}

/// A bounded pool of already-open pipe connections for one drive.
///
/// `checkout`/`checkin` are the two ends of the same bounded
/// [`crossbeam_channel`], pre-filled at construction with as many
/// connections as the caller asked for — see the module doc comment for
/// the checkout/checkin/drop-on-error contract.
struct ConnectionPool {
    /// Checked-in (idle) connections, ready to be checked out.
    checkout: Receiver<std::fs::File>,
    /// The other end of the same channel — returns a connection after a
    /// successful round trip.
    checkin: Sender<std::fs::File>,
}

impl ConnectionPool {
    /// Open `pool_size` fresh connections and fill a new pool with them
    /// (clamped to at least 1 — a pool can never be usefully empty).
    fn connect(lease_id: u64, pool_size: usize) -> Result<Self> {
        let clamped_pool_size = pool_size.max(1);
        let (checkin, checkout) = crossbeam_channel::bounded(clamped_pool_size);
        for _ in 0..clamped_pool_size {
            let pipe = connect_with_retry()
                .with_context(|| format!("failed to open a connection for lease {lease_id}"))?;
            // Never blocks: the channel's capacity is exactly
            // clamped_pool_size and we send exactly that many.
            checkin.try_send(pipe).map_err(|err| {
                anyhow::anyhow!("connection pool for lease {lease_id} overfilled: {err}")
            })?;
        }
        Ok(Self { checkout, checkin })
    }
}

impl ContentReader {
    /// Spawn `uffs-content-reader --device <device_path>=<snapshot_lease_id>
    /// ...` for every `(device_path, lease_id, _)` in `devices`, and open
    /// a connection pool of the given size for each — see
    /// `CONNECTIONS_PER_DRIVE` for how the caller should choose that
    /// size per drive.
    ///
    /// # Errors
    /// Returns an error if `devices` is empty, the binary can't be
    /// spawned, or any connection never comes up within
    /// [`CONNECT_RETRY_BUDGET`].
    pub(crate) fn spawn(job_id: [u8; 16], devices: &[(String, u64, usize)]) -> Result<Self> {
        anyhow::ensure!(
            !devices.is_empty(),
            "at least one device is required to spawn a content reader"
        );

        let exe = find_reader_exe();
        let mut command = Command::new(&exe);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (device_path, lease_id, _pool_size) in devices {
            command
                .arg("--device")
                .arg(format!("{device_path}={lease_id}"));
        }
        tracing::info!(
            exe = %exe.display(),
            device_count = devices.len(),
            "content reader: spawning uffs-content-reader"
        );
        let child = command
            .spawn()
            .with_context(|| format!("failed to spawn {}", exe.display()))?;
        tracing::info!(pid = child.id(), "content reader: process spawned");

        let mut connections = HashMap::with_capacity(devices.len());
        for (_device_path, lease_id, pool_size) in devices {
            let pool = ConnectionPool::connect(*lease_id, *pool_size)
                .with_context(|| format!("failed to build connection pool for lease {lease_id}"))?;
            tracing::info!(
                lease_id,
                connections = pool_size,
                "content reader: connection pool established"
            );
            connections.insert(*lease_id, pool);
        }

        Ok(Self {
            child,
            connections,
            job_id,
            next_nonce: AtomicU64::new(1),
        })
    }

    /// Read up to `maximum_logical_length` bytes at `logical_offset`
    /// from the file identified by `full_file_reference`, scoped to
    /// `snapshot_lease_id`.
    ///
    /// # Errors
    /// Returns an error if the round trip fails or the Reader reports
    /// failure.
    pub(crate) fn read_at(
        &self,
        snapshot_lease_id: u64,
        candidate_id: u64,
        full_file_reference: u64,
        logical_offset: u64,
        maximum_logical_length: u32,
    ) -> Result<Vec<u8>> {
        let request = ReadRequest {
            job_id: self.job_id,
            snapshot_lease_id,
            candidate_id,
            // Presently inert on the Reader side — v1's `OpenFileById`
            // locates the file by `full_file_reference` alone, no
            // volume cross-check. See
            // `uffs-content-reader/src/reader/logical.rs`'s module doc.
            volume_identity: VolumeIdentity {
                volume_serial: 0,
                volume_guid: Vec::new(),
            },
            full_file_reference,
            stream_kind: StreamKind::UnnamedData,
            logical_offset,
            maximum_logical_length,
            requested_mode: RequestedReadMode::Logical,
            request_nonce: self.next_nonce.fetch_add(1, Ordering::Relaxed),
        };

        match self.round_trip(snapshot_lease_id, &request) {
            Ok(ReadResponse::Bytes { payload, .. }) => Ok(payload),
            Ok(ReadResponse::Error { code, message }) => {
                tracing::warn!(
                    snapshot_lease_id,
                    candidate_id,
                    logical_offset,
                    ?code,
                    message = %message,
                    "content reader: read rejected"
                );
                anyhow::bail!("Reader rejected read: {code:?}: {message}")
            }
            Err(err) => {
                tracing::warn!(
                    snapshot_lease_id,
                    candidate_id,
                    logical_offset,
                    error = %err,
                    "content reader: round trip failed"
                );
                Err(err)
            }
        }
    }

    /// Send one framed [`ReadRequest`] and read back one framed
    /// [`ReadResponse`], over one of `snapshot_lease_id`'s own pooled
    /// connections — never contending with a different drive's pool.
    /// Blocks until a connection is available if every connection in
    /// this drive's pool is currently checked out.
    fn round_trip(&self, snapshot_lease_id: u64, request: &ReadRequest) -> Result<ReadResponse> {
        let pool = self.connections.get(&snapshot_lease_id).ok_or_else(|| {
            anyhow::anyhow!(
                "no content reader connection pool for snapshot_lease_id {snapshot_lease_id}"
            )
        })?;
        let mut pipe = pool.checkout.recv().map_err(|err| {
            anyhow::anyhow!(
                "connection pool for lease {snapshot_lease_id} is exhausted \
                 (every connection failed): {err}"
            )
        })?;

        let result = (|| -> Result<ReadResponse> {
            write_framed_message(&mut pipe, &request.encode())?;
            let response_bytes = read_framed_message(&mut pipe)?;
            let mut wire_reader = WireReader::new(&response_bytes);
            ReadResponse::decode(&mut wire_reader, MAX_RESPONSE_PAYLOAD_BYTES)
                .map_err(|err| anyhow::anyhow!("malformed Reader response: {err}"))
        })();

        if result.is_ok() {
            // Still framing-aligned — return it for reuse. Best-effort:
            // the pool never holds more than its original connection
            // count, so this can't actually overflow; `try_send` is
            // just the non-panicking way to express "give it back", and
            // a failure here just means one fewer pooled connection.
            drop(pool.checkin.try_send(pipe));
        }
        // On error, `pipe` is dropped here instead of returned — see
        // the module doc comment for why a connection that failed
        // mid-round-trip must not be reused.
        result
    }

    /// Tear down this instance: kill the spawned process. The pipe
    /// connection is closed when `self` drops.
    ///
    /// # Errors
    /// Returns an error if the process couldn't be killed.
    pub(crate) fn shutdown(mut self) -> Result<()> {
        self.child
            .kill()
            .context("failed to kill content reader process")?;
        drop(self.child.wait());
        Ok(())
    }
}

impl Drop for ContentReader {
    /// Best-effort safety net: if [`Self::shutdown`] was never called
    /// explicitly, don't leak the child process.
    fn drop(&mut self) {
        drop(self.child.kill());
    }
}

/// Open [`READER_PIPE_NAME`], retrying briefly while the freshly
/// spawned process finishes binding it.
fn connect_with_retry() -> Result<std::fs::File> {
    let deadline = Instant::now() + CONNECT_RETRY_BUDGET;
    let last_err = loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(READER_PIPE_NAME)
        {
            Ok(pipe) => return Ok(pipe),
            Err(err) => {
                if Instant::now() >= deadline {
                    break err;
                }
                std::thread::sleep(CONNECT_RETRY_INTERVAL);
            }
        }
    };
    Err(anyhow::anyhow!(
        "could not connect to content reader at {READER_PIPE_NAME}: {last_err}"
    ))
}

/// Find the `uffs-content-reader` executable: prefer a sibling of the
/// current binary, falling back to the platform binary name on `$PATH`.
fn find_reader_exe() -> std::path::PathBuf {
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        let sibling = parent.join("uffs-content-reader.exe");
        if sibling.exists() {
            return sibling;
        }
    }
    std::path::PathBuf::from("uffs-content-reader.exe")
}

/// Write `payload` as `[u32 LE length][payload]`, flushing immediately.
fn write_framed_message(pipe: &mut std::fs::File, payload: &[u8]) -> Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|err| anyhow::anyhow!("request payload too large to frame: {err}"))?;
    pipe.write_all(&length.to_le_bytes())?;
    pipe.write_all(payload)?;
    pipe.flush()?;
    Ok(())
}

/// Read one `[u32 LE length][payload]`-framed message.
fn read_framed_message(pipe: &mut std::fs::File) -> Result<Vec<u8>> {
    let mut length_bytes = [0_u8; 4];
    pipe.read_exact(&mut length_bytes)?;
    let length = u32::from_le_bytes(length_bytes);
    anyhow::ensure!(
        length <= MAX_RESPONSE_PAYLOAD_BYTES,
        "response length {length} exceeds maximum {MAX_RESPONSE_PAYLOAD_BYTES}"
    );

    let mut payload = vec![0_u8; length as usize];
    pipe.read_exact(&mut payload)?;
    Ok(payload)
}
