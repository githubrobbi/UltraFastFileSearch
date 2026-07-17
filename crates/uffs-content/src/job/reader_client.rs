// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Coordinator-side client for `uffs-content-reader-protocol`.
//!
//! Spawns `uffs-content-reader --device <path>=<snapshot_lease_id> ...`
//! once per job — mirrors [`super::ephemeral_daemon`]'s spawn model, but
//! for the content-reading phase rather than target selection — connects
//! to its fixed `READER_PIPE_NAME`, and sends framed
//! `ReadRequest`/`ReadResponse` messages over that one persistent
//! connection for the whole job.
//!
//! Mirrors [`super::snapshot_client`]'s connect style (plain
//! `std::fs::OpenOptions` + `Read`/`Write`) and wire framing
//! (`[u32 LE length][payload]`) exactly — see that module's doc comment
//! for the rationale.

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::io::{Read as _, Write as _};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{Context as _, Result};
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

/// A running `uffs-content-reader` process + its live pipe connection,
/// held for the whole job's content-reading phase.
pub(crate) struct ContentReader {
    /// The spawned `uffs-content-reader` child process. Killed on
    /// [`Self::shutdown`]/[`Drop`] — this process spawned it, so a
    /// direct kill is simplest and correct (mirrors
    /// [`super::ephemeral_daemon::EphemeralDaemon::shutdown`]).
    child: Child,
    /// The one persistent pipe connection this job's whole
    /// content-reading phase shares. `Mutex`-guarded so `read_at` can
    /// take `&self` (the `ContentSource` trait's shape) while still
    /// mutating the connection.
    pipe: Mutex<std::fs::File>,
    /// This job's id, echoed into every `ReadRequest`.
    job_id: [u8; 16],
    /// Monotonically increasing nonce for request/response correlation.
    next_nonce: AtomicU64,
}

impl ContentReader {
    /// Spawn `uffs-content-reader --device <device_path>=<snapshot_lease_id>
    /// ...` for every pair in `devices`, and connect to it.
    ///
    /// # Errors
    /// Returns an error if `devices` is empty, the binary can't be
    /// spawned, or the pipe never comes up within
    /// [`CONNECT_RETRY_BUDGET`].
    pub(crate) fn spawn(job_id: [u8; 16], devices: &[(String, u64)]) -> Result<Self> {
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
        for (device_path, lease_id) in devices {
            command
                .arg("--device")
                .arg(format!("{device_path}={lease_id}"));
        }
        let child = command
            .spawn()
            .with_context(|| format!("failed to spawn {}", exe.display()))?;

        let pipe = connect_with_retry()?;

        Ok(Self {
            child,
            pipe: Mutex::new(pipe),
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

        match self.round_trip(&request)? {
            ReadResponse::Bytes { payload, .. } => Ok(payload),
            ReadResponse::Error { code, message } => {
                anyhow::bail!("Reader rejected read: {code:?}: {message}")
            }
        }
    }

    /// Send one framed [`ReadRequest`] and read back one framed
    /// [`ReadResponse`], over this job's one persistent connection.
    fn round_trip(&self, request: &ReadRequest) -> Result<ReadResponse> {
        let Ok(mut pipe) = self.pipe.lock() else {
            anyhow::bail!("content reader pipe mutex poisoned");
        };
        write_framed_message(&mut pipe, &request.encode())?;
        let response_bytes = read_framed_message(&mut pipe)?;
        let mut wire_reader = WireReader::new(&response_bytes);
        ReadResponse::decode(&mut wire_reader, MAX_RESPONSE_PAYLOAD_BYTES)
            .map_err(|err| anyhow::anyhow!("malformed Reader response: {err}"))
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
