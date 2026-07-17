// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Coordinator-side client for the Broker's Snapshot Manager pipe
//! (`uffs_broker_protocol::snapshot_manager::SNAPSHOT_PIPE_NAME`).
//!
//! Mirrors `uffs-daemon::broker_client`'s connect style (plain
//! `std::fs::OpenOptions` + `Read`/`Write`, no raw Win32 FFI, no
//! pipe-existence probe before the real request — see that module's
//! doc comment for why a probe would starve the real request). The
//! wire shape here is different, though: the MFT-handle protocol is a
//! fixed-length exchange, but this one is a variable-length
//! `[u32 LE length][payload]`-framed request/response, one per
//! connection — this module implements the client side of exactly the
//! framing `uffs-broker`'s `read_framed_message`/`write_framed_message`
//! implement server-side (`crates/uffs-broker/src/broker/
//! snapshot_manager/mod.rs`).
//!
//! The Broker only replies at all if this process's own image passes
//! its Coordinator identity check (`uffs-content*.exe` + Authenticode —
//! see `verify_coordinator_identity` in the Broker module above): a
//! connection from any other binary gets no response and the Broker
//! closes the pipe.

use std::io::{Read as _, Write as _};

use anyhow::Context as _;
use uffs_broker_protocol::snapshot_manager::{
    CreateSnapshotLease, CreateSnapshotLeaseResult, ReleaseSnapshotLease, SNAPSHOT_PIPE_NAME,
    SnapshotManagerErrorCode, SnapshotManagerRequest, SnapshotManagerResponse, VolumeIdentity,
};

/// A structured `Create` rejection from the Broker, as opposed to a
/// transport-level failure (pipe unreachable, malformed response, …).
///
/// Kept separate from a plain `anyhow::bail!` string so callers (see
/// [`super::vss_orchestrator::prepare_ephemeral_daemon_for_roots`]) can
/// `downcast_ref` and branch on `code`/`hresult` — e.g. skipping a
/// drive VSS permanently refuses (`VSS_E_VOLUME_NOT_SUPPORTED` for
/// removable media) instead of string-matching `message`.
#[derive(Debug)]
pub(crate) struct BrokerRejectedCreate {
    /// Stable error code the Broker reported.
    pub(crate) code: SnapshotManagerErrorCode,
    /// The underlying `HRESULT`, when the Broker's failure came from a
    /// VSS call and one was available.
    pub(crate) hresult: Option<i32>,
    /// Human-readable diagnostic message.
    pub(crate) message: String,
}

impl core::fmt::Display for BrokerRejectedCreate {
    #[expect(
        clippy::use_debug,
        reason = "SnapshotManagerErrorCode has no Display impl (it's a wire enum, not \
                  user-facing text) — Debug is the only formatting available, and this \
                  is itself a diagnostic-only error message"
    )]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Broker rejected Create: {:?}: {}",
            self.code, self.message
        )
    }
}

impl core::error::Error for BrokerRejectedCreate {}

/// Matches the Broker's own `MAX_REQUEST_BYTES` — a response this large
/// would indicate a protocol desync, not a legitimate reply.
const MAX_RESPONSE_BYTES: u32 = 64 * 1024;

/// A live snapshot lease this process holds — the Coordinator-side
/// counterpart of the Broker's `CreateSnapshotLeaseResult`.
#[expect(
    clippy::struct_field_names,
    reason = "field names deliberately mirror CreateSnapshotLeaseResult's own \
              wire field names for clarity when converting between the two"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SnapshotLease {
    /// Lease identifier, used in every subsequent call for this lease.
    pub(crate) snapshot_lease_id: u64,
    /// Opaque VSS snapshot identifier.
    pub(crate) snapshot_id: Vec<u8>,
    /// Device path the snapshot is reachable at (e.g.
    /// `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`).
    pub(crate) snapshot_device_identity: String,
    /// Snapshot creation time, Unix milliseconds.
    pub(crate) snapshot_created_at_unix_ms: i64,
    /// Lease expiry, Unix milliseconds.
    pub(crate) expires_at_unix_ms: i64,
}

/// Request a new snapshot lease from the Broker.
///
/// # Errors
/// Returns an error if the pipe can't be opened (e.g. the Broker isn't
/// running, or this process fails its identity check), the request
/// can't be sent, the response can't be read/decoded, or the Broker
/// reports failure (`SnapshotManagerResponse::Error`).
pub(crate) fn create_lease(
    authenticated_job_id: [u8; 16],
    source_volume_identity: VolumeIdentity,
    requested_root: Vec<u8>,
    maximum_lifetime_secs: u64,
    policy_id: u32,
) -> anyhow::Result<SnapshotLease> {
    let request = SnapshotManagerRequest::Create(CreateSnapshotLease {
        authenticated_job_id,
        source_volume_identity,
        requested_root,
        maximum_lifetime_secs,
        policy_id,
    });
    match round_trip(&request)? {
        SnapshotManagerResponse::Created(CreateSnapshotLeaseResult {
            snapshot_lease_id,
            snapshot_id,
            snapshot_device_identity,
            snapshot_created_at_unix_ms,
            expires_at_unix_ms,
        }) => Ok(SnapshotLease {
            snapshot_lease_id,
            snapshot_id,
            snapshot_device_identity,
            snapshot_created_at_unix_ms,
            expires_at_unix_ms,
        }),
        SnapshotManagerResponse::Error {
            code,
            hresult,
            message,
        } => Err(BrokerRejectedCreate {
            code,
            hresult,
            message,
        }
        .into()),
        other @ (SnapshotManagerResponse::Duplicated
        | SnapshotManagerResponse::Renewed { .. }
        | SnapshotManagerResponse::Released
        | SnapshotManagerResponse::Status(_)) => {
            anyhow::bail!("unexpected response to Create: {other:?}")
        }
    }
}

/// Release a previously created lease.
///
/// # Errors
/// Returns an error if the pipe round trip fails or the Broker reports
/// failure.
pub(crate) fn release_lease(snapshot_lease_id: u64) -> anyhow::Result<()> {
    let request = SnapshotManagerRequest::Release(ReleaseSnapshotLease { snapshot_lease_id });
    match round_trip(&request)? {
        SnapshotManagerResponse::Released => Ok(()),
        SnapshotManagerResponse::Error { code, message, .. } => {
            anyhow::bail!("Broker rejected Release: {code:?}: {message}")
        }
        other @ (SnapshotManagerResponse::Created(_)
        | SnapshotManagerResponse::Duplicated
        | SnapshotManagerResponse::Renewed { .. }
        | SnapshotManagerResponse::Status(_)) => {
            anyhow::bail!("unexpected response to Release: {other:?}")
        }
    }
}

/// Open the Snapshot Manager pipe, send one framed request, and read
/// back one framed response.
///
/// # Errors
/// Returns an error if the pipe can't be opened, the write/read fails,
/// the response exceeds [`MAX_RESPONSE_BYTES`], or the payload doesn't
/// decode as a valid [`SnapshotManagerResponse`].
fn round_trip(request: &SnapshotManagerRequest) -> anyhow::Result<SnapshotManagerResponse> {
    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(std::path::Path::new(SNAPSHOT_PIPE_NAME))
        .map_err(|err| anyhow::anyhow!("opening Snapshot Manager pipe: {err}"))?;

    write_framed_message(&mut pipe, &request.encode())
        .context("writing request to Snapshot Manager pipe")?;
    let response_bytes =
        read_framed_message(&mut pipe).context("reading response from Snapshot Manager pipe")?;
    SnapshotManagerResponse::decode(&response_bytes)
        .map_err(|err| anyhow::anyhow!("malformed Snapshot Manager response: {err}"))
}

/// Write `payload` as `[u32 LE length][payload]`, flushing immediately —
/// the client-side mirror of the Broker's `write_framed_message`.
fn write_framed_message(pipe: &mut std::fs::File, payload: &[u8]) -> anyhow::Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|err| anyhow::anyhow!("request payload too large to frame: {err}"))?;
    pipe.write_all(&length.to_le_bytes())?;
    pipe.write_all(payload)?;
    pipe.flush()?;
    Ok(())
}

/// Read one `[u32 LE length][payload]`-framed message — the
/// client-side mirror of the Broker's `read_framed_message`.
fn read_framed_message(pipe: &mut std::fs::File) -> anyhow::Result<Vec<u8>> {
    let mut length_bytes = [0_u8; 4];
    pipe.read_exact(&mut length_bytes)
        .context("reading response length prefix")?;
    let length = u32::from_le_bytes(length_bytes);
    if length > MAX_RESPONSE_BYTES {
        anyhow::bail!("response length {length} exceeds maximum {MAX_RESPONSE_BYTES}");
    }

    let mut payload = vec![0_u8; usize::try_from(length).unwrap_or(0)];
    pipe.read_exact(&mut payload)
        .context("reading response payload")?;
    Ok(payload)
}
