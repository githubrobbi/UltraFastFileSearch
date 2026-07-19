// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Reader logic: a cross-platform pure core ([`read_plan`]) plus
//! Windows-only I/O (`logical`, `pipe_server`).
//!
//! [`read_plan`] is deliberately NOT gated behind `#[cfg(windows)]` —
//! see its own module doc for why it runs (and is exhaustively tested)
//! on every platform, unlike the rest of this module.
//!
//! # Trust model (v1, Windows-only pieces below)
//!
//! This process is spawned directly by `uffs-content` (the Coordinator)
//! while it is itself elevated — there is no Broker-mediated handle
//! duplication or Authenticode identity check on the connecting client
//! for this pipe (unlike the Broker's Snapshot Manager pipe). The named
//! pipe's owner-only DACL (`uffs_security::pipe::OwnerOnlySd`) is the
//! security boundary: only the current elevated user's linked/primary
//! token can open it at all. `FIRST_PIPE_INSTANCE` protects against
//! another process squatting the well-known name first.
//!
//! # Resolving a lease id to a snapshot device path
//!
//! `ReadRequest` carries `snapshot_lease_id` + `volume_identity`, but
//! (by design — addendum §2.1-§2.4: the Coordinator's requests never
//! carry the snapshot handle or a raw device path over this wire
//! protocol) no device path field. This process instead receives every
//! `(device_path, snapshot_lease_id)` pair it will ever need as
//! `--device PATH=LEASE_ID` startup arguments — mirroring `uffsd`'s own
//! `--device PATH=LETTER` flag for the same reason (multi-drive jobs
//! lease more than one snapshot) — and looks up `snapshot_lease_id` in
//! that table per request.

pub(crate) mod read_plan;

#[cfg(windows)]
mod logical;
#[cfg(windows)]
pub(crate) mod pipe_server;

#[cfg(windows)]
use std::collections::HashMap;

#[cfg(windows)]
use uffs_content_reader_protocol::{ReadRequest, ReadResponse, ReaderErrorCode};

/// Dispatch one decoded `ReadRequest` into a `ReadResponse`, threading
/// this connection's [`logical::ReadHandleCache`] through the call —
/// see that type's own doc comment for why. Always returns a fresh
/// cache: `Some` (the possibly-reused-or-reopened handle) on success,
/// `ReadHandleCache::empty()` on any failure, since a failed read leaves
/// the cached handle's state unknown.
///
/// Every failure mode (unknown lease, open failure, read failure,
/// invalid VDL/EOF metadata) is caught here and turned into a typed
/// `ReadResponse::Error` — this function never panics or propagates an
/// `Err` up to its caller, since a malformed *single* request must not
/// tear down the whole connection.
#[cfg(windows)]
fn dispatch_request(
    request: &ReadRequest,
    devices: &HashMap<u64, String>,
    cache: logical::ReadHandleCache,
) -> (ReadResponse, logical::ReadHandleCache) {
    let Some(device_path) = devices.get(&request.snapshot_lease_id) else {
        return (
            ReadResponse::Error {
                code: ReaderErrorCode::LeaseInvalid,
                message: format!(
                    "snapshot_lease_id {} is not one of this process's --device leases",
                    request.snapshot_lease_id
                ),
            },
            logical::ReadHandleCache::empty(),
        );
    };

    match logical::read_logical(
        device_path,
        request.full_file_reference,
        request.known_logical_size,
        request.logical_offset,
        request.maximum_logical_length,
        cache,
    ) {
        Ok((payload, actual_mode, updated_cache)) => (
            ReadResponse::Bytes {
                logical_offset: request.logical_offset,
                actual_mode,
                payload,
            },
            updated_cache,
        ),
        Err(err) => (
            ReadResponse::Error {
                code: ReaderErrorCode::ReadIoTransient,
                message: format!("{err:#}"),
            },
            logical::ReadHandleCache::empty(),
        ),
    }
}

/// Run the Reader for the process's whole lifetime, resolving each
/// request's `snapshot_lease_id` against `devices`.
///
/// # Errors
/// Returns an error only if the pipe itself cannot be created at all;
/// per-request failures are turned into `ReadResponse::Error` and never
/// propagate here.
#[cfg(windows)]
pub(crate) fn run(devices: &HashMap<u64, String>) -> anyhow::Result<()> {
    pipe_server::run(devices)
}
