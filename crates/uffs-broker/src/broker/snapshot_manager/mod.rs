// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Snapshot Manager: the Broker's VSS-lease API for `uffs-content` (the
//! Content Coordinator), per `uffs-ingest-implementation-plan.md` §4.
//!
//! Serves [`SNAPSHOT_PIPE_NAME`] — a **separate** named pipe from
//! [`uffs_broker_protocol::PIPE_NAME`] (the daemon's MFT-handle channel):
//! Coordinator↔Broker is a distinct channel with a distinct peer and
//! distinct trust check (only `uffs-content` may call it, not `uffsd`).
//!
//! The lease-lifecycle state machine lives in [`crate::snapshot_lease`]
//! (cross-platform, unit-tested against a fake `VssProvider`); the real
//! backend is [`vss_helper::WindowsVssProvider`] (spawns
//! `uffs-vss-requestor` per lease). This module is the remaining
//! Windows-only wiring: pipe creation, per-connection identity
//! verification (reusing this crate's existing
//! `OwnedProcessHandle`/Authenticode machinery), wire framing, and
//! request dispatch.

mod vss_helper;
// The `--self-test-vss` round trip: split into its own file purely to
// keep `vss_helper.rs` under the workspace's 800-LOC file-size policy.
mod vss_self_test;

use alloc::sync::Arc;
use core::time::Duration;

use uffs_broker_protocol::snapshot_manager::{
    CreateSnapshotLeaseResult, DuplicateSnapshotHandle, SNAPSHOT_PIPE_NAME, SnapshotLeaseState,
    SnapshotLeaseStatus, SnapshotManagerErrorCode, SnapshotManagerRequest, SnapshotManagerResponse,
};
use vss_helper::WindowsVssProvider;
// Re-exported so `broker::run` can wire up `--self-test-vss` without
// reaching past this module's own submodule privacy boundary.
pub(super) use vss_self_test::self_test_round_trip;
use windows::Win32::Foundation::HANDLE;
use windows::core::PCWSTR;

use super::owned_handle::OwnedHandle;
use super::process_handle::{OwnedProcessHandle, query_process_image_name};
use crate::snapshot_lease::{LeaseError, SnapshotLeaseManager, VssError};

/// Maximum accepted request payload, before allocation — a generous bound
/// for this small, narrow API (no bulk data ever crosses this pipe).
const MAX_REQUEST_BYTES: u32 = 64 * 1024;

/// How often the background sweep checks for expired leases, for an
/// otherwise-idle manager that would never otherwise notice an expiry
/// (every request-handling path also sweeps opportunistically — see
/// `crate::snapshot_lease::SnapshotLeaseManager::sweep_expired`).
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Run the Snapshot Manager: reconcile orphaned snapshots from any
/// previous run, then serve requests until the process exits.
///
/// Called from `broker::run_foreground` on its own thread, alongside the
/// existing MFT-handle pipe server.
///
/// # Errors
/// Returns an error only if the pipe itself cannot be created at all;
/// per-connection failures are logged and never propagate here.
pub(super) fn run() -> anyhow::Result<()> {
    let manager = Arc::new(SnapshotLeaseManager::new(WindowsVssProvider::new()));

    let reconciled = manager.reconcile_at_startup().unwrap_or_else(|err| {
        tracing::warn!(error = %err, "startup snapshot reconciliation failed to list existing snapshots");
        0
    });
    if reconciled > 0 {
        tracing::info!(
            count = reconciled,
            "reconciled orphaned VSS snapshots from a previous run"
        );
    }

    let sweep_manager = Arc::clone(&manager);
    #[expect(
        clippy::infinite_loop,
        reason = "runs for the Broker's whole lifetime, sweeping expired leases; \
                  there is no termination condition short of process exit"
    )]
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(SWEEP_INTERVAL);
            sweep_manager.sweep_expired(unix_ms_now());
        }
    });

    serve_snapshot_pipe(&manager)
}

/// Accept loop for [`SNAPSHOT_PIPE_NAME`], mirroring the shape of
/// `broker::serve_pipe_requests` (separate pipe, separate instances, one
/// worker thread per connection).
fn serve_snapshot_pipe(
    manager: &Arc<SnapshotLeaseManager<WindowsVssProvider>>,
) -> anyhow::Result<()> {
    tracing::info!(
        pipe = SNAPSHOT_PIPE_NAME,
        "Listening for Snapshot Manager requests"
    );
    let mut first_instance = true;

    loop {
        if super::service::stop_requested() {
            return Ok(());
        }

        let pipe = match create_snapshot_pipe(first_instance) {
            Ok(pipe) => {
                first_instance = false;
                pipe
            }
            Err(err) => {
                tracing::warn!(error = %err, "snapshot pipe instance unavailable; retrying shortly");
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        if let Err(err) = super::wait_for_client(pipe) {
            tracing::warn!(error = %err, "wait_for_client (snapshot pipe) failed; dropping instance");
            super::disconnect_pipe(pipe);
            super::close_pipe(pipe);
            continue;
        }
        if super::service::stop_requested() {
            super::disconnect_pipe(pipe);
            super::close_pipe(pipe);
            return Ok(());
        }

        let owned = OwnedHandle::new(pipe);
        let worker_manager = Arc::clone(manager);
        std::thread::spawn(move || {
            handle_connection(owned.raw(), &worker_manager);
            super::disconnect_pipe(owned.raw());
        });
    }
}

/// Verify the client connected to `pipe` is the Content Coordinator
/// (`uffs-content`), logging and returning `false` if not.
fn verify_connected_coordinator(pipe: HANDLE) -> bool {
    let Some(pid) = super::get_pipe_client_pid(pipe) else {
        tracing::warn!("snapshot pipe: could not determine client PID — rejecting");
        return false;
    };
    let Some(client_process) = OwnedProcessHandle::open_client(pid) else {
        tracing::warn!(
            pid,
            "snapshot pipe: could not open client process — rejecting"
        );
        return false;
    };
    let exe_path = query_process_image_name(client_process.raw());
    if !verify_coordinator_identity(exe_path.as_deref()) {
        tracing::warn!(pid, "snapshot pipe: rejected client — not uffs-content");
        return false;
    }
    true
}

/// Read one framed request from `pipe`, dispatch it against `manager`,
/// and write the framed response back.
fn handle_one_request(pipe: HANDLE, manager: &SnapshotLeaseManager<WindowsVssProvider>) {
    let request_bytes = match read_framed_message(pipe) {
        Ok(bytes) => bytes,
        Err(err) => {
            // Kept at `warn!` (not `debug!`): a broken Coordinator request
            // read is operationally significant — it's the only signal a
            // production deployment (service, no console) gets that a
            // client round trip silently died. Was invisible at the
            // default `--run`/service INFO level until this fix.
            tracing::warn!(error = %err, "snapshot pipe: failed to read request");
            return;
        }
    };
    let response = match SnapshotManagerRequest::decode(&request_bytes) {
        Ok(request) => dispatch_request(request, manager),
        Err(decode_err) => SnapshotManagerResponse::Error {
            code: SnapshotManagerErrorCode::InternalError,
            hresult: None,
            message: format!("malformed request: {decode_err}"),
        },
    };
    if let Err(err) = write_framed_message(pipe, &response.encode()) {
        tracing::warn!(error = %err, "snapshot pipe: failed to write response");
    }
}

/// Handle one connected client: verify it is the Content Coordinator
/// (`uffs-content`), then read, dispatch, and respond to exactly one
/// framed request.
fn handle_connection(pipe: HANDLE, manager: &SnapshotLeaseManager<WindowsVssProvider>) {
    if !verify_connected_coordinator(pipe) {
        return;
    }
    handle_one_request(pipe, manager);
}

/// Dispatch one decoded request against `manager`, returning the wire
/// response.
fn dispatch_request(
    wire_request: SnapshotManagerRequest,
    manager: &SnapshotLeaseManager<WindowsVssProvider>,
) -> SnapshotManagerResponse {
    let now = unix_ms_now();
    match wire_request {
        SnapshotManagerRequest::Create(request) => {
            match manager.create_lease(
                &request.source_volume_identity,
                &request.requested_root,
                request.maximum_lifetime_secs,
                now,
            ) {
                Ok(created) => SnapshotManagerResponse::Created(CreateSnapshotLeaseResult {
                    snapshot_lease_id: created.lease_id,
                    snapshot_id: created.snapshot_id,
                    snapshot_device_identity: created.device_identity,
                    snapshot_created_at_unix_ms: created.created_at_unix_ms,
                    expires_at_unix_ms: created.expires_at_unix_ms,
                }),
                Err(err) => lease_error_response(&err),
            }
        }
        SnapshotManagerRequest::Duplicate(request) => handle_duplicate(&request, manager),
        SnapshotManagerRequest::Renew(request) => match manager.renew_lease(
            request.snapshot_lease_id,
            request.requested_expiry_unix_ms,
            now,
        ) {
            Ok(new_expires_at_unix_ms) => SnapshotManagerResponse::Renewed {
                new_expires_at_unix_ms,
            },
            Err(err) => lease_error_response(&err),
        },
        SnapshotManagerRequest::Release(request) => {
            match manager.release_lease(request.snapshot_lease_id) {
                Ok(()) => SnapshotManagerResponse::Released,
                Err(err) => lease_error_response(&err),
            }
        }
        SnapshotManagerRequest::Query(request) => {
            let status = manager
                .query_lease(request.snapshot_lease_id, now)
                .map_or_else(
                    || SnapshotLeaseStatus {
                        snapshot_lease_id: request.snapshot_lease_id,
                        state: SnapshotLeaseState::Unknown,
                        snapshot_id: Vec::new(),
                        created_at_unix_ms: 0,
                        expires_at_unix_ms: 0,
                    },
                    |status| SnapshotLeaseStatus {
                        snapshot_lease_id: request.snapshot_lease_id,
                        state: status.state,
                        snapshot_id: status.snapshot_id,
                        created_at_unix_ms: status.created_at_unix_ms,
                        expires_at_unix_ms: status.expires_at_unix_ms,
                    },
                );
            SnapshotManagerResponse::Status(status)
        }
    }
}

/// Handle `DuplicateSnapshotHandle`: verify the *named* reader process
/// (not the connected Coordinator) is a legitimate `uffs-content-reader`,
/// then open the lease's snapshot device and duplicate a read-only
/// handle into it.
///
/// **Open item**: the wire response (`SnapshotManagerResponse::Duplicated`)
/// carries no handle value — `DuplicateHandle`'s result is only
/// meaningful inside the target process's own handle table. How the
/// Reader itself learns *which* handle value to use is a UFI.2 decision
/// (`uffs-content-reader` doesn't exist yet); this function performs the
/// real duplication and trusts that mechanism to be settled before the
/// Reader is built.
fn handle_duplicate(
    request: &DuplicateSnapshotHandle,
    manager: &SnapshotLeaseManager<WindowsVssProvider>,
) -> SnapshotManagerResponse {
    let now = unix_ms_now();
    let Some(device_identity) = manager.device_identity_if_active(request.snapshot_lease_id, now)
    else {
        return lease_error_response(&LeaseError::NotFound);
    };

    let Some(reader_process) = OwnedProcessHandle::open_client(request.approved_reader_process_id)
    else {
        return SnapshotManagerResponse::Error {
            code: SnapshotManagerErrorCode::ReaderIdentityRejected,
            hresult: None,
            message: "could not open the approved reader process".to_owned(),
        };
    };
    let reader_exe = query_process_image_name(reader_process.raw());
    if !verify_reader_identity(reader_exe.as_deref()) {
        return SnapshotManagerResponse::Error {
            code: SnapshotManagerErrorCode::ReaderIdentityRejected,
            hresult: None,
            message: "reader process failed identity verification".to_owned(),
        };
    }

    match duplicate_snapshot_device_to_reader(&device_identity, &reader_process) {
        Ok(()) => SnapshotManagerResponse::Duplicated,
        Err(err) => SnapshotManagerResponse::Error {
            code: SnapshotManagerErrorCode::InternalError,
            hresult: None,
            message: err.to_string(),
        },
    }
}

/// Open `device_identity` read-only and duplicate the handle into
/// `reader_process` — the same open+duplicate shape as
/// `broker::open_volume_read_only` /
/// `broker::duplicate_volume_handle_to_client`, generalized to an arbitrary
/// snapshot device path instead of a bare drive letter.
#[expect(unsafe_code, reason = "CreateFileW + CloseHandle are FFI calls")]
fn duplicate_snapshot_device_to_reader(
    device_identity: &str,
    reader_process: &OwnedProcessHandle,
) -> anyhow::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;

    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED, FILE_FLAG_SEQUENTIAL_SCAN,
        FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide_path: Vec<u16> = std::ffi::OsStr::new(device_identity)
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: `wide_path` is a NUL-terminated UTF-16 buffer owned for the
    // duration of this call; every other argument is a plain integer or
    // `None`. Mirrors `broker::open_volume_read_only`'s flags exactly —
    // `FILE_FLAG_OVERLAPPED` because the Reader performs overlapped/IOCP
    // reads on the vended handle, matching `uffs-mft::VolumeHandle`.
    let device_handle = unsafe {
        CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN,
            None,
        )
    }
    .map_err(|err| anyhow::anyhow!("CreateFileW failed for {device_identity}: {err}"))?;

    let dup_result = super::duplicate_volume_handle_to_client(device_handle, reader_process);

    // SAFETY: `device_handle` came from `CreateFileW` above; our copy is
    // closed regardless of whether the duplicate succeeded.
    if let Err(close_err) = unsafe { CloseHandle(device_handle) } {
        tracing::debug!(err = ?close_err, "CloseHandle(device_handle) failed after dup");
    }

    dup_result.map(|_client_handle| ())
}

/// Map a [`LeaseError`] to the wire error response.
fn lease_error_response(err: &LeaseError) -> SnapshotManagerResponse {
    let code = match err {
        LeaseError::NotFound => SnapshotManagerErrorCode::LeaseNotFound,
        LeaseError::NotActive => SnapshotManagerErrorCode::LeaseNotActive,
        LeaseError::Vss(VssError::InvalidVolume(_)) => {
            SnapshotManagerErrorCode::VolumeValidationFailed
        }
        LeaseError::Vss(VssError::CreateFailed { .. }) => {
            SnapshotManagerErrorCode::SnapshotCreateFailed
        }
        LeaseError::Vss(VssError::DeleteFailed(_)) => SnapshotManagerErrorCode::InternalError,
    };
    let hresult = match err {
        LeaseError::Vss(VssError::CreateFailed { hresult, .. }) => *hresult,
        LeaseError::NotFound
        | LeaseError::NotActive
        | LeaseError::Vss(VssError::InvalidVolume(_) | VssError::DeleteFailed(_)) => None,
    };
    SnapshotManagerResponse::Error {
        code,
        hresult,
        message: err.to_string(),
    }
}

/// Whether `exe_path`'s file name matches the Content Coordinator binary.
///
/// Exact-name match only — no `starts_with` fallback. `uffs-content` is
/// itself a prefix of `uffs-content-reader`, whose own identity is
/// verified separately by [`is_uffs_content_reader_image`]; a prefix
/// match here would let the Reader binary also pass as the Coordinator.
fn is_uffs_content_image(exe_path: &std::ffi::OsStr) -> bool {
    let name = std::path::Path::new(exe_path)
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .unwrap_or("");
    name == "uffs-content" || name == "uffs-content.exe"
}

/// Whether `exe_path`'s file name matches the Snapshot Reader binary.
///
/// Exact-name match only, for the same reason as
/// [`is_uffs_content_image`]: a `starts_with` fallback on an identity
/// check is a standing invitation for a future binary sharing this
/// prefix to pass unintentionally.
fn is_uffs_content_reader_image(exe_path: &std::ffi::OsStr) -> bool {
    let name = std::path::Path::new(exe_path)
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .unwrap_or("");
    name == "uffs-content-reader" || name == "uffs-content-reader.exe"
}

/// Verify the connected pipe client is a legitimate `uffs-content`
/// (image name allow-list + Authenticode), mirroring
/// `broker::check_client_identity`'s two checks but against a different
/// name allow-list and without the drive-specific audit logging.
fn verify_coordinator_identity(coordinator_exe_path: Option<&std::ffi::OsStr>) -> bool {
    let Some(exe_path) = coordinator_exe_path else {
        return false;
    };
    if !is_uffs_content_image(exe_path) {
        return false;
    }
    exe_path
        .to_str()
        .is_some_and(uffs_security::authenticode::verify_authenticode)
}

/// Verify the named reader process is a legitimate `uffs-content-reader`
/// (image name allow-list + Authenticode).
fn verify_reader_identity(reader_exe_path: Option<&std::ffi::OsStr>) -> bool {
    let Some(exe_path) = reader_exe_path else {
        return false;
    };
    if !is_uffs_content_reader_image(exe_path) {
        return false;
    }
    exe_path
        .to_str()
        .is_some_and(uffs_security::authenticode::verify_authenticode)
}

/// Read a `u32`-LE-length-prefixed message from the pipe, bounded by
/// [`MAX_REQUEST_BYTES`] before allocating the payload buffer.
fn read_framed_message(pipe: HANDLE) -> anyhow::Result<Vec<u8>> {
    let mut length_bytes = [0_u8; 4];
    read_exact(pipe, &mut length_bytes)?;
    let length = u32::from_le_bytes(length_bytes);
    if length > MAX_REQUEST_BYTES {
        anyhow::bail!("request length {length} exceeds maximum {MAX_REQUEST_BYTES}");
    }

    let mut payload = vec![0_u8; usize::try_from(length).unwrap_or(0)];
    read_exact(pipe, &mut payload)?;
    Ok(payload)
}

/// Read exactly `buf.len()` bytes from the pipe.
#[expect(unsafe_code, reason = "ReadFile is an FFI call")]
fn read_exact(pipe: HANDLE, buf: &mut [u8]) -> anyhow::Result<()> {
    use windows::Win32::Storage::FileSystem::ReadFile;

    let mut bytes_read = 0_u32;
    // SAFETY: `pipe` is a valid open pipe HANDLE; `buf` is a caller-owned
    // mutable slice; `bytes_read` is a stack-owned u32 accessed exclusively.
    let result = unsafe { ReadFile(pipe, Some(buf), Some(&raw mut bytes_read), None) };
    if let Err(win_err) = result {
        anyhow::bail!("ReadFile failed: {win_err}");
    }
    if (bytes_read as usize) < buf.len() {
        anyhow::bail!("short read: got {bytes_read}, expected {}", buf.len());
    }
    Ok(())
}

/// Write a `u32`-LE-length-prefixed message to the pipe.
///
/// Calls `FlushFileBuffers` after a successful `WriteFile` and before
/// returning, so the caller's subsequent `disconnect_pipe` (see
/// `serve_snapshot_pipe`) can never race the client's read of this
/// response. `WriteFile` returning success only means the bytes were
/// copied into the pipe's kernel buffer — it does **not** mean the
/// client has actually read them yet. `DisconnectNamedPipe` discards
/// any buffered-but-unread bytes immediately, which is exactly what
/// produced `ERROR_PIPE_NOT_CONNECTED` (233) on the client's *second*
/// `ReadFile` (the response payload, after the 4-byte length prefix
/// already made it through) in the 2026-07-17 real-hardware VSS
/// playback test: the length prefix is 4 bytes and gets read almost
/// instantly, but the larger payload was still in flight when the
/// worker thread's `disconnect_pipe` ran. `FlushFileBuffers` on a pipe
/// server handle blocks until the client has drained everything this
/// call wrote, closing that window.
#[expect(unsafe_code, reason = "WriteFile/FlushFileBuffers are FFI calls")]
fn write_framed_message(pipe: HANDLE, payload: &[u8]) -> anyhow::Result<()> {
    use windows::Win32::Storage::FileSystem::{FlushFileBuffers, WriteFile};

    let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut framed = Vec::with_capacity(payload.len() + 4);
    framed.extend_from_slice(&length.to_le_bytes());
    framed.extend_from_slice(payload);

    let mut bytes_written = 0_u32;
    // SAFETY: `pipe` is a valid open pipe HANDLE; `framed` is a locally
    // owned buffer; `bytes_written` is a stack-owned u32.
    let result = unsafe { WriteFile(pipe, Some(&framed), Some(&raw mut bytes_written), None) };
    if let Err(win_err) = result {
        anyhow::bail!("WriteFile failed: {win_err}");
    }
    // SAFETY: `pipe` is the same valid, still-open pipe HANDLE written to above.
    if let Err(win_err) = unsafe { FlushFileBuffers(pipe) } {
        anyhow::bail!("FlushFileBuffers failed: {win_err}");
    }
    Ok(())
}

/// Create a Snapshot Manager named-pipe instance, reusing the exact same
/// SDDL trust model as `broker::pipe::create_broker_pipe`: Authenticated
/// Users may connect (identity is checked at the app layer per
/// connection), with a low mandatory-integrity label so the non-elevated
/// Coordinator can open it despite the elevated/SYSTEM Broker creating it.
#[expect(unsafe_code, reason = "CreateNamedPipeW is an FFI call")]
fn create_snapshot_pipe(first_instance: bool) -> anyhow::Result<HANDLE> {
    use std::os::windows::ffi::OsStrExt as _;

    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
    use windows::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    let pipe_name: Vec<u16> = std::ffi::OsStr::new(SNAPSHOT_PIPE_NAME)
        .encode_wide()
        .chain(Some(0))
        .collect();

    let sddl: Vec<u16> = "D:(A;;GRGW;;;AU)S:(ML;;NW;;;LW)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is a NUL-terminated UTF-16 string valid for the call;
    // `descriptor` is a valid out-pointer receiving a `LocalAlloc`-ed
    // descriptor, freed below regardless of the outcome past this point.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }
    .map_err(|err| anyhow::anyhow!("failed to build snapshot pipe security descriptor: {err}"))?;

    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    let open_mode = if first_instance {
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
    } else {
        PIPE_ACCESS_DUPLEX
    };

    // SAFETY: `pipe_name` is a NUL-terminated UTF-16 buffer and `sa` (with
    // its security descriptor) both live until after this call returns;
    // the pipe copies the descriptor, so it may be freed afterwards.
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(pipe_name.as_ptr()),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            super::MAX_PIPE_INSTANCES,
            8192,
            8192,
            0,
            Some(&raw const sa),
        )
    };

    if !descriptor.0.is_null() {
        // SAFETY: `descriptor.0` was allocated by
        // `ConvertStringSecurityDescriptorToSecurityDescriptorW` via
        // `LocalAlloc`; freeing it once here is the documented contract
        // (the pipe already copied what it needed from `sa`).
        _ = unsafe {
            windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                descriptor.0,
            )))
        };
    }

    if handle.is_invalid() {
        anyhow::bail!(
            "CreateNamedPipeW (snapshot pipe) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(handle)
}

/// Current wall-clock time, Unix milliseconds, saturating to `0` if the
/// clock is somehow set before the epoch.
fn unix_ms_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::{is_uffs_content_image, is_uffs_content_reader_image};

    #[test]
    fn recognizes_coordinator_image_names() {
        assert!(is_uffs_content_image(std::ffi::OsStr::new(
            r"C:\uffs\uffs-content.exe"
        )));
        assert!(is_uffs_content_image(std::ffi::OsStr::new(
            "/usr/local/bin/uffs-content"
        )));
        assert!(!is_uffs_content_image(std::ffi::OsStr::new(
            r"C:\uffs\uffs-content-reader.exe"
        )));
    }

    #[test]
    fn recognizes_reader_image_names() {
        assert!(is_uffs_content_reader_image(std::ffi::OsStr::new(
            r"C:\uffs\uffs-content-reader.exe"
        )));
        assert!(!is_uffs_content_reader_image(std::ffi::OsStr::new(
            r"C:\uffs\uffs-content.exe"
        )));
    }
}
