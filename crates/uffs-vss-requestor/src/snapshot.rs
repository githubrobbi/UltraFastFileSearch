// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Safe RAII wrapper over the raw VSS shim FFI ([`crate::ffi`]).

use crate::ffi;

/// A live VSS requestor session: exactly one snapshot set, created via
/// [`VssSnapshotSession::create`] and torn down exactly once, on
/// [`Drop`].
///
/// Deliberately not `Send`/`Sync` — this process holds exactly one
/// session for its entire lifetime and drives it from a single thread
/// (see `main.rs`); a background thread that notices the parent Broker
/// has died signals cleanup via a channel rather than touching the
/// session directly.
pub(crate) struct VssSnapshotSession {
    /// The live shim session handle.
    raw: *mut ffi::Session,
}

/// Everything about a created snapshot the Broker needs to hand off a
/// read lease: identifiers for cleanup/diagnostics, the device path a
/// [`super`]-level consumer would open, and the creation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SnapshotDescriptor {
    /// The snapshot set's GUID, canonical `{...}` string form.
    pub(crate) snapshot_set_id: String,
    /// This specific snapshot's GUID, canonical `{...}` string form.
    pub(crate) snapshot_id: String,
    /// The VSS provider's GUID, canonical `{...}` string form.
    pub(crate) provider_id: String,
    /// The original volume's name, if the shim reported one.
    pub(crate) original_volume_name: Option<String>,
    /// The snapshot's device path, if the shim reported one.
    pub(crate) snapshot_device_object: Option<String>,
    /// Snapshot creation time, Unix milliseconds.
    pub(crate) created_at_unix_ms: i64,
}

/// A failed VSS requestor operation, preserving stage + `HRESULT` for
/// diagnostics (never flattened to a bare string — see the
/// implementation guide's error-handling section).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VssRequestError {
    /// Which step of the requestor sequence failed.
    pub(crate) stage: i32,
    /// The failing `HRESULT`.
    pub(crate) hresult: i32,
    /// Human-readable diagnostic message.
    pub(crate) message: String,
}

impl VssSnapshotSession {
    /// Create a `VSS_CTX_FILE_SHARE_BACKUP` snapshot of `volume_path`
    /// (a canonical `\\?\Volume{GUID}\`-style path).
    ///
    /// # Errors
    /// Returns [`VssRequestError`] if any step of the requestor sequence
    /// fails; no session is returned in that case (nothing to release).
    #[expect(
        unsafe_code,
        reason = "calls into the native VSS shim; see the inline SAFETY comment"
    )]
    pub(crate) fn create(volume_path: &str) -> Result<(Self, SnapshotDescriptor), VssRequestError> {
        let wide_path: Vec<u16> = volume_path.encode_utf16().chain(Some(0)).collect();
        let mut raw_session: *mut ffi::Session = core::ptr::null_mut();
        let mut info = ffi::SnapshotInfo::zeroed();
        let mut error = ffi::VssError::zeroed();

        // SAFETY: `wide_path` is a NUL-terminated UTF-16 buffer valid for
        // the duration of this call; the three out-parameters are
        // stack-owned locals passed as exclusive raw pointers, matching
        // `native/vss_shim.h`'s documented contract.
        let hresult = unsafe {
            ffi::uffs_vss_create_file_share_snapshot(
                wide_path.as_ptr(),
                &raw mut raw_session,
                &raw mut info,
                &raw mut error,
            )
        };

        if hresult < 0_i32 {
            return Err(take_error(&mut error));
        }

        let descriptor = SnapshotDescriptor {
            snapshot_set_id: info.snapshot_set_id.to_braced_string(),
            snapshot_id: info.snapshot_id.to_braced_string(),
            provider_id: info.provider_id.to_braced_string(),
            original_volume_name: read_optional_wide(info.original_volume_name),
            snapshot_device_object: read_optional_wide(info.snapshot_device_object),
            created_at_unix_ms: info.creation_timestamp_unix_ms,
        };
        free_snapshot_info(&mut info);

        Ok((Self { raw: raw_session }, descriptor))
    }
}

impl Drop for VssSnapshotSession {
    #[expect(
        unsafe_code,
        reason = "releases the native VSS shim session; see the inline SAFETY comment"
    )]
    fn drop(&mut self) {
        // SAFETY: `self.raw` was produced by `create` and is released
        // exactly once here. If the snapshot set was never explicitly
        // deleted above, this is where `VSS_CTX_FILE_SHARE_BACKUP`'s
        // auto-release semantics actually remove it — the crash-safety
        // net this whole design relies on.
        unsafe {
            ffi::uffs_vss_session_release(self.raw);
        }
    }
}

/// Convert a populated `VssError` out-parameter into an owned
/// [`VssRequestError`], freeing the shim-allocated message string.
fn take_error(error: &mut ffi::VssError) -> VssRequestError {
    let message = read_optional_wide(error.message).unwrap_or_else(|| "(no message)".to_owned());
    let request_error = VssRequestError {
        stage: error.stage,
        hresult: error.hresult,
        message,
    };
    free_error(error);
    request_error
}

/// Free `info`'s shim-allocated string fields.
#[expect(
    unsafe_code,
    reason = "frees shim-allocated memory; see the inline SAFETY comment"
)]
fn free_snapshot_info(info: &mut ffi::SnapshotInfo) {
    // SAFETY: `info`'s string fields (if any) were allocated by the shim
    // and must be released through its own free function.
    unsafe { ffi::uffs_vss_snapshot_info_free(info) }
}

/// Free `error`'s shim-allocated message string.
#[expect(
    unsafe_code,
    reason = "frees shim-allocated memory; see the inline SAFETY comment"
)]
fn free_error(error: &mut ffi::VssError) {
    // SAFETY: `error.message`, if non-null, was allocated by the shim.
    unsafe { ffi::uffs_vss_error_free(error) }
}

/// Read a NUL-terminated UTF-16 string the shim allocated, or `None` if
/// `ptr` is null. Does not free `ptr` — the caller is responsible for
/// that via the matching `*_free` function.
#[expect(
    unsafe_code,
    reason = "reads a shim-allocated string; see the inline SAFETY comments"
)]
fn read_optional_wide(ptr: *mut u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }

    let mut length = 0_usize;
    loop {
        // SAFETY: `ptr` is non-null and points to a NUL-terminated
        // UTF-16 buffer per the shim's contract; `length` stays in
        // bounds because the loop stops at the first NUL unit.
        let unit_ptr = unsafe { ptr.add(length) };
        // SAFETY: `unit_ptr` was just computed as an in-bounds offset
        // from a valid buffer, established immediately above.
        let unit = unsafe { *unit_ptr };
        if unit == 0 {
            break;
        }
        length += 1;
    }

    // SAFETY: `ptr` is non-null and valid for `length` `u16` elements —
    // established by the loop above stopping at the first NUL unit.
    let slice = unsafe { core::slice::from_raw_parts(ptr, length) };
    Some(String::from_utf16_lossy(slice))
}
