// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Raw FFI declarations for the native VSS shim (`native/vss_shim.h`/
//! `.cpp`, compiled and linked in by `build.rs`).
//!
//! Every `#[repr(C)]` type here must exactly mirror the C header's field
//! order, size, and alignment — see `Guid`'s doc comment for why it's
//! not a bare `[u8; 16]`. This module only declares the raw boundary;
//! [`crate::snapshot`] owns the safe wrapper (RAII session, string
//! decoding, error conversion).

/// Mirrors the Win32 `GUID` struct field-for-field (`data1: u32`,
/// `data2`/`data3: u16`, `data4: [u8; 8]`) rather than a bare `[u8; 16]`.
/// A byte array has alignment 1, but `GUID`'s actual alignment is 4 (from
/// its leading `u32`) — since [`SnapshotInfo`] embeds three of these
/// directly (not as pointers), a wrong alignment here would shift every
/// field after them, corrupting the ABI silently.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Guid {
    /// First 4 bytes (`Data1`).
    pub(crate) data1: u32,
    /// Next 2 bytes (`Data2`).
    pub(crate) data2: u16,
    /// Next 2 bytes (`Data3`).
    pub(crate) data3: u16,
    /// Final 8 bytes (`Data4`).
    pub(crate) data4: [u8; 8],
}

impl Guid {
    /// Render in the canonical `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`
    /// form.
    pub(crate) fn to_braced_string(self) -> String {
        format!(
            "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        )
    }
}

/// Mirrors `UffsVssSnapshotInfo` in `native/vss_shim.h` field-for-field.
#[repr(C)]
pub(crate) struct SnapshotInfo {
    /// The snapshot set's GUID.
    pub(crate) snapshot_set_id: Guid,
    /// This specific snapshot's GUID.
    pub(crate) snapshot_id: Guid,
    /// The VSS provider's GUID.
    pub(crate) provider_id: Guid,
    /// NUL-terminated UTF-16 original volume name, or null.
    pub(crate) original_volume_name: *mut u16,
    /// NUL-terminated UTF-16 snapshot device path, or null.
    pub(crate) snapshot_device_object: *mut u16,
    /// Snapshot creation time, Unix milliseconds.
    pub(crate) creation_timestamp_unix_ms: i64,
}

impl SnapshotInfo {
    /// A zeroed value, matching the shim's `zero_info` — safe to pass as
    /// an out-parameter before the shim populates (or fails to
    /// populate) it.
    pub(crate) const fn zeroed() -> Self {
        Self {
            snapshot_set_id: Guid {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            },
            snapshot_id: Guid {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            },
            provider_id: Guid {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            },
            original_volume_name: core::ptr::null_mut(),
            snapshot_device_object: core::ptr::null_mut(),
            creation_timestamp_unix_ms: 0,
        }
    }
}

/// Mirrors `UffsVssError` in `native/vss_shim.h` field-for-field. `stage`
/// is `i32`, not `u32`: a plain C/C++ enum with no explicit underlying
/// type (as `UffsVssStage` is declared) has an implementation-defined
/// signed underlying type — `int` for every target this workspace
/// builds against.
#[repr(C)]
pub(crate) struct VssError {
    /// The failing `HRESULT`.
    pub(crate) hresult: i32,
    /// Which step of the requestor sequence failed (`UffsVssStage`).
    pub(crate) stage: i32,
    /// NUL-terminated UTF-16 diagnostic message, or null.
    pub(crate) message: *mut u16,
}

impl VssError {
    /// A zeroed value, safe to pass as an out-parameter.
    pub(crate) const fn zeroed() -> Self {
        Self {
            hresult: 0,
            stage: 0,
            message: core::ptr::null_mut(),
        }
    }
}

/// Opaque handle to a live VSS requestor session — never constructed or
/// read from Rust, only passed back to the shim that produced it.
pub(crate) enum Session {}

#[expect(
    unsafe_code,
    reason = "raw FFI declarations for the native VSS shim compiled by build.rs; \
              every call site documents its own safety contract in crate::snapshot"
)]
unsafe extern "C" {
    pub(crate) fn uffs_vss_create_file_share_snapshot(
        volume_path: *const u16,
        out_session: *mut *mut Session,
        out_info: *mut SnapshotInfo,
        out_error: *mut VssError,
    ) -> i32;

    pub(crate) fn uffs_vss_session_release(session: *mut Session);
    pub(crate) fn uffs_vss_snapshot_info_free(info: *mut SnapshotInfo);
    pub(crate) fn uffs_vss_error_free(error: *mut VssError);
}
