// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Windows NTFS volume handle and metadata access helpers.
//!
//! Exception: Volume handle + write-protect fallback handles; splitting would
//! fragment the handle lifecycle.

use core::mem::size_of;
use core::time::Duration;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_NO_BUFFERING, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAG_OVERLAPPED, FILE_FLAG_SEQUENTIAL_SCAN, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    SYNCHRONIZE,
};
use windows::Win32::System::Ioctl::{FSCTL_GET_NTFS_VOLUME_DATA, NTFS_VOLUME_DATA_BUFFER};
use windows::core::PCWSTR;
use zerocopy::FromBytes as _;

use super::bitmap::MftBitmap;
use super::extents::{MftExtent, get_retrieval_pointers};
use crate::error::{MftError, Result};
use crate::index::{frs_to_usize, u32_as_usize};
use crate::ntfs::NtfsBootSector;

/// `FILE_READ_DATA` access right (0x0001) - required to read data from a
/// file/volume.
const FILE_READ_DATA: u32 = 0x0001;

/// Short poll interval for Windows completion waits in MFT hot paths.
pub(crate) const IOCP_WAIT_POLL_INTERVAL_MS: u32 = 100;

/// Maximum stall time allowed between Windows completion notifications.
pub(crate) const IOCP_WAIT_COMPLETION_DEADLINE: Duration = Duration::from_secs(30);

/// Win32 error code reported when a wait interval expires.
pub(crate) const WAIT_TIMEOUT_ERROR_CODE: u32 = 258;

/// Win32 error code reported when an overlapped operation is aborted.
const ERROR_OPERATION_ABORTED_CODE: u32 = 995;

// ── Access Broker handle registry ──────────────────────────────────────────
//
// On Windows, opening `\\.\X:` for raw MFT reads needs Administrator.  When a
// non-elevated daemon runs with the UFFS Access Broker service available, the
// broker (elevated) opens the volume and hands the daemon a duplicated handle
// over a named pipe.  The daemon deposits that handle here keyed by drive
// letter; `VolumeHandle::open` checks the registry FIRST and adopts the
// pre-opened handle instead of calling `CreateFileW` (which would fail with
// access-denied).  This keeps the broker plumbing out of the deep
// load-live-drives call chain — one deposit, one lookup.
//
// Handles are stored as the raw `u64` value the broker sends over the wire
// (`HANDLE` itself is not `Send`/`Sync`); the value is a process-local
// capability already duplicated into this process by the broker.

/// Process-wide map of drive letter → broker-supplied raw volume handle.
#[cfg(windows)]
static BROKER_HANDLES: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<char, u64>>> =
    std::sync::OnceLock::new();

/// Deposit a broker-supplied volume handle for `drive`.
///
/// `raw_handle` is the duplicated `HANDLE` value `uffs-broker` returned over
/// its pipe.  Every [`VolumeHandle::open`] for this drive **duplicates** it
/// (the registry copy stays in place) — the live MFT read opens the volume
/// more than once (read pass + cache-write pass), so a take-once handle would
/// leave the second open to fall back to `CreateFileW` and fail with
/// access-denied.  The registry entry is freed by [`release_broker_handle`].
#[cfg(windows)]
pub fn register_broker_handle(drive: super::DriveLetter, raw_handle: u64) {
    let map =
        BROKER_HANDLES.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        guard.insert(drive.as_char(), raw_handle);
    }
}

/// Read (without removing) the registered broker handle for `drive`, if any.
///
/// The entry is intentionally retained for the daemon's lifetime: every
/// `VolumeHandle::open` duplicates it (so multiple opens in one load, and
/// later re-reads, all succeed), and the OS closes the original on process
/// exit.  Keeping it also means re-reads keep working even if the broker
/// service later stops — the daemon holds its own independent handle.
#[cfg(windows)]
fn peek_broker_handle(drive: super::DriveLetter) -> Option<u64> {
    let map = BROKER_HANDLES.get()?;
    let guard = map.lock().ok()?;
    guard.get(&drive.as_char()).copied()
}

/// `DuplicateHandle` a registered broker volume handle into an independent,
/// caller-owned handle.
///
/// `raw` is the registry's `u64` (the handle `uffs-broker` duplicated into this
/// process).  The returned handle is a *separate* duplicate, so closing it does
/// not invalidate the registry entry — every open in a load can adopt its own
/// copy.  Centralised here so the MFT read (`VolumeHandle::open` /
/// [`VolumeHandle::from_broker_handle`]), the USN journal open, and the `$MFT`
/// extent read share one `DuplicateHandle` implementation instead of each
/// re-deriving the `with_exposed_provenance_mut` reconstruction.
#[cfg(windows)]
#[expect(unsafe_code, reason = "FFI: DuplicateHandle / GetCurrentProcess")]
fn duplicate_registered_handle(raw: u64, drive: super::DriveLetter) -> Result<HANDLE> {
    use windows::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
    use windows::Win32::System::Threading::GetCurrentProcess;

    let registered = HANDLE(core::ptr::with_exposed_provenance_mut::<core::ffi::c_void>(
        usize::try_from(raw).unwrap_or(0),
    ));
    let mut handle = HANDLE::default();
    // SAFETY: returns the current-process pseudo-handle; no preconditions.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: `process` is valid; `registered` is the broker handle owned by
    // this process; `&raw mut handle` is a valid out-pointer.  On success the
    // duplicate is owned by the caller.
    let dup = unsafe {
        DuplicateHandle(
            process,
            registered,
            process,
            &raw mut handle,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    };
    dup.map_err(|err| MftError::VolumeOpen {
        volume: drive,
        source: hresult_to_io_error(&err),
    })?;
    Ok(handle)
}

/// Adopt a duplicate of the registered broker volume handle for `drive`, if one
/// is registered.
///
/// Returns `Ok(Some(handle))` with a caller-owned duplicate when the Access
/// Broker has deposited a handle for `drive`, or `Ok(None)` when none is
/// registered (the caller should then open the volume directly with its own
/// access/flags).  This is the single policy seam shared by the MFT read, the
/// USN journal open, and the `$MFT` extent read: the *adoption* is uniform, but
/// each caller's *direct-open* flags differ, so only this half is centralised.
///
/// `pub(crate)` so the USN journal open (FU-2b) and, later, the `$MFT` extent
/// read (FU-3) can adopt the same broker handle the MFT read uses — re-exported
/// as `crate::platform::try_adopt_broker_handle`.
#[cfg(windows)]
pub(crate) fn try_adopt_broker_handle(drive: super::DriveLetter) -> Result<Option<HANDLE>> {
    match peek_broker_handle(drive) {
        Some(raw) => Ok(Some(duplicate_registered_handle(raw, drive)?)),
        None => Ok(None),
    }
}

/// Read `buf.len()` bytes from a raw volume `handle` at byte `offset`, carrying
/// the offset in an `OVERLAPPED`.
///
/// Works on the broker's `FILE_FLAG_OVERLAPPED` handle — which has **no
/// synchronous file pointer**, so a `SetFilePointerEx` seek fails on it (the
/// `$UpCase` "parameter is incorrect" failure) — as well as on a plain
/// synchronous handle (the offset in the `OVERLAPPED` is honoured either way).
/// These are single, non-concurrent metadata reads, so completion is awaited
/// via `GetOverlappedResult` on the handle without a dedicated event.  Shared
/// by the MFT-extent bootstrap (FU-3) and the `$UpCase` read (FU-8).
///
/// # Errors
///
/// [`MftError::Io`] if `ReadFile` / `GetOverlappedResult` fail, or
/// [`MftError::InvalidData`] on a short read.
#[cfg(windows)]
pub(crate) fn read_handle_at(handle: HANDLE, offset: u64, buf: &mut [u8]) -> Result<()> {
    // `ERROR_OPERATION_ABORTED` (995) is transient: the OS cancels a *pending*
    // overlapped read when the thread that issued it is reaped — e.g. a tokio
    // `spawn_blocking` / rayon worker recycling during a parked-drive re-warm
    // (the USN-refresh reads MFT extents over the broker's overlapped handle).
    // The read is valid, so reissue it; bounded so a genuinely wedged handle
    // still fails fast instead of spinning forever.
    const MAX_ABORT_RETRIES: u32 = 8;

    let mut attempt = 0_u32;
    loop {
        match read_handle_at_once(handle, offset, buf) {
            Ok(()) => return Ok(()),
            Err(err) if attempt < MAX_ABORT_RETRIES && is_operation_aborted(&err) => {
                attempt += 1;
                // Yield so the recycled thread / overlapped slot can settle
                // before the read is reissued.
                std::thread::yield_now();
            }
            Err(err) => return Err(err),
        }
    }
}

/// `true` when `err` is a Windows `ERROR_OPERATION_ABORTED` (995) I/O failure —
/// the transient cancellation [`read_handle_at`] retries.
#[cfg(windows)]
fn is_operation_aborted(err: &MftError) -> bool {
    let aborted = i32::try_from(ERROR_OPERATION_ABORTED_CODE).ok();
    matches!(err, MftError::Io(io) if io.raw_os_error() == aborted)
}

/// One overlapped read attempt; the [`read_handle_at`] wrapper adds the
/// transient-abort (995) retry.
///
/// # Errors
///
/// [`MftError::Io`] if `ReadFile` / `GetOverlappedResult` fail, or
/// [`MftError::InvalidData`] on a short read.
#[cfg(windows)]
#[expect(unsafe_code, reason = "FFI: create/close a per-read completion event")]
fn read_handle_at_once(handle: HANDLE, offset: u64, buf: &mut [u8]) -> Result<()> {
    use windows::Win32::System::Threading::CreateEventW;

    // Bind THIS read to a dedicated manual-reset event and wait on the event —
    // never on the bare file handle. The Access Broker vends duplicate handles
    // to the same volume file object, so during a fresh concurrent multi-drive
    // load several overlapped reads race on that object; a NULL-event
    // `GetOverlappedResult(bWait=true)` then cannot tell which read completed
    // and blocks forever (Microsoft's documented pitfall). That was the post-
    // read `$UpCase` read that silently hung 1-2 drives at 5-or-6-of-7 on every
    // fresh (no-cache) daemon start. The event makes the wait specific to this
    // read and lets us bound it.
    //
    // SAFETY: FFI. `CreateEventW` returns an owned event handle we close below.
    let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
        .map_err(|err| MftError::Io(hresult_to_io_error(&err)))?;
    let outcome = read_handle_at_once_event(handle, offset, buf, event);
    // SAFETY: FFI. `event` is the live event we created; close it exactly once.
    unsafe {
        let _closed = CloseHandle(event);
    }
    outcome
}

/// Body of [`read_handle_at_once`] given a dedicated completion `event`, split
/// out so the caller closes the event on every return path.
///
/// # Errors
///
/// [`MftError::Io`] if `ReadFile` / the wait / `GetOverlappedResult` fail — an
/// overrun of [`IOCP_WAIT_COMPLETION_DEADLINE`] surfaces as a retryable
/// `ERROR_OPERATION_ABORTED` — or [`MftError::InvalidData`] on a short read.
#[cfg(windows)]
#[expect(unsafe_code, reason = "FFI: overlapped ReadFile + event-bounded wait")]
fn read_handle_at_once_event(
    handle: HANDLE,
    offset: u64,
    buf: &mut [u8],
    event: HANDLE,
) -> Result<()> {
    use windows::Win32::Foundation::{ERROR_IO_PENDING, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::Storage::FileSystem::ReadFile;
    use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows::Win32::System::Threading::WaitForSingleObject;

    let mut overlapped = OVERLAPPED::default();
    crate::io::readers::set_overlapped_offset(&mut overlapped, offset);
    overlapped.hEvent = event;

    let mut bytes_read = 0_u32;
    // SAFETY: `buf` is valid+writable for its length; `overlapped` (with its
    // event) outlives the call and the wait; `handle` is a live volume handle.
    let read = unsafe {
        ReadFile(
            handle,
            Some(buf),
            Some(&raw mut bytes_read),
            Some(&raw mut overlapped),
        )
    };
    if let Err(err) = read {
        if err.code() != ERROR_IO_PENDING.to_hresult() {
            return Err(MftError::Io(hresult_to_io_error(&err)));
        }
        let deadline_ms =
            u32::try_from(IOCP_WAIT_COMPLETION_DEADLINE.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: FFI. `event` is the manual-reset event bound to `overlapped`.
        let wait = unsafe { WaitForSingleObject(event, deadline_ms) };
        if wait == WAIT_TIMEOUT {
            // The read wedged. Cancel it and drain the cancellation so the
            // kernel stops referencing `buf` / `overlapped` before they drop,
            // then report a retryable abort (995) that `read_handle_at`
            // reissues.
            // SAFETY: FFI. Cancel the in-flight read on this handle+overlapped.
            unsafe {
                let _cancelled = CancelIoEx(handle, Some(&raw const overlapped));
            }
            // SAFETY: FFI. Drain the cancellation (blocks via the bound event
            // until it settles) so the kernel stops referencing `buf` /
            // `overlapped` before they drop.
            unsafe {
                let _drained =
                    GetOverlappedResult(handle, &raw const overlapped, &raw mut bytes_read, true);
            }
            return Err(MftError::Io(std::io::Error::from_raw_os_error(
                i32::try_from(ERROR_OPERATION_ABORTED_CODE).unwrap_or(995),
            )));
        }
        if wait != WAIT_OBJECT_0 {
            return Err(MftError::Io(std::io::Error::other(format!(
                "overlapped read wait failed: WaitForSingleObject returned 0x{:08X}",
                wait.0
            ))));
        }
        // Signaled: collect the result without waiting further.
        // SAFETY: FFI. `overlapped` is the completed in-flight struct.
        unsafe { GetOverlappedResult(handle, &raw const overlapped, &raw mut bytes_read, false) }
            .map_err(|wait_err| MftError::Io(hresult_to_io_error(&wait_err)))?;
    }
    if (bytes_read as usize) < buf.len() {
        return Err(MftError::InvalidData(format!(
            "overlapped read short: {bytes_read} of {} bytes",
            buf.len()
        )));
    }
    Ok(())
}

/// Convert a `windows::core::Error` into the equivalent `std::io::Error`,
/// **unwrapping** the `HRESULT_FROM_WIN32` envelope so std's
/// `decode_error_kind` table (keyed on bare Win32 codes like
/// `ERROR_FILE_EXISTS = 80`, `ERROR_ACCESS_DENIED = 5`, …) resolves the
/// canonical `ErrorKind` rather than degrading every failure to
/// `ErrorKind::Other`.
///
/// `windows::core::Error::code()` returns an HRESULT.  Win32 failures
/// arrive wrapped via `HRESULT_FROM_WIN32`, which sets facility = 7
/// (`FACILITY_WIN32`, severity = 1) and stuffs `GetLastError()` into
/// the low 16 bits:
///
/// ```text
///     0x8007_XXXX  ← XXXX = GetLastError()
/// ```
///
/// `io::Error::from_raw_os_error` expects the bare Win32 code (not the
/// wrapped HRESULT), so we strip the envelope when present.  Non-WIN32
/// HRESULTs fall through unchanged — std has no portable kind mapping
/// for them anyway, and `from_raw_os_error` will preserve the raw value
/// verbatim.
///
/// This mirrors the same fix applied to
/// `WindowsRuntimeDir::create_owner_only` in PR #273 (refs #267,
/// nightly run 26037964594).  The four `CreateFileW` error sites in
/// this file (`VolumeHandle::open`, `open_overlapped_handle`,
/// `open_mft_read_handle`, `open_unbuffered_handle`) previously
/// forwarded the raw HRESULT to `io::Error::from_raw_os_error`,
/// producing the same latent contract bug — no current test exercises
/// `ErrorKind` on those paths, so the bug stayed hidden, but a future
/// caller doing `if err.kind() == ErrorKind::PermissionDenied { … }`
/// would silently take the wrong branch.
fn hresult_to_io_error(err: &windows::core::Error) -> std::io::Error {
    let hresult = err.code().0;
    // `i32::cast_unsigned` reinterprets the same bits as `u32` for
    // comparison against documented HRESULT envelope constants (which
    // Microsoft publishes as `u32`).  Matches the existing convention
    // at `VolumeHandle::open` (this file, search for `code_unsigned`).
    let win32_code = if (hresult.cast_unsigned() & 0xFFFF_0000_u32) == 0x8007_0000_u32 {
        hresult & 0xFFFF_i32
    } else {
        hresult
    };
    std::io::Error::from_raw_os_error(win32_code)
}

/// Classifies a Windows wait failure using the approved Wave 3A taxonomy.
#[must_use]
pub(crate) fn classify_wait_error_code(
    operation: &'static str,
    error_code: u32,
    detail: impl Into<String>,
) -> MftError {
    let detail_str: String = detail.into();

    match error_code {
        ERROR_OPERATION_ABORTED_CODE => MftError::Cancelled {
            operation,
            reason: format!("{detail_str} (Win32 error {error_code})"),
        },
        _ => MftError::WaitFailed {
            operation,
            reason: format!("{detail_str} (Win32 error {error_code})"),
        },
    }
}

/// Builds a timeout error for a Windows completion wait that exceeded its
/// deadline.
#[must_use]
pub(crate) fn wait_deadline_exceeded(
    operation: &'static str,
    waited: Duration,
    detail: impl Into<String>,
) -> MftError {
    let detail_str: String = detail.into();

    MftError::Timeout {
        operation,
        reason: format!(
            "{detail_str} after {} ms without observing a completion",
            waited.as_millis()
        ),
    }
}

/// A handle to an NTFS volume for direct disk access.
///
/// This handle is opened with backup semantics and no buffering for
/// optimal MFT reading performance.
#[derive(Debug)]
pub struct VolumeHandle {
    /// The raw Windows handle.
    handle: HANDLE,
    /// The volume letter.
    volume: super::DriveLetter,
    /// NTFS volume data from `FSCTL_GET_NTFS_VOLUME_DATA`.
    volume_data: NtfsVolumeData,
    /// `true` when `handle` was supplied by the Access Broker rather than
    /// opened here via `CreateFileW`.  A broker handle is already an
    /// elevated, overlapped volume handle, so [`Self::open_overlapped_handle`]
    /// duplicates it instead of re-opening `\\.\X:` (which would need admin).
    broker_backed: bool,
}

#[expect(
    unsafe_code,
    reason = "windows file handles are thread-safe kernel objects"
)]
// SAFETY: `VolumeHandle` owns a Windows `HANDLE` to a kernel-managed file
// object plus immutable metadata (`volume` and `volume_data`). It contains no
// Rust references or unsynchronized interior mutability, so moving ownership
// to another thread does not invalidate any aliasing assumptions. Handle
// cleanup remains centralized in `Drop`.
unsafe impl Send for VolumeHandle {}

#[expect(
    unsafe_code,
    reason = "windows file handles are thread-safe kernel objects"
)]
// SAFETY: Shared references to `VolumeHandle` only expose immutable metadata or
// copy the raw `HANDLE`. The wrapper itself performs no unsynchronized mutable
// access, and Windows file handles are designed to be used from multiple
// threads.
unsafe impl Sync for VolumeHandle {}

/// NTFS volume data retrieved from `FSCTL_GET_NTFS_VOLUME_DATA`.
#[derive(Debug, Clone, Copy)]
pub struct NtfsVolumeData {
    /// Volume serial number.
    pub volume_serial_number: u64,
    /// NTFS major version (e.g. 3 for NTFS 3.1).
    pub ntfs_major_version: u16,
    /// NTFS minor version (e.g. 1 for NTFS 3.1).
    pub ntfs_minor_version: u16,
    /// Number of sectors on the volume.
    pub number_of_sectors: u64,
    /// Total number of clusters.
    pub total_clusters: u64,
    /// Number of free clusters.
    pub free_clusters: u64,
    /// Total number of reserved clusters.
    pub total_reserved: u64,
    /// Bytes per sector.
    pub bytes_per_sector: u32,
    /// Bytes per cluster.
    pub bytes_per_cluster: u32,
    /// Bytes per file record segment.
    pub bytes_per_file_record_segment: u32,
    /// Clusters per file record segment.
    pub clusters_per_file_record_segment: u32,
    /// MFT valid data length.
    pub mft_valid_data_length: u64,
    /// MFT start LCN (Logical Cluster Number).
    pub mft_start_lcn: u64,
    /// MFT2 start LCN.
    pub mft2_start_lcn: u64,
    /// MFT zone start.
    pub mft_zone_start: u64,
    /// MFT zone end.
    pub mft_zone_end: u64,
}

impl NtfsVolumeData {
    /// Computes the reserved allocated bytes for the root directory.
    ///
    /// NTFS formula: `TotalReserved * BytesPerCluster`.
    ///
    /// The MFT zone contribution is suppressed by setting
    /// `mft_zone_end = mft_zone_start` before computing `reserved_clusters`
    /// (see `mft_reader_init.hpp` lines 166-171).  So the effective formula
    /// is just `TotalReserved * BytesPerCluster`.
    #[must_use]
    pub const fn reserved_allocated_bytes(&self) -> u64 {
        self.total_reserved * self.bytes_per_cluster as u64
    }
}

impl VolumeHandle {
    /// Opens a volume for direct MFT reading.
    ///
    /// # Errors
    ///
    /// Returns [`MftError::Io`] if `CreateFileW` on the `\\.\<letter>:`
    /// path fails (typically `ERROR_ACCESS_DENIED` when the caller is not
    /// elevated), or if `FSCTL_GET_NTFS_VOLUME_DATA` cannot read the volume
    /// descriptor for the opened handle.
    #[expect(unsafe_code, reason = "FFI: windows API (CreateFileW)")]
    pub fn open(volume: super::DriveLetter) -> Result<Self> {
        // Access Broker fast-path: if the (elevated) broker has deposited a
        // pre-opened, duplicated volume handle for this drive, adopt a
        // duplicate of it instead of calling `CreateFileW` — which would fail
        // with access-denied in a non-elevated daemon.  The registry entry
        // stays so later opens in the same load succeed (see
        // `try_adopt_broker_handle`).
        if let Some(handle) = try_adopt_broker_handle(volume)? {
            return Self::from_adopted_handle(handle, volume);
        }

        // `DriveLetter` is already validated (`A..=Z`), so no fallible
        // pre-check is needed here.  The wire path uses the
        // canonical uppercase ASCII byte directly.
        let volume_path: Vec<u16> = format!("\\\\.\\{}:", volume.as_char())
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();

        // SAFETY: `volume_path` is UTF-16 and NUL-terminated for the duration of
        // the call, optional pointers are passed as `None`, and on success the
        // returned handle is owned by this function.
        let create_result = unsafe {
            CreateFileW(
                PCWSTR::from_raw(volume_path.as_ptr()),
                FILE_READ_DATA | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN,
                None,
            )
        };

        let handle = match create_result {
            Ok(handle) => handle,
            Err(err) => {
                // `err.code().0` is an `i32` holding an HRESULT bit
                // pattern; `i32::cast_unsigned` reinterprets the same
                // bits as `u32` for comparison against documented Win32
                // error constants (which Microsoft publishes as u32).
                let code_unsigned = err.code().0.cast_unsigned();
                if code_unsigned == 0x8007_0005 {
                    return Err(MftError::InsufficientPrivileges);
                }
                return Err(MftError::VolumeOpen {
                    volume,
                    source: hresult_to_io_error(&err),
                });
            }
        };

        let volume_data = Self::get_ntfs_volume_data(handle, volume)?;

        Ok(Self {
            handle,
            volume,
            volume_data,
            broker_backed: false,
        })
    }

    /// Adopt a **duplicate** of the broker-supplied volume handle for `volume`.
    ///
    /// `raw_handle` is the registry's broker handle (the one `uffs-broker`
    /// duplicated into this process).  This function `DuplicateHandle`s it so
    /// the returned `VolumeHandle` owns an independent copy — its `Drop` closes
    /// only the duplicate, leaving the registry entry valid for the next open
    /// in the same load (the original is freed via `release_broker_handle`).
    /// The broker opens the volume with
    /// `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED |
    /// FILE_FLAG_SEQUENTIAL_SCAN`, so the duplicate is usable for both the
    /// volume-data query here and the overlapped MFT read via
    /// [`Self::open_overlapped_handle`].
    ///
    /// # Errors
    ///
    /// Returns [`MftError`] if the handle cannot be duplicated or the volume
    /// descriptor cannot be read from it.
    #[cfg(windows)]
    pub fn from_broker_handle(volume: super::DriveLetter, raw_handle: u64) -> Result<Self> {
        let handle = duplicate_registered_handle(raw_handle, volume)?;
        Self::from_adopted_handle(handle, volume)
    }

    /// Build a broker-backed `VolumeHandle` from an already-duplicated,
    /// caller-owned volume `handle` (the output of
    /// [`duplicate_registered_handle`] / [`try_adopt_broker_handle`]).
    ///
    /// Reads the volume descriptor from the handle and marks the result
    /// `broker_backed` so [`Self::open_overlapped_handle`] duplicates the
    /// handle rather than re-opening `\\.\X:`.  Shared by [`Self::open`]'s
    /// fast-path and [`Self::from_broker_handle`] so the descriptor read +
    /// `broker_backed` construction live in one place.
    ///
    /// # Errors
    ///
    /// Returns [`MftError`] if the volume descriptor cannot be read from
    /// `handle`.
    #[cfg(windows)]
    fn from_adopted_handle(handle: HANDLE, volume: super::DriveLetter) -> Result<Self> {
        let volume_data = Self::get_ntfs_volume_data(handle, volume)?;
        tracing::info!(drive = %volume, "Adopted Access Broker volume handle for MFT read");
        Ok(Self {
            handle,
            volume,
            volume_data,
            broker_backed: true,
        })
    }

    /// Retrieves NTFS volume data using `FSCTL_GET_NTFS_VOLUME_DATA`.
    #[expect(unsafe_code, reason = "FFI: windows API (DeviceIoControl)")]
    fn get_ntfs_volume_data(handle: HANDLE, volume: super::DriveLetter) -> Result<NtfsVolumeData> {
        use windows::Win32::System::IO::DeviceIoControl;

        let mut buffer = NTFS_VOLUME_DATA_BUFFER::default();
        let mut bytes_returned: u32 = 0;

        // `size_of::<NTFS_VOLUME_DATA_BUFFER>()` is ~96 bytes — always fits u32.
        let ntfs_volume_data_buffer_size =
            u32::try_from(size_of::<NTFS_VOLUME_DATA_BUFFER>()).unwrap_or(u32::MAX);

        // SAFETY: `handle` is an open volume handle, `buffer` points to valid
        // writable storage for `NTFS_VOLUME_DATA_BUFFER`, and
        // `bytes_returned` is a valid out-parameter for the duration of the
        // call.
        let result = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_GET_NTFS_VOLUME_DATA,
                None,
                0,
                Some(core::ptr::from_mut(&mut buffer).cast()),
                ntfs_volume_data_buffer_size,
                Some(&raw mut bytes_returned),
                None,
            )
        };

        if result.is_err() {
            return Err(MftError::NotNtfs(volume));
        }

        // Note: NTFS major/minor version requires NTFS_EXTENDED_VOLUME_DATA
        // (not available in NTFS_VOLUME_DATA_BUFFER).  Default to 0; callers
        // should use `query_ntfs_version()` if they need the actual version.
        //
        // Every `i64 -> u64` reinterpret below comes from an on-disk
        // NTFS count (sector / cluster / LCN / length) that the NTFS
        // on-disk format and Microsoft's `NTFS_VOLUME_DATA_BUFFER` MSDN
        // page document as non-negative.  `i64::cast_unsigned` /
        // `u64::cast_unsigned` are the stable Rust 1.87
        // exact-bit-pattern converters that replace the previous
        // `cast_sign_loss` expect.
        let volume_data = NtfsVolumeData {
            volume_serial_number: buffer.VolumeSerialNumber.cast_unsigned(),
            ntfs_major_version: 0,
            ntfs_minor_version: 0,
            number_of_sectors: buffer.NumberSectors.cast_unsigned(),
            total_clusters: buffer.TotalClusters.cast_unsigned(),
            free_clusters: buffer.FreeClusters.cast_unsigned(),
            total_reserved: buffer.TotalReserved.cast_unsigned(),
            bytes_per_sector: buffer.BytesPerSector,
            bytes_per_cluster: buffer.BytesPerCluster,
            bytes_per_file_record_segment: buffer.BytesPerFileRecordSegment,
            clusters_per_file_record_segment: buffer.ClustersPerFileRecordSegment,
            mft_valid_data_length: buffer.MftValidDataLength.cast_unsigned(),
            mft_start_lcn: buffer.MftStartLcn.cast_unsigned(),
            mft2_start_lcn: buffer.Mft2StartLcn.cast_unsigned(),
            mft_zone_start: buffer.MftZoneStart.cast_unsigned(),
            mft_zone_end: buffer.MftZoneEnd.cast_unsigned(),
        };
        Ok(volume_data)
    }

    /// Returns the volume letter.
    #[must_use]
    pub const fn volume(&self) -> super::DriveLetter {
        self.volume
    }

    /// Returns the NTFS volume data.
    #[must_use]
    pub const fn volume_data(&self) -> &NtfsVolumeData {
        &self.volume_data
    }

    /// Returns the raw Windows handle.
    #[must_use]
    pub const fn raw_handle(&self) -> HANDLE {
        self.handle
    }

    /// Opens a new handle to the same volume with `FILE_FLAG_OVERLAPPED`.
    ///
    /// # Errors
    ///
    /// Returns `MftError::VolumeOpen` if `CreateFileW` fails.
    #[expect(unsafe_code, reason = "FFI: windows API (CreateFileW)")]
    pub fn open_overlapped_handle(&self) -> Result<HANDLE> {
        let volume = self.volume;

        // Broker-backed: `\\.\X:` can't be re-opened here (non-elevated →
        // access-denied).  The broker handle is already overlapped, so hand
        // back an independent duplicate the caller can close on its own.
        if self.broker_backed {
            return self.duplicate_broker_handle();
        }

        let volume_path: Vec<u16> = format!("\\\\.\\{volume}:")
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();

        // SAFETY: `volume_path` is UTF-16 and NUL-terminated for the duration of
        // the call, optional pointers are passed as `None`, and ownership of
        // any returned handle is transferred to the caller.
        let handle = unsafe {
            CreateFileW(
                PCWSTR::from_raw(volume_path.as_ptr()),
                FILE_READ_DATA | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN,
                None,
            )
        };

        handle.map_err(|err| MftError::VolumeOpen {
            volume,
            source: hresult_to_io_error(&err),
        })
    }

    /// Duplicate the adopted broker handle into a fresh, independently-owned
    /// overlapped handle for the bulk MFT read path.
    ///
    /// Same-process `DuplicateHandle` with `DUPLICATE_SAME_ACCESS` clones the
    /// access rights and the `FILE_FLAG_OVERLAPPED` mode of the broker handle;
    /// the caller closes the returned handle, leaving `self.handle` intact for
    /// the volume-data queries and for `Drop`.
    #[cfg(windows)]
    #[expect(unsafe_code, reason = "FFI: DuplicateHandle / GetCurrentProcess")]
    fn duplicate_broker_handle(&self) -> Result<HANDLE> {
        use windows::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
        use windows::Win32::System::Threading::GetCurrentProcess;

        let mut duplicated = HANDLE::default();
        // SAFETY: `GetCurrentProcess` takes no arguments and returns the
        // current-process pseudo-handle; there are no preconditions.
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: `process` is a valid (pseudo) process handle; `self.handle`
        // is a valid open volume handle owned by this `VolumeHandle`;
        // `&raw mut duplicated` is a valid out-pointer.  On success ownership
        // of `duplicated` transfers to the caller.
        let result = unsafe {
            DuplicateHandle(
                process,
                self.handle,
                process,
                &raw mut duplicated,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
        };
        result.map_err(|err| MftError::VolumeOpen {
            volume: self.volume,
            source: hresult_to_io_error(&err),
        })?;
        Ok(duplicated)
    }

    /// Opens a read handle to `X:\$MFT` for direct file-based MFT reading.
    ///
    /// This is used as a fallback on write-protected volumes where raw volume
    /// I/O (`\\.\X:`) fails with `ERROR_WRITE_PROTECT`.  Reading `$MFT` as a
    /// file works because the filesystem driver handles the VCN→LCN mapping
    /// internally.  Byte 0 of the returned handle corresponds to FRS 0.
    ///
    /// Automatically enables `SeBackupPrivilege` in the process token before
    /// opening — required for `FILE_FLAG_BACKUP_SEMANTICS` on NTFS metafiles.
    ///
    /// # Errors
    ///
    /// Returns `MftError::VolumeOpen` if `CreateFileW` fails.
    #[expect(unsafe_code, reason = "FFI: windows API (CreateFileW)")]
    pub(crate) fn open_mft_read_handle(&self) -> Result<HANDLE> {
        // Enable SeBackupPrivilege — required for $MFT access even as admin
        enable_backup_privilege();

        let volume = self.volume;
        let mft_path: Vec<u16> = format!("{volume}:\\$MFT")
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();

        // SAFETY: `mft_path` is UTF-16 and NUL-terminated for the duration of
        // the call, optional pointers are passed as `None`, and ownership of
        // any returned handle is transferred to the caller.
        let handle = unsafe {
            CreateFileW(
                PCWSTR::from_raw(mft_path.as_ptr()),
                FILE_READ_DATA | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN,
                None,
            )
        };

        handle.map_err(|err| MftError::VolumeOpen {
            volume,
            source: hresult_to_io_error(&err),
        })
    }

    /// Opens an unbuffered volume handle for direct I/O.
    ///
    /// On write-protected volumes the cache-manager path
    /// (`FILE_FLAG_SEQUENTIAL_SCAN`) fails with `ERROR_WRITE_PROTECT`.
    /// `FILE_FLAG_NO_BUFFERING` bypasses the cache manager entirely and
    /// issues I/O directly to the device driver, which only requires
    /// sector-aligned buffers and offsets (already guaranteed by
    /// [`AlignedBuffer`]).
    ///
    /// The caller is responsible for closing the returned handle.
    ///
    /// # Errors
    ///
    /// Returns `MftError::VolumeOpen` if `CreateFileW` fails.
    #[expect(unsafe_code, reason = "FFI: windows API (CreateFileW)")]
    pub(crate) fn open_unbuffered_handle(&self) -> Result<HANDLE> {
        let volume = self.volume;
        let volume_path: Vec<u16> = format!("\\\\.\\{volume}:")
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();

        // SAFETY: `volume_path` is UTF-16 and NUL-terminated for the duration
        // of the call, optional pointers are passed as `None`, and the
        // returned handle is transferred to the caller.
        let handle = unsafe {
            CreateFileW(
                PCWSTR::from_raw(volume_path.as_ptr()),
                FILE_READ_DATA | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_NO_BUFFERING,
                None,
            )
        };

        handle.map_err(|err| MftError::VolumeOpen {
            volume,
            source: hresult_to_io_error(&err),
        })
    }

    /// Returns the byte offset of the MFT on the volume.
    #[must_use]
    pub fn mft_byte_offset(&self) -> u64 {
        self.volume_data.mft_start_lcn * u64::from(self.volume_data.bytes_per_cluster)
    }

    /// Returns the size of a file record segment in bytes.
    #[must_use]
    pub const fn file_record_size(&self) -> u32 {
        self.volume_data.bytes_per_file_record_segment
    }

    /// Returns the estimated number of MFT records.
    #[must_use]
    pub(crate) fn estimated_record_count(&self) -> u64 {
        self.volume_data.mft_valid_data_length
            / u64::from(self.volume_data.bytes_per_file_record_segment)
    }

    /// Reads the boot sector from the volume.
    ///
    /// # Errors
    ///
    /// Returns [`MftError::Io`] if `SetFilePointerEx`/`ReadFile` on the
    /// volume handle fails, and [`MftError::InvalidData`] if the sector
    /// returns fewer bytes than `size_of::<NtfsBootSector>()` or decoding
    /// the boot-sector layout fails.
    #[expect(unsafe_code, reason = "FFI: windows API to read the boot sector")]
    pub fn read_boot_sector(&self) -> Result<NtfsBootSector> {
        use windows::Win32::Storage::FileSystem::{FILE_BEGIN, ReadFile, SetFilePointerEx};

        let mut new_position = 0_i64;
        // SAFETY: `self.handle` is a live volume handle and `new_position`
        // points to writable stack storage for the duration of the call.
        unsafe { SetFilePointerEx(self.handle, 0, Some(&raw mut new_position), FILE_BEGIN) }?;

        let mut buffer = [0_u8; 512];
        let mut bytes_read = 0_u32;

        // SAFETY: `self.handle` is a live volume handle, `buffer` is a writable
        // 512-byte stack array, and `bytes_read` is a valid out-parameter.
        unsafe {
            ReadFile(
                self.handle,
                Some(&mut buffer),
                Some(&raw mut bytes_read),
                None,
            )
        }?;

        if bytes_read != 512 {
            return Err(MftError::BootSectorRead(format!(
                "Expected 512 bytes, got {bytes_read}"
            )));
        }

        let Ok((boot_sector, _)) = NtfsBootSector::read_from_prefix(&buffer) else {
            return Err(MftError::InvalidBootSector(
                "Unable to decode NTFS boot sector layout".to_owned(),
            ));
        };

        if !boot_sector.is_valid() {
            return Err(MftError::InvalidBootSector(
                "Invalid OEM ID (not NTFS)".to_owned(),
            ));
        }

        Ok(boot_sector)
    }

    /// Gets the MFT extents (data runs) using `FSCTL_GET_RETRIEVAL_POINTERS`.
    ///
    /// # Errors
    ///
    /// Returns [`MftError::Io`] if `CreateFileW` on `\\.\<letter>:\$MFT`
    /// or `DeviceIoControl(FSCTL_GET_RETRIEVAL_POINTERS, ..)` fails.
    #[expect(
        unsafe_code,
        reason = "FFI: windows API (CreateFileW, DeviceIoControl, CloseHandle)"
    )]
    pub fn get_mft_extents(&self) -> Result<Vec<MftExtent>> {
        let mft_path: Vec<u16> = format!("{}:\\$MFT", self.volume)
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();

        // Fast path (elevated): open $MFT and ask the kernel for its retrieval
        // pointers.  A non-elevated daemon can't open $MFT at all, so this open
        // fails and we bootstrap the real layout from FRS 0 below.
        // SAFETY: `mft_path` is UTF-16 + NUL-terminated for the call; optional
        // pointers are `None`; any returned handle is wrapped in `HandleGuard`.
        if let Ok(mft_handle) = unsafe {
            CreateFileW(
                PCWSTR::from_raw(mft_path.as_ptr()),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        } {
            let _guard = HandleGuard(mft_handle);
            return get_retrieval_pointers(mft_handle);
        }

        // Non-elevated (broker-backed) path: `$MFT` can't be opened directly.
        // The old fallback was a SINGLE assumed-contiguous extent — silently
        // wrong on a fragmented MFT (it reads the wrong physical region past the
        // first fragment, producing a partial index).  Bootstrap the REAL
        // extents from FRS 0's `$DATA` runlist, read through our volume handle.
        Ok(self.mft_extents_from_frs0())
    }

    /// Bootstrap the MFT extent map from FRS 0 ($MFT's own record), read
    /// through the volume handle — the non-elevated / broker path where
    /// `$MFT` can't be opened for `FSCTL_GET_RETRIEVAL_POINTERS`.
    ///
    /// FRS 0 always lives at the start of the MFT ([`Self::mft_byte_offset`],
    /// the first fragment), and its non-resident `$DATA` runlist *is* the
    /// MFT's physical layout — so the extents it yields match what the
    /// kernel would return, fragmented or not.  Degrades **loudly** to the
    /// legacy single-contiguous assumption only if FRS 0 can't be read or
    /// parsed, so a non-elevated load still produces an index rather than
    /// failing outright.
    #[cfg(windows)]
    fn mft_extents_from_frs0(&self) -> Vec<MftExtent> {
        use crate::ntfs::{AttributeIterator, AttributeType};

        let record_size = self.volume_data.bytes_per_file_record_segment as usize;
        let mut record = vec![0_u8; record_size];
        if let Err(err) = read_handle_at(self.handle, self.mft_byte_offset(), &mut record) {
            tracing::warn!(
                drive = %self.volume, error = %err,
                "FRS 0 read failed; assuming single contiguous MFT extent (index may be partial on a fragmented MFT)"
            );
            return self.single_contiguous_extent();
        }
        crate::parse::apply_fixup(&mut record);

        let runs = AttributeIterator::new(&record)
            .and_then(|mut attrs| {
                attrs.find(|attr| {
                    attr.attribute_type() == Some(AttributeType::Data)
                        && attr.is_non_resident()
                        && attr.header.name_length == 0
                })
            })
            .map(|attr| attr.data_runs())
            .unwrap_or_default();
        let extents = super::extents::data_runs_to_extents(&runs);

        if extents.is_empty() {
            tracing::warn!(
                drive = %self.volume,
                "FRS 0 $DATA parse yielded no extents; assuming single contiguous MFT extent"
            );
            return self.single_contiguous_extent();
        }
        tracing::info!(
            drive = %self.volume, num_extents = extents.len(),
            "MFT extents bootstrapped from FRS 0 $DATA runlist (broker path)"
        );
        extents
    }

    /// The legacy single-contiguous MFT extent derived from `NTFS_VOLUME_DATA`,
    /// kept as the loud fallback for [`Self::mft_extents_from_frs0`].
    #[cfg(windows)]
    fn single_contiguous_extent(&self) -> Vec<MftExtent> {
        vec![MftExtent {
            vcn: 0,
            cluster_count: self.volume_data.mft_valid_data_length
                / u64::from(self.volume_data.bytes_per_cluster),
            lcn: super::Lcn::new(self.volume_data.mft_start_lcn.cast_signed()),
        }]
    }

    /// Gets the MFT bitmap which indicates which records are in use.
    ///
    /// # Errors
    ///
    /// Returns [`MftError::Io`] if opening `\\.\<letter>:\$MFT::$BITMAP`,
    /// seeking to its extents, or reading bitmap bytes via `ReadFile` fails.
    pub fn get_mft_bitmap(&self) -> Result<MftBitmap> {
        self.get_mft_bitmap_internal(false)
    }

    /// Gets the MFT bitmap with optional verbose diagnostic output.
    ///
    /// # Errors
    ///
    /// Same failure modes as [`Self::get_mft_bitmap`]; additionally emits
    /// diagnostic tracing for partial reads before falling back to an
    /// all-valid bitmap.
    pub fn get_mft_bitmap_verbose(&self) -> Result<MftBitmap> {
        self.get_mft_bitmap_internal(true)
    }

    /// Open `$MFT::$BITMAP` and read the entire bitmap stream into memory.
    ///
    /// `verbose` controls whether progress is logged at `info!` (caller-driven
    /// telemetry) or `trace!` (silent path).
    ///
    /// # Errors
    ///
    /// Returns [`MftError::Io`] if `CreateFileW`, `GetFileSizeEx`, or
    /// `ReadFile` fail, or if the bitmap is empty / mis-sized.
    #[expect(
        unsafe_code,
        reason = "FFI: windows API (CreateFileW, GetFileSizeEx, ReadFile)"
    )]
    #[expect(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "open + size + retrieval-pointers + per-extent read + verbose-logging branches form a single bitmap-load operation; splitting them adds plumbing without simplifying control flow"
    )]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "every failure branch returns `Ok(MftBitmap::new_all_valid(...))` (graceful fallback); the `Result<_>` signature documents the fallible Win32 call surface and aligns with `get_mft_bitmap` / `get_mft_bitmap_verbose` callers"
    )]
    fn get_mft_bitmap_internal(&self, verbose: bool) -> Result<MftBitmap> {
        use windows::Win32::Storage::FileSystem::{
            FILE_BEGIN, GetFileSizeEx, ReadFile, SYNCHRONIZE, SetFilePointerEx,
        };

        let bitmap_path_str = format!("{}:\\$MFT::$BITMAP", self.volume);
        let bitmap_path: Vec<u16> = bitmap_path_str
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();

        if verbose {
            tracing::info!(volume = %self.volume, bitmap_path = %bitmap_path_str, "Opening MFT bitmap");
        }

        // SAFETY: `bitmap_path` is UTF-16 and NUL-terminated for the duration of
        // the call, optional pointers are `None`, and any returned handle is
        // wrapped in `HandleGuard` before use.
        let bitmap_handle = match unsafe {
            CreateFileW(
                PCWSTR::from_raw(bitmap_path.as_ptr()),
                FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_NO_BUFFERING,
                None,
            )
        } {
            Ok(handle) => {
                if verbose {
                    tracing::info!(volume = %self.volume, handle = ?handle, "CreateFileW for MFT bitmap succeeded");
                }
                handle
            }
            Err(err) => {
                if verbose {
                    tracing::warn!(
                        volume = %self.volume,
                        error = ?err,
                        "CreateFileW for MFT bitmap failed; falling back to all-valid bitmap"
                    );
                }
                return Ok(MftBitmap::new_all_valid(frs_to_usize(
                    self.estimated_record_count(),
                )));
            }
        };

        let _guard = HandleGuard(bitmap_handle);

        let mut file_size: i64 = 0;
        // SAFETY: `bitmap_handle` is a live file handle and `file_size` points
        // to writable stack storage for the duration of the call.
        unsafe {
            if let Err(err) = GetFileSizeEx(bitmap_handle, &raw mut file_size) {
                if verbose {
                    tracing::warn!(
                        volume = %self.volume,
                        error = ?err,
                        "GetFileSizeEx for MFT bitmap failed; falling back to all-valid bitmap"
                    );
                }
                return Ok(MftBitmap::new_all_valid(frs_to_usize(
                    self.estimated_record_count(),
                )));
            }
        }

        if verbose {
            tracing::info!(volume = %self.volume, file_size, "Retrieved MFT bitmap size");
        }

        let extents = match get_retrieval_pointers(bitmap_handle) {
            Ok(extents) if !extents.is_empty() => {
                if verbose {
                    tracing::info!(volume = %self.volume, extent_count = extents.len(), "Retrieved MFT bitmap extents");
                    for (i, ext) in extents.iter().enumerate().take(5) {
                        tracing::info!(
                            volume = %self.volume,
                            extent_index = i,
                            vcn = ext.vcn,
                            cluster_count = ext.cluster_count,
                            lcn = %ext.lcn,
                            "MFT bitmap extent sample"
                        );
                    }
                    if extents.len() > 5 {
                        tracing::info!(
                            volume = %self.volume,
                            additional_extent_count = extents.len() - 5,
                            "Additional MFT bitmap extents omitted from verbose sample"
                        );
                    }
                }
                extents
            }
            Ok(_) => {
                if verbose {
                    tracing::warn!(
                        volume = %self.volume,
                        "get_retrieval_pointers returned no MFT bitmap extents; falling back to all-valid bitmap"
                    );
                }
                return Ok(MftBitmap::new_all_valid(frs_to_usize(
                    self.estimated_record_count(),
                )));
            }
            Err(err) => {
                if verbose {
                    tracing::warn!(
                        volume = %self.volume,
                        error = ?err,
                        "get_retrieval_pointers for MFT bitmap failed; falling back to all-valid bitmap"
                    );
                }
                return Ok(MftBitmap::new_all_valid(frs_to_usize(
                    self.estimated_record_count(),
                )));
            }
        };

        let bytes_per_cluster = self.volume_data.bytes_per_cluster;
        let total_clusters: u64 = extents.iter().map(|ext| ext.cluster_count).sum();
        let aligned_size = frs_to_usize(total_clusters * u64::from(bytes_per_cluster));
        let mut buffer = vec![0_u8; aligned_size];
        let mut buffer_offset = 0_usize;

        if verbose {
            tracing::info!(
                volume = %self.volume,
                bytes_per_cluster,
                file_size,
                aligned_size,
                "Reading MFT bitmap extents from volume"
            );
        }

        for (i, extent) in extents.iter().enumerate() {
            let byte_offset = extent.lcn.raw() * i64::from(bytes_per_cluster);
            let extent_bytes = frs_to_usize(extent.cluster_count * u64::from(bytes_per_cluster));

            if extent_bytes == 0 {
                continue;
            }

            if verbose && i < 3 {
                tracing::info!(
                    volume = %self.volume,
                    extent_index = i,
                    byte_offset,
                    extent_bytes,
                    "Reading MFT bitmap extent"
                );
            }

            let mut new_position = 0_i64;
            // SAFETY: `self.handle` is a live volume handle and `new_position`
            // is valid writable storage for the duration of the seek call.
            unsafe {
                if let Err(err) = SetFilePointerEx(
                    self.handle,
                    byte_offset,
                    Some(&raw mut new_position),
                    FILE_BEGIN,
                ) {
                    if verbose {
                        tracing::warn!(
                            volume = %self.volume,
                            extent_index = i,
                            byte_offset,
                            error = ?err,
                            "SetFilePointerEx for MFT bitmap extent failed; falling back to all-valid bitmap"
                        );
                    }
                    return Ok(MftBitmap::new_all_valid(frs_to_usize(
                        self.estimated_record_count(),
                    )));
                }
            }

            let mut bytes_read: u32 = 0;
            let Some(extent_window) = buffer.get_mut(buffer_offset..buffer_offset + extent_bytes)
            else {
                if verbose {
                    tracing::warn!(
                        volume = %self.volume,
                        extent_index = i,
                        buffer_offset,
                        extent_bytes,
                        buffer_len = buffer.len(),
                        "MFT bitmap extent exceeds buffer size; falling back to all-valid bitmap"
                    );
                }
                return Ok(MftBitmap::new_all_valid(frs_to_usize(
                    self.estimated_record_count(),
                )));
            };
            // SAFETY: `self.handle` is a live volume handle, the slice points to
            // a contiguous writable region of `extent_bytes`, and `bytes_read`
            // is a valid out-parameter for the duration of the read.
            unsafe {
                if let Err(err) = ReadFile(
                    self.handle,
                    Some(extent_window),
                    Some(&raw mut bytes_read),
                    None,
                ) {
                    if verbose {
                        tracing::warn!(
                            volume = %self.volume,
                            extent_index = i,
                            extent_bytes,
                            error = ?err,
                            "ReadFile for MFT bitmap extent failed; falling back to all-valid bitmap"
                        );
                    }
                    return Ok(MftBitmap::new_all_valid(frs_to_usize(
                        self.estimated_record_count(),
                    )));
                }
            }

            if verbose && i < 3 {
                tracing::info!(volume = %self.volume, extent_index = i, bytes_read, "Read MFT bitmap extent bytes");
                if i == 0 && bytes_read > 0 {
                    let sample_end = buffer_offset + 32.min(u32_as_usize(bytes_read));
                    let sample: Vec<String> = buffer
                        .get(buffer_offset..sample_end)
                        .unwrap_or(&[])
                        .iter()
                        .map(|byte| format!("{byte:02X}"))
                        .collect();
                    tracing::info!(
                        volume = %self.volume,
                        extent_index = i,
                        sample_hex = %sample.join(" "),
                        "MFT bitmap first-byte sample"
                    );
                }
            }

            buffer_offset += u32_as_usize(bytes_read);
        }

        if verbose {
            tracing::info!(
                volume = %self.volume,
                total_bytes_read = buffer_offset,
                file_size,
                "Completed MFT bitmap read; truncating to reported file size"
            );
            let file_size_usize = usize::try_from(file_size).unwrap_or(0);
            let all_ff = buffer
                .iter()
                .take(file_size_usize)
                .all(|&byte| byte == 0xFF);
            let all_00 = buffer
                .iter()
                .take(file_size_usize)
                .all(|&byte| byte == 0x00);
            tracing::info!(volume = %self.volume, all_ff, all_00, "Computed MFT bitmap byte-pattern summary");
        }

        buffer.truncate(usize::try_from(file_size).unwrap_or(0));
        Ok(MftBitmap::from_bytes(buffer))
    }
}

impl Drop for VolumeHandle {
    #[expect(unsafe_code, reason = "FFI: windows API (CloseHandle)")]
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: `VolumeHandle` owns this valid handle and closes it once
            // during drop after all safe borrows have ended.
            _ = unsafe { CloseHandle(self.handle) };
        }
    }
}

/// RAII guard for Windows handles.
pub(super) struct HandleGuard(pub(super) HANDLE);

impl Drop for HandleGuard {
    #[expect(unsafe_code, reason = "FFI: windows API (CloseHandle)")]
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `HandleGuard` exclusively owns this valid handle and drops
            // it exactly once when the guard is destroyed.
            _ = unsafe { CloseHandle(self.0) };
        }
    }
}

/// Enables `SeBackupPrivilege` in the current process token.
///
/// `FILE_FLAG_BACKUP_SEMANTICS` only bypasses NTFS security checks when the
/// calling thread's token has `SeBackupPrivilege` **enabled** (not just
/// present).  Administrator tokens include it but it's disabled by default.
///
/// This is required to open `$MFT` for reading on write-protected volumes.
/// The privilege is process-wide and persists for the lifetime of the process,
/// so calling this multiple times is harmless.
fn enable_backup_privilege() {
    let Some(token) = open_current_process_token() else {
        return;
    };
    let Some(luid) = lookup_backup_privilege_luid() else {
        unsafe_close_token(token);
        return;
    };

    enable_privilege_with_token(token, luid);
}

/// Open the current process's token with `TOKEN_ADJUST_PRIVILEGES` rights.
///
/// Returns `None` (and logs a debug line) when the underlying Win32 call
/// fails — the only legitimate cause is non-elevated callers, which is
/// expected for the `MftReader::new` fast path.
#[expect(unsafe_code, reason = "FFI: GetCurrentProcess + OpenProcessToken")]
fn open_current_process_token() -> Option<HANDLE> {
    use windows::Win32::Security::TOKEN_ADJUST_PRIVILEGES;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    // SAFETY: `GetCurrentProcess()` returns a constant pseudo-handle and has
    // no preconditions.
    let current_process = unsafe { GetCurrentProcess() };
    // SAFETY: `current_process` is a valid pseudo-handle and `token` is
    // valid writable stack storage for the call duration.
    if unsafe { OpenProcessToken(current_process, TOKEN_ADJUST_PRIVILEGES, &raw mut token) }
        .is_err()
    {
        tracing::debug!("Could not open process token for privilege adjustment");
        return None;
    }
    Some(token)
}

/// Look up the LUID for `SeBackupPrivilege`.  Returns `None` when the call
/// fails (extremely rare; would indicate a missing privilege constant).
#[expect(
    unsafe_code,
    reason = "FFI: LookupPrivilegeValueW with caller-owned LUID storage"
)]
fn lookup_backup_privilege_luid() -> Option<windows::Win32::Foundation::LUID> {
    use windows::Win32::Foundation::LUID;
    use windows::Win32::Security::{LookupPrivilegeValueW, SE_BACKUP_NAME};

    let mut luid = LUID::default();
    // SAFETY: `SE_BACKUP_NAME` is a static wide string constant and `luid`
    // is valid writable stack storage for the call duration.
    if unsafe { LookupPrivilegeValueW(None, SE_BACKUP_NAME, &raw mut luid) }.is_err() {
        tracing::debug!("Could not look up SeBackupPrivilege LUID");
        return None;
    }
    Some(luid)
}

/// Adjust `token` so `luid` is enabled, then close `token`.  Logs the
/// outcome at info / debug level — this function is best-effort and never
/// returns an error to the caller.
#[expect(unsafe_code, reason = "FFI: AdjustTokenPrivileges + CloseHandle")]
fn enable_privilege_with_token(token: HANDLE, luid: windows::Win32::Foundation::LUID) {
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES,
    };

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // SAFETY: `token` was opened with `TOKEN_ADJUST_PRIVILEGES`, `tp` is a
    // valid `TOKEN_PRIVILEGES` struct, and no previous-state buffer is
    // requested.
    let result = unsafe { AdjustTokenPrivileges(token, false, Some(&raw const tp), 0, None, None) };

    // SAFETY: `token` was opened by the caller and is closed exactly once.
    _ = unsafe { CloseHandle(token) };

    match result {
        Ok(()) => tracing::info!("✅ SeBackupPrivilege enabled"),
        Err(err) => tracing::debug!(error = %err, "Could not enable SeBackupPrivilege"),
    }
}

/// Close a privilege-helper token, logging but not propagating any failure.
#[expect(
    unsafe_code,
    reason = "FFI: CloseHandle on a token opened by open_current_process_token"
)]
fn unsafe_close_token(token: HANDLE) {
    // SAFETY: caller passes a token returned from
    // `open_current_process_token` that has not yet been closed.
    _ = unsafe { CloseHandle(token) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_wait_error_maps_aborted_waits_to_cancelled() {
        let error = classify_wait_error_code("read_all_index", 995, "wait aborted");

        assert!(matches!(error, MftError::Cancelled {
            operation: "read_all_index",
            ..
        }));
    }

    #[test]
    fn classify_wait_error_maps_other_wait_failures_to_wait_failed() {
        let error = classify_wait_error_code("read_all_index", 123, "wait failed");

        assert!(matches!(error, MftError::WaitFailed {
            operation: "read_all_index",
            ..
        }));
    }

    #[test]
    fn wait_deadline_helper_builds_timeout_error() {
        let error = wait_deadline_exceeded(
            "read_all_index",
            Duration::from_secs(31),
            "no completions arrived",
        );

        assert!(matches!(error, MftError::Timeout {
            operation: "read_all_index",
            ..
        }));
    }

    // ── hresult_to_io_error regression tests ─────────────────────────────
    //
    // These pin the documented `RuntimeDir::create_owner_only`-style
    // contract that PR #273 introduced workspace-wide: any
    // `windows::core::Error` carrying a `FACILITY_WIN32` HRESULT must
    // surface its bare Win32 code through `io::Error` so std's
    // `decode_error_kind` table resolves the canonical `ErrorKind`.
    //
    // Without these tests the same latent bug PR #273 fixed could
    // silently regress at any of the four `CreateFileW` call sites in
    // this file the next time a refactor touches them.
    use windows::core::{Error as WinError, HRESULT};

    /// Build a `windows::core::Error` carrying an explicit HRESULT bit
    /// pattern.  The constructor takes an `HRESULT`, which wraps an
    /// `i32`; `u32::cast_signed` is the stable 1.87 exact-bit-pattern
    /// converter that matches the rest of this file's HRESULT-handling
    /// idiom (see `code_unsigned` at `VolumeHandle::open`).
    fn synthesize_error(hresult_bits: u32) -> WinError {
        WinError::from_hresult(HRESULT(hresult_bits.cast_signed()))
    }

    #[test]
    fn hresult_to_io_error_unwraps_file_exists_to_already_exists() {
        // `HRESULT_FROM_WIN32(ERROR_FILE_EXISTS = 80)`.
        let err = synthesize_error(0x8007_0050);
        let io_err = hresult_to_io_error(&err);

        assert_eq!(
            io_err.kind(),
            std::io::ErrorKind::AlreadyExists,
            "FACILITY_WIN32 envelope for ERROR_FILE_EXISTS must map to AlreadyExists",
        );
        assert_eq!(
            io_err.raw_os_error(),
            Some(80_i32),
            "raw_os_error must report the bare Win32 code (80), not the HRESULT",
        );
    }

    #[test]
    fn hresult_to_io_error_unwraps_access_denied_to_permission_denied() {
        // `HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED = 5)`.
        let err = synthesize_error(0x8007_0005);
        let io_err = hresult_to_io_error(&err);

        assert_eq!(
            io_err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "FACILITY_WIN32 envelope for ERROR_ACCESS_DENIED must map to PermissionDenied",
        );
        assert_eq!(io_err.raw_os_error(), Some(5_i32));
    }

    #[test]
    fn hresult_to_io_error_passes_through_non_win32_hresults() {
        // `E_NOINTERFACE = 0x8000_4002` — FACILITY_NULL (0), severity 1.
        // No portable Win32 code lives in here; the helper must leave
        // the bit pattern intact so std at least preserves the raw
        // value.
        let bits = 0x8000_4002_u32;
        let err = synthesize_error(bits);
        let io_err = hresult_to_io_error(&err);

        assert_eq!(
            io_err.raw_os_error(),
            Some(bits.cast_signed()),
            "non-WIN32 HRESULT must be forwarded verbatim",
        );
    }
}
