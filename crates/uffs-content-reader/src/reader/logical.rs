// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Stage A: the logical reader (`uffs-ingest-implementation-plan.md`
//! §5.1).
//!
//! Opens the target file directly against the snapshot device by its
//! NTFS file reference (`OpenFileById`) — no path resolution needed, no
//! `uffs-mft` dependency. Re-resolves `EOF` from the freshly opened
//! handle, applies the VDL/EOF zero-synthesis rule
//! ([`super::read_plan::read_plan`]), and reads real bytes via
//! `ReadFile` at the requested offset.
//!
//! # Handle caching across a connection's consecutive requests
//!
//! `open_file_by_id` is not cheap: `OpenFileById` has to resolve/validate
//! the target FRS against the MFT, and against a VSS snapshot's
//! copy-on-write device that cost varies a lot request to request.
//! Real-hardware benchmarking found this dominating read time on large
//! files far more than actual disk throughput did — a 2.76 GB file at
//! the old 64 KiB chunk size needed roughly 42,000 full open/close
//! cycles, one per chunk. [`ReadHandleCache`] lets [`read_logical`] reuse
//! the same open file handle across consecutive requests for the same
//! `full_file_reference`, opening fresh only when the target file
//! actually changes. The caller (`pipe_server`) owns one cache per
//! connection and threads it through every request on that connection —
//! this only pays off because the Coordinator now pins one connection
//! per candidate's whole sequential read (see
//! `uffs-content::job::reader_client`'s module doc) rather than
//! round-robining a chunk at a time across the pool.
//!
//! [`ReadHandleCache`] also caches [`open_volume_hint`]'s handle,
//! independent of which file is currently being read: real-hardware
//! benchmarking against small-file-heavy drives (thousands of tiny
//! `.txt`/driver-readme files, each its own candidate) found this handle
//! was being opened and closed **fresh for every single candidate**,
//! even though it only identifies the *volume* — never the file — and
//! every candidate on one connection is read from the same volume (one
//! connection is only ever drawn from one lease's pool, so `device_path`
//! never actually changes mid-connection). Caching it removes one whole
//! `CreateFileW`+`CloseHandle` cycle per candidate at no correctness
//! cost, on top of the file-handle caching above.
//!
//! # Trusting a caller-supplied size (opt-in per request)
//!
//! [`read_logical`]'s `known_logical_size` parameter, when `Some`, skips
//! the `GetFileSizeEx` re-resolution on a cache miss entirely and uses
//! the caller's value as `EOF` directly — real-hardware benchmarking
//! against small-file-heavy drives found `GetFileSizeEx` a real fraction
//! of per-candidate time even after the caching above. This is a genuine
//! (if rare) trust tradeoff: the value could theoretically be stale, so
//! it is opt-in per request via `ReadRequest::known_logical_size`, never
//! a blanket change to this function's own default behavior. Only the
//! real Coordinator populates it (`VssCandidateSource`'s manifest size
//! comes from parsing the exact same frozen snapshot this read targets,
//! so the two should always agree); any request that leaves it `None`
//! gets the original always-re-verify behavior with no code changes
//! required on the caller's part.
//!
//! # v1 simplifications (documented, not silent)
//!
//! - **VDL is treated as equal to EOF.** Getting the true NTFS valid data
//!   length requires undocumented/internal APIs; treating it as EOF is correct
//!   for the overwhelming majority of files — only a sparse-tail file extended
//!   via `SetFileValidData`/`SetEndOfFile` without writing has `vdl < eof`.
//!   Revisit if that edge case matters in practice.
//! - **No identity revalidation against the snapshot's own MFT.**
//!   `OpenFileById` inherently defends against the classic "FRS reused by a
//!   different file" attack — the encoded sequence number (high 16 bits of
//!   `full_file_reference`) must match the live file's, or the open fails
//!   outright. The deeper `identity.rs` piece from the design doc (re-parsing
//!   the MFT record to cross-check size/ attributes after open) is deferred.
//! - **No Broker-mediated lease/volume cross-validation.** The Reader trusts
//!   the Coordinator's `snapshot_device_identity` string as-is; only the
//!   Coordinator's own successful VSS lease (validated by the Broker) gated
//!   whether that string was ever handed out at all.

use core::mem::size_of;
use core::time::Duration;
use std::os::windows::ffi::OsStrExt as _;
use std::time::Instant;

use uffs_content_reader_protocol::ActualReadMode;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_BEGIN, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_ID_DESCRIPTOR,
    FILE_ID_DESCRIPTOR_0, FILE_ID_TYPE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileSizeEx, OPEN_EXISTING, OpenFileById, ReadFile, SetFilePointerEx,
};
use windows::core::PCWSTR;

use super::read_plan::read_plan;

/// `FileIdType` (the classic 64-bit NTFS file ID variant) — matches
/// `uffs-core::compact::CompactRecord::file_ref`'s
/// `(sequence_number << 48) | frs` encoding, which is exactly the shape
/// `OpenFileById` expects for this discriminant.
const FILE_ID_TYPE_CLASSIC: FILE_ID_TYPE = FILE_ID_TYPE(0);

/// RAII wrapper closing a raw `HANDLE` on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        #[expect(
            unsafe_code,
            reason = "CloseHandle is an FFI call; `self.0` is always a valid, \
                      owned handle this module opened"
        )]
        // SAFETY: `self.0` was returned by a successful `CreateFileW` or
        // `OpenFileById` call in this module and is closed at most once
        // (ownership is exclusive to this struct).
        unsafe {
            drop(CloseHandle(self.0));
        }
    }
}

#[expect(
    unsafe_code,
    reason = "windows file handles are thread-safe kernel objects, not thread-affine"
)]
// SAFETY: `OwnedHandle` owns a Windows `HANDLE` to a kernel-managed file
// object with no thread affinity and no unsynchronized interior
// mutability of its own — moving ownership to another thread (as
// `ReadHandleCache` does across a `spawn_blocking` boundary in
// `pipe_server`) does not invalidate any aliasing assumptions. Handle
// cleanup remains centralized in `Drop`, above.
unsafe impl Send for OwnedHandle {}

/// A previously-opened file handle, cached across a connection's
/// consecutive requests — see this module's doc comment for why.
/// `pub(crate)` (rather than living entirely inside this module) because
/// `pipe_server` owns one instance per connection and threads it through
/// every request on that connection, across a `spawn_blocking` boundary.
///
/// Also caches the [`open_volume_hint`] handle used to resolve
/// `OpenFileById` calls, independent of which file is being read —
/// real-hardware benchmarking against small-file-heavy drives (drives
/// dominated by tiny `.txt`/driver-readme files) found this handle was
/// being opened and closed **fresh for every single candidate**, even
/// though it identifies only the *volume*, not the file, and every
/// candidate on one connection is read from the same volume. Caching it
/// removes one whole `CreateFileW`+`CloseHandle` cycle per candidate
/// with no correctness cost.
#[derive(Default)]
pub(crate) struct ReadHandleCache {
    /// The cached open file handle, if any — see [`CachedFileHandle`].
    file: Option<CachedFileHandle>,
    /// The cached volume-hint handle, if any — see [`CachedVolumeHint`].
    volume_hint: Option<CachedVolumeHint>,
}

impl ReadHandleCache {
    /// A fresh cache holding nothing — one per new connection.
    pub(crate) const fn empty() -> Self {
        Self {
            file: None,
            volume_hint: None,
        }
    }
}

/// One cached open file handle plus the file reference and `EOF` it was
/// opened/resolved for — [`read_logical`] reuses it only when a new
/// request's `full_file_reference` matches exactly.
struct CachedFileHandle {
    /// The file reference this handle was opened against.
    full_file_reference: u64,
    /// The open handle itself.
    handle: OwnedHandle,
    /// `EOF` as resolved when this handle was opened. Deliberately not
    /// re-queried on every cached-hit read: the file is being read
    /// against a frozen VSS snapshot, not the live volume, so its size
    /// cannot legitimately change for the life of that snapshot — a
    /// changed `EOF` on a subsequent query would indicate something has
    /// gone wrong (a corrupted snapshot, a bug), not a real update to
    /// react to.
    eof: u64,
}

/// One cached [`open_volume_hint`] handle plus the `device_path` it was
/// opened against — [`read_logical`] reuses it for every candidate on
/// this connection, only reopening if `device_path` ever actually
/// changes (never happens in practice, since one physical connection is
/// only ever drawn from one lease's pool — see
/// `uffs-content::job::reader_client`'s module doc — but checking rather
/// than assuming keeps this correct even if that ever changed).
struct CachedVolumeHint {
    /// The device path this handle was opened against.
    device_path: String,
    /// The open handle itself.
    handle: OwnedHandle,
}

/// Encode `text` as a NUL-terminated UTF-16 buffer for `PCWSTR` FFI calls.
fn to_wide_null(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(core::iter::once(0))
        .collect()
}

/// Open a handle to the snapshot device's volume root — used only as
/// `OpenFileById`'s volume hint. The file handle `OpenFileById` returns
/// is entirely independent of this one once opened, so the caller is
/// free to keep this handle around and reuse it across many
/// `OpenFileById` calls rather than reopening it per file — see
/// [`CachedVolumeHint`].
fn open_volume_hint(device_path: &str) -> anyhow::Result<OwnedHandle> {
    let wide = to_wide_null(device_path);
    #[expect(
        unsafe_code,
        reason = "CreateFileW is an FFI call opening the snapshot volume root"
    )]
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer kept alive for the
    // duration of the call; no other pointer arguments are passed.
    let result = unsafe {
        CreateFileW(
            PCWSTR::from_raw(wide.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    };
    let handle = result.map_err(|err| {
        anyhow::anyhow!("failed to open snapshot volume root {device_path}: {err}")
    })?;
    Ok(OwnedHandle(handle))
}

/// Open the target file directly by its 64-bit NTFS file reference,
/// using `volume_hint` to identify which volume it lives on.
fn open_file_by_id(
    volume_hint: &OwnedHandle,
    full_file_reference: u64,
) -> anyhow::Result<OwnedHandle> {
    let descriptor = FILE_ID_DESCRIPTOR {
        dwSize: u32::try_from(size_of::<FILE_ID_DESCRIPTOR>()).unwrap_or(u32::MAX),
        Type: FILE_ID_TYPE_CLASSIC,
        Anonymous: FILE_ID_DESCRIPTOR_0 {
            // NTFS classic file IDs are a bit-pattern reinterpretation,
            // not a numeric value — `cast_signed` preserves every bit.
            FileId: full_file_reference.cast_signed(),
        },
    };
    #[expect(
        unsafe_code,
        reason = "OpenFileById is an FFI call; `descriptor` is a valid, \
                  fully-initialized FILE_ID_DESCRIPTOR for its lifetime"
    )]
    // SAFETY: `volume_hint.0` is a valid open handle on the target
    // volume; `descriptor` is `#[repr(C)]`, matches the classic 64-bit
    // `FileId` union arm the `Type` field selects, and lives until the
    // call returns.
    let result = unsafe {
        OpenFileById(
            volume_hint.0,
            &raw const descriptor,
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    };
    let handle = result.map_err(|err| {
        anyhow::anyhow!("failed to open file by id {full_file_reference:#018x}: {err}")
    })?;
    Ok(OwnedHandle(handle))
}

/// Query a handle's current size (this call's own re-resolution of
/// `EOF` — never trusted from manifest metadata, per §5.1 point 2).
fn file_size(handle: &OwnedHandle) -> anyhow::Result<u64> {
    let mut size: i64 = 0;
    #[expect(unsafe_code, reason = "GetFileSizeEx is an FFI call")]
    // SAFETY: `handle.0` is a valid open file handle; `size` is a valid
    // `&mut i64` for the duration of the call.
    let result = unsafe { GetFileSizeEx(handle.0, &raw mut size) };
    result.map_err(|err| anyhow::anyhow!("GetFileSizeEx failed: {err}"))?;
    Ok(size.cast_unsigned())
}

/// Move the handle's file pointer to `offset` from the start of the file.
fn seek(handle: &OwnedHandle, offset: u64) -> anyhow::Result<()> {
    #[expect(unsafe_code, reason = "SetFilePointerEx is an FFI call")]
    // SAFETY: `handle.0` is a valid open file handle; no output pointer
    // is requested.
    let result = unsafe { SetFilePointerEx(handle.0, offset.cast_signed(), None, FILE_BEGIN) };
    result.map_err(|err| anyhow::anyhow!("SetFilePointerEx failed: {err}"))
}

/// Read exactly `buf.len()` bytes from the handle's current position.
fn read_exact(handle: &OwnedHandle, buf: &mut [u8]) -> anyhow::Result<()> {
    let mut total_read: u32 = 0;
    while (total_read as usize) < buf.len() {
        let mut bytes_read: u32 = 0;
        let dest = buf
            .get_mut(total_read as usize..)
            .ok_or_else(|| anyhow::anyhow!("read_exact: buffer index out of bounds"))?;
        #[expect(unsafe_code, reason = "ReadFile is an FFI call")]
        // SAFETY: `handle.0` is a valid open file handle; `dest` is a
        // valid, exclusively-borrowed byte slice for the call's
        // duration; no overlapped I/O is requested.
        let result = unsafe { ReadFile(handle.0, Some(dest), Some(&raw mut bytes_read), None) };
        result.map_err(|err| anyhow::anyhow!("ReadFile failed: {err}"))?;
        if bytes_read == 0 {
            anyhow::bail!("ReadFile returned 0 bytes before the requested range was satisfied");
        }
        total_read += bytes_read;
    }
    Ok(())
}

/// Perform one logical read: reuse `cache`'s open handle if it's already
/// open against `full_file_reference` (see this module's doc comment),
/// else open fresh by file reference and resolve `EOF` — trusting
/// `known_logical_size` directly if `Some`, else re-querying via
/// `GetFileSizeEx` (see the "Trusting a caller-supplied size" doc
/// section for the tradeoff); apply the VDL/EOF rule, and read the
/// resulting real-byte range (zero-extending per the plan).
///
/// Returns the (possibly newly-opened) handle back as an updated
/// [`ReadHandleCache`] for the caller to reuse on its next call — on
/// success this always holds `Some`, even when nothing changed, so the
/// caller never has to special-case "cache unchanged" against "cache
/// now empty".
///
/// # Errors
/// Returns an error if the device/file can't be opened, the read fails,
/// or the resolved metadata is invalid (`vdl > eof` — never possible
/// here since VDL is derived from EOF, but `read_plan`'s contract keeps
/// that check in one place regardless of caller). The returned error
/// carries no cache — the caller must treat the connection's cache as
/// empty afterward, matching how a round-trip failure already discards
/// the connection itself one level up.
pub(crate) fn read_logical(
    device_path: &str,
    full_file_reference: u64,
    known_logical_size: Option<u64>,
    logical_offset: u64,
    maximum_logical_length: u32,
    cache: ReadHandleCache,
) -> anyhow::Result<(Vec<u8>, ActualReadMode, ReadHandleCache)> {
    let call_started_at = Instant::now();
    let cache_hit = matches!(
        &cache.file,
        Some(cached) if cached.full_file_reference == full_file_reference
    );

    let mut open_volume_hint_time = Duration::ZERO;
    let volume_hint = match cache.volume_hint {
        Some(cached) if cached.device_path == device_path => cached,
        _ => {
            let volume_hint_started_at = Instant::now();
            let handle = open_volume_hint(device_path)?;
            open_volume_hint_time = volume_hint_started_at.elapsed();
            CachedVolumeHint {
                device_path: device_path.to_owned(),
                handle,
            }
        }
    };

    let mut open_file_by_id_time = Duration::ZERO;
    let mut file_size_time = Duration::ZERO;
    let mut trusted_known_size = false;
    let (file_handle, eof) = match cache.file {
        Some(cached) if cached.full_file_reference == full_file_reference => {
            (cached.handle, cached.eof)
        }
        _ => {
            let open_by_id_started_at = Instant::now();
            let file_handle = open_file_by_id(&volume_hint.handle, full_file_reference)?;
            open_file_by_id_time = open_by_id_started_at.elapsed();

            let eof = if let Some(size) = known_logical_size {
                trusted_known_size = true;
                size
            } else {
                let file_size_started_at = Instant::now();
                let eof = file_size(&file_handle)?;
                file_size_time = file_size_started_at.elapsed();
                eof
            };

            (file_handle, eof)
        }
    };
    let vdl = eof; // v1 simplification — see module doc.

    let plan = read_plan(vdl, eof, logical_offset, maximum_logical_length)
        .map_err(|err| anyhow::anyhow!("{err}"))?;

    let mut payload = Vec::with_capacity(plan.total_len() as usize);
    let read_started_at = Instant::now();
    if plan.real_bytes > 0 {
        seek(&file_handle, logical_offset)?;
        let mut real_buf = vec![0_u8; plan.real_bytes as usize];
        read_exact(&file_handle, &mut real_buf)?;
        payload.extend_from_slice(&real_buf);
    }
    let read_time = read_started_at.elapsed();
    payload.resize(payload.len() + plan.zero_bytes as usize, 0);

    // PROFILING (temporary — see the "confirm the per-file open/close
    // overhead theory" investigation): one structured line per call,
    // broken down by phase, so a real run's log can be aggregated
    // (`grep 'read_logical: per-phase timing'` + average each field) to
    // see whether open/close overhead or actual disk I/O dominates total
    // read time for a given drive's workload.
    tracing::debug!(
        cache_hit,
        trusted_known_size,
        real_bytes = plan.real_bytes,
        open_volume_hint_us = duration_micros(open_volume_hint_time),
        open_file_by_id_us = duration_micros(open_file_by_id_time),
        file_size_us = duration_micros(file_size_time),
        read_us = duration_micros(read_time),
        total_us = duration_micros(call_started_at.elapsed()),
        "read_logical: per-phase timing"
    );

    let updated_cache = ReadHandleCache {
        file: Some(CachedFileHandle {
            full_file_reference,
            handle: file_handle,
            eof,
        }),
        volume_hint: Some(volume_hint),
    };

    Ok((payload, ActualReadMode::Logical, updated_cache))
}

/// Converts `duration` to whole microseconds, saturating instead of
/// panicking — only used for diagnostic log fields, where a saturated
/// value is still obviously "very large" rather than a silent wrap.
fn duration_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}
