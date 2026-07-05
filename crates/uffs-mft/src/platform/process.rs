// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Native Windows process introspection for the self-update detector.
//!
//! Exposes a pid's full image path and enumeration of pids by image file
//! name.
//!
//! Lives here (not in `uffs-cli`) so the `unsafe` Win32 FFI stays in the
//! crate that already owns it; `uffs-cli` calls the safe wrappers and
//! stays `unsafe`-free. Replaces the earlier PowerShell `Get-CimInstance`
//! shell-out (EDR-noisy, lockdown-fragile, slow) with documented Win32
//! calls. Uses only already-enabled `windows`-crate features
//! (`Win32_System_Threading` + `Win32_System_ProcessStatus`).

#![cfg(windows)]

use std::os::windows::ffi::OsStringExt as _;
use std::path::PathBuf;

use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::System::ProcessStatus::EnumProcesses;
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

/// Buffer size (in UTF-16 code units) for an extended-length image path.
const PATH_CAP: usize = 32_768;

/// 100-nanosecond intervals between the Windows epoch (1601-01-01) and the
/// Unix epoch (1970-01-01) — the offset that converts a `FILETIME` tick count
/// into a `SystemTime`.
const WINDOWS_TO_UNIX_100NS: u64 = 11_644_473_600 * 10_000_000;

/// Number of 100-ns `FILETIME` ticks per second.
const FILETIME_TICKS_PER_SEC: u64 = 10_000_000;

/// Resolve a process's full image path from its pid, or `None` if the
/// process cannot be opened (e.g. exited, or access denied).
#[must_use]
pub fn process_image_path(pid: u32) -> Option<PathBuf> {
    let handle = open_for_query(pid)?;
    let result = image_path_of(handle);
    close_handle(handle);
    result
}

/// Wall-clock time a process was created, or `None` if it cannot be queried
/// (exited, access denied, or a `FILETIME` predating the Unix epoch).
///
/// Lets an operator view a service's uptime and detect a stale binary (the
/// process started before its on-disk image was last modified) without a
/// PowerShell shell-out.
#[must_use]
pub fn process_creation_time(pid: u32) -> Option<std::time::SystemTime> {
    let handle = open_for_query(pid)?;
    let result = creation_time_of(handle);
    close_handle(handle);
    result
}

/// Read the creation `FILETIME` of an open process handle and convert it to a
/// [`std::time::SystemTime`].
fn creation_time_of(handle: HANDLE) -> Option<std::time::SystemTime> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all four `FILETIME` out-params are valid writable pointers;
    // `GetProcessTimes` fills them and returns `Err` on failure.
    #[expect(unsafe_code, reason = "Win32 FFI — GetProcessTimes")]
    let outcome = unsafe {
        GetProcessTimes(
            handle,
            core::ptr::from_mut(&mut creation),
            core::ptr::from_mut(&mut exit),
            core::ptr::from_mut(&mut kernel),
            core::ptr::from_mut(&mut user),
        )
    };
    outcome.ok()?;
    let ticks = (u64::from(creation.dwHighDateTime) << 32_u32) | u64::from(creation.dwLowDateTime);
    let unix_100ns = ticks.checked_sub(WINDOWS_TO_UNIX_100NS)?;
    let secs = unix_100ns / FILETIME_TICKS_PER_SEC;
    let nanos = u32::try_from((unix_100ns % FILETIME_TICKS_PER_SEC) * 100).ok()?;
    Some(std::time::UNIX_EPOCH + core::time::Duration::new(secs, nanos))
}

/// Enumerate the pids whose image **file name** equals `file_name`
/// (case-insensitive, e.g. `"uffsmcp.exe"`).
#[must_use]
pub fn pids_by_image_name(file_name: &str) -> Vec<u32> {
    enum_pids()
        .into_iter()
        .filter(|&pid| {
            process_image_path(pid).is_some_and(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(file_name))
            })
        })
        .collect()
}

/// Open a process handle with the minimal query-only access right.
fn open_for_query(pid: u32) -> Option<HANDLE> {
    // SAFETY: `OpenProcess` is a documented Win32 call; the access mask
    // and pid are plain values and it returns `Err` on failure.
    #[expect(unsafe_code, reason = "Win32 FFI — OpenProcess")]
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    (!handle.is_invalid()).then_some(handle)
}

/// Query the full Win32 image path for an open process handle.
fn image_path_of(handle: HANDLE) -> Option<PathBuf> {
    let mut buf = vec![0_u16; PATH_CAP];
    let mut size = u32::try_from(buf.len()).ok()?;
    // SAFETY: `buf`/`size` are a valid writable buffer + length pair;
    // `PROCESS_NAME_WIN32` requests a Win32-format path. On success
    // `size` is updated to the number of code units written.
    #[expect(unsafe_code, reason = "Win32 FFI — QueryFullProcessImageNameW")]
    let outcome = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            core::ptr::from_mut(&mut size),
        )
    };
    outcome.ok()?;
    let written = usize::try_from(size).ok()?;
    let slice = buf.get(..written)?;
    // Lossless: Windows paths are arbitrary u16 sequences (not necessarily
    // valid Unicode); `OsString::from_wide` preserves every code unit, so the
    // resulting `PathBuf` compares exactly against real paths — no decode.
    Some(PathBuf::from(std::ffi::OsString::from_wide(slice)))
}

/// Snapshot all process ids on the system via `EnumProcesses`, growing
/// the buffer until it is not saturated.
fn enum_pids() -> Vec<u32> {
    let mut pids = vec![0_u32; 4_096];
    loop {
        let Ok(cap_bytes) = u32::try_from(pids.len() * size_of::<u32>()) else {
            return Vec::new();
        };
        let mut needed_bytes = 0_u32;
        // SAFETY: `pids` is a valid writable buffer of `cap_bytes` bytes;
        // `needed_bytes` receives the bytes actually used.
        #[expect(unsafe_code, reason = "Win32 FFI — EnumProcesses")]
        let outcome = unsafe {
            EnumProcesses(
                pids.as_mut_ptr(),
                cap_bytes,
                core::ptr::from_mut(&mut needed_bytes),
            )
        };
        if outcome.is_err() {
            return Vec::new();
        }
        let Ok(needed) = usize::try_from(needed_bytes) else {
            return Vec::new();
        };
        let count = needed / size_of::<u32>();
        if count < pids.len() {
            pids.truncate(count);
            return pids;
        }
        // Buffer was saturated — grow and retry to avoid truncation.
        pids.resize(pids.len() * 2, 0_u32);
    }
}

/// Close a process handle obtained from [`open_for_query`].
fn close_handle(handle: HANDLE) {
    // SAFETY: `handle` came from `OpenProcess` and is closed exactly once.
    #[expect(unsafe_code, reason = "Win32 FFI — CloseHandle")]
    let _closed = unsafe { CloseHandle(handle) };
}
