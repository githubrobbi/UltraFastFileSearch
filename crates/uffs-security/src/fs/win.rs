// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Windows-only security FFI helpers backing [`super`]'s cross-platform
//! filesystem primitives.
//!
//! Extracted from `fs.rs` so the platform-agnostic public surface
//! (`secure_remove`, `atomic_write`, `create_secure_dir`, `FileLock`, …)
//! stays readable and the `unsafe` Win32 calls live together in one auditable
//! place. The whole module is gated behind `#[cfg(windows)]` at the `mod`
//! declaration, so the individual items need no per-item `cfg`.
//!
//! Three helpers are called from the parent module and are therefore
//! `pub(super)`: [`win_clear_readonly`], [`win_set_hidden`], and
//! [`win_set_owner_only_acl`]. The rest are private plumbing.

use std::io;
use std::path::Path;

/// Windows: set the `FILE_ATTRIBUTE_HIDDEN` flag on a path.
///
/// Best-effort: silently does nothing if the Win32 calls fail.  Callers
/// treat this as a defense-in-depth layer on top of ACLs, not a hard
/// guarantee.
pub(super) fn win_set_hidden(path: &Path) {
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_HIDDEN;
    let wide = path_to_wide(path);
    let Some(current) = win_get_file_attributes(&wide) else {
        return;
    };
    win_set_file_attributes(&wide, current | FILE_ATTRIBUTE_HIDDEN.0);
}

/// Windows: clear the `FILE_ATTRIBUTE_READONLY` flag on a path.
///
/// Returns `Ok(())` when the path already has no read-only flag. A path that
/// does **not exist** is also `Ok(())`: `secure_remove` (the caller) treats an
/// absent path as a no-op success, and the open-for-write it performs next
/// would itself map `NotFound` to `Ok`. Without this, the read-only pre-clear
/// would surface `GetFileAttributesW`'s "file not found" as a hard error and
/// break that contract on Windows. Any other attribute-query failure is a real
/// error and propagates.
pub(super) fn win_clear_readonly(path: &Path) -> io::Result<()> {
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY;

    let wide = path_to_wide(path);
    let Some(current) = win_get_file_attributes(&wide) else {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(err);
    };
    if current & FILE_ATTRIBUTE_READONLY.0 == 0 {
        return Ok(()); // already writable
    }
    if win_set_file_attributes(&wide, current & !FILE_ATTRIBUTE_READONLY.0) {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Encode `path` as a null-terminated UTF-16 buffer for Win32 APIs.
///
/// Infallible: `encode_wide` yields valid UTF-16 code units for any
/// `OsStr`, and we only append a single null terminator.
fn path_to_wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt as _;
    path.as_os_str().encode_wide().chain(Some(0_u16)).collect()
}

/// `GetFileAttributesW` wrapper — returns `None` on `INVALID_FILE_ATTRIBUTES`.
fn win_get_file_attributes(wide: &[u16]) -> Option<u32> {
    use windows::Win32::Storage::FileSystem::GetFileAttributesW;
    use windows::core::PCWSTR;

    // SAFETY: `wide` is a null-terminated UTF-16 buffer owned by the
    // caller; `PCWSTR` borrows it for the duration of the Win32 call.
    #[expect(unsafe_code, reason = "Win32 FFI — attribute query")]
    let current = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    if current == u32::MAX {
        None
    } else {
        Some(current)
    }
}

/// `SetFileAttributesW` wrapper — returns `true` on success.
fn win_set_file_attributes(wide: &[u16], attrs: u32) -> bool {
    use windows::Win32::Storage::FileSystem::{FILE_FLAGS_AND_ATTRIBUTES, SetFileAttributesW};
    use windows::core::PCWSTR;

    // SAFETY: `wide` is a null-terminated UTF-16 buffer owned by the
    // caller; `PCWSTR` borrows it for the duration of the Win32 call.
    #[expect(unsafe_code, reason = "Win32 FFI — attribute set")]
    let result =
        unsafe { SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(attrs)) };
    result.is_ok()
}

/// Windows: grant the current user full control of `path` via the native
/// Win32 security APIs (no subprocess).
///
/// S1.2.6: adds an explicit full-control ACE for the **process token's owner
/// SID** while keeping inherited ACEs intact (the DACL is set *unprotected*,
/// so the parent's inheritable ACEs are re-applied). This is still secure for
/// the cache use case (a user-private `%LOCALAPPDATA%` directory).
///
/// Why native instead of `icacls`:
/// - **Correctness.** The old path resolved the principal from `%USERNAME%`,
///   which diverges from the effective SID under elevation — it could grant to
///   the wrong principal. The token's owner SID is always the right one.
/// - **Cost.** Shelling out to `icacls.exe` is a full process spawn (tens of
///   ms). `create_new_secure_file` runs this on every write, so the spawn was a
///   per-call tax; the native calls are microseconds.
///
/// Returns `true` on success; callers fall back to the hidden attribute.
pub(super) fn win_set_owner_only_acl(path: &Path) -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: returns a pseudo-handle that is always valid for the current
    // process and needs no close.
    #[expect(unsafe_code, reason = "Win32 FFI — current-process pseudo-handle")]
    let process = unsafe { GetCurrentProcess() };

    let mut token = HANDLE::default();
    // SAFETY: `process` is valid; `&raw mut token` is a valid out-pointer for
    // the returned token handle.
    #[expect(unsafe_code, reason = "Win32 FFI — open our own process token")]
    let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) };
    if opened.is_err() {
        return false;
    }

    let applied = win_apply_owner_ace(path, token);

    // SAFETY: `token` was returned by a successful `OpenProcessToken` and has
    // not been closed elsewhere.
    #[expect(unsafe_code, reason = "Win32 FFI — close the process token handle")]
    let _closed = unsafe { CloseHandle(token) };
    applied
}

/// Read the process token's owner SID and apply a full-control ACE for it to
/// `path`'s DACL. Split out so the token handle in the caller is always
/// closed on every return path.
fn win_apply_owner_ace(path: &Path, token: windows::Win32::Foundation::HANDLE) -> bool {
    use core::ffi::c_void;

    use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetNamedSecurityInfoW,
        TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetTokenInformation, PSID,
        SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_USER, TokenUser,
    };
    use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows::core::PWSTR;

    // Size the TOKEN_USER buffer (first call fails, filling `needed`).
    let mut needed = 0_u32;
    // SAFETY: a null buffer with length 0 is the documented "query size" call;
    // `&raw mut needed` receives the required byte count.
    #[expect(unsafe_code, reason = "Win32 FFI — size the token-info buffer")]
    let _probe = unsafe { GetTokenInformation(token, TokenUser, None, 0, &raw mut needed) };
    if needed == 0 {
        return false;
    }

    // Over-aligned backing store: a `TOKEN_USER` embeds a pointer (8-byte
    // aligned on x64) which a `Vec<u8>` would not guarantee. Round the byte
    // count up to whole `u64` words so the cast below is well-aligned. We pass
    // `needed` (≤ the allocation) as the length, so no `usize→u32` cast.
    let words = (needed as usize).div_ceil(size_of::<u64>());
    let mut buffer = vec![0_u64; words];
    // SAFETY: `buffer` is `words * 8 ≥ needed` bytes; the pointer/length pair
    // stay within it and `&raw mut needed` receives the bytes written.
    #[expect(unsafe_code, reason = "Win32 FFI — read the token user/SID")]
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            needed,
            &raw mut needed,
        )
    };
    if read.is_err() {
        return false;
    }

    // The SID lives *inside* `buffer`, which must outlive every use below.
    #[expect(
        unsafe_code,
        reason = "Win32 FFI — interpret token buffer as TOKEN_USER"
    )]
    // SAFETY: `GetTokenInformation(TokenUser)` populated `buffer` (a `u64`
    // allocation, so 8-aligned) with a `TOKEN_USER` whose `User.Sid` points
    // into that same allocation.
    let sid: PSID = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    if sid.is_invalid() {
        return false;
    }

    // The SID is passed through the `ptstrName` pointer slot, per the
    // documented `TRUSTEE_IS_SID` convention — it is never dereferenced as
    // UTF-16.
    let sid_name = PWSTR(sid.0.cast::<u16>());

    // Grant the owner SID full control; (OI)(CI) so a directory's children
    // inherit it (ignored for plain files).
    let explicit = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS.0,
        grfAccessMode: SET_ACCESS,
        grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        Trustee: TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: sid_name,
            ..Default::default()
        },
    };

    let mut new_dacl: *mut ACL = core::ptr::null_mut();
    let entries = [explicit];
    // SAFETY: `entries` outlives the call; `&raw mut new_dacl` receives a
    // `LocalAlloc`-owned ACL we free below.
    #[expect(unsafe_code, reason = "Win32 FFI — build the new DACL")]
    let build = unsafe { SetEntriesInAclW(Some(&entries), None, &raw mut new_dacl) };
    if build != ERROR_SUCCESS {
        return false;
    }

    let mut wide = path_to_wide(path);
    // SAFETY: `wide` is a mutable null-terminated UTF-16 buffer; `new_dacl` is
    // a valid ACL from `SetEntriesInAclW`. Owner/group are unchanged (`None`);
    // only the DACL is set, unprotected (inherited ACEs preserved).
    #[expect(unsafe_code, reason = "Win32 FFI — apply the DACL to the path")]
    let set = unsafe {
        SetNamedSecurityInfoW(
            PWSTR(wide.as_mut_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_dacl),
            None,
        )
    };

    if !new_dacl.is_null() {
        // SAFETY: `new_dacl` was allocated by `SetEntriesInAclW` via
        // `LocalAlloc`, so `LocalFree` is the matching deallocator.
        #[expect(unsafe_code, reason = "Win32 FFI — free the ACL allocation")]
        let _freed = unsafe { LocalFree(Some(HLOCAL(new_dacl.cast::<c_void>()))) };
    }

    set == ERROR_SUCCESS
}
