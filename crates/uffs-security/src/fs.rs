// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Secure filesystem operations: atomic writes, secure delete, permissions,
//! file locking.
//!
//! These primitives are used by `uffs-mft` (cache), `uffs-daemon` (socket dir,
//! PID file), and any other crate that needs secure file handling.
//!
//! # Platform Support
//!
//! | Function | macOS | Linux | Windows |
//! |----------|-------|-------|---------|
//! | `create_secure_dir` | 0700 | 0700 | inherits parent ACL + read-only attr |
//! | `set_file_permissions_owner_only` | 0600 | 0600 | read-only attribute |
//! | `atomic_write` | rename | rename | rename (MoveFileExW) |
//! | `secure_remove` | zero+delete | zero+delete | zero+delete |
//! | `FileLock` | flock | flock | LockFileEx |

use std::io;
use std::path::Path;

// ────────────────────────────────────────────────────────────────────────────
// Directory & File Permissions (S1.2)
// ────────────────────────────────────────────────────────────────────────────

/// Create a brand-new file with owner-only permissions, failing if the
/// path already exists (including as a dangling symlink).
///
/// On Unix the file is born `0o600` via `O_CREAT | O_EXCL` + `mode()`, so
/// there is never a window where it is world-readable (cf.
/// `set_permissions`-after-create). On Windows `create_new` likewise refuses
/// to follow/replace an existing path; owner-only ACL is applied immediately.
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::AlreadyExists`] if the path exists, or any
/// other error from the underlying open.
pub fn create_new_secure_file(path: &Path) -> io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(windows)]
    {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        // Apply owner-only ACL immediately (best-effort, same as elsewhere).
        if !win_set_owner_only_acl(path) {
            win_set_hidden(path);
        }
        Ok(file)
    }
}

/// Create a brand-new file at a **user-chosen output path**, failing if the
/// path already exists (including as a symlink/pre-planted target).
///
/// Unlike [`create_new_secure_file`], this does **not** apply an owner-only
/// ACL (Windows) or `0o600` mode (Unix). The destination is a path the user
/// explicitly asked us to write (e.g. `--out=<path>`), so the file should
/// adopt the normal permissions of the directory the user chose rather than
/// being locked to the daemon's owner — forcing owner-only here is both
/// surprising (e.g. exporting into a shared folder) and, on Windows, costly:
/// the owner-only ACL path historically shelled out to `icacls.exe`, adding a
/// process-spawn (~tens of ms) to **every** query that writes results.
///
/// The exclusive `create_new(true)` open still closes the TOCTOU /
/// symlink-swap window, which is the only hardening that matters for a
/// throwaway temp file that is `rename`d into place. Callers that write a
/// *secret* (cache key, daemon state) must use [`create_new_secure_file`]
/// instead.
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::AlreadyExists`] if the path exists, or any
/// other error from the underlying open.
pub fn create_new_file_exclusive(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Write `data` to a **new** secret file born with owner-only permissions.
///
/// Refuses to overwrite an existing path; callers that intend to replace an
/// existing secret must remove it first (so a symlink cannot be followed).
///
/// # Errors
///
/// Returns an error if creation, writing, or syncing fails.
pub fn write_secret_file(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let mut file = create_new_secure_file(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

/// Creates a directory (and parents) with owner-only permissions.
///
/// - **Unix** (macOS + Linux): each component we create is **born** `0700`
///   (`drwx------`) via `DirBuilderExt::mode`, so there is no window where the
///   dir exists at default perms. `recursive(true)` makes the call succeed if
///   the dir already exists; components that already existed keep their current
///   perms (we only guarantee birth perms for what we create).
/// - **Windows**: creates the directory; applies an owner-only ACL (falling
///   back to the hidden attribute) since full DACL control requires elevation.
///
/// # Errors
///
/// Returns an error if directory creation or permission setting fails.
pub fn create_secure_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    return {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    };

    #[cfg(windows)]
    return {
        std::fs::create_dir_all(path)?;
        // Try icacls first — works without elevation, sets proper DACL
        if !win_set_owner_only_acl(path) {
            // Fallback: at least mark hidden (best-effort, infallible).
            win_set_hidden(path);
        }
        Ok(())
    };
}

/// Sets a file's permissions to owner-only (read+write).
///
/// - **Unix** (macOS + Linux): mode `0600` (`-rw-------`)
/// - **Windows**: sets read-only attribute removed (writable by owner); marks
///   hidden to discourage casual access
///
/// # Errors
///
/// Returns an error if permission setting fails.
pub fn set_file_permissions_owner_only(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    return {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    };

    #[cfg(windows)]
    return {
        // Ensure writable — remove FILE_ATTRIBUTE_READONLY if set.
        // We cannot use `std::fs::Permissions::set_readonly(false)` because
        // its cross-platform semantics are not what we want (and clippy
        // rightly flags it).  Go through Win32 directly.
        win_clear_readonly(path)?;
        // Try proper DACL, fall back to hidden
        if !win_set_owner_only_acl(path) {
            win_set_hidden(path);
        }
        Ok(())
    };
}

/// Windows: set the `FILE_ATTRIBUTE_HIDDEN` flag on a path.
///
/// Best-effort: silently does nothing if the Win32 calls fail.  Callers
/// treat this as a defense-in-depth layer on top of ACLs, not a hard
/// guarantee.
#[cfg(windows)]
fn win_set_hidden(path: &Path) {
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_HIDDEN;
    let wide = path_to_wide(path);
    let Some(current) = win_get_file_attributes(&wide) else {
        return;
    };
    win_set_file_attributes(&wide, current | FILE_ATTRIBUTE_HIDDEN.0);
}

/// Windows: clear the `FILE_ATTRIBUTE_READONLY` flag on a path.
///
/// Returns `Ok(())` unchanged if the path already has no read-only flag,
/// or if the path does not exist (that failure surfaces downstream).
#[cfg(windows)]
fn win_clear_readonly(path: &Path) -> io::Result<()> {
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY;

    let wide = path_to_wide(path);
    let Some(current) = win_get_file_attributes(&wide) else {
        // GetFileAttributesW failed — surface as the last OS error so the
        // caller sees why.
        return Err(io::Error::last_os_error());
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
#[cfg(windows)]
fn path_to_wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt as _;
    path.as_os_str().encode_wide().chain(Some(0_u16)).collect()
}

/// `GetFileAttributesW` wrapper — returns `None` on `INVALID_FILE_ATTRIBUTES`.
#[cfg(windows)]
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
#[cfg(windows)]
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
#[cfg(windows)]
fn win_set_owner_only_acl(path: &Path) -> bool {
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
#[cfg(windows)]
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

// ────────────────────────────────────────────────────────────────────────────
// Atomic Writes (S1.3)
// ────────────────────────────────────────────────────────────────────────────

/// Writes data atomically: write to a **randomised** temp in the same
/// directory, `sync_all()`, rename over the target.
///
/// If the process is killed mid-write, the original file remains intact.
/// Stale temp files are cleaned up on the next `cache_dir()` call.
///
/// The temp file is **born** `0600` via [`create_new_secure_file`] and carries
/// a random suffix, so there is no perms-after-create window and no
/// predictable name an attacker could pre-plant as a symlink (`create_new`
/// refuses to follow it).
///
/// Works on all platforms: POSIX `rename` is atomic on the same filesystem;
/// on Windows `std::fs::rename` uses `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`.
///
/// # Errors
///
/// Returns an error if writing, syncing, or renaming fails.
pub fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

    use rand::Rng as _;

    // Unique temp name in the SAME directory as `path` (same-FS rename stays
    // atomic). `unwrap_or_default` here is on `Option`, not `Result`.
    // Use `fill_bytes` (the API the keystore/crypto already use) for the
    // random suffix rather than the version-sensitive `random()` helper.
    let mut suffix_bytes = [0_u8; 8];
    rand::rng().fill_bytes(&mut suffix_bytes);
    let suffix = u64::from_le_bytes(suffix_bytes);
    let file_name = path.file_name().unwrap_or_default();
    let tmp_name = format!("{}.{:016x}.uffs.tmp", file_name.to_string_lossy(), suffix);
    let tmp_path = path.with_file_name(tmp_name);

    let write_result = (|| -> io::Result<()> {
        let mut file = create_new_secure_file(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp_path, path)
    })();

    if write_result.is_err() {
        // Best-effort cleanup of the temp on any failure before rename.
        let _ignore = std::fs::remove_file(&tmp_path);
    }
    write_result
}

// ────────────────────────────────────────────────────────────────────────────
// Secure Wipe (S3.1) — fully cross-platform
// ────────────────────────────────────────────────────────────────────────────

/// Securely removes a file: zero-overwrite, `sync_all()`, then delete.
///
/// On HDD this overwrites the data sectors with zeros before unlinking.
/// On SSD the overwrite is best-effort (wear-leveling may retain old data),
/// but combined with encryption (S2) the plaintext is unrecoverable.
///
/// Does nothing if the file doesn't exist.
/// Works identically on macOS, Linux, and Windows.
///
/// # Errors
///
/// Returns an error if overwriting, syncing, or removal fails.
pub fn secure_remove(path: &Path) -> io::Result<()> {
    use std::io::{Seek as _, SeekFrom, Write as _};

    /// Size of the zero-fill buffer for secure wipe.
    const ZERO_BUF_SIZE: usize = 64 * 1024;

    // On Windows, ensure the file isn't read-only before we try to open it
    // for write. This is a path-based attribute clear that necessarily
    // precedes the fd anchor below — acceptable because it only toggles an
    // attribute, not content. See `win_clear_readonly` docs for why we don't
    // use `std::fs::Permissions::set_readonly(false)` here.
    #[cfg(windows)]
    win_clear_readonly(path)?;

    // Anchor on a single fd: open once, then read the length from the OPEN
    // file (not a separate `std::fs::metadata(path)` stat). This closes the
    // TOCTOU window where the path could be re-pointed between the size we
    // overwrite and the bytes we write. NotFound is a no-op, as before.
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    let file_len = file.metadata()?.len();

    let zeros = vec![0_u8; ZERO_BUF_SIZE];
    let mut remaining = file_len;

    file.seek(SeekFrom::Start(0))?;
    while remaining > 0 {
        // ZERO_BUF_SIZE is a small constant — usize→u64 is lossless on 64-bit.
        let chunk = if remaining >= ZERO_BUF_SIZE as u64 {
            ZERO_BUF_SIZE
        } else {
            usize::try_from(remaining).unwrap_or(ZERO_BUF_SIZE)
        };
        let buf = zeros
            .get(..chunk)
            .ok_or_else(|| io::Error::other("zero buffer slice out of bounds"))?;
        file.write_all(buf)?;
        remaining -= chunk as u64; // chunk ≤ ZERO_BUF_SIZE (64 KiB) — fits u64
    }

    file.sync_all()?;
    drop(file);

    std::fs::remove_file(path)
}

// ────────────────────────────────────────────────────────────────────────────
// Path identity (Category 3)
// ────────────────────────────────────────────────────────────────────────────

/// Answer "are these two paths the **same file**?" by filesystem identity,
/// not by string comparison.
///
/// String equality on paths is not filesystem identity: two different
/// strings can name the same file (hardlink, symlink, `.`/`..`, case-fold,
/// trailing separators), and two equal strings can name different files
/// across mounts. Where a *safety/scoping* decision turns on "same file",
/// compare the OS identity instead:
///
/// - **Unix:** `(st_dev, st_ino)` from `MetadataExt`.
/// - **Windows:** the volume serial + file index from
///   `BY_HANDLE_FILE_INFORMATION` (via `std::os::windows::fs::MetadataExt`).
///
/// This **follows symlinks** (uses `metadata`, not `symlink_metadata`): it
/// answers "do these resolve to the same file", which is the question a
/// scoping/identity check actually has.
///
/// # Errors
///
/// Returns an error if either path cannot be `stat`'d (e.g. missing).
pub fn paths_identical(first: &Path, second: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let meta_a = std::fs::metadata(first)?;
        let meta_b = std::fs::metadata(second)?;
        Ok(meta_a.dev() == meta_b.dev() && meta_a.ino() == meta_b.ino())
    }
    #[cfg(windows)]
    {
        // Windows file identity is `(dwVolumeSerialNumber, nFileIndex)` from
        // `BY_HANDLE_FILE_INFORMATION`. The `std::os::windows::fs::MetadataExt`
        // accessors for these (`volume_serial_number` / `file_index`) are
        // still unstable (rust-lang/rust#63010, `windows_by_handle`), so a
        // stable implementation must go through `GetFileInformationByHandle`
        // directly. That FFI is deferred until a caller actually needs
        // same-file identity on Windows (the WI-3.1 audit found the
        // drive-scoping path uses the typed `DriveLetter`, not this helper).
        // Until then, be explicit rather than silently wrong.
        let _: (&Path, &Path) = (first, second);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "paths_identical: Windows file-identity comparison not yet implemented \
             (needs stable GetFileInformationByHandle FFI; no caller requires it yet)",
        ))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// File Locking (S3.2)
// ────────────────────────────────────────────────────────────────────────────

/// Advisory file lock type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockKind {
    /// Shared (read) lock — multiple readers allowed.
    Shared,
    /// Exclusive (write) lock — single writer, no readers.
    Exclusive,
}

/// An advisory file lock backed by a `.lock` file.
///
/// The lock is released when this struct is dropped (closing the fd/handle
/// releases the flock/`LockFileEx` lock automatically).
///
/// Works on all platforms: `flock` (macOS + Linux), `LockFileEx` (Windows).
pub struct FileLock {
    /// Kept open for the lifetime of the lock.
    _file: std::fs::File,
}

impl FileLock {
    /// Acquires an advisory lock on `lock_path`.
    ///
    /// Creates the lock file if it doesn't exist. Blocks up to `timeout`
    /// with a spin-sleep retry loop.
    ///
    /// # Errors
    ///
    /// Returns `io::ErrorKind::TimedOut` if the lock cannot be acquired
    /// within the timeout.
    #[cfg(unix)]
    pub fn acquire(
        lock_path: &Path,
        kind: LockKind,
        timeout: core::time::Duration,
    ) -> io::Result<Self> {
        use std::os::unix::io::AsRawFd as _;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .open(lock_path)?;

        let deadline = std::time::Instant::now() + timeout;
        let sleep_step = core::time::Duration::from_millis(50);

        let operation = match kind {
            LockKind::Shared => libc::LOCK_SH | libc::LOCK_NB,
            LockKind::Exclusive => libc::LOCK_EX | libc::LOCK_NB,
        };

        loop {
            // SAFETY: flock is a well-defined POSIX syscall operating on a valid fd.
            #[expect(unsafe_code, reason = "flock requires unsafe FFI call")]
            let result = unsafe { libc::flock(file.as_raw_fd(), operation) };

            if result == 0 {
                return Ok(Self { _file: file });
            }

            let lock_err = io::Error::last_os_error();
            let is_contention = lock_err.kind() == io::ErrorKind::WouldBlock
                || lock_err.raw_os_error() == Some(libc::EWOULDBLOCK)
                || lock_err.raw_os_error() == Some(libc::EAGAIN);

            if is_contention {
                if std::time::Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "could not acquire {kind:?} lock on {} within {}s",
                            lock_path.display(),
                            timeout.as_secs()
                        ),
                    ));
                }
                std::thread::sleep(sleep_step);
            } else {
                return Err(lock_err);
            }
        }
    }

    /// Acquire a file lock on Windows using `LockFileEx`.
    ///
    /// # Errors
    ///
    /// Returns `io::ErrorKind::TimedOut` if the lock cannot be acquired
    /// within `timeout`, or any other `io::Error` raised by opening the
    /// lock file or the `LockFileEx` call itself.
    #[cfg(windows)]
    pub fn acquire(
        lock_path: &Path,
        kind: LockKind,
        timeout: core::time::Duration,
    ) -> io::Result<Self> {
        use std::os::windows::io::AsRawHandle as _;

        /// Windows error code for lock contention.
        const ERROR_LOCK_VIOLATION: i32 = 33;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .open(lock_path)?;

        let deadline = std::time::Instant::now() + timeout;
        let sleep_step = core::time::Duration::from_millis(50);

        loop {
            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::Storage::FileSystem::{
                LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
            };

            // SAFETY: `OVERLAPPED` is a POD struct of integers and pointers;
            // zero-initialisation matches Win32's "not used for overlapped
            // I/O" convention for `LockFileEx`.
            #[expect(unsafe_code, reason = "zero-init POD struct for Win32")]
            let mut overlapped: windows::Win32::System::IO::OVERLAPPED =
                unsafe { core::mem::zeroed() };
            let mut flags = LOCKFILE_FAIL_IMMEDIATELY;
            if kind == LockKind::Exclusive {
                flags |= LOCKFILE_EXCLUSIVE_LOCK;
            }

            // `as_raw_handle()` returns `*mut c_void`; wrap into the
            // windows-rs `HANDLE` newtype with an explicit `.cast()`.
            let handle = HANDLE(file.as_raw_handle().cast::<core::ffi::c_void>());

            // SAFETY: `handle` is a valid open-for-write file handle
            // (guaranteed by `file`'s lifetime); `overlapped` lives for
            // the whole call.
            #[expect(unsafe_code, reason = "LockFileEx requires unsafe FFI call")]
            let lock_result = unsafe {
                LockFileEx(
                    handle,
                    flags,
                    Some(0),
                    u32::MAX,
                    u32::MAX,
                    core::ptr::from_mut(&mut overlapped),
                )
            };

            if lock_result.is_ok() {
                return Ok(Self { _file: file });
            }

            let lock_err = io::Error::last_os_error();
            let is_contention = lock_err.kind() == io::ErrorKind::WouldBlock
                || lock_err.raw_os_error() == Some(ERROR_LOCK_VIOLATION);

            if is_contention {
                if std::time::Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "could not acquire {kind:?} lock on {} within {}s",
                            lock_path.display(),
                            timeout.as_secs()
                        ),
                    ));
                }
                std::thread::sleep(sleep_step);
            } else {
                return Err(lock_err);
            }
        }
    }
}

/// Runs a closure while holding an advisory file lock.
///
/// Creates a `.lock` file at `lock_path`, acquires the lock, runs `func`,
/// then releases the lock when the guard drops.
///
/// # Errors
///
/// Returns an error if the lock cannot be acquired within `timeout`, or if
/// `func` returns an error.
pub fn with_file_lock<F, T>(
    lock_path: &Path,
    kind: LockKind,
    timeout: core::time::Duration,
    func: F,
) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T>,
{
    let _guard = FileLock::acquire(lock_path, kind, timeout)?;
    func()
}

#[cfg(test)]
#[path = "fs/tests.rs"]
mod tests;
