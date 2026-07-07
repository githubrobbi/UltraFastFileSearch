// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Platform-native secure key storage.
//!
//! Provides [`get_cache_key`] which returns a 256-bit AES key, generating and
//! storing it on first use via the OS-native secure vault:
//!
//! | Platform | Backend | Key Location |
//! |----------|---------|-------------|
//! | **macOS** | Keychain Services | `com.uffs.cache` / `encryption-key-v1` |
//! | **Windows** | DPAPI (`CryptProtectData`) | `%LOCALAPPDATA%/uffs/key.dpapi` |
//! | **Linux** | File-based (secure dir + 0600 perms) | `~/.local/share/uffs/key.bin` |
//!
//! The user never sees, configures, or manages keys. If the key is lost
//! (keychain corruption, password reset), a new key is generated and old
//! cache files trigger a rebuild from MFT.
//!
//! ## Development mode (`UFFS_DEV=1`)
//!
//! On **non-Windows** platforms, setting `UFFS_DEV=1` bypasses Keychain and
//! uses file-based key storage (`~/.local/share/uffs/key.bin` with `0600`
//! permissions). This avoids the macOS login-password prompt that occurs
//! after every `cargo build` (each rebuild produces a binary with a different
//! ad-hoc code signature, which Keychain treats as a new application).
//!
//! On **Windows**, `UFFS_DEV` is ignored — DPAPI never prompts.

use std::io;

/// Size of the AES-256 key in bytes.
const KEY_SIZE: usize = 32;

// ────────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────────

/// Returns the 256-bit AES cache encryption key, generating one on first use.
///
/// The key is persisted in the platform's secure storage so it survives
/// across process restarts.
///
/// # Errors
///
/// Returns an error if key generation or storage fails.
/// Retrieves or creates a platform-specific encryption key (macOS Keychain).
///
/// Tries to read an existing key from Keychain; if not found or wrong size,
/// generates a new 256-bit key, stores it, and returns it.
///
/// # Errors
///
/// Returns an error if Keychain access or key storage fails.
#[cfg(target_os = "macos")]
pub fn get_cache_key() -> io::Result<[u8; KEY_SIZE]> {
    // Dev mode: bypass Keychain to avoid login-password prompts after
    // every rebuild (each cargo build changes the ad-hoc code signature).
    if is_dev_mode() {
        tracing::debug!("UFFS_DEV set — using file-based key (Keychain bypassed)");
        return file_based_key();
    }
    keychain_key()
}

/// Retrieve or create the encryption key via macOS Keychain Services.
///
/// # Errors
///
/// Returns [`std::io::Error`] if Keychain access fails (e.g. user denies
/// permission, Keychain is locked, or the stored key has an invalid size
/// after multiple regeneration attempts).
#[cfg(target_os = "macos")]
fn keychain_key() -> io::Result<[u8; KEY_SIZE]> {
    use rand::Rng as _;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    /// macOS Keychain `errSecItemNotFound` error code.
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300_i32;

    const SERVICE: &str = "com.uffs.cache";
    const ACCOUNT: &str = "encryption-key-v1";

    // Try to retrieve existing key
    match get_generic_password(SERVICE, ACCOUNT) {
        Ok(key_data) => {
            if key_data.len() == KEY_SIZE {
                let mut key = [0_u8; KEY_SIZE];
                key.copy_from_slice(&key_data);
                return Ok(key);
            }
            // Wrong size — delete and regenerate
            tracing::warn!(
                len = key_data.len(),
                "Keychain entry has wrong size, regenerating"
            );
            let _ignore = delete_generic_password(SERVICE, ACCOUNT);
        }
        Err(keychain_err) => {
            // errSecItemNotFound is the expected "not yet created" case
            let code = keychain_err.code();
            if code != ERR_SEC_ITEM_NOT_FOUND {
                tracing::debug!(
                    error_code = code,
                    "Keychain lookup failed (will generate new key)"
                );
            }
        }
    }

    // Generate new key using OS CSPRNG
    let mut key = [0_u8; KEY_SIZE];
    rand::rng().fill_bytes(&mut key);

    // Store in Keychain
    set_generic_password(SERVICE, ACCOUNT, &key).map_err(|store_err| {
        io::Error::other(format!("failed to store key in Keychain: {store_err}"))
    })?;

    tracing::info!("Generated and stored new encryption key in macOS Keychain");
    Ok(key)
}

// ────────────────────────────────────────────────────────────────────────────
// Windows: DPAPI (CryptProtectData / CryptUnprotectData)
// ────────────────────────────────────────────────────────────────────────────

/// Windows DPAPI key retrieval or generation.
///
/// The raw 32-byte key is encrypted with `CryptProtectData` using the
/// entropy string `"uffs-cache-v1"`. The encrypted blob is stored at
/// `%LOCALAPPDATA%/uffs/key.dpapi`. Only the same Windows user account
/// can decrypt it via `CryptUnprotectData`.
///
/// # Errors
///
/// Returns an error if DPAPI access or file I/O fails.
#[cfg(target_os = "windows")]
pub fn get_cache_key() -> io::Result<[u8; KEY_SIZE]> {
    use rand::Rng as _;
    let key_path = dpapi_key_path()?;

    // Try to read and decrypt existing DPAPI blob
    if key_path.exists() {
        match dpapi_read_key(&key_path) {
            Ok(key) => return Ok(key),
            Err(dpapi_err) => {
                tracing::warn!(
                    path = %key_path.display(),
                    error = %dpapi_err,
                    "DPAPI decrypt failed, regenerating key"
                );
                let _ignore = std::fs::remove_file(&key_path);
            }
        }
    }

    // Generate new key using OS CSPRNG
    let mut key = [0_u8; KEY_SIZE];
    rand::rng().fill_bytes(&mut key);

    // Ensure parent dir exists with secure permissions
    if let Some(parent) = key_path.parent() {
        crate::fs::create_secure_dir(parent)?;
    }

    // Encrypt with DPAPI and write
    dpapi_write_key(&key_path, &key)?;

    tracing::info!(path = %key_path.display(), "Generated and stored new encryption key (DPAPI)");
    Ok(key)
}

/// DPAPI key file path: `%LOCALAPPDATA%/uffs/key.dpapi`
#[cfg(target_os = "windows")]
fn dpapi_key_path() -> io::Result<std::path::PathBuf> {
    let base = dirs_next::data_local_dir().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "cannot determine %LOCALAPPDATA%")
    })?;
    Ok(base.join("uffs").join("key.dpapi"))
}

/// Entropy string for DPAPI — binds the encrypted blob to this application.
#[cfg(target_os = "windows")]
const DPAPI_ENTROPY: &[u8] = b"uffs-cache-v1";

/// Encrypt a key with DPAPI and write the blob to disk.
#[cfg(target_os = "windows")]
fn dpapi_write_key(path: &std::path::Path, key: &[u8; KEY_SIZE]) -> io::Result<()> {
    let encrypted = dpapi_protect(key)?;
    // Replace any stale blob first so create_new can't follow a planted symlink.
    if path.exists() {
        let _ignore = std::fs::remove_file(path);
    }
    crate::fs::write_secret_file(path, &encrypted)?;
    Ok(())
}

/// Read a DPAPI blob from disk and decrypt it to get the key.
#[cfg(target_os = "windows")]
fn dpapi_read_key(path: &std::path::Path) -> io::Result<[u8; KEY_SIZE]> {
    let blob = std::fs::read(path)?;
    let plaintext = dpapi_unprotect(&blob)?;
    if plaintext.len() != KEY_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("DPAPI decrypted key has wrong size: {}", plaintext.len()),
        ));
    }
    let mut key = [0_u8; KEY_SIZE];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Call `CryptProtectData` to encrypt data with DPAPI.
#[cfg(target_os = "windows")]
fn dpapi_protect(data: &[u8]) -> io::Result<Vec<u8>> {
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };

    // DPAPI reads `pbData` and does not mutate it, but the Win32 struct
    // type is `*mut u8`.  `cast_mut()` documents that we are handing the
    // C API a const-origin pointer wearing a `*mut` hat — sound because
    // the call is documented read-only for input blobs.
    let input_blob = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).unwrap_or(u32::MAX),
        pbData: data.as_ptr().cast_mut(),
    };
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(DPAPI_ENTROPY.len()).unwrap_or(u32::MAX),
        pbData: DPAPI_ENTROPY.as_ptr().cast_mut(),
    };
    let mut output_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: core::ptr::null_mut(),
    };

    // SAFETY: CryptProtectData is a well-defined Win32 API; all three
    // blob references outlive this call and the output blob is
    // exclusively borrowed.
    #[expect(unsafe_code, reason = "DPAPI requires unsafe FFI")]
    let ok = unsafe {
        CryptProtectData(
            core::ptr::from_ref(&input_blob),
            None, // description (optional)
            Some(core::ptr::from_ref(&entropy_blob)),
            None,                      // reserved
            None,                      // prompt struct
            CRYPTPROTECT_UI_FORBIDDEN, // no UI
            core::ptr::from_mut(&mut output_blob),
        )
    };

    if let Err(win_err) = ok {
        return Err(io::Error::other(format!(
            "CryptProtectData failed: {win_err}"
        )));
    }

    // Copy output blob to Vec and free the Windows-allocated memory.
    Ok(read_and_free_crypt_blob(&output_blob))
}

/// Call `CryptUnprotectData` to decrypt a DPAPI blob.
#[cfg(target_os = "windows")]
fn dpapi_unprotect(blob: &[u8]) -> io::Result<Vec<u8>> {
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    // See `dpapi_protect` for the rationale on `cast_mut()` over input
    // blobs: the DPAPI contract treats them as read-only.
    let input_blob = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(blob.len()).unwrap_or(u32::MAX),
        pbData: blob.as_ptr().cast_mut(),
    };
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(DPAPI_ENTROPY.len()).unwrap_or(u32::MAX),
        pbData: DPAPI_ENTROPY.as_ptr().cast_mut(),
    };
    let mut output_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: core::ptr::null_mut(),
    };

    // SAFETY: CryptUnprotectData is a well-defined Win32 API; all three
    // blob references outlive this call and the output blob is
    // exclusively borrowed.
    #[expect(unsafe_code, reason = "DPAPI requires unsafe FFI")]
    let ok = unsafe {
        CryptUnprotectData(
            core::ptr::from_ref(&input_blob),
            None, // description out
            Some(core::ptr::from_ref(&entropy_blob)),
            None,                      // reserved
            None,                      // prompt struct
            CRYPTPROTECT_UI_FORBIDDEN, // no UI
            core::ptr::from_mut(&mut output_blob),
        )
    };

    if let Err(win_err) = ok {
        return Err(io::Error::other(format!(
            "CryptUnprotectData failed: {win_err}"
        )));
    }

    Ok(read_and_free_crypt_blob(&output_blob))
}

/// Copy a `CRYPT_INTEGER_BLOB` returned by DPAPI into an owned `Vec<u8>`
/// and free the Win32-allocated memory behind it.
///
/// Shared between `dpapi_protect` and `dpapi_unprotect`; both have to
/// read `pbData .. pbData + cbData` and then `LocalFree` the allocation.
#[cfg(target_os = "windows")]
fn read_and_free_crypt_blob(
    blob: &windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
) -> Vec<u8> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};

    // SAFETY: DPAPI populated `pbData` with a buffer of `cbData` bytes
    // allocated via `LocalAlloc`; we read it as an immutable slice which
    // cannot outlive this function.
    #[expect(unsafe_code, reason = "reading Win32-allocated output buffer")]
    let slice = unsafe { core::slice::from_raw_parts(blob.pbData, blob.cbData as usize) };
    let vec = slice.to_vec();

    // SAFETY: `blob.pbData` is the same `LocalAlloc`-backed pointer
    // DPAPI handed us; `LocalFree` is the documented deallocator.  After
    // this call `blob.pbData` must not be used again — the caller drops
    // the blob immediately.  `LocalFree` returns `HLOCAL` (Copy) so the
    // result is discarded via tail-expression.
    #[expect(unsafe_code, reason = "LocalFree for DPAPI-allocated output")]
    unsafe {
        LocalFree(Some(HLOCAL(blob.pbData.cast::<core::ffi::c_void>())))
    };

    vec
}

// ────────────────────────────────────────────────────────────────────────────
// Linux: file-based key with 0600 permissions
// ────────────────────────────────────────────────────────────────────────────

/// Linux file-based key retrieval or generation.
///
/// Delegates to `file_based_key` — the key is a raw 32-byte file stored at
/// `~/.local/share/uffs/key.bin` with owner-only permissions (`0600`).
///
/// # Errors
///
/// Returns an error if filesystem access or key generation fails.
#[cfg(target_os = "linux")]
pub fn get_cache_key() -> io::Result<[u8; KEY_SIZE]> {
    file_based_key()
}

// ────────────────────────────────────────────────────────────────────────────
// Shared: file-based key (used by Linux always, macOS in dev mode)
// ────────────────────────────────────────────────────────────────────────────

/// File-based key retrieval or generation.
///
/// Stores a raw 32-byte key at `<data_local_dir>/uffs/key.bin` with
/// owner-only permissions (`0600` on Unix, read-only on Windows).
///
/// Used directly by Linux, and as the dev-mode bypass on macOS
/// (`UFFS_DEV=1`) to avoid Keychain password prompts after rebuilds.
///
/// # Errors
///
/// Returns an error if filesystem access or key generation fails.
#[cfg(not(target_os = "windows"))]
fn file_based_key() -> io::Result<[u8; KEY_SIZE]> {
    use rand::Rng as _;

    let base = dirs_next::data_local_dir().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "cannot determine local data dir")
    })?;
    let key_path = base.join("uffs").join("key.bin");

    if key_path.exists() {
        let data = std::fs::read(&key_path)?;
        if data.len() == KEY_SIZE {
            let mut key = [0_u8; KEY_SIZE];
            key.copy_from_slice(&data);
            return Ok(key);
        }
        tracing::warn!(
            len = data.len(),
            path = %key_path.display(),
            "Key file has wrong size, regenerating"
        );
    }

    // Generate new key using OS CSPRNG
    let mut key = [0_u8; KEY_SIZE];
    rand::rng().fill_bytes(&mut key);

    if let Some(parent) = key_path.parent() {
        crate::fs::create_secure_dir(parent)?;
    }

    // Replace any stale key first so create_new can't follow a planted symlink.
    if key_path.exists() {
        let _ignore = std::fs::remove_file(&key_path);
    }
    crate::fs::write_secret_file(&key_path, &key)?;

    tracing::info!(path = %key_path.display(), "Generated and stored new encryption key (file-based)");
    Ok(key)
}

/// Returns `true` when `UFFS_DEV` is set to a truthy value.
///
/// Only used on macOS to bypass Keychain after ad-hoc code signature
/// changes during development.  On Windows, DPAPI never prompts, and
/// on Linux the file-based key path is already the default.
#[cfg(target_os = "macos")]
fn is_dev_mode() -> bool {
    std::env::var("UFFS_DEV").is_ok_and(|val| matches!(val.as_str(), "1" | "true" | "yes"))
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// S2.2.6: key round-trip — generate, store, retrieve, compare.
    ///
    /// IGNORED in CI: triggers macOS Keychain login prompt which blocks
    /// headless runners. Run manually with: `cargo test -p uffs-security --
    /// --ignored key_round_trip`
    #[test]
    #[ignore = "triggers macOS Keychain prompt — run manually"]
    fn key_round_trip() {
        let key1 = get_cache_key().expect("first get_cache_key");
        let key2 = get_cache_key().expect("second get_cache_key");
        assert_eq!(key1, key2, "key should be stable across calls");
    }

    /// Verify generated key is non-zero (not all zeros).
    ///
    /// IGNORED in CI: triggers macOS Keychain login prompt.
    #[test]
    #[ignore = "triggers macOS Keychain prompt — run manually"]
    fn key_is_nonzero() {
        let key = get_cache_key().expect("get_cache_key");
        assert_ne!(key, [0_u8; KEY_SIZE], "key should not be all zeros");
    }

    /// Dev-mode file-based key round-trip (no Keychain prompt).
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn dev_mode_file_key_round_trip() {
        // Use file-based key directly (same path UFFS_DEV=1 uses).
        let key1 = file_based_key().expect("first file_based_key");
        let key2 = file_based_key().expect("second file_based_key");
        assert_eq!(key1, key2, "file-based key should be stable across calls");
        assert_ne!(key1, [0_u8; KEY_SIZE], "key should not be all zeros");
    }

    /// WI-2.3: the keystore's key-write pattern produces a 0600 file with no
    /// perms-after window — exercised against an isolated temp path so the
    /// assertion is deterministic and never depends on (or mutates) the real
    /// shared `key.bin`. This mirrors the exact `remove_file`-then-
    /// `write_secret_file` shape now used by `file_based_key` /
    /// `dpapi_write_key`.
    #[cfg(unix)]
    #[test]
    fn key_write_pattern_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("uffs").join("key.bin");
        crate::fs::create_secure_dir(key_path.parent().expect("parent")).expect("secure dir");

        let key = [0xAB_u8; KEY_SIZE];
        // First write (born 0600).
        crate::fs::write_secret_file(&key_path, &key).expect("write");
        let mode = std::fs::metadata(&key_path)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "key.bin must be born 0600, got {mode:o}");

        // Regeneration path: remove-then-write stays 0600 (no widening).
        std::fs::remove_file(&key_path).expect("remove");
        crate::fs::write_secret_file(&key_path, &key).expect("rewrite");
        let mode2 = std::fs::metadata(&key_path)
            .expect("stat2")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode2, 0o600,
            "rewritten key.bin must stay 0600, got {mode2:o}"
        );
    }
}
