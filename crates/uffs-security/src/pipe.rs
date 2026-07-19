// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

#![cfg(windows)]

//! Windows named-pipe security helpers.
//!
//! UFFS uses a Windows named pipe (`\\.\pipe\uffs-<hash>`) as the IPC
//! transport between the unelevated client CLI and the elevated daemon.
//! This replaces the earlier AF_UNIX socket on Windows, which pulled in
//! `ws2_32.dll` (13 imports, +54 ms launch overhead).
//!
//! # Security model
//!
//! **Goal:** match the Unix `0600` semantics — only the user who launched
//! the daemon can open the pipe.
//!
//! **Non-trivial subtlety:** when the daemon runs elevated, the current
//! process token's *owner* is `BUILTIN\Administrators`, **not** the human
//! user who clicked "Yes" on the UAC prompt.  If we used `OW` ("owner
//! rights") in the DACL, we would silently grant pipe access to every
//! local admin, not just the user.
//!
//! **Fix:** resolve the user SID via `TokenLinkedToken` — which returns the
//! *unelevated* sibling token of a UAC-elevated process — and inject its
//! user SID into the DACL explicitly:
//!
//! ```text
//! D:(A;;GA;;;<user-sid>)
//! ```
//!
//! When `TokenLinkedToken` fails (e.g. the user is logged in as
//! Administrator with no UAC split), we fall back to the current token's
//! `TokenUser`.  In that case the owner and user are identical anyway.
//!
//! # API surface
//!
//! * [`crate::pipe::PipeName`] — validated newtype wrapping a Windows
//!   named-pipe path of the form `\\.\pipe\<name>`.  The canonical constructor
//!   [`crate::pipe::PipeName::for_current_user`] computes the deterministic
//!   per-user pipe path; [`crate::pipe::PipeName::parse`] validates an
//!   arbitrary string.
//! * `current_user_sid_string` — linked-or-current token user SID as a Win32
//!   SDDL-compatible string (`"S-1-5-21-..."`).
//! * [`crate::pipe::OwnerOnlySd`] — RAII wrapper for a `SECURITY_DESCRIPTOR`
//!   granting `GENERIC_ALL` to a single user SID.  Pass
//!   `as_security_attributes()` to
//!   `ServerOptions::create_with_security_attributes_raw`.
//!
//! Every unsafe Win32 call in the UFFS named-pipe stack lives in this
//! file.  Keep it that way.

use core::fmt;
use std::io;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_DUPLICATE,
    TOKEN_LINKED_TOKEN, TOKEN_QUERY, TOKEN_USER, TokenLinkedToken, TokenUser,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{PCWSTR, PWSTR};

/// SDDL revision 1 — the only revision Windows supports.
const SDDL_REVISION_1: u32 = 1;

// ── Public API ──────────────────────────────────────────────────────────

/// A validated Windows named-pipe path of the form `\\.\pipe\<name>`.
///
/// Centralises the producer + consumer surface for the per-user UFFS
/// daemon pipe so every call site is statically guaranteed to be talking
/// about *a* validated pipe path — not an arbitrary `String`.  Eliminates
/// the swap risk between pipe names and the many other strings that flow
/// through the IPC layer (executable paths, user SIDs, JSON-RPC payloads,
/// drive letters cast to strings, …).
///
/// # Invariants
///
/// Every `PipeName` value upholds, by construction:
///
/// 1. Starts with the Win32 named-pipe prefix `\\.\pipe\`.
/// 2. Has at least one character after the prefix (the pipe's *name*).
/// 3. Total length is within the Win32 named-pipe-path limit
///    ([`PipeName::MAX_TOTAL_LEN`]).
///
/// # Construction
///
/// * [`PipeName::for_current_user`] — the canonical per-user UFFS daemon pipe
///   path (`\\.\pipe\uffs-<fnv1a64-of-user-sid>`), computed deterministically
///   so client and daemon agree without shared state.
/// * [`PipeName::parse`] — validate an arbitrary owned-or-borrowed string
///   (useful for test fixtures and reading a peer-supplied path).
///
/// `PipeName` deliberately does **not** implement `From<String>` /
/// `From<&str>`: the only ways in are the two validated constructors
/// above, which is what makes the type a real correctness improvement.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PipeName(String);

/// Error returned by [`PipeName::parse`] when the input is not a valid
/// Windows named-pipe path.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PipeNameError {
    /// The input did not start with the required `\\.\pipe\` prefix.
    BadPrefix {
        /// The original (now-rejected) input, captured verbatim so the
        /// error message can quote it for the operator.
        raw: String,
    },
    /// The input had the prefix but nothing after it — a pipe path
    /// without a name is not a valid Win32 pipe identifier.
    Empty,
    /// The input exceeded [`PipeName::MAX_TOTAL_LEN`]; Win32 would
    /// refuse to create or open it anyway.
    TooLong {
        /// Length of the rejected input, in `char`s (`s.chars().count()`).
        len: usize,
    },
}

impl fmt::Display for PipeNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadPrefix { raw } => write!(
                f,
                "Windows named-pipe path must start with `\\\\.\\pipe\\` (got: `{raw}`)",
            ),
            Self::Empty => f.write_str(
                "Windows named-pipe path must have at least one character after `\\\\.\\pipe\\`",
            ),
            Self::TooLong { len } => write!(
                f,
                "Windows named-pipe path is {len} chars; Win32 limit is {} chars",
                PipeName::MAX_TOTAL_LEN,
            ),
        }
    }
}

impl core::error::Error for PipeNameError {}

impl PipeName {
    /// Required Win32 named-pipe path prefix (local machine, `pipe`
    /// device namespace).
    pub const PREFIX: &'static str = r"\\.\pipe\";

    /// Maximum total path length Win32 will accept for a named pipe.
    /// Documented by the `CreateNamedPipeW` MSDN reference as 256 chars
    /// including the prefix.
    pub const MAX_TOTAL_LEN: usize = 256;

    /// Compute the canonical per-user UFFS daemon pipe path.
    ///
    /// The result is deterministic per user: both daemon and client,
    /// running as the same Windows user, produce the same path without
    /// any shared state.  The FNV-1a hash is used purely for short,
    /// collision-resistant naming — **security comes from the DACL**,
    /// not from the name.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if the user SID cannot be resolved.  This
    /// should not happen on a normally functioning Windows session; if
    /// it does, the caller should log and exit rather than fall back to
    /// an insecure name.
    pub fn for_current_user() -> io::Result<Self> {
        let sid = current_user_sid_string()?;
        let hash = fnv1a_64(sid.as_bytes());
        Ok(Self(format!(r"\\.\pipe\uffs-{hash:016x}")))
    }

    /// Validate `input` and wrap it as a [`PipeName`].
    ///
    /// # Errors
    ///
    /// Returns [`PipeNameError`] when any of the [`PipeName`]
    /// invariants does not hold.
    pub fn parse<Input: Into<String>>(input: Input) -> Result<Self, PipeNameError> {
        let raw: String = input.into();
        if !raw.starts_with(Self::PREFIX) {
            return Err(PipeNameError::BadPrefix { raw });
        }
        if raw.len() == Self::PREFIX.len() {
            return Err(PipeNameError::Empty);
        }
        let len = raw.chars().count();
        if len > Self::MAX_TOTAL_LEN {
            return Err(PipeNameError::TooLong { len });
        }
        Ok(Self(raw))
    }

    /// Borrow the pipe path as a `&str` — for passing to Win32 FFI
    /// (`ServerOptions::create_with_security_attributes_raw`,
    /// `ClientOptions::open`, `tracing` fields, …).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PipeName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PipeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Resolve the user SID of the interactive human user, as an SDDL string.
///
/// Returns the SID in the canonical string form, e.g.
/// `"S-1-5-21-3623811015-3361044348-30300820-1013"`.
///
/// Resolution order:
/// 1. `TokenLinkedToken` on the current process token — this yields the
///    *unelevated* sibling token when the process is UAC-elevated. Its
///    `TokenUser` is the real human user.
/// 2. If step 1 fails (no linked token, e.g. the user is a primary
///    Administrator), fall back to the current process token's `TokenUser`.
///
/// # Errors
///
/// Returns [`std::io::Error`] if both resolution paths fail — typically only
/// in very broken token scenarios.
pub(crate) fn current_user_sid_string() -> io::Result<String> {
    // Try the linked-token path first.
    match linked_token_user_sid() {
        Ok(sid) => Ok(sid),
        Err(primary_err) => {
            tracing::debug!(
                error = %primary_err,
                "TokenLinkedToken unavailable, falling back to current token user"
            );
            current_token_user_sid().map_err(|fallback_err| {
                io::Error::other(format!(
                    "failed to resolve user SID: linked-token: {primary_err}; \
                     current-token fallback: {fallback_err}"
                ))
            })
        }
    }
}

/// RAII wrapper around a `SECURITY_DESCRIPTOR` granting `GENERIC_ALL` to a
/// single user SID.
///
/// Construct with [`OwnerOnlySd::for_current_user`]; borrow with
/// [`OwnerOnlySd::as_security_attributes`].  The descriptor is allocated
/// by `ConvertStringSecurityDescriptorToSecurityDescriptorW` (backed by
/// `LocalAlloc`) and freed with `LocalFree` on drop.
pub struct OwnerOnlySd {
    /// Pointer returned by
    /// `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
    /// Owned — freed in `Drop`.
    sd: PSECURITY_DESCRIPTOR,
}

impl OwnerOnlySd {
    /// Build a DACL granting `GENERIC_ALL` to the current user (resolved
    /// via `current_user_sid_string`).
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if SID resolution or SDDL conversion fails.
    pub fn for_current_user() -> io::Result<Self> {
        let sid = current_user_sid_string()?;
        Self::for_sid_string(&sid)
    }

    /// Build a DACL granting `GENERIC_ALL` to the given user SID string.
    ///
    /// The SID must be in canonical SDDL form (e.g. `"S-1-5-21-..."`).
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if the SDDL conversion fails.
    pub(crate) fn for_sid_string(sid: &str) -> io::Result<Self> {
        // SDDL: DACL with one ACE — Allow, GenericAll, to <sid>.
        let sddl = format!("D:(A;;GA;;;{sid})");
        let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(core::iter::once(0)).collect();

        let mut sd = PSECURITY_DESCRIPTOR::default();

        // SAFETY: `ConvertStringSecurityDescriptorToSecurityDescriptorW`
        // parses the null-terminated UTF-16 SDDL string and allocates a
        // new SECURITY_DESCRIPTOR (via LocalAlloc).  We own the allocation
        // and free it in `Drop`.
        #[expect(unsafe_code, reason = "Win32 FFI — SDDL parse + SD allocation")]
        let result = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_wide.as_ptr()),
                SDDL_REVISION_1,
                core::ptr::from_mut(&mut sd),
                None,
            )
        };

        result.map_err(|win_err| {
            io::Error::other(format!("SDDL '{sddl}' conversion failed: {win_err}"))
        })?;

        Ok(Self { sd })
    }

    /// Borrow as a `SECURITY_ATTRIBUTES` struct for passing to Win32
    /// `CreateNamedPipeW` / tokio
    /// `ServerOptions::create_with_security_attributes_raw`.
    ///
    /// The returned `SECURITY_ATTRIBUTES` borrows this descriptor; it must
    /// not outlive `self`.
    #[must_use]
    pub fn as_security_attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: self.sd.0,
            bInheritHandle: false.into(),
        }
    }

    /// Raw pointer to the `SECURITY_ATTRIBUTES` — kept alive by `self`.
    ///
    /// Prefer [`OwnerOnlySd::as_security_attributes`] unless the target API
    /// takes a raw `*mut c_void`.
    #[must_use]
    pub const fn raw_security_descriptor(&self) -> *mut core::ffi::c_void {
        self.sd.0
    }
}

#[expect(
    unsafe_code,
    reason = "PSECURITY_DESCRIPTOR is *mut c_void but the allocation is owned exclusively"
)]
// SAFETY: `OwnerOnlySd` owns its `PSECURITY_DESCRIPTOR` allocation
// exclusively — the pointer is private, never aliased, and freed in
// `Drop`.  Moving the struct to another thread therefore moves the
// whole allocation with it, which is sound.  We do not implement `Sync`
// because two threads reading `self.sd.0` and passing it to Win32 APIs
// simultaneously has no documented guarantee in the Windows SDK.
unsafe impl Send for OwnerOnlySd {}

impl Drop for OwnerOnlySd {
    fn drop(&mut self) {
        if !self.sd.0.is_null() {
            // SAFETY: `self.sd` was allocated by
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW` and
            // the only deallocator Win32 guarantees for it is `LocalFree`.
            // After this call the pointer is nulled out below so no one can
            // use it again.  `LocalFree` returns `HLOCAL` (Copy, no Result)
            // so discarding its tail value is idiomatic.
            #[expect(unsafe_code, reason = "LocalFree required for LocalAlloc'd SD")]
            unsafe {
                LocalFree(Some(HLOCAL(self.sd.0)))
            };
            self.sd.0 = core::ptr::null_mut();
        }
    }
}

// ── Internals ───────────────────────────────────────────────────────────

/// Resolve the linked (unelevated) token's user SID.
///
/// Fails with `ERROR_NO_SUCH_LOGON_SESSION` or similar when the current
/// token has no linked sibling (e.g. user logged in as a primary
/// Administrator).
fn linked_token_user_sid() -> io::Result<String> {
    let proc_token = open_current_process_token(TOKEN_QUERY.0 | TOKEN_DUPLICATE.0)?;
    let linked = query_linked_token(proc_token.0)?;
    // proc_token handle dropped (closed) by `TokenHandle` RAII below.
    drop(proc_token);

    let sid = token_user_sid_string(linked.0)?;
    drop(linked);
    Ok(sid)
}

/// Resolve the current process token's user SID (no linked-token lookup).
fn current_token_user_sid() -> io::Result<String> {
    let token = open_current_process_token(TOKEN_QUERY.0)?;
    let sid = token_user_sid_string(token.0)?;
    drop(token);
    Ok(sid)
}

/// Open the current process's access token.
fn open_current_process_token(access: u32) -> io::Result<TokenHandle> {
    let mut handle = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that does not
    // need to be closed.
    #[expect(unsafe_code, reason = "Win32 pseudo-handle accessor")]
    let current_proc = unsafe { GetCurrentProcess() };
    // SAFETY: `OpenProcessToken` writes a token handle into `&mut handle`
    // on success.  `current_proc` is a valid pseudo-handle.
    #[expect(unsafe_code, reason = "Win32 token FFI")]
    let result = unsafe {
        OpenProcessToken(
            current_proc,
            windows::Win32::Security::TOKEN_ACCESS_MASK(access),
            core::ptr::from_mut(&mut handle),
        )
    };
    result.map_err(|win_err| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("OpenProcessToken failed: {win_err}"),
        )
    })?;
    Ok(TokenHandle(handle))
}

/// Call `GetTokenInformation(TokenLinkedToken)` and return the linked
/// token handle.
fn query_linked_token(token: HANDLE) -> io::Result<TokenHandle> {
    let mut linked = TOKEN_LINKED_TOKEN {
        LinkedToken: HANDLE::default(),
    };
    let mut returned_len = 0_u32;

    // SAFETY: `GetTokenInformation` with `TokenLinkedToken` writes a
    // `TOKEN_LINKED_TOKEN` struct (single HANDLE).  Out-pointer is valid.
    #[expect(unsafe_code, reason = "Win32 token FFI")]
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenLinkedToken,
            Some(core::ptr::from_mut(&mut linked).cast()),
            u32::try_from(size_of::<TOKEN_LINKED_TOKEN>()).unwrap_or(0),
            core::ptr::from_mut(&mut returned_len),
        )
    };
    result.map_err(|win_err| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("TokenLinkedToken unavailable: {win_err}"),
        )
    })?;

    if linked.LinkedToken.is_invalid() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "TokenLinkedToken returned null handle",
        ));
    }
    Ok(TokenHandle(linked.LinkedToken))
}

/// Extract the user SID from a token and convert to SDDL string form.
fn token_user_sid_string(token: HANDLE) -> io::Result<String> {
    // Two-pass GetTokenInformation: first to size the buffer, second to
    // fill it.  `TOKEN_USER` is variable-length (SID tail).
    let mut required_len = 0_u32;
    // SAFETY: size-probe call with null buffer is explicitly defined by
    // Win32 to return ERROR_INSUFFICIENT_BUFFER and write the required
    // length into the out-param.  We don't care about the `Err` return.
    #[expect(unsafe_code, reason = "Win32 size probe (null buffer is documented)")]
    let size_probe: windows::core::Result<()> = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            None,
            0,
            core::ptr::from_mut(&mut required_len),
        )
    };
    drop(size_probe);
    if required_len == 0 {
        return Err(io::Error::other(
            "GetTokenInformation(TokenUser) returned zero required length",
        ));
    }

    let mut buffer = vec![0_u8; required_len as usize];
    let mut actual_len = 0_u32;
    // SAFETY: `buffer` is sized per the probe.  Out-ptr is valid.
    #[expect(unsafe_code, reason = "Win32 token FFI")]
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            required_len,
            core::ptr::from_mut(&mut actual_len),
        )
    };
    result.map_err(|win_err| {
        io::Error::other(format!("GetTokenInformation(TokenUser) failed: {win_err}"))
    })?;

    // Reinterpret the buffer head as TOKEN_USER.  The `Sid` field is a
    // pointer into the same buffer.
    #[expect(
        unsafe_code,
        reason = "reinterpret cast for Win32 variable-length struct"
    )]
    // SAFETY: buffer size was validated by the successful GetTokenInformation
    // call above; reading `TOKEN_USER` at offset 0 is well-defined because
    // that is the layout Win32 wrote.  The returned reference is bound to
    // `buffer` via lifetime elision.
    let token_user: &TOKEN_USER = unsafe { &*buffer.as_ptr().cast() };
    let sid_ptr = token_user.User.Sid;

    // Convert the SID to SDDL string form.
    let mut sid_wide = PWSTR::null();
    // SAFETY: `ConvertSidToStringSidW` allocates the string via `LocalAlloc`;
    // we must free it with `LocalFree`.
    #[expect(unsafe_code, reason = "Win32 SID conversion")]
    let conv_result =
        unsafe { ConvertSidToStringSidW(sid_ptr, core::ptr::from_mut(&mut sid_wide)) };
    conv_result
        .map_err(|win_err| io::Error::other(format!("ConvertSidToStringSidW failed: {win_err}")))?;

    // SAFETY: `sid_wide` is a null-terminated UTF-16 string allocated by
    // `ConvertSidToStringSidW` above — valid until we `LocalFree` it.
    #[expect(unsafe_code, reason = "read null-terminated UTF-16 from Win32")]
    let sid_string = unsafe { pwstr_to_string(sid_wide) };

    // SAFETY: `ConvertSidToStringSidW` documents `LocalFree` as the
    // required deallocator for `sid_wide`.  After this call `sid_wide`
    // is dropped by going out of scope.  `LocalFree` returns `HLOCAL`
    // (Copy, no Result) so discarding its tail value is idiomatic.
    #[expect(unsafe_code, reason = "LocalFree for LocalAlloc'd SID string")]
    unsafe {
        LocalFree(Some(HLOCAL(sid_wide.0.cast())))
    };

    Ok(sid_string)
}

/// Read a null-terminated UTF-16 `PWSTR` into a Rust `String`.
///
/// # Safety
///
/// `ptr` must point to a valid null-terminated UTF-16 buffer; the caller
/// must guarantee the string is terminated within an allocation they own.
#[expect(unsafe_code, reason = "Win32 string conversion")]
unsafe fn pwstr_to_string(ptr: PWSTR) -> String {
    if ptr.0.is_null() {
        return String::new();
    }
    let mut len = 0_usize;
    loop {
        // SAFETY: pointer arithmetic — caller guarantees we stay inside a
        // null-terminated UTF-16 allocation, so `add(len)` is in-bounds
        // up to and including the terminator.
        let ch_ptr = unsafe { ptr.0.add(len) };
        // SAFETY: `ch_ptr` is in-bounds per the caller's contract.
        let ch = unsafe { *ch_ptr };
        if ch == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: `ptr.0 .. ptr.0 + len` is contiguous valid UTF-16 per the
    // caller's contract; we do not include the trailing null.
    let slice = unsafe { core::slice::from_raw_parts(ptr.0, len) };
    // AUDIT-OK(bytes): the only caller decodes a SID string from
    // `ConvertSidToStringSidW`, whose output is by specification pure ASCII
    // (`S-1-5-21-...`). Lossy and lossless decoding are therefore identical
    // here; `from_utf16_lossy` cannot alter a valid SID (Category 4, WI-4.2).
    String::from_utf16_lossy(slice)
}

/// FNV-1a 64-bit hash.  Not cryptographic — used only for short,
/// collision-resistant pipe names.  Security comes from the DACL.
const fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
    const PRIME: u64 = 0x100_0000_01B3;

    let mut hash = OFFSET;
    let mut idx = 0_usize;
    while idx < bytes.len() {
        hash ^= bytes[idx] as u64;
        hash = hash.wrapping_mul(PRIME);
        idx += 1;
    }
    hash
}

// ── RAII ────────────────────────────────────────────────────────────────

/// Auto-close wrapper for a Windows `HANDLE`.
struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: handle returned by `OpenProcessToken` or
            // `GetTokenInformation(TokenLinkedToken)` — owned by this
            // wrapper and not aliased elsewhere.
            #[expect(unsafe_code, reason = "CloseHandle for owned Win32 handle")]
            // `CloseHandle` returns `Result<()>`; ignore the value — we
            // cannot meaningfully recover from a failed close in `Drop`.
            let close_result = unsafe { CloseHandle(self.0) };
            drop(close_result);
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_is_stable_across_calls() {
        let first = PipeName::for_current_user().expect("SID resolvable in tests");
        let second = PipeName::for_current_user().expect("SID resolvable in tests");
        assert_eq!(
            first, second,
            "pipe name must be deterministic for a given user"
        );
    }

    #[test]
    fn pipe_name_has_expected_shape() {
        let name = PipeName::for_current_user().expect("SID resolvable in tests");
        let raw = name.as_str();
        assert!(
            raw.starts_with(r"\\.\pipe\uffs-"),
            "unexpected prefix: {raw}"
        );
        assert_eq!(
            raw.len(),
            r"\\.\pipe\uffs-".len() + 16,
            "expected 16 hex chars of FNV-1a: {raw}"
        );
    }

    #[test]
    fn parse_accepts_valid_path() {
        let pn = PipeName::parse(r"\\.\pipe\uffs-test").expect("valid path");
        assert_eq!(pn.as_str(), r"\\.\pipe\uffs-test");
        assert_eq!(format!("{pn}"), r"\\.\pipe\uffs-test");
    }

    #[test]
    fn parse_rejects_missing_prefix() {
        let raw = "uffs-no-prefix";
        match PipeName::parse(raw) {
            Err(PipeNameError::BadPrefix { raw: returned }) => {
                assert_eq!(returned, raw, "BadPrefix must echo the rejected input");
            }
            other => panic!("expected BadPrefix, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_empty_name_after_prefix() {
        match PipeName::parse(PipeName::PREFIX) {
            Err(PipeNameError::Empty) => {}
            other => panic!("expected Empty, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_overlong_path() {
        // Build prefix + 257 ASCII chars → total 266 chars, well over the
        // 256-char Win32 named-pipe path limit.
        let mut raw = String::from(PipeName::PREFIX);
        raw.extend(core::iter::repeat_n('x', PipeName::MAX_TOTAL_LEN));
        match PipeName::parse(raw) {
            Err(PipeNameError::TooLong { len }) => {
                assert!(
                    len > PipeName::MAX_TOTAL_LEN,
                    "TooLong must report the actual length: got {len}"
                );
            }
            other => panic!("expected TooLong, got {other:?}"),
        }
    }

    #[test]
    fn for_current_user_round_trips_through_parse() {
        // Anything `for_current_user` produces must, by contract, also be
        // accepted by `parse` — they're two doors on the same invariant.
        let name = PipeName::for_current_user().expect("SID resolvable in tests");
        let reparsed = PipeName::parse(name.as_str()).expect("self-round-trip");
        assert_eq!(reparsed, name);
    }

    #[test]
    fn user_sid_string_parses() {
        let sid = current_user_sid_string().expect("SID resolvable in tests");
        assert!(
            sid.starts_with("S-"),
            "SDDL-form SIDs start with 'S-': got {sid}"
        );
    }

    #[test]
    fn owner_only_sd_builds_and_drops_cleanly() {
        let sd = OwnerOnlySd::for_current_user().expect("SD build");
        let sa = sd.as_security_attributes();
        assert!(!sa.lpSecurityDescriptor.is_null());
        drop(sd); // must not panic on LocalFree
    }

    #[test]
    fn fnv1a_known_vector() {
        // FNV-1a-64 of "foobar" per the reference implementation.
        //
        // Source: http://www.isthe.com/chongo/src/fnv/test_fnv.c (vector
        // entry for `"foobar"`, 64-bit).  Cross-checked with a pure-Python
        // implementation using the same OFFSET / PRIME constants above:
        //
        //     OFFSET = 0xCBF29CE484222325
        //     PRIME  = 0x100000001B3
        //     fnv1a("foobar") == 0x85944171F73967E8
        //
        // The previous hardcoded `0x8584_8993_3606_5430` was stale: this
        // test is inside a `#![cfg(windows)]` module, `pr-fast.yml`'s
        // `Tests` job runs on `ubuntu-22.04`, and `Windows compile check`
        // is compile-only — so the assertion had NEVER executed in CI
        // before `preview-artifacts.yml`'s `smoke-windows` job (first
        // ran 2026-04-24, PR #52 run 24873800282).  See tracking issue
        // #53 and `docs/architecture/dev-flow-implementation-plan.md`
        // §10.5 bug #5 for the full diagnostic.
        assert_eq!(fnv1a_64(b"foobar"), 0x8594_4171_F739_67E8);
    }
}
