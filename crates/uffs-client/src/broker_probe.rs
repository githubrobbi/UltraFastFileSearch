// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Detect a running UFFS Access Broker.
//!
//! The broker is an elevated Windows service that vends read-only NTFS
//! volume handles to a non-elevated daemon.
//! [`crate::broker_probe::broker_pipe_present`] lets the client's daemon-spawn
//! logic ([`crate::daemon_spawn`]) decide whether a non-elevated `uffs` can
//! start the daemon anyway (the daemon then obtains handles from the broker)
//! instead of returning [`crate::error::ClientError::DaemonNeedsElevation`].
//!
//! This whole module is `#[cfg(windows)]` (declared so in `lib.rs`), so
//! it carries no per-item cfg gates.

/// Return `true` when the UFFS Access Broker named pipe exists — i.e. the
/// broker Windows service is installed and running.
///
/// Uses `WaitNamedPipeW`, which checks pipe **availability without
/// connecting**. The previous `GetFileAttributesW` probe *opened* the pipe to
/// read its attributes, which the broker saw as a real connection and logged as
/// a rejected `uffs.exe` client on **every** search (FU-6) — wasteful, and it
/// consumed a pipe instance the single-instance broker then had to recover.
/// `WaitNamedPipeW` never opens the pipe, so the broker sees nothing.
///
/// Presence semantics: an available instance → `Ok`; an existing-but-busy pipe
/// → `ERROR_SEM_TIMEOUT`; a missing pipe → `ERROR_FILE_NOT_FOUND`.  Only
/// `ERROR_FILE_NOT_FOUND` is treated as "no broker"; everything else is
/// present, so a momentarily-busy broker isn't a false negative (the daemon's
/// real handle request is the authoritative test either way).
pub(crate) fn broker_pipe_present() -> bool {
    use std::os::windows::ffi::OsStrExt as _;

    use uffs_broker_protocol::PIPE_NAME;
    use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
    use windows::Win32::System::Pipes::WaitNamedPipeW;
    use windows::core::PCWSTR;

    let wide: Vec<u16> = std::ffi::OsStr::new(PIPE_NAME)
        .encode_wide()
        .chain(Some(0))
        .collect();

    // 1 ms: we only need existence, not to actually wait for a free instance.
    #[expect(unsafe_code, reason = "WaitNamedPipeW non-connecting existence probe")]
    // SAFETY: `wide` is a null-terminated UTF-16 buffer that outlives the call;
    // `WaitNamedPipeW` only reads through the pointer and opens no handle.
    let available = unsafe { WaitNamedPipeW(PCWSTR(wide.as_ptr()), 1) };

    // `BOOL::ok()` maps `true` → `Ok(())` and `false` → `Err` carrying
    // `GetLastError`.  Only a missing pipe (`ERROR_FILE_NOT_FOUND`) means "no
    // broker"; an existing-but-busy pipe (`ERROR_SEM_TIMEOUT`) or any other
    // error is treated as present.
    match available.ok() {
        Ok(()) => true,
        Err(err) => err.code() != ERROR_FILE_NOT_FOUND.to_hresult(),
    }
}
