// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Connect to the Broker-created private control pipe as a client.
//!
//! The Broker (running as `LocalSystem`, same identity this helper
//! inherits) creates the named pipe *before* spawning this process, so
//! in the normal case the first connect attempt succeeds; the retry loop
//! below is a safety margin, not a load-bearing race handler.

use core::time::Duration;
use std::fs::File;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::FromRawHandle as _;

use windows::Win32::Foundation::ERROR_PIPE_BUSY;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE,
    OPEN_EXISTING,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;
use windows::core::PCWSTR;

/// Maximum connect attempts before giving up.
const MAX_ATTEMPTS: u32 = 50;

/// Delay between attempts that aren't following an explicit
/// `ERROR_PIPE_BUSY` wait.
const RETRY_DELAY: Duration = Duration::from_millis(100);

/// Connect to `pipe_name` as a duplex client, retrying briefly if the
/// Broker hasn't finished creating the pipe instance yet.
///
/// # Errors
/// Returns an error if every attempt fails.
#[expect(
    unsafe_code,
    reason = "CreateFileW and WaitNamedPipeW are FFI calls; File::from_raw_handle \
              takes ownership of a HANDLE this function itself just opened"
)]
pub(crate) fn connect(pipe_name: &str) -> anyhow::Result<File> {
    let wide_name: Vec<u16> = std::ffi::OsStr::new(pipe_name)
        .encode_wide()
        .chain(Some(0))
        .collect();

    for attempt in 0..MAX_ATTEMPTS {
        // SAFETY: `wide_name` is a NUL-terminated UTF-16 buffer valid for
        // the duration of this call.
        let result = unsafe {
            CreateFileW(
                PCWSTR(wide_name.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        };

        match result {
            Ok(handle) => {
                // SAFETY: `handle` is a valid, freshly opened, exclusively
                // owned HANDLE to a byte-mode duplex pipe; `File` takes
                // ownership and will `CloseHandle` it on drop.
                let file = unsafe { File::from_raw_handle(handle.0.cast::<core::ffi::c_void>()) };
                return Ok(file);
            }
            Err(err) if err.code() == ERROR_PIPE_BUSY.to_hresult() => {
                // SAFETY: `wide_name` is valid for the call; waits up to
                // 5s for an instance to free up before retrying.
                let _wait_result = unsafe { WaitNamedPipeW(PCWSTR(wide_name.as_ptr()), 5000) };
            }
            Err(err) if attempt + 1 == MAX_ATTEMPTS => {
                anyhow::bail!("CreateFileW failed connecting to {pipe_name}: {err}");
            }
            Err(_err) => {
                std::thread::sleep(RETRY_DELAY);
            }
        }
    }
    anyhow::bail!("failed to connect to {pipe_name} after {MAX_ATTEMPTS} attempts")
}
