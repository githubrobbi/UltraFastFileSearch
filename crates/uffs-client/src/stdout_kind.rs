// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Detect the kind of destination `stdout` is connected to.
//!
//! Used by the thin CLI to choose the cheapest output strategy for the
//! current invocation:
//!
//! - [`StdoutKind::Null`] — `> NUL` on Windows or `> /dev/null` on Unix. The
//!   CLI asks the daemon to skip row materialisation + `paths_blob`
//!   construction + IPC row transfer entirely (saves ~20-30 ms on medium result
//!   sets by avoiding a 3.5 MB pipe transfer whose bytes would be discarded
//!   anyway).
//! - [`StdoutKind::Terminal`] — interactive console / TTY.  Prefer a single
//!   large write over per-line `writeln!` to minimise console syscall count
//!   (Phase 3.2 in `docs/research/perf-phase3-output-optimization.md`).
//! - [`StdoutKind::Pipe`] / [`StdoutKind::File`] — redirected output. Either a
//!   `BufWriter` or a single-buffer render works; used as a fallback label when
//!   neither `Null` nor `Terminal` applies.
//! - [`StdoutKind::Unknown`] — detection failed for any reason.  Treat as
//!   `Pipe` (the safe default: no NUL short-circuit, no TTY-specific batching).
//!
//! The module is intentionally zero-cost: only the entry point
//! [`StdoutKind::detect`] reaches out to the OS, and it is called once
//! per CLI invocation.

/// Classification of the process's standard output destination.
///
/// # `#[non_exhaustive]` decision (Phase 3b §3.6)
///
/// **Kept exhaustive.**  The CLI's NUL-short-circuit / TTY-batching /
/// pipe-default dispatch in [`crate::shmem::write_search_results`]
/// and the daemon-side fast-path selector both `match` exhaustively
/// over this enum — the compile-time exhaustiveness check is the
/// safety net that guarantees every newly-added stdout destination
/// (e.g. a future shared-memory transport) gets explicit handling at
/// both call sites.  This is the playbook §3.6 "state-machine /
/// dispatch enum" exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdoutKind {
    /// Interactive terminal / console (TTY).
    Terminal,
    /// Redirected to a regular file (e.g. `> out.csv`).
    File,
    /// Redirected to a pipe (e.g. `| head`, or a Windows named pipe).
    Pipe,
    /// Redirected to the null device (`> NUL` on Windows, `> /dev/null`
    /// on Unix) — output would be discarded by the kernel.
    Null,
    /// Detection failed or the handle is an OS-specific shape not
    /// covered by the other variants.  Callers should treat this the
    /// same as [`Self::Pipe`] (safe default: no NUL fast path, no
    /// TTY-only batching).
    Unknown,
}

impl StdoutKind {
    /// Detect the kind of destination `stdout` is currently connected to.
    ///
    /// Performs one or two syscalls on first call; the result is not
    /// cached because the process's stdout handle can theoretically be
    /// replaced at runtime (e.g. via `dup2`).  In practice the CLI
    /// calls this exactly once at entry.
    #[must_use]
    pub fn detect() -> Self {
        #[cfg(unix)]
        {
            platform_unix::detect()
        }
        #[cfg(windows)]
        {
            platform_windows::detect()
        }
        #[cfg(not(any(unix, windows)))]
        {
            Self::Unknown
        }
    }

    /// Returns `true` when stdout is the null device (output discarded).
    #[must_use]
    pub const fn is_null(self) -> bool {
        matches!(self, Self::Null)
    }

    /// Returns `true` when stdout is an interactive terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }
}

// ── Platform-aware single-buffer write (Phase 3.3) ─────────────────────

/// Write a UTF-8 buffer to stdout via the platform's fastest path.
///
/// * On **Windows**, when stdout is a real console ([`StdoutKind::Terminal`]),
///   transcodes `buf` to UTF-16 once and issues one or more `WriteConsoleW`
///   calls.  This bypasses both Rust stdio's per-chunk UTF-8 validity prescan
///   *and* the narrow-CRT codepage translation that the legacy conhost would
///   otherwise apply to `WriteFile` output — `WriteConsoleW` speaks UTF-16
///   directly, which is what the console itself uses internally.
///
/// * Everywhere else — Unix, Windows pipe/file/NUL — falls through to
///   `stdout.lock().write_all(buf)`, which is already optimal: the kernel write
///   path doesn't touch the bytes.
///
/// The caller supplies the complete rendered buffer (typically from the
/// Phase 3.2 single-buffer render in `uffs-cli`).  Returning
/// [`std::io::Result`] keeps this a pure-library surface; callers can
/// layer `anyhow::Context` on top as needed.
///
/// # Errors
///
/// Returns any I/O error surfaced by the underlying `write_all` call or
/// by the Windows `GetStdHandle` / `WriteConsoleW` FFI.
pub fn write_stdout_buffer(buf: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    #[cfg(windows)]
    {
        if matches!(StdoutKind::detect(), StdoutKind::Terminal) {
            return platform_windows::write_to_console_w(buf);
        }
    }
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(buf)
}

/// Transcode a UTF-8 byte buffer to UTF-16.
///
/// Not gated on `#[cfg(windows)]` so the full suite of UTF-8 / UTF-16
/// edge cases (multibyte sequences, surrogate pairs, invalid bytes) can
/// be pinned by unit tests on every host OS.  The Windows console path
/// is the only production consumer today.
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::InvalidData`] when `buf` is not
/// well-formed UTF-8.  `WriteConsoleW` cannot represent invalid UTF-8
/// anyway, so surfacing the error up-front is strictly better than a
/// mangled console write.
pub fn utf8_to_utf16(buf: &[u8]) -> std::io::Result<Vec<u16>> {
    let utf8 = core::str::from_utf8(buf)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    Ok(utf8.encode_utf16().collect())
}

// ── Unix implementation ────────────────────────────────────────────────
//
// Uses `fstat` on fd 1 to read the mode bits.  When stdout is a
// character device (e.g. a TTY or `/dev/null`), cross-checks
// `st_rdev` against `stat("/dev/null")` to distinguish NUL from a
// real terminal — `isatty(3)` is already folded into this via the
// `S_IFCHR` + `st_rdev` comparison chain.

/// Unix-specific stdout classifier: `isatty(1)` + `fstat(1)` + device-id
/// match against `/dev/null`.
#[cfg(unix)]
mod platform_unix {
    use std::io::IsTerminal as _;
    use std::os::fd::AsRawFd as _;

    use super::StdoutKind;

    /// Platform entry point invoked by [`super::StdoutKind::detect`].
    pub(super) fn detect() -> StdoutKind {
        // Fast TTY check via the stdlib — covers xterm, Windows Terminal
        // over WSL, Apple Terminal, etc.  This is just `isatty(1)` on
        // Unix but avoids re-implementing it per libc crate.
        if std::io::stdout().is_terminal() {
            return StdoutKind::Terminal;
        }

        let fd = std::io::stdout().as_raw_fd();
        detect_for_fd(fd)
    }

    /// Classify a file descriptor.  Extracted so unit tests can point it
    /// at an arbitrary fd (tempfile, pipe, `/dev/null`, etc.) without
    /// disturbing the process's real stdout.
    #[expect(unsafe_code, reason = "FFI to libc::fstat / libc::stat")]
    pub(crate) fn detect_for_fd(fd: std::os::fd::RawFd) -> StdoutKind {
        // SAFETY: zero-initialising POD (`libc::stat`) — all fields are
        // plain integers; zero is a valid bit pattern for each of them.
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        // SAFETY: `fstat` writes to our valid stack-allocated `stat`
        // struct; any fd error is surfaced through the return value.
        let fstat_rc = unsafe { libc::fstat(fd, &raw mut st) };
        if fstat_rc != 0_i32 {
            return StdoutKind::Unknown;
        }

        let ifmt = st.st_mode & libc::S_IFMT;
        if ifmt == libc::S_IFREG {
            return StdoutKind::File;
        }
        if ifmt == libc::S_IFIFO || ifmt == libc::S_IFSOCK {
            return StdoutKind::Pipe;
        }
        if ifmt != libc::S_IFCHR {
            // Block device, directory, or something exotic — treat as
            // unknown so the CLI falls back to the safe default.
            return StdoutKind::Unknown;
        }

        // Character device: could be a TTY (already excluded above in
        // `detect`, but `detect_for_fd` is called without that prefix)
        // or `/dev/null`.  Compare the device id to `/dev/null`'s.
        //
        // SAFETY: zero-initialising POD (`libc::stat`).
        let mut null_st: libc::stat = unsafe { core::mem::zeroed() };
        // SAFETY: `c"/dev/null"` is a well-formed NUL-terminated C
        // string; `stat` writes into our valid stack allocation.
        let stat_rc = unsafe { libc::stat(c"/dev/null".as_ptr(), &raw mut null_st) };
        if stat_rc == 0_i32 && st.st_rdev == null_st.st_rdev {
            return StdoutKind::Null;
        }

        // Some other character device (e.g. `/dev/tty` when
        // `is_terminal()` returned `false` for odd reasons).  Return
        // `Terminal` conservatively — the caller will treat it as
        // interactive, which is the safer choice than accidentally
        // suppressing output.
        StdoutKind::Terminal
    }

    #[cfg(test)]
    mod tests {
        use std::io::Write as _;
        use std::os::fd::AsRawFd as _;

        use super::{StdoutKind, detect_for_fd};

        #[test]
        fn regular_file_is_classified_as_file() {
            let tmp = tempfile::NamedTempFile::new().expect("create tempfile");
            let fd = tmp.as_file().as_raw_fd();
            assert_eq!(detect_for_fd(fd), StdoutKind::File);
        }

        #[test]
        fn dev_null_is_classified_as_null() {
            let null = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/null")
                .expect("open /dev/null");
            assert_eq!(detect_for_fd(null.as_raw_fd()), StdoutKind::Null);
        }

        #[test]
        #[expect(
            unsafe_code,
            reason = "FFI to libc::pipe / libc::close for a test fixture"
        )]
        fn pipe_is_classified_as_pipe() {
            // `libc::pipe` returns a pair of fds; the write end is a
            // FIFO, which is the shape `|` produces between shell
            // stages.
            let mut fds = [0_i32; 2];
            // SAFETY: pipe writes two valid fds into `fds`.
            let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
            assert_eq!(rc, 0_i32, "libc::pipe must succeed");
            let kind = detect_for_fd(fds[1]);
            // SAFETY: closing the read-end fd we own.  Binding the
            // result (even though we ignore errors) keeps the `unsafe`
            // block a pure expression, which satisfies both
            // `semicolon-{inside,outside}-block` clippy rules at once.
            // Each close gets its own block to satisfy
            // `multiple-unsafe-ops-per-block`.
            let _close_read_rc: libc::c_int = unsafe { libc::close(fds[0]) };
            // SAFETY: closing the write-end fd we own.
            let _close_write_rc: libc::c_int = unsafe { libc::close(fds[1]) };
            assert_eq!(kind, StdoutKind::Pipe);
        }

        #[test]
        fn invalid_fd_is_classified_as_unknown() {
            // fd -1 is always invalid.  `fstat` returns -1 / EBADF.
            assert_eq!(detect_for_fd(-1), StdoutKind::Unknown);
        }

        #[test]
        fn write_to_detected_file_still_works() {
            // Sanity: detection does not perturb the fd it inspects.
            let mut tmp = tempfile::NamedTempFile::new().expect("create tempfile");
            let fd = tmp.as_file().as_raw_fd();
            assert_eq!(detect_for_fd(fd), StdoutKind::File);
            tmp.write_all(b"hello\n").expect("write after detect");
        }
    }
}

// ── Windows implementation ─────────────────────────────────────────────
//
// `GetFileType` classifies the handle into DISK / PIPE / CHAR / UNKNOWN.
// Only `CHAR` is ambiguous (console vs NUL vs other character device) —
// we resolve it by calling `GetConsoleMode`, which succeeds for a real
// console handle and fails for NUL.

/// Windows-specific stdout classifier via `GetFileType` + `GetConsoleMode`.
#[cfg(windows)]
mod platform_windows {
    use std::os::windows::io::AsRawHandle as _;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE, FILE_TYPE_UNKNOWN, GetFileType,
    };
    use windows::Win32::System::Console::{
        CONSOLE_MODE, GetConsoleMode, GetStdHandle, STD_OUTPUT_HANDLE, WriteConsoleW,
    };

    use super::StdoutKind;

    /// Platform entry point invoked by [`super::StdoutKind::detect`].
    pub(super) fn detect() -> StdoutKind {
        let handle = HANDLE(std::io::stdout().as_raw_handle().cast());
        detect_for_handle(handle)
    }

    /// Maximum UTF-16 code units per `WriteConsoleW` call.
    ///
    /// `WriteConsoleW` accepts a `DWORD` count (up to `u32::MAX`) but
    /// conhost has historically exhibited write-size-sensitive bugs
    /// under memory pressure on very large buffers (≥ ~1 MiB).  64 KiB
    /// chars (128 KiB bytes) is the well-trodden safe ceiling used by
    /// `termcolor`, `anstream`, and msvcrt's own console path.
    const WRITE_CONSOLE_CHUNK_CHARS: usize = 64 * 1024;

    /// Write `buf` to the real Windows console via `WriteConsoleW`.
    ///
    /// Performs **one** UTF-8 → UTF-16 transcode, then one or more
    /// chunked `WriteConsoleW` calls (chunked purely as a conhost
    /// robustness measure — a single call would be legal per the API
    /// contract).
    ///
    /// The caller must have already confirmed that stdout is a real
    /// console (via [`super::StdoutKind::detect`]); calling this on
    /// a pipe/file/NUL stdout would fail at `WriteConsoleW` with
    /// `ERROR_INVALID_HANDLE`.
    #[expect(unsafe_code, reason = "FFI to GetStdHandle + WriteConsoleW")]
    pub(super) fn write_to_console_w(buf: &[u8]) -> std::io::Result<()> {
        let utf16 = super::utf8_to_utf16(buf)?;
        if utf16.is_empty() {
            return Ok(());
        }

        // SAFETY: `GetStdHandle` is a documented, read-only API that
        // returns a handle to the process's standard output device.
        // It takes a static enum constant — no pointers, no allocation.
        let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }.map_err(std::io::Error::other)?;
        if handle.is_invalid() {
            return Err(std::io::Error::from_raw_os_error(6_i32)); // ERROR_INVALID_HANDLE
        }

        for chunk in utf16.chunks(WRITE_CONSOLE_CHUNK_CHARS) {
            let mut written: u32 = 0;
            // SAFETY: `chunk` is a shared borrow of a `Vec<u16>` we own,
            // so the slice reference the `windows` binding derives a
            // `*const u16` + length from is valid for the duration of
            // the call.  `&raw mut written` is a valid out-param.
            // `None` for `lpreserved` is the documented value for all
            // current Windows versions.
            let result = unsafe { WriteConsoleW(handle, chunk, Some(&raw mut written), None) };
            result.map_err(std::io::Error::other)?;
            if written == 0_u32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "WriteConsoleW reported zero chars written",
                ));
            }
        }
        Ok(())
    }

    /// Classify a Win32 handle.  Extracted so unit tests can point it
    /// at a tempfile / pipe handle without disturbing the real stdout.
    #[expect(unsafe_code, reason = "FFI to GetFileType / GetConsoleMode")]
    pub(crate) fn detect_for_handle(handle: HANDLE) -> StdoutKind {
        if handle.is_invalid() {
            return StdoutKind::Unknown;
        }

        // SAFETY: `GetFileType` is read-only and accepts any HANDLE,
        // returning `FILE_TYPE_UNKNOWN` for ones it can't classify.
        let ftype = unsafe { GetFileType(handle) };

        if ftype == FILE_TYPE_DISK {
            return StdoutKind::File;
        }
        if ftype == FILE_TYPE_PIPE {
            return StdoutKind::Pipe;
        }
        if ftype == FILE_TYPE_UNKNOWN {
            return StdoutKind::Unknown;
        }
        if ftype != FILE_TYPE_CHAR {
            return StdoutKind::Unknown;
        }

        // FILE_TYPE_CHAR: console, NUL, or another character device.
        // `GetConsoleMode` succeeds only for a real console handle.
        let mut mode = CONSOLE_MODE::default();
        // SAFETY: handle is valid (checked above), mode is a valid
        // out-param pointer.
        let is_console = unsafe { GetConsoleMode(handle, &raw mut mode) }.is_ok();
        if is_console {
            StdoutKind::Terminal
        } else {
            // Character device that is not a console — on Windows this
            // is overwhelmingly `\\.\NUL`.  Treat as Null to enable the
            // output-skip fast path.  If someone ever redirects stdout
            // to `\\.\COM1` or similar, the worst outcome is suppressed
            // output when they wanted to see it, which is the same as
            // `> NUL` would be for them anyway.
            StdoutKind::Null
        }
    }

    #[cfg(test)]
    mod tests {
        use std::fs::OpenOptions;
        use std::os::windows::io::AsRawHandle as _;

        use windows::Win32::Foundation::HANDLE;

        use super::{StdoutKind, detect_for_handle};

        #[test]
        fn regular_file_is_classified_as_file() {
            let tmp = tempfile::NamedTempFile::new().expect("create tempfile");
            let handle = HANDLE(tmp.as_file().as_raw_handle().cast());
            assert_eq!(detect_for_handle(handle), StdoutKind::File);
        }

        #[test]
        fn nul_device_is_classified_as_null() {
            let nul = OpenOptions::new()
                .write(true)
                .open("NUL")
                .expect("open NUL");
            let handle = HANDLE(nul.as_raw_handle().cast());
            assert_eq!(detect_for_handle(handle), StdoutKind::Null);
        }

        #[test]
        fn invalid_handle_is_classified_as_unknown() {
            assert_eq!(detect_for_handle(HANDLE::default()), StdoutKind::Unknown);
        }
    }
}

#[cfg(test)]
mod shared_tests {
    use super::{StdoutKind, utf8_to_utf16};

    #[test]
    fn is_null_matches_enum() {
        assert!(StdoutKind::Null.is_null());
        assert!(!StdoutKind::Terminal.is_null());
        assert!(!StdoutKind::File.is_null());
        assert!(!StdoutKind::Pipe.is_null());
        assert!(!StdoutKind::Unknown.is_null());
    }

    #[test]
    fn is_terminal_matches_enum() {
        assert!(StdoutKind::Terminal.is_terminal());
        assert!(!StdoutKind::Null.is_terminal());
        assert!(!StdoutKind::File.is_terminal());
        assert!(!StdoutKind::Pipe.is_terminal());
        assert!(!StdoutKind::Unknown.is_terminal());
    }

    /// `detect()` must never panic regardless of what stdout is pointing
    /// at in the test harness (typically a pipe under `cargo test`).
    #[test]
    fn detect_does_not_panic() {
        let _kind = StdoutKind::detect();
    }

    // ── Phase 3.3: `utf8_to_utf16` transcode invariants ───────────

    /// Empty input → empty output.  No panic, no spurious BOM.
    #[test]
    fn utf8_to_utf16_empty_input_returns_empty() {
        let out = utf8_to_utf16(b"").expect("empty UTF-8 is valid");
        assert!(out.is_empty());
    }

    /// Pure ASCII round-trips as zero-extended 16-bit code units —
    /// exactly the same bytes the CLI would push to conhost before
    /// Phase 3.3.
    #[test]
    fn utf8_to_utf16_ascii_zero_extends() {
        let out = utf8_to_utf16(b"hello").expect("ASCII is valid UTF-8");
        assert_eq!(out, [0x68_u16, 0x65, 0x6C, 0x6C, 0x6F]);
    }

    /// Multibyte BMP codepoints collapse to a single UTF-16 code unit.
    /// `é` is `0xC3 0xA9` in UTF-8, `0x00E9` in UTF-16 — confirms the
    /// narrow-CRT codepage translation bug is gone (it would have
    /// produced `0x3F ?` on CP437 or garbled on CP1252).
    #[test]
    fn utf8_to_utf16_multibyte_bmp_maps_to_single_unit() {
        let out = utf8_to_utf16("café".as_bytes()).expect("UTF-8");
        assert_eq!(out, [0x63_u16, 0x61, 0x66, 0x00E9]);
    }

    /// Astral-plane codepoints (U+1D54F, MATHEMATICAL DOUBLE-STRUCK X)
    /// must split into a UTF-16 surrogate pair.  `termcolor` and
    /// `anstream` rely on this exact pairing; a bug here would produce
    /// two replacement characters on screen.
    #[test]
    fn utf8_to_utf16_astral_codepoint_produces_surrogate_pair() {
        let out = utf8_to_utf16("𝕏".as_bytes()).expect("UTF-8");
        // U+1D54F → high 0xD835, low 0xDD4F
        assert_eq!(out, [0xD835_u16, 0xDD4F]);
    }

    /// Invalid UTF-8 must surface as `InvalidData`, not silently
    /// produce mojibake on the console.
    #[test]
    fn utf8_to_utf16_invalid_utf8_is_invalid_data_error() {
        // 0xFF is never valid as a standalone UTF-8 byte.
        let err = utf8_to_utf16(&[0xFF_u8]).expect_err("must reject invalid UTF-8");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// A 128 KiB buffer (twice the `WriteConsoleW` chunk ceiling)
    /// transcodes cleanly — pins that the transcode itself has no
    /// hidden chunking assumption.  The chunking lives in the
    /// Windows-only `write_to_console_w`, not here.
    #[test]
    fn utf8_to_utf16_large_input_transcodes_fully() {
        let input = "a".repeat(128 * 1024);
        let out = utf8_to_utf16(input.as_bytes()).expect("ASCII");
        assert_eq!(out.len(), input.len());
        assert!(out.iter().all(|&code| code == 0x61_u16));
    }
}
