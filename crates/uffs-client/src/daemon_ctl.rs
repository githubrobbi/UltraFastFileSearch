// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Daemon lifecycle helpers: socket/pipe paths, PID file, identity
//! verification, deep-health-check toggle, keepalive, exe discovery.
//!
//! # Module layout
//!
//! Scope-cohesive siblings hold the rest of the daemon-control
//! surface.  **Call each item from the module that defines it** —
//! we deliberately do not cascade re-exports through `daemon_ctl`:
//!
//! | Module                         | Responsibility                                                        |
//! |--------------------------------|-----------------------------------------------------------------------|
//! | `daemon_ctl` (this)            | paths, identity verify, keepalive, exe discovery, health-check toggle |
//! | `crate::daemon_spawn`          | `ElevationPolicy`, `spawn_daemon`, arg quoting, Windows UAC helpers   |
//! | `crate::daemon_child`          | `DaemonChildHandle` and the cross-platform `try_wait` poll            |

use std::path::PathBuf;

/// Platform-specific socket/pipe path (must match daemon's `ipc::socket_path`).
///
/// On Windows this returns the legacy `AF_UNIX` socket path, which is still
/// served by the daemon as a fallback during the named-pipe transition.
/// New code on Windows should prefer the Windows-only `pipe_name`
/// helper in this module — it avoids the `ws2_32.dll` import
/// (+54 ms launch cost).
#[must_use]
pub fn socket_path() -> PathBuf {
    let base = dirs_next::data_local_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    #[cfg(target_os = "macos")]
    {
        base.join("uffs").join("daemon.sock")
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_RUNTIME_DIR").map_or_else(
            |_| base.join("uffs").join("daemon.sock"),
            |runtime_dir| PathBuf::from(runtime_dir).join("uffs").join("daemon.sock"),
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        base.join("uffs").join("daemon.sock")
    }
}

/// Windows named-pipe path (`\\.\pipe\uffs-<hash>`).
///
/// This is the preferred IPC transport on Windows — replaces `AF_UNIX`
/// to avoid the `ws2_32.dll` launch overhead.  The name is deterministic
/// per user (FNV-1a of the user SID); see [`uffs_security::pipe`] for
/// the security model.
///
/// # Errors
///
/// Returns an error if the user SID cannot be resolved, which should
/// only happen on a severely broken Windows session.
#[cfg(windows)]
pub fn pipe_name() -> std::io::Result<uffs_security::pipe::PipeName> {
    uffs_security::pipe::PipeName::for_current_user()
}

/// Commit C — deep health check: is the check enabled?
///
/// Off if `UFFS_CLIENT_SKIP_HEALTH_CHECK=1` / `true` / `yes`
/// (case-insensitive, whitespace-trimmed — PowerShell often sets env
/// vars with a trailing newline after `$env:X = "1"`).  The health
/// check is on by default.
///
/// Cost when on: ~200–600 µs per connect (one local-IPC `drives`
/// round-trip).  Turn off for latency-critical scripts or when the
/// daemon is known to be misbehaving and you want to inspect it
/// manually.
#[must_use]
pub(crate) fn deep_health_check_enabled() -> bool {
    let Ok(val) = std::env::var("UFFS_CLIENT_SKIP_HEALTH_CHECK") else {
        return true;
    };
    let trimmed = val.trim();
    !(trimmed == "1" || trimmed.eq_ignore_ascii_case("true") || trimmed.eq_ignore_ascii_case("yes"))
}

/// S4.3.4: Verify daemon identity after connecting (warn-only).
///
/// **Legacy variant kept for backward compatibility** — if identity
/// verification fails, this only logs a `tracing::warn!` and returns,
/// leaving the caller with an untrusted connection.  New call sites
/// should prefer `verify_daemon_after_connect_strict`, which refuses
/// to continue on mismatch.
pub fn verify_daemon_after_connect() {
    let pid_path = pid_file_path();
    if !pid_path.exists() {
        tracing::debug!("No PID file found, skipping daemon identity verification");
        return;
    }
    if !crate::verify::verify_daemon_pid_file(&pid_path) {
        tracing::warn!(
            path = %pid_path.display(),
            "Daemon identity verification failed — proceed with caution"
        );
    }
}

/// Verify daemon identity after connecting — strict variant.
///
/// Reads the PID file written by the daemon at startup, re-computes the
/// FNV-1a hash of the connected daemon's exe path, and compares it with
/// the hash stored in the PID file.  A mismatch means one of:
///
/// * A **rogue process** bound the named pipe / socket before the real daemon
///   could (PID recycled, path hijacked, etc.).
/// * The daemon binary was **swapped on disk** after the PID file was written —
///   the exe we just connected to is not what we expected.
/// * The daemon on the pipe is from a different install (different build,
///   different drive letter, etc.).
///
/// In all three cases, continuing to talk to that process is unsafe —
/// we'd be forwarding `--data-dir` paths, search patterns, and RPC
/// credentials to an unknown peer.  This function therefore returns a
/// [`crate::error::ClientError::ConnectionFailed`] with the diagnostic
/// details so the caller can disconnect and either error out or retry.
///
/// If the PID file is missing or unreadable (e.g. first-ever run, or
/// the daemon hasn't finished writing it), this returns `Ok(())` — we
/// trade strictness for availability in the startup race window.
///
/// Cost: ~100–200 µs per call (one file read + one OS exe-path lookup
/// + one FNV-1a hash over the path string — no file hashing involved).
///
/// # Errors
///
/// Returns [`crate::error::ClientError::ConnectionFailed`] when the
/// PID file exists and its embedded exe-path hash does not match the
/// peer's actual exe path.  The error message includes the PID file
/// location so callers can report it verbatim.
pub(crate) fn verify_daemon_after_connect_strict() -> Result<(), crate::error::ClientError> {
    verify_daemon_after_connect_strict_at(&pid_file_path())
}

/// Testable inner: verify the daemon identity against a specific
/// PID-file path.
///
/// Production callers use [`verify_daemon_after_connect_strict`],
/// which reads the canonical path from [`pid_file_path`].  This
/// variant lets tests point at a tempfile without touching the
/// user's real daemon state.  Marked `#[doc(hidden)]` because it is
/// an implementation detail of the strict-verify contract; its
/// signature and semantics may change.
///
/// # Errors
///
/// Returns [`crate::error::ClientError::ConnectionFailed`] when the
/// PID file at `pid_path` exists and its embedded exe-path hash
/// does not match the peer's actual exe path.  Returns `Ok(())`
/// when the file is missing, unparseable, or the hashes match.
#[doc(hidden)]
pub(crate) fn verify_daemon_after_connect_strict_at(
    pid_path: &std::path::Path,
) -> Result<(), crate::error::ClientError> {
    if !pid_path.exists() {
        tracing::debug!("No PID file found, skipping daemon identity verification");
        return Ok(());
    }
    if crate::verify::verify_daemon_pid_file(pid_path) {
        return Ok(());
    }
    tracing::warn!(
        path = %pid_path.display(),
        "Daemon identity verification FAILED — refusing connection"
    );
    Err(crate::error::ClientError::ConnectionFailed(format!(
        "Daemon identity verification failed (PID file: {}). The process on \
         the IPC endpoint does not match the exe hash recorded when the \
         daemon started — another process may have hijacked the pipe/socket, \
         or the daemon binary was replaced on disk.",
        pid_path.display(),
    )))
}

/// Send a keepalive message using blocking std I/O (works on all platforms).
///
/// On Unix, opens the `AF_UNIX` socket at `sock_path`.
/// On Windows, opens the named pipe (no `ws2_32` cost) — `sock_path` is
/// unused but kept for API stability.
///
/// Only consumed by the async keepalive task, hence the `async` feature
/// gate (matches `connect_keepalive` in `lib.rs`).
#[cfg(feature = "async")]
pub(crate) fn keepalive_send_blocking(sock_path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::net::UnixStream;
        if let Ok(mut stream) = UnixStream::connect(sock_path) {
            let msg = r#"{"jsonrpc":"2.0","id":0,"method":"keepalive"}"#;
            // Surface a failed keepalive at debug level instead of silently
            // dropping it: a write failure here means the daemon connection
            // is gone. It is NOT propagated (the keepalive task has no return
            // channel and the next cycle/connection-check self-corrects), but
            // it is no longer invisible. (WI-6.1)
            if let Err(err) = stream
                .write_all(msg.as_bytes())
                .and_then(|()| stream.write_all(b"\n"))
                .and_then(|()| stream.flush())
            {
                tracing::debug!(error = %err, "keepalive write failed (daemon may be gone)");
            }
        }
    }
    #[cfg(windows)]
    {
        use std::fs::OpenOptions;
        use std::io::Write as _;

        // `sock_path` is unused on Windows — the pipe name is derived
        // from the current user's SID — but we keep the parameter for
        // cross-platform API parity.  Discard explicitly to silence the
        // unused-parameter warning without introducing a suppression.
        _ = sock_path;

        let Ok(name) = pipe_name() else {
            return;
        };
        if let Ok(mut pipe) = OpenOptions::new()
            .read(true)
            .write(true)
            .open(name.as_str())
        {
            let msg = r#"{"jsonrpc":"2.0","id":0,"method":"keepalive"}"#;
            // See the Unix arm: surface a failed keepalive write at debug
            // level (daemon likely gone) rather than dropping it silently;
            // not propagated — the next cycle self-corrects. (WI-6.1)
            if let Err(err) = pipe
                .write_all(msg.as_bytes())
                .and_then(|()| pipe.write_all(b"\n"))
                .and_then(|()| pipe.flush())
            {
                tracing::debug!(error = %err, "keepalive write failed (daemon may be gone)");
            }
        }
    }
}

/// PID file path (must match daemon's lifecycle.rs).
#[must_use]
pub fn pid_file_path() -> PathBuf {
    let base = dirs_next::data_local_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join("uffs").join("daemon.pid")
}

/// Parse a daemon PID file. Returns `(pid, timestamp, exe_hash, nonce)`.
#[must_use]
pub fn parse_pid_file(path: &std::path::Path) -> Option<(u32, u64, u64, String)> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut lines = content.lines();
    let pid: u32 = lines.next()?.parse().ok()?;
    let ts: u64 = lines.next()?.parse().ok()?;
    let hash: u64 = lines.next()?.parse().ok()?;
    let nonce = lines.next()?.to_owned();
    Some((pid, ts, hash, nonce))
}

/// Whether a process with `pid` is currently alive.
///
/// A bare liveness probe used by `uffs --daemon kill` to confirm a terminate
/// actually took effect **before** the PID file is removed. A non-elevated
/// `taskkill /F` against an *elevated* daemon fails silently (Access denied),
/// so the caller must verify rather than trust the exit code — otherwise it
/// deletes the PID file while the process keeps running (an orphaned daemon).
///
/// Unix uses `kill(pid, 0)` (existence check, no signal delivered). Windows
/// filters `tasklist` by PID and confirms the image is `uffsd`, so a recycled
/// PID that is now some *other* process reads as "not our daemon" → dead.
#[must_use]
pub fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // Unix PIDs fit in i32 by spec; the saturating fallback is unreachable.
        let pid_i32 = i32::try_from(pid).unwrap_or(i32::MAX);
        // SAFETY: `kill(pid, 0)` performs a permission/existence check without
        // delivering a signal; `pid` comes from our own PID file.
        #[expect(unsafe_code, reason = "kill(pid, 0) is a safe existence check")]
        let rc = unsafe { libc::kill(pid_i32, 0) };
        rc == 0
    }
    #[cfg(not(unix))]
    {
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .is_ok_and(|output| {
                // AUDIT-OK(bytes): liveness probe via substring match; a lossy
                // decode can only FAIL the match → reads as "not alive"
                // (fail-safe: we never wrongly claim a live daemon is dead).
                let text = String::from_utf8_lossy(&output.stdout);
                text.contains(&pid.to_string()) && text.contains("uffsd")
            })
    }
}

/// Find the `uffs` CLI executable.
///
/// The `$PATH` fallback carries the `.exe` extension on Windows so a bare
/// `uffs` can never be resolved to a legacy `uffs.com` via PATHEXT (`.COM`
/// precedes `.EXE`) if this path is ever handed to a shell / registry entry /
/// logged command rather than spawned directly.
#[must_use]
pub fn find_uffs_exe() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        let name = exe.file_stem().and_then(|stem| stem.to_str()).unwrap_or("");
        if name == "uffs" {
            return exe;
        }
        if let Some(parent) = exe.parent() {
            let uffs_bin = if cfg!(windows) { "uffs.exe" } else { "uffs" };
            let sibling = parent.join(uffs_bin);
            if sibling.exists() {
                return sibling;
            }
        }
    }
    PathBuf::from(if cfg!(windows) { "uffs.exe" } else { "uffs" })
}

/// Find the `uffsd` daemon executable.
///
/// Search order:
/// 1. If the current binary is already `uffsd`, return it.
/// 2. Look for `uffsd` / `uffsd.exe` next to the current binary.
/// 3. Fall back to the platform binary name `uffsd.exe` / `uffsd` on `$PATH` —
///    always `.exe`-qualified on Windows so a bare `uffsd` can never resolve to
///    a legacy `.com` via PATHEXT if handed to a shell.
#[must_use]
pub(crate) fn find_daemon_exe() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        let name = exe.file_stem().and_then(|stem| stem.to_str()).unwrap_or("");
        if name == "uffsd" {
            return exe;
        }
        if let Some(parent) = exe.parent() {
            let daemon_bin = if cfg!(windows) { "uffsd.exe" } else { "uffsd" };
            let sibling = parent.join(daemon_bin);
            if sibling.exists() {
                return sibling;
            }
        }
    }
    PathBuf::from(if cfg!(windows) { "uffsd.exe" } else { "uffsd" })
}

#[cfg(test)]
mod deep_health_check_tests {
    use super::deep_health_check_enabled;

    /// Serialise env-mutating tests in this module — cargo runs unit
    /// tests in parallel by default, and `std::env::set_var` is process-
    /// global, so without this mutex two tests can race on the same
    /// variable and see each other's writes.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper: run `body` with `UFFS_CLIENT_SKIP_HEALTH_CHECK` set to
    /// `value`, then restore it.  Uses `unsafe { std::env::set_var }`
    /// because Rust 2024 marks env mutation as unsafe — the mutex above
    /// guarantees no other test observes the partial write window.
    fn with_skip_env<F: FnOnce()>(value: Option<&str>, body: F) {
        let guard = ENV_LOCK.lock().expect("env mutex poisoned");
        let previous = std::env::var("UFFS_CLIENT_SKIP_HEALTH_CHECK").ok();
        if let Some(val) = value {
            // SAFETY: the mutex above serialises all test-time env writes.
            #[expect(unsafe_code, reason = "std::env::set_var is unsafe in Rust 2024")]
            unsafe {
                std::env::set_var("UFFS_CLIENT_SKIP_HEALTH_CHECK", val);
            }
        } else {
            // SAFETY: same as above.
            #[expect(unsafe_code, reason = "std::env::remove_var is unsafe in Rust 2024")]
            unsafe {
                std::env::remove_var("UFFS_CLIENT_SKIP_HEALTH_CHECK");
            }
        }
        body();
        match previous {
            Some(prev) => {
                // SAFETY: same as above — restore original value under the same lock.
                #[expect(unsafe_code, reason = "std::env::set_var is unsafe in Rust 2024")]
                unsafe {
                    std::env::set_var("UFFS_CLIENT_SKIP_HEALTH_CHECK", prev);
                }
            }
            None => {
                // SAFETY: same as above.
                #[expect(unsafe_code, reason = "std::env::remove_var is unsafe in Rust 2024")]
                unsafe {
                    std::env::remove_var("UFFS_CLIENT_SKIP_HEALTH_CHECK");
                }
            }
        }
        drop(guard);
    }

    /// Default posture: health check is on when the env var is unset.
    #[test]
    fn default_is_enabled() {
        with_skip_env(None, || {
            assert!(deep_health_check_enabled());
        });
    }

    /// Canonical opt-out tokens must disable the health check.  We
    /// accept the three most common truthy spellings (`1`, `true`, `yes`)
    /// case-insensitively, and trim surrounding whitespace so that
    /// PowerShell's `$env:X = "1"` (which often leaves trailing `\r\n`)
    /// still counts.
    #[test]
    fn canonical_truthy_tokens_disable() {
        for token in [
            "1", "true", "TRUE", "True", "yes", "YES", "Yes", "  1  ", " yes\n",
        ] {
            with_skip_env(Some(token), || {
                assert!(
                    !deep_health_check_enabled(),
                    "token {token:?} should disable the health check",
                );
            });
        }
    }

    /// Any other value — including `0`, `false`, the empty string, or
    /// garbage — must keep the health check **on**.  Rationale: the
    /// default posture is "probe the daemon", and the opt-out has to
    /// be explicit to avoid accidentally bypassing robustness because
    /// of a mis-set env var.
    #[test]
    fn non_truthy_values_keep_it_enabled() {
        for token in ["0", "false", "no", "off", "", "maybe", "2", "nope"] {
            with_skip_env(Some(token), || {
                assert!(
                    deep_health_check_enabled(),
                    "token {token:?} should NOT disable the health check",
                );
            });
        }
    }
}

#[cfg(test)]
mod verify_strict_tests {
    use super::verify_daemon_after_connect_strict_at;

    /// FNV-1a 64-bit — must match the hash written by the daemon's
    /// `lifecycle::write_pid_file`.  Hoisted into the test module so
    /// we can forge matching PID files on disk.
    fn fnv1a(bytes: &[u8]) -> u64 {
        let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
        for &byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01B3);
        }
        hash
    }

    /// Missing PID file → `Ok(())`.  Locks in the "fail open during the
    /// first-run / startup-race window" contract: we never want the
    /// identity check to block the very first connect, before the
    /// daemon has had a chance to write its PID file.
    #[test]
    fn missing_pid_file_is_ok() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist.pid");
        assert!(!path.exists());
        assert!(
            verify_daemon_after_connect_strict_at(&path).is_ok(),
            "missing PID file must not block the connect",
        );
    }

    /// Valid PID file whose exe-path hash matches the **current test
    /// process** → `Ok(())`.  This exercises the full success path:
    /// the verifier reads the file, parses pid + hash, looks up the
    /// process's exe path via the platform API, re-computes the
    /// FNV-1a of that path, and confirms equality.
    ///
    /// Using the *test* process as the pretend-daemon is safe because
    /// all the verifier checks is the FNV-1a of the exe-path string —
    /// it doesn't care what the process actually does.
    #[test]
    fn valid_pid_file_for_current_process_is_ok() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.pid");
        let pid = std::process::id();
        let exe = std::env::current_exe().expect("current_exe");
        let hash = fnv1a(exe.to_string_lossy().as_bytes());
        std::fs::write(&path, format!("{pid}\n0\n{hash}\nnonce-xyz\n")).expect("write pid file");
        assert!(
            verify_daemon_after_connect_strict_at(&path).is_ok(),
            "valid-hash PID file pointing at the test process must pass verification",
        );
    }

    /// Tampered PID file (valid live PID, **wrong** exe-path hash) →
    /// `Err(ConnectionFailed)`.  This is the hijacked-pipe scenario
    /// the strict variant was designed to catch: something is alive
    /// at the recorded PID, but its exe is not what we expected, so
    /// the IPC endpoint could be a rogue process and continuing to
    /// talk to it would leak our search arguments.
    #[test]
    fn tampered_pid_file_returns_err() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.pid");
        let pid = std::process::id();
        // Hash of a string that is extremely unlikely to be our own
        // exe path — the verifier will compute the actual hash from
        // our live exe and refuse to match.
        let bogus_hash: u64 = 0xDEAD_BEEF_DEAD_BEEF;
        std::fs::write(&path, format!("{pid}\n0\n{bogus_hash}\nnonce-xyz\n"))
            .expect("write pid file");

        let err = verify_daemon_after_connect_strict_at(&path)
            .expect_err("tampered hash must return Err");
        let crate::error::ClientError::ConnectionFailed(msg) = &err else {
            panic!("expected ClientError::ConnectionFailed, got {err:?}");
        };
        assert!(
            msg.contains("identity verification failed"),
            "error message must explain the failure mode: {msg}",
        );
        assert!(
            msg.contains(path.to_string_lossy().as_ref()),
            "error message must include the offending PID file path: {msg}",
        );
    }

    /// PID file with `hash == 0` falls back to process-name matching
    /// (see `verify::verify_daemon_pid_file`).  Since the test process
    /// is not named `uffsd`, this path returns `false` from the
    /// underlying check, and the strict wrapper then returns `Err`.
    /// Locks in the downgraded check behavior so future refactors do
    /// not accidentally widen it into a silent pass.
    #[test]
    fn zero_hash_falls_back_to_name_check_and_refuses_non_uffsd() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.pid");
        let pid = std::process::id();
        std::fs::write(&path, format!("{pid}\n0\n0\nnonce-xyz\n")).expect("write pid file");

        // The test binary is not named `uffsd`, so the name-based
        // fallback inside `verify::verify_daemon_identity` returns
        // `false`, and the strict wrapper propagates the refusal.
        assert!(
            verify_daemon_after_connect_strict_at(&path).is_err(),
            "hash=0 PID file pointing at a non-uffsd process must be refused",
        );
    }
}
