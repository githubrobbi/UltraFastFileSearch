// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Daemon spawn logic: Unix `Command::spawn`, Windows `CreateProcessW`
//! + optional `ShellExecuteW("runas")`, and shared elevation policy.
//!
//! This is the **canonical home** of `spawn_daemon`,
//! `ElevationPolicy`, `resolve_elevation_policy`, and
//! `elevation_policy_from`.  Import them from
//! `crate::daemon_spawn` (or `uffs_client::daemon_spawn` from
//! outside the crate) — there is intentionally no `pub use`
//! cascade through `daemon_ctl`.

use crate::daemon_child::DaemonChildHandle;

// ── Elevation policy ──────────────────────────────────────────────────────

/// Policy for whether `spawn_daemon` may trigger a Windows UAC prompt.
///
/// Before v0.5.36, `spawn_daemon` on Windows unconditionally used
/// `ShellExecuteW("runas")` whenever the current process was not
/// elevated — so any non-admin shell running `uffs <pattern>` with the
/// daemon stopped would get a UAC dialog as a side-effect.  That was
/// surprising and made piping or scripting the CLI fragile.
///
/// The new default is [`ElevationPolicy::RequireExistingElevation`]:
/// the spawn succeeds only if the current process is already elevated;
/// otherwise it returns [`crate::error::ClientError::DaemonNeedsElevation`] and
/// the CLI renders an actionable message.  Callers that actually want the
/// UAC dialog (e.g. `uffs --daemon start --elevate`) must opt in with
/// [`ElevationPolicy::AllowUacPrompt`].
///
/// Has no effect on Unix — Unix spawn never triggers UAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ElevationPolicy {
    /// Spawn only if this process is already elevated.  If not, return
    /// [`crate::error::ClientError::DaemonNeedsElevation`] without
    /// touching the UI.
    ///
    /// This is the default for every implicit auto-spawn path (e.g.
    /// `UffsClient::connect_with_args`).
    #[default]
    RequireExistingElevation,

    /// When not elevated, request a UAC prompt via `ShellExecuteW`
    /// with the `"runas"` verb.  Preserves the pre-v0.5.36 behavior.
    ///
    /// Used by `uffs --daemon start --elevate` and by auto-spawn paths
    /// when the environment variable `UFFS_ELEVATE=1` is set.
    AllowUacPrompt,
}

/// Pure policy decision used by [`resolve_elevation_policy`].
///
/// Rules, in priority order:
///
/// 1. If `force_allow` is `true` (e.g. `uffs --daemon start --elevate`), return
///    [`ElevationPolicy::AllowUacPrompt`].
/// 2. Otherwise, if `env_value` contains a truthy token (`1`, `true`, `yes`,
///    `on`, case-insensitive — leading/trailing whitespace is trimmed), return
///    [`ElevationPolicy::AllowUacPrompt`].  This is how `UFFS_ELEVATE` is
///    interpreted.
/// 3. Otherwise, return [`ElevationPolicy::RequireExistingElevation`].
///
/// Kept env-free so both the async and sync clients (and tests) can
/// share one decision matrix without racing on real environment state.
#[must_use]
pub(crate) fn elevation_policy_from(force_allow: bool, env_value: Option<&str>) -> ElevationPolicy {
    if force_allow {
        return ElevationPolicy::AllowUacPrompt;
    }
    if let Some(raw) = env_value {
        let normalized = raw.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "1" | "true" | "yes" | "on") {
            return ElevationPolicy::AllowUacPrompt;
        }
    }
    ElevationPolicy::RequireExistingElevation
}

/// Resolve the effective [`ElevationPolicy`] for an implicit
/// auto-spawn.
///
/// Reads the `UFFS_ELEVATE` environment variable once and feeds the
/// result into [`elevation_policy_from`].  `force_allow = true` from
/// an explicit `--elevate` flag short-circuits the env lookup.
#[must_use]
pub(crate) fn resolve_elevation_policy(force_allow: bool) -> ElevationPolicy {
    elevation_policy_from(force_allow, std::env::var("UFFS_ELEVATE").ok().as_deref())
}

/// Whether an `UFFS_NO_AUTOSTART` value disables daemon auto-spawn:
/// any non-empty value other than `0` counts as "disabled".
fn autostart_disabled_from(value: Option<&str>) -> bool {
    value.is_some_and(|text| !text.is_empty() && text != "0")
}

/// Read the `UFFS_NO_AUTOSTART` kill-switch. When set, [`spawn_daemon`]
/// refuses to launch `uffsd`, so a missing daemon fails fast with a
/// spawn error instead of starting one and polling readiness. For
/// operators who manage `uffsd` themselves and for tests, where an
/// auto-spawned daemon is 120 s of nondeterminism and a leaked process
/// per run (CI flake: `other_single_dash_token_is_a_pattern_not_help`,
/// issue #610).
fn autostart_disabled() -> bool {
    autostart_disabled_from(std::env::var("UFFS_NO_AUTOSTART").ok().as_deref())
}

/// The [`autostart_disabled`] refusal, shared by both platform
/// dispatchers so the message can never drift between them.
fn autostart_disabled_error() -> crate::error::ClientError {
    crate::error::ClientError::DaemonStartFailed(
        "daemon autostart is disabled (UFFS_NO_AUTOSTART is set); start `uffsd` yourself or unset it"
            .to_owned(),
    )
}

// ── Spawn dispatchers ─────────────────────────────────────────────────────

/// Spawn the daemon as a detached background process.
///
/// On **Unix**, uses a normal `Command::new` spawn (no elevation needed);
/// the `policy` parameter is ignored.
///
/// On **Windows**, behavior depends on `policy` and the current
/// elevation state:
///
/// | already elevated | policy                        | action                        |
/// |------------------|-------------------------------|-------------------------------|
/// | yes              | any                           | `CreateProcessW` (no UAC)     |
/// | no               | `RequireExistingElevation`    | return `DaemonNeedsElevation` |
/// | no               | `AllowUacPrompt`              | `ShellExecuteW("runas")` + UAC|
///
/// # Errors
///
/// Returns [`crate::error::ClientError::DaemonStartFailed`] if the
/// process creation itself fails, or
/// [`crate::error::ClientError::DaemonNeedsElevation`] if the policy
/// does not allow a UAC prompt in the current elevation state.
#[cfg(unix)]
pub(crate) fn spawn_daemon(
    exe: &std::path::Path,
    args: &[std::ffi::OsString],
    _policy: ElevationPolicy,
) -> Result<DaemonChildHandle, crate::error::ClientError> {
    if autostart_disabled() {
        return Err(autostart_disabled_error());
    }
    // `policy` is Windows-only; the Unix spawn never prompts for
    // elevation.  The parameter stays in the public signature so
    // callers can pass the same value on every platform.
    let merged_args = crate::daemon_resident::apply_resident_marker(args);
    spawn_daemon_unix(exe, &merged_args)
}

/// Windows implementation of [`spawn_daemon`].
///
/// Behavior is decided by `policy` combined with the current
/// elevation state (see [`spawn_daemon_windows`] for the full
/// decision tree).
///
/// # Errors
///
/// Returns [`ClientError`](crate::error::ClientError) on spawn
/// failure, including:
/// * [`crate::error::ClientError::DaemonNeedsElevation`] when the policy
///   forbids UAC and the caller is not elevated.
/// * [`crate::error::ClientError::DaemonStartFailed`] when `CreateProcessW` /
///   `ShellExecuteW` itself rejects the launch.
#[cfg(windows)]
pub(crate) fn spawn_daemon(
    exe: &std::path::Path,
    args: &[std::ffi::OsString],
    policy: ElevationPolicy,
) -> Result<DaemonChildHandle, crate::error::ClientError> {
    if autostart_disabled() {
        return Err(autostart_disabled_error());
    }
    let merged_args = crate::daemon_resident::apply_resident_marker(args);
    spawn_daemon_windows(exe, &merged_args, policy)
}

// ── Platform-specific spawn impls ─────────────────────────────────────────

/// Unix daemon spawn: simple detached process.
/// # Errors
///
/// Returns [`ClientError`](crate::error::ClientError) if the daemon process
/// cannot be spawned.
#[cfg(unix)]
#[expect(
    clippy::single_call_fn,
    reason = "platform-specific helper — clarity over inlining"
)]
fn spawn_daemon_unix(
    exe: &std::path::Path,
    args: &[std::ffi::OsString],
) -> Result<DaemonChildHandle, crate::error::ClientError> {
    let child = std::process::Command::new(exe)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .spawn()
        .map_err(|spawn_err| {
            crate::error::ClientError::DaemonStartFailed(format!(
                "Failed to spawn {}: {spawn_err}",
                exe.display()
            ))
        })?;
    Ok(DaemonChildHandle::from_unix_child(child))
}

/// Windows daemon spawn: elevation-aware.
#[cfg(windows)]
#[expect(
    clippy::single_call_fn,
    reason = "platform-specific helper — clarity over inlining"
)]
fn spawn_daemon_windows(
    exe: &std::path::Path,
    args: &[std::ffi::OsString],
    policy: ElevationPolicy,
) -> Result<DaemonChildHandle, crate::error::ClientError> {
    let elevated = is_elevated();
    tracing::debug!(
        exe = %exe.display(),
        ?args,
        elevated,
        ?policy,
        "spawn_daemon_windows"
    );

    if elevated {
        tracing::debug!("spawning via CreateProcessW (no handle inheritance)");
        return spawn_detached_no_inherit(exe, args);
    }

    match policy {
        ElevationPolicy::AllowUacPrompt => spawn_via_uac_prompt(exe, args),
        ElevationPolicy::RequireExistingElevation => spawn_unelevated_or_refuse(exe, args),
    }
}

/// `RequireExistingElevation` arm of [`spawn_daemon_windows`]: the shell
/// is not elevated and UAC is forbidden.
///
/// Before refusing, check for a running Access Broker: if its named pipe
/// is present the daemon can start as the current (non-elevated) user and
/// obtain volume handles from the broker instead of needing admin itself
/// (the whole point of `uffs-broker --install`; the daemon-side consumer
/// is `uffs-daemon::broker_client`).  With no broker, return
/// [`DaemonNeedsElevation`](crate::error::ClientError::DaemonNeedsElevation)
/// so the CLI renders its recovery help.
#[cfg(windows)]
#[expect(
    clippy::single_call_fn,
    reason = "extracted from spawn_daemon_windows to stay under the cognitive-complexity ceiling"
)]
fn spawn_unelevated_or_refuse(
    exe: &std::path::Path,
    args: &[std::ffi::OsString],
) -> Result<DaemonChildHandle, crate::error::ClientError> {
    if crate::broker_probe::broker_pipe_present() {
        tracing::info!(
            "Not elevated, but the Access Broker pipe is present — spawning the \
             daemon non-elevated; it will obtain volume handles via the broker."
        );
        return spawn_detached_no_inherit(exe, args);
    }
    tracing::info!("Not elevated and policy forbids UAC — returning DaemonNeedsElevation");
    Err(crate::error::ClientError::DaemonNeedsElevation {
        daemon_path: exe.display().to_string(),
    })
}

/// UAC-prompt arm of [`spawn_daemon_windows`].
///
/// `ShellExecuteW("runas")` does not hand back a process handle — the OS
/// shell owns the elevated child — so we cannot poll for early exit on
/// this path.  Return an `opaque` handle; the retry loop falls back to
/// the plain "could not connect after N attempts" error for UAC spawns.
#[cfg(windows)]
fn spawn_via_uac_prompt(
    exe: &std::path::Path,
    args: &[std::ffi::OsString],
) -> Result<DaemonChildHandle, crate::error::ClientError> {
    tracing::debug!("NOT elevated, using ShellExecuteW runas (policy allows UAC)");
    tracing::info!("Not elevated — requesting elevation via UAC prompt");
    shell_execute_elevated(exe, args)?;
    tracing::debug!("ShellExecuteW returned OK");
    Ok(DaemonChildHandle::opaque())
}

// ── CreateProcessW arg quoting (MSVCRT-compatible) ────────────────────────

/// Escape a single command-line argument for `CreateProcessW` per the
/// Microsoft argv-parsing rules used by `CommandLineToArgvW` and the
/// standard C runtime (`__wgetmainargs`).
///
/// Rules (condensed from Raymond Chen's "Everyone quotes command line
/// arguments the wrong way" and the MSVCRT parser source):
///
/// * An **empty** argument must become `""` — otherwise it collapses into the
///   separating space and disappears from the child's argv.  This is exactly
///   what caused the silent `uffs --daemon start` failure (`LOG/Output`): the
///   CLI pushed `["--log-level", ""]` and the child saw only `--log-level`,
///   then consumed the *next* flag as its value.
/// * If the arg contains no whitespace, double-quote, or control chars, emit it
///   verbatim — cheap and readable.
/// * Otherwise wrap in `"..."` and, inside the quotes, double every run of
///   backslashes that precedes a `"`, and escape each `"` as `\"`. Trailing
///   backslashes just before the closing `"` must also be doubled so the
///   closing quote is not interpreted as escaped.
///
/// This function operates on **UTF-16 code units** (`&[u16]`), the native
/// width of a `CreateProcessW` command line, and appends the escaped result
/// to `out` (also `&mut Vec<u16>`).  Working in UTF-16 — rather than the old
/// `&str` → `String` form — means a path containing unpaired surrogates or
/// other non-UTF-8 (WTF-8) sequences survives **losslessly** from the caller's
/// `OsStr` all the way to the child's argv (Category 4, WI-4.2).  The caller
/// derives the `&[u16]` via `OsStr::encode_wide`.
///
/// It is pure code-unit manipulation and is compiled (and unit tested) on
/// every platform even though it is only *called* from
/// [`spawn_detached_no_inherit`] on Windows.  We gate the item on
/// `any(windows, test)` so macOS/Linux release builds don't emit a
/// `dead_code` warning, while `cargo test` still compiles it everywhere
/// and the unit tests run on the ship box.
#[cfg(any(windows, test))]
fn quote_arg_for_createprocess(arg: &[u16], out: &mut Vec<u16>) {
    // UTF-16 code units for the ASCII metacharacters we test against.
    const SPACE: u16 = b' ' as u16;
    const TAB: u16 = b'\t' as u16;
    const NEWLINE: u16 = b'\n' as u16;
    const VTAB: u16 = 0x000B; // vertical tab (\x0b)
    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;

    if arg.is_empty() {
        // An empty argument must become `""` — otherwise it collapses into the
        // separating space and disappears from the child's argv.
        out.push(QUOTE);
        out.push(QUOTE);
        return;
    }
    // Fast path: nothing that needs escaping — emit the code units verbatim.
    let needs_quoting = arg
        .iter()
        .any(|&unit| matches!(unit, SPACE | TAB | NEWLINE | VTAB | QUOTE));
    if !needs_quoting {
        out.extend_from_slice(arg);
        return;
    }

    out.push(QUOTE);
    let mut pending_backslashes: usize = 0;
    for &unit in arg {
        if unit == BACKSLASH {
            pending_backslashes += 1;
        } else if unit == QUOTE {
            // Double the pending backslashes, then escape the quote.
            for _ in 0..=(pending_backslashes * 2) {
                out.push(BACKSLASH);
            }
            out.push(QUOTE);
            pending_backslashes = 0;
        } else {
            for _ in 0..pending_backslashes {
                out.push(BACKSLASH);
            }
            out.push(unit);
            pending_backslashes = 0;
        }
    }
    // Trailing backslashes must be doubled so the closing quote is not
    // swallowed as an escape target.
    for _ in 0..(pending_backslashes * 2) {
        out.push(BACKSLASH);
    }
    out.push(QUOTE);
}

/// Build a space-separated, MSVCRT-quoted, **null-terminated** UTF-16 command
/// line from an optional leading program token followed by `args`.
///
/// Each token is run through [`quote_arg_for_createprocess`] so the result is
/// safe to hand to `CreateProcessW` (`lead = Some(exe)`) or to
/// `ShellExecuteW` as the parameter list (`lead = None`). Building from
/// `OsStr` code units keeps non-UTF-8/WTF-8 path bytes intact (WI-4.2).
#[cfg(windows)]
fn build_wide_command_line(
    lead: Option<&std::ffi::OsStr>,
    args: &[std::ffi::OsString],
) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt as _;

    let mut wide: Vec<u16> = Vec::new();
    if let Some(program) = lead {
        let program_wide: Vec<u16> = program.encode_wide().collect();
        quote_arg_for_createprocess(&program_wide, &mut wide);
    }
    for arg in args {
        // A space separates tokens; emit one before every token except the
        // very first written (i.e. when `wide` is still empty).
        if !wide.is_empty() {
            wide.push(u16::from(b' '));
        }
        let arg_wide: Vec<u16> = arg.encode_wide().collect();
        quote_arg_for_createprocess(&arg_wide, &mut wide);
    }
    wide.push(0); // CreateProcessW / ShellExecuteW require null termination.
    wide
}

// ── CreateProcessW spawn ──────────────────────────────────────────────────

/// Spawn the daemon as a fully detached process with NO handle inheritance.
///
/// Uses `CreateProcessW` directly with `bInheritHandles = FALSE` and
/// `DETACHED_PROCESS` creation flag.
///
/// Returns a [`DaemonChildHandle`] that keeps the process handle alive so
/// the caller's IPC-readiness retry loop can detect early exit via
/// [`DaemonChildHandle::try_wait`] — without this, a daemon that panics or
/// clap-rejects its argv looks identical to a daemon that just hasn't
/// bound its pipe yet, and the client spins through all 20 retries with
/// no diagnostic signal (the `LOG/Output` silent-failure scenario).
#[cfg(windows)]
fn spawn_detached_no_inherit(
    exe: &std::path::Path,
    args: &[std::ffi::OsString],
) -> Result<DaemonChildHandle, crate::error::ClientError> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        CreateProcessW, DETACHED_PROCESS, PROCESS_INFORMATION, STARTUPINFOW,
    };

    // Build the command-line as UTF-16 directly, using full MSVCRT-compatible
    // escaping (the program token leads). Working in UTF-16 — rather than
    // `to_string_lossy()` → `String` — preserves non-UTF-8/WTF-8 path bytes
    // losslessly through to the child's argv (Category 4, WI-4.2). The
    // previous naive implementation also dropped empty args entirely and
    // mangled any arg containing spaces or quotes — see
    // `quote_arg_for_createprocess` for the gory details.
    let mut cmd_wide: Vec<u16> = build_wide_command_line(Some(exe.as_os_str()), args);

    let si = STARTUPINFOW {
        cb: u32::try_from(size_of::<STARTUPINFOW>()).unwrap_or(u32::MAX),
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    // SAFETY: CreateProcessW is a well-defined Win32 API. All pointers are
    // valid: cmd_wide is a mutable null-terminated UTF-16 buffer, si is
    // a zeroed STARTUPINFOW with cb set, pi is zeroed output buffer.
    // We close the returned handles immediately after success.
    #[expect(unsafe_code, reason = "CreateProcessW requires unsafe FFI")]
    let result = unsafe {
        CreateProcessW(
            None,
            Some(windows::core::PWSTR(cmd_wide.as_mut_ptr())),
            None,
            None,
            false, // bInheritHandles = FALSE ← key fix
            DETACHED_PROCESS,
            None,
            None,
            core::ptr::from_ref(&si),
            core::ptr::from_mut(&mut pi),
        )
    };

    match result {
        Ok(()) => {
            tracing::debug!(pid = pi.dwProcessId, "spawn_detached_no_inherit: spawned");
            tracing::info!(
                pid = pi.dwProcessId,
                "Daemon spawned (no handle inheritance)"
            );
            // Close the *thread* handle immediately — we only use the
            // thread handle to unblock the initial process primary thread,
            // which is automatic on spawn.  Keep the *process* handle
            // open so the retry loop can poll for early exit.
            // SAFETY: thread handle was just returned by CreateProcessW
            // and is not aliased elsewhere.
            #[expect(unsafe_code, reason = "closing Win32 thread handle")]
            let thread_close = unsafe { CloseHandle(pi.hThread) };
            drop(thread_close);
            Ok(DaemonChildHandle::from_windows_process(
                pi.hProcess,
                pi.dwProcessId,
            ))
        }
        Err(win_err) => {
            tracing::debug!(error = %win_err, "spawn_detached_no_inherit: FAILED");
            Err(crate::error::ClientError::DaemonStartFailed(format!(
                "CreateProcessW failed for {}: {win_err}",
                exe.display()
            )))
        }
    }
}

// ── Windows elevation helpers ─────────────────────────────────────────────

/// Check if the current process is running with Administrator privileges.
#[cfg(windows)]
fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();

    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that does not
    // need closing.
    #[expect(unsafe_code, reason = "Win32 pseudo-handle accessor")]
    let current_proc = unsafe { GetCurrentProcess() };
    // SAFETY: `OpenProcessToken` writes a valid token handle into `token`
    // on success; `current_proc` is valid.
    #[expect(unsafe_code, reason = "Win32 token FFI")]
    let open_result =
        unsafe { OpenProcessToken(current_proc, TOKEN_QUERY, core::ptr::from_mut(&mut token)) };
    if open_result.is_err() {
        return false;
    }

    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut size = 0_u32;
    // SAFETY: `token` is a valid token handle; the out-pointer points to
    // a stack-owned `TOKEN_ELEVATION` that lives for the whole call.
    #[expect(unsafe_code, reason = "Win32 token information query")]
    let query_result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(core::ptr::from_mut(&mut elevation).cast()),
            u32::try_from(size_of::<TOKEN_ELEVATION>()).unwrap_or(u32::MAX),
            core::ptr::from_mut(&mut size),
        )
    };
    // SAFETY: `token` is owned by this function; no other code references it.
    #[expect(unsafe_code, reason = "CloseHandle for owned Win32 handle")]
    let close_result = unsafe { CloseHandle(token) };
    drop(close_result);

    query_result.is_ok() && elevation.TokenIsElevated != 0
}

/// Launch a process elevated via `ShellExecuteW` with the `"runas"` verb.
///
/// This triggers the Windows UAC consent dialog. If the user clicks "Yes",
/// the process starts elevated; if they click "No" or dismiss the dialog,
/// an error is returned.
#[cfg(windows)]
fn shell_execute_elevated(
    exe: &std::path::Path,
    args: &[std::ffi::OsString],
) -> Result<(), crate::error::ClientError> {
    use std::os::windows::ffi::OsStrExt as _;

    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::core::PCWSTR;

    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    // Build `file` and `params` as UTF-16 directly so non-UTF-8/WTF-8 path
    // bytes survive losslessly (Category 4, WI-4.2). `params` reuses the same
    // MSVCRT-compatible quoting as the CreateProcessW path so args with spaces
    // or quotes are not mangled by the elevated re-parse.
    let mut file: Vec<u16> = exe.as_os_str().encode_wide().collect();
    file.push(0); // null terminator

    // No leading program token: `file` is the program; `params` is the args.
    let params: Vec<u16> = build_wide_command_line(None, args);

    tracing::debug!(
        verb = "runas",
        file = %exe.display(),
        "ShellExecuteW"
    );

    // SAFETY: ShellExecuteW is a well-defined Win32 Shell API.
    // All PCWSTR pointers are valid null-terminated UTF-16 buffers
    // that outlive the call (stack-allocated Vecs above).
    #[expect(unsafe_code, reason = "ShellExecuteW requires unsafe FFI")]
    let hinst = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR(params.as_ptr()),
            PCWSTR::null(),
            windows::Win32::UI::WindowsAndMessaging::SW_HIDE,
        )
    };

    // ShellExecuteW returns HINSTANCE — values > 32 indicate success.
    let code = hinst.0 as isize;
    if code > 32 {
        tracing::debug!(code, "ShellExecuteW succeeded");
        Ok(())
    } else {
        let msg = match code {
            0 => "The OS is out of memory or resources",
            2 => "Executable not found (ERROR_FILE_NOT_FOUND)",
            3 => "Path not found (ERROR_PATH_NOT_FOUND)",
            5 => "Access denied (ERROR_ACCESS_DENIED)",
            _ => "Unknown ShellExecuteW error",
        };
        tracing::debug!(code, msg, "ShellExecuteW failed");
        Err(crate::error::ClientError::DaemonStartFailed(format!(
            "ShellExecuteW(runas) failed for {}: code={code} — {msg}",
            exe.display()
        )))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "daemon_spawn_tests.rs"]
mod tests;
