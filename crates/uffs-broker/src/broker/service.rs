// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Windows Service registration + control dispatcher for the access broker.
//!
//! Extracted from `broker.rs` (which sits at the 800-LOC file-size ceiling).
//! `install_service` / `uninstall_service` shell out to `sc`; the FU-1
//! dispatcher (`run_as_service`, `service_main`, the control handler) is the
//! `LocalSystem` entry point the SCM invokes at boot — so the broker runs as a
//! real service without the `--run` terminal.

/// Registered service name — the single source of truth shared with the
/// updater + CLI. Used for `sc create`/`delete` and the `service_main`
/// table entry.
#[cfg(windows)]
use uffs_broker_protocol::SERVICE_NAME;

/// Set by the SCM control handler on STOP / SHUTDOWN; polled by the broker's
/// accept loop ([`stop_requested`]) so it exits between connections.
#[cfg(windows)]
static STOP_REQUESTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// `SERVICE_STATUS_HANDLE` from `RegisterServiceCtrlHandlerW`, stored so the
/// control handler (a C callback with no user context) can report status.
/// Null until `service_main` registers it.
#[cfg(windows)]
static STATUS_HANDLE: core::sync::atomic::AtomicPtr<core::ffi::c_void> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// `true` once a service stop has been requested; the accept loop checks this.
#[cfg(windows)]
pub(super) fn stop_requested() -> bool {
    STOP_REQUESTED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Encode `text` as a NUL-terminated UTF-16 buffer for Win32 wide-string APIs.
#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Combine an `sc.exe` invocation's stdout + stderr for an error message.
///
/// `sc.exe` writes most of its diagnostics to **stdout**, not stderr, so a
/// stderr-only message comes out empty (as seen on a failed `sc create`).
#[cfg(windows)]
fn sc_output(output: &std::process::Output) -> String {
    // AUDIT-OK(bytes): operator-facing diagnostic text only — the combined
    // output is formatted into an error message, never parsed or matched.
    let stdout = String::from_utf8_lossy(&output.stdout);
    // AUDIT-OK(bytes): same display-only argument as stdout above.
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!("{} {}", stdout.trim(), stderr.trim())
        .trim()
        .to_owned()
}

/// Print an in-progress step label without a trailing newline and flush, so
/// the operator sees what a slow step (e.g. the blocking `sc start`) is doing
/// before its "ok"/"failed" verdict lands on the same line.
#[cfg(windows)]
#[expect(
    clippy::print_stdout,
    reason = "CLI admin command — stdout is the user-visible result channel"
)]
fn print_step(label: &str) {
    use std::io::Write as _;

    print!("{label}");
    let _flushed = std::io::stdout().flush();
}

/// Register the broker as an auto-start Windows Service and start it.
///
/// # Why the argv is split the way it is
///
/// `sc create` parses `option= value` where `option=` and the value are
/// **separate command-line tokens** (the space after `=` is the
/// delimiter).  The prior code passed `binPath= "<path>"` as a *single*
/// argument, so the registered `ImagePath` ended up as ` "<path>"` —
/// with a leading space and literal quotes — and the service failed to
/// start with `StartService` error 87 (`ERROR_INVALID_PARAMETER`).  Here
/// `binPath=` and the raw path are distinct argv elements; `std`'s
/// Windows argument quoting wraps the path in quotes only if it contains
/// spaces, producing a valid `ImagePath` in both cases.
#[cfg(windows)]
#[expect(
    clippy::print_stdout,
    reason = "CLI admin command — stdout is the user-visible result channel"
)]
pub(super) fn install_service() -> anyhow::Result<()> {
    if !super::is_elevated() {
        anyhow::bail!(
            "installing the broker service requires Administrator.\n\
             Open an elevated terminal (right-click PowerShell or cmd → \
             \"Run as administrator\") and re-run:\n    uffs-broker --install"
        );
    }

    // Step-by-step narration: `sc start` blocks until the service reports
    // ready, which can take a minute — a silent wait reads as a hang.
    let exe = std::env::current_exe()?;
    println!("Installing the UFFS Access Broker service...");
    print_step("  registering the service (sc create)... ");
    let create = std::process::Command::new("sc.exe")
        .args([
            "create",
            SERVICE_NAME,
            "binPath=",
            &exe.display().to_string(),
            "start=",
            "auto",
            "DisplayName=",
            "UFFS Access Broker",
        ])
        .output()?;

    if !create.status.success() {
        println!("failed");
        // AUDIT-OK(bytes): `sc` output surfaced verbatim to the operator —
        // display only, no decision.
        anyhow::bail!(
            "Install failed (sc create): {}\n(If the service already exists, run \
             `uffs-broker --uninstall` first.)",
            sc_output(&create)
        );
    }
    println!("ok");

    // Start it now so the broker is usable immediately — the whole point
    // is "no future UAC", which only holds once the service is running.
    // `start= auto` also brings it back on every boot.
    print_step(
        "  starting the service (Windows waits for it to report ready; \
         this can take a minute)... ",
    );
    let start = std::process::Command::new("sc.exe")
        .args(["start", SERVICE_NAME])
        .output()?;

    if start.status.success() {
        println!("ok");
        println!(
            "UFFS Access Broker installed and started (auto-start on boot).\n\
             Non-elevated `uffs` searches will now use the broker for volume \
             access — no more UAC prompts."
        );
    } else {
        println!("failed");
        // AUDIT-OK(bytes): `sc` output surfaced verbatim to the operator.
        println!(
            "Service installed (auto-start on boot), but starting it failed: \
             {}\nStart it manually from an elevated shell with:\n    \
             sc.exe start UffsAccessBroker",
            sc_output(&start)
        );
    }
    Ok(())
}

/// Deregister the broker Windows Service via `sc delete`.
///
/// See [`install_service`] for why stdout is the output channel.
#[cfg(windows)]
#[expect(
    clippy::print_stdout,
    reason = "CLI admin command — stdout is the user-visible result channel"
)]
pub(super) fn uninstall_service() -> anyhow::Result<()> {
    if !super::is_elevated() {
        anyhow::bail!(
            "removing the broker service requires Administrator.\n\
             Open an elevated terminal and re-run:\n    uffs-broker --uninstall"
        );
    }
    // Stop the service before deleting it.  `sc delete` on a RUNNING service
    // only MARKS it for deletion (deferred until it stops), which then makes a
    // later `--install` fail with a cryptic `sc create` error.  Stopping first
    // makes the delete take effect immediately.  Ignore the stop result — the
    // service may already be stopped or not exist.
    let _stopped = std::process::Command::new("sc.exe")
        .args(["stop", SERVICE_NAME])
        .output();
    let output = std::process::Command::new("sc.exe")
        .args(["delete", SERVICE_NAME])
        .output()?;

    if output.status.success() {
        println!("Service uninstalled.");
    } else {
        // AUDIT-OK(bytes): `sc` command output surfaced verbatim in an error
        // message for the operator — display only, no decision.
        anyhow::bail!("Uninstall failed: {}", sc_output(&output));
    }
    Ok(())
}

// ── FU-1: Windows Service control dispatcher ────────────────────────────────

/// Hand control to the SCM via `StartServiceCtrlDispatcherW`; blocks until the
/// service stops.
///
/// When the binary is launched **interactively** (no SCM), the dispatcher fails
/// with `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (1063) — in that case we
/// print usage, so a bare `uffs-broker` is still helpful instead of hanging.
#[cfg(windows)]
#[expect(unsafe_code, reason = "FFI: StartServiceCtrlDispatcherW")]
pub(super) fn run_as_service() -> anyhow::Result<()> {
    use windows::Win32::Foundation::ERROR_FAILED_SERVICE_CONTROLLER_CONNECT;
    use windows::Win32::System::Services::{SERVICE_TABLE_ENTRYW, StartServiceCtrlDispatcherW};
    use windows::core::PWSTR;

    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(), // NULL terminator
    ];

    // SAFETY: `table` is NULL-terminated and, with `name`, outlives the
    // (blocking) dispatcher call.
    match unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } {
        Ok(()) => Ok(()),
        Err(err) if err.code() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT.to_hresult() => {
            // Not launched by the SCM → interactive invocation.
            super::print_usage();
            Ok(())
        }
        Err(err) => Err(anyhow::anyhow!("StartServiceCtrlDispatcherW failed: {err}")),
    }
}

/// SCM service entry point: register the control handler, report RUNNING, serve
/// until a stop is requested, then report STOPPED.
#[cfg(windows)]
#[expect(unsafe_code, reason = "FFI: RegisterServiceCtrlHandlerW")]
extern "system" fn service_main(_argc: u32, _argv: *mut windows::core::PWSTR) {
    use core::sync::atomic::Ordering;

    use windows::Win32::System::Services::{
        RegisterServiceCtrlHandlerW, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STOPPED,
    };
    use windows::core::PCWSTR;

    let name = wide(SERVICE_NAME);
    // SAFETY: `name` is a NUL-terminated wide string valid for the call.
    let Ok(handle) =
        (unsafe { RegisterServiceCtrlHandlerW(PCWSTR(name.as_ptr()), Some(service_ctrl_handler)) })
    else {
        return;
    };
    STATUS_HANDLE.store(handle.0, Ordering::Relaxed);

    report_status(SERVICE_START_PENDING, 0);
    super::init_tracing();
    tracing::info!("uffs-broker starting (service mode)");
    report_status(SERVICE_RUNNING, accepted_controls());

    if let Err(err) = super::serve_pipe_requests() {
        tracing::error!(error = %err, "broker serve loop exited with error");
    }
    tracing::info!("uffs-broker stopped (service mode)");
    report_status(SERVICE_STOPPED, 0);
}

/// SCM control handler: on STOP / SHUTDOWN flag the accept loop to exit and
/// nudge it awake (it blocks in `ConnectNamedPipe`).
#[cfg(windows)]
extern "system" fn service_ctrl_handler(control: u32) {
    use core::sync::atomic::Ordering;

    use windows::Win32::System::Services::{
        SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
        SERVICE_RUNNING, SERVICE_STOP_PENDING,
    };

    if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
        STOP_REQUESTED.store(true, Ordering::Relaxed);
        report_status(SERVICE_STOP_PENDING, 0);
        signal_stop();
    } else if control == SERVICE_CONTROL_INTERROGATE {
        report_status(SERVICE_RUNNING, accepted_controls());
    }
}

/// Controls the broker accepts while RUNNING (operator STOP + system SHUTDOWN).
#[cfg(windows)]
const fn accepted_controls() -> u32 {
    use windows::Win32::System::Services::{SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP};
    SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
}

/// Report a service-status transition to the SCM (no-op before registration).
#[cfg(windows)]
#[expect(unsafe_code, reason = "FFI: SetServiceStatus")]
fn report_status(
    state: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE,
    controls_accepted: u32,
) {
    use core::sync::atomic::Ordering;

    use windows::Win32::System::Services::{
        SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
    };

    let raw = STATUS_HANDLE.load(Ordering::Relaxed);
    if raw.is_null() {
        return;
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: controls_accepted,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    // SAFETY: `raw` is the handle stored by `service_main`; `status` is fully
    // initialised and valid for the duration of the call.
    if let Err(err) = unsafe { SetServiceStatus(SERVICE_STATUS_HANDLE(raw), &raw const status) } {
        tracing::debug!(err = ?err, "SetServiceStatus failed");
    }
}

/// Wake the accept loop's blocking `ConnectNamedPipe` by opening the pipe as a
/// throwaway client, so a stop takes effect promptly.  The loop then sees
/// [`stop_requested`] and exits without serving this connection.
#[cfg(windows)]
#[expect(unsafe_code, reason = "FFI: CreateFileW dummy connect + CloseHandle")]
fn signal_stop() {
    use uffs_broker_protocol::PIPE_NAME;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
    };
    use windows::core::PCWSTR;

    let name = wide(PIPE_NAME);
    // SAFETY: `name` is a NUL-terminated wide path valid for the call; any
    // returned handle is closed immediately below.
    let opened = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    };
    if let Ok(handle) = opened {
        // SAFETY: `handle` is a freshly opened, valid handle owned here.
        if let Err(err) = unsafe { CloseHandle(handle) } {
            tracing::debug!(err = ?err, "CloseHandle failed for stop-signal pipe");
        }
    }
}
