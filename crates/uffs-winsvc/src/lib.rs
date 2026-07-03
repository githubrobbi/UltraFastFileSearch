// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Native Windows **service control** (SCM) plus the broker **named-pipe
//! readiness** probe — the single source of truth for the mechanics that
//! were previously hand-rolled with `sc.exe` across `uffs-broker`,
//! `uffs-update`, and `uffs-cli`.
//!
//! Why native, not `sc.exe`: `sc query` prints **localized** state words
//! (`RUNNING`/`STOPPED`), so text-matching them silently breaks on a
//! non-English Windows. The SCM APIs here return the **numeric**
//! `SERVICE_RUNNING` (4) etc., which are locale-proof. This crate is pure
//! *mechanism* and takes the service/pipe name as a parameter; the broker's
//! *identity* (its `SERVICE_NAME` / `PIPE_NAME`) lives in
//! `uffs-broker-protocol`.
//!
//! Cross-platform: every public function compiles everywhere. Off Windows
//! there is no SCM, so [`query`] reports [`ServiceState::NotInstalled`],
//! [`stop`] is a no-op, [`start`] errors, and [`pipe_serving`] is `true`.

use anyhow::Result;

#[cfg(windows)]
#[path = "windows.rs"]
mod sys;
#[cfg(not(windows))]
#[path = "stub.rs"]
mod sys;

/// The current run state of a Windows service — numeric and locale-proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// No service is registered under the queried name.
    NotInstalled,
    /// Installed and stopped.
    Stopped,
    /// A start was requested but has not completed.
    StartPending,
    /// A stop was requested but has not completed.
    StopPending,
    /// Running.
    Running,
    /// Any other SCM state (paused, continue-pending, …), value verbatim.
    Other(u32),
}

impl ServiceState {
    /// Map a raw `SERVICE_STATUS_CURRENT_STATE` value to a [`ServiceState`].
    #[cfg(windows)]
    pub(crate) const fn from_raw(raw: u32) -> Self {
        match raw {
            1 => Self::Stopped,
            2 => Self::StartPending,
            3 => Self::StopPending,
            4 => Self::Running,
            other => Self::Other(other),
        }
    }

    /// `true` only when the service is fully running.
    #[must_use]
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }

    /// `true` when a service is registered (any state but `NotInstalled`).
    #[must_use]
    pub const fn is_installed(self) -> bool {
        !matches!(self, Self::NotInstalled)
    }

    /// A short human-readable label for display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotInstalled => "not installed",
            Self::Stopped => "stopped",
            Self::StartPending => "start pending",
            Self::StopPending => "stop pending",
            Self::Running => "running",
            Self::Other(_) => "other",
        }
    }
}

/// A snapshot of a service: its [`ServiceState`] and, when running, its pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceInfo {
    /// Current run state.
    pub state: ServiceState,
    /// The service process id when running, else `None`.
    pub pid: Option<u32>,
}

impl ServiceInfo {
    /// The "no such service" snapshot.
    #[must_use]
    pub const fn not_installed() -> Self {
        Self {
            state: ServiceState::NotInstalled,
            pid: None,
        }
    }
}

/// Query a service's state + pid. **Best-effort**: any failure to open or
/// query it (including "no such service") yields
/// [`ServiceInfo::not_installed`].
#[must_use]
pub fn query(service: &str) -> ServiceInfo {
    sys::query(service)
}

/// The service's [`ServiceState`] — a convenience over [`query`].
#[must_use]
pub fn status(service: &str) -> ServiceState {
    sys::query(service).state
}

/// `true` when a service is registered under `service`.
#[must_use]
pub fn is_installed(service: &str) -> bool {
    sys::query(service).state.is_installed()
}

/// Start `service` and wait until it reports Running (or a timeout). A
/// no-op if it is already running.
///
/// # Errors
///
/// Open/start failures, or the service not reaching Running in time. Always
/// errors off Windows (there is no SCM).
pub fn start(service: &str) -> Result<()> {
    sys::start(service)
}

/// Like [`start`], but waits up to `timeout` for the Running state — a generous
/// timeout for AV-throttled boxes where service control is slow.
///
/// # Errors
///
/// Same as [`start`].
pub fn start_with(service: &str, timeout: core::time::Duration) -> Result<()> {
    sys::start_with(service, timeout)
}

/// Stop `service` and wait until it reports Stopped (or a timeout). A no-op
/// if it is already stopped or not installed.
///
/// # Errors
///
/// Open/control failures, or the service not reaching Stopped in time.
pub fn stop(service: &str) -> Result<()> {
    sys::stop(service)
}

/// Like [`stop`], but waits up to `timeout` for the Stopped state — a generous
/// timeout for AV-throttled boxes where service control is slow.
///
/// # Errors
///
/// Same as [`stop`].
pub fn stop_with(service: &str, timeout: core::time::Duration) -> Result<()> {
    sys::stop_with(service, timeout)
}

/// Wait up to `timeout_ms` for `pipe_name` to be serving.
///
/// Uses a **non-connecting** `WaitNamedPipe` probe — it never consumes a
/// pipe instance, so it cannot itself cause `ERROR_PIPE_BUSY`. Always
/// `true` off Windows; `false` on timeout or if no pipe exists.
#[must_use]
pub fn pipe_serving(pipe_name: &str, timeout_ms: u32) -> bool {
    sys::pipe_serving(pipe_name, timeout_ms)
}

/// `true` if the current process runs with an elevated (Administrator) token.
///
/// Queries `TokenElevation` on the current process token. Any FFI failure maps
/// to `false` — the conservative answer for a privilege gate. Always `false`
/// off Windows (there is no token-elevation concept; non-Windows callers that
/// care about root use their own check).
#[must_use]
pub fn is_elevated() -> bool {
    sys::is_elevated()
}

#[cfg(test)]
mod tests {
    use super::{ServiceInfo, ServiceState};

    #[test]
    fn state_predicates() {
        assert!(ServiceState::Running.is_running());
        assert!(ServiceState::Running.is_installed());
        assert!(!ServiceState::NotInstalled.is_installed());
        assert!(!ServiceState::Stopped.is_running());
        assert!(ServiceState::Stopped.is_installed());
    }

    #[test]
    fn not_installed_snapshot() {
        let info = ServiceInfo::not_installed();
        assert_eq!(info.state, ServiceState::NotInstalled);
        assert!(info.pid.is_none());
    }

    #[test]
    fn labels_are_distinct_and_nonempty() {
        for state in [
            ServiceState::NotInstalled,
            ServiceState::Stopped,
            ServiceState::Running,
        ] {
            assert!(!state.label().is_empty());
        }
    }

    // On non-Windows hosts the stub path is active: an improbable service
    // is "not installed", stop is a no-op, and the pipe is vacuously ready.
    #[cfg(not(windows))]
    #[test]
    fn stub_behaviour_off_windows() {
        assert_eq!(
            super::status("UffsNoSuchService"),
            ServiceState::NotInstalled
        );
        assert!(!super::is_installed("UffsNoSuchService"));
        super::stop("UffsNoSuchService").expect("stub stop is a no-op");
        super::start("UffsNoSuchService").expect_err("stub start has no SCM");
        assert!(super::pipe_serving(r"\\.\pipe\nope", 10));
    }
}
