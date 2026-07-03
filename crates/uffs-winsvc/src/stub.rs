// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Non-Windows stubs. There is no Service Control Manager and no broker
//! named pipe off Windows, so the operations degrade to sensible no-ops:
//! every service is "not installed", `stop` succeeds trivially, `start`
//! reports the platform has no SCM, and a pipe is vacuously "serving".
//!
//! These are deliberately **not** `const fn`, even though their bodies
//! could be: the Windows implementations are genuinely non-const (SCM /
//! pipe FFI), and keeping the stub signatures identical means the public
//! wrappers in `lib.rs` have one uniform callability profile across
//! platforms instead of being `const`-only off Windows.

use anyhow::{Result, bail};

use crate::ServiceInfo;

/// Always reports "no such service" off Windows.
#[expect(
    clippy::missing_const_for_fn,
    reason = "mirrors the non-const Windows impl so the public wrapper is uniform"
)]
pub(crate) fn query(_service: &str) -> ServiceInfo {
    ServiceInfo::not_installed()
}

/// Nothing to start — there is no SCM here.
pub(crate) fn start(_service: &str) -> Result<()> {
    bail!("Windows service control is unavailable on this platform")
}

/// Non-Windows stub for [`super::start_with`].
///
/// # Errors
///
/// Always errors: there is no SCM off Windows.
pub(crate) fn start_with(_service: &str, _timeout: core::time::Duration) -> Result<()> {
    bail!("service control is only available on Windows")
}

/// Nothing to stop — idempotent no-op.
#[expect(
    clippy::missing_const_for_fn,
    reason = "mirrors the non-const Windows impl so the public wrapper is uniform"
)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "signature parity with the fallible Windows stop()"
)]
pub(crate) fn stop(_service: &str) -> Result<()> {
    Ok(())
}

/// Non-Windows stub for [`super::stop_with`].
///
/// # Errors
///
/// Always errors: there is no SCM off Windows.
pub(crate) fn stop_with(_service: &str, _timeout: core::time::Duration) -> Result<()> {
    bail!("service control is only available on Windows")
}

/// No broker pipe exists, so readiness is vacuously `true`.
#[expect(
    clippy::missing_const_for_fn,
    reason = "mirrors the non-const Windows impl so the public wrapper is uniform"
)]
pub(crate) fn pipe_serving(_pipe_name: &str, _timeout_ms: u32) -> bool {
    true
}

/// No Windows token here — off-Windows callers use their own root check.
#[expect(
    clippy::missing_const_for_fn,
    reason = "mirrors the non-const Windows impl so the public wrapper is uniform"
)]
pub(crate) fn is_elevated() -> bool {
    false
}
