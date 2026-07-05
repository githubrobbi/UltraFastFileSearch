// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Capture-strategy classification: OS install class and the best-effort mode
//! derived from host capabilities. Pure logic — unit-tested here.

/// OS installation class — the capture-strategy discriminator.
///
/// Sourced from `HKLM\...\CurrentVersion\InstallationType` on Windows. The
/// `Client`/`Server` variants are constructed only by the Windows collector and
/// the tests, so non-Windows non-test builds legitimately never see them.
#[cfg_attr(
    all(not(windows), not(test)),
    expect(
        dead_code,
        reason = "Client/Server are constructed only by the Windows collector and the tests"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum InstallationType {
    /// Windows client (10/11) — VSS shadow create needs WMI; C++-on-shadow is
    /// awkward.
    Client,
    /// Windows Server — `diskshadow expose` enables skew-free C++-on-shadow.
    Server,
    /// Could not be determined (registry read failed or non-Windows host).
    Unknown,
}

impl InstallationType {
    /// Short label for the human report.
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Client => "Client",
            Self::Server => "Server",
            Self::Unknown => "Unknown",
        }
    }
}

/// Parse the registry `InstallationType` string into the typed enum.
///
/// Compiled on Windows (used by the Windows collector) and under `test`.
#[cfg(any(windows, test))]
pub(super) fn parse_installation_type(raw: &str) -> InstallationType {
    match raw.trim().to_ascii_lowercase().as_str() {
        "client" => InstallationType::Client,
        "server" | "server core" => InstallationType::Server,
        _ => InstallationType::Unknown,
    }
}

/// Best-effort capture strategy chosen from host capabilities (§2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum CaptureMode {
    /// Server + VSS: frozen shadow set + skew-free C++-on-shadow + live
    /// `.iocp`.
    FullServer,
    /// Client + VSS: frozen shadow set (Rust) + C++ golden live + live `.iocp`.
    BestEffortClient,
    /// No VSS or not elevated: live `.iocp` + listings only; frozen set
    /// skipped.
    LiveOnly,
    /// Non-Windows host: probe only, no capture possible.
    Unsupported,
}

impl CaptureMode {
    /// One-line description for the human report.
    pub(super) const fn describe(self) -> &'static str {
        match self {
            Self::FullServer => {
                "full(server) = live .iocp + shadow(frozen) + C++ golden on shadow (skew-free)"
            }
            Self::BestEffortClient => {
                "best-effort(client) = live .iocp + shadow(frozen, Rust) ; C++ golden live"
            }
            Self::LiveOnly => {
                "live-only = .iocp + listings ; frozen set SKIPPED (no VSS/elevation)"
            }
            Self::Unsupported => "unsupported = non-Windows host, probe only",
        }
    }
}

/// Choose the capture strategy from host capabilities. Pure — unit-tested.
pub(super) const fn decide_capture_mode(
    os: InstallationType,
    elevated: bool,
    vss_available: bool,
    is_windows: bool,
) -> CaptureMode {
    if !is_windows {
        return CaptureMode::Unsupported;
    }
    // Shadow create + raw MFT read both require elevation; without it the only
    // thing achievable is a degraded live capture (or nothing).
    if !elevated || !vss_available {
        return CaptureMode::LiveOnly;
    }
    match os {
        InstallationType::Server => CaptureMode::FullServer,
        InstallationType::Client | InstallationType::Unknown => CaptureMode::BestEffortClient,
    }
}

#[cfg(test)]
mod tests {
    use super::{CaptureMode, InstallationType, decide_capture_mode, parse_installation_type};

    #[test]
    fn server_with_vss_is_full() {
        assert_eq!(
            decide_capture_mode(InstallationType::Server, true, true, true),
            CaptureMode::FullServer
        );
    }

    #[test]
    fn client_with_vss_is_best_effort() {
        assert_eq!(
            decide_capture_mode(InstallationType::Client, true, true, true),
            CaptureMode::BestEffortClient
        );
    }

    #[test]
    fn unknown_os_defaults_to_client_effort() {
        assert_eq!(
            decide_capture_mode(InstallationType::Unknown, true, true, true),
            CaptureMode::BestEffortClient
        );
    }

    #[test]
    fn no_vss_falls_back_to_live_only() {
        assert_eq!(
            decide_capture_mode(InstallationType::Server, true, false, true),
            CaptureMode::LiveOnly
        );
    }

    #[test]
    fn not_elevated_falls_back_to_live_only() {
        assert_eq!(
            decide_capture_mode(InstallationType::Server, false, true, true),
            CaptureMode::LiveOnly
        );
    }

    #[test]
    fn non_windows_is_unsupported() {
        assert_eq!(
            decide_capture_mode(InstallationType::Server, true, true, false),
            CaptureMode::Unsupported
        );
    }

    #[test]
    fn parses_installation_type() {
        assert_eq!(parse_installation_type("Client"), InstallationType::Client);
        assert_eq!(
            parse_installation_type("  server  "),
            InstallationType::Server
        );
        assert_eq!(
            parse_installation_type("nonsense"),
            InstallationType::Unknown
        );
    }
}
