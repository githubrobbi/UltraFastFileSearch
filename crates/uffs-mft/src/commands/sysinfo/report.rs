// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! The capture-host report data model and its human-readable rendering, plus
//! the cross-platform host-facts builder shared by both platform collectors.
#![expect(
    clippy::default_numeric_fallback,
    reason = "unsuffixed byte/time unit divisors (1024, 60) in human-readable report formatting"
)]

use core::fmt;

use super::capture_mode::{CaptureMode, InstallationType, decide_capture_mode};

/// Host facts describing the machine a capture ran on.
#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct HostInfo {
    /// Computer name.
    machine: String,
    /// OS product name + display version (e.g. `Windows 11 Pro 24H2`).
    os_name: String,
    /// OS build number (e.g. `26100`).
    os_build: String,
    /// Target architecture (e.g. `x86_64`).
    arch: String,
    /// Client/Server discriminator.
    installation_type: InstallationType,
    /// Edition id (e.g. `Professional`, `ServerStandard`).
    edition: String,
    /// Whether the process is elevated (admin/root).
    elevated: bool,
    /// Whether the Volume Shadow Copy service is installed and not disabled.
    vss_available: bool,
    /// Logical CPU count.
    cpu_cores: usize,
    /// Total physical RAM in bytes.
    ram_bytes: u64,
    /// Local UTC offset in minutes (relevant to timestamp collation).
    utc_offset_minutes: i32,
    /// Capture timestamp (RFC 3339, UTC).
    captured_at: String,
    /// `uffs-mft` version string.
    tool_version: String,
    /// Selected best-effort capture strategy.
    capture_mode: CaptureMode,
}

/// Per-drive media, geometry, and capture capability.
#[expect(
    clippy::struct_excessive_bools,
    reason = "four independent per-drive capability flags; a bitfield would obscure the JSON schema and report"
)]
#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct DriveCapture {
    /// Drive letter (e.g. `C`).
    pub(super) drive: String,
    /// `true` when this drive hosts the running OS.
    pub(super) boot: bool,
    /// Storage kind: `NVMe`, `SSD`, `HDD`, `Removable`, `Virtual`, `Unknown`.
    pub(super) media_type: String,
    /// Volume serial number, hex.
    pub(super) volume_serial: String,
    /// Total capacity in bytes (0 when the volume handle could not be opened).
    pub(super) total_bytes: u64,
    /// Free capacity in bytes.
    pub(super) free_bytes: u64,
    /// Cluster size in bytes.
    pub(super) bytes_per_cluster: u32,
    /// `$MFT` size in bytes.
    pub(super) mft_size_bytes: u64,
    /// Allocated MFT record count.
    pub(super) mft_records: u64,
    /// NTFS version (e.g. `3.1`).
    pub(super) ntfs_version: String,
    /// Whether the volume is mounted read-only.
    pub(super) read_only: bool,
    /// Whether a live `.iocp` capture is possible (writable volume).
    pub(super) iocp_capturable: bool,
    /// Whether the drive is VSS-eligible (fixed, non-removable).
    pub(super) vss_eligible: bool,
}

/// A mounted volume on the host (any filesystem) — provenance, not a capture
/// target.
#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct Volume {
    /// Mount point (Unix) or drive root (Windows, e.g. `C:\`).
    pub(super) mount: String,
    /// Filesystem type (e.g. `apfs`, `ext4`, `NTFS`, `exFAT`).
    pub(super) filesystem: String,
    /// Storage media kind where detectable, else `n/a`.
    pub(super) media_type: String,
    /// Total capacity in bytes.
    pub(super) total_bytes: u64,
    /// Free capacity in bytes.
    pub(super) free_bytes: u64,
}

/// Full capture-host report: host facts + per-drive capabilities.
#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct Report {
    /// Host-level facts.
    pub(super) host: HostInfo,
    /// One entry per detected NTFS drive (Windows capture targets).
    pub(super) drives: Vec<DriveCapture>,
    /// All mounted volumes (any filesystem) — host provenance.
    pub(super) volumes: Vec<Volume>,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = &self.host;
        writeln!(f, "UFFS Capture Host Report")?;
        writeln!(
            f,
            "  Captured:      {} (UTC{:+03}:{:02})",
            host.captured_at,
            host.utc_offset_minutes / 60,
            host.utc_offset_minutes.rem_euclid(60),
        )?;
        writeln!(f, "  Tool:          uffs-mft {}", host.tool_version)?;
        writeln!(f, "  Host:          {}", host.machine)?;
        writeln!(
            f,
            "  OS:            {} build {} {}",
            host.os_name, host.os_build, host.arch
        )?;
        writeln!(
            f,
            "  InstallType:   {:<8}  <-- gates VSS / C++-on-shadow strategy",
            host.installation_type.label()
        )?;
        writeln!(f, "  Edition:       {}", host.edition)?;
        writeln!(f, "  Elevated:      {}", yes_no(host.elevated))?;
        writeln!(f, "  VSS service:   {}", available(host.vss_available))?;
        writeln!(
            f,
            "  CPU / RAM:     {} cores / {} GB",
            host.cpu_cores,
            host.ram_bytes / (1024 * 1024 * 1024)
        )?;
        writeln!(f, "  Capture mode:  {}", host.capture_mode.describe())?;
        writeln!(f)?;
        writeln!(f, "  Drives (NTFS):")?;
        if self.drives.is_empty() {
            writeln!(f, "    (none detected / not a Windows host)")?;
        }
        for drive in &self.drives {
            let used = drive.total_bytes.saturating_sub(drive.free_bytes);
            let used_pct = (used * 100).checked_div(drive.total_bytes).unwrap_or(0);
            writeln!(
                f,
                "    {}:  {:<9} {} GB ({}% used, serial {})  MFT {} MB / {} recs",
                drive.drive,
                drive.media_type,
                drive.total_bytes / (1024 * 1024 * 1024),
                used_pct,
                drive.volume_serial,
                drive.mft_size_bytes / (1024 * 1024),
                drive.mft_records,
            )?;
            writeln!(
                f,
                "        ntfs:{}  read_only:{}  iocp:{}  vss_eligible:{}",
                drive.ntfs_version,
                yes_no(drive.read_only),
                yes_no(drive.iocp_capturable),
                yes_no(drive.vss_eligible),
            )?;
        }
        writeln!(f)?;
        writeln!(f, "  Volumes (all filesystems):")?;
        if self.volumes.is_empty() {
            writeln!(f, "    (none detected)")?;
        }
        for vol in &self.volumes {
            let used = vol.total_bytes.saturating_sub(vol.free_bytes);
            let used_pct = (used * 100).checked_div(vol.total_bytes).unwrap_or(0);
            writeln!(
                f,
                "    {:<26} {:<8} {:<9} {} GB / {} GB used ({}%)",
                vol.mount,
                vol.filesystem,
                vol.media_type,
                vol.total_bytes / (1024 * 1024 * 1024),
                used / (1024 * 1024 * 1024),
                used_pct,
            )?;
        }
        Ok(())
    }
}

/// Render a bool as `yes`/`no`.
const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Render a service-availability bool for the report.
const fn available(value: bool) -> &'static str {
    if value {
        "installed (shadow create: probe on capture)"
    } else {
        "not available"
    }
}

/// Cross-platform host facts shared by both collectors.
///
/// `installation_type`, `os_name`, `os_build`, `edition`, and `vss_available`
/// are filled by the platform-specific caller; everything else is portable.
pub(super) fn base_host(
    os_name: String,
    os_build: String,
    edition: String,
    installation_type: InstallationType,
    vss_available: bool,
    is_windows: bool,
) -> HostInfo {
    let now_local = chrono::Local::now();
    let utc_offset_minutes = {
        use chrono::Offset as _;
        now_local.offset().fix().local_minus_utc() / 60
    };
    let elevated = uffs_mft::is_elevated();
    let cpu_cores = std::thread::available_parallelism().map_or(0, core::num::NonZeroUsize::get);
    HostInfo {
        machine: machine_name(),
        os_name,
        os_build,
        arch: std::env::consts::ARCH.to_owned(),
        installation_type,
        edition,
        elevated,
        vss_available,
        cpu_cores,
        ram_bytes: uffs_mft::query_system_memory().total_bytes,
        utc_offset_minutes,
        captured_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        capture_mode: decide_capture_mode(installation_type, elevated, vss_available, is_windows),
    }
}

/// Real computer name via the OS (falls back to `unknown`).
fn machine_name() -> String {
    hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::super::capture_mode::{CaptureMode, InstallationType};
    use super::{HostInfo, Report};

    /// Build a deterministic host record for rendering tests.
    fn sample_host() -> HostInfo {
        HostInfo {
            machine: "TEST-PC".to_owned(),
            os_name: "Windows 11 Pro 24H2".to_owned(),
            os_build: "26100".to_owned(),
            arch: "x86_64".to_owned(),
            installation_type: InstallationType::Client,
            edition: "Professional".to_owned(),
            elevated: true,
            vss_available: true,
            cpu_cores: 24,
            ram_bytes: 64 * 1024 * 1024 * 1024,
            utc_offset_minutes: -420,
            captured_at: "2026-07-05T18:22:04Z".to_owned(),
            tool_version: "0.0.0".to_owned(),
            capture_mode: CaptureMode::BestEffortClient,
        }
    }

    #[test]
    fn report_renders_key_fields() {
        let report = Report {
            host: sample_host(),
            drives: Vec::new(),
            volumes: Vec::new(),
        };
        let text = report.to_string();
        assert!(text.contains("UFFS Capture Host Report"));
        assert!(text.contains("InstallType:   Client"));
        assert!(text.contains("Capture mode:"));
        assert!(text.contains("(none detected"));
    }
}
