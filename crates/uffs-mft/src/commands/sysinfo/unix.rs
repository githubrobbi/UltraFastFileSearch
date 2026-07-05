// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Non-Windows capture-host collectors: real OS identity + all-volume
//! enumeration with per-device filesystem and media-type detection. This whole
//! module is compiled only on non-Windows hosts (see the `mod unix;` gate in
//! `mod.rs`); MFT capture itself is Windows-only, so `drives` is always empty.

use super::capture_mode::InstallationType;
use super::report::{Report, Volume, base_host};

/// Collect the capture-host report on non-Windows hosts.
///
/// Host identity (OS, CPU, RAM, hostname) is real — useful as a benchmark
/// provenance stamp — but the capture mode resolves to `Unsupported`.
pub(super) fn collect() -> Report {
    let (os_name, os_build) = os_release();
    let host = base_host(
        os_name,
        os_build,
        "n/a".to_owned(),
        InstallationType::Unknown,
        false,
        false,
    );
    Report {
        host,
        drives: Vec::new(),
        volumes: collect_volumes(),
    }
}

/// Friendly OS name + build for macOS via `sw_vers`.
#[cfg(target_os = "macos")]
fn os_release() -> (String, String) {
    let sw_vers = |arg: &str| -> Option<String> {
        let output = std::process::Command::new("sw_vers")
            .arg(arg)
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        // AUDIT-OK(bytes): decodes `sw_vers` stdout into a display string; the
        // emptiness filter below fails closed on any non-UTF-8 garbage.
        let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        (!text.is_empty()).then_some(text)
    };
    let name = sw_vers("-productName").unwrap_or_else(|| "macOS".to_owned());
    let version = sw_vers("-productVersion").unwrap_or_default();
    let build = sw_vers("-buildVersion").unwrap_or_else(|| "?".to_owned());
    let os_name = if version.is_empty() {
        name
    } else {
        format!("{name} {version}")
    };
    (os_name, build)
}

/// Friendly OS name + kernel for Linux via `/etc/os-release` + `uname -r`.
#[cfg(target_os = "linux")]
fn os_release() -> (String, String) {
    let pretty = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                line.strip_prefix("PRETTY_NAME=")
                    .map(|value| value.trim_matches('"').to_owned())
            })
        })
        .unwrap_or_else(|| "Linux".to_owned());
    let kernel = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .filter(|output| output.status.success())
        // AUDIT-OK(bytes): decodes `uname -r` stdout into a display string.
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|kernel| !kernel.is_empty())
        .unwrap_or_else(|| "?".to_owned());
    (pretty, kernel)
}

/// Fallback OS identity for other Unix targets.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn os_release() -> (String, String) {
    (std::env::consts::OS.to_owned(), "?".to_owned())
}

/// List mounted volumes (any filesystem) via `df` + a mount→fstype map.
///
/// Only real block devices (`/dev/...`) are listed; synthetic mounts are
/// skipped, and volumes sharing one physical container collapse to a single
/// row (e.g. the many synthetic APFS `/System/Volumes/*` mounts).
fn collect_volumes() -> Vec<Volume> {
    let output = match std::process::Command::new("df").args(["-k", "-P"]).output() {
        Ok(out) if out.status.success() => out,
        _ => return Vec::new(),
    };
    // AUDIT-OK(bytes): decodes `df` stdout for a display; rows that fail to
    // parse are skipped (fail-closed).
    let text = String::from_utf8_lossy(&output.stdout);
    let fstypes = fstype_map();
    let mut seen = std::collections::HashSet::new();
    text.lines()
        .skip(1)
        .filter_map(|line| {
            // POSIX `df -P`: Filesystem 1024-blocks Used Available Capacity Mounted-on
            let cols: Vec<&str> = line.split_whitespace().collect();
            let device = *cols.first()?;
            if !device.starts_with("/dev/") {
                return None;
            }
            let total_kib: u64 = cols.get(1)?.parse().ok()?;
            let avail_kib: u64 = cols.get(3)?.parse().ok()?;
            if !seen.insert((base_device(device), total_kib, avail_kib)) {
                return None;
            }
            let mount = cols.get(5..)?.join(" ");
            let filesystem = fstypes
                .get(&mount)
                .cloned()
                .unwrap_or_else(|| device.to_owned());
            Some(Volume {
                mount,
                filesystem,
                media_type: disk_media_type(device),
                total_bytes: total_kib * 1024,
                free_bytes: avail_kib * 1024,
            })
        })
        .collect()
}

/// Map of mount point → filesystem type on Linux (`/proc/mounts`).
#[cfg(target_os = "linux")]
fn fstype_map() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if let Ok(content) = std::fs::read_to_string("/proc/mounts") {
        for line in content.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if let (Some(mount), Some(fstype)) = (cols.get(1), cols.get(2)) {
                map.insert((*mount).to_owned(), (*fstype).to_owned());
            }
        }
    }
    map
}

/// Map of mount point → filesystem type on macOS (`mount` output).
#[cfg(target_os = "macos")]
fn fstype_map() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let Ok(output) = std::process::Command::new("mount").output() else {
        return map;
    };
    if !output.status.success() {
        return map;
    }
    // AUDIT-OK(bytes): decodes `mount` stdout into a display map.
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        // "/dev/disk3s1s1 on / (apfs, sealed, local, ...)"
        if let Some((_, rest)) = line.split_once(" on ")
            && let Some((mount, paren)) = rest.split_once(" (")
        {
            let fstype = paren.split([',', ')']).next().unwrap_or("").trim();
            if !fstype.is_empty() {
                map.insert(mount.to_owned(), fstype.to_owned());
            }
        }
    }
    map
}

/// Empty mount→fstype map on other Unix targets.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn fstype_map() -> std::collections::HashMap<String, String> {
    std::collections::HashMap::new()
}

/// Detect SSD/HDD/NVMe/Removable for a device via `diskutil info` on macOS.
#[cfg(target_os = "macos")]
fn disk_media_type(device: &str) -> String {
    let Ok(output) = std::process::Command::new("diskutil")
        .args(["info", device])
        .output()
    else {
        return "Unknown".to_owned();
    };
    if !output.status.success() {
        return "Unknown".to_owned();
    }
    // AUDIT-OK(bytes): decodes `diskutil info` stdout for a display string.
    let text = String::from_utf8_lossy(&output.stdout);
    let field = |name: &str| -> String {
        text.lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == name).then(|| value.trim().to_owned())
            })
            .unwrap_or_default()
    };
    let solid_state = field("Solid State");
    let protocol = field("Protocol");
    if protocol.eq_ignore_ascii_case("USB") || protocol.contains("External") {
        "Removable".to_owned()
    } else if solid_state.eq_ignore_ascii_case("Yes") {
        if protocol.contains("PCI") {
            "NVMe".to_owned()
        } else {
            "SSD".to_owned()
        }
    } else if solid_state.eq_ignore_ascii_case("No") {
        "HDD".to_owned()
    } else {
        "Unknown".to_owned()
    }
}

/// Detect SSD/HDD/NVMe for a device via `/sys/block/<dev>/queue/rotational`.
#[cfg(target_os = "linux")]
fn disk_media_type(device: &str) -> String {
    let base = base_device(device);
    let rotational = std::fs::read_to_string(format!("/sys/block/{base}/queue/rotational"))
        .ok()
        .map(|text| text.trim().to_owned());
    match rotational.as_deref() {
        Some("0") if base.starts_with("nvme") => "NVMe".to_owned(),
        Some("0") => "SSD".to_owned(),
        Some("1") => "HDD".to_owned(),
        _ => "Unknown".to_owned(),
    }
}

/// Media detection is unavailable on other Unix targets.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn disk_media_type(_device: &str) -> String {
    "Unknown".to_owned()
}

/// Reduce a device node to its parent physical device, so volumes sharing one
/// container collapse to a single row (`/dev/disk3s1s1` → `disk3`,
/// `/dev/sda1` → `sda`, `/dev/nvme0n1p2` → `nvme0n1`, `/dev/mmcblk0p1` →
/// `mmcblk0`).
fn base_device(device: &str) -> String {
    let name = device.strip_prefix("/dev/").unwrap_or(device);
    // macOS: `diskNsM...` → `diskN`.
    if let Some(rest) = name.strip_prefix("disk") {
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if !digits.is_empty() {
            return format!("disk{digits}");
        }
    }
    // Linux `nvme`/`mmcblk`: strip the `pN` partition suffix.
    if name.starts_with("nvme") || name.starts_with("mmcblk") {
        if let Some(idx) = name.rfind('p') {
            let is_partition = name.get(idx + 1..).is_some_and(|rest| {
                !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit())
            });
            if is_partition {
                return name.get(..idx).unwrap_or(name).to_owned();
            }
        }
        return name.to_owned();
    }
    // Linux `sdXN`/`vdXN`: strip trailing partition digits.
    name.trim_end_matches(|character: char| character.is_ascii_digit())
        .to_owned()
}
