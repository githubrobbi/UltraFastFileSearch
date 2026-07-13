// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Non-privileged physical drive summary: kind, capacity, used, and free.
//!
//! `VolumeHandle` needs an opened volume
//! handle (Administrator or the Access Broker) to read `$MFT` geometry.
//! Everything here, by contrast, comes from non-privileged Win32 calls
//! (`GetVolumeInformationW`, `GetDiskFreeSpaceExW`, and the query-only
//! `IOCTL_STORAGE_QUERY_PROPERTY` behind
//! `detect_drive_type`), so a
//! non-elevated `uffs` — the daemon's normal mode via the Access Broker — can
//! still describe each NTFS drive: its kind (`NVMe` / SSD / HDD), volume label,
//! total size, used, and free space. `$MFT` statistics are intentionally out
//! of scope here; callers that want them (e.g. the `uffs-mft drives` table)
//! layer them on via `VolumeHandle`.
//!
//! This is the single gathering path for physical drive facts; the CLI status
//! view and the `drives` command both build on [`physical_drives`]. On
//! non-Windows targets it returns an empty vector (no NTFS volume model).

use crate::platform::{DriveLetter, DriveType};

/// Physical characteristics of one mounted NTFS volume, gathered without
/// elevation. Answers "what hardware is this drive, and how full is it".
#[derive(Debug, Clone)]
pub struct PhysicalDrive {
    /// Drive letter (e.g. `C`).
    pub letter: DriveLetter,
    /// `true` when this drive hosts the running OS (the boot/system volume).
    pub is_boot: bool,
    /// Volume label (empty string when the volume has no label set).
    pub label: String,
    /// Detected medium: `NVMe` / SSD / HDD / Removable / Virtual / Unknown.
    pub drive_type: DriveType,
    /// Total volume capacity in bytes (`0` when the size query failed).
    pub total_bytes: u64,
    /// Used capacity in bytes (`total - free`).
    pub used_bytes: u64,
    /// Free space in bytes available to the caller.
    pub free_bytes: u64,
}

impl PhysicalDrive {
    /// Used capacity as a percentage in `[0.0, 100.0]`; `0.0` for an empty or
    /// unreadable volume (guards divide-by-zero).
    #[must_use]
    #[expect(
        clippy::float_arithmetic,
        reason = "human-readable used-% derived from byte counters; rendered with one decimal"
    )]
    pub fn used_pct(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0_f64;
        }
        (crate::u64_to_f64(self.used_bytes) / crate::u64_to_f64(self.total_bytes)) * 100.0_f64
    }

    /// Short display label for [`Self::drive_type`] (`"NVMe"`, `"SSD"`, ...).
    #[must_use]
    pub const fn type_label(&self) -> &'static str {
        self.drive_type.label()
    }
}

/// Enumerate every NTFS volume with its kind, label, capacity, used, and free
/// space, using only non-privileged Win32 calls. Order follows
/// `detect_ntfs_drives`.
#[cfg(windows)]
#[must_use]
pub fn physical_drives() -> Vec<PhysicalDrive> {
    use crate::platform::{detect_drive_type, detect_ntfs_drives, is_boot_drive};

    detect_ntfs_drives()
        .into_iter()
        .map(|letter| {
            let (total_bytes, free_bytes) = disk_space(letter);
            PhysicalDrive {
                letter,
                is_boot: is_boot_drive(letter),
                label: volume_label(letter).unwrap_or_default(),
                drive_type: detect_drive_type(letter),
                total_bytes,
                used_bytes: total_bytes.saturating_sub(free_bytes),
                free_bytes,
            }
        })
        .collect()
}

/// Non-Windows stub: there is no NTFS volume model to enumerate here.
#[cfg(not(windows))]
#[must_use]
pub const fn physical_drives() -> Vec<PhysicalDrive> {
    Vec::new()
}

/// `(total_bytes, free_bytes)` for `letter` via the non-privileged
/// `GetDiskFreeSpaceExW`. Both are `0` when the query fails.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "FFI: GetDiskFreeSpaceExW — non-privileged volume size query"
)]
fn disk_space(letter: DriveLetter) -> (u64, u64) {
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    use windows::core::PCWSTR;

    let root: Vec<u16> = format!("{letter}:\\")
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();

    let mut free_to_caller = 0_u64;
    let mut total = 0_u64;
    let mut total_free = 0_u64;
    // SAFETY: `root` is a NUL-terminated UTF-16 buffer valid for the call; the
    // three out-parameters point to writable `u64` locals. On failure the
    // locals stay `0`.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            PCWSTR(root.as_ptr()),
            Some(&raw mut free_to_caller),
            Some(&raw mut total),
            Some(&raw mut total_free),
        )
    }
    .is_ok();
    if ok { (total, free_to_caller) } else { (0, 0) }
}

/// Volume label for `letter` via the non-privileged `GetVolumeInformationW`,
/// or `None` when the volume is unreadable. A labelless volume yields
/// `Some(String::new())`.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "FFI: GetVolumeInformationW — non-privileged volume label read"
)]
fn volume_label(letter: DriveLetter) -> Option<String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt as _;

    use windows::Win32::Storage::FileSystem::GetVolumeInformationW;
    use windows::core::PCWSTR;

    let root: Vec<u16> = format!("{letter}:\\")
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();
    let mut name_buf = [0_u16; 261];
    // SAFETY: `root` is a NUL-terminated UTF-16 buffer valid for the call;
    // `name_buf` is a writable 261-element stack buffer (the Win32 maximum
    // volume-name length); the remaining four out-parameters accept `None`.
    let ok = unsafe {
        GetVolumeInformationW(
            PCWSTR(root.as_ptr()),
            Some(&mut name_buf),
            None,
            None,
            None,
            None,
        )
    }
    .is_ok();
    ok.then(|| {
        let len = name_buf.iter().position(|&code| code == 0).unwrap_or(0);
        OsString::from_wide(name_buf.get(..len).unwrap_or(&[]))
            .to_string_lossy()
            .into_owned()
    })
}
