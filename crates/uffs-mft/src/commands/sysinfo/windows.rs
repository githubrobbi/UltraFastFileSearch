// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Windows capture-host collectors: OS identity (registry), VSS availability,
//! per-drive NTFS geometry, and all-volume enumeration. This whole module is
//! compiled only on Windows (see the `mod windows;` gate in `mod.rs`).

use super::capture_mode::{InstallationType, parse_installation_type};
use super::report::{DriveCapture, Report, Volume, base_host};

/// Collect the capture-host report on Windows.
pub(super) fn collect() -> Report {
    let (os_name, os_build, edition, installation_type) = os_identity();
    let host = base_host(
        os_name,
        os_build,
        edition,
        installation_type,
        vss_available(),
        true,
    );
    Report {
        host,
        drives: collect_drives(),
        volumes: collect_volumes(),
    }
}

/// Human label for a [`uffs_mft::DriveType`].
const fn media_label(kind: uffs_mft::DriveType) -> &'static str {
    use uffs_mft::DriveType;
    match kind {
        DriveType::Nvme => "NVMe",
        DriveType::Ssd => "SSD",
        DriveType::Hdd => "HDD",
        DriveType::Removable => "Removable",
        DriveType::Virtual => "Virtual",
        DriveType::Unknown => "Unknown",
    }
}

/// Read the OS identity strings from the registry.
fn os_identity() -> (String, String, String, InstallationType) {
    const CV: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let product = reg_string(CV, "ProductName").unwrap_or_else(|| "Windows".to_owned());
    let display = reg_string(CV, "DisplayVersion").or_else(|| reg_string(CV, "ReleaseId"));
    let os_build = reg_string(CV, "CurrentBuildNumber").unwrap_or_else(|| "?".to_owned());
    let edition = reg_string(CV, "EditionID").unwrap_or_else(|| "?".to_owned());
    let installation_type = reg_string(CV, "InstallationType")
        .map_or(InstallationType::Unknown, |raw| {
            parse_installation_type(&raw)
        });
    let os_name = display.map_or_else(|| product.clone(), |ver| format!("{product} {ver}"));
    (os_name, os_build, edition, installation_type)
}

/// Whether the Volume Shadow Copy service is installed and not disabled.
fn vss_available() -> bool {
    // `Start == 4` means "Disabled"; anything else (or presence) means usable.
    reg_u32(r"SYSTEM\CurrentControlSet\Services\VSS", "Start").is_some_and(|start| start != 4)
}

/// Volume-derived geometry, or `unavailable` placeholders when the handle
/// cannot be opened (e.g. not elevated).
struct VolFields {
    /// Total capacity in bytes.
    total_bytes: u64,
    /// Free capacity in bytes.
    free_bytes: u64,
    /// Cluster size in bytes.
    bytes_per_cluster: u32,
    /// `$MFT` size in bytes.
    mft_size_bytes: u64,
    /// Allocated MFT record count.
    mft_records: u64,
    /// Volume serial (hex), or a placeholder when unavailable.
    volume_serial: String,
    /// NTFS version, or `?` when unavailable.
    ntfs_version: String,
}

impl VolFields {
    /// Placeholders for a volume whose handle could not be opened.
    fn unavailable() -> Self {
        Self {
            total_bytes: 0,
            free_bytes: 0,
            bytes_per_cluster: 0,
            mft_size_bytes: 0,
            mft_records: 0,
            volume_serial: String::from("(needs elevation)"),
            ntfs_version: String::from("?"),
        }
    }

    /// Extract geometry from an open volume handle.
    fn from_handle(handle: &uffs_mft::platform::VolumeHandle) -> Self {
        let vol = handle.volume_data();
        let bytes_per_cluster = vol.bytes_per_cluster;
        let mft_size_bytes = vol.mft_valid_data_length;
        let mft_records = if vol.bytes_per_file_record_segment > 0 {
            mft_size_bytes / u64::from(vol.bytes_per_file_record_segment)
        } else {
            0
        };
        Self {
            total_bytes: vol.total_clusters * u64::from(bytes_per_cluster),
            free_bytes: vol.free_clusters * u64::from(bytes_per_cluster),
            bytes_per_cluster,
            mft_size_bytes,
            mft_records,
            volume_serial: format!("0x{:016X}", vol.volume_serial_number),
            ntfs_version: format!("{}.{}", vol.ntfs_major_version, vol.ntfs_minor_version),
        }
    }
}

/// Enumerate NTFS drives with media type, geometry, and capture capability.
fn collect_drives() -> Vec<DriveCapture> {
    use uffs_mft::DriveType;
    use uffs_mft::platform::{
        VolumeHandle, detect_drive_type, detect_ntfs_drives, is_boot_drive, is_volume_read_only,
    };

    detect_ntfs_drives()
        .into_iter()
        .map(|drive| {
            let media = detect_drive_type(drive);
            let read_only = is_volume_read_only(drive);
            let fields = VolumeHandle::open(drive)
                .ok()
                .map_or_else(VolFields::unavailable, |handle| {
                    VolFields::from_handle(&handle)
                });
            DriveCapture {
                drive: drive.to_string(),
                boot: is_boot_drive(drive),
                media_type: media_label(media).to_owned(),
                volume_serial: fields.volume_serial,
                total_bytes: fields.total_bytes,
                free_bytes: fields.free_bytes,
                bytes_per_cluster: fields.bytes_per_cluster,
                mft_size_bytes: fields.mft_size_bytes,
                mft_records: fields.mft_records,
                ntfs_version: fields.ntfs_version,
                read_only,
                iocp_capturable: !read_only,
                vss_eligible: !matches!(media, DriveType::Removable),
            }
        })
        .collect()
}

/// List all mounted logical volumes (any filesystem) for host provenance.
#[expect(
    unsafe_code,
    reason = "FFI: GetLogicalDrives / GetVolumeInformationW / GetDiskFreeSpaceExW to enumerate all mounted volumes"
)]
fn collect_volumes() -> Vec<Volume> {
    use uffs_mft::platform::{DriveLetter, detect_drive_type};
    use windows::Win32::Storage::FileSystem::{
        GetDiskFreeSpaceExW, GetLogicalDrives, GetVolumeInformationW,
    };
    use windows::core::PCWSTR;

    // SAFETY: `GetLogicalDrives` takes no pointers and returns a bitmask by value.
    let mask = unsafe { GetLogicalDrives() };
    let mut volumes = Vec::new();
    for index in 0_u8..26 {
        if (mask & (1_u32 << index)) == 0 {
            continue;
        }
        let letter = char::from(b'A' + index);
        let root: Vec<u16> = format!("{letter}:\\")
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();

        let mut fs_buf = [0_u16; 32];
        // SAFETY: `root` is NUL-terminated UTF-16 valid for the call; `fs_buf` is
        // a writable 32-element buffer for the filesystem name; the other
        // out-parameters are documented as accepting `None`.
        let info = unsafe {
            GetVolumeInformationW(
                PCWSTR(root.as_ptr()),
                None,
                None,
                None,
                None,
                Some(&mut fs_buf),
            )
        };
        if info.is_err() {
            // Empty removable slot / disconnected network drive — skip.
            continue;
        }

        let mut free_to_caller = 0_u64;
        let mut total = 0_u64;
        let mut total_free = 0_u64;
        // SAFETY: `root` is NUL-terminated UTF-16 valid for the call; the three
        // out-parameters point to writable `u64` locals. Sizes are best-effort;
        // on failure the locals stay zero.
        let _sizes_ok = unsafe {
            GetDiskFreeSpaceExW(
                PCWSTR(root.as_ptr()),
                Some(&raw mut free_to_caller),
                Some(&raw mut total),
                Some(&raw mut total_free),
            )
        }
        .is_ok();

        let media_type = DriveLetter::parse(letter)
            .ok()
            .map(detect_drive_type)
            .map_or("Unknown", media_label);

        volumes.push(Volume {
            mount: format!("{letter}:\\"),
            filesystem: u16_to_string(&fs_buf),
            media_type: media_type.to_owned(),
            total_bytes: total,
            free_bytes: free_to_caller,
        });
    }
    volumes
}

/// Decode a NUL-terminated UTF-16 buffer up to its first NUL.
fn u16_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&code| code == 0).unwrap_or(buf.len());
    // AUDIT-OK(bytes): decodes a Win32 filesystem-name buffer (e.g. "NTFS",
    // "FAT32") from GetVolumeInformationW, not an NTFS on-disk filename — it
    // never touches the MFT name path the WI-4.1 malformed-name mitigation
    // guards, and the value is display-only sysinfo, not indexed/searched.
    String::from_utf16_lossy(buf.get(..len).unwrap_or(&[]))
}

/// Read a read-only `HKLM` string value via `RegGetValueW`.
///
/// Returns `None` when the key/value is absent or not a string.
#[expect(
    unsafe_code,
    reason = "FFI: Win32 RegGetValueW to read read-only HKLM OS-identity strings"
)]
fn reg_string(subkey: &str, value: &str) -> Option<String> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
    use windows::core::PCWSTR;

    let subkey_w: Vec<u16> = subkey.encode_utf16().chain(core::iter::once(0)).collect();
    let value_w: Vec<u16> = value.encode_utf16().chain(core::iter::once(0)).collect();
    let mut buf = [0_u16; 512];
    // Bytes available in `buf` (512 * size_of::<u16>()); updated in place.
    let mut cb: u32 = 1024;

    // SAFETY: `subkey_w`/`value_w` are NUL-terminated UTF-16 buffers valid for
    // the call; `buf` is writable for `cb` bytes; `RRF_RT_REG_SZ` restricts the
    // result to a string value; `cb` receives the byte length written.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(value_w.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast::<core::ffi::c_void>()),
            Some(&raw mut cb),
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    // `cb` counts bytes including the trailing NUL; convert to a u16 length.
    let units = usize::try_from(cb).unwrap_or(0) / size_of::<u16>();
    let len = units.saturating_sub(1).min(buf.len());
    // AUDIT-OK(bytes): decodes an HKLM OS-identity registry string (e.g.
    // ProductName), not an NTFS on-disk filename — no MFT name path or
    // WI-4.1 mitigation applies; display-only sysinfo, not indexed/searched.
    let text = String::from_utf16_lossy(buf.get(..len)?);
    let trimmed = text.trim().to_owned();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// Read a read-only `HKLM` `DWORD` value via `RegGetValueW`.
#[expect(
    unsafe_code,
    reason = "FFI: Win32 RegGetValueW to read a read-only service-config DWORD"
)]
fn reg_u32(subkey: &str, value: &str) -> Option<u32> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW};
    use windows::core::PCWSTR;

    let subkey_w: Vec<u16> = subkey.encode_utf16().chain(core::iter::once(0)).collect();
    let value_w: Vec<u16> = value.encode_utf16().chain(core::iter::once(0)).collect();
    let mut data: u32 = 0;
    let mut cb: u32 = 4;

    // SAFETY: NUL-terminated UTF-16 key/value valid for the call; `data` is a
    // writable `u32` of `cb` bytes; `RRF_RT_REG_DWORD` restricts the result to a
    // DWORD.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(value_w.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut data).cast::<core::ffi::c_void>()),
            Some(&raw mut cb),
        )
    };
    (status == ERROR_SUCCESS).then_some(data)
}
