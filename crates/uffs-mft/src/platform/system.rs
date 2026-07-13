// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Platform privilege, path, and drive-classification helpers.
//!
//! Covers Windows (UAC token, drive-type detection, volume enumeration) and
//! Unix (geteuid-based elevation check, memory query).
//!
//! Exception: single cross-platform module covering Windows Win32 FFI
//! (privilege checking, volume detection, drive classification) and Unix stubs
//! (geteuid, /proc/meminfo, sysctl).  Splitting by OS would require duplicating
//! shared types (`DriveType`, `SystemMemory`) or a separate types module,
//! adding more files for a marginal line-count benefit.

#[cfg(windows)]
use core::mem::size_of;

/// Narrow u32 size-of helper for Win32 FFI sizing parameters.
///
/// Every struct passed here is a small fixed-size Win32 type
/// (`TOKEN_ELEVATION`, `MEMORYSTATUSEX`, `StoragePropertyQuery`,
/// `UsnJournalDataV0`, etc.) whose size is provably well under
/// `u32::MAX`.  A saturating cast keeps the function total without
/// introducing an `#[expect]` per call site.
///
/// `pub(crate)` so the matching Win32 FFI const sites in `usn` can
/// reuse the single centralized expect rather than declaring their own.
#[cfg(windows)]
pub(crate) const fn u32_size_of<T>() -> u32 {
    // Saturating truncation: Win32 structs are always < u32::MAX bytes, so this
    // branch is unreachable in practice.
    if size_of::<T>() > u32::MAX as usize {
        u32::MAX
    } else {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "size_of<T>() is bounded above by the branch guard; cast is lossless"
        )]
        let size = size_of::<T>() as u32;
        size
    }
}

#[cfg(windows)]
use std::path::{Path, PathBuf};

#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
#[cfg(windows)]
use windows::core::PCWSTR;

#[cfg(windows)]
use super::drive_letter::DriveLetter;
#[cfg(windows)]
use super::volume::HandleGuard;

/// Checks if the current process is running with elevated privileges.
///
/// - **Windows**: returns `true` when the process token carries the
///   Administrator elevation flag (UAC-checked via `GetTokenInformation`).
/// - **Unix** (Linux, macOS, …): returns `true` when the effective user ID is 0
///   (root / sudo).
///
/// MFT reading requires Administrator privileges or `SE_BACKUP_PRIVILEGE` on
/// Windows and root on Unix.
#[cfg(windows)]
#[must_use]
#[expect(
    unsafe_code,
    reason = "FFI: windows API (OpenProcessToken, GetTokenInformation)"
)]
pub fn is_elevated() -> bool {
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token_handle = HANDLE::default();
    // SAFETY: `GetCurrentProcess()` returns a constant pseudo-handle and has
    // no preconditions.
    let current_process = unsafe { GetCurrentProcess() };
    // SAFETY: `current_process` is a valid pseudo-handle and `token_handle`
    // points to writable storage for the returned token handle.
    if unsafe { OpenProcessToken(current_process, TOKEN_QUERY, &raw mut token_handle) }.is_err() {
        return false;
    }

    let _token_guard = HandleGuard(token_handle);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut return_length = 0_u32;

    // SAFETY: `token_handle` was successfully opened above, `elevation`
    // provides writable storage matching the advertised buffer size, and
    // `return_length` is a valid out-parameter.
    let result = unsafe {
        GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(core::ptr::from_mut(&mut elevation).cast()),
            u32_size_of::<TOKEN_ELEVATION>(),
            &raw mut return_length,
        )
    };

    result.is_ok() && elevation.TokenIsElevated != 0
}

/// Unix implementation: elevated iff the effective user ID is 0 (root/sudo).
#[cfg(unix)]
#[must_use]
#[expect(
    unsafe_code,
    reason = "FFI: POSIX geteuid() — defined to be safe but the libc binding is unsafe"
)]
pub fn is_elevated() -> bool {
    // SAFETY: `geteuid()` is always safe to call: it has no preconditions,
    // never fails, and is signal-safe per POSIX.
    unsafe { libc::geteuid() == 0 }
}

/// Unix: the caller's effective user ID.
///
/// Used by daemon-management to decide whether a *mutating* action needs
/// elevation: a daemon owned by the **same** uid as the caller is theirs to
/// stop/restart, whereas a daemon owned by a different (typically root) user
/// is not (see `uffs-cli::commands::daemon_mgmt`).
#[cfg(unix)]
#[must_use]
#[expect(
    unsafe_code,
    reason = "FFI: POSIX geteuid() — defined to be safe but the libc binding is unsafe"
)]
pub fn current_euid() -> u32 {
    // SAFETY: `geteuid()` has no preconditions, never fails, and is
    // signal-safe per POSIX.
    unsafe { libc::geteuid() }
}

/// Unix: whether the calling user can create or remove entries inside `dir`,
/// via a POSIX `access(2)` `W_OK` probe.
///
/// Used by `uffs --uninstall` to decide whether a binary root is removable
/// without `sudo` before it tries: a user-owned root (`~/bin`, `~/.cargo/bin`,
/// a dev build) is writable; a root-owned one (`/usr/local/bin`) is not. A
/// missing or unreadable `dir` returns `false` (conservative: flag escalation).
#[cfg(unix)]
#[must_use]
#[expect(
    unsafe_code,
    reason = "FFI: POSIX access() — the libc binding is unsafe"
)]
pub fn dir_user_writable(dir: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;

    let Ok(c_dir) = alloc::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c_dir` is a valid NUL-terminated C string that outlives the
    // call; `access()` only reads through the pointer and returns 0 when the
    // directory is writable by the caller.
    unsafe { libc::access(c_dir.as_ptr(), libc::W_OK) == 0 }
}

/// Returns the path to the volume root (e.g., "C:\").
#[cfg(windows)]
#[must_use]
pub fn volume_root_path(volume: DriveLetter) -> PathBuf {
    PathBuf::from(format!("{}:\\", volume.as_char()))
}

/// Infer drive letter from a file path.
///
/// Returns `None` for paths without a drive-letter prefix (UNC paths,
/// relative paths when the CWD lookup also fails).  The drive byte
/// from the OS prefix is always an ASCII letter, so the
/// [`DriveLetter::parse`] conversion never fails in practice; `.ok()`
/// discards the theoretical error rather than introducing a fallible
/// API at this call site.
#[cfg(windows)]
#[must_use]
pub fn infer_drive_from_path(path: &Path) -> Option<DriveLetter> {
    use std::path::{Component, Prefix};

    if let Some(Component::Prefix(prefix)) = path.components().next()
        && let Prefix::Disk(drive_byte) | Prefix::VerbatimDisk(drive_byte) = prefix.kind()
    {
        return DriveLetter::parse(drive_byte as char).ok();
    }

    std::env::current_dir().ok().and_then(|cwd| {
        if let Some(Component::Prefix(prefix)) = cwd.components().next()
            && let Prefix::Disk(drive_byte) | Prefix::VerbatimDisk(drive_byte) = prefix.kind()
        {
            DriveLetter::parse(drive_byte as char).ok()
        } else {
            None
        }
    })
}

/// Returns the boot/system drive letter (from `%SystemDrive%`, typically `C`).
///
/// Falls back to [`DriveLetter::C`] if the environment variable is
/// missing or malformed.
#[cfg(windows)]
#[must_use]
pub fn detect_boot_drive() -> DriveLetter {
    std::env::var("SystemDrive")
        .ok()
        .and_then(|drive| drive.chars().next())
        .and_then(|ch| DriveLetter::parse(ch).ok())
        .unwrap_or(DriveLetter::C)
}

/// Returns `true` if the given drive letter is the boot/system drive.
#[cfg(windows)]
#[must_use]
pub fn is_boot_drive(drive_letter: DriveLetter) -> bool {
    drive_letter == detect_boot_drive()
}

/// Detects all available NTFS drives on the system.
#[cfg(windows)]
#[must_use]
#[expect(unsafe_code, reason = "FFI: windows API (GetLogicalDrives)")]
pub fn detect_ntfs_drives() -> Vec<DriveLetter> {
    use windows::Win32::Storage::FileSystem::GetLogicalDrives;

    let mut ntfs_drives = Vec::new();

    // SAFETY: `GetLogicalDrives` takes no pointers and returns a bitmask by
    // value, so there are no aliasing or lifetime preconditions to satisfy.
    let drive_mask = unsafe { GetLogicalDrives() };

    if drive_mask == 0 {
        return ntfs_drives;
    }

    for i in 0_u8..26 {
        if (drive_mask & (1_u32 << i)) != 0 {
            // `b'A' + i` for `i in 0..26` is always in `b'A'..=b'Z'`, so
            // the invariant of `DriveLetter::from_byte_unchecked` holds.
            let drive_letter = DriveLetter::from_byte_unchecked(b'A' + i);

            if is_ntfs_volume(drive_letter) {
                ntfs_drives.push(drive_letter);
            }
        }
    }

    ntfs_drives
}

/// Checks if a drive is an NTFS volume.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "FFI: windows API (GetDriveTypeW, GetVolumeInformationW)"
)]
fn is_ntfs_volume(drive_letter: DriveLetter) -> bool {
    use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetVolumeInformationW};

    let root_path: Vec<u16> = format!("{}:\\", drive_letter.as_char())
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();

    // SAFETY: `root_path` is UTF-16 and NUL-terminated for the duration of the
    // call.
    let drive_type = unsafe { GetDriveTypeW(PCWSTR(root_path.as_ptr())) };

    if drive_type != 2 && drive_type != 3 {
        return false;
    }

    let mut fs_name_buffer: [u16; 32] = [0; 32];

    // SAFETY: `root_path` is UTF-16 and NUL-terminated, and `fs_name_buffer`
    // points to writable storage for the filesystem name returned by Windows.
    let result = unsafe {
        GetVolumeInformationW(
            PCWSTR(root_path.as_ptr()),
            None,
            None,
            None,
            None,
            Some(&mut fs_name_buffer),
        )
    };

    if result.is_err() {
        return false;
    }

    // AUDIT-OK(bytes): decodes the Windows filesystem TYPE label (e.g. "NTFS")
    // for an `== "NTFS"` check — not an NTFS filename. A lossy decode could
    // only fail the equality (fail-safe: treat as not-NTFS), never corrupt a
    // stored name, so the instrumented name decoder does not apply here.
    let fs_name_raw = String::from_utf16_lossy(&fs_name_buffer);
    let fs_name = fs_name_raw.trim_end_matches('\0');

    fs_name == "NTFS"
}

/// Checks if a volume is read-only.
#[cfg(windows)]
#[must_use]
#[expect(unsafe_code, reason = "FFI: windows API (GetVolumeInformationW)")]
pub fn is_volume_read_only(drive_letter: DriveLetter) -> bool {
    use windows::Win32::Storage::FileSystem::GetVolumeInformationW;

    const FILE_READ_ONLY_VOLUME: u32 = 0x0008_0000;

    let root_path: Vec<u16> = format!("{}:\\", drive_letter.as_char())
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();

    let mut fs_flags: u32 = 0;

    // SAFETY: `root_path` is UTF-16 and NUL-terminated, and `fs_flags` points
    // to writable storage for the returned filesystem flags.
    let result = unsafe {
        GetVolumeInformationW(
            PCWSTR(root_path.as_ptr()),
            None,
            None,
            None,
            Some(&raw mut fs_flags),
            None,
        )
    };

    if result.is_err() {
        return false;
    }

    (fs_flags & FILE_READ_ONLY_VOLUME) != 0
}

/// Represents the type of storage device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveType {
    /// `NVMe` Solid State Drive (`PCIe`, extremely high IOPS, 64K+ queue
    /// depth).
    Nvme,
    /// SATA Solid State Drive (no seek time, high IOPS, 32 queue depth).
    Ssd,
    /// Hard Disk Drive (rotational, seek time matters).
    Hdd,
    /// Removable / external media — USB, SD, or MMC. The bus, not the media,
    /// is the bottleneck, so it takes the conservative (HDD-like) I/O profile.
    Removable,
    /// Virtual disk — VHD/VHDX or a file/RAM-backed virtual volume. The backing
    /// medium is opaque, so it takes the conservative (HDD-like) I/O profile.
    Virtual,
    /// Unknown drive type (assume HDD for safety).
    Unknown,
}

impl DriveType {
    /// Short human display label for this medium (`"NVMe"`, `"SSD"`, `"HDD"`,
    /// `"Removable"`, `"Virtual"`, `"Unknown"`). Shared by the `uffs-mft
    /// drives` table and the `uffs --daemon status -v` physical view so both
    /// surfaces name drive kinds identically.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Nvme => "NVMe",
            Self::Ssd => "SSD",
            Self::Hdd => "HDD",
            Self::Removable => "Removable",
            Self::Virtual => "Virtual",
            Self::Unknown => "Unknown",
        }
    }

    /// Returns the optimal chunk size for this drive type.
    #[must_use]
    pub const fn optimal_chunk_size(self) -> usize {
        match self {
            Self::Nvme => 4 * 1024 * 1024,
            Self::Ssd => 2 * 1024 * 1024,
            Self::Hdd | Self::Removable | Self::Virtual | Self::Unknown => 1024 * 1024,
        }
    }

    /// Returns the optimal number of prefetch buffers.
    #[must_use]
    pub const fn prefetch_buffers(self) -> usize {
        match self {
            Self::Nvme => 8,
            Self::Ssd => 4,
            Self::Hdd | Self::Removable | Self::Virtual | Self::Unknown => 2,
        }
    }

    /// Returns the optimal I/O concurrency (queue depth) for this drive type.
    #[must_use]
    pub const fn optimal_concurrency(self) -> usize {
        match self {
            Self::Nvme => 32,
            Self::Ssd => 8,
            Self::Hdd | Self::Removable | Self::Virtual | Self::Unknown => 4,
        }
    }

    /// Returns the optimal I/O concurrency for HDD based on MFT fragmentation.
    #[must_use]
    pub const fn optimal_concurrency_for_hdd(extent_count: usize) -> usize {
        if extent_count > 50 {
            2
        } else if extent_count > 20 {
            4
        } else {
            6
        }
    }

    /// Returns the optimal I/O chunk size for this drive type.
    #[must_use]
    pub const fn optimal_io_size(self) -> usize {
        self.optimal_chunk_size()
    }

    /// Returns true if this is a high-performance drive (SSD or `NVMe`).
    #[must_use]
    pub const fn is_high_performance(self) -> bool {
        matches!(self, Self::Nvme | Self::Ssd)
    }

    /// Returns true if this drive benefits from parallel parsing.
    #[must_use]
    pub const fn benefits_from_parallel_parsing(self) -> bool {
        matches!(self, Self::Nvme)
    }
}

/// Detects whether a drive is `NVMe`, SSD, HDD, removable (USB / SD / MMC), or
/// virtual (VHD / file- or RAM-backed).
#[cfg(windows)]
#[must_use]
#[expect(
    unsafe_code,
    reason = "FFI: windows API (CreateFileW, DeviceIoControl) for drive classification"
)]
#[expect(
    clippy::too_many_lines,
    reason = "drive-type detection ladder: opens a single physical-drive handle then runs a fall-through sequence of IOCTL probes (storage descriptor for NVMe → seek-penalty for SSD/HDD → TRIM-support fallback). Splitting would either replicate the FFI handle/struct setup per-probe or hide the ordered fall-through behind helper indirection"
)]
pub fn detect_drive_type(drive_letter: DriveLetter) -> DriveType {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
    const STORAGE_DEVICE_PROPERTY: u32 = 0;
    const STORAGE_DEVICE_SEEK_PENALTY_PROPERTY: u32 = 7;
    const PROPERTY_STANDARD_QUERY: u32 = 0;
    const BUS_TYPE_NVME: u32 = 17;
    // Removable / external buses (STORAGE_BUS_TYPE): USB, SD, MMC. The bus is
    // the bottleneck, so these all classify as `DriveType::Removable`.
    const BUS_TYPE_USB: u32 = 7;
    const BUS_TYPE_SD: u32 = 12;
    const BUS_TYPE_MMC: u32 = 13;
    const BUS_TYPE_VIRTUAL: u32 = 14;
    const BUS_TYPE_FILE_BACKED_VIRTUAL: u32 = 15;
    const STORAGE_DEVICE_DESCRIPTOR_BUS_TYPE_OFFSET: usize = 28;
    const STORAGE_DEVICE_DESCRIPTOR_BUS_TYPE_END: usize =
        STORAGE_DEVICE_DESCRIPTOR_BUS_TYPE_OFFSET + size_of::<u32>();

    #[repr(C)]
    struct StoragePropertyQuery {
        property_id: u32,
        query_type: u32,
        additional_parameters: [u8; 1],
    }

    #[repr(C)]
    struct DeviceSeekPenaltyDescriptor {
        version: u32,
        size: u32,
        incurs_seek_penalty: u8,
    }

    let drive_path: Vec<u16> = format!("\\\\.\\{}:", drive_letter.as_char())
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();

    // SAFETY: `drive_path` is UTF-16 and NUL-terminated for the duration of the
    // call, optional pointers are `None`, and any returned handle is wrapped in
    // `HandleGuard` before use.
    let handle_result = unsafe {
        CreateFileW(
            PCWSTR(drive_path.as_ptr()),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    };

    let Ok(drive_handle) = handle_result else {
        return DriveType::Unknown;
    };

    let drive_classification = {
        let _handle_guard = HandleGuard(drive_handle);

        let bus_type: Option<u32> = {
            let query = StoragePropertyQuery {
                property_id: STORAGE_DEVICE_PROPERTY,
                query_type: PROPERTY_STANDARD_QUERY,
                additional_parameters: [0],
            };

            let mut buffer = [0_u8; 1024];
            let mut bytes_returned: u32 = 0;

            // `buffer` is a fixed-size 1024-byte stack array; len is compile-time
            // known and always fits in u32.
            let buffer_len_u32 = u32::try_from(buffer.len()).unwrap_or(u32::MAX);

            // SAFETY: `drive_handle` is a live device handle, `query` contains the
            // exact input bytes Windows expects for this IOCTL, `buffer` is a
            // writable output buffer of the advertised length, and
            // `bytes_returned` is a valid out-parameter.
            let result = unsafe {
                DeviceIoControl(
                    drive_handle,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    Some((&raw const query).cast::<core::ffi::c_void>()),
                    u32_size_of::<StoragePropertyQuery>(),
                    Some(buffer.as_mut_ptr().cast::<core::ffi::c_void>()),
                    buffer_len_u32,
                    Some(&raw mut bytes_returned),
                    None,
                )
            };

            // Compare in usize space to avoid truncating the compile-time
            // constant offset into u32.
            if result.is_ok() && (bytes_returned as usize) >= STORAGE_DEVICE_DESCRIPTOR_BUS_TYPE_END
            {
                buffer
                    .get(
                        STORAGE_DEVICE_DESCRIPTOR_BUS_TYPE_OFFSET
                            ..STORAGE_DEVICE_DESCRIPTOR_BUS_TYPE_END,
                    )
                    .and_then(|bytes| <[u8; size_of::<u32>()]>::try_from(bytes).ok())
                    .map(u32::from_le_bytes)
            } else {
                None
            }
        };

        // Bus type settles NVMe and removable media directly; everything else
        // (SATA/SAS/RAID/…) falls through to the seek-penalty SSD-vs-HDD probe.
        match bus_type {
            Some(BUS_TYPE_NVME) => return DriveType::Nvme,
            Some(BUS_TYPE_USB | BUS_TYPE_SD | BUS_TYPE_MMC) => return DriveType::Removable,
            Some(BUS_TYPE_VIRTUAL | BUS_TYPE_FILE_BACKED_VIRTUAL) => return DriveType::Virtual,
            _ => {}
        }

        let query = StoragePropertyQuery {
            property_id: STORAGE_DEVICE_SEEK_PENALTY_PROPERTY,
            query_type: PROPERTY_STANDARD_QUERY,
            additional_parameters: [0],
        };

        let mut descriptor = DeviceSeekPenaltyDescriptor {
            version: 0,
            size: 0,
            incurs_seek_penalty: 0,
        };

        let mut bytes_returned: u32 = 0;

        // SAFETY: `drive_handle` is a live device handle, `query` and `descriptor`
        // point to initialized storage matching the advertised sizes, and
        // `bytes_returned` is a valid out-parameter.
        let result = unsafe {
            DeviceIoControl(
                drive_handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                Some((&raw const query).cast::<core::ffi::c_void>()),
                u32_size_of::<StoragePropertyQuery>(),
                Some((&raw mut descriptor).cast::<core::ffi::c_void>()),
                u32_size_of::<DeviceSeekPenaltyDescriptor>(),
                Some(&raw mut bytes_returned),
                None,
            )
        };

        let big_enough =
            result.is_ok() && (bytes_returned as usize) >= size_of::<DeviceSeekPenaltyDescriptor>();
        let drive_type = if descriptor.incurs_seek_penalty == 0 {
            DriveType::Ssd
        } else {
            DriveType::Hdd
        };
        big_enough.then_some(drive_type)
    };

    let result = drive_classification.unwrap_or_else(|| detect_drive_type_via_trim(drive_letter));
    tracing::debug!(
        drive = %drive_letter,
        detected = ?result,
        seek_penalty_query = ?drive_classification,
        "🔍 Drive type detection result"
    );
    result
}

/// Fallback detection using TRIM support (SSDs support TRIM).
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "FFI: windows API (CreateFileW, DeviceIoControl) for trim detection"
)]
fn detect_drive_type_via_trim(drive_letter: DriveLetter) -> DriveType {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
    const STORAGE_DEVICE_TRIM_PROPERTY: u32 = 8;
    const PROPERTY_STANDARD_QUERY: u32 = 0;

    #[repr(C)]
    struct StoragePropertyQuery {
        property_id: u32,
        query_type: u32,
        additional_parameters: [u8; 1],
    }

    #[repr(C)]
    struct DeviceTrimDescriptor {
        version: u32,
        size: u32,
        trim_enabled: u8,
    }

    let drive_path: Vec<u16> = format!("\\\\.\\{}:", drive_letter.as_char())
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();

    // SAFETY: `drive_path` is UTF-16 and NUL-terminated for the duration of the
    // call, optional pointers are `None`, and any returned handle is wrapped in
    // `HandleGuard` before use.
    let handle_result = unsafe {
        CreateFileW(
            PCWSTR(drive_path.as_ptr()),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    };

    let Ok(drive_handle) = handle_result else {
        return DriveType::Unknown;
    };

    let _handle_guard = HandleGuard(drive_handle);

    let query = StoragePropertyQuery {
        property_id: STORAGE_DEVICE_TRIM_PROPERTY,
        query_type: PROPERTY_STANDARD_QUERY,
        additional_parameters: [0],
    };

    let mut descriptor = DeviceTrimDescriptor {
        version: 0,
        size: 0,
        trim_enabled: 0,
    };

    let mut bytes_returned: u32 = 0;

    // SAFETY: `drive_handle` is a live device handle, `query` and `descriptor`
    // point to initialized storage matching the advertised sizes, and
    // `bytes_returned` is a valid out-parameter.
    let result = unsafe {
        DeviceIoControl(
            drive_handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some((&raw const query).cast::<core::ffi::c_void>()),
            u32_size_of::<StoragePropertyQuery>(),
            Some((&raw mut descriptor).cast::<core::ffi::c_void>()),
            u32_size_of::<DeviceTrimDescriptor>(),
            Some(&raw mut bytes_returned),
            None,
        )
    };

    if result.is_ok() && (bytes_returned as usize) >= size_of::<DeviceTrimDescriptor>() {
        if descriptor.trim_enabled != 0 {
            DriveType::Ssd
        } else {
            DriveType::Hdd
        }
    } else {
        DriveType::Unknown
    }
}

// ─── System Memory ──────────────────────────────────────────────────────────

/// Information about available system memory.
#[derive(Debug, Clone, Copy)]
pub struct SystemMemory {
    /// Total physical RAM in bytes.
    pub total_bytes: u64,
    /// Currently available (free + reclaimable) RAM in bytes.
    pub available_bytes: u64,
}

impl SystemMemory {
    /// Fraction of RAM currently available (0.0 – 1.0).
    #[must_use]
    pub fn available_fraction(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        #[expect(clippy::float_arithmetic, reason = "division for ratio")]
        {
            crate::index::u64_to_f64(self.available_bytes)
                / crate::index::u64_to_f64(self.total_bytes)
        }
    }
}

/// Queries the system for total and available physical memory.
///
/// Uses platform-specific APIs:
/// - **Windows**: `GlobalMemoryStatusEx`
/// - **macOS**: `sysctl hw.memsize` + `vm_stat`
/// - **Linux**: `/proc/meminfo`
///
/// Returns a conservative fallback (8 GB total, 2 GB available) if the
/// platform query fails.
#[must_use]
pub fn query_system_memory() -> SystemMemory {
    let fallback = SystemMemory {
        total_bytes: 8 * 1024 * 1024 * 1024,
        available_bytes: 2 * 1024 * 1024 * 1024,
    };

    query_system_memory_impl().unwrap_or(fallback)
}

/// Platform-specific memory query implementation.
fn query_system_memory_impl() -> Option<SystemMemory> {
    #[cfg(windows)]
    {
        query_memory_windows()
    }
    #[cfg(target_os = "macos")]
    {
        query_memory_macos()
    }
    #[cfg(target_os = "linux")]
    {
        query_memory_linux()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

/// Windows implementation using `GlobalMemoryStatusEx`.
#[cfg(windows)]
#[expect(unsafe_code, reason = "FFI: windows API (GlobalMemoryStatusEx)")]
fn query_memory_windows() -> Option<SystemMemory> {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    let mut status = MEMORYSTATUSEX {
        dwLength: u32_size_of::<MEMORYSTATUSEX>(),
        ..MEMORYSTATUSEX::default()
    };
    // SAFETY: `status` is a properly sized, initialised MEMORYSTATUSEX with
    // `dwLength` set.  The pointer is valid for the duration of the call.
    unsafe { GlobalMemoryStatusEx(&raw mut status).ok() }?;
    Some(SystemMemory {
        total_bytes: status.ullTotalPhys,
        available_bytes: status.ullAvailPhys,
    })
}

/// macOS implementation using `sysctl` + `vm_stat` commands.
#[cfg(target_os = "macos")]
fn query_memory_macos() -> Option<SystemMemory> {
    use std::process::Command;

    // Total: sysctl hw.memsize → "hw.memsize: 34359738368"
    let total_out = Command::new("sysctl")
        .arg("-n")
        .arg("hw.memsize")
        .output()
        .ok()?;
    // AUDIT-OK(bytes): sysctl memsize for a stats display; the following
    // .parse().ok()? already fails closed on any non-numeric/garbage byte.
    // (WI-4.3 follow-up)
    let total_str = String::from_utf8_lossy(&total_out.stdout);
    let total_bytes: u64 = total_str.trim().parse().ok()?;

    // Available: vm_stat → parse "Pages free" and "Pages inactive"
    let vm_out = Command::new("vm_stat").output().ok()?;
    // AUDIT-OK(bytes): vm_stat output parsed line-by-line for a stats display;
    // each field parse fails closed. (WI-4.3 follow-up)
    let vm_str = String::from_utf8_lossy(&vm_out.stdout);

    // First line: "Mach Virtual Memory Statistics: (page size of 16384 bytes)"
    let page_size = vm_str
        .lines()
        .next()
        .and_then(|line| {
            let start = line.find("page size of ")? + "page size of ".len();
            let tail = line.get(start..)?;
            let end = tail.find(' ')? + start;
            line.get(start..end)?.parse::<u64>().ok()
        })
        .unwrap_or(16384);

    let mut free_pages: u64 = 0;
    let mut inactive_pages: u64 = 0;
    let mut speculative_pages: u64 = 0;

    for line in vm_str.lines() {
        if let Some(val) = parse_vmstat_line(line, "Pages free") {
            free_pages = val;
        } else if let Some(val) = parse_vmstat_line(line, "Pages inactive") {
            inactive_pages = val;
        } else if let Some(val) = parse_vmstat_line(line, "Pages speculative") {
            speculative_pages = val;
        }
    }

    let available_bytes = (free_pages + inactive_pages + speculative_pages) * page_size;

    Some(SystemMemory {
        total_bytes,
        available_bytes,
    })
}

/// Parses a `vm_stat` line like `"Pages free:       123456."` → `Some(123456)`.
#[cfg(target_os = "macos")]
fn parse_vmstat_line(line: &str, key: &str) -> Option<u64> {
    if !line.starts_with(key) {
        return None;
    }
    let val_str = line.split(':').nth(1)?.trim().trim_end_matches('.');
    val_str.parse().ok()
}

/// Linux implementation using `/proc/meminfo`.
#[cfg(target_os = "linux")]
fn query_memory_linux() -> Option<SystemMemory> {
    let contents = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total_kb: u64 = 0;
    let mut available_kb: u64 = 0;

    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total_kb = parse_meminfo_kb(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available_kb = parse_meminfo_kb(rest);
        }
    }

    if total_kb == 0 {
        return None;
    }

    Some(SystemMemory {
        total_bytes: total_kb * 1024,
        available_bytes: available_kb * 1024,
    })
}

/// Parses a `/proc/meminfo` value like `"    12345678 kB"` → `12345678`.
#[cfg(target_os = "linux")]
fn parse_meminfo_kb(rest: &str) -> u64 {
    rest.split_whitespace()
        .next()
        .and_then(|val| val.parse().ok())
        .unwrap_or(0)
}
