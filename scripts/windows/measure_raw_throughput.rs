#!/usr/bin/env rust-script
//! ```cargo
//! [target.'cfg(windows)'.dependencies]
//! windows = { version = "0.62", features = [
//!     "Win32_Foundation",
//!     "Win32_Security",
//!     "Win32_Storage_FileSystem",
//!     "Win32_System_IO",
//!     "Win32_System_Ioctl",
//! ] }
//! ```
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Measures the raw sequential-read throughput floor of a physical
//! volume, independent of `uffs-content`'s per-file read pipeline --
//! a `dd`-style streaming read straight off the block device.
//!
//! Real-hardware benchmarking kept showing sustained content-read
//! throughput in the single-digit MiB/s range on some drives even
//! after ascending-FRS ordering and true-LCN-sorted ordering were both
//! in place (see `check_frs_vs_lcn.rs`). Without a floor measurement,
//! "the pipeline is slow" and "this drive simply cannot go faster than
//! ~8 MiB/s at this access pattern" are indistinguishable -- this tool
//! answers that by reading raw bytes sequentially off the volume,
//! bypassing candidate enumeration, `OpenFileById`, and every other
//! layer of the real pipeline entirely.
//!
//! Reads three zones by default (outer edge, middle, inner edge of the
//! volume) since HDDs are markedly faster at the outer edge (larger
//! track circumference) than the inner one -- a single-point
//! measurement can be misleadingly optimistic or pessimistic depending
//! on where it happens to land. Reports per-zone MiB/s plus the
//! per-chunk min/max within each zone, so a zone whose *average* looks
//! fine but which stalls badly on some chunks (a sign of bad sectors,
//! thermal throttling, or a drive silently retrying) is still visible.
//!
//! # Usage
//! ```text
//! rust-script scripts/windows/measure_raw_throughput.rs <DriveLetter> [zone_mib=512] [chunk_mib=4] [device_path]
//! ```
//! `device_path` optionally overrides `\\.\<DriveLetter>:` -- pass a VSS
//! snapshot device path (e.g. from a `uffs-broker --run` log's
//! `device=\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyNNN` line) to
//! measure the same device `uffs-content` actually reads through,
//! rather than the live volume.

#[cfg(windows)]
mod imp {
    use std::time::Instant;

    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_BEGIN, FILE_FLAG_SEQUENTIAL_SCAN, FILE_GENERIC_READ, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadFile, SetFilePointerEx,
    };
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::System::Ioctl::{FSCTL_GET_NTFS_VOLUME_DATA, NTFS_VOLUME_DATA_BUFFER};
    use windows::core::PCWSTR;

    /// One probe location within the volume.
    struct Zone {
        label: &'static str,
        /// Fraction of the volume's total size to seek to before reading
        /// (clamped so the read never runs off the end).
        fraction: f64,
    }

    const ZONES: [Zone; 3] = [
        Zone {
            label: "outer edge (start of volume)",
            fraction: 0.02,
        },
        Zone {
            label: "middle of volume",
            fraction: 0.50,
        },
        Zone {
            label: "inner edge (near end of volume)",
            fraction: 0.90,
        },
    ];

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        let Some(drive) = args.get(1) else {
            eprintln!(
                "usage: measure_raw_throughput.rs <DriveLetter> [zone_mib=512] [chunk_mib=4] \
                 [device_path]\n\
                 \n\
                 Reads zone_mib of raw sequential data from each of three zones (outer/\n\
                 middle/inner) on DriveLetter (or device_path, if given) and reports \n\
                 MiB/s -- the raw physical floor, independent of uffs-content's own \n\
                 per-file read pipeline."
            );
            std::process::exit(2);
        };
        let zone_mib: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(512);
        let chunk_mib: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(4);
        let device_override = args.get(4).cloned();

        let path = device_override.unwrap_or_else(|| format!("\\\\.\\{drive}:"));
        println!("Opening {path} ...");
        let handle = match open_read_handle(&path) {
            Ok(handle) => handle,
            Err(err) => {
                eprintln!(
                    "failed to open {path}: {err}\n(needs Administrator to open a raw volume \
                     handle)"
                );
                std::process::exit(1);
            }
        };

        let volume_bytes = match query_size(handle) {
            Ok(size) => size,
            Err(err) => {
                eprintln!("failed to query volume size: {err}");
                close(handle);
                std::process::exit(1);
            }
        };
        println!(
            "Volume size: {:.1} GiB",
            volume_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
        );

        let chunk_bytes = chunk_mib * 1024 * 1024;
        let zone_bytes = (zone_mib * 1024 * 1024).min(volume_bytes / 4);
        let mut zone_results = Vec::with_capacity(ZONES.len());

        for zone in &ZONES {
            let max_offset = volume_bytes.saturating_sub(zone_bytes);
            let raw_offset = ((volume_bytes as f64 * zone.fraction) as u64).min(max_offset);
            // Volume-handle I/O requires a sector-aligned offset (fails
            // with ERROR_INVALID_PARAMETER otherwise) even for buffered
            // reads -- unlike a regular file, there's no cache-manager
            // layer translating an arbitrary byte offset for you. A
            // fraction like 0.02 or 0.9 essentially never lands on a
            // sector boundary by chance, so round down to a 1 MiB
            // boundary, comfortably covering every real sector/stripe
            // size in use today.
            let offset = align_down(raw_offset, OFFSET_ALIGNMENT);
            println!();
            println!(
                "=== {} (offset {:.1} GiB, reading {} MiB) ===",
                zone.label,
                offset as f64 / (1024.0 * 1024.0 * 1024.0),
                zone_bytes / (1024 * 1024)
            );
            match read_zone(handle, offset, zone_bytes, chunk_bytes) {
                Ok(result) => {
                    println!(
                        "  {:.1} MiB/s average ({} chunks; fastest chunk {:.1} MiB/s, slowest \
                         chunk {:.1} MiB/s)",
                        result.mib_per_sec,
                        result.chunk_count,
                        result.fastest_chunk_mib_per_sec,
                        result.slowest_chunk_mib_per_sec
                    );
                    zone_results.push((zone.label, result.mib_per_sec));
                }
                Err(err) => eprintln!("  read failed: {err}"),
            }
        }

        close(handle);

        if zone_results.is_empty() {
            eprintln!("No zone read succeeded -- can't report a floor.");
            std::process::exit(1);
        }

        println!();
        println!("=== Summary ===");
        let slowest = zone_results
            .iter()
            .copied()
            .fold(f64::INFINITY, |acc, (_, mib)| acc.min(mib));
        let fastest = zone_results
            .iter()
            .copied()
            .fold(0.0_f64, |acc, (_, mib)| acc.max(mib));
        for (label, mib) in &zone_results {
            println!("  {label}: {mib:.1} MiB/s");
        }
        println!();
        println!(
            "Raw sequential floor for this device: ~{slowest:.1} MiB/s (slowest zone) to \
             ~{fastest:.1} MiB/s (fastest zone)."
        );
        println!(
            "Compare against uffs-content's own \"mib_per_sec_since_job_start\" progress lines \
             for the same drive: if the pipeline number is close to this floor, the drive itself \
             is the bottleneck (ordering/concurrency can't help further); if the pipeline number \
             is far below even the slowest zone here, something in the read pattern (seeking, \
             per-file open/close overhead, fragmentation -- see check_frs_vs_lcn.rs) is still \
             costing real throughput."
        );
    }

    /// One zone's read result.
    struct ZoneResult {
        mib_per_sec: f64,
        chunk_count: usize,
        fastest_chunk_mib_per_sec: f64,
        slowest_chunk_mib_per_sec: f64,
    }

    /// Byte offsets and read lengths against a raw volume handle must be
    /// sector-aligned (Windows rejects anything else with
    /// `ERROR_INVALID_PARAMETER`, even for buffered/cached access) --
    /// 1 MiB comfortably covers every real physical/logical sector or
    /// stripe size in use today.
    const OFFSET_ALIGNMENT: u64 = 1024 * 1024;

    /// Rounds `value` down to the nearest multiple of `alignment`.
    const fn align_down(value: u64, alignment: u64) -> u64 {
        value - (value % alignment)
    }

    /// Seeks to `offset` and reads `total_bytes` sequentially in
    /// `chunk_bytes`-sized calls, timing the whole zone and each
    /// individual chunk. Only ever issues full `chunk_bytes`-sized reads
    /// -- a short final read would need its own (smaller) alignment
    /// reasoning, so any less-than-a-full-chunk remainder is simply left
    /// unread rather than risking a second alignment failure mode.
    fn read_zone(
        handle: HANDLE,
        offset: u64,
        total_bytes: u64,
        chunk_bytes: u64,
    ) -> Result<ZoneResult, String> {
        seek(handle, offset)?;

        let mut buf = vec![0_u8; usize::try_from(chunk_bytes).unwrap_or(4 * 1024 * 1024)];
        let mut remaining = total_bytes;
        let mut chunk_count = 0_usize;
        let mut fastest_mib_per_sec = 0.0_f64;
        let mut slowest_mib_per_sec = f64::INFINITY;
        let zone_started_at = Instant::now();

        while remaining >= chunk_bytes {
            let dest = &mut buf[..];
            let chunk_started_at = Instant::now();
            let mut bytes_read = 0_u32;
            // SAFETY: `handle` is a valid, open, synchronous file handle
            // for the duration of this call; `dest` is a valid, writable
            // buffer sized to the requested read length.
            let result =
                unsafe { ReadFile(handle, Some(dest), Some(&raw mut bytes_read), None) };
            result.map_err(|err| format!("ReadFile failed: {err}"))?;
            if bytes_read == 0 {
                break; // hit end of volume before filling this zone
            }
            let chunk_secs = chunk_started_at.elapsed().as_secs_f64();
            if chunk_secs > 0.0 {
                let chunk_mib_per_sec = (f64::from(bytes_read) / (1024.0 * 1024.0)) / chunk_secs;
                fastest_mib_per_sec = fastest_mib_per_sec.max(chunk_mib_per_sec);
                slowest_mib_per_sec = slowest_mib_per_sec.min(chunk_mib_per_sec);
            }
            chunk_count += 1;
            remaining = remaining.saturating_sub(u64::from(bytes_read));
        }

        let zone_secs = zone_started_at.elapsed().as_secs_f64();
        let bytes_actually_read = total_bytes.saturating_sub(remaining);
        let mib_per_sec = if zone_secs > 0.0 {
            (bytes_actually_read as f64 / (1024.0 * 1024.0)) / zone_secs
        } else {
            0.0
        };

        Ok(ZoneResult {
            mib_per_sec,
            chunk_count,
            fastest_chunk_mib_per_sec: fastest_mib_per_sec,
            slowest_chunk_mib_per_sec: if slowest_mib_per_sec.is_finite() {
                slowest_mib_per_sec
            } else {
                0.0
            },
        })
    }

    /// Opens `path` (a `\\.\<Drive>:` volume path or a VSS device path)
    /// for sequential read access.
    fn open_read_handle(path: &str) -> Result<HANDLE, String> {
        let wide: Vec<u16> = path
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();
        // SAFETY: `wide` is UTF-16 and NUL-terminated for the duration of
        // this call; no other pointers are passed.
        let handle = unsafe {
            CreateFileW(
                PCWSTR::from_raw(wide.as_ptr()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_SEQUENTIAL_SCAN,
                None,
            )
        };
        handle.map_err(|err| err.to_string())
    }

    /// Total size in bytes of the volume/device behind `handle`.
    ///
    /// `GetFileSizeEx` does not work on raw volume/device handles (it
    /// fails with `ERROR_INVALID_PARAMETER`) -- volume size instead
    /// comes from `FSCTL_GET_NTFS_VOLUME_DATA`'s `TotalClusters *
    /// BytesPerCluster`, the same ioctl `uffs-mft`'s own
    /// `VolumeHandle::get_ntfs_volume_data` uses for the same reason.
    fn query_size(handle: HANDLE) -> Result<u64, String> {
        let mut volume_data = NTFS_VOLUME_DATA_BUFFER::default();
        let mut bytes_returned: u32 = 0;
        let buffer_size =
            u32::try_from(size_of::<NTFS_VOLUME_DATA_BUFFER>()).unwrap_or(u32::MAX);

        // SAFETY: `handle` is a valid, open volume handle; `volume_data`
        // points to valid writable storage of `buffer_size` bytes; and
        // `bytes_returned` is a valid out-pointer for the duration of
        // this call.
        unsafe {
            DeviceIoControl(
                handle,
                FSCTL_GET_NTFS_VOLUME_DATA,
                None,
                0,
                Some(core::ptr::from_mut(&mut volume_data).cast()),
                buffer_size,
                Some(&raw mut bytes_returned),
                None,
            )
        }
        .map_err(|err| format!("FSCTL_GET_NTFS_VOLUME_DATA failed: {err}"))?;

        let total_clusters = volume_data.TotalClusters.cast_unsigned();
        let bytes_per_cluster = u64::from(volume_data.BytesPerCluster);
        total_clusters
            .checked_mul(bytes_per_cluster)
            .ok_or_else(|| "volume size overflowed u64".to_owned())
    }

    /// Moves `handle`'s file pointer to `offset` bytes from the start.
    fn seek(handle: HANDLE, offset: u64) -> Result<(), String> {
        let distance = i64::try_from(offset).map_err(|err| err.to_string())?;
        // SAFETY: `handle` is a valid, open handle; no output pointer is
        // requested.
        unsafe { SetFilePointerEx(handle, distance, None, FILE_BEGIN) }
            .map_err(|err| err.to_string())
    }

    /// Closes `handle`, ignoring the (practically infallible) result.
    fn close(handle: HANDLE) {
        // SAFETY: `handle` was returned by a successful `CreateFileW`
        // call above and is closed exactly once, here.
        let _ = unsafe { CloseHandle(handle) };
    }
}

#[cfg(windows)]
fn main() {
    imp::main();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("measure_raw_throughput.rs opens raw Windows volume handles -- Windows only.");
    std::process::exit(1);
}
