// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Windows-specific USN journal helpers backed by `FSCTL_QUERY_USN_JOURNAL`,
//! `FSCTL_READ_USN_JOURNAL`, and targeted FRS reads via `CreateFileW` /
//! `DeviceIoControl`.
//!
//! All public entries here are re-exported by the parent [`crate::usn`]
//! module under platform gating; non-Windows targets see the no-op
//! fallbacks in `usn::*` instead.
//!
//! ## Why this is its own file
//!
//! Split out of the parent `usn.rs` so the DTO-side surface (the
//! [`Usn`](super::Usn) newtype + [`UsnJournalInfo`](super::UsnJournalInfo) /
//! [`UsnRecord`](super::UsnRecord) / aggregation helpers / non-Windows stubs /
//! tests) stays under the workspace file-size policy without needing an
//! exception entry.  The Win32 FFI surface — `#[repr(C)]` mirror structs,
//! `CreateFileW` / `DeviceIoControl` calls, fixed-size record-decode loop — is
//! a single cohesive unit that benefits from living together.

#![expect(
    unsafe_code,
    reason = "FFI: Windows API calls (CreateFileW, DeviceIoControl, CloseHandle)"
)]

use core::ptr;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt as _;

use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL};
use windows::core::PCWSTR;
use zerocopy::{FromBytes, Immutable, KnownLayout};

use super::{UsnJournalInfo, UsnRecord};
use crate::platform::u32_size_of;

/// Mirror of the Win32 `USN_JOURNAL_DATA_V0` struct populated by
/// `FSCTL_QUERY_USN_JOURNAL`.  Field order and layout match the
/// `winioctl.h` definition.
#[repr(C)]
#[derive(Default)]
struct UsnJournalDataV0 {
    /// Unique journal-instance identifier.
    usn_journal_id: u64,
    /// First valid USN in the journal.
    first_usn: i64,
    /// Next USN that will be assigned to a new record.
    next_usn: i64,
    /// Lowest USN still readable from the journal.
    lowest_valid_usn: i64,
    /// Largest USN the journal will accept before wrapping.
    max_usn: i64,
    /// Configured maximum journal size in bytes.
    maximum_size: u64,
    /// Allocation-growth quantum for the journal.
    allocation_delta: u64,
}

/// Mirror of the Win32 `READ_USN_JOURNAL_DATA_V0` input struct for
/// `FSCTL_READ_USN_JOURNAL`.
#[repr(C)]
struct ReadUsnJournalDataV0 {
    /// USN to start reading from.
    start_usn: i64,
    /// Bitmask of `USN_REASON_*` flags to filter on.
    reason_mask: u32,
    /// Non-zero: return records only once their file is closed.
    return_only_on_close: u32,
    /// Wait timeout in 100ns units (0 = don't block).
    timeout: u64,
    /// Minimum bytes to wait for before returning (0 = return any).
    bytes_to_wait_for: u64,
    /// Journal identifier (must match `usn_journal_id` from query).
    usn_journal_id: u64,
}

/// Mirror of the Win32 `USN_RECORD_V2` fixed-size header.  The filename
/// follows the header starting at `file_name_offset`.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout)]
struct UsnRecordV2Header {
    /// Total record length including trailing filename (bytes).
    record_length: u32,
    /// Major version of this record format.
    major_version: u16,
    /// Minor version of this record format.
    minor_version: u16,
    /// MFT file reference number (FRN) of the target file.
    file_reference_number: u64,
    /// FRN of the parent directory.
    parent_file_reference_number: u64,
    /// USN of this record.
    usn: i64,
    /// FILETIME of the change (100ns ticks since 1601-01-01 UTC).
    time_stamp: i64,
    /// Bitmask of `USN_REASON_*` flags describing the change.
    reason: u32,
    /// Bitmask of `USN_SOURCE_*` flags (e.g. replication-driven edits).
    source_info: u32,
    /// Security-descriptor id (unused on most filesystems).
    security_id: u32,
    /// Windows file attributes (`FILE_ATTRIBUTE_*`).
    file_attributes: u32,
    /// Length of the trailing filename in bytes (UTF-16 LE).
    file_name_length: u16,
    /// Offset from the start of this record to the trailing filename.
    file_name_offset: u16,
}

/// Size of a `UsnJournalDataV0` in bytes — always fits in `u32`.
///
/// Routes the `usize -> u32` narrowing through the centralized
/// `u32_size_of` helper so the `cast_possible_truncation` expect
/// lives at one site (next to the Win32 FFI-sizing comment) rather
/// than at every Win32 ioctl const that needs the same bound.
const USN_JOURNAL_DATA_V0_SIZE: u32 = u32_size_of::<UsnJournalDataV0>();
/// Size of a `ReadUsnJournalDataV0` in bytes — always fits in `u32`.
const READ_USN_JOURNAL_DATA_V0_SIZE: u32 = u32_size_of::<ReadUsnJournalDataV0>();

/// Open a `\\.\X:` volume handle with read access for USN-journal ioctls.
///
/// Adopts a broker-supplied volume handle when one is registered for `volume`
/// (the non-elevated daemon path): `FSCTL_QUERY_USN_JOURNAL` /
/// `FSCTL_READ_USN_JOURNAL` operate on a **volume** handle, which the Access
/// Broker already vends, so a non-elevated daemon that can't `CreateFileW` the
/// raw volume can still poll the journal through a duplicate of the broker
/// handle.  Falls back to a direct `CreateFileW` when no broker handle is
/// registered (the elevated path).
///
/// The returned handle is owned by the caller and closed via
/// [`close_volume_handle`] after the ioctl — for a broker-backed handle that
/// closes only the duplicate, leaving the registry entry intact for the next
/// poll (mirrors the MFT read's per-open duplicate).
fn open_volume_handle(volume: crate::platform::DriveLetter) -> Result<HANDLE, std::io::Error> {
    // Broker fast-path: adopt a duplicate of the registered broker handle if
    // present; otherwise open the volume directly below.
    if let Some(handle) = crate::platform::try_adopt_broker_handle(volume)
        .map_err(|err| std::io::Error::other(err.to_string()))?
    {
        return Ok(handle);
    }

    let path = format!("\\\\.\\{volume}:");
    let wide: Vec<u16> = OsStr::new(&path)
        .encode_wide()
        .chain(core::iter::once(0))
        .collect();
    // USN Journal operations require GENERIC_READ access
    // SAFETY: `wide` is a NUL-terminated UTF-16 path buffer that lives for the
    // duration of the call, optional parameters are `None`, and ownership of any
    // returned handle is transferred to the caller.
    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(wide.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    };
    match handle {
        Ok(raw) if raw != INVALID_HANDLE_VALUE => Ok(raw),
        Ok(_) => Err(std::io::Error::last_os_error()),
        Err(err) => Err(std::io::Error::from_raw_os_error(err.code().0)),
    }
}

/// Close a USN-journal volume handle, logging (but not propagating) any
/// failure from the Win32 `CloseHandle` call.  The handle is treated as
/// consumed on return regardless of outcome.
#[expect(
    unsafe_code,
    reason = "CloseHandle is an FFI call; caller guarantees handle validity"
)]
fn close_volume_handle(handle: HANDLE) {
    // SAFETY: caller passed a HANDLE returned from `open_volume_handle`
    // which has not yet been closed.
    if let Err(err) = unsafe { CloseHandle(handle) } {
        tracing::debug!(err = ?err, "CloseHandle failed in USN journal path");
    }
}

/// Queries the USN Journal for a volume.
///
/// # Errors
///
/// Returns [`std::io::Error`] if opening the volume handle or issuing
/// `FSCTL_QUERY_USN_JOURNAL` fails — typically `ERROR_JOURNAL_NOT_ACTIVE`
/// when the NTFS USN journal has not been enabled for the volume, or
/// `ERROR_ACCESS_DENIED` when the caller is not elevated.
pub fn query_usn_journal(
    volume: crate::platform::DriveLetter,
) -> Result<UsnJournalInfo, std::io::Error> {
    let handle = open_volume_handle(volume)?;
    let mut journal_data = UsnJournalDataV0::default();
    let mut bytes_returned: u32 = 0;
    // SAFETY: `handle` is a live volume handle, the output buffer points to
    // writable `UsnJournalDataV0` storage, and `bytes_returned` is a valid
    // out-parameter for the duration of the call.
    let result = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            None,                                          // Input buffer
            0,                                             // Input buffer size
            Some(ptr::from_mut(&mut journal_data).cast()), // Output buffer
            USN_JOURNAL_DATA_V0_SIZE,                      // Output buffer size
            Some(&raw mut bytes_returned),                 // Bytes returned
            None,                                          // Overlapped
        )
    };
    close_volume_handle(handle);
    if result.is_err() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(UsnJournalInfo {
        journal_id: journal_data.usn_journal_id,
        first_usn: super::Usn::new(journal_data.first_usn),
        next_usn: super::Usn::new(journal_data.next_usn),
        lowest_valid_usn: super::Usn::new(journal_data.lowest_valid_usn),
        max_usn: super::Usn::new(journal_data.max_usn),
        max_size: journal_data.maximum_size,
        allocation_delta: journal_data.allocation_delta,
    })
}

/// Reads all USN Journal records starting from a given USN.
///
/// Loops the `FSCTL_READ_USN_JOURNAL` ioctl until all changes are consumed,
/// preventing data loss on busy volumes where a single 64KB buffer would
/// only return a subset of changes.
///
/// # Errors
///
/// Returns [`std::io::Error`] if the volume handle cannot be opened or
/// `FSCTL_READ_USN_JOURNAL` fails for any iteration of the
/// read-loop. `ERROR_JOURNAL_ENTRY_DELETED` is surfaced unchanged so
/// callers can decide whether to rebuild their checkpoint.
pub fn read_usn_journal(
    volume: crate::platform::DriveLetter,
    journal_id: u64,
    start_usn: super::Usn,
) -> Result<(Vec<UsnRecord>, super::Usn), std::io::Error> {
    let handle = open_volume_handle(volume)?;
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut all_records = Vec::new();
    let mut current_usn = start_usn.raw();

    loop {
        let read_data = ReadUsnJournalDataV0 {
            start_usn: current_usn,
            reason_mask: 0xFFFF_FFFF,
            return_only_on_close: 0,
            timeout: 0,
            bytes_to_wait_for: 0,
            usn_journal_id: journal_id,
        };
        let mut bytes_returned: u32 = 0;
        // u32 truncation is safe: buffer is a fixed 64 KiB allocation
        // (`6_4 * 1024`), well under u32::MAX.
        let buffer_size = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: `handle` is a live volume handle, `read_data` and `buffer`
        // provide valid input/output storage for the advertised byte counts,
        // and `bytes_returned` is a valid out-parameter for the call.
        let result = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_READ_USN_JOURNAL,
                Some(ptr::from_ref(&read_data).cast()),
                READ_USN_JOURNAL_DATA_V0_SIZE,
                Some(buffer.as_mut_ptr().cast()),
                buffer_size,
                Some(&raw mut bytes_returned),
                None,
            )
        };
        if result.is_err() {
            close_volume_handle(handle);
            return Err(std::io::Error::last_os_error());
        }
        // `size_of::<i64>()` is 8, hard-coded as a `u32` literal here.
        if bytes_returned < 8_u32 {
            close_volume_handle(handle);
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "FSCTL_READ_USN_JOURNAL returned fewer than 8 bytes",
            ));
        }

        // First 8 bytes of output = next USN to continue from
        let bytes_returned_usize = bytes_returned as usize; // u32→usize is lossless
        let next_usn_slice = buffer.get(..8).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "USN journal buffer shorter than 8 bytes",
            )
        })?;
        let mut next_usn_bytes = [0_u8; 8];
        next_usn_bytes.copy_from_slice(next_usn_slice);
        let next_usn = i64::from_le_bytes(next_usn_bytes);

        // Parse records from this batch
        let mut offset = 8_usize;
        let mut batch_count = 0_usize;
        while offset + size_of::<UsnRecordV2Header>() <= bytes_returned_usize {
            let Some(record_slice) = buffer.get(offset..bytes_returned_usize) else {
                break;
            };
            let Ok((header, _)) = UsnRecordV2Header::read_from_prefix(record_slice) else {
                break;
            };
            if header.record_length == 0 {
                break;
            }
            let name_start = offset + header.file_name_offset as usize;
            let name_end = name_start + header.file_name_length as usize;
            let filename = buffer
                .get(name_start..name_end)
                .filter(|_| name_end <= bytes_returned_usize)
                .map_or_else(String::new, |name_bytes| {
                    let name_u16: Vec<u16> = name_bytes
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| u16::from_le_bytes(*pair))
                        .collect();
                    crate::io::parser::unified::decode_name_u16(&name_u16).0
                });
            // On-disk → typed boundary.  NTFS file references are 64-bit
            // values whose low 48 bits encode the FRS; the high 16 bits
            // are the sequence number, which downstream consumers don't
            // need.  Mask, then lift into the typed `Frs` / `ParentFrs`
            // domain at this single parser-boundary site.
            let frs_raw = header.file_reference_number & 0x0000_FFFF_FFFF_FFFF;
            let parent_frs_raw = header.parent_file_reference_number & 0x0000_FFFF_FFFF_FFFF;
            all_records.push(UsnRecord {
                frs: crate::frs::Frs::new(frs_raw),
                parent_frs: crate::frs::ParentFrs::new(parent_frs_raw),
                usn: super::Usn::new(header.usn),
                reason: header.reason,
                file_attributes: header.file_attributes,
                filename,
            });
            offset += header.record_length as usize;
            batch_count += 1;
        }

        // If no records were returned in this batch, we've consumed
        // everything — stop looping.
        if batch_count == 0 || next_usn == current_usn {
            current_usn = next_usn;
            break;
        }
        current_usn = next_usn;
    }

    close_volume_handle(handle);
    Ok((all_records, super::Usn::new(current_usn)))
}

/// Reads specific MFT records by FRS and re-parses them into the index.
///
/// This performs **targeted reads** for individual FRS values identified by
/// the USN journal, giving each record full data (size, timestamps, flags,
/// attributes, streams) instead of the incomplete placeholder data that USN
/// alone provides.
///
/// # Performance
///
/// Each read is a single seek + 1-4KB read. For 1000 records on SSD this
/// takes ~2ms total. The cost is dominated by I/O latency on HDD (~5ms per
/// seek).
///
/// # Errors
///
/// Returns an error if the volume cannot be opened or extents cannot be
/// retrieved. Individual record read failures are logged and skipped.
pub fn read_targeted_frs_records(
    volume: &crate::platform::VolumeHandle,
    index: &mut crate::index::MftIndex,
    frs_list: &[u64],
) -> Result<usize, crate::MftError> {
    use crate::io::MftRecordReader;

    if frs_list.is_empty() {
        return Ok(0);
    }

    // Build extent map for the MFT so we can seek to specific records
    let extents = volume.get_mft_extents()?;
    let extent_map = crate::io::MftExtentMap::new(
        extents,
        volume.volume_data().bytes_per_cluster,
        volume.volume_data().bytes_per_file_record_segment,
    );

    let mut reader = MftRecordReader::new_with_extents(extent_map);
    let handle = volume.raw_handle();
    let mut success_count = 0_usize;

    // Collect extension FRS numbers discovered from $ATTRIBUTE_LIST
    // attributes. Processed in a second pass after all base records.
    let mut extension_frs: Vec<u64> = Vec::new();

    for &frs in frs_list {
        success_count +=
            read_one_targeted_record(&mut reader, handle, index, frs, Some(&mut extension_frs));
    }

    // Second pass: read extension records discovered from $ATTRIBUTE_LIST.
    // `parse_record_to_index` detects extension records (base_frs != 0)
    // and dispatches them to `parse_extension_to_index` automatically.
    extension_frs.sort_unstable();
    extension_frs.dedup();
    if !extension_frs.is_empty() {
        tracing::debug!(
            count = extension_frs.len(),
            "📎 Reading extension MFT records"
        );
    }
    for ext_frs in &extension_frs {
        success_count += read_one_targeted_record(&mut reader, handle, index, *ext_frs, None);
    }

    Ok(success_count)
}

/// Read one MFT record by FRS, apply fixup, optionally scan
/// `$ATTRIBUTE_LIST` for extension FRSes, and parse the result into
/// `index`.
///
/// `extension_frs_out` is `Some(_)` for the base-record pass (so
/// extensions are discovered) and `None` for the extension-record pass
/// (where extension scanning is unnecessary).
///
/// Returns `1` on a successful parse, `0` on any read / fixup / parse
/// failure (failures are logged at trace level and skipped to keep the
/// caller's loop simple).
fn read_one_targeted_record(
    reader: &mut crate::io::MftRecordReader,
    handle: HANDLE,
    index: &mut crate::index::MftIndex,
    frs: u64,
    extension_frs_out: Option<&mut Vec<u64>>,
) -> usize {
    use crate::parse::{apply_fixup, parse_record_to_index};

    match reader.read_record(handle, frs) {
        Ok(raw_data) => {
            let mut buf = raw_data.to_vec();
            if !apply_fixup(&mut buf) {
                return 0;
            }
            if let Some(out) = extension_frs_out {
                scan_attribute_list_extensions(&buf, frs, out);
            }
            usize::from(parse_record_to_index(&buf, frs, index))
        }
        Err(err) => {
            tracing::trace!(
                frs,
                error = %err,
                "⚠️ Targeted MFT read failed for FRS (skipping)"
            );
            0
        }
    }
}

/// Scans a base MFT record's attributes for `$ATTRIBUTE_LIST` (type 0x20)
/// and extracts the FRS numbers of any extension records it references.
///
/// Hoisted to module scope (instead of being nested inside
/// [`read_targeted_frs_records`]) so the function item is not declared
/// after statements in the caller — required by
/// `clippy::items_after_statements`.
fn scan_attribute_list_extensions(data: &[u8], base_frs: u64, out: &mut Vec<u64>) {
    use zerocopy::FromBytes as _;

    use crate::ntfs::{
        AttributeListEntry, AttributeRecordHeader, AttributeType, FileRecordSegmentHeader,
    };

    if data.len() < size_of::<FileRecordSegmentHeader>() {
        return;
    }
    let Ok((header, _)) = FileRecordSegmentHeader::read_from_prefix(data) else {
        return;
    };

    let mut offset = header.first_attribute_offset as usize;
    let max_offset = core::cmp::min(header.bytes_in_use as usize, data.len());

    while offset + size_of::<AttributeRecordHeader>() <= max_offset {
        let Some(attr_bytes) = data.get(offset..) else {
            break;
        };
        let Ok((attr, _)) = AttributeRecordHeader::read_from_prefix(attr_bytes) else {
            break;
        };
        if attr.type_code == AttributeType::End as u32 {
            break;
        }
        if attr.length == 0 || offset + attr.length as usize > max_offset {
            break;
        }

        if attr.type_code == AttributeType::AttributeList as u32 && attr.is_non_resident == 0 {
            // Resident $ATTRIBUTE_LIST — parse entries
            let val_offset_raw = data
                .get(offset + 20..offset + 22)
                .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                .map_or(0, u16::from_le_bytes) as usize;
            let val_length = data
                .get(offset + 16..offset + 20)
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                .map_or(0, u32::from_le_bytes) as usize;

            let list_start = offset + val_offset_raw;
            let list_end = core::cmp::min(list_start.saturating_add(val_length), data.len());

            let mut pos = list_start;
            while pos + size_of::<AttributeListEntry>() <= list_end {
                let Some(entry_bytes) = data.get(pos..list_end) else {
                    break;
                };
                let Ok((entry, _)) = AttributeListEntry::read_from_prefix(entry_bytes) else {
                    break;
                };
                if usize::from(entry.length) < size_of::<AttributeListEntry>() {
                    break;
                }
                let target = entry.target_frs();
                if target != base_frs && target != 0 {
                    out.push(target);
                }
                pos += entry.length as usize;
            }
        }

        offset += attr.length as usize;
    }
}
