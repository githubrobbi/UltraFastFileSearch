// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Single-pass direct-to-index parser.
//!
//! This module implements the high-performance single-pass parser that builds
//! an `MftIndex` directly from raw MFT records without creating intermediate
//! `ParsedRecord` allocations.
//!
//! This is a cross-platform parser used for both Windows IOCP and file-based
//! loading.

// Performance-critical hot-path parser — lint suppressions match the style of
// other NTFS parser modules in this crate.
#![expect(
    clippy::doc_markdown,
    reason = "NTFS terminology like MftIndex does not need backticks in internal docs"
)]
#![expect(
    clippy::manual_let_else,
    reason = "explicit match is clearer in NTFS attribute dispatch"
)]
#![expect(
    clippy::single_match_else,
    reason = "explicit match arms are clearer for attribute type dispatch"
)]
#![expect(
    clippy::shadow_unrelated,
    reason = "reusing common names like 'record' in nested scopes is idiomatic here"
)]
#![expect(
    clippy::let_underscore_untyped,
    reason = "let _ = expr is used for intentionally ignoring results"
)]

use core::mem::size_of;

use smallvec::SmallVec;
use zerocopy::FromBytes as _;

use super::direct_index_extension::parse_extension_to_index;
use super::index_helpers::{
    StreamEntry, add_child_entry, add_link_to_index, add_stream_to_index, chain_links,
    chain_streams,
};
use crate::index::{nonneg_to_u64, u32_as_usize};

/// Read a little-endian u16 from the given offset, returning 0 if out of
/// bounds. WI-5.2: this file's attribute-length gate (`offset + attr_header.
/// length <= max_offset`) does not by itself guarantee any *specific* fixed
/// field inside the attribute is in bounds — a short declared `length` can
/// pass that gate while still being too small to cover `value_length`/
/// `value_offset`. Reads of those fields go through this helper instead of
/// raw slicing so a malformed/truncated record degrades gracefully instead
/// of panicking (the daemon builds with `panic = "abort"`).
#[inline]
fn rd_u16(buf: &[u8], off: usize) -> u16 {
    off.checked_add(2)
        .and_then(|end| buf.get(off..end))
        .and_then(|sl| <[u8; 2]>::try_from(sl).ok())
        .map_or(0, u16::from_le_bytes)
}

/// Read a little-endian u32 from the given offset, returning 0 if out of
/// bounds. See [`rd_u16`] for the rationale.
#[inline]
fn rd_u32(buf: &[u8], off: usize) -> u32 {
    off.checked_add(4)
        .and_then(|end| buf.get(off..end))
        .and_then(|sl| <[u8; 4]>::try_from(sl).ok())
        .map_or(0, u32::from_le_bytes)
}

/// Whether an attribute is the "primary" copy for stream-counting purposes.
/// Resident attributes are always primary; a non-resident attribute is
/// primary only when its LowestVCN is 0 — continuation extents of a larger
/// non-resident attribute must not be double-counted as new streams.
#[inline]
fn is_primary_attribute(
    data: &[u8],
    offset: usize,
    attr_header: &crate::ntfs::AttributeRecordHeader,
) -> bool {
    if attr_header.is_non_resident == 0 {
        return true;
    }
    let nr_offset = offset + 16;
    data.get(nr_offset..nr_offset + 8)
        .and_then(|sl| <[u8; 8]>::try_from(sl).ok())
        .is_some_and(|bytes| i64::from_le_bytes(bytes) == 0)
}

/// Extracts an attribute's own name (the NTFS "attribute name", e.g. `$I30`
/// on `$INDEX_ROOT` or an ADS name on `$DATA` — not a `$FILE_NAME`). Empty
/// string if unnamed or the declared length overruns the record.
#[inline]
fn extract_attr_name(
    data: &[u8],
    offset: usize,
    attr_header: &crate::ntfs::AttributeRecordHeader,
) -> String {
    if attr_header.name_length == 0 {
        return String::new();
    }
    let name_offset = offset + usize::from(attr_header.name_offset);
    let name_len = usize::from(attr_header.name_length);
    if name_offset + name_len * 2 > data.len() {
        return String::new();
    }
    let name_bytes = &data[name_offset..name_offset + name_len * 2];
    let name_u16: SmallVec<[u16; 64]> = name_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    crate::io::parser::unified::decode_name_u16(&name_u16).0
}

/// Resident/non-resident `(size, allocated)` for the generic "count as a
/// stream" attribute types (`$OBJECT_ID`, `$EA`, non-`$I30` index
/// attributes, the unknown-type catch-all): resident → `(value_length, 0)`;
/// non-resident → `(DataSize, AllocatedSize)` from the
/// `NonResidentAttributeData` block at `offset + 16`.
#[inline]
fn read_size_allocated(
    data: &[u8],
    offset: usize,
    attr_header: &crate::ntfs::AttributeRecordHeader,
) -> (u64, u64) {
    if attr_header.is_non_resident == 0 {
        return (u64::from(rd_u32(data, offset + 16)), 0_u64);
    }
    let nr_offset = offset + 16;
    if nr_offset + 48 > data.len() {
        return (0_u64, 0_u64);
    }
    let alloc_bytes = &data[nr_offset + 24..nr_offset + 32];
    let allocated = i64::from_le_bytes(alloc_bytes.try_into().unwrap_or([0; 8]));
    let size_bytes = &data[nr_offset + 32..nr_offset + 40];
    let data_size = i64::from_le_bytes(size_bytes.try_into().unwrap_or([0; 8]));
    (nonneg_to_u64(data_size), nonneg_to_u64(allocated))
}

/// `(is_resident, is_sparse)` for an attribute, from already-parsed header
/// fields: `is_resident` from `is_non_resident`, `is_sparse` from the
/// `ATTRIBUTE_FLAG_SPARSE` (`0x8000`) header flag bit — free, no new I/O.
#[inline]
const fn resident_and_sparse(attr_header: &crate::ntfs::AttributeRecordHeader) -> (bool, bool) {
    let is_resident = attr_header.is_non_resident == 0;
    let is_sparse = !is_resident && (attr_header.flags & 0x8000) != 0;
    (is_resident, is_sparse)
}

/// Parses a record directly into `MftIndex` (single-pass inline parsing).
///
/// This function parses the record and adds it directly to the index,
/// creating parent placeholders on-demand. This single-pass approach
/// eliminates the intermediate `ParsedRecord` allocation.
///
/// Handles ALL attribute types that `parse_record_full()` handles, including:
/// - `$STANDARD_INFORMATION`, `$FILE_NAME`, `$DATA` (default + ADS)
/// - `$REPARSE_POINT` (for WoF detection and junctions/symlinks)
/// - `$INDEX_ROOT`, `$INDEX_ALLOCATION`, `$BITMAP` (directory indexes)
/// - `$OBJECT_ID`, `$VOLUME_NAME`, `$VOLUME_INFORMATION`, `$PROPERTY_SET`
/// - `$EA`, `$EA_INFORMATION`, `$LOGGED_UTILITY_STREAM`
/// - `$SECURITY_DESCRIPTOR`, `$ATTRIBUTE_LIST`
/// - Unknown attribute types (counted as streams per NTFS convention)
///
/// # Returns
///
/// `true` if a record was added to the index, `false` if skipped.
#[expect(
    clippy::too_many_lines,
    reason = "monolithic parser kept for performance-critical hot path"
)]
#[expect(
    clippy::cognitive_complexity,
    reason = "NTFS attribute dispatch is inherently complex"
)]
pub fn parse_record_to_index(data: &[u8], frs: u64, index: &mut crate::index::MftIndex) -> bool {
    use crate::index::{IndexNameRef, LinkInfo, NO_ENTRY, SizeInfo, StandardInfo, len_to_u16};
    use crate::ntfs::{
        AttributeRecordHeader, AttributeType, FileNameAttribute, FileRecordSegmentHeader,
        file_reference_to_frs,
    };

    if data.len() < size_of::<FileRecordSegmentHeader>() {
        return false;
    }

    let header = match FileRecordSegmentHeader::read_from_prefix(data) {
        Ok((header, _)) => header,
        Err(_) => return false,
    };

    // Check if record is in use
    if !header.is_in_use() {
        return false;
    }

    // Check magic
    let multi_sector_header = header.multi_sector_header;
    if !multi_sector_header.is_file_record() {
        return false;
    }

    // Handle extension records: add their names/streams to the base record.
    // Extension records reference a base FRS; their attributes are merged inline.
    if !header.is_base_record() {
        let base_frs = file_reference_to_frs(header.base_file_record_segment);
        return parse_extension_to_index(data, base_frs, index);
    }

    let is_directory = header.is_directory();

    // Parse attributes
    let mut offset = usize::from(header.first_attribute_offset);
    let max_offset = core::cmp::min(u32_as_usize(header.bytes_in_use), data.len());

    // Temporary storage for parsed data
    let mut std_info = StandardInfo::default();
    let mut primary_name: Option<(String, u64, u8, u16)> = None; // (name, parent_frs, namespace, parse_index)
    let mut additional_names: SmallVec<[(String, u64, u16); 4]> = SmallVec::new();
    let mut name_parse_counter: u16 = 0;
    // $FILE_NAME's own timestamps for whichever name is currently primary
    // (often differ from $STANDARD_INFORMATION). Only the primary name's
    // values are stored here since FileRecord carries just one set — see
    // `FileRecord::fn_created`'s doc.
    let mut primary_fn_created = 0_i64;
    let mut primary_fn_modified = 0_i64;
    let mut primary_fn_accessed = 0_i64;
    let mut primary_fn_mft_changed = 0_i64;
    let mut default_size = 0_u64;
    let mut default_allocated = 0_u64;
    let mut default_is_sparse = false;
    let mut default_is_resident = false;
    let mut additional_streams: SmallVec<[StreamEntry; 4]> = SmallVec::new();
    // Internal streams for tree-metrics (size, allocated)
    let internal_streams: SmallVec<[(u64, u64); 4]> = SmallVec::new();
    let mut reparse_tag: u32 = 0;
    let mut dir_index_size: u64 = 0;
    let mut dir_index_allocated: u64 = 0;

    while offset + size_of::<AttributeRecordHeader>() <= max_offset {
        let attr_header = match AttributeRecordHeader::read_from_prefix(&data[offset..]) {
            Ok((attr_header, _)) => attr_header,
            Err(_) => break,
        };

        if attr_header.type_code == AttributeType::END_MARKER {
            break;
        }

        if attr_header.length == 0 || offset + u32_as_usize(attr_header.length) > max_offset {
            break;
        }

        let attr_type = AttributeType::from_u32(attr_header.type_code);
        match attr_type {
            Some(AttributeType::StandardInformation) => {
                if attr_header.is_non_resident == 0 {
                    // Shared with the legacy and unified pipelines: reads the
                    // 72-byte NTFS 3.0+ `StandardInformationExtended` form
                    // (usn/security_id/owner_id) when `value_length` says it's
                    // present, falling back to the 36-byte NTFS 1.2 form
                    // otherwise — see `attribute_helpers::parse_standard_info_full`
                    // for the single-source-of-truth rationale.
                    let mut ext = crate::ntfs::ExtendedStandardInfo::default();
                    super::parse_standard_info_full(data, offset, &mut ext);
                    std_info = StandardInfo::from_extended(&ext);
                }
            }
            Some(AttributeType::FileName) => {
                if attr_header.is_non_resident == 0 {
                    // Parse $FILE_NAME
                    let value_offset = usize::from(rd_u16(data, offset + 20));
                    let fn_offset = offset + value_offset;
                    if fn_offset + size_of::<FileNameAttribute>() <= data.len() {
                        let fn_attr = match FileNameAttribute::read_from_prefix(&data[fn_offset..])
                        {
                            Ok((fn_attr, _)) => fn_attr,
                            Err(_) => break,
                        };
                        let name_len = usize::from(fn_attr.file_name_length);
                        let name_bytes_offset = fn_offset + size_of::<FileNameAttribute>();
                        if name_bytes_offset + name_len * 2 <= data.len() {
                            let name_bytes =
                                &data[name_bytes_offset..name_bytes_offset + name_len * 2];
                            // SmallVec avoids heap allocation for typical filenames (<= 64 chars)
                            let name_u16: SmallVec<[u16; 64]> = name_bytes
                                .as_chunks::<2>()
                                .0
                                .iter()
                                .map(|c| u16::from_le_bytes(*c))
                                .collect();
                            let name = crate::io::parser::unified::decode_name_u16(&name_u16).0;
                            let parent_frs = file_reference_to_frs(fn_attr.parent_directory);
                            let namespace = fn_attr.file_name_namespace;

                            // Skip DOS-only names (namespace 2)
                            if namespace != 2 {
                                let parse_idx = name_parse_counter;
                                name_parse_counter += 1;
                                let is_better = match namespace {
                                    1 | 3 => true,               // Win32 or Win32+DOS
                                    0 => primary_name.is_none(), // POSIX only if no name yet
                                    _ => false,
                                };
                                if is_better || primary_name.is_none() {
                                    // Move old primary to additional if exists
                                    if let Some((old_name, old_parent, _, old_parse_idx)) =
                                        primary_name.take()
                                    {
                                        additional_names.push((
                                            old_name,
                                            old_parent,
                                            old_parse_idx,
                                        ));
                                    }
                                    primary_name = Some((name, parent_frs, namespace, parse_idx));
                                    // $FILE_NAME's own timestamps for the new
                                    // primary name — free reads of the
                                    // already-decoded `fn_attr`.
                                    primary_fn_created = fn_attr.creation_time;
                                    primary_fn_modified = fn_attr.modification_time;
                                    primary_fn_accessed = fn_attr.access_time;
                                    primary_fn_mft_changed = fn_attr.mft_change_time;
                                } else {
                                    additional_names.push((name, parent_frs, parse_idx));
                                }
                            }
                        }
                    }
                }
            }
            Some(AttributeType::Data) => {
                // legacy-output parity: Only primary attributes (LowestVCN == 0) count as
                // streams. Continuation extents (LowestVCN > 0) are skipped.
                // See ntfs_index_load.hpp:358
                if !is_primary_attribute(data, offset, &attr_header) {
                    // Skip continuation extents - they don't count as new streams
                    offset += u32_as_usize(attr_header.length);
                    continue;
                }

                // Parse $DATA - track both default stream and ADS
                let name_len = usize::from(attr_header.name_length);
                let (size, allocated) = read_size_allocated(data, offset, &attr_header);
                let (is_resident, is_sparse) = resident_and_sparse(&attr_header);

                if name_len == 0 {
                    // Default stream
                    default_size = size;
                    default_allocated = allocated;
                    default_is_sparse = is_sparse;
                    default_is_resident = is_resident;
                } else {
                    // Alternate Data Stream (ADS)
                    let name_offset = offset + usize::from(attr_header.name_offset);
                    if name_offset + name_len * 2 <= data.len() {
                        let name_bytes = &data[name_offset..name_offset + name_len * 2];
                        let name_u16: SmallVec<[u16; 64]> = name_bytes
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|c| u16::from_le_bytes(*c))
                            .collect();
                        let stream_name = crate::io::parser::unified::decode_name_u16(&name_u16).0;
                        // ALL named $DATA streams create regular stream entries.
                        // Internal ones are filtered from
                        // output by is_internal_windows_stream in the output layer.
                        additional_streams.push((
                            stream_name,
                            size,
                            allocated,
                            is_sparse,
                            is_resident,
                        ));
                    }
                }
            }
            Some(AttributeType::ReparsePoint) => {
                // Parse $REPARSE_POINT to get the reparse tag.
                // Both resident and non-resident forms are handled.
                // $REPARSE_POINT is counted as a stream (affects descendants).
                let (rp_size, rp_allocated) = if attr_header.is_non_resident == 0 {
                    // Resident reparse point (common case)
                    let value_length = u64::from(rd_u32(data, offset + 16));
                    let value_offset = usize::from(rd_u16(data, offset + 20));
                    let rp_offset = offset + value_offset;
                    if rp_offset + 4 <= data.len() {
                        // Read reparse tag (first 4 bytes of reparse point data)
                        let tag_bytes = &data[rp_offset..rp_offset + 4];
                        reparse_tag =
                            u32::from_le_bytes(tag_bytes.try_into().unwrap_or([0, 0, 0, 0]));
                    }
                    (value_length, 0_u64) // Resident, allocated=0
                } else {
                    // Non-resident reparse point (rare - large reparse data)
                    let nr_offset = offset + 16;
                    if nr_offset + 48 <= data.len() {
                        let alloc_bytes = &data[nr_offset + 24..nr_offset + 32];
                        let allocated =
                            i64::from_le_bytes(alloc_bytes.try_into().unwrap_or([0; 8]));
                        let size_bytes = &data[nr_offset + 32..nr_offset + 40];
                        let data_size = i64::from_le_bytes(size_bytes.try_into().unwrap_or([0; 8]));
                        (nonneg_to_u64(data_size), nonneg_to_u64(allocated))
                    } else {
                        (0_u64, 0_u64)
                    }
                };

                // Add $REPARSE_POINT as a stream (contributes to stream counting)
                let (is_resident, is_sparse) = resident_and_sparse(&attr_header);
                additional_streams.push((
                    String::from("$REPARSE"),
                    rp_size,
                    rp_allocated,
                    is_sparse,
                    is_resident,
                ));
            }
            Some(
                AttributeType::IndexRoot | AttributeType::IndexAllocation | AttributeType::Bitmap,
            ) => {
                // $INDEX_ROOT and $INDEX_ALLOCATION with name $I30 contribute to
                // directory size. Non-$I30 indexes are counted as individual streams.

                // Extract attribute name
                let name_len = usize::from(attr_header.name_length);
                let (is_i30, attr_name) = if name_len > 0 {
                    let name_offset = offset + usize::from(attr_header.name_offset);
                    if name_offset + name_len * 2 <= data.len() {
                        let name_bytes = &data[name_offset..name_offset + name_len * 2];
                        // Check for "$I30" in UTF-16LE
                        let is_i30 =
                            attr_header.name_length == 4 && name_bytes == b"$\x00I\x003\x000\x00";
                        // Decode name for non-$I30 indexes
                        let name = if is_i30 {
                            String::new()
                        } else {
                            let name_u16: SmallVec<[u16; 64]> = name_bytes
                                .as_chunks::<2>()
                                .0
                                .iter()
                                .map(|c| u16::from_le_bytes(*c))
                                .collect();
                            crate::io::parser::unified::decode_name_u16(&name_u16).0
                        };
                        (is_i30, name)
                    } else {
                        (false, String::new())
                    }
                } else {
                    (false, String::new())
                };

                if is_i30 {
                    // Accumulate $I30 sizes for directories
                    let (size, allocated) = read_size_allocated(data, offset, &attr_header);
                    dir_index_size += size;
                    dir_index_allocated += allocated;
                } else if is_primary_attribute(data, offset, &attr_header) {
                    // Non-$I30 index - count as stream
                    let (size, allocated) = read_size_allocated(data, offset, &attr_header);
                    let stream_name = if attr_name.is_empty() {
                        match attr_type {
                            Some(AttributeType::Bitmap) => String::from("$BITMAP"),
                            Some(AttributeType::IndexRoot) => String::from("$INDEX_ROOT"),
                            Some(AttributeType::IndexAllocation) => {
                                String::from("$INDEX_ALLOCATION")
                            }
                            _ => String::new(),
                        }
                    } else {
                        attr_name
                    };
                    let (is_resident, is_sparse) = resident_and_sparse(&attr_header);
                    additional_streams.push((stream_name, size, allocated, is_sparse, is_resident));
                }
            }
            Some(
                AttributeType::ObjectId
                | AttributeType::VolumeName
                | AttributeType::VolumeInformation
                | AttributeType::PropertySet
                | AttributeType::Ea
                | AttributeType::EaInformation
                | AttributeType::LoggedUtilityStream
                | AttributeType::SecurityDescriptor
                | AttributeType::AttributeList,
            ) => {
                // All these attribute types are counted as individual streams.
                if is_primary_attribute(data, offset, &attr_header) {
                    let attr_name = extract_attr_name(data, offset, &attr_header);
                    let (size, allocated) = read_size_allocated(data, offset, &attr_header);
                    let stream_name = if attr_name.is_empty() {
                        match attr_type {
                            Some(AttributeType::ObjectId) => String::from("$OBJECT_ID"),
                            Some(AttributeType::VolumeName) => String::from("$VOLUME_NAME"),
                            Some(AttributeType::VolumeInformation) => {
                                String::from("$VOLUME_INFORMATION")
                            }
                            Some(AttributeType::PropertySet) => String::from("$PROPERTY_SET"),
                            Some(AttributeType::Ea) => String::from("$EA"),
                            Some(AttributeType::EaInformation) => String::from("$EA_INFORMATION"),
                            Some(AttributeType::LoggedUtilityStream) => {
                                String::from("$LOGGED_UTILITY_STREAM")
                            }
                            Some(AttributeType::SecurityDescriptor) => {
                                String::from("$SECURITY_DESCRIPTOR")
                            }
                            Some(AttributeType::AttributeList) => String::from("$ATTRIBUTE_LIST"),
                            _ => String::new(),
                        }
                    } else {
                        attr_name
                    };
                    let (is_resident, is_sparse) = resident_and_sparse(&attr_header);
                    additional_streams.push((stream_name, size, allocated, is_sparse, is_resident));
                }
            }
            _ => {
                // All remaining attribute types are counted as streams (catch-all).
                // This includes truly unknown types
                let type_code = attr_header.type_code;

                if is_primary_attribute(data, offset, &attr_header) {
                    let attr_name = extract_attr_name(data, offset, &attr_header);
                    let (size, allocated) = read_size_allocated(data, offset, &attr_header);

                    let stream_name = if attr_name.is_empty() {
                        format!("$UNKNOWN_0x{type_code:X}")
                    } else {
                        attr_name
                    };
                    let (is_resident, is_sparse) = resident_and_sparse(&attr_header);
                    additional_streams.push((stream_name, size, allocated, is_sparse, is_resident));
                }
            }
        }

        offset += u32_as_usize(attr_header.length);
    }

    // Set directory flag in std_info BEFORE checking for filename
    // This ensures is_directory is set even when $FILE_NAME is in extension record
    if is_directory {
        std_info.set_directory(true);
        // For directories, set default size to directory index size
        if dir_index_size > 0 {
            default_size = dir_index_size;
            default_allocated = dir_index_allocated;
        }
    }

    // Handle records without a filename in the base record
    // The $FILE_NAME may be in an extension record - we still need to store stdinfo
    let (name, parent_frs, primary_namespace, primary_parse_index) = match primary_name {
        Some(n) => n,
        None => {
            // No $FILE_NAME in base record - store stdinfo anyway
            // The extension record will add the name later
            //
            // IMPORTANT: We must still add ADS streams from the base record!
            // The $FILE_NAME may be in an extension record, but the ADS are here.
            // Without this, ADS on files/directories with extension records are lost.

            // Pre-process ADS streams using helper
            let additional_stream_count = additional_streams.len();
            let stream_indices: Vec<u32> = additional_streams
                .into_iter()
                .map(|(name, size, alloc, is_sparse, is_resident)| {
                    add_stream_to_index(index, &name, size, alloc, is_sparse, is_resident)
                })
                .collect();

            // Setup record and chain streams.
            // Boundary: lift the raw `u64` FRS argument (kernel/USN buffer)
            // into a typed `Frs` once for the typed index API.
            let record = index.get_or_create(crate::frs::Frs::new(frs));
            // Pre-existing gap, fixed alongside this one: this early-return
            // path never set sequence_number/lsn at all (only the main path
            // below did), so a record whose $FILE_NAME arrives via a later
            // extension record got neither — nothing else in the pipeline
            // sets them for it (extension records carry their own,
            // different-meaning sequence/LSN, per unified.rs's identical
            // base-record-only scoping).
            record.sequence_number = header.sequence_number;
            record.lsn = header.log_file_sequence_number;
            record.stdinfo = std_info;
            record.first_stream.size = SizeInfo {
                length: default_size,
                allocated: default_allocated,
            };
            record.first_stream.flags = u8::from(default_is_sparse)
                | (u8::from(default_is_resident) << 1_u8)
                | (8_u8 << 2_u8);

            if !stream_indices.is_empty() {
                chain_streams(index, &stream_indices);
                let record = index.get_or_create(crate::frs::Frs::new(frs));
                record.first_stream.next_entry = stream_indices[0];
                record.stream_count = 1 + len_to_u16(additional_stream_count);
            }

            return false;
        }
    };

    // Add primary name to names buffer and get reference
    let name_offset = index.add_name(&name);
    let name_len = name.len();
    let is_ascii = name.is_ascii();
    let extension_id = index.intern_extension(&name);
    let name_ref = IndexNameRef::new(name_offset, len_to_u16(name_len), is_ascii, extension_id);

    // Pre-process additional names using helpers
    let additional_count = additional_names.len();
    let mut additional_parent_frs: SmallVec<[(u64, u16); 4]> =
        SmallVec::with_capacity(additional_count);
    let link_indices: Vec<u32> = additional_names
        .into_iter()
        .map(|(link_name, link_parent, link_parse_idx)| {
            additional_parent_frs.push((link_parent, link_parse_idx));
            add_link_to_index(index, &link_name, link_parent)
        })
        .collect();

    // Pre-process additional streams (ADS) using helpers
    let additional_stream_count = additional_streams.len();
    let stream_indices: Vec<u32> = additional_streams
        .into_iter()
        .map(|(name, size, alloc, is_sparse, is_resident)| {
            add_stream_to_index(index, &name, size, alloc, is_sparse, is_resident)
        })
        .collect();

    // Ensure parent exists (create placeholder if needed) - do this before
    // getting our record.  Boundary: typed wrap of the raw `u64` from this
    // file's parse-layer locals into the typed index API.
    if parent_frs != frs && parent_frs != 0 {
        let _ = index.get_or_create(crate::frs::Frs::new(parent_frs));
    }

    // Now get or create the record in the index - no more index mutations
    // after this.
    let record = index.get_or_create(crate::frs::Frs::new(frs));
    // Persist the NTFS sequence number (slot-reuse generation). Together with
    // the FRS it forms the File Reference the compact index packs into
    // `file_ref`; without it a delete-then-reuse of an MFT slot is invisible to
    // the snapshot diff (the slot number alone is stable across reuse).
    record.sequence_number = header.sequence_number;
    record.lsn = header.log_file_sequence_number;
    // $FILE_NAME's own namespace/timestamps for the primary name (often
    // differ from $STANDARD_INFORMATION — e.g. timestomping alters
    // STD_INFO but leaves FILE_NAME original). Captured above per-name;
    // only the primary's values are stored since FileRecord carries just
    // one set.
    record.namespace = primary_namespace;
    record.fn_created = primary_fn_created;
    record.fn_modified = primary_fn_modified;
    record.fn_accessed = primary_fn_accessed;
    record.fn_mft_changed = primary_fn_mft_changed;
    record.stdinfo = std_info;
    record.first_stream.size = SizeInfo {
        length: default_size,
        allocated: default_allocated,
    };
    record.first_stream.flags =
        u8::from(default_is_sparse) | (u8::from(default_is_resident) << 1_u8) | (8_u8 << 2_u8);
    record.first_name = LinkInfo {
        next_entry: NO_ENTRY,
        name: name_ref,
        _pad0: [0; 4],
        // Typed `ParentFrs` written into the typed `LinkInfo.parent_frs`
        // slot; raw `u64` only lives as a parse-layer local.
        parent_frs: crate::frs::ParentFrs::new(parent_frs),
    };
    record.name_count = 1 + len_to_u16(additional_count);
    // stream_count = 1 (default) + additional ADS
    record.stream_count = 1 + len_to_u16(additional_stream_count);
    // total_stream_count includes all streams (including internal ones like
    // $REPARSE)
    record.total_stream_count =
        1 + len_to_u16(additional_stream_count) + len_to_u16(internal_streams.len());
    // Set reparse tag if this is a reparse point
    record.reparse_tag = reparse_tag;

    // Accumulate internal stream sizes for tree-metrics
    for (ist_size, ist_allocated) in &internal_streams {
        record.internal_streams_size = record.internal_streams_size.saturating_add(*ist_size);
        record.internal_streams_allocated = record
            .internal_streams_allocated
            .saturating_add(*ist_allocated);
    }

    // Chain the additional links: first_name -> link[0] -> link[1] -> ... ->
    // NO_ENTRY The links were pushed with next_entry = NO_ENTRY, now we chain
    // them
    if !link_indices.is_empty() {
        // Point first_name to the first additional link
        record.first_name.next_entry = link_indices[0];
    }

    // Chain the additional streams: first_stream -> stream[0] -> stream[1] -> ...
    if !stream_indices.is_empty() {
        // Point first_stream to the first additional stream
        record.first_stream.next_entry = stream_indices[0];
    }

    // Chain links and streams together using helpers
    chain_links(index, &link_indices);
    chain_streams(index, &stream_indices);

    // Build parent-child relationships for tree metrics computation
    add_child_entry(index, parent_frs, frs, primary_parse_index);
    for &(link_parent_frs, link_parse_idx) in &additional_parent_frs {
        add_child_entry(index, link_parent_frs, frs, link_parse_idx);
    }

    true
}
