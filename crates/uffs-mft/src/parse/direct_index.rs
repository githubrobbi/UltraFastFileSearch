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
    add_child_entry, add_link_to_index, add_stream_to_index, chain_links, chain_streams,
};
use crate::index::{nonneg_to_u64, u32_as_usize};

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
        StandardInformation, file_reference_to_frs,
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
    let mut default_size = 0_u64;
    let mut default_allocated = 0_u64;
    // ADS: (stream_name, size, allocated)
    let mut additional_streams: SmallVec<[(String, u64, u64); 4]> = SmallVec::new();
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
                    // Parse $STANDARD_INFORMATION
                    let value_offset_bytes = &data[offset + 20..offset + 22];
                    let value_offset = usize::from(u16::from_le_bytes(
                        value_offset_bytes.try_into().unwrap_or([0, 0]),
                    ));
                    let si_offset = offset + value_offset;
                    if si_offset + size_of::<StandardInformation>() <= data.len() {
                        let si = match StandardInformation::read_from_prefix(&data[si_offset..]) {
                            Ok((si, _)) => si,
                            Err(_) => break,
                        };
                        // Two-step canonical approach:
                        // 1. Parse raw attrs to ExtendedStandardInfo (complete parsing)
                        // 2. Convert to compact StandardInfo (single source of truth)
                        let ext =
                            crate::ntfs::ExtendedStandardInfo::from_attributes(si.file_attributes);
                        let mut info = StandardInfo::from_extended(&ext);
                        info.created = si.creation_time;
                        info.modified = si.modification_time;
                        info.accessed = si.access_time;
                        info.mft_changed = si.mft_change_time;
                        std_info = info;
                    }
                }
            }
            Some(AttributeType::FileName) => {
                if attr_header.is_non_resident == 0 {
                    // Parse $FILE_NAME
                    let value_offset_bytes = &data[offset + 20..offset + 22];
                    let value_offset = usize::from(u16::from_le_bytes(
                        value_offset_bytes.try_into().unwrap_or([0, 0]),
                    ));
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
                let is_primary = if attr_header.is_non_resident == 0 {
                    true // Resident attributes are always primary
                } else {
                    let nr_offset = offset + 16;
                    if nr_offset + 8 <= data.len() {
                        let lowest_vcn = i64::from_le_bytes(
                            data[nr_offset..nr_offset + 8].try_into().unwrap_or([0; 8]),
                        );
                        lowest_vcn == 0
                    } else {
                        false // Can't verify, skip to be safe
                    }
                };

                if !is_primary {
                    // Skip continuation extents - they don't count as new streams
                    offset += u32_as_usize(attr_header.length);
                    continue;
                }

                // Parse $DATA - track both default stream and ADS
                let name_len = usize::from(attr_header.name_length);
                let (size, allocated) = if attr_header.is_non_resident != 0 {
                    // Non-resident: size at offset 48, allocated at offset 40
                    let alloc_offset = offset + 40;
                    let size_offset = offset + 48;
                    if size_offset + 8 <= data.len() {
                        let allocated = u64::from_le_bytes(
                            data[alloc_offset..alloc_offset + 8]
                                .try_into()
                                .unwrap_or([0; 8]),
                        );
                        let size = u64::from_le_bytes(
                            data[size_offset..size_offset + 8]
                                .try_into()
                                .unwrap_or([0; 8]),
                        );
                        (size, allocated)
                    } else {
                        (0, 0)
                    }
                } else {
                    // Resident: value_length at offset 16
                    // Resident files have no clusters allocated — data is stored in the MFT record.
                    // allocated_size=0 for resident files.
                    let len_offset = offset + 16;
                    if len_offset + 4 <= data.len() {
                        let len = u64::from(u32::from_le_bytes(
                            data[len_offset..len_offset + 4]
                                .try_into()
                                .unwrap_or([0; 4]),
                        ));
                        (len, 0) // allocated_size = 0 for resident files
                    } else {
                        (0, 0)
                    }
                };

                if name_len == 0 {
                    // Default stream
                    default_size = size;
                    default_allocated = allocated;
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
                        additional_streams.push((stream_name, size, allocated));
                    }
                }
            }
            Some(AttributeType::ReparsePoint) => {
                // Parse $REPARSE_POINT to get the reparse tag.
                // Both resident and non-resident forms are handled.
                // $REPARSE_POINT is counted as a stream (affects descendants).
                let (rp_size, rp_allocated) = if attr_header.is_non_resident == 0 {
                    // Resident reparse point (common case)
                    let value_length_bytes = &data[offset + 16..offset + 20];
                    let value_length = u64::from(u32::from_le_bytes(
                        value_length_bytes.try_into().unwrap_or([0, 0, 0, 0]),
                    ));

                    let value_offset_bytes = &data[offset + 20..offset + 22];
                    let value_offset = usize::from(u16::from_le_bytes(
                        value_offset_bytes.try_into().unwrap_or([0, 0]),
                    ));
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
                additional_streams.push((String::from("$REPARSE"), rp_size, rp_allocated));
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
                    if attr_header.is_non_resident == 0 {
                        let value_length_bytes = &data[offset + 16..offset + 20];
                        let value_length = u64::from(u32::from_le_bytes(
                            value_length_bytes.try_into().unwrap_or([0; 4]),
                        ));
                        dir_index_size += value_length;
                    } else {
                        let nr_offset = offset + 16;
                        if nr_offset + 48 <= data.len() {
                            let alloc_bytes = &data[nr_offset + 24..nr_offset + 32];
                            let allocated =
                                i64::from_le_bytes(alloc_bytes.try_into().unwrap_or([0; 8]));
                            let size_bytes = &data[nr_offset + 32..nr_offset + 40];
                            let data_size =
                                i64::from_le_bytes(size_bytes.try_into().unwrap_or([0; 8]));
                            dir_index_size += nonneg_to_u64(data_size);
                            dir_index_allocated += nonneg_to_u64(allocated);
                        }
                    }
                } else {
                    // Non-$I30 index - count as stream
                    // Check if primary attribute (LowestVCN == 0)
                    let is_primary = if attr_header.is_non_resident == 0 {
                        true
                    } else {
                        let nr_offset = offset + 16;
                        if nr_offset + 8 <= data.len() {
                            let lowest_vcn = i64::from_le_bytes(
                                data[nr_offset..nr_offset + 8].try_into().unwrap_or([0; 8]),
                            );
                            lowest_vcn == 0
                        } else {
                            false
                        }
                    };

                    if is_primary {
                        let (size, allocated) = if attr_header.is_non_resident == 0 {
                            let value_length_bytes = &data[offset + 16..offset + 20];
                            let value_length = u64::from(u32::from_le_bytes(
                                value_length_bytes.try_into().unwrap_or([0; 4]),
                            ));
                            (value_length, 0_u64)
                        } else {
                            let nr_offset = offset + 16;
                            if nr_offset + 48 <= data.len() {
                                let alloc_bytes = &data[nr_offset + 24..nr_offset + 32];
                                let allocated =
                                    i64::from_le_bytes(alloc_bytes.try_into().unwrap_or([0; 8]));
                                let size_bytes = &data[nr_offset + 32..nr_offset + 40];
                                let data_size =
                                    i64::from_le_bytes(size_bytes.try_into().unwrap_or([0; 8]));
                                (nonneg_to_u64(data_size), nonneg_to_u64(allocated))
                            } else {
                                (0_u64, 0_u64)
                            }
                        };

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
                        additional_streams.push((stream_name, size, allocated));
                    }
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
                // Check if primary attribute (LowestVCN == 0)
                let is_primary = if attr_header.is_non_resident == 0 {
                    true
                } else {
                    let nr_offset = offset + 16;
                    if nr_offset + 8 <= data.len() {
                        let lowest_vcn = i64::from_le_bytes(
                            data[nr_offset..nr_offset + 8].try_into().unwrap_or([0; 8]),
                        );
                        lowest_vcn == 0
                    } else {
                        false
                    }
                };

                if is_primary {
                    // Extract attribute name (if any)
                    let attr_name = if attr_header.name_length > 0 {
                        let name_offset = offset + usize::from(attr_header.name_offset);
                        let name_len = usize::from(attr_header.name_length);
                        if name_offset + name_len * 2 <= data.len() {
                            let name_bytes = &data[name_offset..name_offset + name_len * 2];
                            let name_u16: SmallVec<[u16; 64]> = name_bytes
                                .as_chunks::<2>()
                                .0
                                .iter()
                                .map(|c| u16::from_le_bytes(*c))
                                .collect();
                            crate::io::parser::unified::decode_name_u16(&name_u16).0
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };

                    let (size, allocated) = if attr_header.is_non_resident == 0 {
                        let value_length_bytes = &data[offset + 16..offset + 20];
                        let value_length = u64::from(u32::from_le_bytes(
                            value_length_bytes.try_into().unwrap_or([0; 4]),
                        ));
                        (value_length, 0_u64)
                    } else {
                        let nr_offset = offset + 16;
                        if nr_offset + 48 <= data.len() {
                            let alloc_bytes = &data[nr_offset + 24..nr_offset + 32];
                            let allocated =
                                i64::from_le_bytes(alloc_bytes.try_into().unwrap_or([0; 8]));
                            let size_bytes = &data[nr_offset + 32..nr_offset + 40];
                            let data_size =
                                i64::from_le_bytes(size_bytes.try_into().unwrap_or([0; 8]));
                            (nonneg_to_u64(data_size), nonneg_to_u64(allocated))
                        } else {
                            (0_u64, 0_u64)
                        }
                    };

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
                    additional_streams.push((stream_name, size, allocated));
                }
            }
            _ => {
                // All remaining attribute types are counted as streams (catch-all).
                // This includes truly unknown types
                let type_code = attr_header.type_code;

                // Check if primary attribute (LowestVCN == 0)
                let is_primary = if attr_header.is_non_resident == 0 {
                    true
                } else {
                    let nr_offset = offset + 16;
                    if nr_offset + 8 <= data.len() {
                        let lowest_vcn = i64::from_le_bytes(
                            data[nr_offset..nr_offset + 8].try_into().unwrap_or([0; 8]),
                        );
                        lowest_vcn == 0
                    } else {
                        false
                    }
                };

                if is_primary {
                    // Extract attribute name (if any)
                    let attr_name = if attr_header.name_length > 0 {
                        let name_offset = offset + usize::from(attr_header.name_offset);
                        let name_len = usize::from(attr_header.name_length);
                        if name_offset + name_len * 2 <= data.len() {
                            let name_bytes = &data[name_offset..name_offset + name_len * 2];
                            let name_u16: SmallVec<[u16; 64]> = name_bytes
                                .as_chunks::<2>()
                                .0
                                .iter()
                                .map(|c| u16::from_le_bytes(*c))
                                .collect();
                            crate::io::parser::unified::decode_name_u16(&name_u16).0
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };

                    let (size, allocated) = if attr_header.is_non_resident == 0 {
                        let value_length_bytes = &data[offset + 16..offset + 20];
                        let value_length = u64::from(u32::from_le_bytes(
                            value_length_bytes.try_into().unwrap_or([0; 4]),
                        ));
                        (value_length, 0_u64)
                    } else {
                        let nr_offset = offset + 16;
                        if nr_offset + 48 <= data.len() {
                            let alloc_bytes = &data[nr_offset + 24..nr_offset + 32];
                            let allocated =
                                i64::from_le_bytes(alloc_bytes.try_into().unwrap_or([0; 8]));
                            let size_bytes = &data[nr_offset + 32..nr_offset + 40];
                            let data_size =
                                i64::from_le_bytes(size_bytes.try_into().unwrap_or([0; 8]));
                            (nonneg_to_u64(data_size), nonneg_to_u64(allocated))
                        } else {
                            (0_u64, 0_u64)
                        }
                    };

                    let stream_name = if attr_name.is_empty() {
                        format!("$UNKNOWN_0x{type_code:X}")
                    } else {
                        attr_name
                    };
                    additional_streams.push((stream_name, size, allocated));
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
    let (name, parent_frs, _namespace, primary_parse_index) = match primary_name {
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
                .map(|(name, size, alloc)| add_stream_to_index(index, &name, size, alloc))
                .collect();

            // Setup record and chain streams.
            // Boundary: lift the raw `u64` FRS argument (kernel/USN buffer)
            // into a typed `Frs` once for the typed index API.
            let record = index.get_or_create(crate::frs::Frs::new(frs));
            record.stdinfo = std_info;
            record.first_stream.size = SizeInfo {
                length: default_size,
                allocated: default_allocated,
            };

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
        .map(|(name, size, alloc)| add_stream_to_index(index, &name, size, alloc))
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
    record.stdinfo = std_info;
    record.first_stream.size = SizeInfo {
        length: default_size,
        allocated: default_allocated,
    };
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
