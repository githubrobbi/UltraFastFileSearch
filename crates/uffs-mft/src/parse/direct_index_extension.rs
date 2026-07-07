// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Extension record parser for direct-to-index path.
//!
//! Exception: Direct index extension record parser for offline mode.
//!
//! This module handles extension records for the single-pass parser, extracting
//! names, streams, and all attribute types from extension records and merging
//! them into base records in the index.

// Performance-critical hot-path parser — lint suppressions match the style of
// other NTFS parser modules in this crate.
#![expect(
    clippy::manual_let_else,
    reason = "explicit match is clearer in NTFS attribute dispatch"
)]
#![expect(
    clippy::shadow_unrelated,
    reason = "reusing common names like 'record' in nested scopes is idiomatic here"
)]
#![expect(
    clippy::let_underscore_untyped,
    reason = "let _ = expr is used for intentionally ignoring results"
)]
#![expect(
    clippy::if_not_else,
    reason = "!condition checks are clearer for NTFS flag testing"
)]
#![expect(
    clippy::if_then_some_else_none,
    reason = "explicit if/else is clearer than bool::then in complex NTFS logic"
)]
#![expect(
    clippy::single_call_fn,
    reason = "parse_extension_to_index is a separate function for code organization"
)]

use core::mem::size_of;

use smallvec::SmallVec;
use zerocopy::FromBytes as _;

use super::index_helpers::{add_link_to_index, add_stream_to_index};
use crate::index::{frs_to_usize, len_to_u16, len_to_u32, nonneg_to_u64, u32_as_usize};

/// Parses an extension record and adds its names/streams to the base record.
///
/// Extension records contain additional `$FILE_NAME` attributes (hard links)
/// and additional attributes (ADS, system attributes, etc.) that don't fit
/// in the base record. This function extracts those attributes and adds them
/// to the base record in the index.
///
/// Handles ALL attribute types that `parse_record_full()` handles, including:
/// - `$FILE_NAME` (hard links)
/// - `$DATA` (ADS)
/// - `$REPARSE_POINT`, `$INDEX_ROOT`, `$INDEX_ALLOCATION`, `$BITMAP`
/// - `$OBJECT_ID`, `$EA`, `$LOGGED_UTILITY_STREAM`, etc.
/// - Unknown attribute types
///
/// # Arguments
///
/// * `data` - The raw extension record data (after fixup)
/// * `base_frs` - The FRS of the base record this extension belongs to
/// * `index` - The MFT index to update
///
/// # Returns
///
/// `true` if any names/streams were added, `false` otherwise.
#[expect(
    clippy::cognitive_complexity,
    reason = "NTFS attribute dispatch is inherently complex"
)]
#[expect(
    clippy::too_many_lines,
    reason = "monolithic extension parser for performance"
)]
pub(super) fn parse_extension_to_index(
    data: &[u8],
    base_frs: u64,
    index: &mut crate::index::MftIndex,
) -> bool {
    use crate::index::{ChildInfo, NO_ENTRY};
    use crate::ntfs::{
        AttributeRecordHeader, AttributeType, FileNameAttribute, FileRecordSegmentHeader,
    };

    if data.len() < size_of::<FileRecordSegmentHeader>() {
        return false;
    }

    let header = match FileRecordSegmentHeader::read_from_prefix(data) {
        Ok((header, _)) => header,
        Err(_) => return false,
    };

    // Parse attributes to find $FILE_NAME and $DATA
    let mut offset = usize::from(header.first_attribute_offset);
    let max_offset = core::cmp::min(u32_as_usize(header.bytes_in_use), data.len());

    // Collect names and streams from extension record
    let mut names: SmallVec<[(String, u64); 4]> = SmallVec::new();
    let mut streams: SmallVec<[(String, u64, u64); 4]> = SmallVec::new();
    let ext_internal_streams: SmallVec<[(u64, u64); 4]> = SmallVec::new();
    let mut dir_index_size: u64 = 0;
    let mut dir_index_allocated: u64 = 0;
    // Default $DATA stream (unnamed, name_len == 0) found in extension record
    let mut default_data_size: u64 = 0;
    let mut default_data_allocated: u64 = 0;
    let mut found_default_data = false;

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
            Some(AttributeType::FileName) => {
                // Parse $FILE_NAME attribute
                if attr_header.is_non_resident == 0 {
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

                        // Skip DOS-only names (namespace 2)
                        if fn_attr.file_name_namespace != 2 {
                            let name_len = usize::from(fn_attr.file_name_length);
                            let name_start = fn_offset + size_of::<FileNameAttribute>();
                            if name_start + name_len * 2 <= data.len() {
                                let name_bytes = &data[name_start..name_start + name_len * 2];
                                let name_u16: SmallVec<[u16; 64]> = name_bytes
                                    .as_chunks::<2>()
                                    .0
                                    .iter()
                                    .map(|c| u16::from_le_bytes(*c))
                                    .collect();
                                let name = crate::io::parser::unified::decode_name_u16(&name_u16).0;
                                let parent_frs = fn_attr.parent_directory & 0x0000_FFFF_FFFF_FFFF;
                                names.push((name, parent_frs));
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

                // Parse $DATA attribute — default stream (unnamed) or ADS (named)
                let name_len = usize::from(attr_header.name_length);
                let (size, allocated) = if attr_header.is_non_resident != 0 {
                    let nr_offset = offset + 16;
                    if nr_offset + 48 <= data.len() {
                        let allocated = i64::from_le_bytes(
                            data[nr_offset + 24..nr_offset + 32]
                                .try_into()
                                .unwrap_or([0; 8]),
                        );
                        let size = i64::from_le_bytes(
                            data[nr_offset + 32..nr_offset + 40]
                                .try_into()
                                .unwrap_or([0; 8]),
                        );
                        (nonneg_to_u64(size), nonneg_to_u64(allocated))
                    } else {
                        (0, 0)
                    }
                } else {
                    let len_offset = offset + 16;
                    if len_offset + 4 <= data.len() {
                        let len = u64::from(u32::from_le_bytes(
                            data[len_offset..len_offset + 4]
                                .try_into()
                                .unwrap_or([0; 4]),
                        ));
                        (len, 0)
                    } else {
                        (0, 0)
                    }
                };

                if name_len == 0 {
                    // Default $DATA stream — update base record size
                    default_data_size = size;
                    default_data_allocated = allocated;
                    found_default_data = true;
                } else {
                    // ADS (named stream)
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
                        // ALL named $DATA streams create regular
                        // stream entries.  Internal ones are filtered from
                        // output by is_internal_windows_stream in the output layer.
                        streams.push((stream_name, size, allocated));
                    }
                }
            }
            Some(AttributeType::ReparsePoint) => {
                // Parse $REPARSE_POINT - add as stream
                let (rp_size, rp_allocated) = if attr_header.is_non_resident == 0 {
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
                        let data_size = i64::from_le_bytes(size_bytes.try_into().unwrap_or([0; 8]));
                        (nonneg_to_u64(data_size), nonneg_to_u64(allocated))
                    } else {
                        (0_u64, 0_u64)
                    }
                };
                streams.push((String::from("$REPARSE"), rp_size, rp_allocated));
            }
            Some(
                AttributeType::IndexRoot | AttributeType::IndexAllocation | AttributeType::Bitmap,
            ) => {
                // Extract attribute name
                let name_len = usize::from(attr_header.name_length);
                let (is_i30, attr_name) = if name_len > 0 {
                    let name_offset = offset + usize::from(attr_header.name_offset);
                    if name_offset + name_len * 2 <= data.len() {
                        let name_bytes = &data[name_offset..name_offset + name_len * 2];
                        let is_i30 =
                            attr_header.name_length == 4 && name_bytes == b"$\x00I\x003\x000\x00";
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
                    // Accumulate $I30 sizes
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
                        streams.push((stream_name, size, allocated));
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
                // All counted as streams
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
                    streams.push((stream_name, size, allocated));
                }
            }
            Some(AttributeType::StandardInformation) => {
                // Skip - not expected in extension records
            }
            _ => {
                // Unknown attribute types — counted as streams (catch-all).
                let type_code = attr_header.type_code;

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
                    streams.push((stream_name, size, allocated));
                }
            }
        }

        offset += u32_as_usize(attr_header.length);
    }

    // If no names, streams, default data, or directory index sizes found,
    // nothing to do
    if names.is_empty()
        && streams.is_empty()
        && ext_internal_streams.is_empty()
        && !found_default_data
        && dir_index_size == 0
        && dir_index_allocated == 0
    {
        return false;
    }

    // Add names to the base record
    // First, add all names to the names buffer and create LinkInfo entries
    // Add names/streams using helpers
    let link_indices: Vec<u32> = names
        .iter()
        .map(|(name, parent)| add_link_to_index(index, name, *parent))
        .collect();
    let stream_indices: Vec<u32> = streams
        .iter()
        .map(|(name, size, alloc)| add_stream_to_index(index, name, *size, *alloc))
        .collect();

    // Ensure parent directories exist for the new names.  Parser-local
    // raw `u64` lifts to typed `Frs` at the typed-API boundary.
    for (_, parent_frs) in &names {
        if *parent_frs != base_frs && *parent_frs != 0 {
            let _ = index.get_or_create(crate::frs::Frs::new(*parent_frs));
        }
    }

    // Get the base record and add the names/streams to it
    let base_frs_usize = frs_to_usize(base_frs);
    if base_frs_usize >= index.frs_to_idx.len() {
        // Base record doesn't exist yet - create a placeholder
        let _ = index.get_or_create(crate::frs::Frs::new(base_frs));
    }

    let record_idx = index.frs_to_idx[base_frs_usize];
    if record_idx == NO_ENTRY {
        // Base record doesn't exist - create it
        let _ = index.get_or_create(crate::frs::Frs::new(base_frs));
    }

    // Now get the record and chain the new links/streams
    let record_idx = index.frs_to_idx[base_frs_usize];
    if record_idx != NO_ENTRY {
        let record = &mut index.records[u32_as_usize(record_idx)];
        // Snapshot name_count BEFORE link-chaining modifies it (for child entries)
        let pre_chain_name_count = record.name_count;

        // Add new links to the record
        if !link_indices.is_empty() {
            // Check if base record has no name (first_name is empty)
            // This happens when the $FILE_NAME attribute is ONLY in extension records
            if !record.first_name.name.is_valid() {
                // Copy the first extension name directly into first_name
                // This matches established behavior (ntfs_index.hpp lines 559-567)
                let first_link = &index.links[u32_as_usize(link_indices[0])];
                record.first_name.name = first_link.name;
                record.first_name.parent_frs = first_link.parent_frs;
                // Don't increment name_count for the first name (it's already counted as 1)

                // Chain remaining links (if any) to first_name.next_entry
                if link_indices.len() > 1 {
                    // Chain the remaining links together
                    for i in 1..link_indices.len().saturating_sub(1) {
                        let current_idx = u32_as_usize(link_indices[i]);
                        let next_idx = link_indices[i + 1];
                        index.links[current_idx].next_entry = next_idx;
                    }
                    // Attach remaining links to first_name
                    let record = &mut index.records[u32_as_usize(record_idx)];
                    record.first_name.next_entry = link_indices[1];
                    // Update name count for additional links only
                    record.name_count += len_to_u16(link_indices.len().saturating_sub(1));
                }
            } else {
                // Base record already has a name - chain extension names as additional hard
                // links Find the end of the current link chain
                let last_link_idx = if record.first_name.next_entry != NO_ENTRY {
                    let mut idx = record.first_name.next_entry;
                    while index.links[u32_as_usize(idx)].next_entry != NO_ENTRY {
                        idx = index.links[u32_as_usize(idx)].next_entry;
                    }
                    Some(idx)
                } else {
                    None
                };

                // Chain the new links together
                for i in 0..link_indices.len().saturating_sub(1) {
                    let current_idx = u32_as_usize(link_indices[i]);
                    let next_idx = link_indices[i + 1];
                    index.links[current_idx].next_entry = next_idx;
                }

                // Attach to the chain
                if let Some(last_idx) = last_link_idx {
                    index.links[u32_as_usize(last_idx)].next_entry = link_indices[0];
                } else {
                    // first_name has no next_entry, attach directly
                    let record = &mut index.records[u32_as_usize(record_idx)];
                    record.first_name.next_entry = link_indices[0];
                }

                // Update name count
                let record = &mut index.records[u32_as_usize(record_idx)];
                record.name_count += len_to_u16(link_indices.len());
            }
        }

        // Chain new streams to the end of the existing stream chain
        if !stream_indices.is_empty() {
            let record = &mut index.records[u32_as_usize(record_idx)];

            // Find the end of the current stream chain
            let last_stream_idx = if record.first_stream.next_entry != NO_ENTRY {
                let mut idx = record.first_stream.next_entry;
                while index.streams[u32_as_usize(idx)].next_entry != NO_ENTRY {
                    idx = index.streams[u32_as_usize(idx)].next_entry;
                }
                Some(idx)
            } else {
                None
            };

            // Chain the new streams together
            for i in 0..stream_indices.len().saturating_sub(1) {
                let current_idx = u32_as_usize(stream_indices[i]);
                let next_idx = stream_indices[i + 1];
                index.streams[current_idx].next_entry = next_idx;
            }

            // Attach to the chain
            if let Some(last_idx) = last_stream_idx {
                index.streams[u32_as_usize(last_idx)].next_entry = stream_indices[0];
            } else {
                // first_stream has no next_entry, attach directly
                let record = &mut index.records[u32_as_usize(record_idx)];
                record.first_stream.next_entry = stream_indices[0];
            }

            // Update stream count
            let record = &mut index.records[u32_as_usize(record_idx)];
            record.stream_count += len_to_u16(stream_indices.len());
            record.total_stream_count += len_to_u16(stream_indices.len());
        }

        // Merge default $DATA stream from extension record into base record.
        // This handles files whose $DATA attribute doesn't fit in the base MFT
        // record (e.g., large files with extensive run lists).
        if found_default_data {
            let record = &mut index.records[u32_as_usize(record_idx)];

            // If base record has no $DATA (both fields are 0), use extension's $DATA.
            // Otherwise, accumulate extension $DATA to base $DATA.
            if record.first_stream.size.length == 0 && record.first_stream.size.allocated == 0 {
                // Base has no $DATA — use extension's values
                record.first_stream.size.length = default_data_size;
                record.first_stream.size.allocated = default_data_allocated;
            } else {
                // Base has partial $DATA — accumulate extension values
                record.first_stream.size.length = record
                    .first_stream
                    .size
                    .length
                    .saturating_add(default_data_size);
                record.first_stream.size.allocated = record
                    .first_stream
                    .size
                    .allocated
                    .saturating_add(default_data_allocated);
            }
        }

        // Accumulate internal stream sizes from extension records
        if !ext_internal_streams.is_empty() {
            let record = &mut index.records[u32_as_usize(record_idx)];
            for (ist_size, ist_allocated) in &ext_internal_streams {
                record.internal_streams_size =
                    record.internal_streams_size.saturating_add(*ist_size);
                record.internal_streams_allocated = record
                    .internal_streams_allocated
                    .saturating_add(*ist_allocated);
            }
            record.total_stream_count += len_to_u16(ext_internal_streams.len());
        }

        // Merge directory index sizes from extension records
        if dir_index_size > 0 || dir_index_allocated > 0 {
            let record = &mut index.records[u32_as_usize(record_idx)];

            // CRITICAL: Handle IOCP out-of-order scenarios.
            // Apply the same snapshot/restore pattern as default $DATA (lines 718-733).
            // If base record has no first_stream size (both 0), either:
            // (a) base hasn't been parsed yet, OR
            // (b) genuinely has no $DATA/$I30
            //
            // We use the same pattern: write if empty, accumulate otherwise.

            if record.first_stream.size.length == 0 && record.first_stream.size.allocated == 0 {
                // Base has no size set - use extension's dir_index values
                record.first_stream.size.length = dir_index_size;
                record.first_stream.size.allocated = dir_index_allocated;
            } else {
                // Base has size set - accumulate extension's dir_index
                record.first_stream.size.length = record
                    .first_stream
                    .size
                    .length
                    .saturating_add(dir_index_size);
                record.first_stream.size.allocated = record
                    .first_stream
                    .size
                    .allocated
                    .saturating_add(dir_index_allocated);
            }
        }

        // Build parent-child relationship for names added from extension records
        // This is critical for compute_tree_metrics() to work correctly.
        // Use the name_count from BEFORE link-chaining to avoid overflow
        let existing_name_count = pre_chain_name_count;

        for (name_idx, (_, parent_frs)) in names.iter().enumerate() {
            let p_frs = *parent_frs;
            if p_frs == base_frs || p_frs == u64::from(NO_ENTRY) {
                continue;
            }

            // Ensure parent exists
            let parent_idx = {
                let p_frs_usize = frs_to_usize(p_frs);
                if p_frs_usize >= index.frs_to_idx.len() {
                    index.frs_to_idx.resize(p_frs_usize + 1, NO_ENTRY);
                }
                if index.frs_to_idx[p_frs_usize] == NO_ENTRY {
                    // Create placeholder parent
                    let new_idx = len_to_u32(index.records.len());
                    index.frs_to_idx[p_frs_usize] = new_idx;
                    index
                        .records
                        .push(crate::index::FileRecord::new(crate::frs::Frs::new(p_frs)));
                }
                index.frs_to_idx[p_frs_usize]
            };

            // Add child entry
            // name_index is the position in the combined name list (existing + new)
            // For extension records, the first name might replace first_name (if empty),
            // so we need to account for that
            let effective_name_idx = if existing_name_count == 0 {
                // First extension name became first_name, so name_index starts at 0
                len_to_u16(name_idx)
            } else {
                // Extension names are appended after existing names
                existing_name_count - 1 + len_to_u16(name_idx)
            };

            let child_idx = len_to_u32(index.children.len());
            let parent = &mut index.records[u32_as_usize(parent_idx)];
            let old_first_child = parent.first_child;
            parent.first_child = child_idx;

            index.children.push(ChildInfo {
                next_entry: old_first_child,
                _pad0: [0; 4],
                child_frs: crate::frs::Frs::new(base_frs),
                name_index: effective_name_idx,
                _pad1: [0; 6],
            });
        }
    }

    !names.is_empty()
        || !streams.is_empty()
        || !ext_internal_streams.is_empty()
        || found_default_data
        || dir_index_size > 0
        || dir_index_allocated > 0
}
