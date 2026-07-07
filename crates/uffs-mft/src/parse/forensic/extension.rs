// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Extension-record forensic parsing for merge-oriented handling.

use zerocopy::FromBytes as _;

use super::super::{
    ExtensionAttributes, ParseResult, parse_data_attribute_full, parse_file_name_full,
};
use crate::index::nonneg_to_u64;
use crate::ntfs::{
    AttributeRecordHeader, AttributeType, FileRecordSegmentHeader, NameInfo, StreamInfo,
};

/// Parses an extension record for merge-mode handling.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "extension parsing still handles many attribute types sequentially"
)]
#[expect(
    clippy::cognitive_complexity,
    reason = "extension parsing mirrors base attribute dispatch for parity"
)]
#[expect(
    clippy::single_call_fn,
    reason = "kept separate from the dispatching entry point for forensic readability"
)]
pub(super) fn parse_extension_record(
    data: &[u8],
    frs: u64,
    header: &FileRecordSegmentHeader,
    base_frs_value: u64,
) -> ParseResult {
    use core::mem::size_of;

    // Parse attributes for extension merging
    // Must handle ALL attribute types that base record parsing handles
    let mut names: Vec<NameInfo> = Vec::new();
    let mut streams: Vec<StreamInfo> = Vec::new();
    let mut dir_index_size: u64 = 0;
    let mut dir_index_allocated: u64 = 0;

    let mut offset = header.first_attribute_offset as usize;
    let max_offset = core::cmp::min(header.bytes_in_use as usize, data.len());

    while offset + size_of::<AttributeRecordHeader>() <= max_offset {
        let Ok((attr_header, _)) = AttributeRecordHeader::read_from_prefix(&data[offset..]) else {
            break;
        };

        if attr_header.type_code == AttributeType::End as u32 {
            break;
        }
        if attr_header.length == 0 || offset + attr_header.length as usize > max_offset {
            break;
        }

        match AttributeType::from_u32(attr_header.type_code) {
            Some(AttributeType::FileName) if attr_header.is_non_resident == 0 => {
                if let Some(name_info) = parse_file_name_full(data, offset, frs)
                    && name_info.namespace != 2
                {
                    names.push(name_info);
                }
            }
            Some(AttributeType::Data) => {
                if let Some(stream_info) =
                    parse_data_attribute_full(data, offset, &attr_header, frs)
                {
                    streams.push(stream_info);
                }
            }
            Some(AttributeType::ReparsePoint) => {
                // Parse $REPARSE_POINT - same logic as base record parsing
                let (rp_size, rp_allocated, is_resident) = if attr_header.is_non_resident == 0 {
                    let value_length = u64::from(u32::from_le_bytes(
                        data.get(offset + 16..offset + 20)
                            .and_then(|b| b.try_into().ok())
                            .unwrap_or([0, 0, 0, 0]),
                    ));
                    (value_length, 0_u64, true)
                } else {
                    let nr_offset = offset + 16;
                    let (data_size, alloc_size) = if nr_offset + 48 <= data.len() {
                        let ds = i64::from_le_bytes(
                            data[nr_offset + 32..nr_offset + 40]
                                .try_into()
                                .unwrap_or([0; 8]),
                        );
                        let alloc = i64::from_le_bytes(
                            data[nr_offset + 24..nr_offset + 32]
                                .try_into()
                                .unwrap_or([0; 8]),
                        );
                        (nonneg_to_u64(ds), nonneg_to_u64(alloc))
                    } else {
                        (0_u64, 0_u64)
                    };
                    (data_size, alloc_size, false)
                };
                streams.push(StreamInfo {
                    name: String::from("$REPARSE"),
                    size: rp_size,
                    allocated_size: rp_allocated,
                    is_sparse: false,
                    is_compressed: false,
                    is_resident,
                });
            }
            Some(
                AttributeType::IndexRoot | AttributeType::IndexAllocation | AttributeType::Bitmap,
            ) => {
                // Handle $I30 directory index attributes
                let (is_i30, attr_name) = if attr_header.name_length > 0 {
                    let name_offset = offset + usize::from(attr_header.name_offset);
                    let name_len = usize::from(attr_header.name_length);
                    if name_offset + name_len * 2 <= data.len() {
                        let name_bytes = &data[name_offset..name_offset + name_len * 2];
                        let is_i30 =
                            attr_header.name_length == 4 && name_bytes == b"$\x00I\x003\x000\x00";
                        let name = if is_i30 {
                            String::new()
                        } else {
                            let name_u16: smallvec::SmallVec<[u16; 64]> = name_bytes
                                .as_chunks::<2>()
                                .0
                                .iter()
                                .map(|chunk| u16::from_le_bytes(*chunk))
                                .collect();
                            String::from_utf16(&name_u16).unwrap_or_default()
                        };
                        (is_i30, name)
                    } else {
                        (false, String::new())
                    }
                } else {
                    (false, String::new())
                };

                if is_i30 {
                    // $I30:$BITMAP is NOT included in directory size.
                    // $BITMAP is metadata (used/free slots in the directory index),
                    // not part of directory byte size. Skip this attribute.
                    if matches!(
                        AttributeType::from_u32(attr_header.type_code),
                        Some(AttributeType::Bitmap)
                    ) {
                        // Skip $I30:$BITMAP - don't add to dir_index_size
                    } else {
                        // Accumulate $I30 sizes for directory
                        // Only $INDEX_ROOT and $INDEX_ALLOCATION contribute to directory size
                        if attr_header.is_non_resident == 0 {
                            let value_length = u64::from(u32::from_le_bytes(
                                data.get(offset + 16..offset + 20)
                                    .and_then(|b| b.try_into().ok())
                                    .unwrap_or([0; 4]),
                            ));
                            dir_index_size += value_length;
                        } else {
                            let nr_offset = offset + 16;
                            if nr_offset + 48 <= data.len() {
                                let allocated = i64::from_le_bytes(
                                    data[nr_offset + 24..nr_offset + 32]
                                        .try_into()
                                        .unwrap_or([0; 8]),
                                );
                                let data_size = i64::from_le_bytes(
                                    data[nr_offset + 32..nr_offset + 40]
                                        .try_into()
                                        .unwrap_or([0; 8]),
                                );
                                dir_index_size += nonneg_to_u64(data_size);
                                dir_index_allocated += nonneg_to_u64(allocated);
                            }
                        }
                    }
                } else {
                    // Non-$I30 index - add as stream
                    let (size, allocated_size, is_resident) = if attr_header.is_non_resident == 0 {
                        let value_length = u64::from(u32::from_le_bytes(
                            data.get(offset + 16..offset + 20)
                                .and_then(|b| b.try_into().ok())
                                .unwrap_or([0; 4]),
                        ));
                        (value_length, 0_u64, true)
                    } else {
                        let nr_offset = offset + 16;
                        if nr_offset + 48 <= data.len() {
                            let allocated = i64::from_le_bytes(
                                data[nr_offset + 24..nr_offset + 32]
                                    .try_into()
                                    .unwrap_or([0; 8]),
                            );
                            let data_size = i64::from_le_bytes(
                                data[nr_offset + 32..nr_offset + 40]
                                    .try_into()
                                    .unwrap_or([0; 8]),
                            );
                            (nonneg_to_u64(data_size), nonneg_to_u64(allocated), false)
                        } else {
                            (0_u64, 0_u64, false)
                        }
                    };
                    let stream_name = if attr_name.is_empty() {
                        match AttributeType::from_u32(attr_header.type_code) {
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
                    streams.push(StreamInfo {
                        name: stream_name,
                        size,
                        allocated_size,
                        is_sparse: false,
                        is_compressed: false,
                        is_resident,
                    });
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
                // Handle other stream-creating attributes
                // Note: AttributeList (0x20) IS counted as a stream (catch-all below).
                // case
                let attr_name = if attr_header.name_length > 0 {
                    let name_offset = offset + usize::from(attr_header.name_offset);
                    let name_len = usize::from(attr_header.name_length);
                    if name_offset + name_len * 2 <= data.len() {
                        let name_bytes = &data[name_offset..name_offset + name_len * 2];
                        let name_u16: smallvec::SmallVec<[u16; 64]> = name_bytes
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|chunk| u16::from_le_bytes(*chunk))
                            .collect();
                        String::from_utf16(&name_u16).unwrap_or_default()
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };

                let (size, allocated_size, is_resident) = if attr_header.is_non_resident == 0 {
                    let value_length = u64::from(u32::from_le_bytes(
                        data.get(offset + 16..offset + 20)
                            .and_then(|b| b.try_into().ok())
                            .unwrap_or([0; 4]),
                    ));
                    (value_length, 0_u64, true)
                } else {
                    let nr_offset = offset + 16;
                    if nr_offset + 48 <= data.len() {
                        let allocated = i64::from_le_bytes(
                            data[nr_offset + 24..nr_offset + 32]
                                .try_into()
                                .unwrap_or([0; 8]),
                        );
                        let data_size = i64::from_le_bytes(
                            data[nr_offset + 32..nr_offset + 40]
                                .try_into()
                                .unwrap_or([0; 8]),
                        );
                        (nonneg_to_u64(data_size), nonneg_to_u64(allocated), false)
                    } else {
                        (0_u64, 0_u64, false)
                    }
                };

                let stream_name = if attr_name.is_empty() {
                    match AttributeType::from_u32(attr_header.type_code) {
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

                streams.push(StreamInfo {
                    name: stream_name,
                    size,
                    allocated_size,
                    is_sparse: false,
                    is_compressed: false,
                    is_resident,
                });
            }
            _ => {
                // All remaining attribute types are counted as streams (catch-all).
                let type_code = attr_header.type_code;
                let attr_name = if attr_header.name_length > 0 {
                    let name_offset = offset + usize::from(attr_header.name_offset);
                    let name_len = usize::from(attr_header.name_length);
                    if name_offset + name_len * 2 <= data.len() {
                        let name_bytes = &data[name_offset..name_offset + name_len * 2];
                        let name_u16: smallvec::SmallVec<[u16; 64]> = name_bytes
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|chunk| u16::from_le_bytes(*chunk))
                            .collect();
                        String::from_utf16(&name_u16).unwrap_or_default()
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                let (size, allocated_size, is_resident) = if attr_header.is_non_resident == 0 {
                    let value_length = u64::from(u32::from_le_bytes(
                        data.get(offset + 16..offset + 20)
                            .and_then(|b| b.try_into().ok())
                            .unwrap_or([0; 4]),
                    ));
                    (value_length, 0_u64, true)
                } else {
                    let nr_offset = offset + 16;
                    if nr_offset + 48 <= data.len() {
                        let allocated = i64::from_le_bytes(
                            data[nr_offset + 24..nr_offset + 32]
                                .try_into()
                                .unwrap_or([0; 8]),
                        );
                        let data_size = i64::from_le_bytes(
                            data[nr_offset + 32..nr_offset + 40]
                                .try_into()
                                .unwrap_or([0; 8]),
                        );
                        (nonneg_to_u64(data_size), nonneg_to_u64(allocated), false)
                    } else {
                        (0_u64, 0_u64, false)
                    }
                };
                let stream_name = if attr_name.is_empty() {
                    format!("$UNKNOWN_0x{type_code:X}")
                } else {
                    attr_name
                };
                streams.push(StreamInfo {
                    name: stream_name,
                    size,
                    allocated_size,
                    is_sparse: false,
                    is_compressed: false,
                    is_resident,
                });
            }
        }
        offset += attr_header.length as usize;
    }

    ParseResult::Extension(ExtensionAttributes {
        base_frs: crate::frs::Frs::new(base_frs_value),
        extension_frs: crate::frs::Frs::new(frs),
        names,
        streams,
        dir_index_size,
        dir_index_allocated,
    })
}
