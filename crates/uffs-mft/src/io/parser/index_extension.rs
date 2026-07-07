// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Extension record parser for direct-to-index path.
//!
//! Exception: This file is intentionally large (720+ LOC) to match the
//! completeness of `index.rs` - it handles all the same attribute types that
//! can appear in extension records. See `scripts/ci/file_size_exceptions.txt`.
//!
//! This module handles extension records for the single-pass parser, extracting
//! names, streams, and all attribute types from extension records and merging
//! them into base records in the index.
//!
//! # Hardening (WI-5.2)
//! This module parses **untrusted on-disk bytes**. Every offset/length derived
//! from those bytes is combined with `checked_add`/`checked_mul` (or
//! `saturating_*` where overflow is provably unreachable) and every slice into
//! `data` goes through `.get()` / the `rd_u*` helpers — never `data[a..b]`
//! indexing. The daemon builds with `panic = "abort"`, so a single parser panic
//! on a malformed record would be a whole-process denial of service.
//! `arithmetic_side_effects` is enabled module-wide as a regression guard: any
//! new raw `+`/`*` on a byte-derived value is a compile error here.
#![warn(clippy::arithmetic_side_effects)]

use core::mem::size_of;

use smallvec::SmallVec;
use zerocopy::FromBytes as _;

use crate::index::{frs_to_usize, len_to_u16, len_to_u32, u32_as_usize};

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
#[expect(
    clippy::indexing_slicing,
    reason = "the only `[]` indexing that remains is into internal arena vectors \
              (index.records / index.links / index.streams / index.internal_streams / \
              index.frs_to_idx) whose indices are produced by this code, not by untrusted \
              on-disk bytes. All reads of the untrusted `data` slice go through `.get()` / \
              the `rd_u*` helpers (WI-5.2)"
)]
pub(super) fn parse_extension_to_index(
    data: &[u8],
    base_frs: u64,
    index: &mut crate::index::MftIndex,
) -> bool {
    use crate::index::{ChildInfo, IndexNameRef, IndexStreamInfo, LinkInfo, NO_ENTRY, SizeInfo};
    use crate::ntfs::{
        AttributeRecordHeader, AttributeType, FileNameAttribute, FileRecordSegmentHeader,
    };

    if data.len() < size_of::<FileRecordSegmentHeader>() {
        return false;
    }

    let Ok((header, _)) = FileRecordSegmentHeader::read_from_prefix(data) else {
        return false;
    };

    // Parse attributes to find $FILE_NAME and $DATA
    let mut offset = usize::from(header.first_attribute_offset);
    let max_offset = core::cmp::min(u32_as_usize(header.bytes_in_use), data.len());

    // Collect names and streams from extension record
    let mut names: SmallVec<[(String, u64); 4]> = SmallVec::new();
    // User-visible ADS only
    let mut streams: SmallVec<[(String, u64, u64); 4]> = SmallVec::new();
    // Internal NTFS streams (for tree-metrics accounting)
    let mut ext_internal_streams: SmallVec<[(u64, u64); 4]> = SmallVec::new();
    let mut dir_index_size: u64 = 0;
    let mut dir_index_allocated: u64 = 0;
    // Default $DATA stream (unnamed, name_len == 0) found in extension record
    let mut default_data_size: u64 = 0;
    let mut default_data_allocated: u64 = 0;
    let mut found_default_data = false;

    while offset
        .checked_add(size_of::<AttributeRecordHeader>())
        .is_some_and(|end| end <= max_offset)
    {
        let Some(attr_slice) = data.get(offset..) else {
            break;
        };
        let Ok((attr_header, _)) = AttributeRecordHeader::read_from_prefix(attr_slice) else {
            break;
        };

        if attr_header.type_code == AttributeType::END_MARKER {
            break;
        }

        // `offset + length` can overflow on a crafted `length`; checked_add → break.
        let Some(attr_end) = offset.checked_add(u32_as_usize(attr_header.length)) else {
            break;
        };
        if attr_header.length == 0 || attr_end > max_offset {
            break;
        }

        let attr_type = AttributeType::from_u32(attr_header.type_code);
        match attr_type {
            Some(AttributeType::FileName) => {
                // Parse $FILE_NAME attribute
                if attr_header.is_non_resident == 0 {
                    let value_offset = usize::from(rd_u16(data, offset.saturating_add(20)));
                    // `offset + value_offset` is byte-derived; checked, then re-validated
                    // by the `.get()` below.
                    if let Some(fn_offset) = offset.checked_add(value_offset)
                        && let Some(fn_slice) = fn_offset
                            .checked_add(size_of::<FileNameAttribute>())
                            .filter(|end| *end <= data.len())
                            .and_then(|_| data.get(fn_offset..))
                    {
                        let Ok((fn_attr, _)) = FileNameAttribute::read_from_prefix(fn_slice) else {
                            break;
                        };

                        // Skip DOS-only names (namespace 2)
                        if fn_attr.file_name_namespace != 2 {
                            let name_len = usize::from(fn_attr.file_name_length);
                            let name_start =
                                fn_offset.saturating_add(size_of::<FileNameAttribute>());
                            // `name_len * 2` (UTF-16) overflows on a crafted length →
                            // checked_mul/checked_add, then `.get()` bounds the slice.
                            if let Some(name_bytes) = name_len
                                .checked_mul(2)
                                .and_then(|byte_len| name_start.checked_add(byte_len))
                                .and_then(|end| data.get(name_start..end))
                            {
                                let name_u16: SmallVec<[u16; 64]> = name_bytes
                                    .as_chunks::<2>()
                                    .0
                                    .iter()
                                    .map(|pair| u16::from_le_bytes(*pair))
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
                let is_primary = nr_is_primary(data, attr_header.is_non_resident, offset);

                if !is_primary {
                    // Skip continuation extents - they don't count as new streams
                    offset = offset.saturating_add(u32_as_usize(attr_header.length));
                    continue;
                }

                // Parse $DATA attribute — default stream (unnamed) or ADS (named)
                let name_len = usize::from(attr_header.name_length);
                let (size, allocated) = if attr_header.is_non_resident != 0 {
                    // `rd_u*` are individually bounds-safe (return 0 OOB); the
                    // `nr + 48 <= len` guard preserves the original "all fields
                    // present" semantics. `nr` via checked_add.
                    offset
                        .checked_add(16)
                        .filter(|nr| nr.saturating_add(48) <= data.len())
                        .map_or((0, 0), |nr_offset| {
                            // Check if compressed or sparse
                            let is_compressed_or_sparse = (attr_header.flags & 0x8001) != 0;
                            let compression_unit = rd_u16(data, nr_offset.saturating_add(18));
                            let has_compression_unit = compression_unit > 0;

                            let use_compressed_size =
                                is_compressed_or_sparse || has_compression_unit;
                            // offset + 64
                            let compressed_size_offset = nr_offset.saturating_add(48);

                            // Preserve original fallback: only read CompressedSize
                            // when its 8-byte field is fully in bounds; otherwise
                            // read AllocatedLength.
                            let allocated = if use_compressed_size
                                && compressed_size_offset.saturating_add(8) <= data.len()
                            {
                                // Read CompressedSize for compressed/sparse files
                                rd_u64(data, compressed_size_offset).cast_signed()
                            } else {
                                // Read AllocatedLength for normal files
                                rd_u64(data, nr_offset.saturating_add(24)).cast_signed()
                            };

                            let size = rd_u64(data, nr_offset.saturating_add(32)).cast_signed();
                            (
                                size.max(0).cast_unsigned(),
                                allocated.max(0).cast_unsigned(),
                            )
                        })
                } else {
                    (u64::from(rd_u32(data, offset.saturating_add(16))), 0)
                };

                if name_len == 0 {
                    // Default $DATA stream — update base record size
                    // Mark that unnamed $DATA exists on the base record
                    // (distinguishes "empty $DATA" from "no $DATA")
                    {
                        let bf = frs_to_usize(base_frs);
                        if bf < index.frs_to_idx.len() {
                            let base_idx = index.frs_to_idx[bf];
                            if base_idx != NO_ENTRY {
                                index.records[u32_as_usize(base_idx)].set_has_default_data();
                            }
                        }
                    }
                    default_data_size = size;
                    default_data_allocated = allocated;
                    found_default_data = true;
                } else {
                    // ADS (named stream)
                    let name_offset = offset.saturating_add(usize::from(attr_header.name_offset));
                    if let Some(name_bytes) = read_name_bytes(data, name_offset, name_len) {
                        let name_u16: SmallVec<[u16; 64]> = name_bytes
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|pair| u16::from_le_bytes(*pair))
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
                let (rp_size, rp_allocated) =
                    read_attr_size(data, attr_header.is_non_resident, offset);
                ext_internal_streams.push((rp_size, rp_allocated));
            }
            Some(
                AttributeType::IndexRoot | AttributeType::IndexAllocation | AttributeType::Bitmap,
            ) => {
                // Extract attribute name
                let name_len = usize::from(attr_header.name_length);
                let (is_i30, _attr_name) = if name_len > 0 {
                    let name_offset = offset.saturating_add(usize::from(attr_header.name_offset));
                    read_name_bytes(data, name_offset, name_len).map_or_else(
                        || (false, String::new()),
                        |name_bytes| {
                            let is_i30 = attr_header.name_length == 4
                                && name_bytes == b"$\x00I\x003\x000\x00";
                            let name = if is_i30 {
                                String::new()
                            } else {
                                let name_u16: SmallVec<[u16; 64]> = name_bytes
                                    .as_chunks::<2>()
                                    .0
                                    .iter()
                                    .map(|pair| u16::from_le_bytes(*pair))
                                    .collect();
                                crate::io::parser::unified::decode_name_u16(&name_u16).0
                            };
                            (is_i30, name)
                        },
                    )
                } else {
                    (false, String::new())
                };

                if is_i30 {
                    // Accumulate $I30 sizes
                    if attr_header.is_non_resident == 0 {
                        let value_length = u64::from(rd_u32(data, offset.saturating_add(16)));
                        // Disk-derived accumulator; saturate to avoid overflow panic.
                        dir_index_size = dir_index_size.saturating_add(value_length);
                    } else if let Some(nr_offset) = offset
                        .checked_add(16)
                        .filter(|nr| nr.saturating_add(48) <= data.len())
                    {
                        let allocated = rd_u64(data, nr_offset.saturating_add(24)).cast_signed();
                        let data_size = rd_u64(data, nr_offset.saturating_add(32)).cast_signed();
                        // Disk-derived accumulators; saturate to avoid overflow panic.
                        dir_index_size =
                            dir_index_size.saturating_add(data_size.max(0).cast_unsigned());
                        dir_index_allocated =
                            dir_index_allocated.saturating_add(allocated.max(0).cast_unsigned());
                    }
                } else {
                    // Non-$I30 index — internal stream for tree metrics
                    if nr_is_primary(data, attr_header.is_non_resident, offset) {
                        let (size, allocated) =
                            read_attr_size(data, attr_header.is_non_resident, offset);
                        ext_internal_streams.push((size, allocated));
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
                if nr_is_primary(data, attr_header.is_non_resident, offset) {
                    let (size, allocated) =
                        read_attr_size(data, attr_header.is_non_resident, offset);
                    ext_internal_streams.push((size, allocated));
                }
            }
            Some(AttributeType::StandardInformation) => {
                // Skip - not expected in extension records
            }
            _ => {
                // Unknown attribute types — counted as streams (catch-all).
                if nr_is_primary(data, attr_header.is_non_resident, offset) {
                    let (size, allocated) =
                        read_attr_size(data, attr_header.is_non_resident, offset);
                    ext_internal_streams.push((size, allocated));
                }
            }
        }

        // Disk-derived advance; saturate so a crafted length can't overflow.
        offset = offset.saturating_add(u32_as_usize(attr_header.length));
    }

    // If no names, user-visible streams, internal streams, default data, or
    // directory index sizes found, nothing to do
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
    let mut link_indices: Vec<u32> = Vec::with_capacity(names.len());
    for (name, parent_frs) in &names {
        let name_offset = index.add_name(name);
        let name_len = name.len();
        let is_ascii = name.is_ascii();
        let extension_id = index.intern_extension(name);
        let name_ref = IndexNameRef::new(name_offset, len_to_u16(name_len), is_ascii, extension_id);

        let link_idx = len_to_u32(index.links.len());
        index.links.push(LinkInfo {
            next_entry: NO_ENTRY,
            name: name_ref,
            _pad0: [0; 4],
            // Typed `ParentFrs` slot — lift parser-local raw `u64`.
            parent_frs: crate::frs::ParentFrs::new(*parent_frs),
        });
        link_indices.push(link_idx);
    }

    // Add streams to the streams buffer
    let mut stream_indices: Vec<u32> = Vec::with_capacity(streams.len());
    for (stream_name, size, allocated) in &streams {
        let name_offset = index.add_name(stream_name);
        let name_len = stream_name.len();
        let is_ascii = stream_name.is_ascii();
        let extension_id = index.intern_extension(stream_name);
        let name_ref = IndexNameRef::new(name_offset, len_to_u16(name_len), is_ascii, extension_id);

        let stream_idx = len_to_u32(index.streams.len());
        index.streams.push(IndexStreamInfo {
            size: SizeInfo {
                length: *size,
                allocated: *allocated,
            },
            next_entry: NO_ENTRY,
            name: name_ref,
            flags: 8_u8 << 2_u8,
            _pad0: [0; 3],
        });
        stream_indices.push(stream_idx);
    }

    // Ensure parent directories exist for the new names.  Boundary: lift
    // parser-local raw `u64` to typed `Frs` at the typed-API call site.
    for (_, parent_frs) in &names {
        if *parent_frs != base_frs && *parent_frs != 0 {
            index.get_or_create(crate::frs::Frs::new(*parent_frs));
            // ^ side effect: ensures parent placeholder exists
        }
    }

    // Get the base record and add the names/streams to it
    let base_frs_usize = frs_to_usize(base_frs);
    if base_frs_usize >= index.frs_to_idx.len() {
        // Base record doesn't exist yet — create a placeholder
        index.get_or_create(crate::frs::Frs::new(base_frs));
    }

    let record_idx = index.frs_to_idx[base_frs_usize];
    if record_idx == NO_ENTRY {
        // Base record doesn't exist — create it
        index.get_or_create(crate::frs::Frs::new(base_frs));
    }

    // Now get the record and chain the new links/streams
    let base_idx = index.frs_to_idx[base_frs_usize];
    if base_idx != NO_ENTRY {
        // Snapshot fields from the record before any re-borrowing
        let (pre_chain_name_count, has_valid_name, first_name_next, first_stream_next) = {
            let rec = &index.records[u32_as_usize(base_idx)];
            (
                rec.name_count,
                rec.first_name.name.is_valid(),
                rec.first_name.next_entry,
                rec.first_stream.next_entry,
            )
        };

        // Add new links to the record
        if !link_indices.is_empty() {
            // Check if base record has no name (first_name is empty)
            // This happens when the $FILE_NAME attribute is ONLY in extension records
            if has_valid_name {
                // Base record already has a name — chain extension names as additional hard
                // links. Find the end of the current link chain.
                let last_link_idx = if first_name_next == NO_ENTRY {
                    None
                } else {
                    let mut idx = first_name_next;
                    while index.links[u32_as_usize(idx)].next_entry != NO_ENTRY {
                        idx = index.links[u32_as_usize(idx)].next_entry;
                    }
                    Some(idx)
                };

                // Chain the new links together
                for pair in link_indices.windows(2) {
                    if let [current, next] = *pair {
                        index.links[u32_as_usize(current)].next_entry = next;
                    }
                }

                // Attach to the chain
                if let Some(last_idx) = last_link_idx {
                    index.links[u32_as_usize(last_idx)].next_entry = link_indices[0];
                } else {
                    // first_name has no next_entry, attach directly
                    let rec_link = &mut index.records[u32_as_usize(base_idx)];
                    rec_link.first_name.next_entry = link_indices[0];
                }

                // Update name count (bounded internal counter; saturate).
                let rec_name_count = &mut index.records[u32_as_usize(base_idx)];
                rec_name_count.name_count = rec_name_count
                    .name_count
                    .saturating_add(len_to_u16(link_indices.len()));
            } else {
                // Copy the first extension name directly into first_name
                // This matches established behavior (ntfs_index.hpp lines 559-567)
                let first_link_name = index.links[u32_as_usize(link_indices[0])].name;
                let first_link_parent = index.links[u32_as_usize(link_indices[0])].parent_frs;
                let rec_first = &mut index.records[u32_as_usize(base_idx)];
                rec_first.first_name.name = first_link_name;
                rec_first.first_name.parent_frs = first_link_parent;
                // Don't increment name_count for the first name (it's already counted as 1)

                // Chain remaining links (if any) to first_name.next_entry
                if link_indices.len() > 1 {
                    // Chain the remaining links together (links[1..]); link 0 was
                    // copied into first_name above and is not chained from.
                    if let Some(rest) = link_indices.get(1..) {
                        for pair in rest.windows(2) {
                            if let [current, next] = *pair {
                                index.links[u32_as_usize(current)].next_entry = next;
                            }
                        }
                    }
                    // Attach remaining links to first_name
                    let rec_extra = &mut index.records[u32_as_usize(base_idx)];
                    rec_extra.first_name.next_entry = link_indices[1];
                    // Update name count for additional links only (saturate).
                    rec_extra.name_count = rec_extra
                        .name_count
                        .saturating_add(len_to_u16(link_indices.len().saturating_sub(1)));
                }
            }
        }

        // Chain new streams to the end of the existing stream chain
        if !stream_indices.is_empty() {
            // Find the end of the current stream chain (using snapshot)
            let last_stream_idx = if first_stream_next == NO_ENTRY {
                None
            } else {
                let mut idx = first_stream_next;
                while index.streams[u32_as_usize(idx)].next_entry != NO_ENTRY {
                    idx = index.streams[u32_as_usize(idx)].next_entry;
                }
                Some(idx)
            };

            // Chain the new streams together
            for pair in stream_indices.windows(2) {
                if let [current, next] = *pair {
                    index.streams[u32_as_usize(current)].next_entry = next;
                }
            }

            // Attach to the chain
            if let Some(last_idx) = last_stream_idx {
                index.streams[u32_as_usize(last_idx)].next_entry = stream_indices[0];
            } else {
                // first_stream has no next_entry, attach directly
                let rec_stream_attach = &mut index.records[u32_as_usize(base_idx)];
                rec_stream_attach.first_stream.next_entry = stream_indices[0];
            }

            // Update stream count (user-visible only; bounded counters, saturate).
            let rec_stream_count = &mut index.records[u32_as_usize(base_idx)];
            let stream_added = len_to_u16(stream_indices.len());
            rec_stream_count.stream_count =
                rec_stream_count.stream_count.saturating_add(stream_added);
            rec_stream_count.total_stream_count = rec_stream_count
                .total_stream_count
                .saturating_add(stream_added);
        }

        // Build internal stream chain for extension record attributes
        if !ext_internal_streams.is_empty() {
            let rec_internal = &mut index.records[u32_as_usize(base_idx)];

            // Find end of existing internal stream chain
            let last_internal_idx = if rec_internal.first_internal_stream == NO_ENTRY {
                None
            } else {
                let mut idx = rec_internal.first_internal_stream;
                while index.internal_streams[u32_as_usize(idx)].next_entry != NO_ENTRY {
                    idx = index.internal_streams[u32_as_usize(idx)].next_entry;
                }
                Some(idx)
            };

            let mut first_new_internal = NO_ENTRY;
            let mut prev_internal = NO_ENTRY;
            for (ist_size, ist_allocated) in &ext_internal_streams {
                rec_internal.internal_streams_size =
                    rec_internal.internal_streams_size.saturating_add(*ist_size);
                rec_internal.internal_streams_allocated = rec_internal
                    .internal_streams_allocated
                    .saturating_add(*ist_allocated);

                let new_idx = len_to_u32(index.internal_streams.len());
                index
                    .internal_streams
                    .push(crate::index::InternalStreamInfo {
                        size: SizeInfo {
                            length: *ist_size,
                            allocated: *ist_allocated,
                        },
                        next_entry: NO_ENTRY,
                        flags: 0,
                    });

                if first_new_internal == NO_ENTRY {
                    first_new_internal = new_idx;
                }
                if prev_internal != NO_ENTRY {
                    index.internal_streams[u32_as_usize(prev_internal)].next_entry = new_idx;
                }
                prev_internal = new_idx;
            }

            // Attach to existing chain or set as head
            if let Some(last_idx) = last_internal_idx {
                index.internal_streams[u32_as_usize(last_idx)].next_entry = first_new_internal;
            } else {
                let rec_head = &mut index.records[u32_as_usize(base_idx)];
                rec_head.first_internal_stream = first_new_internal;
            }

            // Update total_stream_count to include new internal streams (saturate).
            let rec_total = &mut index.records[u32_as_usize(base_idx)];
            rec_total.total_stream_count = rec_total
                .total_stream_count
                .saturating_add(len_to_u16(ext_internal_streams.len()));
        }

        // Merge default $DATA stream from extension record into base record.
        // This handles files whose $DATA attribute doesn't fit in the base MFT
        // record (e.g., large files with extensive run lists).
        if found_default_data {
            let rec_data = &mut index.records[u32_as_usize(base_idx)];
            // Ensure has_default_data bit is set (may not have been set
            // earlier if the base record didn't exist at attribute-parse time)
            rec_data.set_has_default_data();

            // If base record has no $DATA (both fields are 0), use extension's $DATA.
            // Otherwise, accumulate extension $DATA to base $DATA.
            if rec_data.first_stream.size.length == 0 && rec_data.first_stream.size.allocated == 0 {
                // Base has no $DATA — use extension's values
                rec_data.first_stream.size.length = default_data_size;
                rec_data.first_stream.size.allocated = default_data_allocated;
            } else {
                // Base has partial $DATA — accumulate extension values
                rec_data.first_stream.size.length = rec_data
                    .first_stream
                    .size
                    .length
                    .saturating_add(default_data_size);
                rec_data.first_stream.size.allocated = rec_data
                    .first_stream
                    .size
                    .allocated
                    .saturating_add(default_data_allocated);
            }
        }

        // Merge directory index sizes from extension records
        if dir_index_size > 0 || dir_index_allocated > 0 {
            let rec_dir = &mut index.records[u32_as_usize(base_idx)];
            // Add to the first_stream size (which represents the default stream for
            // directories). Disk-derived sizes; saturate to avoid overflow panic.
            rec_dir.first_stream.size.length = rec_dir
                .first_stream
                .size
                .length
                .saturating_add(dir_index_size);
            rec_dir.first_stream.size.allocated = rec_dir
                .first_stream
                .size
                .allocated
                .saturating_add(dir_index_allocated);
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
                    // `p_frs` is masked to 48 bits, so `+ 1` cannot overflow usize on
                    // 64-bit; saturate defensively to keep arithmetic panic-free.
                    index
                        .frs_to_idx
                        .resize(p_frs_usize.saturating_add(1), NO_ENTRY);
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
            //
            // FIX: The off-by-one bug was here. Extension names are appended AFTER
            // existing names, so the index should be existing_name_count + name_idx,
            // not existing_name_count - 1 + name_idx.
            //
            // Example: base has 1 name (index 0), extension adds 1 name
            //   - existing_name_count = 1
            //   - name_idx = 0 (first extension name)
            //   - effective_name_idx should be 1 (the second name overall)
            let effective_name_idx = if existing_name_count == 0 {
                // First extension name became first_name, so name_index starts at 0
                len_to_u16(name_idx)
            } else {
                // Extension names are appended after existing names (bounded u16
                // name-index counter; saturate).
                existing_name_count.saturating_add(len_to_u16(name_idx))
            };

            let child_idx = len_to_u32(index.children.len());
            let parent = &mut index.records[u32_as_usize(parent_idx)];
            let old_first_child = parent.first_child;
            parent.first_child = child_idx;

            index.children.push(ChildInfo {
                next_entry: old_first_child,
                _pad0: [0; 4],
                // Typed `Frs` slot — lift parser-local raw `u64`.
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

// ── Helpers (untrusted-byte readers, WI-5.2) ────────────────────────────────

/// Read a little-endian `u16` from `buf` at `off`, returning 0 if the 2-byte
/// field is out of bounds.
#[inline]
fn rd_u16(buf: &[u8], off: usize) -> u16 {
    off.checked_add(2)
        .and_then(|end| buf.get(off..end))
        .and_then(|sl| <[u8; 2]>::try_from(sl).ok())
        .map_or(0, u16::from_le_bytes)
}

/// Read a little-endian `u32` from `buf` at `off`, returning 0 if the 4-byte
/// field is out of bounds.
#[inline]
fn rd_u32(buf: &[u8], off: usize) -> u32 {
    off.checked_add(4)
        .and_then(|end| buf.get(off..end))
        .and_then(|sl| <[u8; 4]>::try_from(sl).ok())
        .map_or(0, u32::from_le_bytes)
}

/// Read a little-endian `u64` from `buf` at `off`, returning 0 if the 8-byte
/// field is out of bounds.
#[inline]
fn rd_u64(buf: &[u8], off: usize) -> u64 {
    off.checked_add(8)
        .and_then(|end| buf.get(off..end))
        .and_then(|sl| <[u8; 8]>::try_from(sl).ok())
        .map_or(0, u64::from_le_bytes)
}

/// Determine whether a non-resident attribute is a *primary* extent
/// (`LowestVCN == 0`); resident attributes are always primary.
///
/// Mirrors the original guarded read: when the 8-byte `LowestVCN` field is out
/// of bounds the attribute is treated as non-primary ("can't verify, skip to be
/// safe").
#[inline]
fn nr_is_primary(data: &[u8], is_non_resident: u8, offset: usize) -> bool {
    if is_non_resident == 0 {
        return true;
    }
    offset
        .checked_add(16)
        .filter(|nr| nr.saturating_add(8) <= data.len())
        .is_some_and(|nr_offset| rd_u64(data, nr_offset).cast_signed() == 0)
}

/// Read the `(size, allocated)` pair for an attribute, mirroring the original
/// per-branch logic exactly:
/// - resident: `(ValueLength @ offset+16 as u32, 0)`
/// - non-resident: only when the 48-byte non-resident header is fully present,
///   `(DataSize @ +32, AllocatedSize @ +24)` clamped to `>= 0`; otherwise `(0,
///   0)`.
#[inline]
fn read_attr_size(data: &[u8], is_non_resident: u8, offset: usize) -> (u64, u64) {
    if is_non_resident == 0 {
        return (u64::from(rd_u32(data, offset.saturating_add(16))), 0);
    }
    offset
        .checked_add(16)
        .filter(|nr| nr.saturating_add(48) <= data.len())
        .map_or((0, 0), |nr_offset| {
            let allocated = rd_u64(data, nr_offset.saturating_add(24)).cast_signed();
            let data_size = rd_u64(data, nr_offset.saturating_add(32)).cast_signed();
            (
                data_size.max(0).cast_unsigned(),
                allocated.max(0).cast_unsigned(),
            )
        })
}

/// Return the `name_len * 2` UTF-16 name bytes starting at `name_offset`, or
/// `None` if the (byte-derived) range overflows or lies outside `data`.
#[inline]
fn read_name_bytes(data: &[u8], name_offset: usize, name_len: usize) -> Option<&[u8]> {
    name_len
        .checked_mul(2)
        .and_then(|byte_len| name_offset.checked_add(byte_len))
        .and_then(|end| data.get(name_offset..end))
}
