// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Single-pass direct-to-index parser.
//!
//! Exception: Core MFT record parser with unified parse_record_to_index and
//! forensic mode. This is the performance-critical hot path.
//!
//! This module implements the high-performance single-pass parser that matches
//! an `MftIndex` directly from raw MFT bytes. It parses records into `MftIndex`
//! without creating intermediate `ParsedRecord` allocations, which is critical
//! for IOCP performance.
//!
//! # Hardening (WI-5.2)
//! This module parses **untrusted on-disk bytes**. Every offset/length
//! derived from those bytes is combined with `checked_add`/`checked_mul`
//! (or `saturating_*` where overflow is provably unreachable) and every
//! slice into `data` goes through `.get()` / the `rd_u*` helpers — never
//! `data[a..b]` indexing. The daemon builds with `panic = "abort"`, so a
//! single parser panic on a malformed record would be a whole-process
//! denial of service.
//! `arithmetic_side_effects` is enabled module-wide as a regression guard:
//! any new raw `+`/`*` on a byte-derived value is a compile error here.
#![warn(clippy::arithmetic_side_effects)]
// Performance-critical hot-path parser — minimal, scoped lint suppressions.
// Each suppression is justified with a reason.
#![expect(
    clippy::doc_markdown,
    reason = "NTFS terminology like WoF, MftIndex does not need backticks"
)]
#![expect(
    clippy::manual_let_else,
    reason = "explicit match is clearer in NTFS attribute dispatch"
)]
#![expect(
    clippy::single_match_else,
    reason = "explicit match arms are clearer for attribute type dispatch"
)]
use core::mem::size_of;

use smallvec::SmallVec;
use zerocopy::FromBytes as _;

use super::index_extension::parse_extension_to_index;
use crate::index::{len_to_u16, nonneg_to_u64, u32_as_usize};
use crate::parse::index_helpers::{
    ExtensionSnapshot, InternalStreamChain, add_child_entry, add_link_to_index,
    add_stream_to_index, build_internal_stream_chain, chain_links, chain_streams,
    merge_extension_names, merge_extension_streams,
};

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
#[expect(
    clippy::indexing_slicing,
    reason = "remaining [] are internal arena indices (index.records[..]/stream_indices[..]/\
              link_indices[..]) keyed by indices minted by this fn; not attacker-controlled. \
              All untrusted-`data` reads go through .get()/rd_u* (WI-5.2)."
)]
pub fn parse_record_to_index(data: &[u8], frs: u64, index: &mut crate::index::MftIndex) -> bool {
    use crate::index::{IndexNameRef, LinkInfo, NO_ENTRY, SizeInfo, StandardInfo};
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
    // User-visible ADS: (stream_name, size, allocated)
    let mut additional_streams: SmallVec<[(String, u64, u64); 4]> = SmallVec::new();
    // Internal NTFS streams (e.g. $REPARSE, $EA, $OBJECT_ID) — not emitted as
    // output rows but still tracked for tree-metrics accounting.
    // (size, allocated)
    let mut internal_streams: SmallVec<[(u64, u64); 4]> = SmallVec::new();
    let mut reparse_tag: u32 = 0;
    let mut dir_index_size: u64 = 0;
    let mut dir_index_allocated: u64 = 0;

    // WI-5.2: every offset advance and slice below is derived from
    // attacker-controllable record bytes, so all arithmetic uses
    // `checked_*` and all slicing uses `data.get(..)` (fallible) — a
    // malformed record `break`s the loop / skips the field instead of
    // panicking. The daemon runs `panic = "abort"`, so a parser panic is a
    // whole-process DoS.
    while offset
        .checked_add(size_of::<AttributeRecordHeader>())
        .is_some_and(|end| end <= max_offset)
    {
        let Some(attr_slice) = data.get(offset..) else {
            break;
        };
        let attr_header = match AttributeRecordHeader::read_from_prefix(attr_slice) {
            Ok((attr_header, _)) => attr_header,
            Err(_) => break,
        };

        if attr_header.type_code == AttributeType::END_MARKER {
            break;
        }

        let attr_len = u32_as_usize(attr_header.length);
        let attr_end = offset.checked_add(attr_len);
        if attr_header.length == 0 || attr_end.is_none_or(|end| end > max_offset) {
            break;
        }

        // Validate that the attribute's declared length fits within the record data
        // This prevents reading past record boundaries when attributes are truncated
        if attr_end.is_none_or(|end| end > data.len()) {
            break; // Attribute extends past record — stop processing
        }

        let attr_type = AttributeType::from_u32(attr_header.type_code);
        match attr_type {
            Some(AttributeType::StandardInformation) => {
                if attr_header.is_non_resident == 0 {
                    // Parse $STANDARD_INFORMATION
                    let value_offset = usize::from(rd_u16(data, offset.saturating_add(20)));
                    if let Some(si_slice) = offset
                        .checked_add(value_offset)
                        .filter(|si_off| {
                            si_off.saturating_add(size_of::<StandardInformation>()) <= data.len()
                        })
                        .and_then(|si_off| data.get(si_off..))
                    {
                        let si = match StandardInformation::read_from_prefix(si_slice) {
                            Ok((si, _)) => si,
                            Err(_) => break,
                        };
                        // Two-step canonical approach:
                        // 1. Parse raw attrs to ExtendedStandardInfo (complete parsing)
                        // 2. Convert to compact StandardInfo (single source of truth)
                        let ext =
                            crate::ntfs::ExtendedStandardInfo::from_attributes(si.file_attributes);
                        let mut info = StandardInfo::from_extended(&ext);
                        // Override timestamps from actual NTFS values
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
                    let value_offset = usize::from(rd_u16(data, offset.saturating_add(20)));
                    let fn_offset = offset.checked_add(value_offset);
                    if let Some(fn_slice) = fn_offset
                        .filter(|fn_off| {
                            fn_off.saturating_add(size_of::<FileNameAttribute>()) <= data.len()
                        })
                        .and_then(|fn_off| data.get(fn_off..))
                        && let Some(fn_off) = fn_offset
                    {
                        let fn_attr = match FileNameAttribute::read_from_prefix(fn_slice) {
                            Ok((fn_attr, _)) => fn_attr,
                            Err(_) => break,
                        };
                        let name_len = usize::from(fn_attr.file_name_length);
                        let name_bytes_offset =
                            fn_off.saturating_add(size_of::<FileNameAttribute>());
                        // `name_len` is a u16 (<= 65535); `*2` and `+ offset` use
                        // checked form so the parser is provably total, and let
                        // `data.get(..)` do the bounds check (None on a
                        // declared-length that overruns the record → skip name).
                        if let Some(name_bytes) = name_len
                            .checked_mul(2)
                            .and_then(|byte_len| name_bytes_offset.checked_add(byte_len))
                            .and_then(|name_end| data.get(name_bytes_offset..name_end))
                        {
                            // SmallVec avoids heap allocation for typical filenames (<= 64 chars)
                            let name_u16: SmallVec<[u16; 64]> = name_bytes
                                .as_chunks::<2>()
                                .0
                                .iter()
                                .map(|pair| u16::from_le_bytes(*pair))
                                .collect();
                            let name = crate::io::parser::unified::decode_name_u16(&name_u16).0;
                            let parent_frs = file_reference_to_frs(fn_attr.parent_directory);
                            let namespace = fn_attr.file_name_namespace;

                            // Skip DOS-only names (namespace 2)
                            if namespace != 2 {
                                let parse_idx = name_parse_counter;
                                // Monotonic name counter; one $FILE_NAME per record
                                // iteration, bounded by record size — cannot overflow u16.
                                name_parse_counter = name_parse_counter.saturating_add(1);
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
                    // Assume primary if can't read LowestVCN (None → true).
                    offset
                        .checked_add(16)
                        .and_then(|nr| nr.checked_add(8).and_then(|end| data.get(nr..end)))
                        .and_then(|sl| <[u8; 8]>::try_from(sl).ok())
                        .is_none_or(|bytes| i64::from_le_bytes(bytes) == 0)
                };

                if !is_primary {
                    // Skip continuation extents - they don't count as new streams
                    offset = offset.saturating_add(u32_as_usize(attr_header.length));
                    continue;
                }

                // Parse $DATA - track both default stream and ADS
                let name_len = usize::from(attr_header.name_length);
                let (size, allocated) = if attr_header.is_non_resident != 0 {
                    // Non-resident: size at offset 48, allocated at offset 40
                    // For compressed/sparse files, use CompressedSize at offset 64
                    let nr_offset = offset.saturating_add(16);
                    let alloc_offset = offset.saturating_add(40);
                    let size_offset = offset.saturating_add(48);
                    if size_offset.saturating_add(8) <= data.len() {
                        // Check if compressed or sparse
                        let is_compressed_or_sparse = (attr_header.flags & 0x8001) != 0;
                        let compression_unit = rd_u16(data, nr_offset.saturating_add(18));
                        let has_compression_unit = compression_unit > 0;

                        let use_compressed_size = is_compressed_or_sparse || has_compression_unit;
                        let compressed_size_offset = nr_offset.saturating_add(48); // offset + 64

                        let allocated = if use_compressed_size
                            && compressed_size_offset.saturating_add(8) <= data.len()
                        {
                            // Read CompressedSize for compressed/sparse files
                            rd_u64(data, compressed_size_offset)
                        } else {
                            // Read AllocatedLength for normal files
                            rd_u64(data, alloc_offset)
                        };

                        let size = rd_u64(data, size_offset);
                        (size, allocated)
                    } else if alloc_offset.saturating_add(8) <= data.len() {
                        // Can read AllocatedSize but not DataSize — use AllocatedSize for both
                        let allocated = rd_u64(data, alloc_offset);
                        (allocated, allocated)
                    } else {
                        (0, 0)
                    }
                } else {
                    // Resident: value_length at offset 16
                    let len_offset = offset.saturating_add(16);
                    if len_offset.saturating_add(4) <= data.len() {
                        let len = rd_u32(data, len_offset);
                        (u64::from(len), 0) // allocated_size = 0 for resident files
                    } else {
                        (0, 0)
                    }
                };

                if name_len == 0 {
                    // Default stream — mark that unnamed $DATA exists
                    // (distinguishes "empty $DATA" from "no $DATA").
                    // Boundary: lift parser-local raw `u64` to typed `Frs`.
                    let rec = index.get_or_create(crate::frs::Frs::new(frs));
                    rec.set_has_default_data();
                    default_size = size;
                    default_allocated = allocated;
                } else {
                    // Alternate Data Stream (ADS)
                    let name_offset = offset.saturating_add(usize::from(attr_header.name_offset));
                    if let Some(name_bytes) = name_len
                        .checked_mul(2)
                        .and_then(|byte_len| name_offset.checked_add(byte_len))
                        .and_then(|name_end| data.get(name_offset..name_end))
                    {
                        let name_u16: SmallVec<[u16; 64]> = name_bytes
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|pair| u16::from_le_bytes(*pair))
                            .collect();
                        let stream_name = crate::io::parser::unified::decode_name_u16(&name_u16).0;

                        // $BadClus:$Bad (FRS 8) uses InitializedSize
                        // instead of DataSize/AllocatedSize to avoid counting the
                        // entire volume size (ntfs_index_load.hpp lines 431-452).
                        let (stream_size, stream_alloc) = if frs == 8
                            && attr_header.name_length == 4
                            && stream_name == "$Bad"
                            && attr_header.is_non_resident != 0
                        {
                            let init_size_offset = offset.saturating_add(56);
                            if init_size_offset.saturating_add(8) <= data.len() {
                                let init_size = rd_u64(data, init_size_offset);
                                (init_size, init_size)
                            } else {
                                (0, 0)
                            }
                        } else {
                            (size, allocated)
                        };

                        // ALL named $DATA streams create regular stream entries
                        // (counted in stream_count).  Internal ones (names
                        // starting with $) are filtered from *output* by
                        // is_internal_windows_stream checks in the output layer,
                        // but must be counted here for correct descendants.
                        additional_streams.push((stream_name, stream_size, stream_alloc));
                    }
                }
            }
            Some(AttributeType::ReparsePoint) => {
                // Parse $REPARSE_POINT to get the reparse tag.
                // Both resident and non-resident forms are handled.
                // $REPARSE_POINT is counted as a stream (affects descendants).
                let (rp_size, rp_allocated) = if attr_header.is_non_resident == 0 {
                    // Resident reparse point (common case)
                    let value_length = u64::from(rd_u32(data, offset.saturating_add(16)));

                    let value_offset = usize::from(rd_u16(data, offset.saturating_add(20)));
                    if let Some(rp_offset) = offset.checked_add(value_offset) {
                        // Read reparse tag (first 4 bytes of reparse point data)
                        reparse_tag = rd_u32(data, rp_offset);
                    }
                    (value_length, 0_u64) // Resident, allocated=0
                } else {
                    // Non-resident reparse point (rare - large reparse data)
                    let nr_offset = offset.saturating_add(16);
                    if nr_offset.saturating_add(48) <= data.len() {
                        let allocated = nonneg_to_u64(rd_i64(data, nr_offset.saturating_add(24)));
                        let data_size = nonneg_to_u64(rd_i64(data, nr_offset.saturating_add(32)));
                        (data_size, allocated)
                    } else {
                        (0_u64, 0_u64)
                    }
                };

                // $REPARSE_POINT is an internal stream — tracked for tree metrics
                // but not emitted as a user-visible output row
                internal_streams.push((rp_size, rp_allocated));
            }
            Some(
                AttributeType::IndexRoot | AttributeType::IndexAllocation | AttributeType::Bitmap,
            ) => {
                // $INDEX_ROOT and $INDEX_ALLOCATION with name $I30 contribute to
                // directory size. Non-$I30 indexes are counted as individual streams.

                // Extract attribute name
                let name_len = usize::from(attr_header.name_length);
                let name_offset = offset.saturating_add(usize::from(attr_header.name_offset));
                // None when name_len == 0 or the declared length overruns the
                // record → treated as non-$I30 with an empty name (matches the
                // original guarded-out behavior).
                let name_bytes_opt = if name_len > 0 {
                    name_len
                        .checked_mul(2)
                        .and_then(|byte_len| name_offset.checked_add(byte_len))
                        .and_then(|name_end| data.get(name_offset..name_end))
                } else {
                    None
                };
                let (is_i30, _attr_name) = name_bytes_opt.map_or_else(
                    || (false, String::new()),
                    |name_bytes| {
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
                                .map(|pair| u16::from_le_bytes(*pair))
                                .collect();
                            crate::io::parser::unified::decode_name_u16(&name_u16).0
                        };
                        (is_i30, name)
                    },
                );

                if is_i30 {
                    // Accumulate $I30 sizes for directories
                    if attr_header.is_non_resident == 0 {
                        let value_length = u64::from(rd_u32(data, offset.saturating_add(16)));
                        // Directory index sizes are bounded by the volume; accumulating
                        // them cannot overflow u64 in practice — saturate to stay total.
                        dir_index_size = dir_index_size.saturating_add(value_length);
                    } else {
                        let (size, allocated) = read_nonresident_size_alloc(data, offset);
                        dir_index_size = dir_index_size.saturating_add(size);
                        dir_index_allocated = dir_index_allocated.saturating_add(allocated);
                    }
                } else {
                    // Non-$I30 index - count as stream
                    // Check if primary attribute (LowestVCN == 0)
                    if is_nonresident_primary(data, offset, &attr_header) {
                        let (size, allocated) = read_size_alloc(data, offset, &attr_header);
                        // Non-$I30 index attributes are internal streams
                        internal_streams.push((size, allocated));
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
                // All these are internal streams — tracked for tree metrics but
                // not emitted as user-visible output rows.
                // Check if primary attribute (LowestVCN == 0)
                if is_nonresident_primary(data, offset, &attr_header) {
                    let (size, allocated) = read_size_alloc(data, offset, &attr_header);
                    internal_streams.push((size, allocated));
                }
            }
            _ => {
                // Unknown attribute types are internal streams — tracked for
                // tree metrics but not emitted as user-visible output rows.
                // Check if primary attribute (LowestVCN == 0)
                if is_nonresident_primary(data, offset, &attr_header) {
                    let (size, allocated) = read_size_alloc(data, offset, &attr_header);
                    internal_streams.push((size, allocated));
                }
            }
        }

        // `attr_header.length` was validated above (`offset + length <= data.len()`),
        // so this advance cannot overflow; `saturating_add` keeps it total.
        offset = offset.saturating_add(u32_as_usize(attr_header.length));
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

            // Pre-process user-visible ADS streams BEFORE creating the record
            let additional_stream_count = additional_streams.len();
            let stream_indices: Vec<u32> = additional_streams
                .into_iter()
                .map(|(name, size, alloc)| add_stream_to_index(index, &name, size, alloc))
                .collect();

            // Build internal stream chain for tree-metrics accounting
            let internal_stream_count = internal_streams.len();
            let InternalStreamChain {
                first: first_internal,
                size_total: internal_size_total,
                alloc_total: internal_alloc_total,
            } = build_internal_stream_chain(index, internal_streams);

            // Snapshot and setup record using helper.  Lift parser-local raw
            // `u64` to typed `Frs` once for all the typed-API call sites.
            let frs_typed = crate::frs::Frs::new(frs);
            let record = index.get_or_create(frs_typed);
            let ext = ExtensionSnapshot {
                stream_head: record.first_stream.next_entry,
                stream_count: record.stream_count.saturating_sub(1),
                total_extra: record.total_stream_count.saturating_sub(1),
                name_next: NO_ENTRY,
                name_count: 0,
                internal_head: record.first_internal_stream,
                internal_size: record.internal_streams_size,
                internal_alloc: record.internal_streams_allocated,
                first_stream_len: record.first_stream.size.length,
                first_stream_alloc: record.first_stream.size.allocated,
            };

            record.stdinfo = std_info;
            record.first_stream.size = SizeInfo {
                length: default_size.saturating_add(ext.first_stream_len),
                allocated: default_allocated.saturating_add(ext.first_stream_alloc),
            };
            record.first_stream.flags = if record.stdinfo.is_directory() {
                0
            } else {
                8_u8 << 2_u8
            };
            record.internal_streams_size = internal_size_total;
            record.internal_streams_allocated = internal_alloc_total;
            record.first_internal_stream = first_internal;

            // Chain ADS streams and set counts
            if !stream_indices.is_empty() {
                chain_streams(index, &stream_indices);
                let rec_chain = index.get_or_create(frs_typed);
                rec_chain.first_stream.next_entry = stream_indices[0];
            }
            let rec_counts = index.get_or_create(frs_typed);
            // Stream counts are bounded by attributes-per-record; saturate to stay total.
            rec_counts.stream_count = len_to_u16(additional_stream_count).saturating_add(1);
            rec_counts.total_stream_count = len_to_u16(additional_stream_count)
                .saturating_add(1)
                .saturating_add(len_to_u16(internal_stream_count));

            // Merge extension data
            merge_extension_streams(
                index,
                frs,
                stream_indices.last().copied(),
                first_internal,
                &ext,
            );
            return true;
        }
    };

    // Add primary name to names buffer and get reference
    let name_offset = index.add_name(&name);
    let name_len = name.len();
    let is_ascii = name.is_ascii();
    let extension_id = index.intern_extension(&name);
    let name_ref = IndexNameRef::new(name_offset, len_to_u16(name_len), is_ascii, extension_id);

    // Pre-process additional names: add to names buffer and links list BEFORE
    // getting record reference This avoids borrow checker issues with holding
    // &mut record while modifying index
    let additional_count = additional_names.len();
    // Collect parent FRS values for building children array later
    let mut additional_parent_frs: SmallVec<[(u64, u16); 4]> =
        SmallVec::with_capacity(additional_count);
    let link_indices: Vec<u32> = additional_names
        .into_iter()
        .map(|(link_name, link_parent, link_parse_idx)| {
            additional_parent_frs.push((link_parent, link_parse_idx));
            add_link_to_index(index, &link_name, link_parent)
        })
        .collect();

    // Pre-process user-visible ADS streams: add to names buffer and streams list
    let additional_stream_count = additional_streams.len();
    let stream_indices: Vec<u32> = additional_streams
        .into_iter()
        .map(|(stream_name, stream_size, stream_alloc)| {
            add_stream_to_index(index, &stream_name, stream_size, stream_alloc)
        })
        .collect();

    // Build internal stream chain for tree-metrics accounting
    let internal_stream_count = internal_streams.len();
    let InternalStreamChain {
        first: first_internal,
        size_total: internal_size_total,
        alloc_total: internal_alloc_total,
    } = build_internal_stream_chain(index, internal_streams);

    // Ensure parent exists (create placeholder if needed) - do this before
    // getting our record.  Lift parser-local raw `u64` to typed `Frs`.
    if parent_frs != frs && parent_frs != 0 {
        index.get_or_create(crate::frs::Frs::new(parent_frs));
        // ^ side effect: ensures parent placeholder exists
    }

    // Snapshot and setup record
    let record = index.get_or_create(crate::frs::Frs::new(frs));
    let ext = ExtensionSnapshot {
        stream_head: record.first_stream.next_entry,
        stream_count: record.stream_count.saturating_sub(1),
        total_extra: record.total_stream_count.saturating_sub(1),
        name_next: record.first_name.next_entry,
        name_count: if record.first_name.name.is_valid() {
            record.name_count
        } else {
            0
        },
        internal_head: record.first_internal_stream,
        internal_size: record.internal_streams_size,
        internal_alloc: record.internal_streams_allocated,
        first_stream_len: record.first_stream.size.length,
        first_stream_alloc: record.first_stream.size.allocated,
    };

    record.stdinfo = std_info;
    record.first_stream.size = SizeInfo {
        length: default_size.saturating_add(ext.first_stream_len),
        allocated: default_allocated.saturating_add(ext.first_stream_alloc),
    };
    record.first_stream.flags = if record.stdinfo.is_directory() {
        0
    } else {
        8_u8 << 2_u8
    };
    record.first_name = LinkInfo {
        next_entry: NO_ENTRY,
        name: name_ref,
        _pad0: [0; 4],
        // Typed `ParentFrs` slot — lift raw `u64` parser local.
        parent_frs: crate::frs::ParentFrs::new(parent_frs),
    };
    // Name/stream counts are bounded by attributes-per-record; saturate to stay
    // total.
    record.name_count = len_to_u16(additional_count).saturating_add(1);
    record.stream_count = len_to_u16(additional_stream_count).saturating_add(1);
    record.total_stream_count = len_to_u16(additional_stream_count)
        .saturating_add(1)
        .saturating_add(len_to_u16(internal_stream_count));
    record.internal_streams_size = internal_size_total;
    record.internal_streams_allocated = internal_alloc_total;
    record.first_internal_stream = first_internal;
    record.reparse_tag = reparse_tag;

    // Chain links and streams, attach to record
    if !link_indices.is_empty() {
        record.first_name.next_entry = link_indices[0];
    }
    if !stream_indices.is_empty() {
        record.first_stream.next_entry = stream_indices[0];
    }
    chain_links(index, &link_indices);
    chain_streams(index, &stream_indices);

    // Merge extension data
    merge_extension_streams(
        index,
        frs,
        stream_indices.last().copied(),
        first_internal,
        &ext,
    );
    merge_extension_names(index, frs, link_indices.last().copied(), &ext);

    // Build parent-child relationship for tree metrics computation
    // This is critical for compute_tree_metrics() to work correctly.
    // Each name (primary + additional) creates a child entry in its parent.
    add_child_entry(index, parent_frs, frs, primary_parse_index);

    // Add child entries for additional names (hardlinks)
    for &(link_parent_frs, link_parse_idx) in &additional_parent_frs {
        add_child_entry(index, link_parent_frs, frs, link_parse_idx);
    }

    true
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Read a little-endian u16 from the given offset, returning 0 if out of
/// bounds.
#[inline]
fn rd_u16(buf: &[u8], off: usize) -> u16 {
    off.checked_add(2)
        .and_then(|end| buf.get(off..end))
        .and_then(|sl| <[u8; 2]>::try_from(sl).ok())
        .map_or(0, u16::from_le_bytes)
}

/// Read a little-endian u32 from the given offset, returning 0 if out of
/// bounds.
#[inline]
fn rd_u32(buf: &[u8], off: usize) -> u32 {
    off.checked_add(4)
        .and_then(|end| buf.get(off..end))
        .and_then(|sl| <[u8; 4]>::try_from(sl).ok())
        .map_or(0, u32::from_le_bytes)
}

/// Read a little-endian u64 from the given offset, returning 0 if out of
/// bounds.
#[inline]
fn rd_u64(buf: &[u8], off: usize) -> u64 {
    off.checked_add(8)
        .and_then(|end| buf.get(off..end))
        .and_then(|sl| <[u8; 8]>::try_from(sl).ok())
        .map_or(0, u64::from_le_bytes)
}

/// Read a little-endian i64 from the given offset, returning 0 if out of
/// bounds.
#[inline]
fn rd_i64(buf: &[u8], off: usize) -> i64 {
    off.checked_add(8)
        .and_then(|end| buf.get(off..end))
        .and_then(|sl| <[u8; 8]>::try_from(sl).ok())
        .map_or(0, i64::from_le_bytes)
}

/// Determine whether a non-`$DATA` attribute is the primary extent
/// (`LowestVCN == 0`).
///
/// Resident attributes are always primary. For non-resident attributes the
/// `LowestVCN` lives at `offset + 16` (8 bytes); a truncated record that
/// cannot supply it is treated as **not** primary (preserves the original
/// `else { false }` semantics of the internal-stream branches).
#[inline]
fn is_nonresident_primary(
    data: &[u8],
    offset: usize,
    attr_header: &crate::ntfs::AttributeRecordHeader,
) -> bool {
    if attr_header.is_non_resident == 0 {
        return true;
    }
    offset
        .checked_add(16)
        .filter(|nr| nr.saturating_add(8) <= data.len())
        .is_some_and(|nr| rd_i64(data, nr) == 0)
}

/// Read the `(DataSize, AllocatedSize)` pair from a non-resident attribute's
/// header at `offset`, clamping negative values to 0.
///
/// Returns `(0, 0)` if the header is truncated (the `nr + 48 <= len` guard
/// preserves the original "all fields present" semantics).
#[inline]
fn read_nonresident_size_alloc(data: &[u8], offset: usize) -> (u64, u64) {
    let nr_offset = offset.saturating_add(16);
    if nr_offset.saturating_add(48) <= data.len() {
        let allocated = nonneg_to_u64(rd_i64(data, nr_offset.saturating_add(24)));
        let data_size = nonneg_to_u64(rd_i64(data, nr_offset.saturating_add(32)));
        (data_size, allocated)
    } else {
        (0, 0)
    }
}

/// Read the `(size, allocated)` pair for an internal-stream attribute,
/// dispatching on residency.
///
/// Resident attributes report `(value_length@offset+16, 0)`; non-resident
/// attributes delegate to [`read_nonresident_size_alloc`].
#[inline]
fn read_size_alloc(
    data: &[u8],
    offset: usize,
    attr_header: &crate::ntfs::AttributeRecordHeader,
) -> (u64, u64) {
    if attr_header.is_non_resident == 0 {
        (u64::from(rd_u32(data, offset.saturating_add(16))), 0)
    } else {
        read_nonresident_size_alloc(data, offset)
    }
}
