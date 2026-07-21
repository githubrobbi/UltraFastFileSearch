// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unified MFT record processor.
//!
//! ONE function processes ALL records (base AND extension) through the SAME
//! attribute loop.  This eliminates the dual-parser architecture that caused
//! name-ordering and stream-counting discrepancies.
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

use core::mem::size_of;

use zerocopy::FromBytes as _;

use crate::index::{
    ChildInfo, IndexNameRef, IndexStreamInfo, InternalStreamInfo, MftIndex, NO_ENTRY, SizeInfo,
    len_to_u16, len_to_u32, u32_as_usize,
};
use crate::ntfs::{
    AttributeRecordHeader, AttributeType, FileNameAttribute, FileRecordSegmentHeader,
    file_reference_to_frs,
};

mod name_codec;

// `decode_name_u16`/`lossy_name_count` are consumed crate-wide as
// `crate::io::parser::unified::{decode_name_u16, lossy_name_count}` (nine
// other modules); re-exporting keeps every existing call site unchanged
// even though the implementation now lives in the `name_codec` submodule.
#[cfg(test)]
use name_codec::wtf8_from_utf16le;
pub(crate) use name_codec::{decode_name_u16, lossy_name_count};
use name_codec::{decode_utf16le_into, store_name_lossless};

/// Process a single MFT record (base OR extension) in one pass.
///
/// Both base and extension records go through the **same** attribute loop.
/// For extensions, `frs_base` points to the base record; for base records,
/// `frs_base == frs`.
///
/// Records are created with `FileRecord::new_unified()` (internal helper)
/// which starts all counts at 0.  Every accepted `$FILE_NAME` and every
/// first-occurrence stream increments the respective count.
///
/// Returns `true` if the record was successfully processed.
#[expect(
    clippy::too_many_lines,
    reason = "single-pass MFT record processor — kept as one function for correctness"
)]
#[expect(
    clippy::cognitive_complexity,
    reason = "single-pass attribute walk — complexity is inherent to NTFS record structure"
)]
#[expect(
    clippy::indexing_slicing,
    reason = "remaining [] are internal arena indices (index.records[base_ri], \
              index.streams[..], index.internal_streams[..]) keyed by indices \
              minted by this fn via ensure_record/push; not attacker-controlled. \
              All untrusted-`data` reads go through .get()/rd_u* (WI-5.2)."
)]
pub fn process_record(data: &[u8], frs: u64, index: &mut MftIndex, name_buf: &mut String) -> bool {
    if data.len() < size_of::<FileRecordSegmentHeader>() {
        return false;
    }

    let Ok((header, _)) = FileRecordSegmentHeader::read_from_prefix(data) else {
        return false;
    };

    // Only process valid, in-use FILE records
    let multi_sector_header = header.multi_sector_header;
    if !header.is_in_use() || !multi_sector_header.is_file_record() {
        return false;
    }

    // Determine base FRS (extension records point to their parent base record)
    let frs_base = if header.is_base_record() {
        frs
    } else {
        file_reference_to_frs(header.base_file_record_segment)
    };

    let is_directory = header.is_directory();

    // Get or create the base record (zero-based counts).
    // Cache the record index so we don't repeat the frs→idx lookup for
    // every attribute in this record.  Boundary: lift parser-local raw
    // `u64` to typed `Frs` for the typed index API.
    let frs_base_typed = crate::frs::Frs::new(frs_base);
    let base_ri = u32_as_usize(index.ensure_record(frs_base_typed));

    // Persist the NTFS sequence number (slot-reuse generation) from the base
    // record's own header. With the FRS it forms the File Reference the compact
    // index packs into `file_ref`; the snapshot diff needs it to tell a
    // delete-then-reuse of an MFT slot apart from an unchanged file (the slot
    // number alone is stable across reuse). Extension records carry their own
    // sequence, so only a base record's header sets the file's sequence.
    if header.is_base_record() {
        index.records[base_ri].sequence_number = header.sequence_number;
        // Log File Sequence Number, correlates with the $LogFile journal
        // (forensic value) — already-parsed header data, free to store.
        // Same base-record-only scope as sequence_number above: an
        // extension record segment has its own LSN, a different concept
        // from the file's own.
        index.records[base_ri].lsn = header.log_file_sequence_number;
    }

    // ── Attribute loop ─────────────────────────────────────────────────
    let mut offset = usize::from(header.first_attribute_offset);
    let max_offset = core::cmp::min(u32_as_usize(header.bytes_in_use), data.len());

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
        let Ok((attr_header, _)) = AttributeRecordHeader::read_from_prefix(attr_slice) else {
            break;
        };

        if attr_header.type_code == AttributeType::END_MARKER {
            break;
        }
        let attr_len = u32_as_usize(attr_header.length);
        let attr_end = offset.checked_add(attr_len);
        if attr_len == 0 || attr_end.is_none_or(|end| end > data.len()) {
            break;
        }

        match AttributeType::from_u32(attr_header.type_code) {
            // ── $STANDARD_INFORMATION (0x10) ─────────────────────────
            Some(AttributeType::StandardInformation) => {
                if attr_header.is_non_resident == 0 {
                    // Shared with the legacy and direct-index pipelines: reads
                    // the 72-byte NTFS 3.0+ `StandardInformationExtended` form
                    // (usn/security_id/owner_id) when `value_length` says it's
                    // present, falling back to the 36-byte NTFS 1.2 form
                    // otherwise — see `parse::attribute_helpers` for the
                    // single-source-of-truth rationale.
                    let mut ext = crate::ntfs::ExtendedStandardInfo::default();
                    // Bulk path: `StdInfoParse` has nowhere to live on the
                    // index record, so the status is dropped here.
                    crate::parse::parse_standard_info_full(data, offset, &mut ext);
                    let mut info = crate::index::StandardInfo::from_extended(&ext);
                    if is_directory {
                        info.set_directory(true);
                    }
                    index.records[base_ri].stdinfo = info;
                }
            }

            // ── $FILE_NAME (0x30) ─────────────────────────────────────
            // Push-to-front: each new $FILE_NAME overwrites first_name.
            Some(AttributeType::FileName) => {
                if attr_header.is_non_resident == 0
                    && let Some(fn_off) = resident_value_offset(data, offset)
                    && let Some(fn_slice) = data.get(fn_off..)
                    && let Ok((fn_attr, _)) = FileNameAttribute::read_from_prefix(fn_slice)
                    && fn_attr.file_name_namespace != 2
                {
                    // Skip DOS-only names (namespace 2)
                    let parent_frs = file_reference_to_frs(fn_attr.parent_directory);
                    let name_len = usize::from(fn_attr.file_name_length);
                    let ns = fn_off.saturating_add(size_of::<FileNameAttribute>());

                    // `name_len` is a u16 (≤ 65535); `*2` and `+ ns` cannot
                    // overflow usize on any supported target, but use the
                    // checked form so the parser is provably total, and let
                    // `data.get(..)` do the bounds check (None on a
                    // declared-length that overruns the record → skip name).
                    if let Some(nb) = name_len
                        .checked_mul(2)
                        .and_then(|byte_len| ns.checked_add(byte_len))
                        .and_then(|name_end| data.get(ns..name_end))
                    {
                        let lossy = decode_utf16le_into(nb, name_buf);

                        // Push old first_name to chain
                        // Copy first_name before mutating (borrow checker)
                        let old_valid = index.records[base_ri].first_name.name.is_valid();
                        let old_first = index.records[base_ri].first_name; // Copy
                        if old_valid {
                            let link_idx = len_to_u32(index.links.len());
                            index.links.push(old_first);
                            index.records[base_ri].first_name.next_entry = link_idx;
                        }

                        // Overwrite first_name with the new name. Store the
                        // name LOSSLESSLY (WI-4.4): a well-formed name's
                        // `String` bytes already equal its WTF-8, so the
                        // common path is unchanged; an ill-formed name
                        // (lossy > 0) is stored as byte-faithful WTF-8 of
                        // the raw UTF-16 so it stays findable. `is_ascii` /
                        // extension still derive from the lossy display
                        // `name_buf` (a U+FFFD name is not ASCII and has no
                        // meaningful extension).
                        let (name_off, stored_len) =
                            store_name_lossless(index, name_buf, nb, lossy);
                        let is_ascii = name_buf.is_ascii();
                        let ext_id = index.intern_extension(name_buf);
                        let name_ref =
                            IndexNameRef::new(name_off, len_to_u16(stored_len), is_ascii, ext_id);

                        index.records[base_ri].first_name.name = name_ref;
                        // Typed `ParentFrs` slot — lift parser-local raw `u64`.
                        index.records[base_ri].first_name.parent_frs =
                            crate::frs::ParentFrs::new(parent_frs);

                        // $FILE_NAME's own namespace/timestamps (often
                        // differ from $STANDARD_INFORMATION — e.g.
                        // timestomping leaves STD_INFO altered but
                        // FILE_NAME original). `fn_attr` is already fully
                        // decoded above; these are free reads of already-
                        // resident memory. Push-to-front: whichever name
                        // is currently "first" also owns these fields.
                        let rec = &mut index.records[base_ri];
                        rec.namespace = fn_attr.file_name_namespace;
                        rec.fn_created = fn_attr.creation_time;
                        rec.fn_modified = fn_attr.modification_time;
                        rec.fn_accessed = fn_attr.access_time;
                        rec.fn_mft_changed = fn_attr.mft_change_time;

                        // Build parent-child relationship.
                        // name_index = name_count BEFORE increment
                        let name_index = index.records[base_ri].name_count;

                        if parent_frs != frs_base && parent_frs != u64::from(NO_ENTRY) {
                            let parent_ri =
                                u32_as_usize(index.ensure_record(crate::frs::Frs::new(parent_frs)));
                            let child_idx = len_to_u32(index.children.len());
                            let old_fc = index.records[parent_ri].first_child;
                            index.records[parent_ri].first_child = child_idx;

                            index.children.push(ChildInfo {
                                next_entry: old_fc,
                                _pad0: [0; 4],
                                // Typed `Frs` slot — reuse cached typed FRS.
                                child_frs: frs_base_typed,
                                name_index,
                                _pad1: [0; 6],
                            });
                        }

                        // Increment name_count (zero-based, always increment)
                        // (including the first name).
                        index.records[base_ri].name_count =
                            index.records[base_ri].name_count.saturating_add(1);
                    }
                }
            }

            // ── ALL OTHER ATTRIBUTES ──────────────────────────────────
            _ => {
                // Determine if this is the primary (unnamed) data attribute
                let is_primary = if attr_header.is_non_resident == 0 {
                    true
                } else {
                    // Non-resident header's StartingVcn (offset+16, 8 bytes) ==
                    // 0 marks the primary run. Fallible slice → not-primary on
                    // a truncated record.
                    offset
                        .checked_add(16)
                        .and_then(|nr| nr.checked_add(8).and_then(|end| data.get(nr..end)))
                        .and_then(|sl| <[u8; 8]>::try_from(sl).ok())
                        .is_some_and(|bytes| i64::from_le_bytes(bytes) == 0)
                };

                if is_primary {
                    let attr_type = attr_header.type_code;
                    let aname_len = usize::from(attr_header.name_length);

                    // $I30 directory index check
                    let is_i30 = matches!(
                        AttributeType::from_u32(attr_type),
                        Some(
                            AttributeType::Bitmap
                                | AttributeType::IndexRoot
                                | AttributeType::IndexAllocation
                        )
                    ) && aname_len == 4
                        && offset
                            .checked_add(usize::from(attr_header.name_offset))
                            .and_then(|no| no.checked_add(8).and_then(|end| data.get(no..end)))
                            .is_some_and(|sl| sl == b"$\x00I\x003\x000\x00");

                    // Read stream name (non-$I30, named attributes)
                    let has_stream_name = !is_i30 && aname_len > 0;
                    // WI-4.4: track whether the stream name decoded lossily and
                    // the raw UTF-16LE range, so the store site below can retain
                    // byte-faithful WTF-8 for an ill-formed stream name.
                    let mut stream_name_lossy: u32 = 0;
                    let mut stream_name_raw: Option<&[u8]> = None;
                    if has_stream_name {
                        // Fallible: a declared name length that overruns the
                        // record clears the buffer instead of panicking.
                        let name_bytes = offset
                            .checked_add(usize::from(attr_header.name_offset))
                            .and_then(|no| {
                                aname_len
                                    .checked_mul(2)
                                    .and_then(|byte_len| no.checked_add(byte_len))
                                    .and_then(|end| data.get(no..end))
                            });
                        match name_bytes {
                            Some(bytes) => {
                                stream_name_lossy = decode_utf16le_into(bytes, name_buf);
                                stream_name_raw = Some(bytes);
                            }
                            None => name_buf.clear(),
                        }
                    }

                    // Size calculation for primary data attribute
                    let is_badclus_bad =
                        frs_base == 8 && aname_len == 4 && has_stream_name && name_buf == "$Bad";

                    let (size, alloc) = if attr_header.is_non_resident != 0 {
                        // `rd_u*` are individually bounds-safe (return 0 OOB);
                        // the `nr + 48 <= len` guard preserves the original
                        // "all fields present" semantics. `nr` via checked_add.
                        offset
                            .checked_add(16)
                            .filter(|nr| nr.saturating_add(48) <= data.len())
                            .map_or((0, 0), |nr| {
                                let cu = rd_u16(data, nr.saturating_add(18)); // CompressionUnit
                                let alloc_size = if cu > 0 {
                                    rd_u64(data, nr.saturating_add(48)) // CompressedSize
                                } else if is_badclus_bad {
                                    rd_u64(data, nr.saturating_add(40)) // InitializedSize
                                } else {
                                    rd_u64(data, nr.saturating_add(24)) // AllocatedSize
                                };
                                let logical_size = if is_badclus_bad {
                                    rd_u64(data, nr.saturating_add(40)) // InitializedSize
                                } else {
                                    rd_u64(data, nr.saturating_add(32)) // DataSize
                                };
                                (logical_size, alloc_size)
                            })
                    } else {
                        (u64::from(rd_u32(data, offset.saturating_add(16))), 0)
                    };

                    // Already-parsed attribute-header data, free to read —
                    // `IndexStreamInfo`/`InternalStreamInfo` both reserve
                    // bit0=is_sparse, bit1=is_resident, but every write site
                    // below used to hardcode them to 0/false regardless of
                    // the real attribute.
                    let is_resident = attr_header.is_non_resident == 0;
                    let is_sparse = !is_resident && (attr_header.flags & 0x8000) != 0;

                    // ── Classify and store ───────────────────────────
                    if is_i30 {
                        // $I30: accumulate into first_stream (directory index)
                        let rec = &mut index.records[base_ri];
                        rec.stdinfo.set_directory(true);
                        // type_name_id=0 for $I30
                        rec.first_stream.flags =
                            u8::from(is_sparse) | (u8::from(is_resident) << 1_u8);

                        rec.first_stream.size.length =
                            rec.first_stream.size.length.saturating_add(size);
                        rec.first_stream.size.allocated =
                            rec.first_stream.size.allocated.saturating_add(alloc);
                        // Increment counts once for the first $I30 attribute;
                        // subsequent $I30 attrs ($INDEX_ALLOCATION, $BITMAP)
                        // accumulate size without creating new stream entries.
                        if !rec.has_i30_stream() {
                            rec.set_has_i30_stream();
                            rec.stream_count = rec.stream_count.saturating_add(1);
                            rec.total_stream_count = rec.total_stream_count.saturating_add(1);
                        }
                    } else if attr_type == AttributeType::DATA_TYPE && aname_len == 0 {
                        // Unnamed $DATA: default stream
                        let rec = &mut index.records[base_ri];
                        // Increment counts once for the first unnamed $DATA;
                        // subsequent unnamed $DATA (from extension records)
                        // accumulate size only.
                        if !rec.has_default_data() {
                            rec.stream_count = rec.stream_count.saturating_add(1);
                            rec.total_stream_count = rec.total_stream_count.saturating_add(1);
                        }
                        rec.set_has_default_data();
                        rec.first_stream.size.length =
                            rec.first_stream.size.length.saturating_add(size);
                        rec.first_stream.size.allocated =
                            rec.first_stream.size.allocated.saturating_add(alloc);
                        // type_name_id=8 for $DATA
                        rec.first_stream.flags =
                            u8::from(is_sparse) | (u8::from(is_resident) << 1_u8) | (8_u8 << 2_u8);
                    } else if attr_type == AttributeType::DATA_TYPE && aname_len > 0 {
                        // Named $DATA: ADS (user-visible stream).
                        // Output layer filters internal streams.
                        if has_stream_name && !name_buf.is_empty() {
                            // WI-4.4: store the stream name losslessly (WTF-8
                            // for an ill-formed name; identical bytes for the
                            // common case). `stream_name_raw` is `Some` whenever
                            // `has_stream_name` decoded a non-empty buffer.
                            let (sn_off, sn_len) = if let Some(raw) = stream_name_raw {
                                store_name_lossless(index, name_buf, raw, stream_name_lossy)
                            } else {
                                let nb = name_buf.as_bytes();
                                (index.add_name_bytes(nb), nb.len())
                            };
                            let is_ascii = name_buf.is_ascii();
                            let ext_id = index.intern_extension(name_buf);
                            let nr =
                                IndexNameRef::new(sn_off, len_to_u16(sn_len), is_ascii, ext_id);
                            let si = len_to_u32(index.streams.len());
                            index.streams.push(IndexStreamInfo {
                                size: SizeInfo {
                                    length: size,
                                    allocated: alloc,
                                },
                                next_entry: NO_ENTRY,
                                name: nr,
                                flags: u8::from(is_sparse)
                                    | (u8::from(is_resident) << 1_u8)
                                    | (8_u8 << 2_u8),
                                _pad0: [0; 3],
                            });

                            // Chain to record's stream list
                            let old_next = index.records[base_ri].first_stream.next_entry;
                            // Find end of chain
                            if old_next == NO_ENTRY {
                                index.records[base_ri].first_stream.next_entry = si;
                            } else {
                                let mut tail = old_next;
                                while index.streams[u32_as_usize(tail)].next_entry != NO_ENTRY {
                                    tail = index.streams[u32_as_usize(tail)].next_entry;
                                }
                                index.streams[u32_as_usize(tail)].next_entry = si;
                            }
                            index.records[base_ri].stream_count =
                                index.records[base_ri].stream_count.saturating_add(1);
                            index.records[base_ri].total_stream_count =
                                index.records[base_ri].total_stream_count.saturating_add(1);
                        }
                    } else {
                        // All other attribute types: internal stream
                        let ist_idx = len_to_u32(index.internal_streams.len());
                        index.internal_streams.push(InternalStreamInfo {
                            size: SizeInfo {
                                length: size,
                                allocated: alloc,
                            },
                            next_entry: NO_ENTRY,
                            flags: u8::from(is_sparse) | (u8::from(is_resident) << 1_u8),
                        });

                        // Chain to record's internal stream list
                        let head = index.records[base_ri].first_internal_stream;
                        if head == NO_ENTRY {
                            index.records[base_ri].first_internal_stream = ist_idx;
                        } else {
                            // Walk chain to find tail
                            let mut tail = head;
                            while index.internal_streams[u32_as_usize(tail)].next_entry != NO_ENTRY
                            {
                                tail = index.internal_streams[u32_as_usize(tail)].next_entry;
                            }
                            index.internal_streams[u32_as_usize(tail)].next_entry = ist_idx;
                        }
                        let rec = &mut index.records[base_ri];
                        rec.internal_streams_size = rec.internal_streams_size.saturating_add(size);
                        rec.internal_streams_allocated =
                            rec.internal_streams_allocated.saturating_add(alloc);
                        rec.total_stream_count = rec.total_stream_count.saturating_add(1);
                    }

                    // Extract reparse tag from $REPARSE_POINT
                    if attr_type == AttributeType::REPARSE_POINT_TYPE
                        && attr_header.is_non_resident == 0
                    {
                        // Fallible: a value offset that overruns the record
                        // leaves the reparse tag unset rather than panicking.
                        if let Some(tag) =
                            resident_value_offset(data, offset).map(|rp| rd_u32(data, rp))
                        {
                            index.records[base_ri].reparse_tag = tag;
                        }
                    }
                }
            }
        }

        // `attr_len` (== attr_header.length) was validated above:
        // `offset + attr_len <= data.len()`, so this advance cannot overflow.
        // `saturating_add` keeps it total even on a pathological length.
        offset = offset.saturating_add(attr_len);
    }

    // Set directory flag from header if not already set
    if is_directory {
        index.records[base_ri].stdinfo.set_directory(true);
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

/// Absolute offset of a resident attribute's value, from its own
/// `value_offset` field (`attr_offset + 20`, a `u16`).
#[inline]
fn resident_value_offset(data: &[u8], attr_offset: usize) -> Option<usize> {
    attr_offset.checked_add(usize::from(rd_u16(data, attr_offset.saturating_add(20))))
}

#[cfg(test)]
mod tests;
