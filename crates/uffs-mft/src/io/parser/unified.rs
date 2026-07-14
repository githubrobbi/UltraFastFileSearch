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
    StandardInformation, file_reference_to_frs,
};

/// Decode a UTF-16LE byte slice into `out`, replacing unpaired surrogates
/// with U+FFFD.  Returns the number of U+FFFD replacements emitted
/// (`0` = lossless).
///
/// This avoids the per-call `SmallVec` + `String` allocation that
/// `String::from_utf16_lossy` requires, and — unlike `from_utf16_lossy` —
/// surfaces the substitution count so name loss at the NTFS boundary is
/// measured, not silent (Category 4, WI-4.1).
#[inline]
fn decode_utf16le_into(bytes: &[u8], out: &mut String) -> u32 {
    out.clear();
    let mut replacements: u32 = 0;
    let mut i = 0_usize;
    while let Some(pair) = i
        .checked_add(2)
        .and_then(|end| bytes.get(i..end))
        .and_then(|sl| <[u8; 2]>::try_from(sl).ok())
    {
        let code = u16::from_le_bytes(pair);
        // `i` indexes a &[u8]; it cannot exceed `bytes.len()` (≤ isize::MAX),
        // so `+= 2` cannot overflow usize. saturating_add keeps it total.
        i = i.saturating_add(2);
        match code {
            // High surrogate
            0xD800..=0xDBFF => {
                if let Some(low_pair) = i
                    .checked_add(2)
                    .and_then(|end| bytes.get(i..end))
                    .and_then(|sl| <[u8; 2]>::try_from(sl).ok())
                {
                    let low = u16::from_le_bytes(low_pair);
                    if (0xDC00..=0xDFFF).contains(&low) {
                        i = i.saturating_add(2);
                        // Bounds-proven: `code ∈ 0xD800..=0xDBFF` and
                        // `low ∈ 0xDC00..=0xDFFF`, so both subtractions are
                        // non-negative and the result is ≤ 0x10FFFF — no
                        // overflow/underflow is reachable.
                        let cp = 0x1_0000_u32
                            .saturating_add((u32::from(code).saturating_sub(0xD800_u32)) << 10_u32)
                            .saturating_add(u32::from(low).saturating_sub(0xDC00_u32));
                        if let Some(ch) = char::from_u32(cp) {
                            out.push(ch);
                        } else {
                            out.push(char::REPLACEMENT_CHARACTER);
                            replacements = replacements.saturating_add(1);
                        }
                    } else {
                        out.push(char::REPLACEMENT_CHARACTER);
                        replacements = replacements.saturating_add(1);
                    }
                } else {
                    out.push(char::REPLACEMENT_CHARACTER);
                    replacements = replacements.saturating_add(1);
                }
            }
            // Low surrogate without preceding high
            0xDC00..=0xDFFF => {
                out.push(char::REPLACEMENT_CHARACTER);
                replacements = replacements.saturating_add(1);
            }
            _ => {
                // All non-surrogate u16 values are valid Unicode scalar values.
                // `char::from_u32` is cheap for the common BMP case.
                if let Some(ch) = char::from_u32(u32::from(code)) {
                    out.push(ch);
                }
            }
        }
    }
    replacements
}

/// Decode a `&[u16]` UTF-16 name into a fresh `String`, returning
/// `(String, replacement_count)`.  Use this instead of
/// `String::from_utf16_lossy` at NTFS name boundaries so loss is counted,
/// not silent (Category 4, WI-4.1).
///
/// Most NTFS-name call sites already hold a `Vec<u16>` / `SmallVec<[u16; N]>`
/// (the attribute decoder collects code units before stringifying), so this
/// `&[u16]` entry point avoids re-deriving a byte slice. There is exactly
/// ONE surrogate-handling implementation: this re-encodes to LE bytes and
/// routes through `decode_utf16le_into`.
#[inline]
pub(crate) fn decode_name_u16(units: &[u16]) -> (String, u32) {
    let mut bytes = Vec::with_capacity(units.len().saturating_mul(2));
    for unit in units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let mut out = String::new();
    let count = decode_utf16le_into(&bytes, &mut out);
    if count > 0 {
        LOSSY_NAME_COUNT.fetch_add(u64::from(count), core::sync::atomic::Ordering::Relaxed);
    }
    (out, count)
}

/// Re-encode a UTF-16LE byte slice **losslessly** as WTF-8 into `out`.
///
/// Unlike [`decode_utf16le_into`] (which replaces unpaired surrogates with
/// U+FFFD for a valid-UTF-8 `String`), this preserves *every* code unit —
/// well-formed text becomes ordinary UTF-8, and an **unpaired surrogate**
/// (`0xD800..=0xDFFF` with no valid pairing) is emitted as its 3-byte WTF-8
/// encoding (`1110_xxxx 10xx_xxxx 10xx_xxxx` over the raw 16-bit value). The
/// result is therefore byte-faithful to the on-disk NTFS name and is what the
/// byte-native search/trigram path matches against, so a file with an
/// ill-formed name remains **findable by its true name** (WI-4.4). Surrogate
/// *pairs* are combined into their astral scalar (normal 4-byte UTF-8).
///
/// Only called on the rare lossy path (when `decode_utf16le_into` reported a
/// replacement), so its modest cost never touches the well-formed hot path.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "all arithmetic is on values masked to ≤ 0x10FFFF / 6-bit groups; \
              the WTF-8 byte composition cannot overflow u8/u32"
)]
fn wtf8_from_utf16le(bytes: &[u8], out: &mut Vec<u8>) {
    /// Low 6 bits of `x`, as a UTF-8 continuation byte (`10xx_xxxx`).
    ///
    /// `x & 0x3F` is in `0..=0x3F` and `0x80 | _` is in `0x80..=0xBF`, so the
    /// `u8` cast is exact, never truncating.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "value is masked to 6 bits (≤ 0x3F) then OR'd with 0x80 → always ≤ 0xBF"
    )]
    const fn cont(x: u32) -> u8 {
        (0x80_u32 | (x & 0x3F)) as u8
    }

    /// Leading byte: `prefix` OR the low `mask` bits of `cp_shifted`.
    /// Callers pass a `mask` (5/4/3 bits) that bounds the residual to the
    /// prefix's free bits, so the `u8` cast is exact.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "masked to ≤ 5 bits then OR'd with a fixed prefix → always ≤ 0xFF"
    )]
    const fn lead(prefix: u8, cp_shifted: u32, mask: u32) -> u8 {
        prefix | (cp_shifted & mask) as u8
    }

    /// Push a single code point (or lone surrogate) as WTF-8 bytes.
    fn push_wtf8(cp: u32, out: &mut Vec<u8>) {
        match cp {
            0x0000..=0x007F => {
                // ASCII: single byte, value ≤ 0x7F fits u8 exactly.
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "cp ≤ 0x7F in this arm → exact u8"
                )]
                out.push(cp as u8);
            }
            // 2-byte: 110x_xxxx 10xx_xxxx (5 payload bits in the lead).
            0x0080..=0x07FF => {
                out.push(lead(0xC0, cp >> 6, 0x1F));
                out.push(cont(cp));
            }
            // 3-byte: BMP incl. lone surrogates 0xD800..=0xDFFF (4 lead bits).
            0x0800..=0xFFFF => {
                out.push(lead(0xE0, cp >> 12, 0x0F));
                out.push(cont(cp >> 6));
                out.push(cont(cp));
            }
            // 4-byte: astral from a valid surrogate pair (3 lead bits).
            _ => {
                out.push(lead(0xF0, cp >> 18, 0x07));
                out.push(cont(cp >> 12));
                out.push(cont(cp >> 6));
                out.push(cont(cp));
            }
        }
    }

    let mut i = 0_usize;
    while let Some(pair) = i
        .checked_add(2)
        .and_then(|end| bytes.get(i..end))
        .and_then(|sl| <[u8; 2]>::try_from(sl).ok())
    {
        let code = u16::from_le_bytes(pair);
        i = i.saturating_add(2);
        if (0xD800..=0xDBFF).contains(&code) {
            // High surrogate: combine with a following low surrogate if present.
            if let Some(low) = i
                .checked_add(2)
                .and_then(|end| bytes.get(i..end))
                .and_then(|sl| <[u8; 2]>::try_from(sl).ok())
                .map(u16::from_le_bytes)
                .filter(|low| (0xDC00..=0xDFFF).contains(low))
            {
                i = i.saturating_add(2);
                let cp = 0x1_0000_u32
                    + ((u32::from(code) - 0xD800_u32) << 10_u32)
                    + (u32::from(low) - 0xDC00_u32);
                push_wtf8(cp, out);
            } else {
                // Unpaired high surrogate — preserve verbatim as WTF-8.
                push_wtf8(u32::from(code), out);
            }
        } else {
            // BMP scalar or unpaired low surrogate — both preserved verbatim.
            push_wtf8(u32::from(code), out);
        }
    }
}

/// Store a just-decoded name into the index's name buffer **losslessly**,
/// returning `(byte_offset, stored_byte_len)`.
///
/// - `display` is the lossy `String` produced by [`decode_utf16le_into`]
///   (U+FFFD for ill-formed parts) — used as-is for the common well-formed
///   case, where its bytes are identical to the name's WTF-8.
/// - `raw_utf16le` is the original on-disk UTF-16LE byte slice for the name.
/// - `lossy` is the replacement count `decode_utf16le_into` reported.
///
/// When `lossy == 0` (the overwhelming common case) the `display` bytes are
/// stored directly — zero extra work on the hot path. When `lossy > 0`, the
/// raw UTF-16 is re-encoded to byte-faithful WTF-8 and *those* bytes are
/// stored, so the file is findable by its true name (WI-4.4). The returned
/// length is the **stored** byte length (WTF-8 length on the lossy path),
/// which the caller records in the `IndexNameRef` so `get_name_bytes` slices
/// exactly the stored name.
fn store_name_lossless(
    index: &mut MftIndex,
    display: &str,
    raw_utf16le: &[u8],
    lossy: u32,
) -> (u32, usize) {
    if lossy == 0 {
        let bytes = display.as_bytes();
        (index.add_name_bytes(bytes), bytes.len())
    } else {
        let mut wtf8 = Vec::with_capacity(raw_utf16le.len());
        wtf8_from_utf16le(raw_utf16le, &mut wtf8);
        (index.add_name_bytes(&wtf8), wtf8.len())
    }
}

/// Process-global tally of U+FFFD substitutions emitted by
/// [`decode_name_u16`] across all NTFS-name decodes (Category 4, WI-4.1).
///
/// The parser call sites are spread across nine modules and do not thread a
/// stats accumulator through their (hot-path) signatures, so the count is
/// gathered here with a single relaxed atomic — cheap, lock-free, and read
/// at index-build time into the `lossy_name_count` field of
/// [`crate::index::MftStats`] for the "N filenames were stored with
/// U+FFFD" warning. `Relaxed` is
/// sufficient: it is a monotonic diagnostic counter, not a synchronisation
/// point.
pub(crate) static LOSSY_NAME_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Snapshot the current global lossy-name tally.
#[inline]
pub(crate) fn lossy_name_count() -> u64 {
    LOSSY_NAME_COUNT.load(core::sync::atomic::Ordering::Relaxed)
}

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
                    let vo = usize::from(rd_u16(data, offset.saturating_add(20)));
                    if let Some(si_off) = offset.checked_add(vo)
                        && let Some(si_slice) = data.get(si_off..)
                        && let Ok((si, _)) = StandardInformation::read_from_prefix(si_slice)
                    {
                        // Fast path: map raw NTFS flags directly to our
                        // compact bitmask — skips the intermediate
                        // ExtendedStandardInfo struct entirely.
                        let mut info =
                            crate::index::StandardInfo::from_raw_ntfs_flags(si.file_attributes);
                        info.created = si.creation_time;
                        info.modified = si.modification_time;
                        info.accessed = si.access_time;
                        info.mft_changed = si.mft_change_time;
                        if is_directory {
                            info.set_directory(true);
                        }
                        index.records[base_ri].stdinfo = info;
                    }
                }
            }

            // ── $FILE_NAME (0x30) ─────────────────────────────────────
            // Push-to-front: each new $FILE_NAME overwrites first_name.
            Some(AttributeType::FileName) => {
                if attr_header.is_non_resident == 0 {
                    let vo = usize::from(rd_u16(data, offset.saturating_add(20)));
                    if let Some(fn_off) = offset.checked_add(vo)
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
                            let name_ref = IndexNameRef::new(
                                name_off,
                                len_to_u16(stored_len),
                                is_ascii,
                                ext_id,
                            );

                            index.records[base_ri].first_name.name = name_ref;
                            // Typed `ParentFrs` slot — lift parser-local raw `u64`.
                            index.records[base_ri].first_name.parent_frs =
                                crate::frs::ParentFrs::new(parent_frs);

                            // Build parent-child relationship.
                            // name_index = name_count BEFORE increment
                            let name_index = index.records[base_ri].name_count;

                            if parent_frs != frs_base && parent_frs != u64::from(NO_ENTRY) {
                                let parent_ri = u32_as_usize(
                                    index.ensure_record(crate::frs::Frs::new(parent_frs)),
                                );
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

                    // ── Classify and store ───────────────────────────
                    if is_i30 {
                        // $I30: accumulate into first_stream (directory index)
                        let rec = &mut index.records[base_ri];
                        rec.stdinfo.set_directory(true);
                        rec.first_stream.flags = 0; // type_name_id=0 for $I30

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
                        rec.first_stream.flags = 8_u8 << 2_u8; // type_name_id=8 for $DATA
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
                                flags: 8_u8 << 2_u8,
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
                            flags: 0,
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
                        let vo = usize::from(rd_u16(data, offset.saturating_add(20)));
                        if let Some(tag) = offset.checked_add(vo).map(|rp| rd_u32(data, rp)) {
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

#[cfg(test)]
mod tests;
