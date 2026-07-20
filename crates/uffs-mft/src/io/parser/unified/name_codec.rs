// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! NTFS name decoding: UTF-16LE → `String` with counted, non-silent loss
//! (Category 4, WI-4.1), plus lossless WTF-8 storage for ill-formed names
//! (WI-4.4). Split out of `unified.rs` — this cluster has zero dependency
//! on `process_record`'s attribute-loop state, only on `MftIndex`.
//!
//! `arithmetic_side_effects` is enabled module-wide as a regression guard,
//! matching `unified.rs`'s own hardening posture: every offset here is
//! derived from attacker-controllable on-disk bytes.
#![warn(clippy::arithmetic_side_effects)]

use crate::index::MftIndex;

/// Decode a UTF-16LE byte slice into `out`, replacing unpaired surrogates
/// with U+FFFD.  Returns the number of U+FFFD replacements emitted
/// (`0` = lossless).
///
/// This avoids the per-call `SmallVec` + `String` allocation that
/// `String::from_utf16_lossy` requires, and — unlike `from_utf16_lossy` —
/// surfaces the substitution count so name loss at the NTFS boundary is
/// measured, not silent (Category 4, WI-4.1).
#[inline]
pub(super) fn decode_utf16le_into(bytes: &[u8], out: &mut String) -> u32 {
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
pub(super) fn wtf8_from_utf16le(bytes: &[u8], out: &mut Vec<u8>) {
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
pub(super) fn store_name_lossless(
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
