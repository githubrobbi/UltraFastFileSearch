// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! The 88-byte [`CompactRecord`] row type + the NTFS metafile-name allowlist.
//!
//! Extracted from `compact.rs` (file-size decomposition); the public path
//! `crate::compact::CompactRecord` is preserved via re-export.

/// Compact per-record data for in-memory search, filter, and sort.
///
/// 88 bytes per record (87 data + 1 explicit tail padding).
/// Derives `bytemuck::Pod` + `Zeroable` so the entire record array can be
/// serialized/deserialized as a single bulk `memcpy` — no per-field encoding.
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct CompactRecord {
    // ── u64 fields first (8-byte aligned) ─────────────────────────
    /// Logical file size in bytes.
    pub size: u64,
    /// Allocated size on disk in bytes ("Size on Disk" column).
    pub allocated: u64,
    /// Sum of logical file sizes in entire subtree.
    pub treesize: u64,
    /// Sum of allocated sizes in entire subtree.
    pub tree_allocated: u64,
    /// Creation time (Unix microseconds).
    pub created: i64,
    /// Last write time (Unix microseconds).
    pub modified: i64,
    /// Last access time (Unix microseconds).
    pub accessed: i64,
    /// NTFS **File Reference**: `(sequence_number << 48) | frs`. The FRS (low
    /// 48 bits) is the MFT slot; the sequence number (high 16 bits)
    /// disambiguates slot reuse, so together they uniquely identify a *file
    /// incarnation* — the key a delete/forensic diff must use to tell a
    /// modified file from a recycled slot. `0` for synthetic rows (aggregate
    /// rollups, ADS/hardlink expansions that share the base record identity).
    /// Populated by
    /// [`build_compact_index`](crate::compact::build_compact_index).
    pub file_ref: u64,

    // ── u32 fields (4-byte aligned) ───────────────────────────────
    /// Byte offset into the names blob.
    pub name_offset: u32,
    /// Raw NTFS `FILE_ATTRIBUTE_*` flags.
    pub flags: u32,
    /// Index into the compact array of the parent directory.
    /// `u32::MAX` = root or orphan.
    pub parent_idx: u32,
    /// Count of all descendants in subtree. 0 for files.
    pub descendants: u32,

    // ── u16 fields (2-byte aligned) ───────────────────────────────
    /// UTF-8 byte length of the filename.
    pub name_len: u16,
    /// Interned extension ID (0 = no extension).
    pub extension_id: u16,
    /// Full path length in UTF-8 bytes (e.g. `C:\Windows\System32\cmd.exe` =
    /// 28). Precomputed at index build time via top-down parent-chain walk.
    /// Saturates at `u16::MAX` (65 535) for extremely deep paths.
    pub path_len: u16,

    /// First byte of the filename (e.g. `b'$'` for NTFS metafiles).
    ///
    /// Cached here as a cheap hot-path *gate*: only `$`-prefixed records can be
    /// NTFS metafiles, so [`is_system_metafile`](Self::is_system_metafile) can
    /// reject virtually every record with one sequential field read instead of
    /// a random cache-miss into the names arena.  The handful of `$`-prefixed
    /// candidates then pay one arena lookup for the authoritative name check.
    pub name_first_byte: u8,

    /// Explicit tail padding for 8-byte struct alignment.
    /// Required by `bytemuck::Pod` — no implicit padding allowed.
    #[expect(
        clippy::pub_underscore_fields,
        reason = "bytemuck Pod requires all fields same visibility"
    )]
    pub _pad: [u8; 1],
}

/// Mask for the 48-bit FRS half of a [`CompactRecord::file_ref`].
const FRS_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

impl CompactRecord {
    /// Pack an NTFS **File Reference** from its FRS (MFT slot) and sequence
    /// number (slot-reuse generation): `(sequence_number << 48) | frs`.
    #[must_use]
    pub fn pack_file_reference(frs: u64, sequence_number: u16) -> u64 {
        (frs & FRS_MASK) | (u64::from(sequence_number) << 48)
    }

    /// The FRS (MFT slot, low 48 bits) of a raw packed file reference —
    /// the free-standing counterpart of [`Self::frs`] for callers that
    /// only have the packed `u64` (e.g. `DisplayRow`/`SearchRow`'s
    /// `file_reference` field), not a whole `CompactRecord`.
    #[must_use]
    pub const fn unpack_frs(file_reference: u64) -> u64 {
        file_reference & FRS_MASK
    }

    /// The FRS (MFT slot, low 48 bits) of this record's file reference.
    #[must_use]
    pub const fn frs(&self) -> u64 {
        self.file_ref & FRS_MASK
    }

    /// The sequence number (slot-reuse generation, high 16 bits) of this
    /// record's file reference. `>> 48` always fits `u16`, so the `try_from`
    /// never fails; `unwrap_or` avoids an `unwrap`/`expect` for the lints.
    #[must_use]
    pub fn sequence_number(&self) -> u16 {
        u16::try_from(self.file_ref >> 48).unwrap_or(u16::MAX)
    }
}

/// The fixed set of reserved NTFS metafile names: the `$`-prefixed records at
/// reserved FRS 0–15 and under the `$Extend` directory.  An NTFS volume can
/// only ever contain *these* specific metafiles.
///
/// Any *other* `$`-prefixed name — `$Recycle.Bin`, `$PatchCache`,
/// `$WinREAgent`, the `WinSxS` `$$_*.cdf-ms` filemaps, or a user file literally
/// named `$foo` — is an ordinary file that file managers and tools like
/// Everything display. Classifying those as metafiles is exactly the bug
/// `--hide-system` had.
///
/// Matched case-insensitively: NTFS itself is case-insensitive, and these
/// canonical names are occasionally surfaced with varied casing.
pub(crate) const NTFS_METAFILE_NAMES: &[&str] = &[
    // Reserved FRS 0–11 (volume root metafiles)
    "$MFT",
    "$MFTMirr",
    "$LogFile",
    "$Volume",
    "$AttrDef",
    "$Bitmap",
    "$Boot",
    "$BadClus",
    "$Secure",
    "$UpCase",
    "$Extend",
    // `$Extend` directory children
    "$ObjId",
    "$Quota",
    "$Reparse",
    "$UsnJrnl",
    "$RmMetadata",
    "$Deleted",
    // `$Extend\$RmMetadata` children
    "$Repair",
    "$Tops",
    "$TxfLog",
    "$Txf",
];

/// Returns whether `name` is one of the reserved `NTFS_METAFILE_NAMES`
/// (a crate-private allowlist, so no intra-doc link from this public item).
///
/// Real metafiles are already excluded from the compact index at build time
/// (`build_compact_index` drops them via `PathResolver` FRS-validity, not by
/// name).  This exact-name check is the *authoritative* classifier for the
/// `--hide-system` filter, so it can never misclassify an ordinary
/// `$`-prefixed file as a metafile.
#[must_use]
#[inline]
pub fn is_ntfs_metafile_name(name: &str) -> bool {
    NTFS_METAFILE_NAMES
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

/// How an **ill-formed** (surrogate-bearing) NTFS name renders for display.
///
/// Used by [`CompactRecord::name_display_with`]. Well-formed names are returned
/// verbatim under either variant, so this only matters for the rare malformed
/// case and never touches the well-formed hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MalformedRender {
    /// Replace each ill-formed run with U+FFFD (`�`) — the default, matching
    /// the reference C++ tool and ordinary file managers.
    #[default]
    Lossy,
    /// Replace each offending UTF-16 code unit with a greppable, reversible
    /// sentinel `<BAD:HHHH>` (HHHH = the code unit, e.g. an unpaired low
    /// surrogate → `<BAD:DCFF>`). `<` and `>` are invalid in NTFS names, so the
    /// marker can never collide with a real one; the hex is unique per distinct
    /// bad unit (so two malformed siblings stay distinct) and lossless (the
    /// true name is recoverable). Enabled by `--normalize-malformed`.
    Normalized,
}

/// Render WTF-8 `bytes` one **UTF-16 code unit** at a time, replacing each
/// offending unit (an unpaired surrogate) with a marker; well-formed runs pass
/// through unchanged. Only called on the rare ill-formed path (the caller has
/// already seen `from_utf8` fail).
///
/// Crucially this is **per code unit**, not per byte: a WTF-8 lone surrogate is
/// the 3-byte sequence `0xED 0xA0..=0xBF 0x80..=0xBF` decoding to a single
/// U+D800..=U+DFFF unit, so it yields ONE marker (matching the reference C++
/// tool and ordinary file managers) rather than `from_utf8_lossy`'s three. The
/// marker is U+FFFD (`�`) for [`MalformedRender::Lossy`] or `<BAD:HHHH>` for
/// [`MalformedRender::Normalized`]. Any other invalid byte (not expected from a
/// faithful NTFS name) is treated as one offending position.
fn render_malformed(bytes: &[u8], render: MalformedRender) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_add(8));
    let mut rest = bytes;
    while !rest.is_empty() {
        match core::str::from_utf8(rest) {
            Ok(valid) => {
                out.push_str(valid);
                break;
            }
            Err(err) => {
                let good = err.valid_up_to();
                let (head, bad) = rest.split_at(good);
                // `head` is valid UTF-8 by construction (`valid_up_to`).
                out.push_str(core::str::from_utf8(head).unwrap_or(""));
                if let [0xED, b1 @ 0xA0..=0xBF, b2 @ 0x80..=0xBF, tail @ ..] = bad {
                    match render {
                        MalformedRender::Lossy => out.push('\u{FFFD}'),
                        MalformedRender::Normalized => {
                            // Decode the WTF-8 lone surrogate back to its 16-bit
                            // code unit (lead nibble is the fixed 0xD of 0xED),
                            // then emit `<BAD:HHHH>`. `wrapping_sh*` + bit-ops +
                            // `char::from_digit` are all panic-free here (values
                            // masked to ≤ 0xF, base 16).
                            let unit: u32 = 0xD000
                                | (u32::from(*b1) & 0x3F).wrapping_shl(6)
                                | (u32::from(*b2) & 0x3F);
                            out.push_str("<BAD:");
                            for shift in [12_u32, 8, 4, 0] {
                                let nibble = unit.wrapping_shr(shift) & 0xF;
                                out.push(
                                    char::from_digit(nibble, 16)
                                        .unwrap_or('0')
                                        .to_ascii_uppercase(),
                                );
                            }
                            out.push('>');
                        }
                    }
                    rest = tail;
                } else {
                    let adv = err.error_len().unwrap_or(1).min(bad.len());
                    let (_, after) = bad.split_at(adv);
                    match render {
                        MalformedRender::Lossy => out.push('\u{FFFD}'),
                        MalformedRender::Normalized => out.push_str("<BAD>"),
                    }
                    rest = after;
                }
            }
        }
    }
    out
}

impl CompactRecord {
    /// Directory flag bit in raw NTFS `FILE_ATTRIBUTE_DIRECTORY`.
    const DIRECTORY_BIT: u32 = 0x0010;

    /// Returns `true` if this record is a directory.
    #[inline]
    #[must_use]
    pub const fn is_directory(self) -> bool {
        self.flags & Self::DIRECTORY_BIT != 0
    }

    /// Returns `true` if this record is one of the reserved NTFS metafiles
    /// (`$MFT`, `$LogFile`, `$Bitmap`, `$Secure`, the `$Extend` family, …).
    ///
    /// The cached [`name_first_byte`](Self::name_first_byte) field is a cheap
    /// gate: every metafile name starts with `$`, and `$`-prefixed records are
    /// a vanishing fraction of an index, so this rejects virtually every record
    /// with a single byte comparison and only touches the names arena for the
    /// handful of `$`-prefixed candidates.  The arena lookup is *required* for
    /// correctness, because an ordinary file may also start with `$`
    /// (`$Recycle.Bin`, `$PatchCache`, the `WinSxS` `$$_*.cdf-ms` filemaps) —
    /// those are NOT metafiles and must not be hidden by `--hide-system`.
    /// See [`is_ntfs_metafile_name`].
    #[inline]
    #[must_use]
    pub fn is_system_metafile(&self, names: &[u8]) -> bool {
        self.name_first_byte == b'$' && is_ntfs_metafile_name(self.name(names))
    }

    /// Get the name from a names blob as a **lossy `&str` view**.
    ///
    /// Valid-UTF-8 names (the common case) are returned verbatim; an ill-formed
    /// (surrogate-bearing) name stored as WTF-8 returns `""`. This is the
    /// cheap borrow used by internal hot paths (metafile check, fold/search
    /// keys); for anything **user-visible** prefer [`Self::name_display`],
    /// which renders ill-formed names lossily instead of emptying them (an
    /// empty segment collapses reconstructed paths). Use
    /// [`Self::name_bytes`] for the lossless bytes that exact/substring
    /// search matches against, so a file with an ill-formed name stays
    /// findable (WI-4.4).
    #[inline]
    #[must_use]
    pub fn name<'a>(&self, names: &'a [u8]) -> &'a str {
        core::str::from_utf8(self.name_bytes(names)).unwrap_or("")
    }

    /// Get the name as a **lossy display string** for paths and the name
    /// column.
    ///
    /// Valid-UTF-8 names (the overwhelming common case) are returned as a
    /// zero-cost `Cow::Borrowed`; an ill-formed (surrogate-bearing) name is
    /// rendered with U+FFFD (`�`) via [`String::from_utf8_lossy`] — preserving
    /// the entry's **position** instead of collapsing it to `""`, so a file
    /// under a malformed-named directory keeps its true path and stays visible
    /// (WI-4.4). Only the rare malformed case allocates, so the well-formed hot
    /// path is unaffected. Filtering malformed entries stays on the `malformed`
    /// flag (a real folder named `�` is not the same as a corrupt one); this
    /// accessor is purely for rendering.
    #[inline]
    #[must_use]
    pub fn name_display<'a>(&self, names: &'a [u8]) -> alloc::borrow::Cow<'a, str> {
        self.name_display_with(names, MalformedRender::Lossy)
    }

    /// Whether the stored name is ill-formed UTF-16 (its WTF-8 bytes are not
    /// valid UTF-8). Cheap; used to gate the lossy render and the malformed
    /// flag.
    #[inline]
    #[must_use]
    pub fn is_name_malformed(&self, names: &[u8]) -> bool {
        core::str::from_utf8(self.name_bytes(names)).is_err()
    }

    /// Like [`Self::name_display`] but choosing how an ill-formed name renders:
    /// [`MalformedRender::Lossy`] (U+FFFD) or [`MalformedRender::Normalized`]
    /// (`<BAD:HHHH>` markers, for `--normalize-malformed`). A valid name is a
    /// zero-cost `Cow::Borrowed` under either mode; only the rare malformed
    /// name allocates, so the well-formed hot path is identical to
    /// `name_display`.
    #[inline]
    #[must_use]
    pub fn name_display_with<'a>(
        &self,
        names: &'a [u8],
        render: MalformedRender,
    ) -> alloc::borrow::Cow<'a, str> {
        let bytes = self.name_bytes(names);
        // Well-formed (the overwhelming common case) → zero-cost borrow; an
        // ill-formed name renders one marker per offending code unit (U+FFFD or
        // `<BAD:HHHH>`), matching the reference tool's per-unit replacement.
        core::str::from_utf8(bytes).map_or_else(
            |_| alloc::borrow::Cow::Owned(render_malformed(bytes, render)),
            alloc::borrow::Cow::Borrowed,
        )
    }

    /// Get the name's **raw bytes** (WTF-8) from a names blob — the lossless
    /// accessor.
    ///
    /// Returns exactly the stored bytes, including the byte-faithful encoding
    /// of an ill-formed NTFS name (unpaired surrogates). This is what makes
    /// every file matchable/findable by its true name regardless of UTF-8
    /// well-formedness (WI-4.4). Returns `&[]` for an out-of-range slice.
    #[inline]
    #[must_use]
    pub fn name_bytes<'a>(&self, names: &'a [u8]) -> &'a [u8] {
        let start = self.name_offset as usize;
        let end = start.saturating_add(self.name_len as usize);
        names.get(start..end).unwrap_or(&[])
    }
}

// Compile-time size assertion.
const _: () = assert!(
    size_of::<CompactRecord>() == 88,
    "CompactRecord must be exactly 88 bytes"
);
