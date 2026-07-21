// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Core per-record index types and packed name or stream metadata.
//!
//! `StandardInfo` lives in sibling module `standard_info.rs`.

use super::standard_info::StandardInfo;
use crate::frs::{Frs, ParentFrs};

// ============================================================================
// Constants
// ============================================================================

/// Sentinel value indicating "no entry" in linked-list fields.
pub const NO_ENTRY: u32 = u32::MAX;

/// Root directory FRS in NTFS — raw `u64` for external consumers (DTOs, wire
/// format, fixtures).  Internal code should prefer the typed [`Frs::ROOT`].
pub const ROOT_FRS: u64 = 5;

// ============================================================================
// IndexNameRef - Reference into names buffer
// ============================================================================

/// Reference to a filename in the contiguous names buffer.
///
/// Bit-packed structure: exactly 8 bytes, zero padding.
///
/// # Bit Layout of `meta` field:
/// - Bits 0-9:   UTF-8 length (max 1023 bytes)
/// - Bits 10-15: flags (`is_ascii`, etc.)
/// - Bits 16-31: `extension_id` (65K unique extensions)
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct IndexNameRef {
    /// Byte offset into `MftIndex::names`
    pub offset: u32,
    /// Packed metadata: length (10 bits) + flags (6 bits) + `extension_id` (16
    /// bits)
    pub meta: u32,
}

impl IndexNameRef {
    /// Bit mask for extracting length from meta field (bits 0-9)
    const LENGTH_MASK: u32 = 0x3FF;
    /// Bit shift for length field
    const LENGTH_SHIFT: u32 = 0;

    /// Bit mask for extracting flags from meta field (bits 10-15)
    const FLAGS_MASK: u32 = 0x3F << 10;
    /// Bit shift for flags field
    const FLAGS_SHIFT: u32 = 10;

    /// Bit mask for extracting extension ID from meta field (bits 16-31)
    const EXT_ID_MASK: u32 = 0xFFFF << 16;
    /// Bit shift for extension ID field
    const EXT_ID_SHIFT: u32 = 16;

    /// Flag bit indicating the name is pure ASCII
    const IS_ASCII: u32 = 1 << 0;

    /// No extension (`extension_id` = 0 means no extension)
    pub const NO_EXTENSION: u16 = 0;

    /// Creates a new `IndexNameRef` with the given offset, length, ASCII flag,
    /// and `extension_id`.
    #[must_use]
    pub const fn new(offset: u32, length: u16, is_ascii: bool, extension_id: u16) -> Self {
        let length_bits = (length as u32 & Self::LENGTH_MASK) << Self::LENGTH_SHIFT;
        let flags_bits = if is_ascii {
            Self::IS_ASCII << Self::FLAGS_SHIFT
        } else {
            0
        };
        let ext_id_bits = (extension_id as u32) << Self::EXT_ID_SHIFT;

        Self {
            offset,
            meta: length_bits | flags_bits | ext_id_bits,
        }
    }

    /// Returns the UTF-8 length in bytes.
    #[inline]
    #[must_use]
    pub const fn length(self) -> u16 {
        ((self.meta >> Self::LENGTH_SHIFT) & Self::LENGTH_MASK) as u16
    }

    /// Returns the raw flags field (6 bits).
    #[inline]
    #[must_use]
    pub const fn flags(self) -> u8 {
        ((self.meta >> Self::FLAGS_SHIFT) & (Self::FLAGS_MASK >> Self::FLAGS_SHIFT)) as u8
    }

    /// Returns the extension ID (0 = no extension).
    #[inline]
    #[must_use]
    pub const fn extension_id(self) -> u16 {
        ((self.meta >> Self::EXT_ID_SHIFT) & (Self::EXT_ID_MASK >> Self::EXT_ID_SHIFT)) as u16
    }

    /// Returns true if the name is pure ASCII.
    #[inline]
    #[must_use]
    pub const fn is_ascii(self) -> bool {
        (self.meta & (Self::IS_ASCII << Self::FLAGS_SHIFT)) != 0
    }

    /// Remap the `extension_id` to a new value.
    ///
    /// Used during fragment merging to remap extension IDs from fragment-local
    /// to merged-global space.
    #[inline]
    pub fn remap_extension_id(&mut self, new_extension_id: u16) {
        // Clear old extension_id bits and set new ones
        self.meta =
            (self.meta & !Self::EXT_ID_MASK) | (u32::from(new_extension_id) << Self::EXT_ID_SHIFT);
    }

    /// Returns true if this name reference is valid (not `NO_ENTRY`).
    #[inline]
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.offset != NO_ENTRY
    }
}

// ============================================================================
// LinkInfo - Hard link chain entry
// ============================================================================

/// Hard link information.
///
/// Most files have only one name, stored inline in `FileRecord::first_name`.
/// Files with multiple hard links form a linked list via `next_entry`.
/// [`ParentFrs`] is `#[repr(transparent)]` over `u64`, so on-disk layout
/// is byte-identical to the historic `u64` field.
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct LinkInfo {
    /// Index of next `LinkInfo` in `MftIndex::links`, or `NO_ENTRY`
    pub next_entry: u32,
    /// Filename reference
    pub name: IndexNameRef,
    /// Explicit padding for `u64` alignment of `parent_frs`.
    #[expect(
        clippy::pub_underscore_fields,
        reason = "bytemuck Pod requires all fields same visibility"
    )]
    pub _pad0: [u8; 4],
    /// Parent directory FRS (typed [`ParentFrs`]; `u64`-equivalent on disk).
    pub parent_frs: ParentFrs,
}

// ============================================================================
// SizeInfo - File size information
// ============================================================================

/// File size information.
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct SizeInfo {
    /// Logical file size
    pub length: u64,
    /// Allocated size on disk
    pub allocated: u64,
}

// ============================================================================
// IndexStreamInfo - Alternate Data Stream chain entry
// ============================================================================

/// Alternate Data Stream information.
///
/// Most files have only the default `$DATA` stream, stored inline.
/// Files with ADS form a linked list via `next_entry`.
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct IndexStreamInfo {
    /// Size information
    pub size: SizeInfo,
    /// Index of next `IndexStreamInfo` in `MftIndex::streams`, or `NO_ENTRY`
    pub next_entry: u32,
    /// Stream name reference (empty for default `$DATA`)
    pub name: IndexNameRef,
    /// Packed flags: bit 0 = `is_sparse`, bit 1 = `is_resident`, bits 2-7 =
    /// `type_name_id`
    pub flags: u8,
    /// Explicit tail padding for struct alignment.
    #[expect(
        clippy::pub_underscore_fields,
        reason = "bytemuck Pod requires all fields same visibility"
    )]
    pub _pad0: [u8; 3],
}

impl IndexStreamInfo {
    /// Returns true if this stream is sparse.
    #[inline]
    #[must_use]
    pub const fn is_sparse(&self) -> bool {
        self.flags & 0x01 != 0
    }
    /// Returns true if this stream's data is resident (stored in MFT record).
    #[inline]
    #[must_use]
    pub const fn is_resident(&self) -> bool {
        self.flags & 0x02 != 0
    }
    /// Returns the type name ID for this stream.
    #[inline]
    #[must_use]
    pub const fn type_name_id(&self) -> u8 {
        self.flags >> 2
    }

    /// Returns true if this stream should be included in output.
    ///
    /// Only `$DATA` streams (`type_name_id=8`, i.e., `0x80 >> 4`) and directory
    /// indexes (`type_name_id=0` for `$I30`) are included. Internal attributes
    /// like `$OBJECT_ID` (`type_name_id=4`), `$EA_INFORMATION`
    /// (`type_name_id=13`) are filtered out.
    #[inline]
    #[must_use]
    pub const fn is_output_stream(&self) -> bool {
        let tid = self.type_name_id();
        // type_name_id == 0: directory index ($I30)
        // type_name_id == 8: $DATA (0x80 >> 4)
        tid == 0 || tid == 8
    }
}

// ============================================================================
// ============================================================================
// InternalStreamInfo - Internal NTFS stream chain entry
// ============================================================================

/// Internal NTFS attribute stream information.
///
/// These correspond to internal attributes counted during tree metrics (for
/// example `$REPARSE_POINT`, `$SECURITY_DESCRIPTOR`, and `$OBJECT_ID`) but not
/// exposed as user-visible ADS rows.
///
/// They are stored separately so proportional hard-link attribution can be
/// applied per stream (the delta is not additive after integer rounding).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct InternalStreamInfo {
    /// Size information for the internal stream.
    pub size: SizeInfo,
    /// Index of next `InternalStreamInfo` in `MftIndex::internal_streams`, or
    /// `NO_ENTRY`.
    pub next_entry: u32,
    /// Packed flags (`bit0=is_sparse`, `bit1=is_resident`). Other bits are
    /// reserved.
    pub flags: u8,
}

// ============================================================================
// FileRecord - Core file metadata
// ============================================================================

/// Core file and directory record.
///
/// 240 bytes per record (with explicit padding).  Derives `bytemuck::Pod`
/// so the entire record array can be serialized/deserialized as a single
/// `memcpy`.
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct FileRecord {
    /// FRS number — primary key (typed [`Frs`]; `u64`-equivalent on disk).
    pub frs: Frs,
    /// Sequence number (incremented when FRS is reused, forensic value)
    pub sequence_number: u16,
    /// Primary filename namespace (0=POSIX, 1=Win32, 2=DOS, 3=Win32+DOS)
    pub namespace: u8,
    /// Forensic flags (bit-packed): bit 0 = `is_deleted`, bit 1 = `is_corrupt`,
    /// bit 2 = `is_extension`, bit 3 = `has_default_data` (unnamed $DATA
    /// found), bit 4 = `has_i30_stream`, bit 5 = `is_unified` (created by
    /// unified parser)
    pub forensic_flags: u8,
    /// Explicit padding for `u64` alignment of `lsn`.
    #[expect(
        clippy::pub_underscore_fields,
        reason = "bytemuck Pod requires all fields same visibility"
    )]
    pub _pad0: [u8; 4],
    /// Log File Sequence Number - correlates with `$LogFile` journal (forensic)
    pub lsn: u64,
    /// Reparse tag from `$REPARSE_POINT` (0 if not a reparse point).
    pub reparse_tag: u32,
    /// Explicit padding for `u64` alignment of `base_frs`.
    #[expect(
        clippy::pub_underscore_fields,
        reason = "bytemuck Pod requires all fields same visibility"
    )]
    pub _pad1: [u8; 4],
    /// Base FRS for extension records ([`Frs::ZERO`] for base records).
    pub base_frs: Frs,
    /// Timestamps and bit-packed attributes from `$STANDARD_INFORMATION`
    pub stdinfo: StandardInfo,
    /// Number of hard links (usually 1)
    pub name_count: u16,
    /// Number of user-visible data streams (usually 1)
    pub stream_count: u16,
    /// Total number of all streams including internal Windows streams.
    pub total_stream_count: u16,
    /// Explicit padding for `u32` alignment of `first_internal_stream`.
    #[expect(
        clippy::pub_underscore_fields,
        reason = "bytemuck Pod requires all fields same visibility"
    )]
    pub _pad2: [u8; 2],
    /// Head of linked list of internal streams (`NO_ENTRY` if none)
    pub first_internal_stream: u32,
    /// Index of first child in `MftIndex::children`, or `NO_ENTRY`
    pub first_child: u32,
    /// Primary filename (inline, no allocation)
    pub first_name: LinkInfo,
    /// Primary data stream (inline, no allocation)
    pub first_stream: IndexStreamInfo,

    // $FILE_NAME timestamps (often differ from $STANDARD_INFORMATION)
    /// Creation time from `$FILE_NAME` (Unix microseconds)
    pub fn_created: i64,
    /// Modification time from `$FILE_NAME` (Unix microseconds)
    pub fn_modified: i64,
    /// Access time from `$FILE_NAME` (Unix microseconds)
    pub fn_accessed: i64,
    /// MFT change time from `$FILE_NAME` (Unix microseconds)
    pub fn_mft_changed: i64,

    // Tree metrics
    /// Count of all descendants in subtree (0 for files)
    pub descendants: u32,
    /// Explicit padding for `u64` alignment of `treesize`.
    #[expect(
        clippy::pub_underscore_fields,
        reason = "bytemuck Pod requires all fields same visibility"
    )]
    pub _pad3: [u8; 4],
    /// Sum of logical file sizes in subtree
    pub treesize: u64,
    /// Sum of allocated disk sizes in subtree
    pub tree_allocated: u64,

    /// Size of internal Windows streams (filtered from output, included in
    /// tree metrics)
    pub internal_streams_size: u64,
    /// Allocated size of internal Windows streams.
    pub internal_streams_allocated: u64,
}

impl FileRecord {
    /// Create a new record for the given FRS.
    #[must_use]
    pub fn new(frs: Frs) -> Self {
        Self {
            frs,
            name_count: 1,         // Every file has at least one name
            stream_count: 1,       // User-visible streams (default $DATA)
            total_stream_count: 1, // All streams including internal (for tree metrics)
            first_internal_stream: NO_ENTRY,
            first_child: NO_ENTRY,
            first_name: LinkInfo {
                next_entry: NO_ENTRY,
                name: IndexNameRef {
                    offset: NO_ENTRY,
                    meta: 0,
                },
                _pad0: [0; 4],
                parent_frs: ParentFrs::new(u64::from(NO_ENTRY)),
            },
            first_stream: IndexStreamInfo {
                next_entry: NO_ENTRY,
                name: IndexNameRef {
                    offset: NO_ENTRY,
                    meta: 0,
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Create a new record with zero-based counts.
    ///
    /// Unlike [`new()`](Self::new) which initialises counts at 1 (assuming
    /// every record will have at least one name and one stream), this
    /// constructor starts all counts at 0.  The unified parser
    /// (`process_record`) then increments them for **every** accepted
    /// attribute, including the first, producing correct-by-construction
    /// values that match the unified parser's expectations.
    #[must_use]
    pub(crate) fn new_unified(frs: Frs) -> Self {
        Self {
            frs,
            forensic_flags: 0b10_0000, // bit 5: is_unified
            name_count: 0,
            stream_count: 0,
            total_stream_count: 0,
            first_internal_stream: NO_ENTRY,
            first_child: NO_ENTRY,
            first_name: LinkInfo {
                next_entry: NO_ENTRY,
                name: IndexNameRef {
                    offset: NO_ENTRY,
                    meta: 0,
                },
                _pad0: [0; 4],
                parent_frs: ParentFrs::new(u64::from(NO_ENTRY)),
            },
            first_stream: IndexStreamInfo {
                size: SizeInfo::default(),
                next_entry: NO_ENTRY,
                name: IndexNameRef {
                    offset: NO_ENTRY,
                    meta: 0,
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Returns true if this record is a directory.
    #[inline]
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        self.stdinfo.is_directory()
    }
    /// Returns true if this record has a valid name.
    #[inline]
    #[must_use]
    pub const fn has_name(&self) -> bool {
        self.first_name.name.is_valid()
    }

    /// Returns true if this record has base record data (not just extension
    /// data).
    ///
    /// A placeholder created by extension record processing will have a name
    /// (from the extension) but no stdinfo (created timestamp = 0). A real base
    /// record will have non-zero timestamps from `$STANDARD_INFORMATION`.
    ///
    /// This is used during fragment merging to determine which record to keep
    /// when both have names.
    #[inline]
    #[must_use]
    pub const fn has_base_data(&self) -> bool {
        // Real base records always have a creation timestamp from $STANDARD_INFORMATION
        // Placeholders created by extension processing have stdinfo = Default (all
        // zeros)
        self.stdinfo.created != 0
    }

    // ===== P3 Forensic Flag Accessors =====
    //
    // `forensic_flags` bit layout — the whole byte, not just the forensic bits:
    //
    //   bit 0  is_deleted         bit 3  has_default_data
    //   bit 1  is_corrupt         bit 4  has_i30_stream
    //   bit 2  is_extension       bit 5  is_unified
    //                             bits 6-7  free
    //
    // Only bits 0-2 are forensic. Bits 3-5 are parser bookkeeping written by
    // their own setters (`set_has_default_data`, `set_has_i30_stream`,
    // `set_unified`), which is exactly why `set_forensic_flags` masks them
    // through with `& 0b11_1000` instead of overwriting the byte.
    //
    // A new flag must take bit 6 or 7. Bit 3 in particular feeds
    // `compute_tree_metrics`, where it distinguishes "empty $DATA" from "no
    // $DATA" — clobbering it surfaces as wrong `treesize` / `tree_allocated`,
    // far from the cause. Keep this list complete: the previous version stopped
    // after bit 2 and read as "bit 3 onwards is free".

    /// Returns true if this record is deleted (MFT record not in use).
    /// Only meaningful when parsed with `--forensic` flag.
    #[inline]
    #[must_use]
    pub const fn is_deleted(&self) -> bool {
        self.forensic_flags & 0b001 != 0
    }

    /// Returns true if this record is corrupt (USA fixup failed or BAAD magic).
    /// Only meaningful when parsed with `--forensic` flag.
    #[inline]
    #[must_use]
    pub const fn is_corrupt(&self) -> bool {
        self.forensic_flags & 0b010 != 0
    }

    /// Returns true if this is an extension record (not a base record).
    /// Only meaningful when parsed with `--forensic` flag.
    #[inline]
    #[must_use]
    pub const fn is_extension(&self) -> bool {
        self.forensic_flags & 0b100 != 0
    }

    /// Sets the forensic flags from parsed record fields.
    #[inline]
    pub(crate) fn set_forensic_flags(
        &mut self,
        is_deleted: bool,
        is_corrupt: bool,
        is_extension: bool,
    ) {
        // Preserve bits 3-5 (has_default_data, has_i30_stream, is_unified)
        // when setting forensic bits
        self.forensic_flags = (self.forensic_flags & 0b11_1000)
            | u8::from(is_deleted)
            | (u8::from(is_corrupt) << 1_u8)
            | (u8::from(is_extension) << 2_u8);
    }

    /// Returns true if an unnamed `$DATA` attribute was found during parsing.
    /// Used by tree metrics to distinguish "has empty $DATA" from "has no
    /// $DATA".
    #[inline]
    #[must_use]
    pub const fn has_default_data(&self) -> bool {
        self.forensic_flags & 0b1000 != 0
    }

    /// Marks that an unnamed `$DATA` attribute was found during parsing.
    #[inline]
    pub const fn set_has_default_data(&mut self) {
        self.forensic_flags |= 0b1000;
    }

    /// Returns true if an `$I30` directory-index stream was counted for this
    /// record.  Used by the unified parser to avoid double-counting when
    /// multiple `$I30`-contributing attributes (`$INDEX_ROOT`,
    /// `$INDEX_ALLOCATION`, `$BITMAP`) appear in the same or extension
    /// records.
    #[inline]
    #[must_use]
    pub const fn has_i30_stream(&self) -> bool {
        self.forensic_flags & 0b1_0000 != 0
    }

    /// Marks that an `$I30` stream was counted for this record.
    #[inline]
    pub const fn set_has_i30_stream(&mut self) {
        self.forensic_flags |= 0b1_0000;
    }

    /// Returns true if this record was created by the unified parser
    /// (`new_unified`).  Records from the legacy `new()` constructor do not
    /// have this flag.  Used by `compute_tree_metrics` to decide whether the
    /// `has_default_data` correction hack is needed.
    #[inline]
    #[must_use]
    pub const fn is_unified(&self) -> bool {
        self.forensic_flags & 0b10_0000 != 0
    }

    /// Marks this record as created by the unified parser.
    #[inline]
    pub const fn set_unified(&mut self) {
        self.forensic_flags |= 0b10_0000;
    }

    /// Returns the tree metrics tuple (descendants, treesize,
    /// `tree_allocated`).
    ///
    /// This is the **single source of truth** for tree metrics extraction.
    /// Both OFFLINE (`MftIndex::to_dataframe`) and LIVE
    /// (`results_to_dataframe`) paths should use this method to ensure
    /// consistent behavior.
    ///
    /// # Tree-metrics Notes
    ///
    /// - Directories (including reparse points like junctions/symlinks) always
    ///   return their computed tree metrics. Junctions are directory leaves
    ///   with `descendants=1`, not files with `descendants=0`.
    /// - Files return `descendants=0` and their own size/allocated values.
    #[inline]
    #[must_use]
    pub const fn tree_metrics(&self) -> (u32, u64, u64) {
        (self.descendants, self.treesize, self.tree_allocated)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Compare two strings case-insensitively (zero allocations for ASCII).
///
/// For ASCII strings, this performs a zero-allocation comparison by comparing
/// bytes after converting to lowercase. For non-ASCII strings, it falls back
/// to allocating lowercase versions.
#[cfg(test)]
pub(crate) fn cmp_ascii_case_insensitive(str_a: &str, str_b: &str) -> core::cmp::Ordering {
    if str_a.is_ascii() && str_b.is_ascii() {
        // Fast path: both strings are ASCII
        str_a
            .bytes()
            .map(|byte| byte.to_ascii_lowercase())
            .cmp(str_b.bytes().map(|byte| byte.to_ascii_lowercase()))
    } else {
        // Slow path: at least one string contains non-ASCII characters
        str_a.to_lowercase().cmp(&str_b.to_lowercase())
    }
}
