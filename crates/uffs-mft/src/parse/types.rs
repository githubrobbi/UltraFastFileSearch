// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Shared types and parse results used across the MFT parsing pipeline.

use crate::ntfs::{ExtendedStandardInfo, NameInfo, StreamInfo};

/// Parsed data from an MFT record (full legacy-output parity).
///
/// This struct captures ALL information from an MFT record, including:
/// - Multiple file names (hard links)
/// - Multiple data streams (Alternate Data Streams)
/// - Extended size information (allocated, compressed)
/// - All 18 attribute flags
/// - Sequence number (for detecting reused FRS)
/// - Log File Sequence Number (LSN) for journal correlation
/// - `$FILE_NAME` timestamps (often differ from `$STANDARD_INFORMATION`)
#[derive(Debug, Clone, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "forensic fields require multiple bool flags"
)]
pub struct ParsedRecord {
    /// File Record Segment number.
    pub frs: crate::frs::Frs,
    /// Sequence number (incremented when FRS is reused).
    pub sequence_number: u16,
    /// Log File Sequence Number - correlates with `$LogFile` journal.
    pub lsn: u64,
    /// Primary parent directory FRS (from best name).
    pub parent_frs: crate::frs::ParentFrs,
    /// Primary file name (Win32 or Win32+DOS preferred).
    pub name: String,
    /// Primary filename namespace (0=POSIX, 1=Win32, 2=DOS, 3=Win32+DOS).
    pub namespace: u8,
    /// All file names (hard links). Includes primary name.
    pub names: Vec<NameInfo>,
    /// All data streams. First is the default (unnamed) stream.
    pub streams: Vec<StreamInfo>,
    /// Logical file size (from default stream).
    pub size: u64,
    /// Allocated size on disk.
    pub allocated_size: u64,
    /// Extended standard information with all flags.
    pub std_info: ExtendedStandardInfo,
    /// Whether this record is in use.
    pub in_use: bool,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// Creation time from primary `$FILE_NAME` (raw FILETIME: 100-ns ticks
    /// since 1601-01-01).
    pub fn_created: i64,
    /// Modification time from primary `$FILE_NAME` (raw FILETIME).
    pub fn_modified: i64,
    /// Access time from primary `$FILE_NAME` (raw FILETIME).
    pub fn_accessed: i64,
    /// MFT change time from primary `$FILE_NAME` (raw FILETIME).
    pub fn_mft_changed: i64,
    /// Reparse tag from `$REPARSE_POINT` attribute (0 if not a reparse point).
    /// Common values: symlink (0xA000000C), junction (0xA0000003), `OneDrive`,
    /// etc.
    pub reparse_tag: u32,
    /// How `$STANDARD_INFORMATION` decoded for this record.
    ///
    /// Consult this before trusting [`Self::std_info`]: on
    /// [`Malformed`](crate::parse::StdInfoParse::Malformed) and
    /// [`Absent`](crate::parse::StdInfoParse::Absent) its timestamps are
    /// struct defaults (FILETIME `0` = 1601-01-01), which is
    /// indistinguishable from a real 1601-01-01 record by value alone.
    pub std_info_parse: crate::parse::StdInfoParse,

    // P3 Forensic fields (populated when ParseOptions::forensic is true)
    /// True if this record is deleted (`FRH_IN_USE` flag not set).
    /// Only populated when parsing with `ParseOptions::include_deleted`.
    pub is_deleted: bool,
    /// True if this record has corrupt fixup (USA mismatch).
    /// Only populated when parsing with `ParseOptions::include_corrupt`.
    pub is_corrupt: bool,
    /// True if this is an extension record (not a base record).
    /// Only populated when parsing with `ParseOptions::include_extensions`.
    pub is_extension: bool,
    /// Base FRS for extension records (`Frs::ZERO` for base records).
    /// Only meaningful when `is_extension` is true.
    pub base_frs: crate::frs::Frs,
}

impl ParsedRecord {
    /// Returns the number of hard links (names).
    #[must_use]
    pub fn name_count(&self) -> u16 {
        crate::index::len_to_u16(self.names.len())
    }

    /// Returns the number of data streams.
    #[must_use]
    pub fn stream_count(&self) -> u16 {
        crate::index::len_to_u16(self.streams.len())
    }

    /// Returns the creation time (Unix microseconds).
    #[must_use]
    pub const fn created(&self) -> i64 {
        self.std_info.created
    }

    /// Returns the modification time (Unix microseconds).
    #[must_use]
    pub const fn modified(&self) -> i64 {
        self.std_info.modified
    }

    /// Returns the access time (Unix microseconds).
    #[must_use]
    pub const fn accessed(&self) -> i64 {
        self.std_info.accessed
    }

    /// Returns the MFT change time (Unix microseconds).
    #[must_use]
    pub const fn mft_changed(&self) -> i64 {
        self.std_info.mft_changed
    }

    /// Returns the raw flags as u16 (for backward compatibility).
    #[must_use]
    pub fn flags(&self) -> u16 {
        (self.std_info.to_raw_flags() & 0xFFFF) as u16
    }
}

/// Attributes extracted from an extension record.
///
/// Extension records contain additional attributes for files that don't
/// fit in a single MFT record. These must be merged into the base record.
#[derive(Debug, Clone, Default)]
pub struct ExtensionAttributes {
    /// The base FRS this extension belongs to.
    pub base_frs: crate::frs::Frs,
    /// The extension's own FRS.
    pub extension_frs: crate::frs::Frs,
    /// File names found in this extension.
    pub names: Vec<NameInfo>,
    /// Streams found in this extension.
    pub streams: Vec<StreamInfo>,
    /// Directory index size from `$I30` attributes in this extension.
    /// This is accumulated from `$INDEX_ROOT` and `$INDEX_ALLOCATION`
    /// attributes with name `$I30` (excludes `$BITMAP` for legacy-output
    /// parity).
    pub dir_index_size: u64,
    /// Directory index allocated size from $I30 attributes in this extension.
    pub dir_index_allocated: u64,
}

/// Result of parsing an MFT record.
#[derive(Debug, Clone)]
pub enum ParseResult {
    /// A base record with all its data.
    Base(ParsedRecord),
    /// An extension record with attributes to merge.
    Extension(ExtensionAttributes),
    /// Record is not in use or invalid.
    Skip,
}

/// Options for MFT record parsing.
///
/// By default, parsing skips deleted records, corrupt records, and merges
/// extension records into their base records. Forensic mode enables
/// extraction of these records for analysis.
///
/// # Performance Impact
///
/// - `include_deleted`: +10-50% more records (significant memory/CPU impact)
/// - `include_corrupt`: Minimal impact (corrupt records are rare)
/// - `include_extensions`: Minimal impact (extensions are rare, ~0.1% of
///   records)
#[derive(Debug, Clone, Copy, Default)]
pub struct ParseOptions {
    /// Include deleted records (`FRH_IN_USE` flag not set).
    /// These records may have partial/stale data but are valuable for
    /// forensics.
    pub include_deleted: bool,
    /// Include corrupt records (USA fixup failed).
    /// These records have torn writes but may still contain recoverable data.
    pub include_corrupt: bool,
    /// Include extension records as separate rows instead of merging.
    /// Useful for analyzing fragmented files with many attributes.
    pub include_extensions: bool,
}

impl ParseOptions {
    /// Default options: skip deleted, corrupt, and merge extensions.
    pub const DEFAULT: Self = Self {
        include_deleted: false,
        include_corrupt: false,
        include_extensions: false,
    };

    /// Forensic mode: include all records for analysis.
    pub const FORENSIC: Self = Self {
        include_deleted: true,
        include_corrupt: true,
        include_extensions: true,
    };

    /// Returns true if any forensic options are enabled.
    #[inline]
    #[must_use]
    pub const fn is_forensic(self) -> bool {
        self.include_deleted || self.include_corrupt || self.include_extensions
    }
}
