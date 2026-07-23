// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! NTFS-specific structures and parsing.
//!
//! This module provides low-level NTFS structure definitions for parsing
//! the Master File Table (MFT) directly from disk.
//!
//! # Safety
//!
//! These structures use `#[repr(C, packed)]` to match the on-disk layout.
//! Care must be taken when reading fields due to potential unaligned access.
//!
//! # Reference
//!
//! Based on NTFS on-disk format documentation and the Microsoft NTFS
//! specification.
//!
//! # Platform Support
//!
//! This module is cross-platform - NTFS structures are just byte layouts
//! and can be parsed on any platform.

mod boot_sector;
mod data_runs;
mod metadata;
mod records;
#[cfg(test)]
mod tests;

// Phase 3 — split re-exports by reachability from `lib.rs`.
//
// `pub use` for items that `crates/uffs-mft/src/lib.rs::pub use ntfs::{…}`
// re-publishes at crate root (external API).
//
// `pub(crate) use` for items only consumed within `uffs-mft` itself
// (kept as items here but not part of the crate's public surface).

pub use self::boot_sector::NtfsBootSector;
pub use self::data_runs::{
    DataRun, DataRunIter, data_runs_iter_from_attribute, extract_data_runs_from_attribute,
    parse_data_runs, parse_data_runs_iter,
};
pub use self::metadata::{
    AttributeListEntry, ExtendedStandardInfo, FileNameAttribute, IndexHeader, IndexRoot, NameInfo,
    ReparseMountPointBuffer, ReparsePointHeader, ReparseTag, StandardInformation, StreamInfo,
};
pub(crate) use self::metadata::{
    STANDARD_INFO_SIZE_V12, STANDARD_INFO_SIZE_V30, StandardInformationExtended,
    is_internal_windows_stream,
};
// `FILE_RECORD_MAGIC` is the on-disk magic value used by [`parse::fixup`] to
// recognise FILE records.  `SECTOR_SIZE_U64` is the u64 alias used by the
// Windows-only I/O readers.  Neither is part of the crate's public surface;
// `pub(crate) use` keeps them reachable through this module-level facade for
// internal consumers without re-publishing them externally.
pub(crate) use self::records::FILE_RECORD_MAGIC;
#[cfg(windows)]
pub(crate) use self::records::SECTOR_SIZE_U64;
pub use self::records::{
    AttributeIterator, AttributeRecordHeader, AttributeRef, AttributeType, FileRecordSegmentHeader,
    MultiSectorHeader, NonResidentAttributeData, ResidentAttributeData, SECTOR_SIZE,
    apply_usa_fixup, fixup_file_record,
};

/// Extracts the File Record Segment number from a file reference.
///
/// NTFS file references pack the FRS into the lower 48 bits and the
/// sequence number into the upper 16 bits.  Production code currently
/// only consumes the FRS half; the sequence-number extraction is
/// verified inline in `tests::file_reference_extraction` against the
/// bit layout this function relies on.
#[must_use]
pub(crate) const fn file_reference_to_frs(file_reference: u64) -> u64 {
    file_reference & 0x0000_FFFF_FFFF_FFFF
}
