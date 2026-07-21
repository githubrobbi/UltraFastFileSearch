// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! NTFS attribute payloads and legacy-output metadata helpers.

use core::mem::size_of;

use zerocopy::{FromBytes, Immutable, KnownLayout};

/// Standard Information attribute content (NTFS 1.2 - 36 bytes).
///
/// Contains timestamps and basic file attributes.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct StandardInformation {
    /// File creation time (FILETIME).
    pub creation_time: i64,
    /// Last modification time (FILETIME).
    pub modification_time: i64,
    /// Last MFT change time (FILETIME).
    pub mft_change_time: i64,
    /// Last access time (FILETIME).
    pub access_time: i64,
    /// File attributes (same as DOS attributes).
    pub file_attributes: u32,
}

/// Standard Information attribute content (NTFS 3.0+ - 72 bytes).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub(crate) struct StandardInformationExtended {
    /// File creation time (FILETIME).
    pub creation_time: i64,
    /// Last modification time (FILETIME).
    pub modification_time: i64,
    /// Last MFT change time (FILETIME).
    pub mft_change_time: i64,
    /// Last access time (FILETIME).
    pub access_time: i64,
    /// File attributes (same as DOS attributes).
    pub file_attributes: u32,
    /// Maximum number of versions (usually 0).
    pub max_versions: u32,
    /// Version number (usually 0).
    pub version_number: u32,
    /// Class ID (usually 0).
    pub class_id: u32,
    /// Owner ID for quota tracking.
    pub owner_id: u32,
    /// Security ID - index into `$Secure` file.
    pub security_id: u32,
    /// Quota charged (bytes charged to user's quota).
    pub quota_charged: u64,
    /// Update Sequence Number - correlates with USN journal.
    pub usn: u64,
}

/// Size of NTFS 1.2 `$STANDARD_INFORMATION` (36 bytes).
pub(crate) const STANDARD_INFO_SIZE_V12: usize = 36;

/// Size of NTFS 3.0+ `$STANDARD_INFORMATION` (72 bytes).
pub(crate) const STANDARD_INFO_SIZE_V30: usize = 72;

/// File Name attribute content.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct FileNameAttribute {
    /// Parent directory file reference.
    pub parent_directory: u64,
    /// File creation time.
    pub creation_time: i64,
    /// Last modification time.
    pub modification_time: i64,
    /// Last MFT change time.
    pub mft_change_time: i64,
    /// Last access time.
    pub access_time: i64,
    /// Allocated size.
    pub allocated_size: i64,
    /// Real size (data size).
    pub data_size: i64,
    /// File attributes.
    pub file_attributes: u32,
    /// Packed EA size / reparse tag.
    pub packed_ea_size: u16,
    /// Reserved.
    pub reserved: u16,
    /// File name length in characters.
    pub file_name_length: u8,
    /// File name namespace.  NTFS spec values: `0` = POSIX
    /// (case-sensitive), `1` = Win32 (case-insensitive), `2` = DOS
    /// (8.3 short name), `3` = Win32 and DOS (valid for both).
    pub file_name_namespace: u8,
}

impl FileNameAttribute {
    /// Returns the parent directory FRS (lower 48 bits).
    #[must_use]
    pub const fn parent_frs(&self) -> u64 {
        self.parent_directory & 0x0000_FFFF_FFFF_FFFF
    }

    /// Returns the parent directory sequence number (upper 16 bits).
    #[must_use]
    pub const fn parent_sequence(&self) -> u16 {
        (self.parent_directory >> 48_i32) as u16
    }
}

/// Reparse point type flags.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReparseTag {
    /// Mount point (junction).
    MountPoint = 0xA000_0003,
    /// Symbolic link.
    SymbolicLink = 0xA000_000C,
    /// WOF compressed file.
    WofCompressed = 0x8000_0017,
    /// Windows Container Image.
    WindowsContainerImage = 0x8000_0018,
    /// Global reparse.
    GlobalReparse = 0x8000_0019,
    /// App execution link.
    AppExecLink = 0x8000_001B,
    /// OneDrive/Cloud.
    Cloud = 0x9000_001A,
    /// GVFS.
    Gvfs = 0x9000_001C,
    /// Linux symbolic link (WSL).
    LinuxSymbolicLink = 0xA000_001D,
}

/// Reparse point header.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct ReparsePointHeader {
    /// Reparse tag.
    pub reparse_tag: u32,
    /// Data length (excluding header).
    pub data_length: u16,
    /// Reserved.
    pub reserved: u16,
}

/// Mount point / symbolic link reparse data buffer.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct ReparseMountPointBuffer {
    /// Offset of the substitute name in `PathBuffer` (in bytes).
    pub substitute_name_offset: u16,
    /// Length of the substitute name (in bytes).
    pub substitute_name_length: u16,
    /// Offset of the print name in `PathBuffer` (in bytes).
    pub print_name_offset: u16,
    /// Length of the print name (in bytes).
    pub print_name_length: u16,
}

/// Attribute List entry.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct AttributeListEntry {
    /// Attribute type code.
    pub attribute_type: u32,
    /// Length of this entry.
    pub length: u16,
    /// Length of the attribute name (in characters).
    pub name_length: u8,
    /// Offset to the attribute name.
    pub name_offset: u8,
    /// Starting VCN (for non-resident attributes).
    pub start_vcn: u64,
    /// File reference of the MFT record containing this attribute.
    pub file_reference: u64,
    /// Attribute instance number.
    pub attribute_id: u16,
}

impl AttributeListEntry {
    /// Returns the FRS of the record containing this attribute.
    #[must_use]
    pub const fn target_frs(&self) -> u64 {
        self.file_reference & 0x0000_FFFF_FFFF_FFFF
    }

    /// Returns the sequence number of the target record.
    #[must_use]
    pub const fn target_sequence(&self) -> u16 {
        (self.file_reference >> 48_i32) as u16
    }
}

/// Index header (common to `INDEX_ROOT` and `INDEX_ALLOCATION`).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct IndexHeader {
    /// Offset to the first index entry (from start of this header).
    pub first_entry_offset: u32,
    /// Offset to the first free byte (total size of entries).
    pub first_free_byte: u32,
    /// Allocated size of the index entries.
    pub bytes_available: u32,
    /// Flags: 0x01 = has `INDEX_ALLOCATION` (large index).
    pub flags: u8,
    /// Reserved.
    pub reserved: [u8; 3],
}

impl IndexHeader {
    /// Returns true if this index has an `INDEX_ALLOCATION` attribute.
    #[must_use]
    pub const fn has_index_allocation(&self) -> bool {
        (self.flags & 0x01) != 0
    }
}

/// Index root attribute content (0x90).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct IndexRoot {
    /// Type of the indexed attribute (usually 0x30 for `$FILE_NAME`).
    pub indexed_attribute_type: u32,
    /// Collation rule.
    pub collation_rule: u32,
    /// Size of each index block (in bytes).
    pub bytes_per_index_block: u32,
    /// Clusters per index block.
    pub clusters_per_index_block: u8,
    /// Padding.
    pub padding: [u8; 3],
    /// Index header.
    pub header: IndexHeader,
}

/// Information about a single file name (hard link).
#[derive(Debug, Clone, Default)]
pub struct NameInfo {
    /// The file name.
    pub name: String,
    /// Parent directory FRS.
    pub parent_frs: crate::frs::ParentFrs,
    /// Namespace (0=POSIX, 1=Win32, 2=DOS, 3=Win32+DOS).
    pub namespace: u8,
    /// Creation time from `$FILE_NAME` (Unix microseconds).
    pub fn_created: i64,
    /// Modification time from `$FILE_NAME` (Unix microseconds).
    pub fn_modified: i64,
    /// Access time from `$FILE_NAME` (Unix microseconds).
    pub fn_accessed: i64,
    /// MFT change time from `$FILE_NAME` (Unix microseconds).
    pub fn_mft_changed: i64,
    /// FRS of the MFT record this name was parsed from (base or extension).
    pub source_frs: crate::frs::Frs,
}

/// Information about a single data stream.
#[derive(Debug, Clone, Default)]
pub struct StreamInfo {
    /// Stream name (empty for default stream).
    pub name: String,
    /// Logical size in bytes.
    pub size: u64,
    /// Allocated size on disk.
    pub allocated_size: u64,
    /// Whether this stream is sparse.
    pub is_sparse: bool,
    /// Whether this stream is compressed.
    pub is_compressed: bool,
    /// Whether this stream's data is resident (stored in MFT record itself).
    pub is_resident: bool,
}

/// Extended standard information with individual flags.
#[derive(Debug, Clone, Copy, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "NTFS has many boolean attribute flags"
)]
pub struct ExtendedStandardInfo {
    /// File creation time (Unix microseconds).
    pub created: i64,
    /// Last modification time (Unix microseconds).
    pub modified: i64,
    /// Last access time (Unix microseconds).
    pub accessed: i64,
    /// MFT record change time (Unix microseconds).
    pub mft_changed: i64,
    /// Update Sequence Number - correlates with USN journal (`$UsnJrnl`).
    pub usn: u64,
    /// Security ID - index into `$Secure` file for ACL lookup.
    pub security_id: u32,
    /// Owner ID - for quota tracking.
    pub owner_id: u32,
    /// Quota charged - bytes charged to the owner's quota.
    ///
    /// Zero on NTFS 1.2 records and on volumes without quotas enabled.
    pub quota_charged: u64,
    /// Maximum number of versions (usually 0).
    ///
    /// Zero on NTFS 1.2 records, which have no such field.
    pub max_versions: u32,
    /// Version number (usually 0).
    ///
    /// Zero on NTFS 1.2 records, which have no such field.
    pub version_number: u32,
    /// Class ID (usually 0).
    ///
    /// Zero on NTFS 1.2 records, which have no such field.
    pub class_id: u32,
    /// Read-only flag.
    pub is_readonly: bool,
    /// Hidden flag.
    pub is_hidden: bool,
    /// System flag.
    pub is_system: bool,
    /// Archive flag.
    pub is_archive: bool,
    /// Device flag.
    pub is_device: bool,
    /// Normal flag.
    pub is_normal: bool,
    /// Temporary flag.
    pub is_temporary: bool,
    /// Sparse file flag.
    pub is_sparse: bool,
    /// Reparse point flag.
    pub is_reparse: bool,
    /// Compressed flag.
    pub is_compressed: bool,
    /// Offline flag.
    pub is_offline: bool,
    /// Not content indexed flag.
    pub is_not_content_indexed: bool,
    /// Encrypted flag.
    pub is_encrypted: bool,
    /// Integrity stream flag.
    pub is_integrity_stream: bool,
    /// Virtual flag.
    pub is_virtual: bool,
    /// No scrub data flag.
    pub is_no_scrub_data: bool,
    /// Pinned flag.
    pub is_pinned: bool,
    /// Unpinned flag.
    pub is_unpinned: bool,
}

impl ExtendedStandardInfo {
    /// Creates from raw file attributes.
    #[must_use]
    pub(crate) fn from_attributes(attrs: u32) -> Self {
        Self {
            is_readonly: (attrs & 0x0001) != 0,
            is_hidden: (attrs & 0x0002) != 0,
            is_system: (attrs & 0x0004) != 0,
            is_archive: (attrs & 0x0020) != 0,
            is_device: (attrs & 0x0040) != 0,
            is_normal: (attrs & 0x0080) != 0,
            is_temporary: (attrs & 0x0100) != 0,
            is_sparse: (attrs & 0x0200) != 0,
            is_reparse: (attrs & 0x0400) != 0,
            is_compressed: (attrs & 0x0800) != 0,
            is_offline: (attrs & 0x1000) != 0,
            is_not_content_indexed: (attrs & 0x2000) != 0,
            is_encrypted: (attrs & 0x4000) != 0,
            is_integrity_stream: (attrs & 0x8000) != 0,
            is_virtual: (attrs & 0x0001_0000) != 0,
            is_no_scrub_data: (attrs & 0x0002_0000) != 0,
            is_pinned: (attrs & 0x0008_0000) != 0,
            is_unpinned: (attrs & 0x0010_0000) != 0,
            ..Default::default()
        }
    }

    /// Returns the raw flags as u32.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "can't be const due to if statements"
    )]
    pub(crate) fn to_raw_flags(self) -> u32 {
        let mut flags = 0_u32;
        if self.is_readonly {
            flags |= 0x0001;
        }
        if self.is_hidden {
            flags |= 0x0002;
        }
        if self.is_system {
            flags |= 0x0004;
        }
        if self.is_archive {
            flags |= 0x0020;
        }
        if self.is_device {
            flags |= 0x0040;
        }
        if self.is_normal {
            flags |= 0x0080;
        }
        if self.is_temporary {
            flags |= 0x0100;
        }
        if self.is_sparse {
            flags |= 0x0200;
        }
        if self.is_reparse {
            flags |= 0x0400;
        }
        if self.is_compressed {
            flags |= 0x0800;
        }
        if self.is_offline {
            flags |= 0x1000;
        }
        if self.is_not_content_indexed {
            flags |= 0x2000;
        }
        if self.is_encrypted {
            flags |= 0x4000;
        }
        if self.is_integrity_stream {
            flags |= 0x8000;
        }
        if self.is_virtual {
            flags |= 0x0001_0000;
        }
        if self.is_no_scrub_data {
            flags |= 0x0002_0000;
        }
        if self.is_pinned {
            flags |= 0x0008_0000;
        }
        if self.is_unpinned {
            flags |= 0x0010_0000;
        }
        flags
    }
}

/// Checks if a stream name is an internal Windows stream that should be
/// filtered out during output expansion.
#[inline]
#[must_use]
pub(crate) fn is_internal_windows_stream(name: &str) -> bool {
    name.strip_prefix('$').is_some_and(|rest| {
        rest.chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_uppercase())
    })
}

#[expect(
    clippy::missing_assert_message,
    reason = "compile-time size checks; messages not needed"
)]
const _: () = {
    assert!(size_of::<StandardInformation>() == 36);
    assert!(size_of::<FileNameAttribute>() == 66);
    assert!(size_of::<ReparsePointHeader>() == 8);
};
