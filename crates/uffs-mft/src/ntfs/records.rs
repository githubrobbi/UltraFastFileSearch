// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! NTFS record headers, fixup, and attribute iteration.

use core::mem::size_of;

use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::ntfs::extract_data_runs_from_attribute;

/// Magic number for FILE records ("FILE" in little-endian).
pub(crate) const FILE_RECORD_MAGIC: u32 = 0x454C_4946;

/// Sector size (standard for NTFS).
pub const SECTOR_SIZE: usize = 512;

/// Sector size as `u64` for byte-offset arithmetic.
///
/// NTFS disk offsets are tracked as `u64`; aliasing the same compile-time
/// constant in the wider integer type avoids `as u64` truncation casts at
/// every alignment site without introducing runtime conversion.  Only the
/// Windows-only I/O readers consume this alias, so the constant itself is
/// gated to keep the non-Windows build's dead-code analysis honest.
#[cfg(windows)]
pub(crate) const SECTOR_SIZE_U64: u64 = 512;

/// Multi-sector header present at the start of FILE and INDX records.
///
/// Contains the Update Sequence Array (USA) used for sector-level
/// integrity checking.
///
/// `pub` because it is the type of
/// [`FileRecordSegmentHeader::multi_sector_header`] (a public-API field).
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct MultiSectorHeader {
    /// Magic number ("FILE" or "INDX").
    pub magic: u32,
    /// Offset to the Update Sequence Array.
    pub usa_offset: u16,
    /// Number of entries in the USA (including the check value).
    pub usa_count: u16,
}

impl MultiSectorHeader {
    /// Checks if this is a valid FILE record.
    #[must_use]
    pub const fn is_file_record(self) -> bool {
        self.magic == FILE_RECORD_MAGIC
    }
}

/// Reads a fixed-width little-endian byte array from `data` at `offset`.
#[inline]
fn read_le_array<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    data.get(offset..end)?.try_into().ok()
}

/// Reads a single byte from `data` at `offset`.
#[inline]
fn read_u8(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

/// Reads a little-endian `u16` from `data` at `offset`.
#[inline]
fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(read_le_array(data, offset)?))
}

/// Reads a little-endian `u32` from `data` at `offset`.
#[inline]
fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(read_le_array(data, offset)?))
}

/// Reads a little-endian `u64` from `data` at `offset`.
#[inline]
fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(read_le_array(data, offset)?))
}

/// Reads a little-endian `i64` from `data` at `offset`.
#[inline]
fn read_i64_le(data: &[u8], offset: usize) -> Option<i64> {
    Some(i64::from_le_bytes(read_le_array(data, offset)?))
}

/// Decodes a `MultiSectorHeader` from on-disk bytes without unaligned reads.
#[inline]
fn parse_multi_sector_header(data: &[u8]) -> Option<MultiSectorHeader> {
    Some(MultiSectorHeader {
        magic: read_u32_le(data, 0)?,
        usa_offset: read_u16_le(data, 4)?,
        usa_count: read_u16_le(data, 6)?,
    })
}

/// Applies the Update Sequence Array (USA) fixup to a record buffer.
///
/// NTFS uses the USA for sector-level integrity checking. The last 2 bytes
/// of each 512-byte sector are replaced with a check value, and the original
/// values are stored in the USA at the start of the record.
///
/// This function restores the original sector-end values and validates
/// that the check values match.
#[must_use]
pub fn apply_usa_fixup(buffer: &mut [u8], usa_offset: u16, usa_count: u16) -> bool {
    if usa_count < 1 {
        return false;
    }

    let usa_offset_usize = usize::from(usa_offset);
    let Some(check_bytes) = buffer.get(usa_offset_usize..usa_offset_usize + 2) else {
        return false;
    };
    let Ok(check_arr): Result<[u8; 2], _> = check_bytes.try_into() else {
        return false;
    };
    let check_value = u16::from_le_bytes(check_arr);
    let mut result = true;

    for sector_idx in 1..usa_count {
        let sector_idx_usize = usize::from(sector_idx);
        let sector_end_offset = sector_idx_usize * SECTOR_SIZE - 2;
        let usa_entry_offset = usa_offset_usize + sector_idx_usize * 2;

        let Some(usa_slice) = buffer.get(usa_entry_offset..usa_entry_offset + 2) else {
            break;
        };
        let Ok(replacement): Result<[u8; 2], _> = usa_slice.try_into() else {
            break;
        };

        let Some(sector_slice) = buffer.get(sector_end_offset..sector_end_offset + 2) else {
            break;
        };
        let Ok(sector_arr): Result<[u8; 2], _> = sector_slice.try_into() else {
            break;
        };
        let current_value = u16::from_le_bytes(sector_arr);
        if current_value != check_value {
            result = false;
        }

        if let Some(dest) = buffer.get_mut(sector_end_offset..sector_end_offset + 2) {
            dest.copy_from_slice(&replacement);
        }
    }

    result
}

/// Applies USA fixup to a file record buffer in-place.
#[must_use]
pub fn fixup_file_record(buffer: &mut [u8]) -> bool {
    if buffer.len() < size_of::<MultiSectorHeader>() {
        return false;
    }

    let Some(header) = parse_multi_sector_header(buffer) else {
        return false;
    };

    if !header.is_file_record() {
        return false;
    }

    apply_usa_fixup(buffer, header.usa_offset, header.usa_count)
}

/// NTFS attribute type codes.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeType {
    /// Standard information (timestamps, flags).
    StandardInformation = 0x10,
    /// Attribute list (for records spanning multiple segments).
    AttributeList = 0x20,
    /// File name.
    FileName = 0x30,
    /// Object ID.
    ObjectId = 0x40,
    /// Security descriptor.
    SecurityDescriptor = 0x50,
    /// Volume name.
    VolumeName = 0x60,
    /// Volume information.
    VolumeInformation = 0x70,
    /// File data.
    Data = 0x80,
    /// Index root.
    IndexRoot = 0x90,
    /// Index allocation.
    IndexAllocation = 0xA0,
    /// Bitmap.
    Bitmap = 0xB0,
    /// Reparse point.
    ReparsePoint = 0xC0,
    /// EA information.
    EaInformation = 0xD0,
    /// Extended attributes.
    Ea = 0xE0,
    /// Property set.
    PropertySet = 0xF0,
    /// Logged utility stream.
    LoggedUtilityStream = 0x100,
    /// End marker.
    End = 0xFFFF_FFFF,
}

impl AttributeType {
    /// The end-of-attributes marker as a raw `u32`, for direct comparison
    /// against `AttributeRecordHeader::type_code` without a `cast_lossless`
    /// lint.
    pub(crate) const END_MARKER: u32 = 0xFFFF_FFFF;

    /// `$DATA` attribute type code for raw `u32` comparison.
    pub(crate) const DATA_TYPE: u32 = 0x80;

    /// `$REPARSE_POINT` attribute type code for raw `u32` comparison.
    pub(crate) const REPARSE_POINT_TYPE: u32 = 0xC0;

    /// Creates an `AttributeType` from a raw u32 value.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x10 => Some(Self::StandardInformation),
            0x20 => Some(Self::AttributeList),
            0x30 => Some(Self::FileName),
            0x40 => Some(Self::ObjectId),
            0x50 => Some(Self::SecurityDescriptor),
            0x60 => Some(Self::VolumeName),
            0x70 => Some(Self::VolumeInformation),
            0x80 => Some(Self::Data),
            0x90 => Some(Self::IndexRoot),
            0xA0 => Some(Self::IndexAllocation),
            0xB0 => Some(Self::Bitmap),
            0xC0 => Some(Self::ReparsePoint),
            0xD0 => Some(Self::EaInformation),
            0xE0 => Some(Self::Ea),
            0xF0 => Some(Self::PropertySet),
            0x100 => Some(Self::LoggedUtilityStream),
            0xFFFF_FFFF => Some(Self::End),
            _ => None,
        }
    }
}

/// Common header for all attribute records.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct AttributeRecordHeader {
    /// Attribute type code.
    pub type_code: u32,
    /// Total length of this attribute record.
    pub length: u32,
    /// Non-zero if attribute is non-resident.
    pub is_non_resident: u8,
    /// Length of the attribute name (in characters).
    pub name_length: u8,
    /// Offset to the attribute name.
    pub name_offset: u16,
    /// Attribute flags (compressed, encrypted, sparse).
    pub flags: u16,
    /// Attribute instance number.
    pub instance: u16,
}

/// Resident attribute data (follows `AttributeRecordHeader`).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct ResidentAttributeData {
    /// Length of the attribute value.
    pub value_length: u32,
    /// Offset to the attribute value (from start of attribute record).
    pub value_offset: u16,
    /// Resident flags.
    pub flags: u16,
}

/// Decodes an `AttributeRecordHeader` from on-disk bytes without unaligned
/// reads.
#[inline]
pub(crate) fn parse_attribute_record_header(data: &[u8]) -> Option<AttributeRecordHeader> {
    Some(AttributeRecordHeader {
        type_code: read_u32_le(data, 0)?,
        length: read_u32_le(data, 4)?,
        is_non_resident: read_u8(data, 8)?,
        name_length: read_u8(data, 9)?,
        name_offset: read_u16_le(data, 10)?,
        flags: read_u16_le(data, 12)?,
        instance: read_u16_le(data, 14)?,
    })
}

/// Decodes `ResidentAttributeData` from on-disk bytes without unaligned reads.
#[inline]
#[expect(
    clippy::single_call_fn,
    reason = "kept separate to localize resident attribute header decoding"
)]
fn parse_resident_attribute_data(data: &[u8]) -> Option<ResidentAttributeData> {
    Some(ResidentAttributeData {
        value_length: read_u32_le(data, 0)?,
        value_offset: read_u16_le(data, 4)?,
        flags: read_u16_le(data, 6)?,
    })
}

/// Non-resident attribute data (follows `AttributeRecordHeader`).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct NonResidentAttributeData {
    /// Lowest VCN covered by this attribute record.
    pub lowest_vcn: i64,
    /// Highest VCN covered by this attribute record.
    pub highest_vcn: i64,
    /// Offset to the mapping pairs (data runs).
    pub mapping_pairs_offset: u16,
    /// Compression unit size (log2).
    pub compression_unit: u8,
    /// Reserved.
    pub reserved: [u8; 5],
    /// Allocated size of the attribute.
    pub allocated_size: i64,
    /// Actual data size.
    pub data_size: i64,
    /// Initialized data size.
    pub initialized_size: i64,
}

/// Decodes `NonResidentAttributeData` from on-disk bytes without unaligned
/// reads.
#[inline]
pub(crate) fn parse_non_resident_attribute_data(data: &[u8]) -> Option<NonResidentAttributeData> {
    Some(NonResidentAttributeData {
        lowest_vcn: read_i64_le(data, 0)?,
        highest_vcn: read_i64_le(data, 8)?,
        mapping_pairs_offset: read_u16_le(data, 16)?,
        compression_unit: read_u8(data, 18)?,
        reserved: read_le_array(data, 19)?,
        allocated_size: read_i64_le(data, 24)?,
        data_size: read_i64_le(data, 32)?,
        initialized_size: read_i64_le(data, 40)?,
    })
}

/// File Record Segment Header (MFT entry header).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct FileRecordSegmentHeader {
    /// Multi-sector header with magic and USA info.
    pub multi_sector_header: MultiSectorHeader,
    /// Log file sequence number.
    pub log_file_sequence_number: u64,
    /// Sequence number (incremented on reuse).
    pub sequence_number: u16,
    /// Hard link count.
    pub link_count: u16,
    /// Offset to the first attribute.
    pub first_attribute_offset: u16,
    /// Flags (in use, directory).
    pub flags: u16,
    /// Bytes actually used in this record.
    pub bytes_in_use: u32,
    /// Bytes allocated for this record.
    pub bytes_allocated: u32,
    /// Base file record segment (for extension records).
    pub base_file_record_segment: u64,
    /// Next attribute instance number.
    pub next_attribute_number: u16,
    /// Reserved/padding.
    pub reserved: u16,
    /// Segment number (lower 32 bits).
    pub segment_number_lower: u32,
}

/// Decodes `FileRecordSegmentHeader` from on-disk bytes without unaligned
/// reads.
#[inline]
#[expect(
    clippy::single_call_fn,
    reason = "kept separate to localize file record header decoding"
)]
fn parse_file_record_segment_header(data: &[u8]) -> Option<FileRecordSegmentHeader> {
    Some(FileRecordSegmentHeader {
        multi_sector_header: parse_multi_sector_header(data)?,
        log_file_sequence_number: read_u64_le(data, 8)?,
        sequence_number: read_u16_le(data, 16)?,
        link_count: read_u16_le(data, 18)?,
        first_attribute_offset: read_u16_le(data, 20)?,
        flags: read_u16_le(data, 22)?,
        bytes_in_use: read_u32_le(data, 24)?,
        bytes_allocated: read_u32_le(data, 28)?,
        base_file_record_segment: read_u64_le(data, 32)?,
        next_attribute_number: read_u16_le(data, 40)?,
        reserved: read_u16_le(data, 42)?,
        segment_number_lower: read_u32_le(data, 44)?,
    })
}

impl FileRecordSegmentHeader {
    /// Returns true if this record is in use.
    #[must_use]
    pub const fn is_in_use(&self) -> bool {
        (self.flags & 0x0001) != 0
    }

    /// Returns true if this record is a directory.
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        (self.flags & 0x0002) != 0
    }

    /// Returns true if this is a base record (not an extension).
    #[must_use]
    pub const fn is_base_record(&self) -> bool {
        self.base_file_record_segment == 0
    }
}

/// Iterator over attributes in a file record.
pub struct AttributeIterator<'a> {
    /// The record buffer.
    data: &'a [u8],
    /// Current offset within the buffer.
    offset: usize,
    /// Maximum valid offset (`bytes_in_use` from header).
    max_offset: usize,
}

impl<'a> AttributeIterator<'a> {
    /// Creates a new attribute iterator from a file record buffer.
    #[must_use]
    pub fn new(record: &'a [u8]) -> Option<Self> {
        if record.len() < size_of::<FileRecordSegmentHeader>() {
            return None;
        }

        let header = parse_file_record_segment_header(record)?;
        let multi_sector_header = header.multi_sector_header;
        if !multi_sector_header.is_file_record() {
            return None;
        }

        let first_attr = header.first_attribute_offset as usize;
        let bytes_in_use = header.bytes_in_use as usize;
        if first_attr >= record.len() || bytes_in_use > record.len() {
            return None;
        }

        Some(Self {
            data: record,
            offset: first_attr,
            max_offset: bytes_in_use,
        })
    }
}

/// A reference to an attribute within a record buffer.
#[derive(Debug, Clone, Copy)]
pub struct AttributeRef<'a> {
    /// The attribute data slice.
    pub data: &'a [u8],
    /// The attribute header.
    pub header: AttributeRecordHeader,
}

impl<'a> AttributeRef<'a> {
    /// Returns the attribute type.
    #[must_use]
    pub const fn attribute_type(&self) -> Option<AttributeType> {
        AttributeType::from_u32(self.header.type_code)
    }

    /// Returns true if this is a non-resident attribute.
    #[must_use]
    pub const fn is_non_resident(&self) -> bool {
        self.header.is_non_resident != 0
    }

    /// Returns the resident attribute value, if this is a resident attribute.
    #[must_use]
    pub fn resident_value(&self) -> Option<&'a [u8]> {
        if self.is_non_resident() {
            return None;
        }

        let header_size = size_of::<AttributeRecordHeader>();
        let resident_size = size_of::<ResidentAttributeData>();
        let resident_slice = self.data.get(header_size..header_size + resident_size)?;
        let resident = parse_resident_attribute_data(resident_slice)?;
        let value_offset = resident.value_offset as usize;
        let value_length = resident.value_length as usize;
        self.data.get(value_offset..value_offset + value_length)
    }

    /// Returns the non-resident attribute data, if this is a non-resident
    /// attribute.
    #[must_use]
    pub fn non_resident_data(&self) -> Option<NonResidentAttributeData> {
        if !self.is_non_resident() {
            return None;
        }

        let header_size = size_of::<AttributeRecordHeader>();
        let nr_size = size_of::<NonResidentAttributeData>();
        let nr_slice = self.data.get(header_size..header_size + nr_size)?;
        parse_non_resident_attribute_data(nr_slice)
    }

    /// Parses data runs from a non-resident attribute.
    #[must_use]
    pub fn data_runs(&self) -> Vec<crate::ntfs::DataRun> {
        if !self.is_non_resident() {
            return Vec::new();
        }

        extract_data_runs_from_attribute(self.data)
    }

    /// Returns the decoded attribute name (UTF-16 code units), if present.
    ///
    /// The name is stored as UTF-16LE bytes at an offset that carries no
    /// alignment guarantee, so the units are decoded into an owned `Vec`
    /// rather than reinterpreted in place.
    #[must_use]
    pub fn name(&self) -> Option<Vec<u16>> {
        if self.header.name_length == 0 {
            return None;
        }

        let name_offset = self.header.name_offset as usize;
        let name_length = self.header.name_length as usize;
        let name_byte_len = name_length * 2;
        let name_bytes = self.data.get(name_offset..name_offset + name_byte_len)?;

        Some(
            name_bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|chunk| u16::from_le_bytes(*chunk))
                .collect(),
        )
    }
}

impl<'a> Iterator for AttributeIterator<'a> {
    type Item = AttributeRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let header_size = size_of::<AttributeRecordHeader>();
        let header_slice = self.data.get(self.offset..self.offset + header_size)?;
        if self.offset + header_size > self.max_offset {
            return None;
        }

        let header = parse_attribute_record_header(header_slice)?;
        if header.type_code == 0xFFFF_FFFF {
            return None;
        }

        let length = header.length as usize;
        if length < header_size || self.offset + length > self.max_offset {
            return None;
        }

        let attr_data = self.data.get(self.offset..self.offset + length)?;
        self.offset += length;

        Some(AttributeRef {
            data: attr_data,
            header,
        })
    }
}

#[expect(
    clippy::missing_assert_message,
    reason = "compile-time size checks; messages not needed"
)]
const _: () = {
    assert!(size_of::<MultiSectorHeader>() == 8);
    assert!(size_of::<AttributeRecordHeader>() == 16);
    assert!(size_of::<ResidentAttributeData>() == 8);
    assert!(size_of::<NonResidentAttributeData>() == 48);
    assert!(size_of::<FileRecordSegmentHeader>() == 48);
};
