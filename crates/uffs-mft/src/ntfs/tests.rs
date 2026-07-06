// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Regression tests for the split NTFS module surface.

#![expect(
    clippy::indexing_slicing,
    reason = "test code — relaxed linting for test clarity"
)]

use core::mem::size_of;

use super::*;

fn write_u16_le(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_le(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_i64_le(buffer: &mut [u8], offset: usize, value: i64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

// FILETIME arithmetic tests moved to `uffs-time/src/lib.rs` (colocated
// with the implementation) after the helpers were extracted into the
// zero-dep `uffs-time` crate.  See `crates/uffs-time/src/lib.rs::tests`.

#[test]
fn file_reference_extraction() {
    // NTFS file reference packs: FRS in low 48 bits, sequence in high 16 bits.
    let file_ref: u64 = (7_u64 << 48) | 0x3039;
    assert_eq!(file_reference_to_frs(file_ref), 12345);
    // Verify the high-16 sequence-number layout the FRS extraction relies on.
    // (No production helper for the sequence half — `file_reference_to_frs`
    // is the only consumer of this layout; the assertion below documents the
    // bit-packing contract.)
    assert_eq!((file_ref >> 48_i32) as u16, 7);
}

#[test]
fn attribute_type_from_u32() {
    assert_eq!(
        AttributeType::from_u32(0x10),
        Some(AttributeType::StandardInformation)
    );
    assert_eq!(AttributeType::from_u32(0x30), Some(AttributeType::FileName));
    assert_eq!(AttributeType::from_u32(0x80), Some(AttributeType::Data));
    assert_eq!(
        AttributeType::from_u32(0xFFFF_FFFF),
        Some(AttributeType::End)
    );
    assert_eq!(AttributeType::from_u32(0x99), None);
}

#[test]
fn file_record_flags() {
    let header = FileRecordSegmentHeader {
        multi_sector_header: MultiSectorHeader {
            magic: FILE_RECORD_MAGIC,
            usa_offset: 0,
            usa_count: 0,
        },
        log_file_sequence_number: 0,
        sequence_number: 1,
        link_count: 1,
        first_attribute_offset: 56,
        flags: 0x0003,
        bytes_in_use: 0,
        bytes_allocated: 0,
        base_file_record_segment: 0,
        next_attribute_number: 0,
        reserved: 0,
        segment_number_lower: 0,
    };

    assert!(header.is_in_use());
    assert!(header.is_directory());
    assert!(header.is_base_record());
}

#[test]
fn fixup_file_record_applies_usa_from_safe_header_decode() {
    let mut record = vec![0_u8; 1024];
    let usa_offset = 0x30;
    let check_value = 0xABCD;
    let original_first = 0x1234;
    let original_second = 0x5678;

    record[0..4].copy_from_slice(b"FILE");
    write_u16_le(&mut record, 4, crate::len_to_u16(usa_offset));
    write_u16_le(&mut record, 6, 3);
    write_u16_le(&mut record, usa_offset, check_value);
    write_u16_le(&mut record, usa_offset + 2, original_first);
    write_u16_le(&mut record, usa_offset + 4, original_second);
    write_u16_le(&mut record, SECTOR_SIZE - 2, check_value);
    write_u16_le(&mut record, SECTOR_SIZE * 2 - 2, check_value);

    assert!(fixup_file_record(&mut record));
    assert_eq!(
        &record[SECTOR_SIZE - 2..SECTOR_SIZE],
        &original_first.to_le_bytes()
    );
    assert_eq!(
        &record[SECTOR_SIZE * 2 - 2..SECTOR_SIZE * 2],
        &original_second.to_le_bytes()
    );
}

#[test]
fn attribute_iterator_reads_resident_attribute_value() {
    let mut record = vec![0_u8; 96];
    let record_len = crate::len_to_u32(record.len());
    let first_attribute_offset = size_of::<FileRecordSegmentHeader>();
    let attr_offset = first_attribute_offset;
    let attr_length = size_of::<AttributeRecordHeader>() + size_of::<ResidentAttributeData>() + 4;
    let end_marker_offset = attr_offset + attr_length;

    record[0..4].copy_from_slice(b"FILE");
    write_u16_le(&mut record, 20, crate::len_to_u16(first_attribute_offset));
    // NTFS `FILE_RECORD_SEGMENT_HEADER.flags` bit 0x0001 = "record in use".
    // Encoded inline (the production parser inspects this bit directly via
    // `header.flags & 0x0001`; there is no `FileRecordFlags::InUse` enum).
    write_u16_le(&mut record, 22, 0x0001);
    write_u32_le(
        &mut record,
        24,
        crate::len_to_u32(end_marker_offset + size_of::<AttributeRecordHeader>()),
    );
    write_u32_le(&mut record, 28, record_len);

    write_u32_le(&mut record, attr_offset, AttributeType::DATA_TYPE);
    write_u32_le(&mut record, attr_offset + 4, crate::len_to_u32(attr_length));
    record[attr_offset + 8] = 0;
    record[attr_offset + 9] = 0;
    write_u16_le(&mut record, attr_offset + 10, 0);
    write_u16_le(&mut record, attr_offset + 12, 0);
    write_u16_le(&mut record, attr_offset + 14, 1);

    write_u32_le(&mut record, attr_offset + 16, 4);
    write_u16_le(
        &mut record,
        attr_offset + 20,
        crate::len_to_u16(size_of::<AttributeRecordHeader>() + size_of::<ResidentAttributeData>()),
    );
    write_u16_le(&mut record, attr_offset + 22, 0);
    record[attr_offset + 24..attr_offset + 28].copy_from_slice(&[1, 2, 3, 4]);

    write_u32_le(&mut record, end_marker_offset, AttributeType::END_MARKER);

    let mut iter = AttributeIterator::new(&record).expect("valid record header");
    let attribute = iter.next().expect("resident attribute");

    assert_eq!(attribute.attribute_type(), Some(AttributeType::Data));
    assert_eq!(attribute.resident_value(), Some(&[1, 2, 3, 4][..]));
    assert!(iter.next().is_none());
}

#[test]
fn non_resident_attribute_helpers_decode_mapping_pairs() {
    let mut attr =
        vec![0_u8; size_of::<AttributeRecordHeader>() + size_of::<NonResidentAttributeData>() + 4];
    let attr_len = crate::len_to_u32(attr.len());

    write_u32_le(&mut attr, 0, AttributeType::DATA_TYPE);
    write_u32_le(&mut attr, 4, attr_len);
    attr[8] = 1;
    write_u16_le(&mut attr, 12, 0x0001);
    write_u16_le(&mut attr, 14, 2);

    let nr_offset = size_of::<AttributeRecordHeader>();
    write_i64_le(&mut attr, nr_offset, 7);
    write_i64_le(&mut attr, nr_offset + 8, 11);
    write_u16_le(
        &mut attr,
        nr_offset + 16,
        crate::len_to_u16(nr_offset + size_of::<NonResidentAttributeData>()),
    );
    attr[nr_offset + 18] = 0;
    write_i64_le(&mut attr, nr_offset + 24, 40);
    write_i64_le(&mut attr, nr_offset + 32, 20);
    write_i64_le(&mut attr, nr_offset + 40, 20);
    attr[nr_offset + 48..nr_offset + 52].copy_from_slice(&[0x11, 0x05, 0x0A, 0x00]);

    let attribute = AttributeRef {
        data: &attr,
        header: AttributeRecordHeader {
            type_code: AttributeType::DATA_TYPE,
            length: crate::len_to_u32(attr.len()),
            is_non_resident: 1,
            name_length: 0,
            name_offset: 0,
            flags: 0x0001,
            instance: 2,
        },
    };

    let nr_data = attribute.non_resident_data().expect("non-resident header");
    let lowest_vcn = nr_data.lowest_vcn;
    assert_eq!(lowest_vcn, 7);
    assert_eq!(
        nr_data.mapping_pairs_offset as usize,
        nr_offset + size_of::<NonResidentAttributeData>()
    );

    assert_eq!(attribute.data_runs(), vec![DataRun {
        vcn: 7,
        cluster_count: 5,
        lcn: crate::platform::Lcn::new(10),
    }]);
}

#[test]
fn attribute_name_decodes_utf16() {
    let name_offset = 24_usize;
    let name: Vec<u16> = "$SDS".encode_utf16().collect();
    let mut data = vec![0_u8; name_offset + name.len() * 2];
    for (i, unit) in name.iter().enumerate() {
        let off = name_offset + i * 2;
        data[off..off + 2].copy_from_slice(&unit.to_le_bytes());
    }

    let named = AttributeRef {
        data: &data,
        header: AttributeRecordHeader {
            type_code: AttributeType::DATA_TYPE,
            length: crate::len_to_u32(data.len()),
            is_non_resident: 1,
            name_length: 4,
            name_offset: crate::len_to_u16(name_offset),
            flags: 0,
            instance: 0,
        },
    };
    assert_eq!(named.name().as_deref(), Some(name.as_slice()));

    // An unnamed attribute yields no name.
    let unnamed = AttributeRef {
        data: &data,
        header: AttributeRecordHeader {
            name_length: 0,
            ..named.header
        },
    };
    assert_eq!(unnamed.name(), None);
}
