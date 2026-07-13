// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Tests for parse-module helpers, record decoding, and regressions.

use super::*;
use crate::frs::{Frs, ParentFrs};
use crate::ntfs::{AttributeType, ExtendedStandardInfo, FILE_RECORD_MAGIC, NameInfo, ReparseTag};

fn write_u16_le(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_le(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_i64_le(buffer: &mut [u8], offset: usize, value: i64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Create a minimal valid MFT record header for testing.
/// This creates a 1024-byte record with proper fixup values.
fn create_test_record(frs: u64, in_use: bool, is_dir: bool) -> Vec<u8> {
    let mut data = vec![0_u8; 1024];

    // Magic: "FILE"
    data[0..4].copy_from_slice(&FILE_RECORD_MAGIC.to_le_bytes());

    // USA offset (0x30 is typical)
    data[4..6].copy_from_slice(&0x30_u16.to_le_bytes());

    // USA count (3 for 1024-byte record: check + 2 sectors)
    data[6..8].copy_from_slice(&3_u16.to_le_bytes());

    // LSN (Log Sequence Number)
    data[8..16].copy_from_slice(&12345_u64.to_le_bytes());

    // Sequence number
    data[16..18].copy_from_slice(&1_u16.to_le_bytes());

    // Hard link count
    data[18..20].copy_from_slice(&1_u16.to_le_bytes());

    // First attribute offset (after header, 0x38 typical)
    data[20..22].copy_from_slice(&0x38_u16.to_le_bytes());

    // Flags: 0x01 = in use, 0x02 = directory
    let flags: u16 = u16::from(in_use) | (u16::from(is_dir) << 1);
    data[22..24].copy_from_slice(&flags.to_le_bytes());

    // Used size of record
    data[24..28].copy_from_slice(&0x100_u32.to_le_bytes());

    // Allocated size of record
    data[28..32].copy_from_slice(&0x400_u32.to_le_bytes());

    // Base record reference (0 for base records)
    data[32..40].copy_from_slice(&0_u64.to_le_bytes());

    // Next attribute ID
    data[40..42].copy_from_slice(&1_u16.to_le_bytes());

    // FRS number (at offset 44 in modern NTFS) — test values fit u32
    let frs_u32 = u32::try_from(frs).expect("test FRS fits u32");
    data[44..48].copy_from_slice(&frs_u32.to_le_bytes());

    // USA: check value at offset 0x30
    let check_value: u16 = 0xABCD;
    data[0x30..0x32].copy_from_slice(&check_value.to_le_bytes());

    // USA entry 1 (original bytes from sector 1 end)
    data[0x32..0x34].copy_from_slice(&0x1234_u16.to_le_bytes());

    // USA entry 2 (original bytes from sector 2 end)
    data[0x34..0x36].copy_from_slice(&0x5678_u16.to_le_bytes());

    // Place check value at sector boundaries (will be replaced by fixup)
    data[510..512].copy_from_slice(&check_value.to_le_bytes());
    data[1022..1024].copy_from_slice(&check_value.to_le_bytes());

    // End marker attribute (type 0xFFFFFFFF)
    data[0x38..0x3C].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());

    data
}

fn create_resident_attribute(attr_type: AttributeType, value: &[u8]) -> Vec<u8> {
    let value_offset = 24_usize;
    let length = (value_offset + value.len() + 7) & !7;
    let mut attr = vec![0_u8; length];

    write_u32_le(&mut attr, 0, attr_type as u32);
    write_u32_le(&mut attr, 4, crate::len_to_u32(length));
    write_u32_le(&mut attr, 16, crate::len_to_u32(value.len()));
    write_u16_le(&mut attr, 20, 24);
    attr[value_offset..value_offset + value.len()].copy_from_slice(value);

    attr
}

#[expect(
    clippy::single_call_fn,
    reason = "test helper isolates FileName attribute layout for one targeted regression"
)]
fn create_file_name_value(parent_directory: u64, name: &str, namespace: u8) -> Vec<u8> {
    let name_utf16: Vec<u16> = name.encode_utf16().collect();
    let mut value = vec![0_u8; 66 + name_utf16.len() * 2];

    write_u64_le(&mut value, 0, parent_directory);
    let name_length = u8::try_from(name_utf16.len()).expect("test name fits u8");
    value[64] = name_length;
    value[65] = namespace;

    for (index, unit) in name_utf16.iter().copied().enumerate() {
        let byte_offset = 66 + index * 2;
        value[byte_offset..byte_offset + 2].copy_from_slice(&unit.to_le_bytes());
    }

    value
}

#[expect(
    clippy::single_call_fn,
    reason = "test helper isolates reparse payload layout for one targeted regression"
)]
fn create_reparse_point_value(reparse_tag: u32) -> Vec<u8> {
    let mut value = vec![0_u8; 8];
    write_u32_le(&mut value, 0, reparse_tag);

    value
}

fn create_test_record_with_attributes(
    frs: u64,
    in_use: bool,
    is_dir: bool,
    base_file_record_segment: u64,
    attributes: &[Vec<u8>],
) -> Vec<u8> {
    let mut data = create_test_record(frs, in_use, is_dir);
    write_u64_le(&mut data, 32, base_file_record_segment);

    let mut offset = 0x38_usize;
    for attribute in attributes {
        assert!(offset + attribute.len() + 4 <= data.len());
        data[offset..offset + attribute.len()].copy_from_slice(attribute);
        offset += attribute.len();
    }

    write_u32_le(&mut data, offset, 0xFFFF_FFFF);
    let bytes_in_use = crate::len_to_u32(offset + 4);
    write_u32_le(&mut data, 24, bytes_in_use);

    data
}

#[test]
fn apply_fixup_valid_record() {
    let mut data = create_test_record(5, true, false);

    // Before fixup, sector ends have check value
    assert_eq!(&data[510..512], &0xABCD_u16.to_le_bytes());
    assert_eq!(&data[1022..1024], &0xABCD_u16.to_le_bytes());

    let result = apply_fixup(&mut data);
    assert!(result, "Fixup should succeed for valid record");

    // After fixup, sector ends have original values from USA
    assert_eq!(&data[510..512], &0x1234_u16.to_le_bytes());
    assert_eq!(&data[1022..1024], &0x5678_u16.to_le_bytes());
}

#[test]
fn apply_fixup_invalid_magic() {
    let mut data = vec![0_u8; 1024];
    data[0..4].copy_from_slice(b"BAAD"); // Invalid magic

    let result = apply_fixup(&mut data);
    assert!(!result, "Fixup should fail for invalid magic");
}

#[test]
fn apply_fixup_buffer_too_small() {
    let mut data = vec![0_u8; 10]; // Too small for header

    let result = apply_fixup(&mut data);
    assert!(!result, "Fixup should fail for buffer too small");
}

#[test]
fn apply_fixup_corrupted_check_value() {
    let mut data = create_test_record(5, true, false);

    // Corrupt the check value at first sector end
    data[510..512].copy_from_slice(&0xDEAD_u16.to_le_bytes());

    let result = apply_fixup(&mut data);
    assert!(!result, "Fixup should fail for corrupted check value");
}

#[test]
fn apply_fixup_valid_record_on_unaligned_slice() {
    let record = create_test_record(5, true, false);
    let mut storage = vec![0_u8; record.len() + 1];
    storage[1..].copy_from_slice(&record);

    let result = apply_fixup(&mut storage[1..]);
    assert!(result, "Fixup should succeed for an unaligned record slice");
    assert_eq!(&storage[511..513], &0x1234_u16.to_le_bytes());
    assert_eq!(&storage[1023..1025], &0x5678_u16.to_le_bytes());
}

#[test]
fn parse_standard_info_full_reads_unaligned_v30_payload() {
    let attr_offset = 1_usize;
    let value_offset = 24_u16;
    let si_offset = attr_offset + usize::from(value_offset);
    let mut data = vec![0_u8; si_offset + 72];
    let creation_time = 116_444_736_000_000_010_i64;
    let modification_time = 116_444_736_000_000_020_i64;
    let mft_change_time = 116_444_736_000_000_030_i64;
    let access_time = 116_444_736_000_000_040_i64;
    let owner_id = 44_u32;
    let security_id = 55_u32;
    let usn = 66_u64;

    write_u32_le(&mut data, attr_offset + 16, 72);
    write_u16_le(&mut data, attr_offset + 20, value_offset);
    write_i64_le(&mut data, si_offset, creation_time);
    write_i64_le(&mut data, si_offset + 8, modification_time);
    write_i64_le(&mut data, si_offset + 16, mft_change_time);
    write_i64_le(&mut data, si_offset + 24, access_time);
    write_u32_le(&mut data, si_offset + 48, owner_id);
    write_u32_le(&mut data, si_offset + 52, security_id);
    write_u64_le(&mut data, si_offset + 64, usn);

    let mut result = ExtendedStandardInfo::default();
    parse_standard_info_full(&data, attr_offset, &mut result);

    assert_eq!(result.created, creation_time);
    assert_eq!(result.modified, modification_time);
    assert_eq!(result.mft_changed, mft_change_time);
    assert_eq!(result.accessed, access_time);
    assert_eq!(result.owner_id, owner_id);
    assert_eq!(result.security_id, security_id);
    assert_eq!(result.usn, usn);
}

#[test]
fn parse_file_name_full_reads_unaligned_payload() {
    let attr_offset = 1_usize;
    let value_offset = 24_u16;
    let fn_offset = attr_offset + usize::from(value_offset);
    let name = "abc.txt";
    let name_utf16: Vec<u16> = name.encode_utf16().collect();
    let mut data = vec![0_u8; fn_offset + 66 + name_utf16.len() * 2];
    let parent_directory = (7_u64 << 48_u32) | 0x002A_u64;
    let creation_time = 116_444_736_000_000_100_i64;
    let modification_time = 116_444_736_000_000_200_i64;
    let mft_change_time = 116_444_736_000_000_300_i64;
    let access_time = 116_444_736_000_000_400_i64;
    let name_len = 7_u8;

    write_u16_le(&mut data, attr_offset + 20, value_offset);
    write_u64_le(&mut data, fn_offset, parent_directory);
    write_i64_le(&mut data, fn_offset + 8, creation_time);
    write_i64_le(&mut data, fn_offset + 16, modification_time);
    write_i64_le(&mut data, fn_offset + 24, mft_change_time);
    write_i64_le(&mut data, fn_offset + 32, access_time);
    data[fn_offset + 64] = name_len;
    data[fn_offset + 65] = 1;

    for (index, unit) in name_utf16.iter().copied().enumerate() {
        let byte_offset = fn_offset + 66 + index * 2;
        data[byte_offset..byte_offset + 2].copy_from_slice(&unit.to_le_bytes());
    }

    let result = parse_file_name_full(&data, attr_offset, 99);
    assert!(
        result.is_some(),
        "File name parsing should succeed on unaligned data"
    );

    if let Some(name_info) = result {
        assert_eq!(name_info.name, name);
        assert_eq!(name_info.parent_frs, ParentFrs::new(42));
        assert_eq!(name_info.namespace, 1);
        assert_eq!(name_info.fn_created, creation_time);
        assert_eq!(name_info.fn_modified, modification_time);
        assert_eq!(name_info.fn_accessed, access_time);
        assert_eq!(name_info.fn_mft_changed, mft_change_time);
        assert_eq!(name_info.source_frs, Frs::new(99));
    }
}

#[test]
fn parse_record_forensic_reads_unaligned_record_slice() {
    let record = create_test_record(5, true, false);
    let mut storage = vec![0_u8; record.len() + 1];
    storage[1..].copy_from_slice(&record);

    let result = parse_record_forensic(&storage[1..], 5, ParseOptions::FORENSIC, false);
    assert!(matches!(&result, ParseResult::Base(_)));

    if let ParseResult::Base(parsed_record) = result {
        assert_eq!(parsed_record.frs, Frs::ROOT);
        assert_eq!(parsed_record.sequence_number, 1);
        assert!(parsed_record.in_use);
    }
}

#[test]
fn parse_record_forensic_reads_unaligned_extension_record_slice() {
    let extension_frs = 88_u64;
    let base_frs = 77_u64;
    let base_file_reference = (9_u64 << 48_u32) | base_frs;
    let file_name_attr = create_resident_attribute(
        AttributeType::FileName,
        &create_file_name_value(42, "ext-name.txt", 1),
    );
    let record =
        create_test_record_with_attributes(extension_frs, true, false, base_file_reference, &[
            file_name_attr,
        ]);
    let mut storage = vec![0_u8; record.len() + 1];
    storage[1..].copy_from_slice(&record);

    let merge_result =
        parse_record_forensic(&storage[1..], extension_frs, ParseOptions::DEFAULT, false);
    assert!(matches!(&merge_result, ParseResult::Extension(_)));

    if let ParseResult::Extension(extension) = merge_result {
        assert_eq!(extension.base_frs, Frs::new(base_frs));
        assert_eq!(extension.extension_frs, Frs::new(extension_frs));
        assert_eq!(extension.names.len(), 1);
        assert_eq!(extension.names[0].name, "ext-name.txt");
        assert_eq!(extension.names[0].parent_frs, ParentFrs::new(42));
    }

    let forensic_result =
        parse_record_forensic(&storage[1..], extension_frs, ParseOptions::FORENSIC, false);
    assert!(matches!(&forensic_result, ParseResult::Base(_)));

    if let ParseResult::Base(parsed_record) = forensic_result {
        assert!(parsed_record.is_extension);
        assert_eq!(parsed_record.base_frs, Frs::new(base_frs));
        assert_eq!(parsed_record.name, "ext-name.txt");
    }
}

#[test]
fn parse_record_forensic_reads_unaligned_resident_reparse_tag() {
    let frs = 91_u64;
    let reparse_attr = create_resident_attribute(
        AttributeType::ReparsePoint,
        &create_reparse_point_value(ReparseTag::SymbolicLink as u32),
    );
    let record = create_test_record_with_attributes(frs, true, false, 0, &[reparse_attr]);
    let mut storage = vec![0_u8; record.len() + 1];
    storage[1..].copy_from_slice(&record);

    let result = parse_record_forensic(&storage[1..], frs, ParseOptions::FORENSIC, false);
    assert!(matches!(&result, ParseResult::Base(_)));

    if let ParseResult::Base(parsed_record) = result {
        assert_eq!(parsed_record.reparse_tag, ReparseTag::SymbolicLink as u32);
        assert_eq!(parsed_record.size, 8);
        assert_eq!(parsed_record.streams.len(), 1);
        assert_eq!(parsed_record.streams[0].name, "$REPARSE");
        assert_eq!(parsed_record.streams[0].size, 8);
        assert!(parsed_record.streams[0].is_resident);
    }
}

#[test]
fn create_placeholder_record_works() {
    let record = create_placeholder_record(12345);

    assert_eq!(record.frs, Frs::new(12345));
    // Placeholder records terminate path resolution at the NTFS root.
    assert_eq!(record.parent_frs, ParentFrs::ROOT);
    assert_eq!(record.name, "<dir:12345>");
    assert!(record.is_directory);
    assert!(record.in_use);
    assert!(record.names.is_empty());
    assert!(record.streams.is_empty());
}

#[test]
fn parse_result_variants() {
    // Test ParseResult enum
    let base = ParseResult::Base(create_placeholder_record(1));
    assert!(matches!(base, ParseResult::Base(_)));

    let ext = ParseResult::Extension(ExtensionAttributes {
        base_frs: Frs::new(100),
        extension_frs: Frs::new(101),
        names: Vec::new(),
        streams: Vec::new(),
        dir_index_size: 0,
        dir_index_allocated: 0,
    });
    assert!(matches!(ext, ParseResult::Extension(_)));

    let skip = ParseResult::Skip;
    assert!(matches!(skip, ParseResult::Skip));
}

#[test]
fn parse_options_default() {
    let opts = ParseOptions::default();
    assert!(!opts.include_deleted);
    assert!(!opts.include_corrupt);
    assert!(!opts.include_extensions);
}

#[test]
fn parse_options_forensic() {
    let opts = ParseOptions::FORENSIC;
    assert!(opts.include_deleted);
    assert!(opts.include_corrupt);
    assert!(opts.include_extensions);
    assert!(opts.is_forensic());
}

#[test]
fn parsed_record_default() {
    let record = ParsedRecord::default();
    // `Frs::default()` / `ParentFrs::default()` are the documented ZERO
    // sentinels — a default `ParsedRecord` has no own / parent FRS.
    assert_eq!(record.frs, Frs::ZERO);
    assert_eq!(record.sequence_number, 0);
    assert_eq!(record.parent_frs, ParentFrs::ZERO);
    assert!(record.name.is_empty());
    assert!(!record.in_use);
    assert!(!record.is_directory);
}

#[test]
fn add_missing_parent_placeholders_empty() {
    let mut records: Vec<ParsedRecord> = Vec::new();
    let added = add_missing_parent_placeholders_to_vec(&mut records);
    assert_eq!(added, 0);
}

#[test]
fn add_missing_parent_placeholders_no_missing() {
    let mut records = vec![
        {
            let mut r = create_placeholder_record(5);
            r.parent_frs = ParentFrs::ROOT; // Root references itself
            r
        },
        {
            let mut r = create_placeholder_record(100);
            r.parent_frs = ParentFrs::ROOT; // References root
            r
        },
    ];

    let added = add_missing_parent_placeholders_to_vec(&mut records);
    assert_eq!(added, 0, "No placeholders needed when all parents exist");
}

#[test]
fn add_missing_parent_placeholders_with_missing() {
    let mut records = vec![{
        let mut r = create_placeholder_record(100);
        r.parent_frs = ParentFrs::new(50); // References non-existent parent
        r
    }];

    let added = add_missing_parent_placeholders_to_vec(&mut records);
    assert!(added >= 1, "Should add placeholder for missing parent 50");

    // Verify placeholder was added
    let has_50 = records.iter().any(|r| r.frs == Frs::new(50));
    assert!(has_50, "Placeholder for FRS 50 should exist");
}

// ========================================================================
// Property-Based Tests
// ========================================================================

mod proptest_tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// apply_fixup should never panic regardless of input
        #[test]
        fn apply_fixup_never_panics(mut data in prop::collection::vec(any::<u8>(), 0..2048)) {
            // Should return true or false, never panic
            // For random data, fixup usually fails (returns false) because
            // the data doesn't have valid MFT record structure
            let result = apply_fixup(&mut data);
            // Use black_box to prevent optimization and ensure result is used
            core::hint::black_box(result);
        }


        /// create_placeholder_record should always produce valid records
        #[test]
        fn placeholder_record_always_valid(frs in 0_u64..1_000_000) {
            let record = create_placeholder_record(frs);
            prop_assert_eq!(record.frs, Frs::new(frs));
            prop_assert!(record.is_directory);
            prop_assert!(record.in_use);
            prop_assert_eq!(record.parent_frs, ParentFrs::ROOT); // Always root
        }

        /// ParseOptions should have consistent is_forensic behavior
        #[test]
        fn parse_options_forensic_consistency(
            include_deleted in any::<bool>(),
            include_corrupt in any::<bool>(),
            include_extensions in any::<bool>()
        ) {
            let opts = ParseOptions {
                include_deleted,
                include_corrupt,
                include_extensions,
            };
            let expected = include_deleted || include_corrupt || include_extensions;
            prop_assert_eq!(opts.is_forensic(), expected);
        }

        /// parse_record (and the zero-alloc variant) must handle any buffer
        /// without panicking — crucially including buffers carrying the FILE
        /// magic, which drive the attribute-walk paths where malformed header
        /// offsets can run past a truncated record. Pure random bytes almost
        /// never form the magic, so the forced-magic pass is what exercises
        /// those paths (the gap the fuzz-found truncated-record crash exposed).
        #[test]
        fn parse_record_never_panics(
            mut data in prop::collection::vec(any::<u8>(), 0..4096),
            frs in 0_u64..1_000_000
        ) {
            core::hint::black_box(parse_record(&data, frs));
            core::hint::black_box(parse_record_zero_alloc(&data, frs));
            if data.len() >= 4 {
                data[0..4].copy_from_slice(b"FILE");
                core::hint::black_box(parse_record(&data, frs));
                core::hint::black_box(parse_record(&data, u64::MAX));
                core::hint::black_box(parse_record_zero_alloc(&data, frs));
            }
        }

        /// parse_record_full must handle any buffer without panicking, incl.
        /// forced-FILE-magic buffers that drive the attribute walk.
        #[test]
        fn parse_record_full_never_panics(
            mut data in prop::collection::vec(any::<u8>(), 0..4096),
            frs in 0_u64..1_000_000
        ) {
            let result = parse_record_full(&data, frs);
            prop_assert!(matches!(result, ParseResult::Base(_) | ParseResult::Extension(_) | ParseResult::Skip));
            if data.len() >= 4 {
                data[0..4].copy_from_slice(b"FILE");
                let magic_result = parse_record_full(&data, frs);
                prop_assert!(matches!(magic_result, ParseResult::Base(_) | ParseResult::Extension(_) | ParseResult::Skip));
            }
        }
    }
}

/// Test that extension records with `$FILE_NAME` are properly merged into
/// base records that have no `$FILE_NAME` attribute.
#[test]
fn extension_merge_with_empty_base_name() {
    // Simulate the case where base record has no $FILE_NAME
    // and extension record has the $FILE_NAME

    let mut record_merger = MftRecordMerger::with_capacity(10);

    // Add base record with empty name
    let base = ParsedRecord {
        frs: Frs::new(100),
        sequence_number: 1,
        lsn: 0,
        parent_frs: ParentFrs::ZERO, // Wrong - should be updated from extension
        name: String::new(),         // Empty - should be updated from extension
        namespace: 255,              // Invalid
        names: Vec::new(),           // No names in base record
        streams: Vec::new(),
        size: 0,
        allocated_size: 0,
        std_info: ExtendedStandardInfo::default(),
        in_use: true,
        is_directory: true,
        fn_created: 0,
        fn_modified: 0,
        fn_accessed: 0,
        fn_mft_changed: 0,
        reparse_tag: 0,
        is_deleted: false,
        is_corrupt: false,
        is_extension: false,
        base_frs: Frs::ZERO,
    };
    record_merger.add_result(ParseResult::Base(base));

    // Add extension record with the actual name
    let ext = ExtensionAttributes {
        base_frs: Frs::new(100),
        extension_frs: Frs::new(200),
        names: vec![NameInfo {
            name: "test_directory".to_owned(),
            parent_frs: ParentFrs::ROOT, // Root
            namespace: 1,                // Win32
            fn_created: 0,
            fn_modified: 0,
            fn_accessed: 0,
            fn_mft_changed: 0,
            source_frs: Frs::new(200),
        }],
        streams: Vec::new(),
        dir_index_size: 0,
        dir_index_allocated: 0,
    };
    record_merger.add_result(ParseResult::Extension(ext));

    // Merge
    let result = record_merger.merge();

    // Check that the base record now has the name from extension
    assert_eq!(result.len(), 1, "Should have exactly 1 merged record");
    let rec = &result[0];
    assert_eq!(rec.frs, Frs::new(100));
    assert_eq!(
        rec.name, "test_directory",
        "Name should be merged from extension"
    );
    assert_eq!(
        rec.parent_frs,
        ParentFrs::ROOT,
        "parent_frs should be merged from extension"
    );
    assert_eq!(
        rec.namespace, 1,
        "namespace should be merged from extension"
    );
}

/// Test that extension records are merged even when processed before base
/// record
#[test]
fn extension_before_base_merge() {
    let mut record_merger = MftRecordMerger::with_capacity(10);

    // Add extension record FIRST (before base record)
    let ext = ExtensionAttributes {
        base_frs: Frs::new(100),
        extension_frs: Frs::new(200),
        names: vec![NameInfo {
            name: "test_directory".to_owned(),
            parent_frs: ParentFrs::ROOT,
            namespace: 1,
            fn_created: 0,
            fn_modified: 0,
            fn_accessed: 0,
            fn_mft_changed: 0,
            source_frs: Frs::new(200),
        }],
        streams: Vec::new(),
        dir_index_size: 0,
        dir_index_allocated: 0,
    };
    record_merger.add_result(ParseResult::Extension(ext));

    // Add base record AFTER extension
    let base = ParsedRecord {
        frs: Frs::new(100),
        sequence_number: 1,
        lsn: 0,
        parent_frs: ParentFrs::ZERO,
        name: String::new(),
        namespace: 255,
        names: Vec::new(),
        streams: Vec::new(),
        size: 0,
        allocated_size: 0,
        std_info: ExtendedStandardInfo::default(),
        in_use: true,
        is_directory: true,
        fn_created: 0,
        fn_modified: 0,
        fn_accessed: 0,
        fn_mft_changed: 0,
        reparse_tag: 0,
        is_deleted: false,
        is_corrupt: false,
        is_extension: false,
        base_frs: Frs::ZERO,
    };
    record_merger.add_result(ParseResult::Base(base));

    // Merge
    let result = record_merger.merge();

    // Check that the base record now has the name from extension
    assert_eq!(result.len(), 1, "Should have exactly 1 merged record");
    let rec = &result[0];
    assert_eq!(rec.frs, Frs::new(100));
    assert_eq!(
        rec.name, "test_directory",
        "Name should be merged from extension"
    );
    assert_eq!(
        rec.parent_frs,
        ParentFrs::ROOT,
        "parent_frs should be merged from extension"
    );
}

#[test]
fn repro_fuzz_crash_881b95() {
    let data: [u8; 72] = [
        0x46, 0x49, 0x4C, 0x45, 0x00, 0x29, 0x31, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x4B, 0xFF, 0x86,
        0x1B, 0xE8, 0x3A, 0xD8, 0x7B, 0x02, 0x00, 0xFF, 0x81, 0xE6, 0xE8, 0x3A, 0xD8, 0x7B, 0x00,
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    core::hint::black_box(parse_record(&data, 0));
    core::hint::black_box(parse_record(&data, 5));
    core::hint::black_box(parse_record(&data, u64::MAX));
    core::hint::black_box(parse_record_full(&data, 0));
    core::hint::black_box(parse_record_zero_alloc(&data, 0));
}
