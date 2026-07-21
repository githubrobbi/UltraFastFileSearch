// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Tests for `$STANDARD_INFORMATION` parsing, from the shared helper up to
//! the public `parse_record_full` API.
//!
//! Split out of the parent `tests` module to keep both files under the
//! 800-LOC policy limit; the record-building helpers stay in the parent.

use super::{
    create_file_name_value, create_resident_attribute, create_test_record_with_attributes,
    write_i64_le, write_u16_le, write_u32_le, write_u64_le,
};
use crate::ntfs::{AttributeType, ExtendedStandardInfo};
use crate::parse::{ParseResult, parse_record_full, parse_standard_info_full};

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

/// The NTFS 3.0+ `$SI` fields that live past the timestamps — quota, version
/// and class bookkeeping — must survive the parse, and must stay zero for the
/// 36-byte NTFS 1.2 layout, which has no such fields.
#[test]
fn parse_standard_info_full_reads_quota_and_version_fields() {
    let attr_offset = 0_usize;
    let value_offset = 24_u16;
    let si_offset = attr_offset + usize::from(value_offset);
    let mut data = vec![0_u8; si_offset + 72];
    let max_versions = 3_u32;
    let version_number = 2_u32;
    let class_id = 9_u32;
    let quota_charged = 4_096_u64;

    write_u32_le(&mut data, attr_offset + 16, 72);
    write_u16_le(&mut data, attr_offset + 20, value_offset);
    write_u32_le(&mut data, si_offset + 36, max_versions);
    write_u32_le(&mut data, si_offset + 40, version_number);
    write_u32_le(&mut data, si_offset + 44, class_id);
    write_u64_le(&mut data, si_offset + 56, quota_charged);

    let mut result = ExtendedStandardInfo::default();
    parse_standard_info_full(&data, attr_offset, &mut result);

    assert_eq!(result.max_versions, max_versions);
    assert_eq!(result.version_number, version_number);
    assert_eq!(result.class_id, class_id);
    assert_eq!(result.quota_charged, quota_charged);

    // NTFS 1.2: the same byte positions are past the end of the attribute
    // value, so all four must remain zero.
    let mut v12 = vec![0_u8; si_offset + 36];
    write_u32_le(&mut v12, attr_offset + 16, 36);
    write_u16_le(&mut v12, attr_offset + 20, value_offset);

    let mut v12_result = ExtendedStandardInfo::default();
    parse_standard_info_full(&v12, attr_offset, &mut v12_result);

    assert_eq!(v12_result.max_versions, 0);
    assert_eq!(v12_result.version_number, 0);
    assert_eq!(v12_result.class_id, 0);
    assert_eq!(v12_result.quota_charged, 0);
}

/// End-to-end pin on the **public** API, not just the helper.
///
/// `parse_record_full` is what external consumers call, and it reaches the
/// NTFS 3.0+ `$SI` fields through two hops: `full.rs` calls
/// `parse_standard_info_full` into a local `ExtendedStandardInfo`, which is
/// then moved onto `ParsedRecord::std_info`. A refactor that gave `full.rs`
/// its own `$SI` read would keep the helper-level tests green while silently
/// zeroing these fields for every caller of the public API, so assert them
/// on a `ParsedRecord` that came out of `parse_record_full` itself.
#[test]
fn parse_record_full_surfaces_extended_std_info_on_parsed_record() {
    let quota_charged = 65_536_u64;
    let max_versions = 7_u32;
    let version_number = 3_u32;
    let class_id = 11_u32;
    let owner_id = 44_u32;
    let security_id = 55_u32;
    let usn = 66_u64;

    // 72-byte NTFS 3.0+ $SI value, field order per
    // `ntfs::metadata::StandardInformationExtended`.
    let mut si_value = vec![0_u8; 72];
    write_i64_le(&mut si_value, 0, 116_444_736_000_000_010); // creation_time
    write_i64_le(&mut si_value, 8, 116_444_736_000_000_020); // modification_time
    write_i64_le(&mut si_value, 16, 116_444_736_000_000_030); // mft_change_time
    write_i64_le(&mut si_value, 24, 116_444_736_000_000_040); // access_time
    write_u32_le(&mut si_value, 32, 0x20); // file_attributes = ARCHIVE
    write_u32_le(&mut si_value, 36, max_versions);
    write_u32_le(&mut si_value, 40, version_number);
    write_u32_le(&mut si_value, 44, class_id);
    write_u32_le(&mut si_value, 48, owner_id);
    write_u32_le(&mut si_value, 52, security_id);
    write_u64_le(&mut si_value, 56, quota_charged);
    write_u64_le(&mut si_value, 64, usn);

    let data = create_test_record_with_attributes(5, true, false, 0, &[
        create_resident_attribute(AttributeType::StandardInformation, &si_value),
        create_resident_attribute(
            AttributeType::FileName,
            &create_file_name_value(5, "quota.txt", 1),
        ),
    ]);

    let ParseResult::Base(record) = parse_record_full(&data, 5) else {
        panic!("an in-use base record with a $FILE_NAME must parse as ParseResult::Base");
    };

    assert_eq!(record.std_info.quota_charged, quota_charged);
    assert_eq!(record.std_info.max_versions, max_versions);
    assert_eq!(record.std_info.version_number, version_number);
    assert_eq!(record.std_info.class_id, class_id);
    // The three pre-existing NTFS 3.0+ fields ride the same two hops.
    assert_eq!(record.std_info.owner_id, owner_id);
    assert_eq!(record.std_info.security_id, security_id);
    assert_eq!(record.std_info.usn, usn);
}
