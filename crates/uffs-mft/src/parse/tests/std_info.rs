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
use crate::parse::{ParseResult, StdInfoParse, parse_record_full, parse_standard_info_full};

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
    let status = parse_standard_info_full(&data, attr_offset, &mut result);

    assert_eq!(status, StdInfoParse::V30);
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
    let status = parse_standard_info_full(&data, attr_offset, &mut result);

    assert_eq!(status, StdInfoParse::V30);
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
    let v12_status = parse_standard_info_full(&v12, attr_offset, &mut v12_result);

    assert_eq!(v12_status, StdInfoParse::V12);
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

/// The whole point of the status: a `$SI` that cannot be decoded must be
/// distinguishable from one that genuinely reads 1601-01-01. Both leave the
/// timestamps at `0`, so the value alone can never tell them apart.
#[test]
fn undecodable_standard_info_reports_malformed_not_a_1601_timestamp() {
    let attr_offset = 0_usize;
    let value_offset = 24_u16;
    let si_offset = attr_offset + usize::from(value_offset);

    // 1. Declared value length under the 36-byte NTFS 1.2 minimum.
    let mut too_short = vec![0_u8; si_offset + 72];
    write_u32_le(&mut too_short, attr_offset + 16, 8);
    write_u16_le(&mut too_short, attr_offset + 20, value_offset);

    let mut result = ExtendedStandardInfo::default();
    let status = parse_standard_info_full(&too_short, attr_offset, &mut result);

    assert_eq!(status, StdInfoParse::Malformed);
    assert!(!status.is_decoded());
    assert!(status.is_malformed());
    // The trap this exists to close: the timestamps look like a real record.
    assert_eq!(result.created, 0);

    // 2. Declared length is fine, but the payload overruns the buffer.
    let mut truncated = vec![0_u8; si_offset + 8];
    write_u32_le(&mut truncated, attr_offset + 16, 72);
    write_u16_le(&mut truncated, attr_offset + 20, value_offset);

    let mut truncated_result = ExtendedStandardInfo::default();
    let truncated_status = parse_standard_info_full(&truncated, attr_offset, &mut truncated_result);

    assert_eq!(truncated_status, StdInfoParse::Malformed);

    // 3. The resident header itself runs past the end of the record: the
    //    value-length field at +16..+20 does not fit in an 18-byte buffer.
    let header_overrun = vec![0_u8; 18];

    let mut header_result = ExtendedStandardInfo::default();
    let header_status = parse_standard_info_full(&header_overrun, attr_offset, &mut header_result);

    assert_eq!(header_status, StdInfoParse::Malformed);

    // 4. A genuine 1601-01-01 record: same zero timestamps, decoded status. This is
    //    the pair the status exists to separate.
    let mut epoch = vec![0_u8; si_offset + 72];
    write_u32_le(&mut epoch, attr_offset + 16, 72);
    write_u16_le(&mut epoch, attr_offset + 20, value_offset);

    let mut epoch_result = ExtendedStandardInfo::default();
    let epoch_status = parse_standard_info_full(&epoch, attr_offset, &mut epoch_result);

    assert_eq!(epoch_status, StdInfoParse::V30);
    assert!(epoch_status.is_decoded());
    assert_eq!(epoch_result.created, 0);
}

/// The status has to survive to the public API, or external consumers still
/// cannot tell the two cases apart.
#[test]
fn parse_record_full_reports_the_standard_info_parse_status() {
    // A record whose $STANDARD_INFORMATION declares a value length below the
    // 36-byte minimum, plus a valid $FILE_NAME so the record still parses.
    let mut short_si = create_resident_attribute(AttributeType::StandardInformation, &[0_u8; 72]);
    write_u32_le(&mut short_si, 16, 8);

    let data = create_test_record_with_attributes(5, true, false, 0, &[
        short_si,
        create_resident_attribute(
            AttributeType::FileName,
            &create_file_name_value(5, "damaged.txt", 1),
        ),
    ]);

    let ParseResult::Base(record) = parse_record_full(&data, 5) else {
        panic!("a record with a valid $FILE_NAME must still parse as ParseResult::Base");
    };

    assert_eq!(record.std_info_parse, StdInfoParse::Malformed);
    assert_eq!(
        record.std_info.created, 0,
        "the defaults are what make the status necessary",
    );

    // A record with no $STANDARD_INFORMATION at all is Absent, not Malformed:
    // unusual, but not evidence of damage.
    let no_si =
        create_test_record_with_attributes(5, true, false, 0, &[create_resident_attribute(
            AttributeType::FileName,
            &create_file_name_value(5, "nosi.txt", 1),
        )]);

    let ParseResult::Base(no_si_record) = parse_record_full(&no_si, 5) else {
        panic!("a record with a valid $FILE_NAME must still parse as ParseResult::Base");
    };

    assert_eq!(no_si_record.std_info_parse, StdInfoParse::Absent);
    assert!(!no_si_record.std_info_parse.is_malformed());
}
