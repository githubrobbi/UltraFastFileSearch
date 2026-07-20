// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Windows-specific parsing bridges plus direct-to-index helpers.
//! Split into focused submodules while preserving the legacy `io` parser
//! surface.

mod fragment;
mod fragment_extension;
pub(crate) mod unified;

#[expect(
    deprecated,
    reason = "re-exporting deprecated API for backward compatibility"
)]
pub use fragment::parse_record_to_fragment;
pub use unified::process_record;

pub use crate::parse::{
    ExtensionAttributes, ParseResult, ParsedColumns, ParsedRecord,
    add_missing_parent_placeholders_to_vec, create_placeholder_record, parse_record,
    parse_record_full, parse_record_zero_alloc,
};

#[cfg(test)]
mod tests {
    #[expect(deprecated, reason = "testing deprecated parse_record_to_fragment API")]
    use super::parse_record_to_fragment;
    use super::process_record;
    use crate::index::{MftIndex, MftIndexFragment};

    #[test]
    fn parse_record_to_index_rejects_short_buffers() {
        let mut index = MftIndex::new(crate::platform::DriveLetter::C);
        assert!(!crate::parse::parse_record_to_index(
            &[0_u8; 3], 42, &mut index
        ));
    }

    #[test]
    #[expect(deprecated, reason = "testing deprecated parse_record_to_fragment API")]
    fn parse_record_to_fragment_rejects_short_buffers() {
        let mut fragment = MftIndexFragment::with_capacity(1);
        assert!(!parse_record_to_fragment(&[0_u8; 3], 42, &mut fragment));
    }

    /// Regression pin: `process_record` must persist the header's NTFS
    /// **sequence number** onto the record. Without it `file_ref` degrades to
    /// the FRS alone, and the snapshot diff — keyed on the File Reference —
    /// goes blind to deletions (MFT slot numbers are stable across reuse).
    #[test]
    fn process_record_persists_the_sequence_number() {
        // Minimal in-use base FILE record; sequence_number is a u16 at header
        // offset 0x10. No attributes needed — the record is created regardless
        // and the fix copies the header seq onto it before the attribute loop.
        let mut record = RecordBuilder::new(56).build();
        record
            .get_mut(16..18)
            .expect("header has a sequence-number field at 0x10")
            .copy_from_slice(&0x1234_u16.to_le_bytes());

        let mut index = MftIndex::new(crate::platform::DriveLetter::C);
        let mut name_buf = String::new();
        process_record(&record, 42, &mut index, &mut name_buf);

        let rec = index
            .find(crate::frs::Frs::new(42))
            .expect("process_record must create the base record");
        assert_eq!(
            rec.sequence_number, 0x1234,
            "the header sequence number must be persisted onto the record",
        );
    }

    /// Regression pin: both production `$STANDARD_INFORMATION` parsers —
    /// `process_record` (the default bulk-load pipeline) and
    /// `crate::parse::parse_record_to_index` (the live USN-journal
    /// incremental-update pipeline, wired from `usn::windows`) — must
    /// recognize the NTFS 3.0+ 72-byte `StandardInformationExtended` form
    /// and populate `usn`/`security_id`/`owner_id`, not just the 4
    /// timestamps. Before this fix both silently treated every record as
    /// NTFS 1.2 (36 bytes) and left those three fields at zero.
    #[test]
    fn standard_information_extended_fields_reach_both_production_parsers() {
        let creation_time = 1_i64;
        let modification_time = 2_i64;
        let mft_change_time = 3_i64;
        let access_time = 4_i64;
        let file_attributes = 0x20_u32; // FILE_ATTRIBUTE_ARCHIVE
        let owner_id = 44_u32;
        let security_id = 55_u32;
        let usn = 66_u64;

        // 72-byte StandardInformationExtended payload, field order per
        // `ntfs::metadata::StandardInformationExtended`.
        let mut payload = Vec::new();
        payload.extend_from_slice(&creation_time.to_le_bytes());
        payload.extend_from_slice(&modification_time.to_le_bytes());
        payload.extend_from_slice(&mft_change_time.to_le_bytes());
        payload.extend_from_slice(&access_time.to_le_bytes());
        payload.extend_from_slice(&file_attributes.to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes()); // max_versions
        payload.extend_from_slice(&0_u32.to_le_bytes()); // version_number
        payload.extend_from_slice(&0_u32.to_le_bytes()); // class_id
        payload.extend_from_slice(&owner_id.to_le_bytes());
        payload.extend_from_slice(&security_id.to_le_bytes());
        payload.extend_from_slice(&0_u64.to_le_bytes()); // quota_charged
        payload.extend_from_slice(&usn.to_le_bytes());
        assert_eq!(
            payload.len(),
            72,
            "test fixture must match the real on-disk layout"
        );

        // Resident attribute: 16-byte AttributeRecordHeader + 4-byte
        // value_length + 2-byte value_offset + 2-byte resident-flags/padding
        // = 24-byte prefix, then the 72-byte payload at value_offset = 24.
        let std_info_total_len = u32::try_from(24 + payload.len()).expect("fits in u32");

        // A minimal $FILE_NAME attribute: `direct_index::parse_record_to_index`
        // only returns `true` once a record has a name (real MFT records
        // always do). 66-byte fixed `FileNameAttribute` (per
        // `ntfs::metadata::FileNameAttribute`'s field order) + a 1-char name.
        let mut fn_payload = Vec::new();
        fn_payload.extend_from_slice(&0_u64.to_le_bytes()); // parent_directory
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // creation_time
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // modification_time
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // mft_change_time
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // access_time
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // allocated_size
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // data_size
        fn_payload.extend_from_slice(&0_u32.to_le_bytes()); // file_attributes
        fn_payload.extend_from_slice(&0_u16.to_le_bytes()); // packed_ea_size
        fn_payload.extend_from_slice(&0_u16.to_le_bytes()); // reserved
        fn_payload.push(1); // file_name_length = 1 char
        fn_payload.push(1); // namespace = Win32 (2 = DOS-only would be skipped)
        fn_payload.extend_from_slice(&0x0061_u16.to_le_bytes()); // "a"
        assert_eq!(
            fn_payload.len(),
            68,
            "66-byte FileNameAttribute + 1 UTF-16 char"
        );
        let file_name_total_len = u32::try_from(24 + fn_payload.len()).expect("fits in u32");

        let mut record = RecordBuilder::new(56)
            .attr(0x10, std_info_total_len, 0, 0, 0)
            .raw(&72_u32.to_le_bytes()) // value_length (signals the extended form)
            .raw(&24_u16.to_le_bytes()) // value_offset
            .raw(&[0_u8; 2]) // resident flags + reserved
            .raw(&payload)
            .attr(0x30, file_name_total_len, 0, 0, 0)
            .raw(&u32::try_from(fn_payload.len()).expect("fits in u32").to_le_bytes()) // value_length
            .raw(&24_u16.to_le_bytes()) // value_offset
            .raw(&[0_u8; 2]) // resident flags + reserved
            .raw(&fn_payload)
            .build();

        // `RecordBuilder` zeroes `bytes_in_use` (header offset 24..28); patch
        // it to the real length so the attribute loop actually runs.
        let total_len = u32::try_from(record.len()).expect("fits in u32");
        record
            .get_mut(24..28)
            .expect("record is well over 28 bytes long")
            .copy_from_slice(&total_len.to_le_bytes());

        // Path 1: process_record — the default bulk-load pipeline.
        let mut unified_index = MftIndex::new(crate::platform::DriveLetter::C);
        let mut name_buf = String::new();
        process_record(&record, 42, &mut unified_index, &mut name_buf);
        let unified_rec = unified_index
            .find(crate::frs::Frs::new(42))
            .expect("process_record must create the base record");
        assert_eq!(unified_rec.stdinfo.created, creation_time);
        assert_eq!(unified_rec.stdinfo.usn, usn);
        assert_eq!(unified_rec.stdinfo.security_id, security_id);
        assert_eq!(unified_rec.stdinfo.owner_id, owner_id);

        // Path 2: crate::parse::parse_record_to_index — the live
        // USN-journal incremental-update pipeline (direct_index.rs).
        // Fully qualified: this module's own `parse_record_to_index` import
        // (above) is the unrelated, production-dead `io::parser::index` copy.
        let mut direct_index = MftIndex::new(crate::platform::DriveLetter::C);
        assert!(crate::parse::parse_record_to_index(
            &record,
            42,
            &mut direct_index
        ));
        let direct_rec = direct_index
            .find(crate::frs::Frs::new(42))
            .expect("parse_record_to_index must create the base record");
        assert_eq!(direct_rec.stdinfo.created, creation_time);
        assert_eq!(direct_rec.stdinfo.usn, usn);
        assert_eq!(direct_rec.stdinfo.security_id, security_id);
        assert_eq!(direct_rec.stdinfo.owner_id, owner_id);
    }

    /// Regression pin: a named `$DATA` (ADS) attribute's real `is_sparse`/
    /// `is_resident` status must reach the index's `IndexStreamInfo`, on
    /// both production parsers. Both fields already existed in the struct
    /// (`bit0`/`bit1` of `flags`) but every write site hardcoded them to
    /// `false` regardless of the real attribute — every ADS reported as
    /// non-sparse/non-resident no matter what it actually was.
    #[test]
    fn ads_sparse_and_resident_bits_reach_both_production_parsers() {
        // Minimal $FILE_NAME so both parsers accept the record and give it a
        // name (see the extended-standard-info test above for field order).
        let mut fn_payload = Vec::new();
        fn_payload.extend_from_slice(&0_u64.to_le_bytes()); // parent_directory
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // creation_time
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // modification_time
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // mft_change_time
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // access_time
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // allocated_size
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // data_size
        fn_payload.extend_from_slice(&0_u32.to_le_bytes()); // file_attributes
        fn_payload.extend_from_slice(&0_u16.to_le_bytes()); // packed_ea_size
        fn_payload.extend_from_slice(&0_u16.to_le_bytes()); // reserved
        fn_payload.push(1); // file_name_length = 1 char
        fn_payload.push(1); // namespace = Win32
        fn_payload.extend_from_slice(&0x0061_u16.to_le_bytes()); // "a"
        let file_name_total_len = u32::try_from(24 + fn_payload.len()).expect("fits in u32");

        // Named, non-resident $DATA (an ADS) flagged ATTRIBUTE_FLAG_SPARSE
        // (0x8000) in the attribute-record header. Layout after the 16-byte
        // common header: LowestVCN(8)=0, HighestVCN(8), MappingPairsOffset(2)
        // + CompressionUnit(1) + Reserved(5), AllocatedSize(8), DataSize(8),
        // InitializedSize(8) — 48 bytes total — then the 6-byte UTF-16LE
        // name "ads" at name_offset=48+16=64.
        let allocated_size = 8192_i64;
        let data_size = 4096_i64;
        let mut ads_nr = Vec::new();
        ads_nr.extend_from_slice(&0_i64.to_le_bytes()); // LowestVCN = 0 (primary)
        ads_nr.extend_from_slice(&0_i64.to_le_bytes()); // HighestVCN
        ads_nr.extend_from_slice(&[0_u8; 8]); // MappingPairsOffset+CompressionUnit+Reserved
        ads_nr.extend_from_slice(&allocated_size.to_le_bytes());
        ads_nr.extend_from_slice(&data_size.to_le_bytes());
        ads_nr.extend_from_slice(&0_i64.to_le_bytes()); // InitializedSize
        assert_eq!(ads_nr.len(), 48, "NonResidentAttributeData is 48 bytes");
        let ads_name: Vec<u8> = "ads".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let ads_total_len = u32::try_from(16 + ads_nr.len() + ads_name.len()).expect("fits in u32");

        let mut record = RecordBuilder::new(56)
            .attr(0x30, file_name_total_len, 0, 0, 0)
            .raw(&u32::try_from(fn_payload.len()).expect("fits in u32").to_le_bytes())
            .raw(&24_u16.to_le_bytes()) // value_offset
            .raw(&[0_u8; 2])
            .raw(&fn_payload)
            .attr_flags(0x80, ads_total_len, 1, 3, 64, 0x8000)
            .raw(&ads_nr)
            .raw(&ads_name)
            .build();

        let total_len = u32::try_from(record.len()).expect("fits in u32");
        record
            .get_mut(24..28)
            .expect("record is well over 28 bytes long")
            .copy_from_slice(&total_len.to_le_bytes());

        // Path 1: process_record — the default bulk-load pipeline.
        let mut unified_index = MftIndex::new(crate::platform::DriveLetter::C);
        let mut name_buf = String::new();
        process_record(&record, 42, &mut unified_index, &mut name_buf);
        let unified_rec = unified_index
            .find(crate::frs::Frs::new(42))
            .expect("process_record must create the base record");
        assert_ne!(
            unified_rec.first_stream.next_entry,
            crate::index::NO_ENTRY,
            "the ADS must be chained onto the record"
        );
        let unified_stream = unified_index
            .streams
            .get(crate::index::u32_as_usize(
                unified_rec.first_stream.next_entry,
            ))
            .expect("chained stream index must be valid");
        assert!(
            unified_stream.is_sparse(),
            "process_record dropped is_sparse"
        );
        assert!(
            !unified_stream.is_resident(),
            "a non-resident ADS must not report is_resident"
        );
        assert_eq!(
            unified_stream.size.length,
            u64::try_from(data_size).unwrap()
        );
        assert_eq!(
            unified_stream.size.allocated,
            u64::try_from(allocated_size).unwrap()
        );

        // Path 2: crate::parse::parse_record_to_index — the live
        // USN-journal incremental-update pipeline (direct_index.rs).
        let mut direct_index = MftIndex::new(crate::platform::DriveLetter::C);
        assert!(crate::parse::parse_record_to_index(
            &record,
            42,
            &mut direct_index
        ));
        let direct_rec = direct_index
            .find(crate::frs::Frs::new(42))
            .expect("parse_record_to_index must create the base record");
        assert_ne!(direct_rec.first_stream.next_entry, crate::index::NO_ENTRY);
        let direct_stream = direct_index
            .streams
            .get(crate::index::u32_as_usize(
                direct_rec.first_stream.next_entry,
            ))
            .expect("chained stream index must be valid");
        assert!(
            direct_stream.is_sparse(),
            "parse_record_to_index dropped is_sparse"
        );
        assert!(!direct_stream.is_resident());
    }

    /// Regression pin: `FileRecord.lsn` (from the header's own
    /// `log_file_sequence_number`) and `$FILE_NAME`'s own
    /// `namespace`/timestamps (which often differ from
    /// `$STANDARD_INFORMATION` — e.g. timestomping alters `STD_INFO` but
    /// leaves `FILE_NAME` original) must reach both production parsers. All
    /// five fields already existed on `FileRecord`; the header and
    /// `$FILE_NAME` attribute are both already fully decoded in memory by
    /// the time these values are read, so populating them is free.
    #[test]
    fn lsn_and_file_name_own_fields_reach_both_production_parsers() {
        let lsn = 0x1122_3344_5566_7788_u64;
        let sequence_number = 0x2222_u16;
        let namespace = 1_u8; // Win32
        let fn_created = 10_i64;
        let fn_modified = 20_i64;
        let fn_accessed = 30_i64;
        let fn_mft_changed = 40_i64;

        let mut fn_payload = Vec::new();
        fn_payload.extend_from_slice(&0_u64.to_le_bytes()); // parent_directory
        fn_payload.extend_from_slice(&fn_created.to_le_bytes());
        fn_payload.extend_from_slice(&fn_modified.to_le_bytes());
        fn_payload.extend_from_slice(&fn_mft_changed.to_le_bytes());
        fn_payload.extend_from_slice(&fn_accessed.to_le_bytes());
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // allocated_size
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // data_size
        fn_payload.extend_from_slice(&0_u32.to_le_bytes()); // file_attributes
        fn_payload.extend_from_slice(&0_u16.to_le_bytes()); // packed_ea_size
        fn_payload.extend_from_slice(&0_u16.to_le_bytes()); // reserved
        fn_payload.push(1); // file_name_length = 1 char
        fn_payload.push(namespace);
        fn_payload.extend_from_slice(&0x0061_u16.to_le_bytes()); // "a"
        let file_name_total_len = u32::try_from(24 + fn_payload.len()).expect("fits in u32");

        let mut record = RecordBuilder::new(56)
            .attr(0x30, file_name_total_len, 0, 0, 0)
            .raw(
                &u32::try_from(fn_payload.len())
                    .expect("fits in u32")
                    .to_le_bytes(),
            )
            .raw(&24_u16.to_le_bytes())
            .raw(&[0_u8; 2])
            .raw(&fn_payload)
            .build();

        let total_len = u32::try_from(record.len()).expect("fits in u32");
        record
            .get_mut(24..28)
            .expect("record well over 28 bytes")
            .copy_from_slice(&total_len.to_le_bytes());
        // Header: log_file_sequence_number @ offset 8 (u64), sequence_number
        // @ offset 16 (u16).
        record
            .get_mut(8..16)
            .expect("record well over 16 bytes")
            .copy_from_slice(&lsn.to_le_bytes());
        record
            .get_mut(16..18)
            .expect("record well over 18 bytes")
            .copy_from_slice(&sequence_number.to_le_bytes());

        let mut unified_index = MftIndex::new(crate::platform::DriveLetter::C);
        let mut name_buf = String::new();
        process_record(&record, 42, &mut unified_index, &mut name_buf);
        let unified_rec = unified_index
            .find(crate::frs::Frs::new(42))
            .expect("process_record must create the base record");
        assert_eq!(unified_rec.lsn, lsn);
        assert_eq!(unified_rec.sequence_number, sequence_number);
        assert_eq!(unified_rec.namespace, namespace);
        assert_eq!(unified_rec.fn_created, fn_created);
        assert_eq!(unified_rec.fn_modified, fn_modified);
        assert_eq!(unified_rec.fn_accessed, fn_accessed);
        assert_eq!(unified_rec.fn_mft_changed, fn_mft_changed);

        let mut direct_index = MftIndex::new(crate::platform::DriveLetter::C);
        assert!(crate::parse::parse_record_to_index(
            &record,
            42,
            &mut direct_index
        ));
        let direct_rec = direct_index
            .find(crate::frs::Frs::new(42))
            .expect("parse_record_to_index must create the base record");
        assert_eq!(direct_rec.lsn, lsn);
        assert_eq!(direct_rec.sequence_number, sequence_number);
        assert_eq!(direct_rec.namespace, namespace);
        assert_eq!(direct_rec.fn_created, fn_created);
        assert_eq!(direct_rec.fn_modified, fn_modified);
        assert_eq!(direct_rec.fn_accessed, fn_accessed);
        assert_eq!(direct_rec.fn_mft_changed, fn_mft_changed);
    }

    /// Regression pin: a record whose base segment has **no** `$FILE_NAME`
    /// at all (name arrives later via an extension record — the normal case
    /// for files with enough attributes to overflow the base MFT record)
    /// must still get `sequence_number`/`lsn` from its own header. Before
    /// this fix, `parse_record_to_index`'s no-name early-return path set
    /// neither, and nothing else in the pipeline ever would (an extension
    /// record's header carries a different, per-segment sequence/LSN).
    #[test]
    fn sequence_number_and_lsn_set_even_without_a_base_file_name() {
        let lsn = 0xAABB_CCDD_EEFF_0011_u64;
        let sequence_number = 0x3333_u16;

        let mut record = RecordBuilder::new(56).build();
        record
            .get_mut(8..16)
            .expect("record well over 16 bytes")
            .copy_from_slice(&lsn.to_le_bytes());
        record
            .get_mut(16..18)
            .expect("record well over 18 bytes")
            .copy_from_slice(&sequence_number.to_le_bytes());

        let mut direct_index = MftIndex::new(crate::platform::DriveLetter::C);
        // Returns false (no name found yet), but must still create the
        // record with its header-derived identity fields set.
        assert!(!crate::parse::parse_record_to_index(
            &record,
            42,
            &mut direct_index
        ));
        let direct_rec = direct_index
            .find(crate::frs::Frs::new(42))
            .expect("the no-name path must still create the base record");
        assert_eq!(direct_rec.sequence_number, sequence_number);
        assert_eq!(direct_rec.lsn, lsn);
    }

    /// Regression pin: when a file's *only* `$FILE_NAME` lives in an
    /// extension record (the base MFT record segment has none at all --
    /// the normal case once a record has enough attributes to overflow the
    /// base segment), `direct_index_extension.rs`'s "promote to primary
    /// name" merge path used to copy only the name text and parent FRS,
    /// silently dropping namespace and all four `$FILE_NAME` timestamps
    /// even though they were already fully decoded from the extension
    /// record's own bytes.
    #[test]
    fn extension_only_file_name_sets_namespace_and_fn_timestamps_on_base_record() {
        let namespace = 1_u8; // Win32
        let fn_created = 111_i64;
        let fn_modified = 222_i64;
        let fn_accessed = 333_i64;
        let fn_mft_changed = 444_i64;

        // Base record: no $FILE_NAME attribute at all.
        let mut base_record = RecordBuilder::new(56).build();
        let base_len = u32::try_from(base_record.len()).expect("fits in u32");
        base_record
            .get_mut(24..28)
            .expect("record well over 28 bytes")
            .copy_from_slice(&base_len.to_le_bytes());

        let mut index = MftIndex::new(crate::platform::DriveLetter::C);
        assert!(!crate::parse::parse_record_to_index(
            &base_record,
            42,
            &mut index
        ));
        let base_rec = index
            .find(crate::frs::Frs::new(42))
            .expect("the no-name early-return path must still create the record");
        assert_eq!(base_rec.namespace, 0);
        assert_eq!(base_rec.fn_created, 0);

        // Extension record: carries the file's only $FILE_NAME.
        let mut fn_payload = Vec::new();
        fn_payload.extend_from_slice(&0_u64.to_le_bytes()); // parent_directory
        fn_payload.extend_from_slice(&fn_created.to_le_bytes());
        fn_payload.extend_from_slice(&fn_modified.to_le_bytes());
        fn_payload.extend_from_slice(&fn_mft_changed.to_le_bytes());
        fn_payload.extend_from_slice(&fn_accessed.to_le_bytes());
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // allocated_size
        fn_payload.extend_from_slice(&0_i64.to_le_bytes()); // data_size
        fn_payload.extend_from_slice(&0_u32.to_le_bytes()); // file_attributes
        fn_payload.extend_from_slice(&0_u16.to_le_bytes()); // packed_ea_size
        fn_payload.extend_from_slice(&0_u16.to_le_bytes()); // reserved
        fn_payload.push(1); // file_name_length = 1 char
        fn_payload.push(namespace);
        fn_payload.extend_from_slice(&0x0062_u16.to_le_bytes()); // "b"
        let file_name_total_len = u32::try_from(24 + fn_payload.len()).expect("fits in u32");

        let mut ext_record = RecordBuilder::new(56)
            .attr(0x30, file_name_total_len, 0, 0, 0)
            .raw(
                &u32::try_from(fn_payload.len())
                    .expect("fits in u32")
                    .to_le_bytes(),
            )
            .raw(&24_u16.to_le_bytes())
            .raw(&[0_u8; 2])
            .raw(&fn_payload)
            .build();
        let ext_len = u32::try_from(ext_record.len()).expect("fits in u32");
        ext_record
            .get_mut(24..28)
            .expect("record well over 28 bytes")
            .copy_from_slice(&ext_len.to_le_bytes());
        // base_file_record_segment @ header offset 32 (u64): nonzero makes
        // `is_base_record()` false and routes this to the extension-merge
        // path, targeting FRS 42 (the base record created above).
        ext_record
            .get_mut(32..40)
            .expect("record well over 40 bytes")
            .copy_from_slice(&42_u64.to_le_bytes());

        assert!(crate::parse::parse_record_to_index(
            &ext_record,
            99,
            &mut index
        ));
        let merged_rec = index
            .find(crate::frs::Frs::new(42))
            .expect("extension merge must keep the base record");
        assert_eq!(merged_rec.namespace, namespace);
        assert_eq!(merged_rec.fn_created, fn_created);
        assert_eq!(merged_rec.fn_modified, fn_modified);
        assert_eq!(merged_rec.fn_accessed, fn_accessed);
        assert_eq!(merged_rec.fn_mft_changed, fn_mft_changed);
    }

    // ── WI-5.2 panic-resistance corpus ──────────────────────────────
    //
    // The daemon builds with `panic = "abort"`: a single parser panic on a
    // crafted MFT record is a whole-process DoS. These records all pass the
    // FILE-record header gate (`is_file_record` + `is_in_use`) so the parser
    // enters the attribute loop, then carry attribute bytes engineered to
    // hit every offset/length/multiply edge that WI-5.2 converted from raw
    // `data[..]` / `+` / `* 2` to `.get()` / `checked_*`. The contract under
    // test is simply: **the parser returns; it never panics.**

    /// Forges malformed FILE records by appending bytes (no indexing, no
    /// offset arithmetic — so the builder itself stays panic-free and
    /// lint-clean). The 56-byte `FileRecordSegmentHeader` is emitted first
    /// with a valid magic / in-use flag / first-attribute-offset, then an
    /// arbitrary attribute body is appended.
    struct RecordBuilder {
        bytes: Vec<u8>,
    }

    impl RecordBuilder {
        /// Emit a header that passes `is_file_record` + `is_in_use`, with
        /// `first_attribute_offset` = `attr_start`. The fixed 56-byte header
        /// is built field-by-field via append so offsets are implicit.
        fn new(attr_start: u16) -> Self {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(b"FILE"); // [0..4]  magic
            bytes.extend_from_slice(&[0_u8; 16]); // [4..20] usa/lsn/seq/link
            bytes.extend_from_slice(&attr_start.to_le_bytes()); // [20..22]
            bytes.extend_from_slice(&0x0001_u16.to_le_bytes()); // [22..24] in-use
            bytes.extend_from_slice(&[0_u8; 32]); // [24..56] rest of header
            Self { bytes }
        }

        /// Append a 16-byte resident-attribute header prefix (`type_code`,
        /// `length`, non-resident flag, `name_length`, `name_offset`,
        /// flags/instance).
        fn attr(
            mut self,
            type_code: u32,
            length: u32,
            non_resident: u8,
            name_length: u8,
            name_offset: u16,
        ) -> Self {
            self.bytes.extend_from_slice(&type_code.to_le_bytes());
            self.bytes.extend_from_slice(&length.to_le_bytes());
            self.bytes.push(non_resident);
            self.bytes.push(name_length);
            self.bytes.extend_from_slice(&name_offset.to_le_bytes());
            self.bytes.extend_from_slice(&[0_u8; 4]); // flags + instance
            self
        }

        /// Same as [`Self::attr`], but with an explicit NTFS attribute-flags
        /// value (e.g. `0x8000` = `ATTRIBUTE_FLAG_SPARSE`) instead of always
        /// zeroing that field.
        fn attr_flags(
            mut self,
            type_code: u32,
            length: u32,
            non_resident: u8,
            name_length: u8,
            name_offset: u16,
            attr_flags: u16,
        ) -> Self {
            self.bytes.extend_from_slice(&type_code.to_le_bytes());
            self.bytes.extend_from_slice(&length.to_le_bytes());
            self.bytes.push(non_resident);
            self.bytes.push(name_length);
            self.bytes.extend_from_slice(&name_offset.to_le_bytes());
            self.bytes.extend_from_slice(&attr_flags.to_le_bytes());
            self.bytes.extend_from_slice(&[0_u8; 2]); // instance
            self
        }

        /// Append raw filler bytes (used to reach a target value offset or to
        /// pad with garbage).
        fn raw(mut self, bytes: &[u8]) -> Self {
            self.bytes.extend_from_slice(bytes);
            self
        }

        fn build(self) -> Vec<u8> {
            self.bytes
        }
    }

    /// Run every malformed record through all three entry points; the test
    /// passes iff none of them panics (the return value is irrelevant).
    fn assert_all_parsers_survive(input: &[u8]) {
        // `RecordBuilder` leaves `bytes_in_use` (header offset 24..28) at 0,
        // which makes every parser's attribute loop compute `max_offset = 0`
        // and exit before touching a single attribute byte -- so unless we
        // patch it to the record's real length, this whole corpus never
        // actually reaches the code it claims to stress-test. Patch a local
        // copy rather than requiring every call site to do it.
        let mut patched = input.to_vec();
        if let Some(bytes_in_use_field) = patched.get_mut(24..28) {
            let len = u32::try_from(input.len()).unwrap_or(u32::MAX);
            bytes_in_use_field.copy_from_slice(&len.to_le_bytes());
        }
        let record = patched.as_slice();

        // The return value is irrelevant — reaching the end of this function
        // at all means none of the three parsers panicked, which is the
        // property under test. `black_box` consumes each result so it is
        // neither an unused binding nor an under-typed `let _` discard.
        // `crate::parse::parse_record_to_index` (direct_index.rs) is the
        // parser actually wired to the live USN-journal incremental update
        // path (usn::windows).
        let mut direct_index = MftIndex::new(crate::platform::DriveLetter::C);
        core::hint::black_box(crate::parse::parse_record_to_index(
            record,
            42,
            &mut direct_index,
        ));

        let mut unified_index = MftIndex::new(crate::platform::DriveLetter::C);
        let mut name_buf = String::new();
        core::hint::black_box(process_record(
            record,
            42,
            &mut unified_index,
            &mut name_buf,
        ));

        let mut fragment = MftIndexFragment::with_capacity(1);
        #[expect(deprecated, reason = "panic-resistance also covers the legacy path")]
        let fragment_ran = parse_record_to_fragment(record, 42, &mut fragment);
        core::hint::black_box(fragment_ran);
    }

    #[test]
    fn malformed_records_do_not_panic() {
        // 1. Header valid, first_attribute_offset points past end of buffer.
        assert_all_parsers_survive(&RecordBuilder::new(9999).build());

        // 2. Header valid, attr offset points exactly at end (empty attr area).
        assert_all_parsers_survive(&RecordBuilder::new(56).build());

        // 3. StandardInformation attr whose declared length overruns the record.
        assert_all_parsers_survive(
            &RecordBuilder::new(56)
                .attr(0x10, 0xFFFF_FFFF, 0, 0, 0)
                .build(),
        );

        // 4. FileName attr with a name_length that, doubled, overflows past EOF
        //    (exercises the `name_len * 2` → checked_mul conversion).
        assert_all_parsers_survive(&RecordBuilder::new(56).attr(0x30, 24, 0, 0xFF, 0).build());

        // 5. $DATA attr flagged non-resident but the record is too short to hold the
        //    non-resident size fields (exercises the size-calc block).
        assert_all_parsers_survive(&RecordBuilder::new(56).attr(0x80, 16, 1, 0, 0).build());

        // 6. REPARSE_POINT resident attr whose value offset (rd_u16 @ off+20) points
        //    far past the record (reparse-tag read path). The 16-byte attr prefix puts
        //    bytes [16..20] at value-offset position; we pad to byte 20 then write
        //    0xFFFF as the value offset.
        assert_all_parsers_survive(
            &RecordBuilder::new(56)
                .attr(0xC0, 16, 0, 0, 0)
                .raw(&[0_u8; 4]) // pad [16..20] (value_length region)
                .raw(&0xFFFF_u16.to_le_bytes()) // value_offset = 0xFFFF
                .build(),
        );

        // 7. Attribute with length == 0 (must terminate the loop, not spin).
        assert_all_parsers_survive(&RecordBuilder::new(56).attr(0x10, 0, 0, 0, 0).build());

        // 8. Pure garbage body behind a valid header.
        let garbage: Vec<u8> = (0_u8..=255)
            .map(|n| n.wrapping_mul(31).wrapping_add(7))
            .collect();
        assert_all_parsers_survive(&RecordBuilder::new(56).raw(&garbage).build());

        // 9. Regression pin: a resident attribute whose *declared* length is short
        //    enough to pass the `offset + length <= max_offset` gate, but too short to
        //    actually cover the fixed `value_length` (offset+16..20) / `value_offset`
        //    (offset+20..22) fields the parser reads unconditionally, right at the tail
        //    of the buffer. `crate::parse::parse_record_to_index` used to read these
        //    via raw `&data[a..b]` slicing (no bounds check at all beyond the
        //    attribute-length gate above) and panicked with "range start index ... out
        //    of range" on exactly this shape. Covers StandardInformation, FileName,
        //    ReparsePoint, IndexRoot, ObjectId, and the unknown-type catch-all -- every
        //    arm in direct_index.rs that reads those two fixed fields.
        for type_code in [0x10, 0x30, 0xC0, 0x90, 0x40, 0x77] {
            assert_all_parsers_survive(
                &RecordBuilder::new(56)
                    .attr(type_code, 17, 0, 0, 0)
                    .raw(&[0_u8; 2])
                    .build(),
            );
        }
    }
}
