// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Windows-specific parsing bridges plus direct-to-index helpers.
//! Split into focused submodules while preserving the legacy `io` parser
//! surface.

mod fragment;
mod fragment_extension;
mod index;
mod index_extension;
pub(crate) mod unified;

#[expect(
    deprecated,
    reason = "re-exporting deprecated API for backward compatibility"
)]
pub use fragment::parse_record_to_fragment;
pub use index::parse_record_to_index;
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
    use super::{parse_record_to_index, process_record};
    use crate::index::{MftIndex, MftIndexFragment};

    #[test]
    fn parse_record_to_index_rejects_short_buffers() {
        let mut index = MftIndex::new(crate::platform::DriveLetter::C);
        assert!(!parse_record_to_index(&[0_u8; 3], 42, &mut index));
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
    fn assert_all_parsers_survive(record: &[u8]) {
        // The return value is irrelevant — reaching the end of this function
        // at all means none of the three parsers panicked, which is the
        // property under test. `black_box` consumes each result so it is
        // neither an unused binding nor an under-typed `let _` discard.
        let mut index = MftIndex::new(crate::platform::DriveLetter::C);
        core::hint::black_box(parse_record_to_index(record, 42, &mut index));

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
    }
}
