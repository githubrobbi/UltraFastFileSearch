// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Tests for Alternate Data Stream (ADS) storage and iteration.
//!
//! Regression tests ensuring ADS entries are never silently dropped.

use tests_helpers::push_index_name;

use super::*;

/// Create a minimal index with a file that has ADS streams.
fn create_index_with_ads() -> MftIndex {
    let mut index = MftIndex::new(crate::platform::DriveLetter::M);

    // Create a file record (FRS 100)
    let name_ref = push_index_name(&mut index, "test.pdf");
    let ri = index.get_or_create(100.into());
    ri.first_name.name = name_ref;
    ri.first_name.parent_frs = Into::into(5);
    ri.set_has_default_data();
    ri.first_stream.size.length = 1024;
    ri.first_stream.size.allocated = 4096;
    ri.first_stream.flags = 8 << 2; // type_name_id=8 for $DATA
    ri.stream_count = 1;
    ri.total_stream_count = 1;

    // Add ADS: Zone.Identifier
    let ads_name_offset = index.add_name("Zone.Identifier");
    let ads_name_ref = IndexNameRef::new(
        ads_name_offset,
        u16::try_from("Zone.Identifier".len()).unwrap(),
        true,
        0,
    );
    let ads_si = u32::try_from(index.streams.len()).unwrap();
    index.streams.push(IndexStreamInfo {
        size: SizeInfo {
            length: 228,
            allocated: 0,
        },
        next_entry: NO_ENTRY,
        name: ads_name_ref,
        flags: 8 << 2, // type_name_id=8 for $DATA
        _pad0: [0; 3],
    });

    // Chain ADS to the record's stream list
    let rec_idx = index.frs_to_idx_opt(100.into()).unwrap();
    let rec = &mut index.records[rec_idx];
    rec.first_stream.next_entry = ads_si;
    rec.stream_count += 1;
    rec.total_stream_count += 1;

    index
}

#[test]
fn ads_stream_count_includes_ads() {
    let index = create_index_with_ads();
    let ri = index.frs_to_idx_opt(100.into()).unwrap();
    let rec = &index.records[ri];

    // File should have 2 streams: default $DATA + Zone.Identifier ADS
    assert_eq!(rec.stream_count, 2, "stream_count must include ADS");
    assert_eq!(
        rec.total_stream_count, 2,
        "total_stream_count must include ADS"
    );
}

#[test]
fn ads_stream_iterable_via_iter_streams() {
    let index = create_index_with_ads();
    let ri = index.frs_to_idx_opt(100.into()).unwrap();
    let rec = &index.records[ri];

    let streams: Vec<(u16, &IndexStreamInfo)> = index.iter_streams(rec).collect();
    assert_eq!(streams.len(), 2, "iter_streams must yield default + ADS");

    // First stream: default $DATA (unnamed)
    let (idx0, s0) = &streams[0];
    assert_eq!(*idx0, 0);
    assert!(
        index.stream_name(s0).is_empty(),
        "default stream has no name"
    );
    assert_eq!(s0.size.length, 1024);
    assert!(s0.is_output_stream(), "default $DATA is an output stream");

    // Second stream: ADS (Zone.Identifier)
    let (idx1, s1) = &streams[1];
    assert_eq!(*idx1, 1);
    assert_eq!(index.stream_name(s1), "Zone.Identifier");
    assert_eq!(s1.size.length, 228);
    assert!(s1.is_output_stream(), "ADS $DATA is an output stream");
}

#[test]
fn ads_stream_accessible_via_get_stream_at() {
    let index = create_index_with_ads();
    let ri = index.frs_to_idx_opt(100.into()).unwrap();
    let rec = &index.records[ri];

    // Index 0: default $DATA
    let s0 = index.get_stream_at(rec, 0).expect("stream 0 must exist");
    assert_eq!(index.stream_name(s0), "", "default $DATA stream is unnamed");

    // Index 1: ADS
    let s1 = index.get_stream_at(rec, 1).expect("stream 1 must exist");
    assert_eq!(index.stream_name(s1), "Zone.Identifier");

    // Index 2: out of bounds
    assert!(
        index.get_stream_at(rec, 2).is_none(),
        "stream 2 must not exist"
    );
}

#[test]
fn is_output_stream_accepts_data_streams() {
    // type_name_id=8 ($DATA) → is_output_stream = true
    let data_stream = IndexStreamInfo {
        flags: 8 << 2,
        ..Default::default()
    };
    assert!(
        data_stream.is_output_stream(),
        "$DATA must be output stream"
    );

    // type_name_id=0 ($I30) → is_output_stream = true
    let i30_stream = IndexStreamInfo {
        flags: 0,
        ..Default::default()
    };
    assert!(i30_stream.is_output_stream(), "$I30 must be output stream");

    // type_name_id=4 ($OBJECT_ID) → is_output_stream = false
    let internal_stream = IndexStreamInfo {
        flags: 4 << 2,
        ..Default::default()
    };
    assert!(
        !internal_stream.is_output_stream(),
        "internal stream must NOT be output stream"
    );
}
