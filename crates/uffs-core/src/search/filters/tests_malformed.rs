// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! WI-4.4 malformed-name hot-path filter tests.
//!
//! The decisive contract: `SearchFilters.malformed` is evaluated against the
//! LOSSLESS name bytes (`CompactRecord::name_bytes`), NOT the lossy `&str`
//! view. A regression to `name()` would make every name look well-formed
//! (a lossy `&str` is always valid UTF-8), so the surrogate test below would
//! fail — it pins the feature's whole reason for existing.

use uffs_text::case_fold::CaseFold;

use super::*;
use crate::compact::CompactRecord;

/// WTF-8 of `f` + lone-high-surrogate(U+D800) + `o` — legal on NTFS, illegal
/// in UTF-8 (`0xD800` → 3-byte `ED A0 80`).
const SURROGATE_NAME_WTF8: &[u8] = &[b'f', 0xED, 0xA0, 0x80, b'o'];

/// Build a `CompactRecord` whose name in the arena is the given raw bytes
/// (which may be ill-formed WTF-8 — that is the point).
fn record_with_raw_name(raw: &[u8], names: &mut Vec<u8>) -> CompactRecord {
    let offset = u32::try_from(names.len()).expect("offset overflow");
    names.extend_from_slice(raw);
    CompactRecord {
        size: 1000,
        allocated: 1024,
        treesize: 0,
        tree_allocated: 0,
        created: 1,
        modified: 2,
        accessed: 3,
        file_ref: 0,
        name_offset: offset,
        flags: 0x20,
        parent_idx: u32::MAX,
        descendants: 0,
        name_len: u16::try_from(raw.len()).expect("name too long"),
        extension_id: 0,
        path_len: 0,
        name_first_byte: raw.first().copied().unwrap_or(0),
        _pad: [0; 1],
    }
}

#[test]
fn malformed_true_keeps_only_ill_formed_names() {
    let mut names = Vec::new();
    let bad = record_with_raw_name(SURROGATE_NAME_WTF8, &mut names);
    let good = record_with_raw_name(b"readme.txt", &mut names);
    let filters = SearchFilters {
        malformed: Some(true),
        ..Default::default()
    };
    assert!(
        filters.matches_record(&bad, &names, &mut Vec::new(), CaseFold::default_table()),
        "an ill-formed (surrogate) name must match malformed=Some(true)"
    );
    assert!(
        !filters.matches_record(&good, &names, &mut Vec::new(), CaseFold::default_table()),
        "a well-formed name must NOT match malformed=Some(true)"
    );
}

#[test]
fn malformed_false_keeps_only_well_formed_names() {
    let mut names = Vec::new();
    let bad = record_with_raw_name(SURROGATE_NAME_WTF8, &mut names);
    let good = record_with_raw_name(b"readme.txt", &mut names);
    let filters = SearchFilters {
        malformed: Some(false),
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&bad, &names, &mut Vec::new(), CaseFold::default_table()),
        "an ill-formed name must NOT match malformed=Some(false)"
    );
    assert!(
        filters.matches_record(&good, &names, &mut Vec::new(), CaseFold::default_table()),
        "a well-formed name must match malformed=Some(false)"
    );
}

#[test]
fn malformed_none_is_a_no_op() {
    // The default (no malformed filter) must keep both kinds of names — this
    // guards the "no flag = business as usual" contract.
    let mut names = Vec::new();
    let bad = record_with_raw_name(SURROGATE_NAME_WTF8, &mut names);
    let good = record_with_raw_name(b"readme.txt", &mut names);
    let filters = SearchFilters::default();
    assert!(filters.malformed.is_none());
    assert!(filters.matches_record(&bad, &names, &mut Vec::new(), CaseFold::default_table()));
    assert!(filters.matches_record(&good, &names, &mut Vec::new(), CaseFold::default_table()));
}

#[test]
fn malformed_filter_uses_lossless_bytes_not_lossy_view() {
    // Regression pin: the record's lossy `&str` view of a surrogate name is
    // "" (empty — not valid UTF-8), which IS valid UTF-8 and would read as
    // well-formed. The filter must instead consult name_bytes and see the
    // ill-formed bytes. If this ever regresses to name()/`&str`, the
    // malformed=Some(true) match below flips to false and this test fails.
    let mut names = Vec::new();
    let bad = record_with_raw_name(SURROGATE_NAME_WTF8, &mut names);
    // Confirm the premise: the lossy view loses the ill-formedness.
    assert!(
        core::str::from_utf8(bad.name_bytes(&names)).is_err(),
        "fixture must actually be ill-formed UTF-8"
    );
    assert_eq!(
        bad.name(&names),
        "",
        "lossy &str view of an ill-formed name is empty"
    );
    // The filter still finds it.
    let filters = SearchFilters {
        malformed: Some(true),
        ..Default::default()
    };
    assert!(filters.matches_record(&bad, &names, &mut Vec::new(), CaseFold::default_table()));
}

#[test]
fn malformed_makes_is_empty_false() {
    // Regression: a malformed-only query must NOT count as "no filters".
    // The numeric match-all gate is `has_filters = !is_empty()`, so if
    // `is_empty()` ignored `malformed`, `matches_record` would be skipped and
    // `uffs "*" --malformed` would return every (well-formed) record.
    assert!(
        SearchFilters::default().is_empty(),
        "default has no filters"
    );
    assert!(
        !SearchFilters {
            malformed: Some(true),
            ..Default::default()
        }
        .is_empty(),
        "--malformed must register as an active filter"
    );
    assert!(
        !SearchFilters {
            malformed: Some(false),
            ..Default::default()
        }
        .is_empty(),
        "--well-formed must register as an active filter"
    );
}
