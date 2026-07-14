// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Tests for `SearchFilters`, `matches_record`, and `apply_search_filters`.
//!
//! Exception: integration test suite for filter pipeline; splitting further
//! would scatter related test fixtures and reduce cohesion.

use uffs_mft::index::{IndexNameRef, MftIndex, ROOT_FRS};
use uffs_text::case_fold::CaseFold;

use super::*;
use crate::compact::{CompactRecord, DriveCompactIndex, build_compact_index};

/// Helper: a basic `CompactRecord` with known values.
fn test_record(name: &str, names: &mut Vec<u8>) -> CompactRecord {
    let offset = u32::try_from(names.len()).expect("offset overflow");
    names.extend_from_slice(name.as_bytes());
    CompactRecord {
        size: 1000,
        allocated: 1024,
        treesize: 5000,
        tree_allocated: 5120,
        created: 100_000_000,
        modified: 200_000_000,
        accessed: 300_000_000,
        file_ref: 0,
        name_offset: offset,
        flags: 0x20, // ARCHIVE
        parent_idx: u32::MAX,
        descendants: 5,
        name_len: u16::try_from(name.len()).expect("name too long"),
        extension_id: 0,
        path_len: 0,
        name_first_byte: name.as_bytes().first().copied().unwrap_or(0),
        _pad: [0; 1],
    }
}

/// Helper: build a compact drive with a single `readme.rs` file.
fn test_drive_with_rs_file() -> DriveCompactIndex {
    let mut idx = MftIndex::new(uffs_mft::platform::DriveLetter::C);

    let root_off = idx.add_name(".");
    let root = idx.get_or_create(ROOT_FRS.into());
    root.stdinfo.set_directory(true);
    root.first_name.name = IndexNameRef::new(root_off, 1, true, IndexNameRef::NO_EXTENSION);
    root.first_name.parent_frs = Into::into(ROOT_FRS);

    let name = "readme.rs";
    let off = idx.add_name(name);
    let ext = idx.intern_extension(name);
    let rec = idx.get_or_create(100.into());
    rec.first_name.name = IndexNameRef::new(
        off,
        u16::try_from(name.len()).expect("name too long"),
        true,
        ext,
    );
    rec.first_name.parent_frs = Into::into(ROOT_FRS);
    rec.stdinfo.flags = 0x20;

    let (drive, _, _) = build_compact_index(uffs_mft::platform::DriveLetter::C, &idx);
    drive
}

// ── Size filters ──────────────────────────────────────────────────

#[test]
fn filter_min_size_rejects_small_files() {
    let mut names = Vec::new();
    let rec = test_record("tiny.txt", &mut names);
    let filters = SearchFilters {
        min_size: Some(2000),
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "file with size=1000 should be rejected by min_size=2000"
    );
}

#[test]
fn filter_max_size_rejects_large_files() {
    let mut names = Vec::new();
    let rec = test_record("big.txt", &mut names);
    let filters = SearchFilters {
        max_size: Some(500),
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "file with size=1000 should be rejected by max_size=500"
    );
}

// ── Date filters ──────────────────────────────────────────────────
// These are the filters that were NOT wired in the v0.4.30 refactor.

#[test]
fn filter_newer_modified_rejects_old_files() {
    let mut names = Vec::new();
    let rec = test_record("old.txt", &mut names);
    let filters = SearchFilters {
        newer_us: Some(999_999_999), // modified must be >= this
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "file with modified=200M should be rejected by newer_us=999M"
    );
}

#[test]
fn filter_older_modified_rejects_new_files() {
    let mut names = Vec::new();
    let rec = test_record("new.txt", &mut names);
    let filters = SearchFilters {
        older_us: Some(100_000_000), // modified must be < this
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "file with modified=200M should be rejected by older_us=100M"
    );
}

#[test]
fn filter_newer_created_rejects_old_files() {
    let mut names = Vec::new();
    let rec = test_record("old.txt", &mut names);
    let filters = SearchFilters {
        newer_created_us: Some(999_999_999),
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "file with created=100M should be rejected by newer_created_us=999M"
    );
}

#[test]
fn filter_newer_accessed_rejects_old_files() {
    let mut names = Vec::new();
    let rec = test_record("old.txt", &mut names);
    let filters = SearchFilters {
        newer_accessed_us: Some(999_999_999),
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "file with accessed=300M should be rejected by newer_accessed_us=999M"
    );
}

// ── Attribute filters ─────────────────────────────────────────────

#[test]
fn filter_attr_require_rejects_missing_bits() {
    let mut names = Vec::new();
    let rec = test_record("file.txt", &mut names);
    // Require HIDDEN (0x02) — but record has ARCHIVE (0x20)
    let filters = SearchFilters {
        attr_require: 0x02,
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "ARCHIVE file should be rejected when HIDDEN is required"
    );
}

#[test]
fn filter_attr_exclude_rejects_matching_bits() {
    let mut names = Vec::new();
    let rec = test_record("file.txt", &mut names);
    // Exclude ARCHIVE (0x20) — record has 0x20
    let filters = SearchFilters {
        attr_exclude: 0x20,
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "ARCHIVE file should be rejected when ARCHIVE is excluded"
    );
}

// ── Extension filter ──────────────────────────────────────────────

#[test]
fn filter_extension_rejects_wrong_extension() {
    let mut names = Vec::new();
    let rec = test_record("photo.jpg", &mut names);
    let filters = SearchFilters {
        extensions: vec!["TXT".to_owned(), "PDF".to_owned()],
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        ".jpg should be rejected when only .txt/.pdf are allowed"
    );
}

#[test]
fn filter_extension_accepts_matching_extension() {
    let mut names = Vec::new();
    let rec = test_record("readme.txt", &mut names);
    let filters = SearchFilters {
        extensions: vec!["TXT".to_owned()],
        ..Default::default()
    };
    assert!(
        filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        ".txt should be accepted when .txt is allowed"
    );
}

#[test]
fn from_params_normalizes_extensions_to_lowercase_without_dot() {
    let filters = SearchFilters::from_params(&SearchFilterParams {
        ext_filter: Some(" .RS, JPG ,PnG "),
        ..Default::default()
    });

    assert_eq!(filters.extensions, ["rs", "jpg", "png"]);
}

#[test]
fn from_params_path_excludes_splits_lowercases_and_normalizes() {
    let filters = SearchFilters::from_params(&SearchFilterParams {
        // Mixed case, forward slashes, blank entries, and surrounding spaces.
        path_excludes: Some(" *AppData* , */.Cargo/* , , *Downloads* "),
        ..Default::default()
    });
    let got: Vec<&str> = filters
        .path_excludes_lower
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        got,
        ["*appdata*", "*\\.cargo\\*", "*downloads*"],
        "comma-split, ASCII-lowered, separator-normalized, blanks dropped"
    );
}

#[test]
fn from_params_path_excludes_none_when_absent_or_all_blank() {
    assert!(
        SearchFilters::from_params(&SearchFilterParams::default())
            .path_excludes_lower
            .is_none()
    );
    assert!(
        SearchFilters::from_params(&SearchFilterParams {
            path_excludes: Some("  , ,"),
            ..Default::default()
        })
        .path_excludes_lower
        .is_none(),
        "all-blank spec collapses to None"
    );
}

#[test]
fn resolve_ext_ids_for_drive_accepts_mixed_case_extensions() {
    let drive = test_drive_with_rs_file();
    let mut filters = SearchFilters::from_params(&SearchFilterParams {
        ext_filter: Some("RS"),
        ..Default::default()
    });

    filters.resolve_ext_ids_for_drive(&drive);

    assert_eq!(
        filters.resolved_ext_ids.len(),
        1,
        "must resolve one extension id"
    );
    let resolved_id = filters.resolved_ext_ids.first().copied();
    let resolved_name = resolved_id.and_then(|id| drive.ext_names.get(usize::from(id)));
    assert_eq!(resolved_name.map(AsRef::as_ref), Some("rs"));
}

#[test]
fn resolve_ext_ids_for_drive_is_robust_to_manual_uppercase_filters() {
    let drive = test_drive_with_rs_file();
    let mut filters = SearchFilters {
        extensions: vec!["RS".to_owned()],
        ..Default::default()
    };

    filters.resolve_ext_ids_for_drive(&drive);

    assert_eq!(
        filters.resolved_ext_ids.len(),
        1,
        "uppercase filter must still resolve"
    );
    let resolved_id = filters.resolved_ext_ids.first().copied();
    let resolved_name = resolved_id.and_then(|id| drive.ext_names.get(usize::from(id)));
    assert_eq!(resolved_name.map(AsRef::as_ref), Some("rs"));
}

// ── extract_extension_after_dot (regression pin 2026-04-21) ──────
//
// Pin the shared extension-extraction helper used by both the
// `matches_record` fallback and the sort-key builder.  It must match
// the semantics of `uffs_mft::index::base::MftIndex::intern_extension`:
// dotless/hidden/trailing-dot names report `extension_id = 0` in the
// compact index, so this helper must return `""` for them.  The
// previous `name.rsplit('.').next().unwrap_or("")` used for the
// fallback returned the whole name for dotless inputs, which let a
// directory literally named `dbt` match `--ext dbt` on drives that did
// not populate the resolved-ID fast-path bucket.

#[test]
fn extract_extension_after_dot_returns_empty_for_dotless_names() {
    assert_eq!(extract_extension_after_dot("dbt"), "");
    assert_eq!(extract_extension_after_dot("README"), "");
    assert_eq!(extract_extension_after_dot(""), "");
}

#[test]
fn extract_extension_after_dot_returns_empty_for_dotfiles() {
    // Hidden dotfiles have dot_pos == 0 → no extension bucket.
    assert_eq!(extract_extension_after_dot(".gitignore"), "");
    assert_eq!(extract_extension_after_dot(".env"), "");
}

#[test]
fn extract_extension_after_dot_returns_empty_for_trailing_dot() {
    // Trailing-dot names have dot_pos == len-1 → no extension bucket.
    assert_eq!(extract_extension_after_dot("foo."), "");
    assert_eq!(extract_extension_after_dot("archive.tar."), "");
}

#[test]
fn extract_extension_after_dot_returns_last_segment() {
    assert_eq!(extract_extension_after_dot("report.txt"), "txt");
    assert_eq!(extract_extension_after_dot("archive.tar.gz"), "gz");
    assert_eq!(extract_extension_after_dot("a.b"), "b");
}

#[test]
fn extract_extension_after_dot_preserves_case() {
    // Case normalisation is the caller's responsibility (e.g.
    // `lowercase_into`).  The helper must NOT fold case itself so it
    // can be used for sort-key material that honours case-sensitive
    // sort contracts.
    assert_eq!(extract_extension_after_dot("PHOTO.JPG"), "JPG");
    assert_eq!(extract_extension_after_dot("Mixed.Ext"), "Ext");
}

// ── Fallback-path extension filter (regression pin 2026-04-21) ───
//
// These pin the `matches_record` fallback branch that fires when a
// caller populated `extensions` but never called
// `resolve_ext_ids_for_drive`.  The pre-fix code used
// `rsplit('.').next().unwrap_or("")` which returned the whole name
// for dotless inputs, so a directory literally named `dbt` (no dot)
// matched `--ext dbt` and was emitted as a spurious row on drives
// where `.dbt` is otherwise absent.

#[test]
fn filter_extension_fallback_rejects_dotless_name() {
    let mut names = Vec::new();
    // `test_record` leaves `extension_id = 0`, matching what the MFT
    // indexer assigns to a dotless name.  With no resolved IDs we
    // take the fallback branch.
    let rec = test_record("dbt", &mut names);
    let filters = SearchFilters {
        extensions: vec!["dbt".to_owned()],
        ..Default::default()
    };
    assert!(
        filters.resolved_ext_ids.is_empty(),
        "precondition: fallback branch under test"
    );
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "dotless name 'dbt' must NOT match --ext dbt via the fallback"
    );
}

#[test]
fn filter_extension_fallback_rejects_dotfile() {
    let mut names = Vec::new();
    let rec = test_record(".gitignore", &mut names);
    let filters = SearchFilters {
        extensions: vec!["gitignore".to_owned()],
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "dotfile '.gitignore' must NOT match --ext gitignore via the fallback"
    );
}

#[test]
fn filter_extension_fallback_rejects_trailing_dot() {
    let mut names = Vec::new();
    let rec = test_record("foo.", &mut names);
    let filters = SearchFilters {
        extensions: vec!["foo".to_owned()],
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "trailing-dot 'foo.' must NOT match --ext foo via the fallback"
    );
}

#[test]
fn filter_extension_fallback_accepts_real_extension_case_insensitively() {
    let mut names = Vec::new();
    let rec = test_record("REPORT.TXT", &mut names);
    let filters = SearchFilters {
        extensions: vec!["txt".to_owned()],
        ..Default::default()
    };
    assert!(
        filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "real .TXT extension must match --ext txt via the fallback (case-insensitive)"
    );
}

// ── Exclude pattern ───────────────────────────────────────────────

#[test]
fn filter_exclude_rejects_matching_name() {
    let mut names = Vec::new();
    let rec = test_record("Thumbs.DB", &mut names);
    let mut lower_buf = Vec::new();
    let filters = SearchFilters {
        exclude_lower: Some("THUMBS*".to_owned()),
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut lower_buf, CaseFold::default_table()),
        "Thumbs.DB should be rejected by exclude=thumbs* (case-insensitive via lower_buf)"
    );
}

// ── Descendants filter ────────────────────────────────────────────

#[test]
fn filter_min_descendants_rejects_low_count() {
    let mut names = Vec::new();
    let rec = test_record("small_dir", &mut names);
    let filters = SearchFilters {
        min_descendants: Some(10),
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "dir with 5 descendants should be rejected by min_descendants=10"
    );
}

#[test]
fn filter_max_descendants_rejects_high_count() {
    let mut names = Vec::new();
    let rec = test_record("big_dir", &mut names);
    let filters = SearchFilters {
        max_descendants: Some(3),
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "dir with 5 descendants should be rejected by max_descendants=3"
    );
}

// ── Hide system ───────────────────────────────────────────────────

#[test]
fn filter_hide_system_rejects_true_metafile() {
    let mut names = Vec::new();
    let rec = test_record("$MFT", &mut names);
    let filters = SearchFilters {
        hide_system: true,
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "$MFT is a reserved metafile and must be rejected by hide_system=true"
    );
}

/// Companion to [`filter_hide_system_rejects_true_metafile`]: an ordinary
/// `$`-prefixed file (the `WinSxS` / `$Recycle.Bin` case) must NOT be hidden.
/// This is the 2026-06-11 fix — `hide_system` no longer rejects every `$`-name.
#[test]
fn filter_hide_system_keeps_ordinary_dollar_file() {
    let mut names = Vec::new();
    let rec = test_record("$Recycle.Bin", &mut names);
    let filters = SearchFilters {
        hide_system: true,
        ..Default::default()
    };
    assert!(
        filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "$Recycle.Bin is an ordinary file, not a metafile — hide_system must keep it"
    );
}

// ── Combined filters ──────────────────────────────────────────────
// Regression: multiple filters must ALL pass (AND semantics).

#[test]
fn filter_combined_all_must_pass() {
    let mut names = Vec::new();
    let rec = test_record("report.txt", &mut names);
    // Size OK (1000 > 500), but modified too old (200M < 999M newer_us)
    let filters = SearchFilters {
        min_size: Some(500),
        newer_us: Some(999_999_999),
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "combined: size passes but date fails → must reject"
    );
}

#[test]
fn filter_all_pass_accepts() {
    let mut names = Vec::new();
    let rec = test_record("report.txt", &mut names);
    let filters = SearchFilters {
        min_size: Some(500),
        max_size: Some(2000),
        newer_us: Some(100_000_000),
        extensions: vec!["TXT".to_owned()],
        ..Default::default()
    };
    assert!(
        filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "all filters pass → must accept"
    );
}
// ── apply_search_filters on DisplayRow ─────────────────────────
// Regression: DisplayRow filtering must mirror CompactRecord filtering.

#[test]
fn apply_search_filters_matches_compact_behavior() {
    let mut rows = vec![
        DisplayRow::new(
            0,
            uffs_mft::platform::DriveLetter::C,
            "C:\\file.txt".to_owned(),
            1000,
            false,
            200_000_000,
            100_000_000,
            300_000_000,
            0x20,
            1024,
            0,
            0,
            0,
        ),
        DisplayRow::new(
            0,
            uffs_mft::platform::DriveLetter::C,
            "C:\\$MFT".to_owned(),
            500_000,
            false,
            200_000_000,
            100_000_000,
            300_000_000,
            0x06,
            512_000,
            0,
            0,
            0,
        ),
    ];

    let filters = SearchFilters {
        hide_system: true,
        ..Default::default()
    };
    apply_search_filters(&mut rows, &filters);
    assert_eq!(rows.len(), 1, "hide_system should remove $MFT");
    let first = rows.first().expect("rows should not be empty");
    assert_eq!(first.name(), "file.txt");
}

// ── Older-created / older-accessed filters ───────────────────────
// Regression: only newer_* directions were tested. older_* must also work.

#[test]
fn filter_older_created_rejects_new_files() {
    let mut names = Vec::new();
    let rec = test_record("new.txt", &mut names);
    // created=100M, older_created_us=50M → file is NEWER than cutoff → reject
    let filters = SearchFilters {
        older_created_us: Some(50_000_000),
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "file with created=100M should be rejected by older_created_us=50M"
    );
}

#[test]
fn filter_older_created_accepts_old_files() {
    let mut names = Vec::new();
    let rec = test_record("old.txt", &mut names);
    // created=100M, older_created_us=999M → file IS older than cutoff → accept
    let filters = SearchFilters {
        older_created_us: Some(999_000_000),
        ..Default::default()
    };
    assert!(
        filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "file with created=100M should be accepted by older_created_us=999M"
    );
}

#[test]
fn filter_older_accessed_rejects_new_files() {
    let mut names = Vec::new();
    let rec = test_record("new.txt", &mut names);
    // accessed=300M, older_accessed_us=100M → file is NEWER than cutoff → reject
    let filters = SearchFilters {
        older_accessed_us: Some(100_000_000),
        ..Default::default()
    };
    assert!(
        !filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "file with accessed=300M should be rejected by older_accessed_us=100M"
    );
}

#[test]
fn filter_older_accessed_accepts_old_files() {
    let mut names = Vec::new();
    let rec = test_record("old.txt", &mut names);
    // accessed=300M, older_accessed_us=999M → file IS older than cutoff → accept
    let filters = SearchFilters {
        older_accessed_us: Some(999_000_000),
        ..Default::default()
    };
    assert!(
        filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "file with accessed=300M should be accepted by older_accessed_us=999M"
    );
}

#[test]
fn filter_older_modified_accepts_old_files() {
    let mut names = Vec::new();
    let rec = test_record("old.txt", &mut names);
    // modified=200M, older_us=999M → file IS older → accept
    let filters = SearchFilters {
        older_us: Some(999_000_000),
        ..Default::default()
    };
    assert!(
        filters.matches_record(&rec, &names, &mut Vec::new(), CaseFold::default_table()),
        "file with modified=200M should be accepted by older_us=999M"
    );
}

// ════════════════════════════════════════════════════════════════════════
// TIME GRAMMAR TESTS — Named Time Ranges
// ════════════════════════════════════════════════════════════════════════

/// FILETIME ticks per day constant for tests.
const FT_PER_DAY: i64 = 86_400 * uffs_time::FILETIME_TICKS_PER_SECOND;
/// FILETIME ticks per second constant for tests.
const FT_PER_SEC: i64 = uffs_time::FILETIME_TICKS_PER_SECOND;
/// Days from FILETIME epoch (1601-01-01) to Unix epoch (1970-01-01).
const DAYS_1601_TO_1970: i64 = uffs_time::FILETIME_UNIX_DIFF / FT_PER_DAY;

/// Helper: compute FILETIME for N days after 1601-01-01.
const fn ft_days(days_since_1601: i64) -> i64 {
    days_since_1601 * FT_PER_DAY
}

#[test]
fn parse_time_bound_duration_7d() {
    let now = ft_days(DAYS_1601_TO_1970 + 100);
    let result = parse_time_bound("7d", now, true).unwrap();
    assert_eq!(result, now - 7 * FT_PER_DAY);
}

#[test]
fn parse_time_bound_duration_24h() {
    let now = ft_days(DAYS_1601_TO_1970 + 100);
    let result = parse_time_bound("24h", now, true).unwrap();
    assert_eq!(result, now - 24 * 3600 * FT_PER_SEC);
}

#[test]
fn parse_time_bound_iso_date() {
    let result = parse_time_bound("1970-01-02", 0, true).unwrap();
    // 1970-01-02 = DAYS_1601_TO_1970 + 1 days from 1601 epoch
    assert_eq!(result, ft_days(DAYS_1601_TO_1970 + 1));
}

#[test]
fn parse_time_bound_today() {
    let now = ft_days(DAYS_1601_TO_1970 + 100) + 42_000_000;
    let result = parse_time_bound("today", now, true).unwrap();
    assert_eq!(result, ft_days(DAYS_1601_TO_1970 + 100));
}

#[test]
fn parse_time_bound_yesterday_newer() {
    let now = ft_days(DAYS_1601_TO_1970 + 100) + 42_000_000;
    let result = parse_time_bound("yesterday", now, true).unwrap();
    assert_eq!(result, ft_days(DAYS_1601_TO_1970 + 99));
}

#[test]
fn parse_time_bound_yesterday_older() {
    let now = ft_days(DAYS_1601_TO_1970 + 100) + 42_000_000;
    let result = parse_time_bound("yesterday", now, false).unwrap();
    assert_eq!(result, ft_days(DAYS_1601_TO_1970 + 100));
}

#[test]
fn parse_time_bound_last_7d() {
    let now = ft_days(DAYS_1601_TO_1970 + 100);
    let result = parse_time_bound("last_7d", now, true).unwrap();
    assert_eq!(result, now - 7 * FT_PER_DAY);
}

#[test]
fn parse_time_bound_last_30d() {
    let now = ft_days(DAYS_1601_TO_1970 + 100);
    let result = parse_time_bound("last_30d", now, true).unwrap();
    assert_eq!(result, now - 30 * FT_PER_DAY);
}

#[test]
fn parse_time_bound_this_year() {
    // 2026-04-04 from FILETIME epoch:
    // Days from 1601 to 2026-04-04 = DAYS_1601_TO_1970 + 20548
    let now_ft = ft_days(DAYS_1601_TO_1970 + 20548);
    let result = parse_time_bound("this_year", now_ft, true).unwrap();
    // Should be Jan 1 2026. Days from 1601 to 2026-01-01:
    let jan1_days = DAYS_1601_TO_1970 + (2026 - 1970) * 365 + (2026 - 1969) / 4;
    assert_eq!(result, ft_days(jan1_days));
}

#[test]
fn parse_time_bound_this_month() {
    // Day 100 from Unix epoch = April 11, 1970.
    let now_ft = ft_days(DAYS_1601_TO_1970 + 100);
    let result = parse_time_bound("this_month", now_ft, true).unwrap();
    assert!(result <= now_ft);
    assert!(result >= now_ft - 31 * FT_PER_DAY);
}

#[test]
fn parse_time_bound_last_year_newer() {
    let now_ft = ft_days(DAYS_1601_TO_1970 + 20548);
    let result = parse_time_bound("last_year", now_ft, true).unwrap();
    let jan1_2025 = DAYS_1601_TO_1970 + (2025 - 1970) * 365 + (2025 - 1969) / 4;
    assert_eq!(result, ft_days(jan1_2025));
}

#[test]
fn parse_time_bound_last_year_older() {
    let now_ft = ft_days(DAYS_1601_TO_1970 + 20548);
    let result = parse_time_bound("last_year", now_ft, false).unwrap();
    let jan1_2026 = DAYS_1601_TO_1970 + (2026 - 1970) * 365 + (2026 - 1969) / 4;
    assert_eq!(result, ft_days(jan1_2026));
}

#[test]
fn parse_time_bound_unknown_returns_none() {
    assert!(parse_time_bound("foobar", ft_days(DAYS_1601_TO_1970 + 100), true).is_none());
}

#[test]
fn parse_time_bound_this_week() {
    // 1601-01-01 was Monday. Unix epoch (1970-01-01) was Thursday.
    // Unix day 7 = 1970-01-08 = Thursday. From 1601: DAYS_1601_TO_1970+7.
    let now_ft = ft_days(DAYS_1601_TO_1970 + 7);
    let result = parse_time_bound("this_week", now_ft, true).unwrap();
    // Monday of that week: 1970-01-05 = DAYS_1601_TO_1970 + 4
    assert_eq!(result, ft_days(DAYS_1601_TO_1970 + 4));
}

// ═══════════════════════════════════════════════════════════════════════════
// parse_size tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn parse_size_plain_bytes() {
    assert_eq!(parse_size("0").unwrap(), 0);
    assert_eq!(parse_size("1024").unwrap(), 1024);
    assert_eq!(parse_size("999999").unwrap(), 999_999);
}

#[test]
fn parse_size_b_suffix() {
    assert_eq!(parse_size("512B").unwrap(), 512);
    assert_eq!(parse_size("512b").unwrap(), 512);
}

#[test]
fn parse_size_kb() {
    assert_eq!(parse_size("1KB").unwrap(), 1024);
    assert_eq!(parse_size("1kb").unwrap(), 1024);
    assert_eq!(parse_size("100KB").unwrap(), 100 * 1024);
}

#[test]
fn parse_size_mb() {
    assert_eq!(parse_size("1MB").unwrap(), 1024 * 1024);
    assert_eq!(parse_size("10mb").unwrap(), 10 * 1024 * 1024);
    assert_eq!(parse_size("100Mb").unwrap(), 100 * 1024 * 1024);
}

#[test]
fn parse_size_gb() {
    assert_eq!(parse_size("1GB").unwrap(), 1024 * 1024 * 1024);
    assert_eq!(parse_size("2gb").unwrap(), 2 * 1024 * 1024 * 1024);
}

#[test]
fn parse_size_tb() {
    assert_eq!(parse_size("1TB").unwrap(), 1024_u64 * 1024 * 1024 * 1024);
    assert_eq!(
        parse_size("2tb").unwrap(),
        2 * 1024_u64 * 1024 * 1024 * 1024
    );
}

#[test]
fn parse_size_whitespace() {
    assert_eq!(parse_size("  1MB  ").unwrap(), 1024 * 1024);
}

#[test]
fn parse_size_invalid() {
    parse_size("").unwrap_err();
    parse_size("abc").unwrap_err();
    parse_size("MB").unwrap_err();
    parse_size("-1KB").unwrap_err();
}

// ═══════════════════════════════════════════════════════════════════════════
// Month extraction + parsing
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn month_from_filetime_1970_epoch() {
    // 1970-01-01 00:00:00 UTC as FILETIME → January
    // FILETIME_UNIX_DIFF = 116_444_736_000_000_000
    let ft = uffs_time::FILETIME_UNIX_DIFF;
    assert_eq!(month_from_unix_micros(ft), 1);
}

#[test]
fn month_from_filetime_zero_is_january() {
    // FILETIME 0 = 1601-01-01 → January (default for unset)
    assert_eq!(month_from_unix_micros(0), 1);
}

#[test]
fn month_from_filetime_december() {
    // 2025-12-15 00:00:00 UTC as FILETIME → December
    let unix_us = 1_765_756_800_000_000_i64;
    let ft = unix_us * uffs_time::FILETIME_TICKS_PER_MICROSECOND + uffs_time::FILETIME_UNIX_DIFF;
    assert_eq!(month_from_unix_micros(ft), 12);
}

#[test]
fn month_from_filetime_pre_1970() {
    // 1959-12-02 03:45:50 UTC → December
    let unix_secs: i64 = -318_197_650;
    let ft = unix_secs * uffs_time::FILETIME_TICKS_PER_SECOND + uffs_time::FILETIME_UNIX_DIFF;
    assert_eq!(month_from_unix_micros(ft), 12);
}

#[test]
fn month_from_filetime_leap_day() {
    // 2000-02-29 12:00:00 UTC → February
    let unix_secs: i64 = 951_825_600;
    let ft = unix_secs * uffs_time::FILETIME_TICKS_PER_SECOND + uffs_time::FILETIME_UNIX_DIFF;
    assert_eq!(month_from_unix_micros(ft), 2);
}

#[test]
fn month_from_filetime_year_boundary() {
    // 1999-12-31 23:59:59 → December
    let unix_secs_dec31: i64 = 946_684_799;
    let ft_dec31 =
        unix_secs_dec31 * uffs_time::FILETIME_TICKS_PER_SECOND + uffs_time::FILETIME_UNIX_DIFF;
    assert_eq!(month_from_unix_micros(ft_dec31), 12);

    // 2000-01-01 00:00:00 → January
    let unix_secs_jan01: i64 = 946_684_800;
    let ft_jan01 =
        unix_secs_jan01 * uffs_time::FILETIME_TICKS_PER_SECOND + uffs_time::FILETIME_UNIX_DIFF;
    assert_eq!(month_from_unix_micros(ft_jan01), 1);
}

#[test]
fn month_from_filetime_each_month() {
    // Verify all 12 months are reachable — use the 15th of each month in 2024.
    let months_unix_secs: [(u32, i64); 12] = [
        (1, 1_705_276_800),  // 2024-01-15
        (2, 1_707_955_200),  // 2024-02-15
        (3, 1_710_460_800),  // 2024-03-15
        (4, 1_713_139_200),  // 2024-04-15
        (5, 1_715_731_200),  // 2024-05-15
        (6, 1_718_409_600),  // 2024-06-15
        (7, 1_721_001_600),  // 2024-07-15
        (8, 1_723_680_000),  // 2024-08-15
        (9, 1_726_358_400),  // 2024-09-15
        (10, 1_728_950_400), // 2024-10-15
        (11, 1_731_628_800), // 2024-11-15
        (12, 1_734_220_800), // 2024-12-15
    ];
    for (expected_month, unix_secs) in months_unix_secs {
        let ft = unix_secs * uffs_time::FILETIME_TICKS_PER_SECOND + uffs_time::FILETIME_UNIX_DIFF;
        assert_eq!(
            month_from_unix_micros(ft),
            expected_month,
            "month mismatch for unix_secs={unix_secs}"
        );
    }
}

#[test]
fn parse_month_spec_single_month() {
    assert_eq!(parse_month_spec("january"), vec![1]);
    assert_eq!(parse_month_spec("Jan"), vec![1]);
    assert_eq!(parse_month_spec("dec"), vec![12]);
}

#[test]
fn parse_month_spec_quarter() {
    assert_eq!(parse_month_spec("Q1"), vec![1, 2, 3]);
    assert_eq!(parse_month_spec("q4"), vec![10, 11, 12]);
}

#[test]
fn parse_month_spec_combo() {
    assert_eq!(parse_month_spec("jan,feb"), vec![1, 2]);
    assert_eq!(parse_month_spec("Q1,october"), vec![1, 2, 3, 10]);
}

#[test]
fn parse_month_spec_dedup() {
    // Q1 includes jan; jan should not appear twice
    assert_eq!(parse_month_spec("Q1,jan"), vec![1, 2, 3]);
}

#[test]
fn parse_month_spec_unknown_ignored() {
    assert_eq!(parse_month_spec("foo"), Vec::<u32>::new());
}

// ═══════════════════════════════════════════════════════════════════════════
// Extension collection expansion
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn from_params_expands_extension_collections() {
    let filters = SearchFilters::from_params(&SearchFilterParams {
        ext_filter: Some("executables"),
        ..Default::default()
    });
    assert!(filters.extensions.contains(&"exe".to_owned()));
    assert!(filters.extensions.contains(&"bat".to_owned()));
    assert!(filters.extensions.contains(&"ps1".to_owned()));
}

#[test]
fn from_params_expands_documents_collection() {
    let filters = SearchFilters::from_params(&SearchFilterParams {
        ext_filter: Some("documents,rs"),
        ..Default::default()
    });
    // Should contain both expanded docs and the literal "rs"
    assert!(filters.extensions.contains(&"pdf".to_owned()));
    assert!(filters.extensions.contains(&"docx".to_owned()));
    assert!(filters.extensions.contains(&"rs".to_owned()));
}

/// Regression: `from_params` must convert CLI percentage to per-million scale.
/// `--min-bulkiness 200` (200%) → internal `2_000_000`.
#[test]
fn from_params_converts_bulkiness_percentage_to_per_million() {
    let filters = SearchFilters::from_params(&SearchFilterParams {
        min_bulkiness: Some(200),
        max_bulkiness: Some(500),
        ..Default::default()
    });
    assert_eq!(
        filters.min_bulkiness,
        Some(2_000_000),
        "200% → 2_000_000 per-million"
    );
    assert_eq!(
        filters.max_bulkiness,
        Some(5_000_000),
        "500% → 5_000_000 per-million"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// path_contains separator normalization
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn normalize_path_separators_collapses_double_backslash() {
    assert_eq!(normalize_path_separators("users\\\\rnio"), "users\\rnio");
}

#[test]
fn normalize_path_separators_replaces_forward_slash() {
    assert_eq!(normalize_path_separators("users/rnio"), "users\\rnio");
}

#[test]
fn normalize_path_separators_mixed_separators() {
    assert_eq!(
        normalize_path_separators("github//ultra\\\\fast/search"),
        "github\\ultra\\fast\\search"
    );
}

#[test]
fn normalize_path_separators_single_backslash_unchanged() {
    assert_eq!(normalize_path_separators("users\\rnio"), "users\\rnio");
}

#[test]
fn normalize_path_separators_no_separators() {
    assert_eq!(normalize_path_separators("rnio"), "rnio");
}

#[test]
fn from_params_path_contains_normalizes_separators() {
    let filters = SearchFilters::from_params(&SearchFilterParams {
        path_contains: Some("Users\\\\rnio\\\\GitHub"),
        ..Default::default()
    });
    assert_eq!(
        filters.path_contains_lower.as_deref(),
        Some("users\\rnio\\github"),
        "double backslashes should be collapsed to single"
    );
}

#[test]
fn from_params_path_contains_normalizes_forward_slashes() {
    let filters = SearchFilters::from_params(&SearchFilterParams {
        path_contains: Some("Users/rnio/GitHub"),
        ..Default::default()
    });
    assert_eq!(
        filters.path_contains_lower.as_deref(),
        Some("users\\rnio\\github"),
        "forward slashes should be converted to backslashes"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// `is_ext_only` — gate for the `ExtensionIndex` fast path
// ═══════════════════════════════════════════════════════════════════════════
//
// Regression pin for the 2026-04-19 fix: `--hide-system` / `--hide-ads`
// must NOT disqualify the ext fast path, because those two predicates
// are cheap enough to apply per-candidate inside the
// `collect_global_top_n_numeric` fast-path loop.  Prior to this pin
// every `uffs *.<ext> --hide-system --hide-ads` query (the default
// bench shape) fell back to a 7 M-record linear scan.
//
// Anything heavier than `hide_system` / `hide_ads` — size, date,
// attribute, exclude, descendant, bulkiness, name/path length,
// allocated, treesize, tree_allocated, month, type — must continue to
// disqualify the fast path because applying it per-candidate would
// require non-trivial work (date parsing, path resolution, allocated-
// size lookup, etc.) that defeats the O(K) advantage.

#[test]
fn is_ext_only_true_for_plain_ext_filter() {
    let filters = SearchFilters {
        extensions: vec!["dbt".to_owned()],
        ..Default::default()
    };
    assert!(filters.is_ext_only());
}

#[test]
fn is_ext_only_true_with_hide_system_regression_pin() {
    // Regression pin: `--hide-system` MUST remain compatible with the
    // ext fast path.  The fast-path loop applies the cached
    // `is_system_metafile()` check per-candidate (~1 ns per record)
    // instead of the previous behaviour of rejecting the fast path
    // entirely and falling back to an O(N) linear scan of every record
    // on every loaded drive.
    let filters = SearchFilters {
        hide_system: true,
        extensions: vec!["dbt".to_owned()],
        ..Default::default()
    };
    assert!(
        filters.is_ext_only(),
        "hide_system=true must not disqualify the ext fast path"
    );
}

#[test]
fn is_ext_only_true_with_hide_ads_regression_pin() {
    // Regression pin: `--hide-ads` MUST remain compatible with the ext
    // fast path.  The fast-path loop performs one name-arena read plus
    // `memchr::memchr(b':')` per candidate (~30 ns), only when the
    // flag is actually set, which is negligible compared to the full
    // scan it replaces.
    let filters = SearchFilters {
        hide_ads: true,
        extensions: vec!["dbt".to_owned()],
        ..Default::default()
    };
    assert!(
        filters.is_ext_only(),
        "hide_ads=true must not disqualify the ext fast path"
    );
}

#[test]
fn is_ext_only_true_with_both_hide_flags_regression_pin() {
    // The actual shape produced by `uffs *.dbt --hide-system --hide-ads`
    // (which is what the cross-tool benchmark runs).
    let filters = SearchFilters {
        hide_system: true,
        hide_ads: true,
        extensions: vec!["dbt".to_owned()],
        ..Default::default()
    };
    assert!(
        filters.is_ext_only(),
        "hide_system + hide_ads must not disqualify the ext fast path"
    );
}

#[test]
fn is_ext_only_false_without_extension_filter() {
    let filters = SearchFilters {
        hide_system: true,
        ..Default::default()
    };
    assert!(
        !filters.is_ext_only(),
        "empty extensions must disqualify: there is nothing to look up in the ext-index"
    );
}

#[test]
fn is_ext_only_false_with_size_filter() {
    let filters = SearchFilters {
        min_size: Some(1000),
        extensions: vec!["dll".to_owned()],
        ..Default::default()
    };
    assert!(
        !filters.is_ext_only(),
        "size filter requires per-record size read, which the fast path does not apply"
    );
}

#[test]
fn is_ext_only_false_with_date_filter() {
    let filters = SearchFilters {
        newer_us: Some(1_000_000),
        extensions: vec!["dll".to_owned()],
        ..Default::default()
    };
    assert!(
        !filters.is_ext_only(),
        "date filter requires per-record timestamp read, not applied in fast path"
    );
}

#[test]
fn is_ext_only_false_with_attribute_filter() {
    let filters = SearchFilters {
        attr_require: 0x0002, // HIDDEN
        extensions: vec!["dll".to_owned()],
        ..Default::default()
    };
    assert!(
        !filters.is_ext_only(),
        "attribute filter requires per-record flags read, not applied in fast path"
    );
}

#[test]
fn is_ext_only_false_with_type_filter() {
    let filters = SearchFilters {
        extensions: vec!["dll".to_owned()],
        type_filter: Some("picture".to_owned()),
        ..Default::default()
    };
    // NB: field order above is correct — `extensions` (field 15) precedes
    // `type_filter` (field 19) in the `SearchFilters` struct definition.
    assert!(
        !filters.is_ext_only(),
        "type filter resolves to a superset of extensions, not applied in fast path"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Attribute presets
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn deleted_filter_selects_only_tombstoned_records() {
    let mut names = Vec::new();
    let live = test_record("live.txt", &mut names); // flags = 0x20 (ARCHIVE)
    let mut gone = test_record("gone.txt", &mut names);
    gone.flags |= DELETED_TOMBSTONE_FLAG; // diff-marked deleted (bit 31)
    // Collision guard: a record with the real NTFS Integrity attribute
    // (FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x8000) must NOT read as a diff delete
    // — the marker is bit 31, deliberately clear of every NTFS attribute bit.
    let mut integrity = test_record("integrity.dat", &mut names);
    integrity.flags |= 0x8000;

    let fold = CaseFold::default_table();

    // `--deleted` (Some(true)) is a real filter and keeps only the tombstone.
    let only_deleted = SearchFilters {
        deleted: Some(true),
        ..Default::default()
    };
    assert!(
        !only_deleted.is_empty(),
        "--deleted must register as active"
    );
    assert!(only_deleted.matches_record(&gone, &names, &mut Vec::new(), fold));
    assert!(!only_deleted.matches_record(&live, &names, &mut Vec::new(), fold));
    assert!(
        !only_deleted.matches_record(&integrity, &names, &mut Vec::new(), fold),
        "the NTFS Integrity attribute (0x8000) must not be read as a diff delete",
    );

    // Some(false) keeps only live records.
    let only_live = SearchFilters {
        deleted: Some(false),
        ..Default::default()
    };
    assert!(!only_live.matches_record(&gone, &names, &mut Vec::new(), fold));
    assert!(only_live.matches_record(&live, &names, &mut Vec::new(), fold));

    // None = no filter: both pass.
    let no_filter = SearchFilters::default();
    assert!(no_filter.matches_record(&gone, &names, &mut Vec::new(), fold));
    assert!(no_filter.matches_record(&live, &names, &mut Vec::new(), fold));
}

#[path = "tests_ext.rs"]
mod tests_ext;

#[path = "tests_malformed.rs"]
mod tests_malformed;
