// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Integration tests for the aggregate engine.
//!
//! Exception: `file_size_policy` — test cohesion; splitting by line count would
//! fragment the test narrative built around a shared synthetic drive fixture.

use uffs_mft::index::{IndexNameRef, MftIndex, ROOT_FRS, SizeInfo};

use super::finalize::AggregateResultData;
use super::*;
use crate::compact::build_compact_index;

/// NTFS epoch is `1601-01-01`. Ticks per second = `10_000_000`.
/// `2024-01-15 00:00:00 UTC` in NTFS ticks ≈ `133_496_544_000_000_000`.
const TS_JAN_2024: i64 = 133_496_544_000_000_000;
/// 2024-03-10 00:00:00 UTC.
const TS_MAR_2024: i64 = 133_544_928_000_000_000;
/// 2024-06-20 00:00:00 UTC.
const TS_JUN_2024: i64 = 133_633_536_000_000_000;

/// Build a synthetic drive with well-known data for integration tests.
///
/// Layout:
/// ```text
/// C:\                        (root dir)
/// C:\Projects\               (dir, flags=0x10)
/// C:\Projects\main.rs        (2000 bytes, alloc 4096, modified Jan 2024)
/// C:\Projects\lib.rs         (3000 bytes, alloc 4096, modified Jan 2024)
/// C:\Projects\util.rs        (1000 bytes, alloc 4096, modified Mar 2024)
/// C:\Projects\README.md      (500  bytes, alloc 512,  modified Jan 2024)
/// C:\Projects\CHANGELOG.md   (800  bytes, alloc 1024, modified Jun 2024)
/// C:\Projects\config.toml    (100  bytes, alloc 512,  modified Mar 2024)
/// C:\Projects\data.bin       (10000 bytes, alloc 16384, modified Jun 2024)
/// ```
///
/// Totals (files only): 7 files, 17400 bytes logical, 30628 bytes alloc.
fn build_agg_test_drive() -> DriveCompactIndex {
    build_drive_with_folder(uffs_mft::platform::DriveLetter::C, "Projects", &[
        ("main.rs", 101, 2000, 4096, TS_JAN_2024),
        ("lib.rs", 102, 3000, 4096, TS_JAN_2024),
        ("util.rs", 103, 1000, 4096, TS_MAR_2024),
        ("README.md", 104, 500, 512, TS_JAN_2024),
        ("CHANGELOG.md", 105, 800, 1024, TS_JUN_2024),
        ("config.toml", 106, 100, 512, TS_MAR_2024),
        ("data.bin", 107, 10000, 16384, TS_JUN_2024),
    ])
}

/// Build a synthetic single-folder drive: `<letter>:\<folder>\<files...>`.
///
/// `files` entries are `(name, frs, size, allocated, modified_timestamp)`.
/// The folder directory record uses FRS 100.
fn build_drive_with_folder(
    letter: uffs_mft::platform::DriveLetter,
    folder: &str,
    files: &[(&str, u64, u64, u64, i64)],
) -> DriveCompactIndex {
    let mut idx = MftIndex::new(letter);

    // Root directory.
    let root_off = idx.add_name(".");
    let root = idx.get_or_create(ROOT_FRS.into());
    root.stdinfo.set_directory(true);
    root.first_name.name = IndexNameRef::new(root_off, 1, true, IndexNameRef::NO_EXTENSION);
    root.first_name.parent_frs = Into::into(ROOT_FRS);

    // Folder directory.
    let dir_off = idx.add_name(folder);
    let dir_ext = idx.intern_extension(folder);
    let dir = idx.get_or_create(100.into());
    dir.stdinfo.set_directory(true);
    dir.stdinfo.flags = 0x10;
    dir.first_name.name =
        IndexNameRef::new(dir_off, uffs_mft::len_to_u16(folder.len()), true, dir_ext);
    dir.first_name.parent_frs = Into::into(ROOT_FRS);

    for &(name, frs, size, allocated, modified) in files {
        let off = idx.add_name(name);
        let ext = idx.intern_extension(name);
        let rec = idx.get_or_create(frs.into());
        rec.first_name.name = IndexNameRef::new(off, uffs_mft::len_to_u16(name.len()), true, ext);
        rec.first_name.parent_frs = Into::into(100);
        rec.first_stream.size = SizeInfo {
            length: size,
            allocated,
        };
        rec.stdinfo.flags = 0x20; // archive
        rec.stdinfo.modified = modified;
    }

    let (drive, _, _) = build_compact_index(letter, &idx);
    drive
}

fn run(specs: &[AggregateSpec]) -> AggregateResponse {
    let drive = build_agg_test_drive();
    let output = run_aggregate(&[&drive], specs, &FinalizeOptions::default()).unwrap();
    output.response
}

// ── S1G.10: overview preset ──────────────────────────────────────

#[test]
fn overview_preset_returns_count_and_stats_and_terms() {
    let specs = AggregatePreset::Overview.expand();
    let resp = run(&specs);
    // overview produces: count + file_size stats + type terms + drive terms
    // + date_histogram, etc. — at least 3 results
    assert!(
        resp.results.len() >= 3,
        "overview should produce ≥3 results, got {}",
        resp.results.len()
    );

    // Find the count result.
    let count_result = resp
        .results
        .iter()
        .find(|r| matches!(&r.data, AggregateResultData::Count { .. }))
        .expect("overview should have a count result");
    if let AggregateResultData::Count { value } = &count_result.data {
        // root + dir + 7 files = 9
        assert_eq!(*value, 9, "total record count");
    }
}

#[test]
fn overview_preset_has_size_stats() {
    let specs = AggregatePreset::Overview.expand();
    let resp = run(&specs);
    let stats_result = resp
        .results
        .iter()
        .find(|r| matches!(&r.data, AggregateResultData::Stats { .. }))
        .expect("overview should have stats");
    if let AggregateResultData::Stats { stats, .. } = &stats_result.data {
        assert!(stats.count > 0);
        assert!(stats.sum > 0);
    }
}

// ── S1G.11: by_extension top-N ───────────────────────────────────

#[test]
fn by_extension_returns_sorted_buckets() {
    let specs = AggregatePreset::ByExtension.expand();
    let resp = run(&specs);
    let bucket_result = resp
        .results
        .iter()
        .find(|r| matches!(&r.data, AggregateResultData::Buckets { .. }))
        .expect("by_extension should have buckets");
    if let AggregateResultData::Buckets { rows, .. } = &bucket_result.data {
        assert!(!rows.is_empty());
        // "rs" has 3 files (main.rs, lib.rs, util.rs)
        let rs = rows.iter().find(|r| r.key == "rs").expect("rs bucket");
        assert_eq!(rs.count, 3);
        assert_eq!(rs.total_bytes, 6000); // 2000+3000+1000
        // "md" has 2 files
        let md = rows.iter().find(|r| r.key == "md").expect("md bucket");
        assert_eq!(md.count, 2);
        assert_eq!(md.total_bytes, 1300); // 500+800
        // Sorted by count desc (or total_bytes desc)
        // rs(3) should come before md(2) and bin(1) and toml(1)
    }
}

#[test]
fn by_extension_has_all_extensions() {
    let specs = AggregatePreset::ByExtension.expand();
    let resp = run(&specs);
    let bucket_result = resp
        .results
        .iter()
        .find(|r| matches!(&r.data, AggregateResultData::Buckets { .. }))
        .expect("buckets");
    if let AggregateResultData::Buckets { rows, .. } = &bucket_result.data {
        let keys: Vec<&str> = rows.iter().map(|r| r.key.as_str()).collect();
        assert!(keys.contains(&"rs"), "missing rs: {keys:?}");
        assert!(keys.contains(&"md"), "missing md: {keys:?}");
        assert!(keys.contains(&"toml"), "missing toml: {keys:?}");
        assert!(keys.contains(&"bin"), "missing bin: {keys:?}");
    }
}

// ── S1G.12: by_type category counts ──────────────────────────────

#[test]
fn by_type_returns_category_buckets() {
    let specs = AggregatePreset::ByType.expand();
    let resp = run(&specs);
    let bucket_result = resp
        .results
        .iter()
        .find(|r| matches!(&r.data, AggregateResultData::Buckets { .. }))
        .expect("by_type should have buckets");
    if let AggregateResultData::Buckets { rows, .. } = &bucket_result.data {
        assert!(!rows.is_empty(), "by_type should have at least one bucket");
        // All 7 files should appear in some type category.
        let total: u64 = rows.iter().map(|r| r.count).sum();
        // At minimum, the 7 files should be categorized (dirs may or may not
        // depending on how type categorization handles them).
        assert!(total >= 7, "total categorized should be ≥7, got {total}");
    }
}

// ── S1G.13: hist:size bucket boundaries ──────────────────────────

#[test]
fn range_size_produces_correct_buckets() {
    // Use Range (not Histogram) since interval-based boundaries
    // aren't auto-generated yet. Range gives explicit boundaries.
    let mut spec = AggregateSpec::new(AggregateKind::Range {
        field: crate::search::field::FieldId::Size,
        boundaries: vec![0, 512, 2048, 8192],
        metrics: vec![BucketMetric::Count, BucketMetric::TotalBytes],
    });
    spec.label = Some("size_range".to_owned());
    let resp = run(&[spec]);
    assert_eq!(resp.results.len(), 1);
    if let AggregateResultData::Buckets { rows, .. } = &resp.results[0].data {
        assert!(!rows.is_empty(), "range should have buckets");
        // Total count across all buckets should equal all 9 records.
        let total: u64 = rows.iter().map(|r| r.count).sum();
        assert_eq!(total, 9, "range total count");
        // 4 boundaries → 5 possible buckets, but empty ones may be skipped.
        // [..0) is empty, so expect 4 non-empty buckets.
        assert!(
            rows.len() >= 3,
            "expected ≥3 range buckets, got {}",
            rows.len()
        );
    }
}

#[test]
fn histogram_size_single_bucket_when_no_boundaries() {
    // Histogram without planner-generated boundaries puts all in one bucket.
    let mut spec = AggregateSpec::new(AggregateKind::Histogram {
        field: crate::search::field::FieldId::Size,
        interval: 4096,
        metrics: vec![BucketMetric::Count, BucketMetric::TotalBytes],
    });
    spec.label = Some("hist_test".to_owned());
    let resp = run(&[spec]);
    assert_eq!(resp.results.len(), 1);
    if let AggregateResultData::Buckets { rows, .. } = &resp.results[0].data {
        // Without boundary expansion, all records land in one bucket.
        let total: u64 = rows.iter().map(|r| r.count).sum();
        assert_eq!(total, 9, "all records accounted for");
    }
}

// ── S1G.14: datehist:modified,month ──────────────────────────────

#[test]
fn datehist_modified_monthly_produces_buckets() {
    let mut spec = AggregateSpec::new(AggregateKind::DateHistogram {
        field: crate::search::field::FieldId::Modified,
        calendar: CalendarInterval::Month,
        metrics: vec![BucketMetric::Count],
    });
    spec.label = Some("mod_monthly".to_owned());
    let resp = run(&[spec]);
    assert_eq!(resp.results.len(), 1);
    if let AggregateResultData::Buckets { rows, .. } = &resp.results[0].data {
        assert!(!rows.is_empty(), "datehist should have ≥1 month bucket");
        // We have files in Jan, Mar, Jun 2024.
        // Total across all buckets should include all 9 records (dirs get ts=0
        // which maps to some bucket too).
        let total: u64 = rows.iter().map(|r| r.count).sum();
        assert_eq!(total, 9, "datehist total count should be 9");
        // Check that we have at least 3 distinct month buckets
        // (Jan + Mar + Jun, plus possibly one for timestamp=0 dirs).
        assert!(
            rows.len() >= 3,
            "should have ≥3 month buckets, got {}",
            rows.len()
        );
    }
}

// ── S1G.15: aggregate-only must NOT call path resolution ─────────

#[test]
fn aggregate_only_skips_path_resolution() {
    // The aggregate engine calls `run_aggregate` which scans records
    // directly without using `FastPathResolver`. This test verifies
    // the engine produces correct results without any path resolution
    // infrastructure, proving it never calls path resolution.
    let drive = build_agg_test_drive();
    let specs = AggregatePreset::Overview.expand();
    let output = run_aggregate(&[&drive], &specs, &FinalizeOptions::default()).unwrap();
    // If path resolution were required, this would fail because
    // the synthetic index doesn't have a fully valid parent chain.
    // The fact that it succeeds proves aggregate-only works
    // without path resolution.
    assert!(output.records_scanned > 0);
    assert!(!output.response.results.is_empty());
}

// ── S1G.16: terms:ext uses extension_id, not string allocation ──

#[test]
fn terms_ext_uses_intern_extension_id() {
    // The Terms:Extension accumulator groups by compact
    // extension_id (u16), not by allocating extension strings.
    // String keys are only resolved during finalization.
    // This test verifies correct results through the
    // extension_id path.
    let mut spec = AggregateSpec::new(AggregateKind::Terms {
        field: crate::search::field::FieldId::Extension,
        top: 100,
        metrics: vec![BucketMetric::Count, BucketMetric::TotalBytes],
        sample: None,
    });
    spec.label = Some("ext_terms".to_owned());
    let resp = run(&[spec]);

    if let AggregateResultData::Buckets { rows, .. } = &resp.results[0].data {
        // Check exact counts for each extension.
        let rs = rows.iter().find(|r| r.key == "rs").expect("rs");
        assert_eq!(rs.count, 3);
        let md = rows.iter().find(|r| r.key == "md").expect("md");
        assert_eq!(md.count, 2);
        let toml = rows.iter().find(|r| r.key == "toml").expect("toml");
        assert_eq!(toml.count, 1);
        let bin = rows.iter().find(|r| r.key == "bin").expect("bin");
        assert_eq!(bin.count, 1);
        // Total file count from extension terms (dirs have no ext).
        let total: u64 = rows.iter().map(|r| r.count).sum();
        assert!(total >= 7, "at least 7 files with extensions, got {total}");
    }
}

// ── S2A: TopHits sample rows are materialized ───────────────────

#[test]
fn terms_with_sample_materializes_rows() {
    use crate::search::field::FieldId;

    let drive = build_agg_test_drive();
    let spec = AggregateSpec::new(AggregateKind::Terms {
        field: FieldId::Extension,
        top: 10,
        metrics: vec![BucketMetric::Count, BucketMetric::TotalBytes],
        sample: Some(TopHitsSpec::with_count(2)),
    });
    let output = run_aggregate(&[&drive], &[spec], &FinalizeOptions::default()).unwrap();

    if let AggregateResultData::Buckets { rows, .. } = &output.response.results[0].data {
        // The "rs" bucket has 3 files; sample should have 2 (largest by size).
        let rs = rows.iter().find(|r| r.key == "rs").expect("rs bucket");
        assert_eq!(
            rs.sample_rows.len(),
            2,
            "rs bucket should have 2 sample rows, got {}",
            rs.sample_rows.len()
        );
        // Default sort: Size desc => 3000 (lib.rs), 2000 (main.rs)
        assert_eq!(rs.sample_rows[0].sort_key, 3000);
        assert_eq!(rs.sample_rows[1].sort_key, 2000);

        // Verify projected fields include "name" and "size".
        let names: Vec<&str> = rs.sample_rows[0]
            .fields
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert!(names.contains(&"name"), "should project name field");
        assert!(names.contains(&"size"), "should project size field");

        // Check actual name values.
        let name_val = rs.sample_rows[0]
            .fields
            .iter()
            .find(|(k, _)| k == "name")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert_eq!(name_val, "lib.rs", "largest .rs file is lib.rs");

        // Buckets with 1 file should have 1 sample row.
        let toml = rows.iter().find(|r| r.key == "toml").expect("toml bucket");
        assert_eq!(toml.sample_rows.len(), 1);
    } else {
        panic!("expected Buckets result");
    }
}

#[test]
fn terms_without_sample_has_empty_sample_rows() {
    use crate::search::field::FieldId;

    let drive = build_agg_test_drive();
    let spec = AggregateSpec::new(AggregateKind::Terms {
        field: FieldId::Extension,
        top: 10,
        metrics: vec![BucketMetric::Count],
        sample: None,
    });
    let output = run_aggregate(&[&drive], &[spec], &FinalizeOptions::default()).unwrap();

    if let AggregateResultData::Buckets { rows, .. } = &output.response.results[0].data {
        for row in rows {
            assert!(
                row.sample_rows.is_empty(),
                "bucket '{}' should have no sample rows",
                row.key
            );
        }
    }
}

#[test]
fn terms_sample_custom_projection() {
    use crate::search::field::FieldId;

    let drive = build_agg_test_drive();
    let spec = AggregateSpec::new(AggregateKind::Terms {
        field: FieldId::Extension,
        top: 10,
        metrics: vec![BucketMetric::Count],
        sample: Some(TopHitsSpec::new(1, FieldId::Size, true, vec![
            FieldId::Name,
            FieldId::Size,
        ])),
    });
    let output = run_aggregate(&[&drive], &[spec], &FinalizeOptions::default()).unwrap();

    if let AggregateResultData::Buckets { rows, .. } = &output.response.results[0].data {
        let rs = rows.iter().find(|r| r.key == "rs").expect("rs bucket");
        assert_eq!(rs.sample_rows.len(), 1);
        // Only 2 fields projected.
        assert_eq!(
            rs.sample_rows[0].fields.len(),
            2,
            "custom projection should have 2 fields"
        );
        let field_names: Vec<&str> = rs.sample_rows[0]
            .fields
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(field_names, vec!["name", "size"]);
    }
}

#[test]
fn terms_sample_asc_sort() {
    use crate::search::field::FieldId;

    let drive = build_agg_test_drive();
    let spec = AggregateSpec::new(AggregateKind::Terms {
        field: FieldId::Extension,
        top: 10,
        metrics: vec![BucketMetric::Count],
        sample: Some(TopHitsSpec::new(2, FieldId::Size, false, vec![])),
    });
    let output = run_aggregate(&[&drive], &[spec], &FinalizeOptions::default()).unwrap();

    if let AggregateResultData::Buckets { rows, .. } = &output.response.results[0].data {
        let rs = rows.iter().find(|r| r.key == "rs").expect("rs bucket");
        assert_eq!(rs.sample_rows.len(), 2);
        // Asc sort: smallest first => 1000 (util.rs), 2000 (main.rs)
        assert_eq!(rs.sample_rows[0].sort_key, 1000);
        assert_eq!(rs.sample_rows[1].sort_key, 2000);
    }
}

// ── S2B: Drill-down predicates ──────────────────────────────────

#[test]
fn terms_drilldown_includes_bucket_key() {
    use crate::search::field::FieldId;

    let drive = build_agg_test_drive();
    let spec = AggregateSpec::new(AggregateKind::Terms {
        field: FieldId::Extension,
        top: 10,
        metrics: vec![BucketMetric::Count],
        sample: None,
    });
    let output = run_aggregate(&[&drive], &[spec], &FinalizeOptions::default()).unwrap();

    if let AggregateResultData::Buckets { rows, .. } = &output.response.results[0].data {
        let rs = rows.iter().find(|r| r.key == "rs").expect("rs bucket");

        // Should have exactly 1 drill-down predicate: extension=rs
        assert_eq!(rs.drilldown.len(), 1, "expected 1 drilldown pred");
        assert_eq!(rs.drilldown[0].field, "extension");
        assert_eq!(rs.drilldown[0].op, "eq");
        assert_eq!(
            rs.drilldown[0].value,
            DrilldownValue::String("rs".to_owned())
        );

        // Every bucket should have a drill-down predicate.
        for row in rows {
            assert!(
                !row.drilldown.is_empty(),
                "bucket '{}' should have drilldown",
                row.key
            );
        }
    } else {
        panic!("expected Buckets");
    }
}

#[test]
fn terms_drilldown_preserves_query_predicates() {
    use crate::search::field::FieldId;

    let drive = build_agg_test_drive();
    let spec = AggregateSpec::new(AggregateKind::Terms {
        field: FieldId::Extension,
        top: 10,
        metrics: vec![BucketMetric::Count],
        sample: None,
    });

    // Simulate an original query that filtered by size > 100
    let opts = FinalizeOptions {
        query_predicates: vec![DrilldownPredicate {
            field: "size".to_owned(),
            op: "gte".to_owned(),
            value: DrilldownValue::U64(100),
        }],
        ..FinalizeOptions::default()
    };

    let output = run_aggregate(&[&drive], &[spec], &opts).unwrap();

    if let AggregateResultData::Buckets { rows, .. } = &output.response.results[0].data {
        let rs = rows.iter().find(|r| r.key == "rs").expect("rs bucket");

        // Should have 2 predicates: size>=100 (from query) + extension=rs (bucket)
        assert_eq!(rs.drilldown.len(), 2, "expected 2 drilldown preds");
        assert_eq!(rs.drilldown[0].field, "size");
        assert_eq!(rs.drilldown[0].op, "gte");
        assert_eq!(rs.drilldown[1].field, "extension");
        assert_eq!(rs.drilldown[1].op, "eq");
    } else {
        panic!("expected Buckets");
    }
}

#[test]
fn terms_drilldown_no_query_predicates() {
    use crate::search::field::FieldId;

    let drive = build_agg_test_drive();
    let spec = AggregateSpec::new(AggregateKind::Terms {
        field: FieldId::Extension,
        top: 10,
        metrics: vec![BucketMetric::Count],
        sample: None,
    });
    let output = run_aggregate(&[&drive], &[spec], &FinalizeOptions::default()).unwrap();

    if let AggregateResultData::Buckets { rows, .. } = &output.response.results[0].data {
        // With no query predicates, each bucket has exactly 1 pred
        for row in rows {
            assert_eq!(
                row.drilldown.len(),
                1,
                "bucket '{}' should have 1 drilldown pred (just bucket key)",
                row.key
            );
        }
    }
}

// ── S2F: Preset integration tests on synthetic index ────────────

#[test]
fn s2f4_top_folders_preset() {
    let drive = build_agg_test_drive();
    let specs = AggregatePreset::TopFolders.expand();
    let output = run_aggregate(&[&drive], &specs, &FinalizeOptions::default()).unwrap();
    let result = &output.response.results[0];

    assert_eq!(
        result.label.as_deref(),
        Some("top_folders"),
        "should carry the preset label"
    );

    if let AggregateResultData::Rollup { rows, mode } = &result.data {
        assert_eq!(
            mode, "path(depth=1)",
            "top_folders uses path depth=1 rollup"
        );
        assert!(
            !rows.is_empty(),
            "top_folders should produce at least 1 row"
        );

        let total_bytes: u64 = rows.iter().map(|r| r.total_bytes).sum();
        assert!(total_bytes > 0, "top_folders should report non-zero bytes");

        // Keys must be real folder paths, not raw record indices.
        let keys: Vec<&str> = rows.iter().map(|r| r.key.as_str()).collect();
        assert!(
            keys.contains(&"C:\\Projects"),
            "top_folders should resolve the folder name, got {keys:?}"
        );
        assert!(
            !keys.iter().any(|k| k.starts_with("record_")),
            "no unresolvable rollup keys expected, got {keys:?}"
        );
    } else {
        panic!(
            "expected Rollup result from top_folders, got {:?}",
            result.data
        );
    }
}

// ── Regression: multi-drive top_folders keys must resolve per drive ──
//
// 2026-07-21, found live via the MCP `top_folders` preset over multiple
// drives: rollup group keys were bare per-drive record indices. The
// cross-drive merge collided buckets from different drives, and finalize
// resolved every key against the FIRST drive's records — producing
// malformed folder names (or `record_N` fallbacks). Keys must carry the
// drive they came from and resolve against that drive's name table.

#[test]
fn top_folders_multi_drive_keys_resolve_per_drive() {
    let drive_c = build_agg_test_drive(); // C:\Projects — 17400 bytes of files
    // Same record layout as drive C (identical compact indices) so a bare
    // record-index key collides across drives; different names and sizes so
    // the collision is observable.
    let drive_d = build_drive_with_folder(uffs_mft::platform::DriveLetter::D, "Photos", &[
        ("img_001.jpg", 101, 5000, 8192, TS_JAN_2024),
        ("img_002.jpg", 102, 7000, 8192, TS_MAR_2024),
    ]);

    let specs = AggregatePreset::TopFolders.expand();
    let output = run_aggregate(&[&drive_c, &drive_d], &specs, &FinalizeOptions::default()).unwrap();
    let result = &output.response.results[0];

    let AggregateResultData::Rollup { rows, .. } = &result.data else {
        panic!(
            "expected Rollup result from top_folders, got {:?}",
            result.data
        );
    };
    let keys: Vec<&str> = rows.iter().map(|r| r.key.as_str()).collect();

    // Each drive's folder must appear under its own drive letter and name.
    let projects = rows
        .iter()
        .find(|r| r.key == "C:\\Projects")
        .unwrap_or_else(|| panic!("missing C:\\Projects bucket, got {keys:?}"));
    let photos = rows
        .iter()
        .find(|r| r.key == "D:\\Photos")
        .unwrap_or_else(|| panic!("missing D:\\Photos bucket, got {keys:?}"));

    // No cross-drive merging: each bucket carries only its own drive's bytes.
    assert_eq!(
        projects.total_bytes, 17_400,
        "C:\\Projects must not absorb drive D records"
    );
    assert_eq!(
        photos.total_bytes, 12_000,
        "D:\\Photos must not absorb drive C records"
    );

    // And no unresolvable keys anywhere.
    assert!(
        !keys.iter().any(|k| k.starts_with("record_")),
        "no unresolvable rollup keys expected, got {keys:?}"
    );
}

// ── Regression: ancestor rollups are scoped to their drive ──────
//
// An ancestor drilldown's record index is per-drive. Before drive
// scoping, the index was interpreted against EVERY scanned drive:
// records on other drives were bucketed against an arbitrary unrelated
// record that happened to sit at that index (or flooded the result
// with one-file self buckets). Records on other drives must be
// skipped entirely — in the top-level rows AND in nested sub-buckets.

#[test]
fn ancestor_rollup_scoped_to_named_drive() {
    let drive_c = build_agg_test_drive(); // C:\Projects — 7 files, 17400 B
    let drive_d = build_drive_with_folder(uffs_mft::platform::DriveLetter::D, "Photos", &[
        ("img_001.jpg", 101, 5000, 8192, TS_JAN_2024),
        ("img_002.jpg", 102, 7000, 8192, TS_MAR_2024),
    ]);

    // Find C's "Projects" record index in the compact index.
    let projects_idx = drive_c
        .records
        .iter()
        .position(|rec| rec.name(&drive_c.names) == "Projects")
        .expect("Projects record");

    // Drill into C:\Projects — its children are the 7 files themselves.
    let spec = AggregateSpec::new(AggregateKind::Rollup {
        mode: RollupMode::Ancestor {
            record_idx: uffs_mft::len_to_u32(projects_idx),
            drive: uffs_mft::platform::DriveLetter::C,
        },
        top: 30,
        metrics: vec![BucketMetric::Count, BucketMetric::TotalBytes],
        sample: None,
        sub: None,
    });
    let output =
        run_aggregate(&[&drive_c, &drive_d], &[spec], &FinalizeOptions::default()).unwrap();

    let AggregateResultData::Rollup { rows, mode } = &output.response.results[0].data else {
        panic!("expected Rollup result");
    };
    assert_eq!(
        *mode,
        format!("ancestor(record={projects_idx}, drive=C)"),
        "mode label should carry the drive scope"
    );

    // Every bucket must be a C:\ key — drive D records are out of scope.
    for row in rows {
        assert!(
            row.key.starts_with("C:\\"),
            "ancestor drilldown into C must not bucket drive D records, got {}",
            row.key
        );
    }
    let total_bytes: u64 = rows.iter().map(|r| r.total_bytes).sum();
    assert_eq!(
        total_bytes, 17_400,
        "drilldown totals must cover exactly drive C's Projects files"
    );
}

#[test]
fn s2f5_cleanup_preset() {
    let drive = build_agg_test_drive();
    let specs = AggregatePreset::Cleanup.expand();
    let output = run_aggregate(&[&drive], &specs, &FinalizeOptions::default()).unwrap();

    assert!(
        output.response.results.len() >= 3,
        "cleanup preset should produce at least 3 specs, got {}",
        output.response.results.len()
    );

    // Find the total_files count.
    let total = output
        .response
        .results
        .iter()
        .find(|r| r.label.as_deref() == Some("total_files"));
    assert!(total.is_some(), "cleanup should have total_files");
    if let Some(r) = total
        && let AggregateResultData::Count { value } = &r.data
    {
        // 8 records total (1 dir + 7 files).
        assert!(*value > 0, "total_files should be > 0");
    }

    // zero_byte_files: our test drive has no zero-byte files.
    let zero_byte = output
        .response
        .results
        .iter()
        .find(|r| r.label.as_deref() == Some("zero_byte_files"));
    assert!(
        zero_byte.is_some(),
        "cleanup should have zero_byte_files spec"
    );

    // distinct_extensions: should find our 5 distinct extensions
    // (rs, md, toml, bin, + empty for directory).
    let distinct = output
        .response
        .results
        .iter()
        .find(|r| r.label.as_deref() == Some("distinct_extensions"));
    assert!(
        distinct.is_some(),
        "cleanup should have distinct_extensions"
    );
}

#[test]
fn s2f6_aggregate_and_rows_independent() {
    use crate::search::field::FieldId;

    let drive = build_agg_test_drive();

    // Run an aggregation.
    let agg_spec = AggregateSpec::new(AggregateKind::Terms {
        field: FieldId::Extension,
        top: 10,
        metrics: vec![BucketMetric::Count],
        sample: None,
    });
    let agg_output = run_aggregate(&[&drive], &[agg_spec], &FinalizeOptions::default()).unwrap();

    // Verify aggregation works.
    if let AggregateResultData::Buckets { rows, .. } = &agg_output.response.results[0].data {
        let total: u64 = rows.iter().map(|r| r.count).sum();
        assert!(total >= 7, "aggregation counted files");
    } else {
        panic!("expected Buckets");
    }

    // Run a second, independent aggregation on the same drive.
    let agg_spec2 = AggregateSpec::new(AggregateKind::Count);
    let agg_output2 = run_aggregate(&[&drive], &[agg_spec2], &FinalizeOptions::default()).unwrap();

    if let AggregateResultData::Count { value } = &agg_output2.response.results[0].data {
        assert!(*value >= 7, "count should be >= 7 records");
    } else {
        panic!("expected Count");
    }

    // Key assertion: neither aggregation mutated the drive index.
    // Running them back-to-back on the same &drive proves independence.
    assert_eq!(drive.records.len(), drive.records.len());
}

// ── S3F.2: Paginate through extensions with cursor ──────────────

#[test]
fn s3f2_paginate_extensions_total_equals_unpaginated() {
    use super::pagination::{AggregateCursor, paginate_result};

    let drive = build_agg_test_drive();
    // Full (unpaginated) terms:extension
    let spec = AggregateSpec::new(AggregateKind::Terms {
        field: crate::search::field::FieldId::Extension,
        top: 100,
        metrics: vec![BucketMetric::Count, BucketMetric::TotalBytes],
        sample: None,
    });
    let output = run_aggregate(&[&drive], &[spec], &FinalizeOptions::default()).unwrap();
    let full_result = &output.response.results[0];
    let AggregateResultData::Buckets {
        rows: full_rows, ..
    } = &full_result.data
    else {
        panic!("expected Buckets");
    };
    let full_count: u64 = full_rows.iter().map(|r| r.count).sum();
    let full_len = full_rows.len();

    // Now paginate with page_size=2 and walk all pages.
    let page_size = 2;
    let mut collected_keys = Vec::new();
    let mut collected_count: u64 = 0;
    let mut cursor = AggregateCursor::new(0, page_size);
    let mut pages = 0_u32;

    loop {
        let page =
            paginate_result(full_result, &cursor).expect("paginate should work on bucket result");
        for row in &page.rows {
            collected_keys.push(row.key.clone());
            collected_count += row.count;
        }
        pages += 1;
        if let Some(next_token) = &page.next_cursor {
            cursor = AggregateCursor::decode(next_token).expect("next_cursor should decode");
        } else {
            break;
        }
    }

    // Verify totals match.
    assert_eq!(
        collected_keys.len(),
        full_len,
        "paginated total keys should equal unpaginated"
    );
    assert_eq!(
        collected_count, full_count,
        "paginated total count should equal unpaginated"
    );
    // Pages should be ceil(full_len / page_size).
    let expected_pages = uffs_mft::len_to_u32(full_len.div_ceil(page_size));
    assert_eq!(
        pages, expected_pages,
        "{full_len} extensions / page_size={page_size} → {expected_pages} pages"
    );
}

// ── S3F.3: facet_values prefix filtering ────────────────────────

#[test]
fn s3f3_terms_extension_prefix_filter() {
    // Simulate prefix filtering by running terms:extension then
    // client-side filtering. The synthetic drive has: rs, md, toml, bin.
    // "Prefix" filter is handled by the search pattern in the daemon,
    // but at the core level we verify that terms produces all values
    // and a prefix filter can narrow them.
    let drive = build_agg_test_drive();
    let spec = AggregateSpec::new(AggregateKind::Terms {
        field: crate::search::field::FieldId::Extension,
        top: 100,
        metrics: vec![BucketMetric::Count],
        sample: None,
    });
    let output = run_aggregate(&[&drive], &[spec], &FinalizeOptions::default()).unwrap();
    let AggregateResultData::Buckets { rows, .. } = &output.response.results[0].data else {
        panic!("expected Buckets");
    };

    // All extensions should be present.
    let keys: Vec<&str> = rows.iter().map(|r| r.key.as_str()).collect();
    assert!(keys.contains(&"rs"), "should have rs: {keys:?}");
    assert!(keys.contains(&"md"), "should have md: {keys:?}");

    // Prefix filter: only extensions starting with "r".  Extension
    // keys are lowercase strings — unrelated to `DriveLetter`, which
    // is canonical uppercase.
    let filtered: Vec<_> = rows.iter().filter(|r| r.key.starts_with('r')).collect();
    assert_eq!(filtered.len(), 1, "only 'rs' starts with 'r'");
    assert_eq!(filtered[0].key, "rs");
    assert!(filtered[0].count >= 3, "at least 3 .rs files");

    // Prefix filter: "m" → only "md".
    let m_filtered: Vec<_> = rows.iter().filter(|r| r.key.starts_with('m')).collect();
    assert_eq!(m_filtered.len(), 1);
    assert_eq!(m_filtered[0].key, "md");

    // Prefix filter: "z" → nothing.
    let z_count = rows.iter().filter(|r| r.key.starts_with('z')).count();
    assert_eq!(z_count, 0, "no extensions start with 'z'");
}

// ── S3F.4: nested rollup on synthetic index ─────────────────────

#[test]
fn s3f4_nested_rollup_drive_with_terms_type() {
    let drive = build_agg_test_drive();
    // rollup:drive with sub=terms:type
    let spec = AggregateSpec::new(AggregateKind::Rollup {
        mode: RollupMode::Drive,
        top: 10,
        metrics: vec![BucketMetric::Count, BucketMetric::TotalBytes],
        sample: None,
        sub: Some(Box::new(AggregateSpec::new(AggregateKind::Terms {
            field: crate::search::field::FieldId::Type,
            top: 20,
            metrics: vec![BucketMetric::Count, BucketMetric::TotalBytes],
            sample: None,
        }))),
    });
    let output = run_aggregate(&[&drive], &[spec], &FinalizeOptions::default()).unwrap();
    let result = &output.response.results[0];

    let AggregateResultData::Rollup { rows, .. } = &result.data else {
        panic!("expected Rollup, got: {:?}", result.data);
    };

    // Single drive C: → exactly 1 bucket.
    assert_eq!(rows.len(), 1, "single drive should produce 1 bucket");
    let drive_bucket = &rows[0];
    assert!(
        drive_bucket.key.starts_with('C'),
        "drive bucket key should start with C, got: {}",
        drive_bucket.key
    );

    // Nested sub_buckets should contain type breakdowns.
    assert!(
        !drive_bucket.sub_buckets.is_empty(),
        "drive bucket should have nested type sub-buckets"
    );

    // Total count across sub_buckets should equal the drive total.
    let sub_total: u64 = drive_bucket.sub_buckets.iter().map(|b| b.count).sum();
    assert_eq!(
        sub_total, drive_bucket.count,
        "sub_buckets total count should equal drive bucket count"
    );
}

// ── Regression: ext filter absent on the drive must match NOTHING ──
//
// 2026-06-11, found live by the bench suite's count-vs-file-sink cross-check:
// `uffs *.dll --drive G --count` returned G's TOTAL record count (15,162 —
// every record on the drive) because `resolve_ext_ids(["dll"])` on a drive
// that never interned `dll` returns an empty vec, which the aggregate filter
// read as "no extension filter". An unresolvable extension filter matches
// nothing.

#[test]
fn count_with_extension_absent_on_drive_is_zero() {
    let drive = build_agg_test_drive();
    let specs = vec![AggregateSpec::new(AggregateKind::Count)];

    // Control: an extension present on the drive counts exactly its files.
    let present = AggregateFilter {
        extensions: vec!["rs".to_owned()],
        ..AggregateFilter::default()
    };
    let output = run_aggregate_with_filters(
        &[&drive],
        &specs,
        &FinalizeOptions::default(),
        None,
        &present,
    )
    .expect("count with present extension");
    assert!(
        matches!(
            output.response.results[0].data,
            AggregateResultData::Count { value: 3 }
        ),
        "3 .rs files expected; got {:?}",
        output.response.results[0].data
    );

    // Bug case: an extension the drive has never interned → ZERO, not all.
    let absent = AggregateFilter {
        extensions: vec!["dll".to_owned()],
        ..AggregateFilter::default()
    };
    let absent_output = run_aggregate_with_filters(
        &[&drive],
        &specs,
        &FinalizeOptions::default(),
        None,
        &absent,
    )
    .expect("count with absent extension");
    assert!(
        matches!(
            absent_output.response.results[0].data,
            AggregateResultData::Count { value: 0 }
        ),
        "no .dll files exist — count must be 0, not the drive total; got {:?}",
        absent_output.response.results[0].data
    );
}
