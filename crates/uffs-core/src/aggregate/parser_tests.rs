// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Tests for the `--agg` power-syntax parser.
//!
//! Lifted out of `parser.rs` to keep that file under the 800-line
//! policy ceiling.  Attached via `#[path]` in `parser.rs` so the
//! `use super::*;` continues to resolve against the production
//! module exactly as it did when the tests lived inline.

use super::*;

#[test]
fn parse_count() {
    let spec = parse_agg_spec("count").unwrap();
    assert!(matches!(spec.kind, AggregateKind::Count));
}

#[test]
fn parse_stats_size() {
    let spec = parse_agg_spec("stats:size").unwrap();
    if let AggregateKind::Stats { field, metrics } = &spec.kind {
        assert_eq!(*field, FieldId::Size);
        assert_eq!(metrics.len(), 4); // default: sum/min/max/avg
    } else {
        panic!("expected Stats");
    }
}

#[test]
fn parse_terms_extension_with_top() {
    let spec = parse_agg_spec("terms:extension,top=100").unwrap();
    if let AggregateKind::Terms { field, top, .. } = &spec.kind {
        assert_eq!(*field, FieldId::Extension);
        assert_eq!(*top, 100);
    } else {
        panic!("expected Terms");
    }
}

#[test]
fn parse_facet_alias() {
    let spec = parse_agg_spec("facet:extension").unwrap();
    assert!(matches!(spec.kind, AggregateKind::Terms { .. }));
}

#[test]
fn parse_date_histogram() {
    let spec = parse_agg_spec("datehist:modified,calendar=month").unwrap();
    if let AggregateKind::DateHistogram {
        field, calendar, ..
    } = &spec.kind
    {
        assert_eq!(*field, FieldId::Modified);
        assert_eq!(*calendar, CalendarInterval::Month);
    } else {
        panic!("expected DateHistogram");
    }
}

#[test]
fn parse_range_with_bins() {
    let spec = parse_agg_spec("range:size,bins=1024+1048576+1073741824").unwrap();
    if let AggregateKind::Range { boundaries, .. } = &spec.kind {
        assert_eq!(boundaries.len(), 3);
    } else {
        panic!("expected Range");
    }
}

#[test]
fn parse_rollup_path() {
    let spec = parse_agg_spec("rollup:path,depth=2,top=20").unwrap();
    if let AggregateKind::Rollup { mode, top, .. } = &spec.kind {
        assert_eq!(*mode, RollupMode::Path { depth: 2 });
        assert_eq!(*top, 20);
    } else {
        panic!("expected Rollup");
    }
}

#[test]
fn parse_duplicates() {
    let spec = parse_agg_spec("duplicates:size+name,verify=none,top=50").unwrap();
    if let AggregateKind::Duplicates { keys, top, .. } = &spec.kind {
        assert_eq!(keys.len(), 2);
        assert_eq!(*top, 50);
    } else {
        panic!("expected Duplicates");
    }
}

#[test]
fn parse_missing() {
    let spec = parse_agg_spec("missing:extension").unwrap();
    assert!(matches!(spec.kind, AggregateKind::Missing { .. }));
}

#[test]
fn parse_distinct() {
    let spec = parse_agg_spec("distinct:extension").unwrap();
    assert!(matches!(spec.kind, AggregateKind::Distinct { .. }));
}

#[test]
fn parse_preset() {
    let spec = parse_agg_spec("preset:overview").unwrap();
    assert!(spec.label.as_deref().unwrap().starts_with("__preset__"));
}

#[test]
fn parse_and_expand_preset() {
    let specs = parse_and_expand_agg_specs(&["preset:overview"]).unwrap();
    assert!(specs.len() >= 5); // overview has 5+ specs
}

#[test]
fn parse_unknown_kind() {
    let result = parse_agg_spec("foobar:thing");
    result.unwrap_err();
}

#[test]
fn parse_histogram() {
    let spec = parse_agg_spec("hist:size,interval=1024").unwrap();
    if let AggregateKind::Histogram {
        field, interval, ..
    } = &spec.kind
    {
        assert_eq!(*field, FieldId::Size);
        assert_eq!(*interval, 1024);
    } else {
        panic!("expected Histogram");
    }
}

// ── Stage 2 gap-fill tests ────────────────────────────────────

#[test]
fn parse_terms_with_sample() {
    let spec = parse_agg_spec("terms:extension,top=10,sample=3").unwrap();
    if let AggregateKind::Terms {
        field, top, sample, ..
    } = &spec.kind
    {
        assert_eq!(*field, FieldId::Extension);
        assert_eq!(*top, 10);
        let sample_spec = sample.as_ref().expect("sample should be Some");
        assert_eq!(sample_spec.count, 3);
    } else {
        panic!("expected Terms");
    }
}

#[test]
fn parse_terms_without_sample() {
    let spec = parse_agg_spec("terms:extension,top=5").unwrap();
    if let AggregateKind::Terms { sample, .. } = &spec.kind {
        assert!(sample.is_none(), "no sample= → None");
    } else {
        panic!("expected Terms");
    }
}

#[test]
fn parse_rollup_drive() {
    let spec = parse_agg_spec("rollup:drive,top=10").unwrap();
    if let AggregateKind::Rollup { mode, top, .. } = &spec.kind {
        assert_eq!(*mode, RollupMode::Drive);
        assert_eq!(*top, 10);
    } else {
        panic!("expected Rollup");
    }
}

#[test]
fn parse_rollup_with_sample() {
    let spec = parse_agg_spec("rollup:path,depth=2,sample=2").unwrap();
    if let AggregateKind::Rollup { mode, sample, .. } = &spec.kind {
        assert_eq!(*mode, RollupMode::Path { depth: 2 });
        let sample_spec = sample.as_ref().expect("sample should be Some");
        assert_eq!(sample_spec.count, 2);
    } else {
        panic!("expected Rollup");
    }
}

#[test]
fn parse_duplicates_with_sample() {
    let spec = parse_agg_spec("duplicates:size+name,sample=5,top=50").unwrap();
    if let AggregateKind::Duplicates {
        keys, top, sample, ..
    } = &spec.kind
    {
        assert_eq!(keys.len(), 2);
        assert_eq!(*top, 50);
        let sample_spec = sample.as_ref().expect("sample should be Some");
        assert_eq!(sample_spec.count, 5);
    } else {
        panic!("expected Duplicates");
    }
}

#[test]
fn parse_rollup_folder_alias() {
    let spec = parse_agg_spec("rollup:folder,depth=3").unwrap();
    if let AggregateKind::Rollup { mode, .. } = &spec.kind {
        assert_eq!(*mode, RollupMode::Path { depth: 3 });
    } else {
        panic!("expected Rollup");
    }
}

#[test]
fn parse_rollup_dir_alias() {
    let spec = parse_agg_spec("rollup:dir").unwrap();
    if let AggregateKind::Rollup { mode, .. } = &spec.kind {
        assert_eq!(*mode, RollupMode::Path { depth: 1 });
    } else {
        panic!("expected Rollup");
    }
}

#[test]
fn parse_rollup_ancestor_mode() {
    let spec = parse_agg_spec("rollup:ancestor,record=42,drive=C,top=10").unwrap();
    if let AggregateKind::Rollup { mode, top, .. } = &spec.kind {
        assert_eq!(*mode, RollupMode::Ancestor {
            record_idx: 42,
            drive: uffs_mft::platform::DriveLetter::C,
        });
        assert_eq!(*top, 10);
    } else {
        panic!("expected Rollup");
    }
}

#[test]
fn parse_rollup_ancestor_frs_alias() {
    let spec = parse_agg_spec("rollup:ancestor,frs=100,drive=D").unwrap();
    if let AggregateKind::Rollup { mode, .. } = &spec.kind {
        assert_eq!(*mode, RollupMode::Ancestor {
            record_idx: 100,
            drive: uffs_mft::platform::DriveLetter::D,
        });
    } else {
        panic!("expected Rollup");
    }
}

#[test]
fn parse_rollup_ancestor_missing_record_errors() {
    let err = parse_agg_spec("rollup:ancestor,drive=C,top=10");
    assert!(err.is_err(), "ancestor without record= should fail");
}

#[test]
fn parse_rollup_ancestor_missing_drive_errors() {
    let err = parse_agg_spec("rollup:ancestor,record=42,top=10").expect_err("must error");
    assert_eq!(
        err,
        ParseAggSpecError::AncestorRequiresDrive,
        "ancestor without drive= should fail — the record index is per-drive"
    );
}

#[test]
fn parse_rollup_ancestor_invalid_drive_errors() {
    let err = parse_agg_spec("rollup:ancestor,record=42,drive=nope").expect_err("must error");
    assert_eq!(err, ParseAggSpecError::InvalidDriveLetter {
        val: "nope".to_owned(),
    });
}

#[test]
fn parse_rollup_drilldown_alias() {
    let spec = parse_agg_spec("rollup:drilldown,record=5,drive=C").unwrap();
    if let AggregateKind::Rollup { mode, .. } = &spec.kind {
        assert_eq!(*mode, RollupMode::Ancestor {
            record_idx: 5,
            drive: uffs_mft::platform::DriveLetter::C,
        });
    } else {
        panic!("expected Rollup");
    }
}

#[test]
fn parse_rollup_with_nested_sub() {
    let spec = parse_agg_spec("rollup:drive,sub=terms:extension").unwrap();
    if let AggregateKind::Rollup { mode, sub, .. } = &spec.kind {
        assert_eq!(*mode, RollupMode::Drive);
        let sub_spec = sub.as_ref().expect("sub should be present");
        assert!(
            matches!(&sub_spec.kind, AggregateKind::Terms { .. }),
            "sub should be a terms aggregation"
        );
    } else {
        panic!("expected Rollup");
    }
}

#[test]
fn parse_rollup_no_sub_by_default() {
    let spec = parse_agg_spec("rollup:drive,top=5").unwrap();
    if let AggregateKind::Rollup { sub, .. } = &spec.kind {
        assert!(sub.is_none(), "sub should be None when not specified");
    } else {
        panic!("expected Rollup");
    }
}

#[test]
fn parse_nested_rollup_path_with_terms_type() {
    let spec = parse_agg_spec("rollup:path,depth=1,sub=terms:type,top=20").unwrap();
    if let AggregateKind::Rollup { mode, sub, top, .. } = &spec.kind {
        assert_eq!(*mode, RollupMode::Path { depth: 1 });
        assert_eq!(*top, 20);
        let sub_spec = sub.as_ref().expect("sub should be present");
        assert!(matches!(&sub_spec.kind, AggregateKind::Terms { .. }));
    } else {
        panic!("expected Rollup");
    }
}
#[test]
fn parse_terms_sample_zero_is_none() {
    let spec = parse_agg_spec("terms:extension,sample=0").unwrap();
    if let AggregateKind::Terms { sample, .. } = &spec.kind {
        assert!(sample.is_none(), "sample=0 should produce None");
    } else {
        panic!("expected Terms");
    }
}

// ───────────────────────── Phase 5d typed-error tests ─────────────────────
//
// Each of these locks the Display string of one `ParseAggSpecError`
// variant at the byte-identical text the pre-Phase-5d `Result<_, String>`
// returns produced, so daemon `tracing::warn!` lines and CLI stderr
// stay unchanged through the migration.  Variants that chain an
// underlying `ParseIntError` additionally walk `Error::source` to
// assert the typed chain is intact — net-new coverage over the
// flattened `String` return.

#[test]
fn unknown_kind_display_locked() {
    use core::error::Error as _;
    let err = parse_agg_spec("bogus:thing").expect_err("unknown kind must error");
    assert_eq!(err, ParseAggSpecError::UnknownKind {
        kind: "bogus".to_owned(),
    });
    assert_eq!(err.to_string(), "Unknown aggregate kind: `bogus`");
    assert!(err.source().is_none());
}

#[test]
fn unknown_field_display_locked() {
    let err = parse_agg_spec("stats:not_a_field").expect_err("unknown field must error");
    assert_eq!(err, ParseAggSpecError::UnknownField {
        name: "not_a_field".to_owned(),
    });
    assert_eq!(err.to_string(), "Unknown field: `not_a_field`");
}

#[test]
fn invalid_int_option_top_chains_source() {
    use core::error::Error as _;
    let err = parse_agg_spec("terms:extension,top=abc").expect_err("non-numeric top must error");
    let ParseAggSpecError::InvalidIntOption {
        option,
        value,
        source,
    } = &err
    else {
        panic!("expected InvalidIntOption, got {err:?}");
    };
    assert_eq!(*option, "top");
    assert_eq!(value, "abc");
    // Display: byte-identical with the pre-Phase-5d
    // `format!("Invalid top: `{val}`: {err}")` payload.
    assert_eq!(err.to_string(), format!("Invalid top: `abc`: {source}"));
    // Source chain walks to the underlying ParseIntError — the typed
    // improvement over the previous flattened String.
    let chained = err
        .source()
        .expect("InvalidIntOption exposes ParseIntError");
    assert_eq!(chained.to_string(), source.to_string());
}

#[test]
fn invalid_int_option_interval_locked() {
    let err = parse_agg_spec("hist:size,interval=xyz").expect_err("must error");
    assert!(
        matches!(&err, ParseAggSpecError::InvalidIntOption { option, value, .. }
        if *option == "interval" && value == "xyz")
    );
    assert!(err.to_string().starts_with("Invalid interval: `xyz`: "));
}

#[test]
fn invalid_int_option_range_boundary_locked() {
    let err = parse_agg_spec("range:size,bins=abc").expect_err("must error");
    assert!(
        matches!(&err, ParseAggSpecError::InvalidIntOption { option, value, .. }
        if *option == "range boundary" && value == "abc")
    );
    assert!(
        err.to_string()
            .starts_with("Invalid range boundary: `abc`: ")
    );
}

#[test]
fn invalid_int_option_depth_locked() {
    let err = parse_agg_spec("rollup:path,depth=xx").expect_err("must error");
    assert!(
        matches!(&err, ParseAggSpecError::InvalidIntOption { option, .. }
        if *option == "depth")
    );
}

#[test]
fn invalid_int_option_record_index_locked() {
    let err = parse_agg_spec("rollup:ancestor,record=qq").expect_err("must error");
    assert!(
        matches!(&err, ParseAggSpecError::InvalidIntOption { option, value, .. }
        if *option == "record index" && value == "qq")
    );
}

#[test]
fn invalid_int_option_sample_locked() {
    let err = parse_agg_spec("terms:extension,sample=qq").expect_err("must error");
    assert!(
        matches!(&err, ParseAggSpecError::InvalidIntOption { option, .. }
        if *option == "sample")
    );
}

#[test]
fn invalid_int_option_max_groups_locked() {
    let err = parse_agg_spec("duplicates:size+name,max_groups=qq").expect_err("must error");
    assert!(
        matches!(&err, ParseAggSpecError::InvalidIntOption { option, .. }
        if *option == "max_groups")
    );
}

#[test]
fn invalid_calendar_display_locked() {
    let err = parse_agg_spec("datehist:modified,calendar=fortnight")
        .expect_err("unknown calendar must error");
    assert_eq!(err, ParseAggSpecError::InvalidCalendar {
        val: "fortnight".to_owned(),
    });
    assert_eq!(err.to_string(), "Invalid calendar interval: `fortnight`");
}

#[test]
fn ancestor_requires_record_display_locked() {
    let err = parse_agg_spec("rollup:ancestor,top=10").expect_err("must error");
    assert_eq!(err, ParseAggSpecError::AncestorRequiresRecord);
    assert_eq!(
        err.to_string(),
        "rollup:ancestor requires record=<idx> option"
    );
}

#[test]
fn unknown_rollup_mode_display_locked() {
    let err = parse_agg_spec("rollup:bogus").expect_err("must error");
    assert_eq!(err, ParseAggSpecError::UnknownRollupMode {
        mode: "bogus".to_owned(),
    });
    assert_eq!(
        err.to_string(),
        "Unknown rollup mode: `bogus`. Use 'path', 'drive', or 'ancestor'.",
    );
}

#[test]
fn unknown_verify_mode_display_locked() {
    let err = parse_agg_spec("duplicates:size+name,verify=bogus").expect_err("must error");
    assert_eq!(err, ParseAggSpecError::UnknownVerifyMode {
        val: "bogus".to_owned(),
    });
    assert_eq!(err.to_string(), "Unknown verify mode: `bogus`");
}

#[test]
fn unknown_preset_display_locked() {
    let err = parse_agg_spec("preset:nonsense").expect_err("must error");
    let ParseAggSpecError::UnknownPreset { name, available } = &err else {
        panic!("expected UnknownPreset, got {err:?}");
    };
    assert_eq!(name, "nonsense");
    assert!(
        !available.is_empty(),
        "Available preset list must be non-empty",
    );
    // Display: byte-identical with the pre-Phase-5d format.
    assert_eq!(
        err.to_string(),
        format!("Unknown preset: `nonsense`. Available: {available}")
    );
}

#[test]
fn unknown_scalar_metric_display_locked() {
    let err = parse_agg_spec("stats:size,metrics=bogus").expect_err("must error");
    assert_eq!(err, ParseAggSpecError::UnknownScalarMetric {
        name: "bogus".to_owned(),
    });
    assert_eq!(err.to_string(), "Unknown scalar metric: `bogus`");
}

#[test]
fn unknown_bucket_metric_display_locked() {
    let err = parse_agg_spec("terms:extension,metrics=bogus").expect_err("must error");
    assert_eq!(err, ParseAggSpecError::UnknownBucketMetric {
        name: "bogus".to_owned(),
    });
    assert_eq!(err.to_string(), "Unknown bucket metric: `bogus`");
}
