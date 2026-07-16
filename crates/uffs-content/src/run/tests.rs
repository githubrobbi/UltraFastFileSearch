// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Tests for the ephemeral run-state model (manifest + failure log +
//! atomically finalized summary).

use std::fs;

use uffs_content_protocol::error::ErrorCode;
use uffs_content_protocol::frame::{FailedOutcome, FailureStage, RetryClass};

use super::{
    FailureLogWriter, FailureOutcomeKind, FailureRecord, RunCounters, SummaryFinalizeError,
};

#[test]
fn finalize_rejects_incomplete_run() {
    let mut counters = RunCounters::new(3);
    counters.record_succeeded(100);
    counters.record_failed_terminal();
    // Only 2 of 3 candidates resolved.
    assert!(!counters.is_complete());

    let err = counters
        .finalize("run-1".to_owned(), 1_000, 2_000)
        .expect_err("must not finalize with unresolved candidates");
    assert_eq!(err, SummaryFinalizeError::Incomplete {
        candidate_count: 3,
        resolved_count: 2,
    });
}

#[test]
fn finalize_succeeds_once_every_candidate_is_resolved() {
    let mut counters = RunCounters::new(4);
    counters.record_succeeded(100);
    counters.record_succeeded(200);
    counters.record_failed_retryable();
    counters.record_deferred_manual();
    assert!(counters.is_complete());

    let summary = counters
        .finalize("run-2".to_owned(), 1_000, 5_000)
        .expect("all candidates resolved, finalize must succeed");
    assert_eq!(summary.candidate_count, 4);
    assert_eq!(summary.succeeded_count, 2);
    assert_eq!(summary.failed_retryable_count, 1);
    assert_eq!(summary.failed_terminal_count, 0);
    assert_eq!(summary.deferred_manual_count, 1);
    assert_eq!(summary.logical_bytes_succeeded, 300);
}

#[test]
fn atomic_finalize_writes_final_file_and_removes_partial() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let final_path = dir.path().join("run-3.summary.json");
    let partial_path = dir.path().join("run-3.summary.json.partial");

    let mut counters = RunCounters::new(1);
    counters.record_succeeded(42);
    let summary = counters
        .finalize("run-3".to_owned(), 10, 20)
        .expect("complete run finalizes");

    summary
        .finalize_to_disk(&final_path)
        .expect("finalize_to_disk must succeed");

    assert!(final_path.exists(), "final summary file must exist");
    assert!(
        !partial_path.exists(),
        "partial file must be gone after rename"
    );

    let loaded = super::RunSummary::load_if_finalized(&final_path)
        .expect("load must succeed")
        .expect("summary must be present");
    assert_eq!(loaded, summary);
}

#[test]
fn finalize_to_disk_refuses_to_overwrite_existing_summary() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let final_path = dir.path().join("run-4.summary.json");

    let mut counters = RunCounters::new(1);
    counters.record_succeeded(1);
    let summary = counters
        .finalize("run-4".to_owned(), 0, 1)
        .expect("complete run finalizes");
    summary
        .finalize_to_disk(&final_path)
        .expect("first finalize must succeed");

    let err = summary
        .finalize_to_disk(&final_path)
        .expect_err("second finalize to the same path must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
}

#[test]
fn unfinalized_run_reports_no_summary_rather_than_fabricating_one() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let final_path = dir.path().join("run-5.summary.json");

    let loaded =
        super::RunSummary::load_if_finalized(&final_path).expect("missing file is not an error");
    assert!(
        loaded.is_none(),
        "no summary file present means the run is incomplete, not a default/empty summary"
    );
}

#[test]
fn failure_log_appends_and_round_trips_jsonl() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let log_path = dir.path().join("run-6.failures.jsonl");

    let failed = FailureRecord::failed(
        7,
        FailedOutcome::Retryable,
        FailureStage::Read,
        ErrorCode::ReadIoTransient,
        Some(5),
        RetryClass::RetryNewSnapshot,
        1_024,
        "transient read error",
    );
    let deferred = FailureRecord::deferred(9, ErrorCode::CompressedManual, "NTFS-compressed");

    let mut writer = FailureLogWriter::open(&log_path).expect("open failure log");
    writer.append(&failed).expect("append failed record");
    writer.append(&deferred).expect("append deferred record");
    drop(writer);

    let contents = fs::read_to_string(&log_path).expect("read failure log");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 2, "one JSON object per appended record");

    let line_failed = lines.first().expect("first line present");
    let line_deferred = lines.get(1).expect("second line present");

    let decoded_failed: FailureRecord =
        serde_json::from_str(line_failed).expect("decode first line");
    assert_eq!(decoded_failed, failed);
    assert_eq!(decoded_failed.outcome, FailureOutcomeKind::FailedRetryable);

    let decoded_deferred: FailureRecord =
        serde_json::from_str(line_deferred).expect("decode second line");
    assert_eq!(decoded_deferred, deferred);
    assert_eq!(decoded_deferred.outcome, FailureOutcomeKind::DeferredManual);
    assert!(decoded_deferred.failure_stage.is_none());
    assert!(decoded_deferred.retry_class.is_none());
}

#[test]
fn failure_log_writer_appends_across_reopens() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let log_path = dir.path().join("run-7.failures.jsonl");

    let mut first_writer = FailureLogWriter::open(&log_path).expect("open failure log");
    first_writer
        .append(&FailureRecord::deferred(1, ErrorCode::SparseManual, "a"))
        .expect("append first");
    drop(first_writer);

    let mut second_writer = FailureLogWriter::open(&log_path).expect("reopen failure log");
    second_writer
        .append(&FailureRecord::deferred(2, ErrorCode::SparseManual, "b"))
        .expect("append second after reopen");
    drop(second_writer);

    let contents = fs::read_to_string(&log_path).expect("read failure log");
    assert_eq!(
        contents.lines().count(),
        2,
        "reopening must append, not truncate"
    );
}
