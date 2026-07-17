// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit tests for [`super::RequestHandler::try_pack_csv_blob`] —
//! the multi-column / parity / `--format custom` pre-format fast
//! path that packs a `Vec<SearchRow>` into a
//! `SearchPayload::InlineBlob` (≤ 512 KB) or
//! `SearchPayload::ShmemBlob` (above the threshold), optionally
//! appending the legacy drive footer.
//!
//! Sibling of [`super::handler_paths_blob_tests`] which covers the
//! path-only counterpart.  `bare_response` is duplicated across the
//! two files so each test module is self-contained — the helper is
//! ~15 LOC, and splitting it into a shared helper module would
//! gain little while adding an import dance.
//!
//! Re-attached to the `handler::csv_blob_tests` path via
//! `#[path = "handler_csv_blob_tests.rs"] mod csv_blob_tests;` in
//! `handler.rs`, so `super::` resolves against `handler`'s scope
//! (including private items like
//! [`super::RequestHandler::core_config_to_format`] the
//! shmem byte-parity test calls into).

use uffs_client::protocol::response::{SearchPayload, SearchResponse, SearchRow};
use uffs_client::protocol::{SearchParams, SearchResponseMode};

use super::RequestHandler;

/// Build a minimal `SearchResponse` carrying `rows` as
/// [`SearchPayload::InlineRows`] — the state the search core leaves
/// the response in before [`RequestHandler::try_pack_csv_blob`]
/// gets a chance to swap the payload to a blob variant.
fn bare_response(rows: Vec<SearchRow>) -> SearchResponse {
    let row_count = rows.len();
    SearchResponse {
        payload: SearchPayload::InlineRows(rows),
        total_count: u64::try_from(row_count).unwrap_or(u64::MAX),
        records_scanned: row_count,
        duration_ms: 0,
        truncated: false,
        profile: None,
        applied_sorts: Vec::new(),
        applied_projection: vec!["path".to_owned()],
        response_mode: Some(SearchResponseMode::Rows),
        projected_rows: None,
        aggregations: Vec::new(),
    }
}

/// Build a `SearchRow` with realistic field values so the CSV
/// writer exercises every column type (path, name, size, bool
/// flags, timestamps).  The row's size is tuned per test via
/// `size` so the produced blob can cross the 512 KB threshold on
/// demand.
fn sample_row(
    drive: uffs_mft::platform::DriveLetter,
    path: String,
    name: String,
    size: u64,
) -> SearchRow {
    SearchRow {
        drive,
        path,
        name,
        size,
        is_directory: false,
        // Constant FILETIME in 2026 (2026-01-01T00:00:00Z expressed
        // in Windows 100-ns ticks since 1601) keeps the formatted
        // timestamp column deterministic across hosts.
        modified: 133_775_712_000_000_000,
        created: 133_775_712_000_000_000,
        accessed: 133_775_712_000_000_000,
        flags: 0,
        allocated: size,
        descendants: 0,
        treesize: size,
        tree_allocated: size,
        malformed: false,
        malformed_path: false,
        name_hex: None,
        file_reference: 0,
    }
}

/// Build a directory `SearchRow` tuned for the parity / parity-
/// compat tests.  Sets `is_directory=true`, the `DIRECTORY`
/// attribute bit, and caller-supplied `descendants` / `treesize`
/// / `tree_allocated` so the dir-rewrite assertions can pin the
/// exact aggregated values that replace logical size / allocated
/// on dir rows.
fn sample_dir_row(
    drive: uffs_mft::platform::DriveLetter,
    path: String,
    name: String,
    descendants: u32,
    treesize: u64,
    tree_allocated: u64,
) -> SearchRow {
    let mut row = sample_row(drive, path, name, 0);
    row.is_directory = true;
    row.flags = 0x0010; // FILE_ATTRIBUTE_DIRECTORY
    row.descendants = descendants;
    row.treesize = treesize;
    row.tree_allocated = tree_allocated;
    row.allocated = 0;
    row
}

/// Happy path: a multi-column CSV request from the CLI (with its
/// default `output_format = Some("csv")`) must pre-format the rows
/// into a [`SearchPayload::InlineBlob`] and consume the original
/// `InlineRows`.
///
/// Non-CLI callers (`uffs-mcp` et al) leave `output_format = None`
/// and are covered by
/// [`try_pack_csv_blob_skips_when_output_format_none`] below.
#[test]
fn try_pack_csv_blob_happy_path_multi_column() {
    let rows = vec![
        sample_row(
            uffs_mft::platform::DriveLetter::C,
            "C:\\a\\f1.dll".to_owned(),
            "f1.dll".to_owned(),
            1024,
        ),
        sample_row(
            uffs_mft::platform::DriveLetter::C,
            "C:\\a\\f2.dll".to_owned(),
            "f2.dll".to_owned(),
            2048,
        ),
        sample_row(
            uffs_mft::platform::DriveLetter::D,
            "D:\\b\\f3.txt".to_owned(),
            "f3.txt".to_owned(),
            4096,
        ),
    ];
    let mut response = bare_response(rows);
    let params = SearchParams {
        // Standard multi-column request — the path-only
        // short-circuit in `try_pack_paths_blob` does not
        // trigger, so the CSV dispatcher gets the rows.
        projection: vec!["path".to_owned(), "name".to_owned(), "size".to_owned()],
        output_columns: Some("path,name,size".to_owned()),
        // CLI-shape opt-in: `SearchParams::from_cli_args` always
        // populates `output_format`, defaulting to `"csv"` when the
        // user omits `--format`.  Mirror that here so the test
        // exercises the fast path the CLI actually hits in
        // production.
        output_format: Some("csv".to_owned()),
        ..SearchParams::default()
    };

    RequestHandler::try_pack_csv_blob(&params, &mut response);

    let SearchPayload::InlineBlob(blob) = &response.payload else {
        panic!(
            "multi-column CSV request must be pre-formatted into \
             SearchPayload::InlineBlob; got {:?} — regression of \
             the csv_blob happy path",
            response.payload
        );
    };
    // The writer emits: 1 header line + 1 blank separator line
    // (parity with the CLI's hand-rolled parity writer) + 3 data
    // rows, each `\n`-terminated → 5 newlines total.  Exact
    // header content and separator placement are pinned by the
    // byte-parity tests in
    // `uffs-core::output::tests::format_parity_*`; here we just
    // verify the blob structure survived the handler.
    let newline_count = blob.bytes().filter(|byte| *byte == b'\n').count();
    assert_eq!(
        newline_count, 5,
        "CSV blob must contain 1 header + 1 blank separator + \
         3 data rows = 5 newlines; got {newline_count} in blob:\n{blob}"
    );
    assert!(
        blob.starts_with('"'),
        "default CSV config quotes every header cell; blob \
         must start with a quote character, got:\n{blob}"
    );
}

/// JSON response mode must bypass the CSV pre-format path — the
/// CLI's JSON dispatcher serialises rows with `serde_json`, not
/// the CSV writer, so a pre-formatted blob would be the wrong
/// shape entirely.
#[test]
fn try_pack_csv_blob_skips_json_response_mode() {
    let mut response = bare_response(vec![sample_row(
        uffs_mft::platform::DriveLetter::C,
        "C:\\a.dll".to_owned(),
        "a.dll".to_owned(),
        1024,
    )]);
    let params = SearchParams {
        projection: vec!["path".to_owned(), "size".to_owned()],
        response_mode: Some(SearchResponseMode::Json),
        ..SearchParams::default()
    };

    RequestHandler::try_pack_csv_blob(&params, &mut response);

    assert!(
        matches!(response.payload, SearchPayload::InlineRows(_)),
        "JSON response_mode must leave payload as InlineRows for \
         the client-side NDJSON writer; got {:?}",
        response.payload
    );
}

/// `--format=json` and `--format=table` route through CLI-side
/// structural formatters (NDJSON, fixed-width padding) that the
/// daemon's columnar writer cannot reproduce.  They must skip the
/// pre-format path.
///
/// `--format=custom` is now accepted (Phase 3 lift) and has its
/// own acceptance test — see
/// [`try_pack_csv_blob_custom_appends_footer_when_drives_set`].
#[test]
fn try_pack_csv_blob_skips_non_csv_format() {
    for fmt in ["json", "table", "CSV "] {
        // `"CSV "` (with trailing space) also fails — our gate
        // uses exact case-insensitive match, not a trim, since
        // the CLI arg parser already strips whitespace and a
        // stray-space value means the caller mangled the param
        // in-flight (e.g. a broken shell-quote round-trip).
        let mut response = bare_response(vec![sample_row(
            uffs_mft::platform::DriveLetter::C,
            "C:\\a.dll".to_owned(),
            "a.dll".to_owned(),
            1024,
        )]);
        let params = SearchParams {
            projection: vec!["path".to_owned(), "size".to_owned()],
            output_format: Some(fmt.to_owned()),
            ..SearchParams::default()
        };

        RequestHandler::try_pack_csv_blob(&params, &mut response);

        assert!(
            matches!(response.payload, SearchPayload::InlineRows(_)),
            "output_format={fmt:?} must skip the csv_blob path; \
             got {:?}",
            response.payload
        );
    }
}

/// Explicit `output_format = Some("csv")` (case-insensitive) must
/// be accepted — the CLI forwards the value from its `--format`
/// arg verbatim, including capitalisations users type.
#[test]
fn try_pack_csv_blob_accepts_explicit_csv_format() {
    for fmt in ["csv", "CSV", "Csv"] {
        let mut response = bare_response(vec![sample_row(
            uffs_mft::platform::DriveLetter::C,
            "C:\\a.dll".to_owned(),
            "a.dll".to_owned(),
            1024,
        )]);
        let params = SearchParams {
            projection: vec!["path".to_owned(), "size".to_owned()],
            output_format: Some(fmt.to_owned()),
            ..SearchParams::default()
        };

        RequestHandler::try_pack_csv_blob(&params, &mut response);

        assert!(
            matches!(response.payload, SearchPayload::InlineBlob(_)),
            "output_format={fmt:?} (case-insensitive csv) must \
             be accepted; got {:?}",
            response.payload
        );
    }
}

/// Aggregation responses carry bucket data the blob channel
/// cannot transport — even if the row list looks like a normal
/// CSV request, an active `aggregations` list means the client
/// expects structured access.  Gate rejects.
#[test]
fn try_pack_csv_blob_skips_aggregations() {
    let mut response = bare_response(vec![sample_row(
        uffs_mft::platform::DriveLetter::C,
        "C:\\a.dll".to_owned(),
        "a.dll".to_owned(),
        1024,
    )]);
    let params = SearchParams {
        projection: vec!["path".to_owned(), "size".to_owned()],
        aggregations: vec![uffs_client::protocol::AggregateSpecWire {
            kind: "count".to_owned(),
            ..Default::default()
        }],
        // Still exercise the CLI opt-in so this test pins the
        // aggregation-specific branch rather than incidentally
        // tripping the `output_format.is_none()` reject.
        output_format: Some("csv".to_owned()),
        ..SearchParams::default()
    };

    RequestHandler::try_pack_csv_blob(&params, &mut response);

    assert!(
        matches!(response.payload, SearchPayload::InlineRows(_)),
        "aggregation requests must leave rows intact for the \
         client-side aggregator path; got {:?}",
        response.payload
    );
}

/// `output_file` set means the daemon's `--out=file` path
/// already streamed the rows to disk; the payload at this point
/// is already `Empty`, and even if a bug left it as `InlineRows`
/// the pre-format path must not introduce a second copy in a
/// blob.
#[test]
fn try_pack_csv_blob_skips_when_output_file_set() {
    let mut response = bare_response(vec![sample_row(
        uffs_mft::platform::DriveLetter::C,
        "C:\\a.dll".to_owned(),
        "a.dll".to_owned(),
        1024,
    )]);
    let params = SearchParams {
        projection: vec!["path".to_owned(), "size".to_owned()],
        output_file: Some("/tmp/dummy.csv".to_owned()),
        // Opt into the CLI blob path so this test pins the
        // `output_file`-specific branch rather than incidentally
        // tripping the `output_format.is_none()` reject.
        output_format: Some("csv".to_owned()),
        ..SearchParams::default()
    };

    RequestHandler::try_pack_csv_blob(&params, &mut response);

    assert!(
        matches!(response.payload, SearchPayload::InlineRows(_)),
        "output_file requests must not pre-format — the file \
         sink is the authoritative output; got {:?}",
        response.payload
    );
}

/// `--columns parity` is accepted by the Phase 3 gate: the
/// daemon renders the legacy 25-column parity layout via
/// `uffs_format::write_rows(parity_compat=true)`.  This test
/// pins:
/// 1. The payload lands on `InlineBlob` (not `InlineRows`).
/// 2. The blob starts with the canonical 25-column parity header followed by
///    the `\n\n` blank-separator line.
/// 3. Directory rewrites fire — `build_output_config` auto-sets
///    `parity_compat=true` when `output_columns == "parity"` so the CLI
///    slow-path and daemon fast-path stay in sync.
#[test]
fn try_pack_csv_blob_accepts_columns_parity() {
    let mut response = bare_response(vec![sample_dir_row(
        uffs_mft::platform::DriveLetter::C,
        "C:\\Program Files\\app".to_owned(),
        "app".to_owned(),
        12,
        65_536,
        73_728,
    )]);
    let params = SearchParams {
        projection: vec!["path".to_owned()],
        output_columns: Some("parity".to_owned()),
        // CLI opt-in — mirrors `from_cli_args` default.
        output_format: Some("csv".to_owned()),
        ..SearchParams::default()
    };

    RequestHandler::try_pack_csv_blob(&params, &mut response);

    let SearchPayload::InlineBlob(blob) = &response.payload else {
        panic!(
            "output_columns=parity must be accepted by the Phase 3 \
             gate; got {:?}",
            response.payload
        );
    };
    // Canonical 25-column parity header + blank separator.  If
    // this drifts, CLI↔daemon byte parity is broken.
    assert!(
        blob.starts_with(
            "\"Path\",\"Name\",\"Path Only\",\"Size\",\"Size on Disk\",\
             \"Created\",\"Last Written\",\"Last Accessed\",\"Descendants\",\
             \"Read-only\",\"Archive\",\"System\",\"Hidden\",\"Offline\",\
             \"Not content indexed file\",\"No scrub file\",\"Integrity\",\
             \"Pinned\",\"Unpinned\",\"Directory Flag\",\"Compressed\",\
             \"Encrypted\",\"Sparse\",\"Reparse\",\"Attributes\"\n\n"
        ),
        "parity blob must open with the 25-column legacy header + \
         \\n\\n separator; got:\n{blob}"
    );
    // The directory row must have the trailing backslash + empty
    // Name (the parity-dir rewrite).  Pinning this means
    // `build_output_config`'s auto-parity_compat path stays live.
    assert!(
        blob.contains("\"C:\\Program Files\\app\\\",\"\","),
        "directory row must use parity-dir rewrite (trailing \\, \
         empty Name); got:\n{blob}"
    );
}

/// `--parity-compat` without an explicit `--columns parity` is
/// accepted by the Phase 3 gate and produces a blob with the
/// parity-dir rewrites applied — even on projections other than
/// `parity`.  Matches the CLI's behaviour where
/// `write_columnar(parity_compat)` rewrites Path/Name/Size/etc.
/// for directory rows regardless of column set.
#[test]
fn try_pack_csv_blob_accepts_parity_compat_flag() {
    let mut response = bare_response(vec![sample_dir_row(
        uffs_mft::platform::DriveLetter::D,
        "D:\\Users\\alice".to_owned(),
        "alice".to_owned(),
        3,
        4_096,
        8_192,
    )]);
    let params = SearchParams {
        projection: vec!["path".to_owned(), "size".to_owned()],
        output_columns: Some("path,size".to_owned()),
        output_parity_compat: Some(true),
        // CLI opt-in — mirrors `from_cli_args` default.
        output_format: Some("csv".to_owned()),
        ..SearchParams::default()
    };

    RequestHandler::try_pack_csv_blob(&params, &mut response);

    let SearchPayload::InlineBlob(blob) = &response.payload else {
        panic!(
            "output_parity_compat=Some(true) must be accepted; \
             got {:?}",
            response.payload
        );
    };
    // Directory → Path gets trailing \, Size becomes treesize
    // (4096) not logical size (0).  If either of those slips the
    // fast path and slow path would drift on dir rows.
    assert!(
        blob.contains("\"D:\\Users\\alice\\\",4096"),
        "parity_compat must rewrite dir Path (trailing \\) and \
         Size (→ treesize=4096); got:\n{blob}"
    );
}

/// `--parity-compat` combined with `output_header=false` must
/// still emit the header — the CLI's hand-rolled `write_parity`
/// ignores the header flag entirely and always writes the
/// 25-column header, so the daemon must match or the two paths
/// drift on `--parity-compat --noheader` queries.
#[test]
fn try_pack_csv_blob_parity_forces_header_when_disabled() {
    let mut response = bare_response(vec![sample_row(
        uffs_mft::platform::DriveLetter::C,
        "C:\\a.txt".to_owned(),
        "a.txt".to_owned(),
        100,
    )]);
    let params = SearchParams {
        projection: vec!["path".to_owned()],
        output_columns: Some("parity".to_owned()),
        output_header: Some(false),
        // CLI opt-in — mirrors `from_cli_args` default.
        output_format: Some("csv".to_owned()),
        ..SearchParams::default()
    };

    RequestHandler::try_pack_csv_blob(&params, &mut response);

    let SearchPayload::InlineBlob(blob) = &response.payload else {
        panic!(
            "parity should still be accepted; got {:?}",
            response.payload
        );
    };
    assert!(
        blob.starts_with("\"Path\","),
        "parity must emit header even when output_header=false; \
         got:\n{blob}"
    );
}

/// `--format=custom` with a non-empty `output_drive_targets` must
/// produce an `InlineBlob` whose tail contains the legacy
/// `Drives? … / MMMmmm …` footer.  This is the Phase 3 fast-path
/// equivalent of the CLI's
/// `test_legacy_footer_includes_fast_scan_message_for_full_scan_pattern`.
#[test]
fn try_pack_csv_blob_custom_appends_footer_when_drives_set() {
    let mut response = bare_response(vec![sample_row(
        uffs_mft::platform::DriveLetter::C,
        "C:\\one.txt".to_owned(),
        "one.txt".to_owned(),
        1,
    )]);
    let params = SearchParams {
        pattern: "*".to_owned(),
        projection: vec!["path".to_owned(), "name".to_owned()],
        output_columns: Some("path,name".to_owned()),
        output_format: Some("custom".to_owned()),
        output_drive_targets: vec![uffs_mft::platform::DriveLetter::C],
        ..SearchParams::default()
    };

    RequestHandler::try_pack_csv_blob(&params, &mut response);

    let SearchPayload::InlineBlob(blob) = &response.payload else {
        panic!(
            "custom format must be accepted by the Phase 3 gate; \
             got {:?}",
            response.payload
        );
    };
    // Footer uses CRLF line endings.
    assert!(
        blob.contains("\r\n\r\nDrives? \t1\tC:\r\n"),
        "custom-format blob must carry the legacy drive footer; \
         got:\n{blob}"
    );
    // Full-scan pattern + < 20 000 rows → fast-scan warning fires.
    assert!(
        blob.contains("MMMmmm that was FAST"),
        "full-scan pattern under the row threshold must include \
         the fast-scan warning; got:\n{blob}"
    );
}

/// `--format=custom` without explicit drives (e.g. the user did
/// not pass `--drive` / `--drives`) produces an `InlineBlob`
/// with the CSV body but **no** footer — matches
/// `uffs_format::write_legacy_drive_footer`'s empty-targets
/// short-circuit and the CLI's behaviour on drive-less custom
/// queries.
#[test]
fn try_pack_csv_blob_custom_omits_footer_when_no_drives() {
    let mut response = bare_response(vec![sample_row(
        uffs_mft::platform::DriveLetter::C,
        "C:\\one.txt".to_owned(),
        "one.txt".to_owned(),
        1,
    )]);
    let params = SearchParams {
        pattern: "*".to_owned(),
        projection: vec!["path".to_owned(), "name".to_owned()],
        output_columns: Some("path,name".to_owned()),
        output_format: Some("custom".to_owned()),
        // No `output_drive_targets` — default empty.
        ..SearchParams::default()
    };

    RequestHandler::try_pack_csv_blob(&params, &mut response);

    let SearchPayload::InlineBlob(blob) = &response.payload else {
        panic!("custom format must be accepted; got {:?}", response.payload);
    };
    assert!(
        !blob.contains("Drives?"),
        "empty output_drive_targets must skip the footer entirely; \
         got:\n{blob}"
    );
    assert!(
        !blob.contains("MMMmmm"),
        "footer-skipped path must not emit the fast-scan warning \
         either; got:\n{blob}"
    );
}

/// Empty row list must short-circuit without allocating an empty
/// blob — mirrors `try_pack_paths_blob_skips_empty_response`.
#[test]
fn try_pack_csv_blob_skips_empty_response() {
    let mut response = bare_response(Vec::new());
    let params = SearchParams {
        projection: vec!["path".to_owned(), "size".to_owned()],
        ..SearchParams::default()
    };

    RequestHandler::try_pack_csv_blob(&params, &mut response);

    let SearchPayload::InlineRows(rows) = &response.payload else {
        panic!(
            "empty response must stay as InlineRows(vec![]); got \
             {:?}",
            response.payload
        );
    };
    assert!(rows.is_empty());
}

/// Blobs above `PATHS_BLOB_SHMEM_THRESHOLD` (512 KB) must travel
/// via a raw-bytes shmem file rather than inline JSON — same
/// dispatch boundary as `try_pack_paths_blob`.  Drains and
/// deletes the shmem file to avoid littering `/tmp`, and
/// verifies the streamed bytes match a fresh in-memory format
/// of the same rows so the transport is proven byte-lossless.
#[test]
fn try_pack_csv_blob_offloads_large_blob_to_shmem() {
    // Column set is small (path + name + size) but per-row
    // length is padded via long path strings so the blob crosses
    // 512 KB with ~5 000 rows — keeps fixture build under 50 ms.
    let row_count: usize = 5_000;
    let rows: Vec<SearchRow> = (0..row_count)
        .map(|idx| {
            let path = format!(
                "C:\\very_long_parent_folder_{idx:08}\\deeper_subfolder_with_padding\\file_{idx:010}.extension",
            );
            let name = format!("file_{idx:010}.extension");
            sample_row(uffs_mft::platform::DriveLetter::C, path, name, 1024)
        })
        .collect();

    // Build the expected byte sequence by running `uffs_format`
    // on a clone of the same rows with the same config — any
    // divergence between this direct call and the daemon's
    // `try_pack_csv_blob` output means the handler's transport
    // is corrupting the payload, not the formatter.
    let params = SearchParams {
        projection: vec!["path".to_owned(), "name".to_owned(), "size".to_owned()],
        output_columns: Some("path,name,size".to_owned()),
        // CLI opt-in — mirrors `from_cli_args` default.
        output_format: Some("csv".to_owned()),
        ..SearchParams::default()
    };
    let cfg_core = crate::index::search::build_output_config(&params);
    let cfg_fmt = RequestHandler::core_config_to_format(&cfg_core);
    let mut expected_bytes: Vec<u8> = Vec::new();
    uffs_format::write_rows(&cfg_fmt, &rows, &mut expected_bytes)
        .expect("reference format call must succeed");

    let mut response = bare_response(rows);
    RequestHandler::try_pack_csv_blob(&params, &mut response);

    let SearchPayload::ShmemBlob(shmem_path_str) = &response.payload else {
        panic!(
            "large multi-column CSV blob must be offloaded to \
             SearchPayload::ShmemBlob; got {:?}.\n\n\
             If the variant you see is SearchPayload::InlineBlob(...), \
             the daemon's `package_csv_blob` correctly fell back from \
             shmem to inline because `uffs_client::shmem::\
             write_paths_blob` failed — check test stderr for a \
             `tracing::warn!` line starting with `csv_blob shmem \
             write failed; falling back to inline JSON`.  The single \
             most common cause is `ENOSPC` / `ERROR_DISK_FULL` on \
             the host's data-local dir (e.g. \
             `$CARGO_TARGET_DIR/llvm-cov-target` has grown to 100+ GB \
             or `%LOCALAPPDATA%\\uffs\\shmem` is out of space).  \
             Run `just clean-cov` to prune the llvm-cov tree + \
             orphan shmem files and re-run `just test` — see \
             CONTRIBUTING.md §\"Target-dir hygiene\" for the full \
             recovery procedure.  If the assertion still fails after \
             `just clean-cov`, it is a genuine regression of the \
             csv_blob shmem branch.",
            response.payload
        );
    };

    let shmem_path = std::path::Path::new(shmem_path_str);
    assert!(
        shmem_path.exists(),
        "daemon must create the shmem file before returning so \
         the client can open it — file missing at {shmem_path_str}"
    );

    let mut sink: Vec<u8> = Vec::with_capacity(expected_bytes.len());
    uffs_client::shmem::stream_paths_blob_into(shmem_path, &mut sink)
        .expect("stream_paths_blob_into must succeed");

    assert_eq!(
        sink.as_slice(),
        expected_bytes.as_slice(),
        "streamed CSV blob must match the in-memory reference \
         bytes — any mismatch means the shmem transport is \
         corrupting the payload, not the formatter"
    );
    assert!(
        !shmem_path.exists(),
        "stream_paths_blob_into must delete the file after \
         copying"
    );
}

/// Regression test for the MCP "unexpected non-rows payload"
/// failure: when `output_format` is `None` (the shape non-CLI
/// callers like `uffs-mcp` produce — they never set a rendered
/// format since they consume structured
/// [`uffs_client::protocol::response::SearchRow`]s directly), the
/// fast path MUST leave the payload as `InlineRows`.
///
/// Before the Phase 3.1 opt-in tightening, an absent
/// `output_format` was silently treated as "default csv", which
/// caused the daemon to pre-format an MCP search response into
/// an `InlineBlob` and triggered the
/// `into_inline_rows().ok_or(...)` guard in
/// `uffs_mcp::tools::search` to fail with "unexpected non-rows
/// payload from daemon search — MCP always requests structured
/// rows".  See the healing changelog in
/// `LOG/2026_04_20_20_23_CHANGELOG_HEALING.md` for the full
/// incident timeline.
#[test]
fn try_pack_csv_blob_skips_when_output_format_none() {
    let mut response = bare_response(vec![
        sample_row(
            uffs_mft::platform::DriveLetter::C,
            "C:\\a\\f1.dll".to_owned(),
            "f1.dll".to_owned(),
            1024,
        ),
        sample_row(
            uffs_mft::platform::DriveLetter::C,
            "C:\\a\\f2.dll".to_owned(),
            "f2.dll".to_owned(),
            2048,
        ),
    ]);
    let params = SearchParams {
        // Multi-column projection typical of MCP search
        // (`uffs_mcp::tools::search` defaults to
        // name,ext,type,size,modified,path).
        projection: vec![
            "name".to_owned(),
            "size".to_owned(),
            "modified".to_owned(),
            "path".to_owned(),
        ],
        // `response_mode = Some(Rows)` is what MCP ends up with
        // after `populate_canonical_fields` fills the default.
        response_mode: Some(SearchResponseMode::Rows),
        // ❗ `output_format = None` is the MCP shape — never set
        // by `uffs-mcp` because MCP doesn't render to stdout.
        output_format: None,
        ..SearchParams::default()
    };

    RequestHandler::try_pack_csv_blob(&params, &mut response);

    assert!(
        matches!(response.payload, SearchPayload::InlineRows(_)),
        "MCP-shape request (output_format=None) must leave payload \
         as InlineRows so `uffs_mcp::tools::search` can consume \
         the structured rows; got {:?} — regression of the \
         opt-in fast-path gate (see \
         `RequestHandler::caller_opted_into_blob_payload`)",
        response.payload
    );
}
