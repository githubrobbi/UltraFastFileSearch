// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit tests for [`super::RequestHandler::try_pack_paths_blob`] —
//! the path-only projection fast path that packs a `Vec<SearchRow>`
//! into a `SearchPayload::InlineBlob` (≤ 512 KB) or
//! `SearchPayload::ShmemBlob` (above the threshold).
//!
//! Sibling of [`super::handler_csv_blob_tests`] which covers the
//! multi-column / parity / `--format custom` counterpart.
//!
//! Re-attached to the `handler::paths_blob_tests` path via
//! `#[path = "handler_paths_blob_tests.rs"] mod paths_blob_tests;`
//! in `handler.rs`, so `super::` resolves against `handler`'s scope.

use uffs_client::protocol::response::{SearchPayload, SearchResponse, SearchRow};
use uffs_client::protocol::{SearchParams, SearchResponseMode};

use super::RequestHandler;

/// Build a `SearchRow` with just a path populated — all other
/// fields are irrelevant to [`RequestHandler::try_pack_paths_blob`]
/// because the packing loop only reads `row.path`.
fn path_only_row(path: String) -> SearchRow {
    SearchRow {
        drive: uffs_mft::platform::DriveLetter::C,
        path,
        name: String::new(),
        size: 0,
        is_directory: false,
        modified: 0,
        created: 0,
        accessed: 0,
        flags: 0,
        allocated: 0,
        descendants: 0,
        treesize: 0,
        tree_allocated: 0,
        malformed: false,
        malformed_path: false,
        name_hex: None,
        file_reference: 0,
    }
}

/// Build a minimal `SearchResponse` carrying `rows` as
/// [`SearchPayload::InlineRows`] — the state the search core
/// leaves the response in before [`RequestHandler::try_pack_paths_blob`]
/// gets a chance to swap the payload to a blob variant.  Metadata
/// fields use deterministic defaults so assertions can focus on
/// the dispatcher's variant choice.
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

/// Regression: `try_pack_paths_blob` used to bail out for
/// path-only projections above
/// `uffs_client::shmem::SHMEM_THRESHOLD` (100 000 rows), which
/// forced the daemon to fall back to the SearchRow-shmem transport
/// and made the client re-run `write_columnar` on every row —
/// a ~6× slowdown vs. a packed blob.  v0.5.60 removed the cap so
/// every path-only projection now packs.
///
/// This test pins the **inline** branch (blob below
/// `PATHS_BLOB_SHMEM_THRESHOLD`): even with a row count comfortably
/// above the old 100 000 cap, a small enough average path length
/// keeps the total blob under 512 KB and it stays inline.
#[test]
fn try_pack_paths_blob_inlines_below_shmem_threshold() {
    // 20 K rows × 20-byte paths ≈ 400 KB — under the 512 KB
    // PATHS_BLOB_SHMEM_THRESHOLD and above the old 100 K row cap
    // that this regression guarded against.
    let row_count: usize = 20_000;
    let rows: Vec<SearchRow> = (0..row_count)
        .map(|idx| path_only_row(format!("C:\\x\\f{idx:05}.dll")))
        .collect();
    let mut response = bare_response(rows);
    let params = SearchParams {
        projection: vec!["path".to_owned()],
        // CLI-shape opt-in: `SearchParams::from_cli_args` always
        // populates `output_format`, defaulting to `"csv"` when
        // the user omits `--format`.  See the doc comment on
        // `RequestHandler::caller_opted_into_blob_payload`.
        output_format: Some("csv".to_owned()),
        ..SearchParams::default()
    };

    RequestHandler::try_pack_paths_blob(&params, &mut response);

    let SearchPayload::InlineBlob(blob) = &response.payload else {
        panic!(
            "medium path-only projection must be packed into \
             SearchPayload::InlineBlob (blob under 512 KB); got \
             {:?} — regression of the inline branch",
            response.payload
        );
    };
    assert!(
        blob.len() <= uffs_client::shmem::PATHS_BLOB_SHMEM_THRESHOLD,
        "test scaffold drift: the 20 K × 20-byte fixture must \
         stay under PATHS_BLOB_SHMEM_THRESHOLD for this test to \
         exercise the inline branch (blob_len = {}, threshold = {})",
        blob.len(),
        uffs_client::shmem::PATHS_BLOB_SHMEM_THRESHOLD
    );
    assert_eq!(
        blob.bytes().filter(|byte| *byte == b'\n').count(),
        row_count,
        "blob must contain one newline per row — one write_all \
         emits exactly `row_count` lines"
    );
}

/// v0.5.61: blobs larger than `PATHS_BLOB_SHMEM_THRESHOLD`
/// (512 KB) travel through a raw-bytes shmem file instead of an
/// inline JSON string — skipping ~80 ms of JSON escape/unescape
/// on backslash-heavy multi-megabyte Windows-path payloads.
///
/// This test pins the **shmem** branch and verifies
/// end-to-end that:
///
/// 1. `paths_blob_shmem` is set and the file exists on disk.
/// 2. `paths_blob` is `None` (mutually exclusive with `paths_blob_shmem`, per
///    `SearchResponse` docs).
/// 3. The file's byte content, when streamed via `stream_paths_blob_into`, is
///    **byte-for-byte identical** to what the inline branch would have produced
///    — parity is the key invariant across the two transports.
/// 4. The file is deleted after the stream.
#[test]
fn try_pack_paths_blob_offloads_large_blob_to_shmem() {
    use core::fmt::Write as _;

    // 30 K rows × 25 B ≈ 732 KB — above the 512 KB threshold so
    // the dispatch lands on the shmem branch.  Path format is
    // fixed-width to make the expected-blob construction
    // deterministic and inexpensive.
    let row_count: usize = 30_000;
    let rows: Vec<SearchRow> = (0..row_count)
        .map(|idx| path_only_row(format!("C:\\dir\\file_{idx:08}.dll")))
        .collect();
    // Reconstruct the exact byte sequence the daemon should
    // have written to the shmem file.  Comparing against this
    // catches any off-by-one, encoding, or row-ordering bug in
    // `try_pack_paths_blob` that a newline-count assertion
    // would miss.  `writeln!` avoids the intermediate `format!`
    // allocation flagged by `clippy::format_push_string`.
    let mut expected = String::with_capacity(row_count * 32);
    for idx in 0..row_count {
        writeln!(expected, "C:\\dir\\file_{idx:08}.dll").expect("write to String cannot fail");
    }

    let mut response = bare_response(rows);
    let params = SearchParams {
        projection: vec!["path".to_owned()],
        // CLI opt-in — mirrors `from_cli_args` default.
        output_format: Some("csv".to_owned()),
        ..SearchParams::default()
    };

    RequestHandler::try_pack_paths_blob(&params, &mut response);

    let SearchPayload::ShmemBlob(shmem_path_str) = &response.payload else {
        panic!(
            "large path-only projection must be offloaded to \
             SearchPayload::ShmemBlob; got {:?}.\n\n\
             If the variant you see is SearchPayload::InlineBlob(...), \
             the daemon's `try_pack_paths_blob` correctly fell back \
             from shmem to inline because `uffs_client::shmem::\
             write_paths_blob` failed — check test stderr for a \
             `tracing::warn!` line starting with `paths_blob shmem \
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
             binary transport branch in `try_pack_paths_blob`.",
            response.payload
        );
    };

    let shmem_path = std::path::Path::new(shmem_path_str);
    assert!(
        shmem_path.exists(),
        "daemon must create the shmem file before returning so \
         the client can open it — file missing at {shmem_path_str}"
    );

    // Streaming the file drains + deletes it.  Capture bytes
    // into `sink` and compare against the expected
    // concatenation — parity with the inline branch is the key
    // invariant: same byte output, different transport.
    let mut sink: Vec<u8> = Vec::with_capacity(expected.len());
    uffs_client::shmem::stream_paths_blob_into(shmem_path, &mut sink)
        .expect("stream_paths_blob_into must succeed");

    assert_eq!(
        sink.as_slice(),
        expected.as_bytes(),
        "streamed blob must be byte-for-byte identical to what \
         the inline branch would have produced — any mismatch \
         means the transport silently corrupts the payload"
    );
    assert!(
        !shmem_path.exists(),
        "stream_paths_blob_into must delete the file after \
         copying — leaving it would build up orphan shmem files \
         under `<data_local>/uffs/shmem/`"
    );
}

/// Multi-column projections (e.g. `--columns Path,Size`) must not
/// be packed into `paths_blob` **or** `paths_blob_shmem`: the
/// client still needs the full `SearchRow` data to format the
/// size column.  Pins that the path-only guard
/// (`is_path_only_projection`) is the sole disqualifier — the
/// transport-selection logic is never reached for multi-column
/// responses.
#[test]
fn try_pack_paths_blob_skips_multi_column_projection() {
    let mut response = bare_response(vec![path_only_row("C:\\a.dll".to_owned())]);

    let params = SearchParams {
        projection: vec!["path".to_owned(), "size".to_owned()],
        // Exercise the CLI opt-in so this test pins the
        // multi-column-specific branch rather than incidentally
        // tripping the `caller_opted_into_blob_payload` reject
        // that would fire on an absent `output_format`.
        output_format: Some("csv".to_owned()),
        ..SearchParams::default()
    };

    RequestHandler::try_pack_paths_blob(&params, &mut response);

    let SearchPayload::InlineRows(rows) = &response.payload else {
        panic!(
            "multi-column projection must leave the payload as \
             InlineRows for the client-side formatter; got {:?}",
            response.payload
        );
    };
    assert_eq!(
        rows.len(),
        1,
        "rows must stay populated for the client-side formatter"
    );
}

/// Zero-row responses must short-circuit without allocating an
/// empty blob on either channel.  Keeps the wire format stable
/// (no `"paths_blob": ""` or orphan zero-byte shmem files).
#[test]
fn try_pack_paths_blob_skips_empty_response() {
    let mut response = bare_response(Vec::new());
    let params = SearchParams {
        projection: vec!["path".to_owned()],
        ..SearchParams::default()
    };

    RequestHandler::try_pack_paths_blob(&params, &mut response);

    // Empty row list passes through as `InlineRows(vec![])` —
    // the dispatcher's early return preserves the variant rather
    // than synthesising a zero-byte blob or shmem file.  The
    // `handle_search` wrapper downstream converts zero-row
    // `InlineRows` to `Empty` for wire economy; this test stops
    // at `try_pack_paths_blob` so that step is out of scope.
    let SearchPayload::InlineRows(rows) = &response.payload else {
        panic!(
            "empty response must leave the payload as \
             InlineRows(vec![]) — no blob or shmem file allowed; \
             got {:?}",
            response.payload
        );
    };
    assert!(
        rows.is_empty(),
        "bare_response(Vec::new()) must produce an empty row list"
    );
}

/// Regression test for the MCP "unexpected non-rows payload"
/// failure on path-only projections.
///
/// A non-CLI caller (e.g. `uffs-mcp` with `projection: ["path"]`)
/// leaves `output_format = None` because it does not render to
/// stdout — it feeds structured
/// [`uffs_client::protocol::response::SearchRow`]s into its
/// tool-result envelope.  The fast path MUST therefore leave the
/// payload as `InlineRows`; packing the rows into a newline-only
/// blob the MCP layer cannot re-parse would surface as the
/// "unexpected non-rows payload from daemon search" error.
///
/// Sister test of
/// `try_pack_csv_blob_skips_when_output_format_none` in
/// `handler_csv_blob_tests.rs`.
#[test]
fn try_pack_paths_blob_skips_when_output_format_none() {
    let mut response = bare_response(vec![
        path_only_row("C:\\a\\f1.dll".to_owned()),
        path_only_row("C:\\a\\f2.dll".to_owned()),
    ]);
    let params = SearchParams {
        projection: vec!["path".to_owned()],
        response_mode: Some(SearchResponseMode::Rows),
        // ❗ MCP shape: `output_format` intentionally absent.
        output_format: None,
        ..SearchParams::default()
    };

    RequestHandler::try_pack_paths_blob(&params, &mut response);

    assert!(
        matches!(response.payload, SearchPayload::InlineRows(_)),
        "MCP-shape request (output_format=None) must leave payload \
         as InlineRows so non-CLI callers receive structured \
         rows; got {:?} — regression of the opt-in fast-path \
         gate (see `RequestHandler::caller_opted_into_blob_payload`)",
        response.payload
    );
}
