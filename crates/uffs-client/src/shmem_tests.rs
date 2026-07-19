// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit + integration tests for [`super`] — round-trip coverage of
//! the binary shmem transport (rows mode + paths-blob mode) and the
//! header / record layout invariants.
//!
//! Lifted out of `shmem.rs` to keep that file under the 800-line
//! policy ceiling.  Re-attached to `shmem::tests` via
//! `#[path = "shmem_tests.rs"] mod tests;` in `shmem.rs`, so every
//! `super::*` glob below continues to resolve against the `shmem`
//! module's scope (including private helpers like `shmem_dir` /
//! `unique_shmem_path` the tests exercise).

extern crate alloc;

use std::sync::{Mutex, MutexGuard};

use super::*;
use crate::protocol::response::{SearchPayload, SearchRow};

/// Test helper: unwrap the `InlineRows` payload from a round-tripped
/// shmem response.  [`read_search_results`] always materialises
/// rows into [`SearchPayload::InlineRows`] regardless of how the
/// daemon originally encoded them, so every shmem round-trip test
/// expects this variant.  Panics with a detailed message if the
/// payload carries anything else — a hard regression signal for
/// the serde layer.
fn expect_inline_rows(resp: SearchResponse) -> Vec<SearchRow> {
    match resp.payload {
        SearchPayload::InlineRows(rows) => rows,
        other @ (SearchPayload::Empty
        | SearchPayload::ShmemRows { .. }
        | SearchPayload::InlineBlob(_)
        | SearchPayload::ShmemBlob(_)) => panic!(
            "read_search_results must return InlineRows payload; \
                 got {other:?} — shmem deserialiser regressed"
        ),
    }
}

/// Shared-directory serialisation lock for tests that touch the
/// global shmem directory.
///
/// `cleanup_stale_shmem_files` (invoked by `gc_cleans_*`) sweeps
/// every `.bin` under `shmem_dir()`, which would otherwise race
/// with `concurrent_writes_*`'s in-flight files when the cargo
/// test harness schedules both on parallel threads.  Production
/// cannot hit this: GC only runs at daemon startup, guarded by
/// the PID file, so a write and a sweep never overlap in real
/// usage.  The lock here exists purely to model that invariant
/// inside `cargo test`.
///
/// Poisoning is intentionally ignored — a panicking test should
/// not block the rest of the suite from running.
static SHMEM_DIR_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the shmem-directory lock for the duration of a test.
fn lock_shmem_dir() -> MutexGuard<'static, ()> {
    SHMEM_DIR_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Helper: build a minimal `SearchRow` for testing.
fn sample_row(name: &str) -> SearchRow {
    SearchRow {
        drive: uffs_mft::platform::DriveLetter::C,
        path: format!("C:\\test\\{name}"),
        name: name.to_owned(),
        size: 1024,
        is_directory: false,
        modified: 1_700_000_000_000_000,
        created: 1_700_000_000_000_000,
        accessed: 1_700_000_000_000_000,
        flags: 32,
        allocated: 4096,
        descendants: 0,
        treesize: 1024,
        tree_allocated: 0,
        malformed: false,
        malformed_path: false,
        name_hex: None,
        // Nonzero on purpose: 0 is never a valid NTFS file reference (it's
        // the reserved `$MFT` record), so a round-trip test that used 0
        // here would not have caught the v3-era bug where the shmem
        // reader hardcoded `file_reference: 0` regardless of what was
        // written (see `VERSION`'s v4 doc note in `shmem.rs`).
        file_reference: 0x0002_0000_0000_2AF8,
    }
}

#[test]
fn shmem_round_trip_deletes_file() {
    // Write a shmem file and verify it exists.
    let input_rows = vec![sample_row("a.txt"), sample_row("b.txt")];
    let path = write_search_results(&input_rows, 42, 100, false).expect("write should succeed");

    // Read immediately — avoid race with parallel GC test.
    let resp = read_search_results(&path).expect("read should succeed");
    assert_eq!(resp.duration_ms, 42);
    assert_eq!(resp.records_scanned, 100);
    let round_tripped = expect_inline_rows(resp);
    assert_eq!(round_tripped.len(), 2);
    let first = round_tripped.first().expect("expected at least 1 row");
    let second = round_tripped.get(1).expect("expected at least 2 rows");
    assert_eq!(first.name, "a.txt");
    assert_eq!(second.name, "b.txt");
    assert_eq!(
        first.file_reference, 0x0002_0000_0000_2AF8,
        "file_reference must round-trip through shmem, not come back as 0"
    );

    // The file must be gone now.
    assert!(
        !path.exists(),
        "shmem file must be deleted after read: {}",
        path.display()
    );
}

#[test]
fn shmem_empty_round_trip_deletes_file() {
    // Edge case: zero rows.  Read immediately after write to avoid
    // races with the parallel GC test that sweeps all .bin files.
    let path = write_search_results(&[], 0, 0, false).expect("write should succeed");
    let resp = read_search_results(&path).expect("read should succeed");
    assert!(expect_inline_rows(resp).is_empty());
    assert!(
        !path.exists(),
        "empty shmem file must be deleted after read"
    );
}

#[test]
fn shmem_used_for_large_result_sets() {
    // D5.1.6: Verify that a result set exceeding SHMEM_THRESHOLD
    // can be written to shmem and read back correctly.
    let rows: Vec<SearchRow> = (0..=SHMEM_THRESHOLD)
        .map(|idx| sample_row(&format!("file_{idx}.txt")))
        .collect();
    assert!(
        rows.len() > SHMEM_THRESHOLD,
        "test set must exceed threshold"
    );

    let path =
        write_search_results(&rows, 99, rows.len() as u64, false).expect("write should work");

    // Read immediately — avoid race with parallel GC test.
    let resp = read_search_results(&path).expect("read should work");
    assert_eq!(resp.duration_ms, 99);
    assert_eq!(resp.records_scanned, SHMEM_THRESHOLD + 1);
    let round_tripped = expect_inline_rows(resp);
    assert_eq!(round_tripped.len(), SHMEM_THRESHOLD + 1);
    let first = round_tripped.first().expect("expected at least 1 row");
    assert_eq!(first.name, "file_0.txt");
    let last = round_tripped
        .get(SHMEM_THRESHOLD)
        .expect("expected last row");
    assert_eq!(last.name, format!("file_{SHMEM_THRESHOLD}.txt"));
    assert!(!path.exists(), "shmem file must be deleted after read");
}

#[test]
fn gc_cleans_orphaned_bins_and_preserves_non_bins() {
    // D5.3.6: Combined GC test — runs as a single test to avoid
    // races with other shmem tests (GC sweeps ALL .bin files).
    // Serialised with `concurrent_writes_*` via `SHMEM_DIR_LOCK`
    // so the sweep can never overlap with in-flight writes.
    let _guard = lock_shmem_dir();
    let dir = shmem_dir().expect("shmem_dir should work");

    // 1. Simulate CLI crash: write shmem but never read it.
    let rows = vec![sample_row("orphan.txt")];
    let orphan = write_search_results(&rows, 1, 1, false).expect("write should work");

    // 2. Create extra stale .bin files (simulating older crashes).
    let stale1 = dir.join("gc_stale_1.bin");
    let stale2 = dir.join("gc_stale_2.bin");
    std::fs::write(&stale1, b"stale").expect("write stale1");
    std::fs::write(&stale2, b"stale").expect("write stale2");

    // 3. Create a non-.bin file that must survive.
    let keep = dir.join("gc_keep_me.txt");
    std::fs::write(&keep, b"preserve").expect("write non-bin");

    // GC sweep — should remove all .bin, preserve .txt.
    cleanup_stale_shmem_files();

    assert!(!orphan.exists(), "orphan must be removed by GC");
    assert!(!stale1.exists(), "stale .bin must be removed by GC");
    assert!(!stale2.exists(), "stale .bin must be removed by GC");
    assert!(keep.exists(), "non-.bin must survive GC");

    // Clean up our test file.
    drop(std::fs::remove_file(&keep));
}

#[test]
fn concurrent_writes_get_unique_paths() {
    // Simulate concurrent shmem usage: 8 threads each write a shmem
    // file and immediately read it back (mimicking 8 parallel CLI
    // processes).  Verifies path uniqueness, data isolation, and
    // cleanup.  Serialised with `gc_cleans_*` via `SHMEM_DIR_LOCK`
    // so a concurrent GC sweep cannot wipe the files before the
    // reader threads open them.
    use alloc::sync::Arc;
    use std::sync::Barrier;
    use std::thread;

    const THREADS: usize = 8;

    let _guard = lock_shmem_dir();
    let barrier = Arc::new(Barrier::new(THREADS));
    // Spawn all threads first, then join in a separate loop. The barrier
    // requires all THREADS to reach `wait()` before any can proceed, so
    // joining inside the spawn iterator would deadlock (lazy evaluation:
    // spawn → join → spawn …, only 1 thread ever alive).
    let mut handles = Vec::with_capacity(THREADS);
    for idx in 0..THREADS {
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let row = sample_row(&format!("concurrent_{idx}.txt"));
            // Synchronise so all threads call write at roughly the same time.
            bar.wait();
            let path = write_search_results(&[row], idx as u64, 1, false)
                .expect("concurrent write should succeed");
            // Read+delete immediately (same as real CLI does).
            let resp = read_search_results(&path).expect("read should succeed");
            let round_tripped = expect_inline_rows(resp);
            assert_eq!(round_tripped.len(), 1);
            let first = round_tripped.first().expect("expected 1 row");
            assert_eq!(first.name, format!("concurrent_{idx}.txt"));
            assert!(!path.exists(), "shmem file must be deleted after read");
            path
        }));
    }
    let mut paths = Vec::with_capacity(THREADS);
    for handle in handles {
        paths.push(handle.join().unwrap());
    }

    // All paths must be unique (atomic counter guarantees this).
    let mut sorted = paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        THREADS,
        "expected {THREADS} unique shmem paths, got {}",
        sorted.len()
    );
}

/// Raw-bytes `paths_blob` round-trip via shmem: daemon writes,
/// client streams into an in-memory buffer, file is deleted.
///
/// Pins that:
/// 1. `write_paths_blob` produces a file whose contents are the blob bytes
///    verbatim (no header, no framing).
/// 2. `stream_paths_blob_into` copies every byte to the writer without
///    transformation or truncation.
/// 3. The file is removed after streaming — no orphan left for the startup GC.
#[test]
fn paths_blob_shmem_round_trip_deletes_file() {
    let blob = "C:\\Windows\\System32\\a.dll\n\
                    C:\\Windows\\System32\\b.dll\n\
                    D:\\Data\\ünïcödé path\\c.dll\n";
    let path = write_paths_blob(blob).expect("write should succeed");
    assert!(path.exists(), "shmem file must exist after write");

    let mut sink: Vec<u8> = Vec::new();
    stream_paths_blob_into(&path, &mut sink).expect("stream should succeed");

    assert_eq!(
        sink.as_slice(),
        blob.as_bytes(),
        "streamed bytes must match the original blob verbatim \
             (no escaping, no UTF-8 re-normalisation)"
    );
    assert!(
        !path.exists(),
        "shmem file must be removed after stream: {}",
        path.display()
    );
}

/// 4.5 MB simulated `C: ext:dll` payload — the scale at which the
/// JSON channel becomes the dominant cost.  Pins that the shmem
/// transport handles multi-megabyte blobs without truncation or
/// copy-on-write surprises on Windows (where `MapViewOfFile` has
/// different semantics than `mmap` on Unix).
#[test]
fn paths_blob_shmem_round_trip_large_payload() {
    use core::fmt::Write as _;
    let row_count: usize = 150_000;
    let mut blob = String::with_capacity(row_count * 32);
    for idx in 0..row_count {
        // `writeln!` into the String avoids the intermediate
        // `format!` allocation flagged by clippy::format_push_string.
        writeln!(blob, "C:\\dir\\file_{idx}.dll").expect("write to String cannot fail");
    }
    assert!(
        blob.len() > PATHS_BLOB_SHMEM_THRESHOLD,
        "test payload ({} B) must exceed PATHS_BLOB_SHMEM_THRESHOLD \
             ({PATHS_BLOB_SHMEM_THRESHOLD} B) to exercise the dispatch",
        blob.len()
    );

    let path = write_paths_blob(&blob).expect("write should succeed");
    let mut sink: Vec<u8> = Vec::with_capacity(blob.len());
    stream_paths_blob_into(&path, &mut sink).expect("stream should succeed");

    assert_eq!(sink.len(), blob.len(), "byte count must match exactly");
    assert_eq!(
        sink.as_slice(),
        blob.as_bytes(),
        "every byte must round-trip"
    );
    assert!(!path.exists(), "large shmem file must be cleaned up");
}

/// Zero-byte blob: `MapViewOfFile` and `mmap` both reject
/// zero-length mappings on most platforms, so the writer skips
/// the mmap step and the streamer short-circuits before the
/// mmap call.  This test pins that the file is still created,
/// still deleted, and the writer receives nothing.
#[test]
fn paths_blob_shmem_round_trip_empty_payload() {
    let path = write_paths_blob("").expect("write should succeed for empty blob");
    assert!(path.exists(), "file must be created even for empty blob");
    assert_eq!(
        std::fs::metadata(&path).expect("metadata").len(),
        0,
        "empty blob file must be zero-length"
    );

    let mut sink: Vec<u8> = Vec::new();
    stream_paths_blob_into(&path, &mut sink).expect("stream of empty file should succeed");
    assert!(sink.is_empty(), "nothing should be written");
    assert!(!path.exists(), "empty shmem file must be deleted");
}

/// The threshold constant is the public contract for the
/// daemon's dispatch decision.  Locked at 512 KB because 256 KB
/// is the measured JSON-encode break-even point and 1 MB would
/// leave ~40 ms on the table for mid-sized responses (~30 K
/// rows).  Bumping this requires re-running the `C: ext:dll`
/// benchmark.
#[test]
fn paths_blob_shmem_threshold_is_512_kb() {
    assert_eq!(PATHS_BLOB_SHMEM_THRESHOLD, 512 * 1024);
}
