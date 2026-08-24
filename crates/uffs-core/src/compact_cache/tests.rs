// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit tests for [`super`] (`compact_cache`).
//!
//! Test strategy:
//!
//! * **Round-trips** — exercise both the heap-backed
//!   [`super::deserialize_compact`] and the runtime-mmap-backed
//!   [`super::deserialize_compact_into_runtime`] over the same serialized bytes
//!   and assert byte-equal observable state.
//! * **Backwards compat** — patch a v6 cache to v5 to confirm the trigram
//!   rebuild fallback still kicks in.
//! * **Header invariants** — current [`super::COMPACT_VERSION`] is stamped into
//!   byte 8/9 of every serialized payload.
//! * **Error paths** — v1 caches and truncated bytes are rejected on both code
//!   paths.
//!
//! Extracted from `compact_cache.rs` into a sibling submodule so the
//! lib file stays close to the 800 LOC soft limit instead of leaning
//! on the file-size exception (which was originally granted at "only
//! 26 over limit"; growing tests would invalidate that rationale).

use super::*;

/// Build a minimal `DriveCompactIndex` with 3 records for testing.
///
/// **Phase 8.** Populates `frs_to_compact` with a representative
/// 8-entry mapping (FRS 5 → root, FRS 10 → "foo", FRS 11 → "bar",
/// FRS 12 → "baz"; other slots `u32::MAX`) so v10 round-trip tests
/// exercise the section.  Iterator-collect form sidesteps
/// `clippy::indexing_slicing`.
fn make_test_index() -> DriveCompactIndex {
    let names = b"foobarbaz".to_vec(); // "foo" [0..3], "bar" [3..6], "baz" [6..9]
    let records = vec![
        CompactRecord {
            name_offset: 0,
            flags: 0x0010, // directory
            parent_idx: u32::MAX,
            name_len: 3,
            name_first_byte: b'f',
            ..CompactRecord::default()
        },
        CompactRecord {
            name_offset: 3,
            parent_idx: 0,
            name_len: 3,
            name_first_byte: b'b',
            ..CompactRecord::default()
        },
        CompactRecord {
            name_offset: 6,
            parent_idx: 0,
            name_len: 3,
            name_first_byte: b'b',
            ..CompactRecord::default()
        },
    ];
    let fold = uffs_text::case_fold::CaseFold::default_table();
    let trigram = TrigramIndex::build(&records, &names, fold);
    let children = ChildrenIndex::build(&records);
    let ext_index = ExtensionIndex::build(&records);
    let frs_to_compact: Vec<u32> = (0_usize..16)
        .map(|frs| match frs {
            5 => 0_u32,
            10 => 1,
            11 => 2,
            12 => 3,
            _ => u32::MAX,
        })
        .collect();
    DriveCompactIndex {
        letter: uffs_mft::platform::DriveLetter::T,
        records: ColumnStorage::from_vec(records),
        names: ColumnStorage::from_vec(names),
        trigram: Arc::new(trigram),
        children: Arc::new(children),
        ext_index: Arc::new(ext_index),
        fold,
        ext_names: vec![Box::from("")],
        source: IndexSource::MftFile(PathBuf::from("T:")),
        source_epoch: 42,
        bloom: None,
        path_trie: None,
        frs_to_compact,
        delta: None,
    }
}

#[test]
fn v6_round_trip_preserves_trigram() {
    let index = make_test_index();
    let (tri_keys, tri_offsets, tri_values) = index.trigram.as_csr();
    let original_key_count = tri_keys.len();
    assert!(original_key_count > 0, "test index should have trigrams");

    let serialized = serialize_compact(&index);
    let (loaded, tri_ms) =
        deserialize_compact(&serialized, uffs_mft::platform::DriveLetter::T).unwrap();

    // Trigram loaded from disk — should be fast (< 10ms on any hardware).
    assert!(
        tri_ms < 500,
        "trigram took {tri_ms}ms — should be near-zero for cached CSR"
    );

    // Verify trigram CSR is identical.
    let (loaded_keys, loaded_offsets, loaded_values) = loaded.trigram.as_csr();
    assert_eq!(loaded_keys, tri_keys, "trigram keys mismatch");
    assert_eq!(loaded_offsets, tri_offsets, "trigram offsets mismatch");
    assert_eq!(loaded_values, tri_values, "trigram values mismatch");

    // Verify other fields survived.
    assert_eq!(loaded.letter, uffs_mft::platform::DriveLetter::T);
    assert_eq!(loaded.records.len(), 3);
    assert_eq!(loaded.names.as_slice(), b"foobarbaz");
    assert_eq!(loaded.source_epoch, 42);
}

/// Phase 8 B2: a v9-stamped cache must be rejected so the caller's
/// MFT-rebuild fallback writes a fresh v10 cache (with the
/// `frs_to_compact` mapping the surgical-patch path needs).  This
/// supersedes the now-deleted `v5_backward_compat_rebuilds_trigram`
/// test: v < 10 caches are no longer parseable at all, regardless of
/// section completeness.
#[test]
fn v9_rejected_forces_rebuild() {
    let index = make_test_index();
    let mut serialized = serialize_compact(&index);
    serialized
        .get_mut(8..10)
        .expect("buffer too short for version")
        .copy_from_slice(&9_u16.to_le_bytes());
    let err = deserialize_compact(&serialized, uffs_mft::platform::DriveLetter::T)
        .err()
        .expect("v9 cache must be rejected");
    assert!(
        err.contains("stale compact version"),
        "v9 rejection error message must mention 'stale compact version'; got: {err}"
    );
}

/// Phase 8 B2: round-trip a non-empty `frs_to_compact` mapping
/// through both deserialize paths and assert byte-equal recovery.
/// Pins:
///   1. The serialised section is recoverable (no truncation, no trailing-byte
///      miscount).
///   2. `aligned_vec_from_bytes` returns the same `Vec<u32>` content.
///   3. The runtime-mmap path (records + names mmap-backed) doesn't drop the
///      heap-resident `frs_to_compact` column.
#[test]
fn v10_round_trip_preserves_frs_to_compact() {
    let index = make_test_index();
    let original_mapping = index.frs_to_compact.clone();
    assert!(
        original_mapping.iter().any(|&value| value != u32::MAX),
        "fixture must populate at least one mapped slot"
    );

    let serialized = serialize_compact(&index);

    // Heap deserialise path.
    let (heap_loaded, _) =
        deserialize_compact(&serialized, uffs_mft::platform::DriveLetter::T).expect("heap deser");
    assert_eq!(
        heap_loaded.frs_to_compact, original_mapping,
        "heap-loaded frs_to_compact must match the source mapping"
    );

    // Runtime-mmap deserialise path.
    let (_tmp, runtime_path) = runtime_fixture("f2c_round_trip.live");
    let runtime_dir = uffs_security::runtime_dir::DefaultRuntimeDir::default();
    let (mmap_loaded, _) = deserialize_compact_into_runtime(
        &serialized,
        uffs_mft::platform::DriveLetter::T,
        &runtime_dir,
        &runtime_path,
    )
    .expect("runtime mmap deser");
    assert_eq!(
        mmap_loaded.frs_to_compact, original_mapping,
        "runtime-mmap-loaded frs_to_compact must match the source mapping"
    );
}

/// Phase 8 B2 edge case: a zero-length `frs_to_compact` (e.g. a
/// freshly-built body that hasn't populated the field yet) round-trips
/// to an empty `Vec`, not `Err` or panic.  Guards the `count == 0`
/// fast path in `parse_compact_body`.
#[test]
fn v10_round_trip_empty_frs_to_compact() {
    let mut index = make_test_index();
    index.frs_to_compact = Vec::new();
    let serialized = serialize_compact(&index);
    let (loaded, _) = deserialize_compact(&serialized, uffs_mft::platform::DriveLetter::T)
        .expect("empty mapping deser");
    assert!(
        loaded.frs_to_compact.is_empty(),
        "empty-mapping round-trip must yield Vec::new()"
    );
}

#[test]
fn current_header_version() {
    let index = make_test_index();
    let serialized = serialize_compact(&index);
    let b8 = *serialized.get(8).expect("missing byte 8");
    let b9 = *serialized.get(9).expect("missing byte 9");
    let version = u16::from_le_bytes([b8, b9]);
    assert_eq!(version, COMPACT_VERSION);
}

/// Phase 4 Commit D — every folded record name in the source
/// index must resolve to `contains() == true` after a v9
/// round-trip.  `build_bloom` inserts case-folded basenames (see
/// `compact_filters::build_bloom`), so the query side mirrors the
/// fold contract.  Bloom false-negatives are impossible by
/// construction; a failure here proves the cache-format wiring
/// dropped or corrupted the section.
#[test]
fn v9_round_trip_preserves_bloom() {
    let index = make_test_index();
    let serialized = serialize_compact(&index);
    let (loaded, _tri_ms) =
        deserialize_compact(&serialized, uffs_mft::platform::DriveLetter::T).expect("deser v9");

    let bloom = loaded.bloom.as_ref().expect("v9 cache must carry bloom");
    let mut fold_buf: Vec<u8> = Vec::new();
    for record in &index.records {
        let start = record.name_offset as usize;
        let end = start + usize::from(record.name_len);
        let name_bytes = index
            .names
            .get(start..end)
            .expect("record name slice in source index");
        let name_str =
            core::str::from_utf8(name_bytes).expect("test fixture names are valid UTF-8");
        fold_buf.clear();
        let folded = index.fold.fold_into(name_str, &mut fold_buf);
        assert!(
            bloom.contains(folded.as_bytes()),
            "loaded bloom missed folded name {name_str:?} -> {folded:?}"
        );
    }
}

/// Phase 4 Commit D — the loaded path-trie must be byte-equivalent
/// to one freshly built from the same records / names / fold.  A
/// mismatch in node count, name buffer, or CSR arrays signals the
/// trie section round-trip dropped data.
#[test]
fn v9_round_trip_preserves_path_trie() {
    let index = make_test_index();
    let expected = index.build_path_trie();

    let serialized = serialize_compact(&index);
    let (loaded, _tri_ms) =
        deserialize_compact(&serialized, uffs_mft::platform::DriveLetter::T).expect("deser v9");
    let actual = loaded.path_trie.as_ref().expect("v9 cache must carry trie");

    assert_eq!(
        actual.nodes().len(),
        expected.nodes().len(),
        "trie node count differs after round-trip"
    );
    assert_eq!(
        actual.names(),
        expected.names(),
        "trie names buffer differs after round-trip"
    );
    assert_eq!(
        actual.child_offsets(),
        expected.child_offsets(),
        "trie CSR offsets differ after round-trip"
    );
    assert_eq!(
        actual.child_indices(),
        expected.child_indices(),
        "trie CSR indices differ after round-trip"
    );
}

/// v < 10 caches are rejected outright by the Phase 8 header check.
/// `v1` is the historical canary; the modern rejection covers v1–v9
/// in a single branch.
#[test]
fn v1_rejected() {
    let mut data = vec![0_u8; 64];
    data.get_mut(..8)
        .expect("buffer too short for magic")
        .copy_from_slice(COMPACT_MAGIC);
    data.get_mut(8..10)
        .expect("buffer too short for version")
        .copy_from_slice(&1_u16.to_le_bytes());
    let err = deserialize_compact(&data, uffs_mft::platform::DriveLetter::X)
        .err()
        .expect("v1 cache must be rejected");
    assert!(
        err.contains("stale compact version"),
        "v1 rejection error must mention 'stale compact version'; got: {err}"
    );
}

#[test]
fn truncated_data_rejected() {
    assert!(deserialize_compact(b"short", uffs_mft::platform::DriveLetter::X).is_err());
}

#[test]
fn ext_names_round_trips() {
    let index = make_test_index();
    let serialized = serialize_compact(&index);
    let (deser, _) =
        deserialize_compact(&serialized, uffs_mft::platform::DriveLetter::T).expect("deser");
    assert_eq!(deser.ext_names, index.ext_names);
}

// ─── Phase 2b: runtime-mmap deserialize variant ─────────────────────

/// Open a fresh `DefaultRuntimeDir` + per-test runtime tempfile path
/// inside a `TempDir` so the tempfile is scoped to the test.
fn runtime_fixture(file_name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join(file_name);
    (dir, path)
}

#[test]
fn v6_round_trip_via_runtime_mmap_preserves_trigram() {
    let index = make_test_index();
    let (orig_keys, orig_offsets, orig_values) = index.trigram.as_csr();
    let original_keys = orig_keys.to_vec();
    let original_offsets = orig_offsets.to_vec();
    let original_values = orig_values.to_vec();
    assert!(!original_keys.is_empty(), "test index should have trigrams");

    let serialized = serialize_compact(&index);
    let (_tmp, runtime_path) = runtime_fixture("v6_runtime_mmap.live");
    let runtime_dir = uffs_security::runtime_dir::DefaultRuntimeDir::default();
    let (loaded, tri_ms) = deserialize_compact_into_runtime(
        &serialized,
        uffs_mft::platform::DriveLetter::T,
        &runtime_dir,
        &runtime_path,
    )
    .expect("runtime mmap deser");

    // v6+ CSR is loaded from disk — never rebuilt.
    assert!(
        tri_ms < 500,
        "trigram took {tri_ms}ms via runtime mmap — should be near-zero for cached CSR"
    );

    // Trigram CSR survives byte-for-byte through the mmap path.
    let (loaded_keys, loaded_offsets, loaded_values) = loaded.trigram.as_csr();
    assert_eq!(loaded_keys, original_keys.as_slice());
    assert_eq!(loaded_offsets, original_offsets.as_slice());
    assert_eq!(loaded_values, original_values.as_slice());

    // Records + names columns are now mmap-backed but observably
    // identical to the heap-backed source.
    assert_eq!(loaded.letter, uffs_mft::platform::DriveLetter::T);
    assert_eq!(loaded.records.len(), 3);
    assert_eq!(loaded.names.as_slice(), b"foobarbaz");
    assert_eq!(loaded.source_epoch, 42);
    assert_eq!(loaded.ext_names, index.ext_names);
}

#[test]
fn mmap_path_byte_equal_to_heap_path() {
    let index = make_test_index();
    let serialized = serialize_compact(&index);

    let (heap_loaded, _) =
        deserialize_compact(&serialized, uffs_mft::platform::DriveLetter::T).expect("heap deser");

    let (_tmp, runtime_path) = runtime_fixture("byte_equal.live");
    let runtime_dir = uffs_security::runtime_dir::DefaultRuntimeDir::default();
    let (mmap_loaded, _) = deserialize_compact_into_runtime(
        &serialized,
        uffs_mft::platform::DriveLetter::T,
        &runtime_dir,
        &runtime_path,
    )
    .expect("mmap deser");

    // The two storage variants must yield identical observable
    // contents — bytemuck-cast records and names slice should be
    // bitwise-equal.
    assert_eq!(
        bytemuck::cast_slice::<CompactRecord, u8>(heap_loaded.records.as_slice()),
        bytemuck::cast_slice::<CompactRecord, u8>(mmap_loaded.records.as_slice()),
        "records bytes must match between heap and mmap variants",
    );
    assert_eq!(
        heap_loaded.names.as_slice(),
        mmap_loaded.names.as_slice(),
        "names bytes must match between heap and mmap variants",
    );
    assert_eq!(heap_loaded.ext_names, mmap_loaded.ext_names);
    assert_eq!(heap_loaded.source_epoch, mmap_loaded.source_epoch);
}

#[test]
fn runtime_mmap_rejects_truncated_data() {
    let (_tmp, runtime_path) = runtime_fixture("truncated.live");
    let runtime_dir = uffs_security::runtime_dir::DefaultRuntimeDir::default();
    // `Result::err()` avoids the `T: Debug` bound that `expect_err`
    // would impose on `(DriveCompactIndex, u128)`.
    let err = deserialize_compact_into_runtime(
        b"short",
        uffs_mft::platform::DriveLetter::X,
        &runtime_dir,
        &runtime_path,
    )
    .err()
    .expect("truncated data must error via runtime path");
    assert_eq!(err.kind(), io::ErrorKind::Other);
}

// ─── Phase 2b Commit F: memory regression — storage-variant pinning ───
//
// The runtime mmap path (`deserialize_compact_into_runtime`) must serve
// the two largest columns (`records`, `names`) from the kernel page
// cache, not the heap.  The heap path (`deserialize_compact`) must
// continue to allocate `Vec`s.  Asserting the [`ColumnStorage`] variant
// directly is the deterministic, byte-precise version of the RSS check
// the implementation plan (§3 Phase 2b Commit F) originally proposed —
// the RSS approach is dominated by page granularity (4 KB / 16 KB) at
// any feasible test scale and would be flaky in CI.

#[test]
fn runtime_path_yields_mmap_backed_columns() {
    let index = make_test_index();
    let serialized = serialize_compact(&index);

    let (_tmp, runtime_path) = runtime_fixture("variant_mmap.live");
    let runtime_dir = uffs_security::runtime_dir::DefaultRuntimeDir::default();
    let (loaded, _tri_ms) = deserialize_compact_into_runtime(
        &serialized,
        uffs_mft::platform::DriveLetter::T,
        &runtime_dir,
        &runtime_path,
    )
    .expect("mmap deser");

    assert!(
        loaded.records.is_mmap(),
        "records column must be Mmap-backed after deserialize_compact_into_runtime"
    );
    assert!(
        loaded.names.is_mmap(),
        "names column must be Mmap-backed after deserialize_compact_into_runtime"
    );
    assert!(
        !loaded.records.is_vec(),
        "records column must NOT be Vec-backed after deserialize_compact_into_runtime"
    );
    assert!(
        !loaded.names.is_vec(),
        "names column must NOT be Vec-backed after deserialize_compact_into_runtime"
    );
}

#[test]
fn heap_path_yields_vec_backed_columns() {
    let index = make_test_index();
    let serialized = serialize_compact(&index);

    let (loaded, _tri_ms) =
        deserialize_compact(&serialized, uffs_mft::platform::DriveLetter::T).expect("heap deser");

    assert!(
        loaded.records.is_vec(),
        "records column must be Vec-backed after deserialize_compact (legacy heap path)"
    );
    assert!(
        loaded.names.is_vec(),
        "names column must be Vec-backed after deserialize_compact (legacy heap path)"
    );
    assert!(
        !loaded.records.is_mmap(),
        "records column must NOT be Mmap-backed after deserialize_compact"
    );
    assert!(
        !loaded.names.is_mmap(),
        "names column must NOT be Mmap-backed after deserialize_compact"
    );
}

// ─── Mac wake-up regression: purge_legacy_compact_cache_dir contract ───
//
// Pin the four-arm behaviour of [`super::purge_legacy_compact_cache_dir`]
// so the v0.4.23 legacy-directory recovery path can never silently
// regress.  Each test sets up the on-disk state directly inside a
// `tempfile::TempDir` (no dependence on the global `cache_dir()`), then
// exercises the helper and asserts both the return value and the
// resulting filesystem state.

/// Path doesn't exist → `Ok(())`, filesystem unchanged.  Cold-boot
/// first save hits this arm.
#[test]
fn purge_legacy_dir_missing_path_is_noop() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("Z_compact.uffs");
    assert!(!path.exists(), "precondition: path absent");

    purge_legacy_compact_cache_dir(&path, uffs_mft::platform::DriveLetter::Z)
        .expect("missing path must be Ok(())");

    assert!(
        !path.exists(),
        "missing path must remain missing after purge"
    );
}

/// Path is a regular file → `Ok(())`, file untouched.  Steady-state
/// after the first successful save lands here on every subsequent call.
#[test]
fn purge_legacy_dir_regular_file_is_noop() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("Z_compact.uffs");
    std::fs::write(&path, b"existing cache bytes").expect("seed regular file");

    purge_legacy_compact_cache_dir(&path, uffs_mft::platform::DriveLetter::Z)
        .expect("regular file must be Ok(())");

    let bytes = std::fs::read(&path).expect("regular file must still be readable");
    assert_eq!(
        bytes, b"existing cache bytes",
        "regular file content must survive purge unchanged"
    );
}

/// Path is an **empty** directory (the v0.4.23 layout) → directory
/// removed, helper returns `Ok(())`.  This is the actual legacy state
/// observed on dogfood Mac filesystems on 2026-04-28.
#[test]
fn purge_legacy_dir_empty_directory_is_removed() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("Z_compact.uffs");
    std::fs::create_dir(&path).expect("seed empty directory");
    assert!(path.is_dir(), "precondition: path is empty dir");

    purge_legacy_compact_cache_dir(&path, uffs_mft::platform::DriveLetter::Z)
        .expect("empty dir must be Ok(())");

    assert!(
        !path.exists(),
        "empty legacy directory must be removed by purge"
    );
}

/// Path is a **non-empty** directory → helper returns `Err` (the
/// underlying `ENOTEMPTY`) and the directory is left intact.  Defensive
/// guard against a hypothetical future regression that populates the
/// path: we want the daemon to surface the failure loudly rather than
/// silently `remove_dir_all` user data.
#[test]
fn purge_legacy_dir_non_empty_directory_is_refused() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("Z_compact.uffs");
    std::fs::create_dir(&path).expect("seed dir");
    std::fs::write(path.join("unexpected.bin"), b"surprise").expect("seed dir contents");

    let err = purge_legacy_compact_cache_dir(&path, uffs_mft::platform::DriveLetter::Z)
        .expect_err("non-empty dir must propagate the underlying io::Error");
    assert!(
        matches!(
            err.kind(),
            io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::Other
        ),
        "non-empty dir must produce DirectoryNotEmpty (or fall back to Other on \
         older platforms); got {kind:?}",
        kind = err.kind(),
    );

    assert!(
        path.is_dir(),
        "non-empty dir must remain on disk after refused purge",
    );
    assert!(
        path.join("unexpected.bin").is_file(),
        "non-empty dir contents must be untouched after refused purge",
    );
}

// ─── Corrupt-cache quarantine (2026-08 self-heal) ───────────────────────────

#[test]
fn corruption_classification_is_permanent_failures_only() {
    // Corruption-class: the same on-disk bytes can never load again.
    assert!(LoadCacheError::DecryptFailed("mac mismatch".to_owned()).is_corruption());
    assert!(LoadCacheError::DecompressFailed("bad frame".to_owned()).is_corruption());
    assert!(LoadCacheError::ParseError("bad magic").is_corruption());
    assert!(LoadCacheError::Deserialize("bloom k_hashes out of range".to_owned()).is_corruption());

    // Transient / environmental: retrying or fixing the environment can
    // succeed with the same file — never quarantine these.
    assert!(!LoadCacheError::Missing.is_corruption());
    assert!(
        !LoadCacheError::StaleByTtl {
            age_secs: 10,
            ttl_secs: 5
        }
        .is_corruption()
    );
    assert!(!LoadCacheError::StaleVsMft.is_corruption());
    assert!(
        !LoadCacheError::StaleByEpoch {
            cached_epoch: 1,
            current_epoch: 2
        }
        .is_corruption()
    );
    assert!(!LoadCacheError::Io(io::Error::other("disk gone")).is_corruption());
    assert!(!LoadCacheError::KeyUnavailable("keychain denied".to_owned()).is_corruption());
    assert!(!LoadCacheError::RuntimeTempfile("perms".to_owned()).is_corruption());
}

#[test]
fn quarantine_moves_corrupt_file_aside() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("T_compact.uffs");
    std::fs::write(&path, b"poisoned bytes").unwrap();

    quarantine_corrupt_cache(
        &path,
        uffs_mft::platform::DriveLetter::T,
        &LoadCacheError::Deserialize("bloom k_hashes out of range".to_owned()),
    );

    // The poisoned file is gone (next load reports `Missing` → rebuild)
    // and its bytes survive as a forensic sample.
    assert!(!path.exists());
    let sample = dir.path().join("T_compact.uffs.corrupt");
    assert_eq!(std::fs::read(&sample).unwrap(), b"poisoned bytes");
}

#[test]
fn quarantine_replaces_previous_sample() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("T_compact.uffs");
    let sample = dir.path().join("T_compact.uffs.corrupt");
    std::fs::write(&path, b"newer poison").unwrap();
    // A sample from an earlier incident must not block the rename
    // (Windows `rename` refuses to overwrite an existing destination).
    std::fs::write(&sample, b"older poison").unwrap();

    quarantine_corrupt_cache(
        &path,
        uffs_mft::platform::DriveLetter::T,
        &LoadCacheError::ParseError("bad magic"),
    );

    assert!(!path.exists());
    assert_eq!(std::fs::read(&sample).unwrap(), b"newer poison");
}

#[test]
fn quarantine_of_missing_file_is_harmless() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("T_compact.uffs");

    // Nothing to move and nothing to delete — must not panic or create
    // stray files.
    quarantine_corrupt_cache(
        &path,
        uffs_mft::platform::DriveLetter::T,
        &LoadCacheError::ParseError("bad magic"),
    );

    assert!(!path.exists());
    assert!(!dir.path().join("T_compact.uffs.corrupt").exists());
}

#[test]
fn load_compact_cache_at_quarantines_nothing_itself() {
    // `load_compact_cache_at` is the pure load pipeline: handing it
    // garbage must fail with a corruption-class error and leave the file
    // in place — the quarantine decision belongs to the public wrapper.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("T_compact.uffs");
    std::fs::write(&path, b"definitely not an encrypted cache").unwrap();

    // `.err()` instead of `unwrap_err()`: `DriveCompactIndex` has no
    // `Debug` impl, which `unwrap_err`'s panic message would require.
    let err = load_compact_cache_at(&path, uffs_mft::platform::DriveLetter::T, u64::MAX, 0, true)
        .err()
        .unwrap();

    // Host-dependent early-out: without a cache key (locked Keychain /
    // headless CI) the pipeline fails before decryption ever sees the
    // garbage.  The classification itself is pinned by the pure tests
    // above; this test's subject is the file-untouched contract below.
    if !matches!(err, LoadCacheError::KeyUnavailable(_)) {
        assert!(
            err.is_corruption(),
            "garbage bytes must classify as corruption, got: {err}"
        );
    }
    assert!(path.exists(), "inner loader must not touch the file");
}

// The cache-poisoning regression cluster (empty-trigram shape, the
// delta-carrying misalignment, and the save-boundary refusal) lives in
// a nested sibling file so this module stays under the workspace
// 800-LOC ceiling.  `#[path]` keeps it a child of `tests`, so it can
// use this module's `make_test_index` fixture directly.
#[path = "tests_cache_poison.rs"]
mod cache_poison;
