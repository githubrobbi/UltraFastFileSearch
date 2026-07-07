// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit tests for [`super::RuntimeDir`].
//!
//! Coverage strategy:
//!
//! * **Real `DefaultRuntimeDir`** for `create_owner_only` (Unix permissions /
//!   Windows share mode are exercised on the real platform).
//! * **`TestRuntimeDir`** (the in-process fake) for orphan sweep semantics —
//!   the test owns the "alive pid" oracle so coverage is deterministic and
//!   platform-agnostic.
//! * `mmap_read_only` round-trip covered against the real default impl on
//!   whichever platform is running the test.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use tempfile::TempDir;

use super::test_fake::TestRuntimeDir;
use super::{DefaultRuntimeDir, RuntimeDir as _, mmap_read_only};

// ─────────────────────────────────────────────────────────────────────
// `create_owner_only` — happy path + duplicate-create rejection.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn create_owner_only_writes_and_reads_round_trip() {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("round_trip.live");
    let dir = DefaultRuntimeDir::default();
    let mut rf = dir.create_owner_only(&path).expect("create");

    let payload = b"hello phase 2b runtime tempfile";
    rf.as_file_mut().write_all(payload).expect("write");
    rf.as_file_mut().sync_all().expect("sync_all");
    rf.as_file_mut().seek(SeekFrom::Start(0)).expect("seek");

    let mut buf = Vec::with_capacity(payload.len());
    rf.as_file_mut().read_to_end(&mut buf).expect("read_to_end");
    assert_eq!(buf, payload, "round-trip bytes mismatch");
    assert_eq!(rf.path(), path.as_path(), "path accessor mismatch");
}

#[test]
fn create_owner_only_rejects_existing_file() {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("dupe.live");
    let dir = DefaultRuntimeDir::default();

    let _first = dir.create_owner_only(&path).expect("first create");
    let err = dir
        .create_owner_only(&path)
        .expect_err("second create_new must fail");
    // CREATE_NEW / O_EXCL semantics surface as AlreadyExists.
    // On Windows the error originates from CreateFileW returning
    // ERROR_FILE_EXISTS; the kind translation is best-effort, so
    // tolerate either AlreadyExists or PermissionDenied to keep the
    // assertion robust across kernel paths.
    let kind = err.kind();
    assert!(
        matches!(
            kind,
            std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::PermissionDenied
        ),
        "expected AlreadyExists/PermissionDenied, got {kind:?}: {err}"
    );
}

#[cfg(unix)]
#[test]
fn create_owner_only_sets_0600_on_unix() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("perms.live");
    let dir = DefaultRuntimeDir::default();
    let _rf = dir.create_owner_only(&path).expect("create");

    let meta = std::fs::metadata(&path).expect("metadata");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "mode bits: 0o{mode:o}");
}

// ─────────────────────────────────────────────────────────────────────
// `mmap_read_only` — content equality with the bytes we wrote.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn mmap_read_only_observes_post_write_bytes() {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("mmap.live");
    let dir = DefaultRuntimeDir::default();
    let mut rf = dir.create_owner_only(&path).expect("create");

    // Write a deterministic 4 KiB payload (one page) so we exercise
    // the mmap path on a non-trivial size.
    let payload: Vec<u8> = (0_u8..=u8::MAX).cycle().take(4096).collect();
    rf.as_file_mut().write_all(&payload).expect("write");
    rf.as_file_mut().sync_all().expect("sync_all");

    let mmap = mmap_read_only(&rf).expect("mmap");
    assert_eq!(mmap.len(), payload.len());
    assert_eq!(&*mmap, payload.as_slice());
}

// ─────────────────────────────────────────────────────────────────────
// `cleanup_orphans` — drives every behaviour case via TestRuntimeDir.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn cleanup_orphans_returns_zero_for_empty_root() {
    let tmp = TempDir::new().expect("tempdir");
    let runtime_root = tmp.path().join("runtime");
    std::fs::create_dir_all(&runtime_root).expect("create runtime root");

    let fake = TestRuntimeDir::new();
    let removed = fake.cleanup_orphans(&runtime_root).expect("sweep");
    assert_eq!(removed, 0);
}

#[test]
fn cleanup_orphans_returns_zero_for_missing_root() {
    let tmp = TempDir::new().expect("tempdir");
    // intentionally do NOT create the root — sweep should be a no-op.
    let runtime_root = tmp.path().join("never_created");

    let fake = TestRuntimeDir::new();
    let removed = fake.cleanup_orphans(&runtime_root).expect("sweep");
    assert_eq!(removed, 0);
}

#[test]
fn cleanup_orphans_removes_dead_pid_dirs_only() {
    let tmp = TempDir::new().expect("tempdir");
    let runtime_root = tmp.path().join("runtime");
    std::fs::create_dir_all(&runtime_root).expect("create runtime root");

    // Three pid dirs: 100 (alive), 200 (dead), 300 (alive).
    for pid in [100_u32, 200, 300] {
        let pid_dir = runtime_root.join(pid.to_string());
        std::fs::create_dir_all(&pid_dir).expect("create pid dir");
        std::fs::write(pid_dir.join("shard.live"), b"contents").expect("write contents");
    }

    let fake = TestRuntimeDir::new();
    fake.mark_alive(100);
    fake.mark_alive(300);

    let removed = fake.cleanup_orphans(&runtime_root).expect("sweep");
    assert_eq!(removed, 1, "only pid 200 should be removed");
    assert!(runtime_root.join("100").exists(), "pid 100 must remain");
    assert!(!runtime_root.join("200").exists(), "pid 200 must be gone");
    assert!(runtime_root.join("300").exists(), "pid 300 must remain");
}

#[test]
fn cleanup_orphans_ignores_non_pid_entries() {
    let tmp = TempDir::new().expect("tempdir");
    let runtime_root = tmp.path().join("runtime");
    std::fs::create_dir_all(&runtime_root).expect("create runtime root");

    // Mix of non-numeric dirs, regular files, and one dead-pid dir.
    std::fs::create_dir_all(runtime_root.join("not_a_pid")).expect("dir1");
    std::fs::create_dir_all(runtime_root.join("definitely_text")).expect("dir2");
    std::fs::write(runtime_root.join("123"), b"file_not_dir").expect("regular file");
    let dead_pid_dir = runtime_root.join("9999");
    std::fs::create_dir_all(&dead_pid_dir).expect("dead pid dir");

    let fake = TestRuntimeDir::new();
    // pid 9999 is not marked alive → dead.
    let removed = fake.cleanup_orphans(&runtime_root).expect("sweep");
    assert_eq!(removed, 1, "only the numeric-named dir for the dead pid");
    assert!(runtime_root.join("not_a_pid").exists());
    assert!(runtime_root.join("definitely_text").exists());
    assert!(runtime_root.join("123").exists(), "regular file untouched");
    assert!(!dead_pid_dir.exists(), "dead pid dir should be gone");
}

#[test]
fn cleanup_orphans_recurses_into_dead_pid_subtree() {
    let tmp = TempDir::new().expect("tempdir");
    let runtime_root = tmp.path().join("runtime");
    std::fs::create_dir_all(&runtime_root).expect("create runtime root");

    // A dead pid dir with nested files & subdirs — must be wiped
    // entirely.  Mirrors the real shape: `<pid>/<volume-guid>.live`.
    let pid_dir = runtime_root.join("4242");
    std::fs::create_dir_all(pid_dir.join("nested")).expect("nested dir");
    std::fs::write(pid_dir.join("a.live"), b"shard a").expect("a.live");
    std::fs::write(pid_dir.join("b.live"), b"shard b").expect("b.live");
    std::fs::write(pid_dir.join("nested").join("c.live"), b"shard c").expect("c.live");

    let fake = TestRuntimeDir::new();
    let removed = fake.cleanup_orphans(&runtime_root).expect("sweep");
    assert_eq!(removed, 1);
    assert!(!pid_dir.exists(), "dead pid subtree must be gone");
}

#[test]
fn cleanup_orphans_double_sweep_is_idempotent() {
    let tmp = TempDir::new().expect("tempdir");
    let runtime_root = tmp.path().join("runtime");
    std::fs::create_dir_all(&runtime_root).expect("root");

    let pid_dir = runtime_root.join("7777");
    std::fs::create_dir_all(&pid_dir).expect("pid dir");
    std::fs::write(pid_dir.join("shard.live"), b"x").expect("shard");

    let fake = TestRuntimeDir::new();
    let first = fake.cleanup_orphans(&runtime_root).expect("first sweep");
    let second = fake.cleanup_orphans(&runtime_root).expect("second sweep");
    assert_eq!(first, 1, "first sweep removes the dead pid dir");
    assert_eq!(second, 0, "second sweep is a no-op");
}

#[test]
fn cleanup_orphans_marking_dead_after_mark_alive_re_enables_sweep() {
    let tmp = TempDir::new().expect("tempdir");
    let runtime_root = tmp.path().join("runtime");
    std::fs::create_dir_all(&runtime_root).expect("root");

    let pid_dir = runtime_root.join("5555");
    std::fs::create_dir_all(&pid_dir).expect("pid dir");

    let fake = TestRuntimeDir::new();
    fake.mark_alive(5555);
    let pre = fake.cleanup_orphans(&runtime_root).expect("pre-sweep");
    assert_eq!(pre, 0, "alive pid: dir preserved");
    assert!(pid_dir.exists());

    fake.mark_dead(5555);
    let post = fake.cleanup_orphans(&runtime_root).expect("post-sweep");
    assert_eq!(post, 1, "dead pid: dir removed");
    assert!(!pid_dir.exists());
}

// ─────────────────────────────────────────────────────────────────────
// Default impl smoke test — confirm `cleanup_orphans` runs without
// error when given the real (platform-specific) liveness probe.  The
// test creates a `<u32::MAX - 1>/` dir which is essentially
// guaranteed dead on any real OS, and the current process's own pid
// dir which is essentially guaranteed alive.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn default_runtime_dir_sweeps_with_real_liveness_probe() {
    let tmp = TempDir::new().expect("tempdir");
    let runtime_root = tmp.path().join("runtime");
    std::fs::create_dir_all(&runtime_root).expect("root");

    let our_pid = std::process::id();
    let alive_dir = runtime_root.join(our_pid.to_string());
    std::fs::create_dir_all(&alive_dir).expect("alive dir");

    // Pick a pid that is overwhelmingly likely to be dead.  On
    // POSIX, pids are u16 by tradition (≤ 32767); on Windows pids
    // can be larger but are also bounded well below u32::MAX.
    // u32::MAX - 1 is a safe "never alive" sentinel.
    let dead_pid: u32 = u32::MAX - 1;
    let dead_dir = runtime_root.join(dead_pid.to_string());
    std::fs::create_dir_all(&dead_dir).expect("dead dir");

    let dir = DefaultRuntimeDir::default();
    let removed = dir.cleanup_orphans(&runtime_root).expect("cleanup_orphans");
    assert!(
        removed >= 1,
        "expected at least the synthetic dead-pid dir to be swept (removed={removed})"
    );
    assert!(alive_dir.exists(), "our own process's pid dir must remain");
    assert!(!dead_dir.exists(), "synthetic dead-pid dir must be gone");
}
