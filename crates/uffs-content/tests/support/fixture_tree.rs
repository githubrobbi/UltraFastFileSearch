// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Builds a deterministic test directory tree exercising the size
//! classes, encoding edge cases, and hard-link semantics called for by
//! `uffs-ingest-implementation-plan.md` §9.2.
//!
//! Deliberately smaller than the plan's full real-VSS test sizes (a real
//! 64 MiB+ file): this harness runs on every PR, so its "large" bucket is
//! scaled down to something that still forces multi-chunk streaming
//! without slowing every CI run. The real-VSS test (§9.4, Windows-only,
//! `#[ignore]`) is where the full production size classes belong.

use std::path::{Path, PathBuf};

/// One file this harness deliberately created.
#[derive(Debug, Clone)]
pub(crate) struct FixtureFile {
    /// Path relative to the fixture tree's root.
    pub relative_path: PathBuf,
    /// Exact bytes written.
    pub content: Vec<u8>,
}

/// Builds the fixture tree under `root` (must already exist), returning
/// every file it created.
pub(crate) fn build(root: &Path) -> Vec<FixtureFile> {
    let mut files = vec![
        write_file(root, Path::new("zero_byte.dat"), &[]),
        write_file(
            root,
            Path::new("resident_small.txt"),
            &deterministic_content("resident_small.txt", 200),
        ),
        write_file(
            root,
            Path::new("small_16k.bin"),
            &deterministic_content("small_16k.bin", 16 * 1024),
        ),
        write_file(
            root,
            Path::new("medium_256k.bin"),
            &deterministic_content("medium_256k.bin", 256 * 1024),
        ),
        write_file(
            root,
            Path::new("large_2m.bin"),
            &deterministic_content("large_2m.bin", 2 * 1024 * 1024),
        ),
    ];

    let nested_relative: PathBuf = ["a", "b", "c", "d", "nested.txt"].iter().collect();
    files.push(write_file(
        root,
        &nested_relative,
        &deterministic_content("nested.txt", 512),
    ));

    // Non-ASCII / non-BMP name (the emoji requires a UTF-16 surrogate
    // pair) — exercises the lossless Windows path encoding.
    let unicode_relative = PathBuf::from("日本語_😀.txt");
    files.push(write_file(
        root,
        &unicode_relative,
        &deterministic_content("unicode-name-seed", 128),
    ));

    // Hard link: two directory entries, one underlying file.
    let original_relative = PathBuf::from("hardlink_original.dat");
    let original_content = deterministic_content("hardlink_original.dat", 4096);
    files.push(write_file(root, &original_relative, &original_content));
    let linked_relative = PathBuf::from("hardlink_copy.dat");
    std::fs::hard_link(root.join(&original_relative), root.join(&linked_relative))
        .expect("hard_link must succeed");
    files.push(FixtureFile {
        relative_path: linked_relative,
        content: original_content,
    });

    files
}

/// Writes `content` at `root.join(relative)`, creating parent directories
/// as needed, and returns the corresponding [`FixtureFile`].
fn write_file(root: &Path, relative: &Path, content: &[u8]) -> FixtureFile {
    let absolute = root.join(relative);
    if let Some(parent) = absolute.parent() {
        std::fs::create_dir_all(parent).expect("create_dir_all must succeed");
    }
    std::fs::write(&absolute, content).expect("write must succeed");
    FixtureFile {
        relative_path: relative.to_path_buf(),
        content: content.to_vec(),
    }
}

/// Deterministic, non-uniform content: expands a BLAKE3 hash of `seed`
/// via its extendable output, so content is reproducible across runs but
/// not trivially compressible/all-zeros — catching a digest bug that
/// only manifests on repetitive content.
fn deterministic_content(seed: &str, length: usize) -> Vec<u8> {
    let mut output = vec![0_u8; length];
    let mut hasher = blake3::Hasher::new();
    hasher.update(seed.as_bytes());
    let mut xof_reader = hasher.finalize_xof();
    xof_reader.fill(&mut output);
    output
}
