// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Independent reference directory walk — the end-to-end parity test's
//! oracle.
//!
//! Deliberately does not call into `uffs-content`, `uffs-content-protocol`,
//! `uffs-core`, or `uffs-mft`: the entire point is an implementation that
//! shares no code with the pipeline under test, so a shared bug can't
//! hide from the comparison.

use std::fs;
use std::path::{Path, PathBuf};

/// One file as seen by a plain recursive directory walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainWalkEntry {
    /// Path relative to the walked root.
    pub relative_path: PathBuf,
    /// File size in bytes.
    pub size: u64,
    /// BLAKE3 digest of the file's content, computed directly (not
    /// through `uffs-content-protocol::codec::digest`).
    pub digest: blake3::Hash,
}

/// Recursively walks `root`, hashing every regular file's content with
/// `blake3` directly.
#[must_use]
pub(crate) fn plain_walk(root: &Path) -> Vec<PlainWalkEntry> {
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<PlainWalkEntry>) {
    let mut entries: Vec<fs::DirEntry> = fs::read_dir(dir)
        .expect("read_dir must succeed")
        .collect::<Result<_, _>>()
        .expect("collecting read_dir entries must succeed");
    entries.sort_by_key(fs::DirEntry::path);

    for entry in entries {
        let path = entry.path();
        let metadata = entry.metadata().expect("metadata must succeed");
        if metadata.is_dir() {
            walk(root, &path, out);
        } else if metadata.is_file() {
            let content = fs::read(&path).expect("read must succeed");
            let relative_path = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            out.push(PlainWalkEntry {
                relative_path,
                size: metadata.len(),
                digest: blake3::hash(&content),
            });
        }
    }
}
