// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! MFT file discovery utilities.
//!
//! Scan a data directory for `drive_*` subdirectories and locate MFT files
//! within them. Used by both the CLI and TUI to resolve `--data-dir` into
//! concrete MFT file paths.
//!
//! # Directory layout
//!
//! ```text
//! ~/uffs_data/
//! ├── drive_c/
//! │   └── C_mft.iocp
//! ├── drive_d/
//! │   └── D_mft.bin
//! └── drive_e/
//!     └── E.mft
//! ```
//!
//! # Examples
//!
//! ```no_run
//! use std::path::Path;
//!
//! use uffs_mft::discovery;
//!
//! let files = discovery::discover_mft_files(Path::new("~/uffs_data"));
//! assert!(!files.is_empty());
//! ```

use std::path::{Path, PathBuf};

/// Scan a data directory for MFT files in `drive_*` subdirectories.
///
/// Looks for subdirectories named `drive_c`, `drive_d`, etc. (single ASCII
/// letter after `drive_`). Within each, selects the best MFT file by format
/// priority: `.iocp` > `.bin` > `.mft`.
///
/// Returns a sorted list of discovered MFT file paths.
#[must_use]
pub fn discover_mft_files(data_dir: &Path) -> Vec<PathBuf> {
    let mut mft_files = Vec::new();

    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return mft_files;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|os_name| os_name.to_str()) else {
            continue;
        };
        if let Some(letter) = name.strip_prefix("drive_")
            && letter.len() == 1
            && letter
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic())
            && let Some(best) = find_best_mft_file(&path)
        {
            mft_files.push(best);
        }
    }

    mft_files.sort();
    mft_files
}

/// Find the best MFT file in a directory by format priority.
///
/// Prefers `.iocp` (IOCP capture) over `.bin` (raw MFT) over `.mft`
/// (legacy format). Returns `None` if no recognised MFT file is found.
#[must_use]
pub fn find_best_mft_file(dir: &Path) -> Option<PathBuf> {
    let Ok(files) = std::fs::read_dir(dir) else {
        return None;
    };

    let mut best: Option<(PathBuf, u8)> = None; // (path, priority: 0=iocp, 1=bin, 2=mft)

    for file in files.flatten() {
        let file_path = file.path();
        if !file_path.is_file() {
            continue;
        }
        let Some(ext) = file_path.extension().and_then(|ext_os| ext_os.to_str()) else {
            continue;
        };
        let priority = match ext {
            "iocp" => 0_u8, // best
            "bin" => 1,
            "mft" => 2,
            _ => continue,
        };
        if best.as_ref().is_none_or(|(_, bp)| priority < *bp) {
            best = Some((file_path, priority));
        }
    }

    best.map(|(path, _)| path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_best_mft_file_returns_none_for_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(find_best_mft_file(tmp.path()).is_none());
    }

    #[test]
    fn find_best_mft_file_prefers_iocp_over_bin() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("C.bin"), b"").unwrap();
        std::fs::write(tmp.path().join("C.iocp"), b"").unwrap();
        let best = find_best_mft_file(tmp.path()).unwrap();
        assert_eq!(best.extension().unwrap(), "iocp");
    }

    #[test]
    fn discover_mft_files_finds_drive_subdirs() {
        let tmp = tempfile::tempdir().unwrap();
        let drive_c = tmp.path().join("drive_c");
        let drive_d = tmp.path().join("drive_d");
        std::fs::create_dir(&drive_c).unwrap();
        std::fs::create_dir(&drive_d).unwrap();
        std::fs::write(drive_c.join("C.iocp"), b"").unwrap();
        std::fs::write(drive_d.join("D.bin"), b"").unwrap();
        // Should not be picked up (not a drive_X pattern)
        let other = tmp.path().join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::write(other.join("X.iocp"), b"").unwrap();

        let files = discover_mft_files(tmp.path());
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn discover_mft_files_ignores_multi_letter_suffixes() {
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("drive_cd");
        std::fs::create_dir(&bad).unwrap();
        std::fs::write(bad.join("CD.iocp"), b"").unwrap();

        let files = discover_mft_files(tmp.path());
        assert_eq!(files, Vec::<PathBuf>::new());
    }
}
