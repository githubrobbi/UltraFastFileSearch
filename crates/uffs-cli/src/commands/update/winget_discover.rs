// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Discover a **dormant** WinGet-managed UFFS install (design: Phase A).
//!
//! The ordinary anchor scan (invoking exe + running daemon / broker / MCP)
//! only surfaces a winget root when something is *running* from it. With the
//! daemon and broker both stopped, and `uffs --update` invoked from a different
//! (e.g. hand-placed `~\bin`) copy, the winget install has no live anchor and
//! goes invisible — so the updater can neither see nor reconcile it.
//!
//! `WinGet` does not expose a portable package's install directory (`winget
//! list` prints the version, not the path), but the location is deterministic:
//! portable packages always land under
//! `…\Microsoft\WinGet\Packages\<Id>_<hash>\`. [`discover`] scans that
//! well-known location so a dormant winget install is found regardless of what
//! is running. Windows-only; a no-op elsewhere.

use std::path::{Path, PathBuf};

use super::model::{Anchor, InstallRoot};
use super::winget::WINGET_PACKAGE_ID;

/// Add any WinGet-managed UFFS install root(s) found at the well-known
/// `WinGet\Packages` location to `roots` (deduplicated by
/// [`super::upsert_root`]). No-op off Windows and when winget has no UFFS
/// package folder.
pub(crate) fn discover(roots: &mut Vec<InstallRoot>) {
    for base in winget_packages_bases() {
        for dir in roots_under_packages_base(&base) {
            super::upsert_root(roots, dir, Anchor::Winget);
        }
    }
}

/// Whether `folder_name` is UFFS's winget portable-package folder — i.e.
/// `<WINGET_PACKAGE_ID>_<source-hash>` (case-insensitive). The trailing `_`
/// keeps `SkyLLC.UFFS_…` from matching a hypothetical `SkyLLC.UFFSomething`.
fn is_uffs_package_folder(folder_name: &str) -> bool {
    let prefix = format!("{WINGET_PACKAGE_ID}_").to_ascii_lowercase();
    folder_name.to_ascii_lowercase().starts_with(&prefix)
}

/// Every UFFS install root directly under a `WinGet\Packages` `base`: for each
/// `<Id>_<hash>` package folder, the subdirectory that actually holds the UFFS
/// binaries. Cross-platform filesystem logic (the Windows-only part is which
/// `base` paths are supplied); a missing/unreadable `base` yields nothing.
fn roots_under_packages_base(base: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(base) else {
        return found;
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let name_os = entry.file_name();
        let Some(name) = name_os.to_str() else {
            continue;
        };
        if is_uffs_package_folder(name)
            && let Some(dir) = find_dir_with_uffs(&entry.path())
        {
            found.push(dir);
        }
    }
    found
}

/// The directory holding `uffs` within a package folder: the folder itself, or
/// one of its immediate subdirectories (the extracted zip's single top folder,
/// e.g. `uffs-windows-x64`). Descends at most one level — enough for the winget
/// layout, and bounded so a stray package folder can't trigger a deep walk.
fn find_dir_with_uffs(pkg: &Path) -> Option<PathBuf> {
    if dir_has_uffs(pkg) {
        return Some(pkg.to_path_buf());
    }
    for entry in std::fs::read_dir(pkg).ok()?.flatten() {
        let sub = entry.path();
        if sub.is_dir() && dir_has_uffs(&sub) {
            return Some(sub);
        }
    }
    None
}

/// Whether `dir` contains the UFFS CLI binary (`uffs.exe` on Windows; the bare
/// `uffs` name is accepted too so the logic is unit-testable off Windows).
fn dir_has_uffs(dir: &Path) -> bool {
    dir.join("uffs.exe").exists() || dir.join("uffs").exists()
}

/// The `WinGet\Packages` base directories to scan (user- and machine-scope).
/// Windows-only; empty elsewhere so [`discover`] is a no-op off Windows.
#[cfg(windows)]
fn winget_packages_bases() -> Vec<PathBuf> {
    let mut bases = Vec::new();
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        bases.push(PathBuf::from(local).join(r"Microsoft\WinGet\Packages"));
    }
    if let Ok(program_files) = std::env::var("ProgramFiles") {
        bases.push(PathBuf::from(program_files).join(r"WinGet\Packages"));
    }
    bases
}

/// Off Windows there is no `WinGet`, so there is nothing to scan.
#[cfg(not(windows))]
const fn winget_packages_bases() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::{
        dir_has_uffs, find_dir_with_uffs, is_uffs_package_folder, roots_under_packages_base,
    };

    #[test]
    fn recognizes_the_uffs_package_folder() {
        assert!(is_uffs_package_folder(
            "SkyLLC.UFFS_Microsoft.Winget.Source_8wekyb3d8bbwe"
        ));
        assert!(
            is_uffs_package_folder("skyllc.uffs_abc"),
            "case-insensitive"
        );
        // No trailing underscore → a different package with a shared prefix.
        assert!(!is_uffs_package_folder("SkyLLC.UFFSomething"));
        assert!(!is_uffs_package_folder("Other.Package_hash"));
        assert!(!is_uffs_package_folder("SkyLLC.UFFS"));
    }

    #[test]
    fn finds_the_root_holding_uffs_one_level_down() {
        // Mimic …\Packages\SkyLLC.UFFS_hash\uffs-windows-x64\uffs(.exe).
        let base = tempfile::tempdir().expect("tempdir");
        let pkg = base.path().join("SkyLLC.UFFS_hash");
        let inner = pkg.join("uffs-windows-x64");
        std::fs::create_dir_all(&inner).expect("mkdirs");
        std::fs::write(inner.join("uffs"), b"bin").expect("write uffs");
        // A sibling non-UFFS package folder must be ignored.
        std::fs::create_dir_all(base.path().join("Other.Pkg_x")).expect("mkdir other");

        assert!(dir_has_uffs(&inner));
        assert_eq!(find_dir_with_uffs(&pkg).as_deref(), Some(inner.as_path()));

        let roots = roots_under_packages_base(base.path());
        assert_eq!(roots, vec![inner], "only the UFFS package's inner root");
    }

    #[test]
    fn missing_base_yields_nothing() {
        let roots = roots_under_packages_base(std::path::Path::new("/nonexistent/winget/packages"));
        assert!(roots.is_empty());
    }
}
