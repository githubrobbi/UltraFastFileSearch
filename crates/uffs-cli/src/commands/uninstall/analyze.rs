// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Impure glue for the `uffs --uninstall` analysis (tasks U-10/U-12): turn the
//! reused Phase-A [`DetectionReport`] into resolution [`Candidate`]s, and build
//! the OS executable search-dir list the pure ordering consumes.
//!
//! Side effects are confined to reading the environment (`current_exe`, `PATH`,
//! `current_dir`, `SystemRoot`); nothing here mutates the system.

use std::path::{Path, PathBuf};

use super::resolve_order::Candidate;
use crate::commands::update::model::{BinaryInfo, Channel, DetectionReport, InstallRoot};

/// Binary stems beyond the core `KNOWN_BINARIES` that an install root may hold:
/// retired names, optional members, and the workspace dev/diagnostic tooling.
/// None are managed by `--update`, but a from-source / `cargo install` build
/// drops them next to the core set, so uninstall sweeps any that exist
/// (idempotent — absent ones are skipped).
pub(crate) const EXTRA_BINARY_STEMS: &[&str] = &[
    // Retired / optional names.
    "uffs-tui",      // optional member (moved to uffs-products)
    "uffs-gui",      // optional member (moved to uffs-products)
    "uffs-daemon",   // retired -> uffsd
    "uffs-mcp",      // retired -> uffsmcp
    "uffs-mcp-http", // retired -> uffsmcp (HTTP gateway)
    "uffs_tui",      // ancient underscore naming
    "uffs_gui",      // ancient underscore naming
    "uffs_mft",      // ancient underscore naming
    // Dev / diagnostic / tooling binaries (workspace bin targets).
    "uffs-bench",
    "uffs-ci-pipeline",
    "uffs-analyze-diff",
    "uffs-analyze-mft-parents",
    "uffs-compare-raw-mft",
    "uffs-compare-scan-parity",
    "uffs-cross-check-mft-reference",
    "uffs-dump-mft-extents",
    "uffs-dump-mft-records",
    "uffs-inspect-mft-record-flow",
    "uffs-scan-mft-magic",
    "uffs-verify-iocp-capture",
    "uffs-manifest-audit",
    "uffs-gen-hooks",
    "uffs-gen-workflow",
    // Retired un-prefixed tool names (pre-rename releases up to 0.6.18 shipped
    // these; installed copies must stay detectable by uninstall + the deep
    // sweep, exactly like the other retired names above).
    "analyze-diff",
    "analyze-mft-parents",
    "compare-raw-mft",
    "compare-scan-parity",
    "cross-check-mft-reference",
    "dump-mft-extents",
    "dump-mft-records",
    "gen-hooks",
    "gen-workflow",
    "inspect-mft-record-flow",
    "manifest-audit",
    "scan-mft-magic",
    "verify-iocp-capture",
];

/// Add any [`EXTRA_BINARY_STEMS`] that actually exist in an unmanaged /
/// dev-build root to that root's binary list, so uninstall sweeps retired and
/// optional names alongside the current set. `WinGet` roots are left untouched
/// (managed externally). Read-only stat; mutates only the in-memory report.
pub(crate) fn augment_with_extra_binaries(report: &mut DetectionReport) {
    for root in &mut report.roots {
        if matches!(root.channel, Channel::WinGet) {
            continue;
        }
        for stem in EXTRA_BINARY_STEMS {
            if root.binaries.iter().any(|binary| binary.name == *stem) {
                continue;
            }
            if root.dir.join(extra_exe_name(stem)).is_file() {
                root.binaries.push(BinaryInfo {
                    name: (*stem).to_owned(),
                    version: None,
                });
            }
        }
    }
}

/// The on-disk file name for a stem (`uffs-tui` -> `uffs-tui.exe` on Windows).
fn extra_exe_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_owned()
    }
}

/// Scan `PATH` and the standard binary directories for UFFS family binaries and
/// add any directory holding one as an install root, so copies that are neither
/// running nor the invoking exe are still found and removed. Stat-only
/// (`which`-style) — never a filesystem walk. Cross-platform: on Windows it
/// complements the live-drive deep sweep; off Windows (where UFFS cannot index
/// the live filesystem) it is the primary way we find off-anchor copies.
pub(crate) fn augment_with_path_locations(report: &mut DetectionReport) {
    add_roots_for_dirs(report, &candidate_bin_dirs());
}

/// Add each directory in `dirs` that holds a family binary as a root, skipping
/// any already present (deduplicated by canonical path). The classification
/// (channel / scope) reuses the primary detection's logic, so a `WinGet` copy
/// is still delegated and a machine-scope copy is still flagged for elevation.
fn add_roots_for_dirs(report: &mut DetectionReport, dirs: &[PathBuf]) {
    let mut seen: Vec<PathBuf> = report.roots.iter().map(|root| root.dir.clone()).collect();
    for dir in dirs {
        let key = crate::commands::update::strip_verbatim_prefix(
            std::fs::canonicalize(dir).unwrap_or_else(|_| dir.clone()),
        );
        if seen.iter().any(|existing| existing == &key) {
            continue;
        }
        let binaries = crate::commands::update::binaries::enumerate(&key);
        if binaries.is_empty() {
            continue;
        }
        let (channel, scope) = crate::commands::update::channel::classify(&key);
        report.roots.push(InstallRoot {
            dir: key.clone(),
            channel,
            scope,
            anchored_by: Vec::new(),
            binaries,
        });
        seen.push(key);
    }
}

/// `PATH` entries plus the standard binary directories, in scan order. Each is
/// stat-checked for family binaries; non-existent ones are simply skipped.
fn candidate_bin_dirs() -> Vec<PathBuf> {
    let mut dirs = path_entries();
    if let Some(home) = home_dir() {
        dirs.push(home.join("bin"));
        dirs.push(home.join(".local").join("bin"));
        dirs.push(home.join(".cargo").join("bin"));
    }
    #[cfg(not(windows))]
    dirs.extend([
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/opt/homebrew/bin"),
    ]);
    dirs
}

/// The user's home directory (`HOME`, or `USERPROFILE` on Windows).
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Flatten the detection report's roots × binaries into resolution candidates
/// (one per discovered binary copy).
pub(crate) fn build_candidates(report: &DetectionReport) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for root in &report.roots {
        for binary in &root.binaries {
            candidates.push(Candidate {
                stem: binary.name.clone(),
                version: binary.version.clone(),
                channel: root.channel,
                scope: root.scope,
                dir: root.dir.clone(),
            });
        }
    }
    candidates
}

/// The ordered list of directories the OS searches for an unqualified
/// executable (design §5.1): the running image's dir, the system dirs
/// (Windows), the current dir, then PATH entries in order. On non-Windows this
/// is the current-exe dir, the current dir, then PATH.
pub(crate) fn search_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        dirs.push(crate::commands::update::strip_verbatim_prefix(
            parent.to_path_buf(),
        ));
    }
    #[cfg(windows)]
    {
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            let root = PathBuf::from(system_root);
            dirs.push(root.join("System32"));
            dirs.push(root);
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd);
    }
    if let Some(path) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&path) {
            dirs.push(entry);
        }
    }
    dirs
}

/// The directories on the current `PATH`, in order. Used to offer removal of a
/// PATH entry that points at a UFFS root.
pub(crate) fn path_entries() -> Vec<PathBuf> {
    std::env::var_os("PATH").map_or_else(Vec::new, |path| std::env::split_paths(&path).collect())
}

/// The `PATH` directories that are actually *safe* to drop on uninstall: an
/// unmanaged / dev-build UFFS root that is **dedicated** to UFFS (contains only
/// `uffs*` files). Shared bin dirs (`~/bin`, `~/.local/bin`, …) are
/// deliberately never returned: UFFS installs into pre-existing
/// OS/shell-default locations and never adds a PATH entry of its own, so it
/// must not suggest removing one — that directory belongs to the user's whole
/// toolchain, not to us.
pub(crate) fn removable_path_dirs(
    report: &DetectionReport,
    path_entries: &[PathBuf],
) -> Vec<PathBuf> {
    report
        .roots
        .iter()
        .filter(|root| !matches!(root.channel, Channel::WinGet) && !root.binaries.is_empty())
        .map(|root| root.dir.clone())
        .filter(|dir| {
            path_entries.iter().any(|entry| {
                entry
                    .as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&dir.as_os_str().to_string_lossy())
            })
        })
        .filter(|dir| is_uffs_exclusive_dir(dir))
        .collect()
}

/// Whether `dir` is a dedicated UFFS directory — every entry's file name starts
/// with `uffs` (case-insensitive). A directory holding any non-UFFS file (a
/// shared `~/bin`) is not exclusive, and an unreadable or empty one is treated
/// as not exclusive (we never claim a PATH entry we cannot prove is ours).
fn is_uffs_exclusive_dir(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut saw_entry = false;
    for entry in entries.flatten() {
        saw_entry = true;
        if !entry
            .file_name()
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with("uffs")
        {
            return false;
        }
    }
    saw_entry
}

#[cfg(test)]
mod tests {
    use super::augment_with_extra_binaries;
    use crate::commands::update::model::{Channel, DetectionReport, InstallRoot, Scope};

    #[test]
    fn extra_binaries_present_on_disk_are_added_absent_ones_are_not() {
        let dir = std::env::temp_dir().join(format!(
            "uffs-extra-bin-test-{}-{}",
            std::process::id(),
            "retired"
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // A retired name that exists on disk (use the platform file name).
        let present = if cfg!(windows) {
            "uffs-daemon.exe"
        } else {
            "uffs-daemon"
        };
        std::fs::write(dir.join(present), b"x").unwrap();

        let mut report = DetectionReport {
            roots: vec![InstallRoot {
                dir: dir.clone(),
                channel: Channel::Unmanaged,
                scope: Scope::User,
                anchored_by: Vec::new(),
                binaries: Vec::new(),
            }],
            running: Vec::new(),
        };
        augment_with_extra_binaries(&mut report);

        let names: Vec<&str> = report
            .roots
            .first()
            .expect("a root")
            .binaries
            .iter()
            .map(|binary| binary.name.as_str())
            .collect();
        assert!(
            names.contains(&"uffs-daemon"),
            "a retired name present on disk must be swept: {names:?}"
        );
        assert!(
            !names.contains(&"uffs-tui"),
            "an absent retired name must NOT be added"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
    }

    #[test]
    fn shared_bin_dir_is_not_path_removable_but_a_dedicated_one_is() {
        use crate::commands::update::model::BinaryInfo;

        let pid = std::process::id();
        // A shared bin dir: a uffs binary living next to a foreign tool.
        let shared = std::env::temp_dir().join(format!("uffs-path-shared-{pid}"));
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::write(shared.join("uffs"), b"x").unwrap();
        std::fs::write(shared.join("git"), b"x").unwrap(); // a non-UFFS tool
        // A dedicated dir: only uffs* files.
        let dedicated = std::env::temp_dir().join(format!("uffs-path-dedicated-{pid}"));
        std::fs::create_dir_all(&dedicated).unwrap();
        std::fs::write(dedicated.join("uffs"), b"x").unwrap();
        std::fs::write(dedicated.join("uffsd"), b"x").unwrap();

        let bin = |dir: &std::path::Path| InstallRoot {
            dir: dir.to_path_buf(),
            channel: Channel::Unmanaged,
            scope: Scope::User,
            anchored_by: Vec::new(),
            binaries: vec![BinaryInfo {
                name: "uffs".to_owned(),
                version: None,
            }],
        };
        let report = DetectionReport {
            roots: vec![bin(&shared), bin(&dedicated)],
            running: Vec::new(),
        };
        let on_path = vec![shared.clone(), dedicated.clone()];
        let removable = super::removable_path_dirs(&report, &on_path);

        assert!(
            !removable.contains(&shared),
            "a shared bin dir (other tools present) must NOT be offered for PATH removal"
        );
        assert!(
            removable.contains(&dedicated),
            "a dedicated uffs-only dir IS safe to offer for PATH removal"
        );

        std::fs::remove_dir_all(&shared).expect("cleanup shared");
        std::fs::remove_dir_all(&dedicated).expect("cleanup dedicated");
    }

    #[test]
    fn path_scan_adds_a_dir_with_a_family_binary_once() {
        let dir = std::env::temp_dir().join(format!("uffs-pathscan-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let name = if cfg!(windows) { "uffs.exe" } else { "uffs" };
        std::fs::write(dir.join(name), b"x").unwrap();

        let mut report = DetectionReport {
            roots: Vec::new(),
            running: Vec::new(),
        };
        // Pass the dir twice: it must still be added exactly once (deduped).
        super::add_roots_for_dirs(&mut report, &[dir.clone(), dir.clone()]);

        let key = std::fs::canonicalize(&dir).unwrap();
        let matching: Vec<_> = report.roots.iter().filter(|root| root.dir == key).collect();
        assert_eq!(
            matching.len(),
            1,
            "the dir is added once: {:?}",
            report.roots
        );
        assert!(
            matching
                .first()
                .expect("one matching root")
                .binaries
                .iter()
                .any(|bin| bin.name == "uffs"),
            "the discovered family binary is recorded"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn winget_roots_are_left_untouched() {
        let mut report = DetectionReport {
            roots: vec![InstallRoot {
                dir: std::env::temp_dir(),
                channel: Channel::WinGet,
                scope: Scope::User,
                anchored_by: Vec::new(),
                binaries: Vec::new(),
            }],
            running: Vec::new(),
        };
        augment_with_extra_binaries(&mut report);
        assert!(
            report.roots.first().expect("a root").binaries.is_empty(),
            "winget roots must not be augmented"
        );
    }
}
