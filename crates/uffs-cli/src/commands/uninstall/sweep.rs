// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Deep sweep for `uffs --uninstall` (task U-70/U-71): use UFFS's own search to
//! find stray family files anywhere on the indexed drives, beyond the known
//! install roots. Strays are versioned and removed only under a **separate,
//! explicit second confirmation** (a `uffs.exe` under `Downloads` might be the
//! user's own copy, so they never ride the main plan's single yes — design §8).
//!
//! The dedup logic is pure + unit-tested against a fake
//! [`crate::commands::uninstall::sweep::Search`]; the live backend
//! ([`crate::commands::uninstall::sweep::DaemonSearch`]) is best-effort
//! (no daemon ⇒ no hits, never a hard failure).

use core::time::Duration;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;

/// Gate for the `[sweep]` diagnostic lines: set from `-v` once at the start of
/// an uninstall run, read by [`dbg_line`]. A relaxed static rather than a
/// parameter so the sweep call chain (and its tests) stay signature-stable.
static SWEEP_VERBOSE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Enable/disable the `[sweep]` diagnostics for this run (`-v` / `--verbose`).
pub(crate) fn set_verbose(verbose: bool) {
    SWEEP_VERBOSE.store(verbose, core::sync::atomic::Ordering::Relaxed);
}

/// Deep-sweep diagnostics (candidate counts per pattern, phase timings, probe
/// timeouts). Prints a `[sweep]` line to stdout, only under `-v`.
#[expect(clippy::print_stdout, reason = "verbose-gated deep-sweep diagnostics")]
pub(crate) fn dbg_line(msg: &str) {
    if SWEEP_VERBOSE.load(core::sync::atomic::Ordering::Relaxed) {
        println!("  [sweep] {msg}");
    }
}

/// Blank separator printed before the first `[sweep]` diagnostic block, so the
/// diagnostics never run back-to-back into preceding output. `-v` only.
#[expect(clippy::print_stdout, reason = "verbose-gated deep-sweep diagnostics")]
pub(crate) fn dbg_gap() {
    if SWEEP_VERBOSE.load(core::sync::atomic::Ordering::Relaxed) {
        println!();
    }
}

/// UFFS cache/cursor data-file patterns the sweep searches for. The executable
/// patterns are derived from the shared family set (see [`family_stems`]).
const CACHE_PATTERNS: &[&str] = &["*_compact.uffs", "*_usn.cursor"];

/// Every UFFS family executable stem — the core managed set plus the
/// retired/optional/dev-tooling names. Single source of truth shared with the
/// install-dir sweep ([`super::analyze::EXTRA_BINARY_STEMS`]) so adding a
/// binary in one place updates both the install-dir removal and the deep sweep.
fn family_stems() -> impl Iterator<Item = &'static str> {
    crate::commands::update::binaries::KNOWN_BINARIES
        .iter()
        .copied()
        .chain(super::analyze::EXTRA_BINARY_STEMS.iter().copied())
}

/// A search backend, injected so the dedup logic is testable without a daemon.
pub(crate) trait Search {
    /// Absolute paths matching `pattern` (best-effort; empty on any failure).
    fn find(&mut self, pattern: &str) -> Result<Vec<PathBuf>>;
}

/// A stray family file found outside the known install roots, with its parsed
/// `--version` for binaries (data files like caches carry `None`).
#[derive(Debug, Clone)]
pub(crate) struct StrayHit {
    /// Absolute path of the stray file.
    pub(crate) path: PathBuf,
    /// Parsed `--version`, or `None` for a data file or an unreadable version.
    pub(crate) version: Option<String>,
}

/// Hard cap on a single `--version` probe. A stray that hangs (waits on stdin,
/// starts a service, is a half-written build artifact) must never stall the
/// whole sweep — it just goes unversioned. A healthy console binary returns in
/// well under this.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Attach a version to each stray: probe `--version` on the executable hits and
/// leave UFFS data files (`*_compact.uffs`, `*_usn.cursor`) unversioned. No
/// daemon needed — each binary is run directly.
///
/// Probes run **in parallel** (a small scoped-thread pool) with a **per-probe
/// timeout** — a dev box can hold hundreds of family `*.exe` under `target/`,
/// and probing them one at a time (or letting one hang) is what made the sweep
/// take minutes.
pub(crate) fn version_strays(paths: &[PathBuf]) -> Vec<StrayHit> {
    use core::sync::atomic::{AtomicUsize, Ordering};

    if paths.is_empty() {
        return Vec::new();
    }
    // Probes are subprocess spawns (I/O bound), so a small fixed pool of workers
    // pulling from a shared cursor beats sequential (minutes on a dev box with
    // hundreds of `target/` binaries) without spawning one thread per path.
    let worker_count = std::thread::available_parallelism()
        .map_or(4, core::num::NonZeroUsize::get)
        .min(paths.len());
    let next = AtomicUsize::new(0);
    let timed_out = AtomicUsize::new(0);
    let legacy_gui = AtomicUsize::new(0);

    let mut strays: Vec<StrayHit> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..worker_count)
            .map(|_| {
                scope.spawn(|| {
                    let mut local: Vec<StrayHit> = Vec::new();
                    loop {
                        let idx = next.fetch_add(1, Ordering::Relaxed);
                        let Some(path) = paths.get(idx) else { break };
                        // The legacy C++ `uffs.exe` is a Windows GUI app — a
                        // different product, not our console CLI. Drop it:
                        // probing it pops a window, is slow, and it is not ours.
                        if is_legacy_gui_uffs(path) {
                            legacy_gui.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let version = if is_probeable_binary(path) {
                            match probe_version_bounded(path) {
                                ProbeOutcome::Version(version) => Some(version),
                                ProbeOutcome::TimedOut => {
                                    timed_out.fetch_add(1, Ordering::Relaxed);
                                    None
                                }
                                ProbeOutcome::None => None,
                            }
                        } else {
                            None
                        };
                        local.push(StrayHit {
                            path: path.clone(),
                            version,
                        });
                    }
                    local
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap_or_default())
            .collect()
    });
    // Worker order is non-deterministic; restore the sorted order for output.
    strays.sort_by(|left, right| left.path.cmp(&right.path));
    let timed_out_count = timed_out.load(Ordering::Relaxed);
    if timed_out_count > 0 {
        dbg_line(&format!(
            "{timed_out_count} probe(s) hit the {PROBE_TIMEOUT:?} timeout and were left unversioned"
        ));
    }
    let legacy_gui_count = legacy_gui.load(Ordering::Relaxed);
    if legacy_gui_count > 0 {
        dbg_line(&format!(
            "{legacy_gui_count} legacy GUI `uffs.exe` copy/copies excluded (the predecessor C++ product, a different app — not removed)"
        ));
    }
    strays
}

/// The result of a bounded `--version` probe.
enum ProbeOutcome {
    /// A version string was parsed from the binary's output.
    Version(String),
    /// The binary did not exit within [`PROBE_TIMEOUT`] and was killed.
    TimedOut,
    /// The binary ran but produced no parseable version (or failed to spawn).
    None,
}

/// Probe `path --version` with a hard timeout, killing a process that overruns.
/// `--version` output is tiny, so reading it after exit cannot deadlock on a
/// full pipe. `stdin` is nulled so a binary that reads stdin can't block.
fn probe_version_bounded(path: &Path) -> ProbeOutcome {
    use std::process::Stdio;

    let Ok(mut child) = std::process::Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    else {
        return ProbeOutcome::None;
    };
    let deadline = Instant::now() + PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _kill = child.kill();
                    let _wait = child.wait();
                    return ProbeOutcome::TimedOut;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return ProbeOutcome::None,
        }
    }
    let Ok(output) = child.wait_with_output() else {
        return ProbeOutcome::None;
    };
    // AUDIT-OK(bytes): ASCII version-token extraction from a probed binary's
    // output. A lossy decode cannot fabricate a `MAJOR.MINOR.PATCH` token
    // (U+FFFD is not a digit), only fail to yield one -> "legacy" label.
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    if text.trim().is_empty() {
        // Some tools print `--version` to stderr; fall back to it.
        // AUDIT-OK(bytes): same ASCII-token argument as stdout above.
        text = String::from_utf8_lossy(&output.stderr).into_owned();
    }
    crate::commands::update::binaries::parse_version(&text)
        .map_or(ProbeOutcome::None, ProbeOutcome::Version)
}

/// `IMAGE_SUBSYSTEM_WINDOWS_GUI` — a windowed app with no console.
const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;

/// Whether `path` is the legacy C++ `uffs.exe`: named `uffs.exe` *and* built as
/// a Windows **GUI**-subsystem binary (our Rust CLI is a console app). Only
/// `uffs.exe` collides with the predecessor product — the other family names
/// are Rust-only, so they are never GUI-filtered.
fn is_legacy_gui_uffs(path: &Path) -> bool {
    let is_uffs_exe = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("uffs.exe"));
    is_uffs_exe && pe_subsystem(path) == Some(IMAGE_SUBSYSTEM_WINDOWS_GUI)
}

/// Read a PE image's Optional-Header `Subsystem` field (2 = GUI, 3 = console)
/// without running it — only the headers are read. `None` on any read/parse
/// failure or a non-PE file. The `Subsystem` field sits at offset 68 of the
/// Optional Header in both PE32 and PE32+.
fn pe_subsystem(path: &Path) -> Option<u16> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut file = std::fs::File::open(path).ok()?;
    let mut dos = [0_u8; 64];
    file.read_exact(&mut dos).ok()?;
    if &dos[0..2] != b"MZ" {
        return None;
    }
    // `e_lfanew` (offset to the PE header) lives at 0x3C in the DOS header.
    let pe_off = u64::from(u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]));
    let mut sig = [0_u8; 4];
    file.seek(SeekFrom::Start(pe_off)).ok()?;
    file.read_exact(&mut sig).ok()?;
    if &sig != b"PE\0\0" {
        return None;
    }
    // Optional Header starts after the 4-byte signature + 20-byte COFF header;
    // `Subsystem` is at +68 within it.
    file.seek(SeekFrom::Start(pe_off + 4 + 20 + 68)).ok()?;
    let mut subsystem = [0_u8; 2];
    file.read_exact(&mut subsystem).ok()?;
    Some(u16::from_le_bytes(subsystem))
}

/// Whether `path` names an executable we can run `--version` on, rather than a
/// UFFS data file (`*.uffs` cache / `*.cursor`) that has no version.
fn is_probeable_binary(path: &Path) -> bool {
    !path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("uffs") || ext.eq_ignore_ascii_case("cursor"))
}

/// Find stray family files across every pattern, dropping any hit already under
/// a directory the plan handles. Sorted + de-duplicated.
pub(crate) fn find_strays(search: &mut dyn Search, known_dirs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut strays: Vec<PathBuf> = Vec::new();
    let exe_patterns = family_stems().map(|stem| format!("{stem}.exe"));
    let patterns = exe_patterns.chain(CACHE_PATTERNS.iter().map(|pattern| (*pattern).to_owned()));
    for pattern in patterns {
        let hits = search.find(&pattern)?;
        let raw = hits.len();
        let mut kept = 0_usize;
        for hit in hits {
            if is_family_artifact(&hit) && !is_under_any(&hit, known_dirs) {
                kept += 1;
                strays.push(hit);
            }
        }
        if raw > 0 {
            dbg_line(&format!(
                "pattern {pattern:<22} raw={raw:<5} kept={kept} (after exact-name + known-dir filter)"
            ));
        }
    }
    strays.sort();
    strays.dedup();
    Ok(strays)
}

/// Whether `path`'s file name is *exactly* a UFFS family executable or cache
/// file we would actually remove — not a derived artifact that merely contains
/// a family name as a substring.
///
/// The daemon search matches `uffs.exe` as a *contains* query, so a raw sweep
/// also returns prefetch traces (`UFFS.EXE-1234.pf`), localized resources
/// (`uffs.exe.mui`), checksums (`uffs.exe.sha256`), build recipes
/// (`uffs.exe.recipe`), and NTFS alternate-data-stream entries
/// (`uffs.exe:com.dropbox.attrs`). None of those are ours to delete; this keeps
/// only an exact `*.exe` family binary or a `*_compact.uffs` / `*_usn.cursor`
/// cache file.
fn is_family_artifact(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|raw| raw.to_str()) else {
        return false;
    };
    // An alternate-data-stream entry (`file:stream`) is never a real file.
    if name.contains(':') {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    if lower.ends_with("_compact.uffs") || lower.ends_with("_usn.cursor") {
        return true;
    }
    let Some(stem) = lower.strip_suffix(".exe") else {
        return false;
    };
    family_stems().any(|family| family.eq_ignore_ascii_case(stem))
}

/// Whether `path` is `dir` or lives beneath it (case-insensitive, separator
/// aware so `/opt/uffs` does not spuriously match `/opt/uffs-other`).
fn is_under_any(path: &Path, dirs: &[PathBuf]) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    dirs.iter().any(|dir| {
        let base = dir.to_string_lossy().to_ascii_lowercase();
        lower == base
            || lower.starts_with(&format!("{base}/"))
            || lower.starts_with(&format!("{base}\\"))
    })
}

/// Live search backend over the resident daemon. Best-effort: no daemon, or any
/// RPC error, yields no hits rather than failing the uninstall.
pub(crate) struct DaemonSearch;

impl Search for DaemonSearch {
    fn find(&mut self, pattern: &str) -> Result<Vec<PathBuf>> {
        let Ok(mut client) = uffs_client::connect_sync::UffsClientSync::connect_raw() else {
            return Ok(Vec::new());
        };
        // `--columns path` forces single-column output so the daemon's path /
        // CSV blob fast paths yield clean one-path-per-line text rather than a
        // multi-column CSV blob (which has no JSON `path` field — the original
        // bug, where a real multi-hit Windows sweep returned a blob and the
        // JSON `"path"`-key walk found nothing).
        //
        // `--name-only` anchors the match to the **filename**: a bare `uffs.exe`
        // token is a full-path substring match, so it also returns files merely
        // living under a path that contains "uffs.exe" (e.g. an `…\uffs.exe.bak\`
        // dir). We only ever want files actually named like a family binary.
        let mut args = vec![
            pattern.to_owned(),
            "--files-only".to_owned(),
            "--name-only".to_owned(),
            "--columns".to_owned(),
            "path".to_owned(),
            "--limit".to_owned(),
            "5000".to_owned(),
        ];
        // For a concrete `stem.exe` pattern (no glob), pin the extension too so
        // the daemon drops `uffs.exe.mui` / prefetch `.pf` / ADS noise *before*
        // shipping rows back — measured 158 -> 46 hits for `uffs.exe` on a dev
        // box. Glob cache patterns (`*_compact.uffs`) already pin their own
        // extension, so they are left as-is.
        if !pattern.contains('*')
            && let Some(ext) = Path::new(pattern).extension().and_then(OsStr::to_str)
        {
            args.push("--ext".to_owned());
            args.push(ext.to_owned());
        }
        let Ok(response) = client.search_cli(&args) else {
            return Ok(Vec::new());
        };
        Ok(payload_paths(response.payload))
    }
}

/// Decode every payload variant the daemon may return into result paths. A
/// search response arrives as inline rows, a memory-mapped rows file, an inline
/// pre-formatted blob, or a memory-mapped blob — the daemon picks by size +
/// output shape — so reading only one shape (the old JSON `"path"` walk, which
/// saw just the inline-rows case) silently dropped every blob/shmem result.
fn payload_paths(payload: uffs_client::protocol::response::SearchPayload) -> Vec<PathBuf> {
    use uffs_client::protocol::response::SearchPayload as Payload;
    match payload {
        Payload::InlineRows(rows) => rows
            .into_iter()
            .map(|row| PathBuf::from(row.path))
            .collect(),
        Payload::ShmemRows { path, .. } => {
            uffs_client::shmem::read_search_results(Path::new(&path))
                .map(|resp| payload_paths(resp.payload))
                .unwrap_or_default()
        }
        Payload::InlineBlob(blob) => blob_lines_to_paths(&blob),
        Payload::ShmemBlob(path) => {
            let mut buf: Vec<u8> = Vec::new();
            if uffs_client::shmem::stream_paths_blob_into(Path::new(&path), &mut buf).is_ok() {
                // Strict parse: these paths feed the EXTRA delete list, so a
                // corrupt blob is rejected outright rather than risking a
                // lossy-mangled path. The daemon always emits valid UTF-8.
                core::str::from_utf8(&buf).map_or_else(|_| Vec::new(), blob_lines_to_paths)
            } else {
                Vec::new()
            }
        }
        Payload::Empty => Vec::new(),
    }
}

/// Parse a single-column (`--columns path`) text blob into paths: one per
/// non-empty line, dropping a leading `path`/`Path` header line and any
/// surrounding CSV quotes.
fn blob_lines_to_paths(blob: &str) -> Vec<PathBuf> {
    blob.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.trim_matches('"'))
        .filter(|line| !line.eq_ignore_ascii_case("path"))
        .map(PathBuf::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use anyhow::Result;

    use super::{Search, blob_lines_to_paths, find_strays, is_family_artifact, version_strays};

    #[test]
    fn family_artifact_filter_keeps_binaries_drops_noise() {
        // Real removable family files.
        assert!(is_family_artifact(Path::new(r"C:\x\uffs.exe")));
        assert!(is_family_artifact(Path::new(r"C:\x\uffsd.exe")));
        assert!(is_family_artifact(Path::new(r"C:\x\uffs-broker.exe")));
        assert!(is_family_artifact(Path::new(r"C:\x\uffs-tui.exe")));
        // Dev/diagnostic tooling is part of the family set now.
        assert!(is_family_artifact(Path::new(
            r"C:\x\uffs-dump-mft-records.exe"
        )));
        assert!(is_family_artifact(Path::new(r"C:\x\uffs-ci-pipeline.exe")));
        assert!(is_family_artifact(Path::new(r"C:\x\drive_c_compact.uffs")));
        assert!(is_family_artifact(Path::new(r"C:\x\journal_usn.cursor")));
        // Noise the daemon's substring search also returns — must be dropped.
        assert!(!is_family_artifact(Path::new(
            r"C:\Windows\Prefetch\UFFS.EXE-1867467A.pf"
        )));
        assert!(!is_family_artifact(Path::new(r"C:\x\uffs.exe.mui")));
        assert!(!is_family_artifact(Path::new(r"C:\x\uffs.exe.sha256")));
        assert!(!is_family_artifact(Path::new(r"C:\x\uffs.exe.recipe")));
        assert!(!is_family_artifact(Path::new(
            r"C:\x\uffs.exe:com.dropbox.attrs"
        )));
        // A foreign exe that merely contains "uffs.exe" as a substring.
        assert!(!is_family_artifact(Path::new(r"C:\x\notuffs.exe")));
    }

    /// Returns the same hits for every pattern (the dedup must collapse them).
    struct FakeSearch(Vec<PathBuf>);

    impl Search for FakeSearch {
        fn find(&mut self, _pattern: &str) -> Result<Vec<PathBuf>> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn hits_under_known_dirs_are_filtered_and_deduped() {
        let mut search = FakeSearch(vec![
            PathBuf::from("/opt/uffs/uffs"),
            PathBuf::from("/home/me/Downloads/uffs.exe"),
        ]);
        let known = [PathBuf::from("/opt/uffs")];
        let strays = find_strays(&mut search, &known).unwrap();
        // The /opt/uffs hit is already planned; only the Downloads stray remains,
        // de-duplicated despite being returned once per pattern.
        assert_eq!(strays.len(), 1);
        assert_eq!(
            strays.first().expect("a stray"),
            &PathBuf::from("/home/me/Downloads/uffs.exe")
        );
    }

    #[test]
    fn sibling_prefix_is_not_treated_as_under() {
        let mut search = FakeSearch(vec![PathBuf::from("/opt/uffs-other/uffs.exe")]);
        let known = [PathBuf::from("/opt/uffs")];
        let strays = find_strays(&mut search, &known).unwrap();
        assert_eq!(strays.len(), 1, "sibling dir must not be filtered");
    }

    #[test]
    fn data_files_are_not_probed_for_a_version() {
        // Cache/cursor data files have no version and must not be executed; a
        // (nonexistent) binary path probes to None rather than panicking.
        let strays = version_strays(&[
            PathBuf::from("/x/drive_c_compact.uffs"),
            PathBuf::from("/x/journal_usn.cursor"),
            PathBuf::from("/x/definitely-not-here/uffs"),
        ]);
        assert_eq!(strays.len(), 3);
        assert!(
            strays.iter().all(|stray| stray.version.is_none()),
            "data files (and an absent binary) carry no version"
        );
    }

    #[test]
    fn blob_lines_drop_header_and_quotes() {
        // A single-column (`--columns path`) CSV blob: header line, quoted
        // Windows paths, a blank trailing line.
        let blob = "\"Path\"\r\n\"C:\\Users\\me\\bin\\uffs.exe\"\r\n\"D:\\tools\\uffsd.exe\"\r\n";
        let paths = blob_lines_to_paths(blob);
        assert_eq!(paths, vec![
            PathBuf::from(r"C:\Users\me\bin\uffs.exe"),
            PathBuf::from(r"D:\tools\uffsd.exe"),
        ]);
        // A bare path-per-line blob (no header, no quotes) also works.
        let plain = "/opt/uffs/uffs\n/home/me/Downloads/uffs\n";
        assert_eq!(blob_lines_to_paths(plain).len(), 2);
    }
}
