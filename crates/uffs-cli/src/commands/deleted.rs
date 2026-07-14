// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `uffs --deleted --mft-file <PATH>` — forensic tombstone read.
//!
//! When NTFS deletes a file it clears the record's in-use flag but leaves the
//! record bytes (name, parent, timestamps) intact until the MFT slot is
//! reallocated. This command reads an MFT capture with forensic parsing,
//! surfaces the not-in-use records as **recently-deleted tombstones**, and
//! reconstructs each path by walking the (still-present) parent chain.
//!
//! No baseline needed — this is the "what did I just delete, maybe still
//! recoverable" path (Mechanism 2 in
//! `docs/architecture/delete-visibility-snapshot-diff.md`). Honest limits:
//! best-effort (you only see deletes whose slot has not been recycled), no
//! true *deletion* time (the timestamp is the file's own last-write), and a
//! path is unreliable if a parent directory's slot was itself reused.
//!
//! Memory: the scan collects only the *deleted* records (a small fraction of
//! the MFT) and resolves each parent **on demand** from the raw buffer with a
//! small cache — it never materializes all N records, so peak memory is ~the
//! raw MFT plus the deleted subset, not a multiple of it.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use uffs_mft::parse::{ParseOptions, ParseResult, apply_fixup, parse_record_forensic};
use uffs_mft::platform::DriveLetter;
use uffs_mft::raw::{LoadRawOptions, RawMftData, load_raw_mft};

use crate::args::parse_drive_letter;
use crate::commands::output::format_filetime_local;

/// NTFS reserves File Record Segment 5 for the volume root directory; every
/// path walk terminates here.
const ROOT_FRS: u64 = 5;

/// Parsed `uffs --deleted` invocation. The source is either an offline capture
/// (`--mft-file`) or the live drive (`--drive`, Windows).
#[derive(Debug)]
struct DeletedArgs {
    /// Offline MFT capture to scan (raw `$MFT` dump). Mutually exclusive with a
    /// live-drive scan; when both are given the file wins and `drive` only
    /// labels paths.
    mft_file: Option<PathBuf>,
    /// Drive letter: the live source (Windows) when `mft_file` is absent, or
    /// just the path label otherwise. Defaults to `X` for labelling.
    drive: Option<DriveLetter>,
    /// Max tombstones to print (0 = all).
    limit: u32,
    /// Emit JSON instead of the human table.
    json: bool,
}

/// A deleted record captured during the scan, before path resolution.
struct DeletedEntry {
    /// Parent directory FRS (start of the path walk).
    parent: u64,
    /// The deleted file's own name (leaf).
    name: String,
    /// Logical file size in bytes.
    size: u64,
    /// The file's own last-write time (raw FILETIME) — NOT the deletion time.
    modified: i64,
    /// Whether the record is a directory.
    is_dir: bool,
}

/// One reconstructed deleted-file tombstone (path-resolved, ready to render).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tombstone {
    /// Reconstructed full path (best-effort — see module docs).
    path: String,
    /// Logical file size in bytes.
    size: u64,
    /// The file's own last-write time (raw FILETIME).
    modified: i64,
    /// Whether the record is a directory.
    is_dir: bool,
    /// `true` when the parent chain resolved all the way to the volume root;
    /// `false` when a parent FRS was missing (path is partial / prefixed `…`).
    path_complete: bool,
}

/// Run `uffs --deleted --mft-file <PATH> [--drive D] [--limit N] [--json]`.
///
/// # Errors
///
/// Returns an error on bad arguments or when the MFT capture cannot be read.
pub(crate) fn run_deleted(args: &[String]) -> Result<()> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        crate::args::print_deleted_help();
        return Ok(());
    }

    let parsed = parse_deleted_args(args)?;
    let drive = parsed.drive.unwrap_or(DriveLetter::X);

    // Source the raw MFT from either an offline capture or the live drive.
    let raw = match &parsed.mft_file {
        Some(path) => {
            let options = LoadRawOptions {
                header_only: false,
                volume_letter: Some(drive),
                forensic: true,
            };
            load_raw_mft(path, &options)
                .with_context(|| format!("failed to read MFT capture '{}'", path.display()))?
        }
        None => read_live_raw(drive)
            .with_context(|| format!("failed to read the live MFT of drive {drive}"))?,
    };

    // Pass 1: forensic-parse every slot but KEEP only the deleted records.
    // The default parser drops not-in-use records; forensic mode retains them.
    // One reusable fixup buffer avoids a per-record allocation.
    let mut deleted: Vec<DeletedEntry> = Vec::new();
    let mut fixup_buf: Vec<u8> = Vec::new();
    for (frs, data) in raw.iter_records() {
        fixup_buf.clear();
        fixup_buf.extend_from_slice(data);
        let fixup_ok = apply_fixup(&mut fixup_buf);
        if let ParseResult::Base(record) =
            parse_record_forensic(&fixup_buf, frs, ParseOptions::FORENSIC, !fixup_ok)
            && record.is_deleted
        {
            deleted.push(DeletedEntry {
                parent: record.parent_frs.raw(),
                name: record.name,
                size: record.size,
                modified: record.std_info.modified,
                is_dir: record.is_directory,
            });
        }
    }

    let total = deleted.len();
    let limit = uffs_mft::u32_as_usize(parsed.limit);
    let truncated = limit > 0 && total > limit;
    let take = if truncated { limit } else { total };

    // Pass 2: resolve each kept tombstone's path by walking parents on demand
    // from the raw buffer, memoizing shared ancestors.
    let mut parent_cache: HashMap<u64, Option<(String, u64)>> = HashMap::new();
    let mut lookup_buf: Vec<u8> = Vec::new();
    let mut tombstones: Vec<Tombstone> = Vec::with_capacity(take);
    for entry in deleted.iter().take(take) {
        let (path, complete) = resolve_path(&entry.name, entry.parent, drive, |frs| {
            lookup_parent(&raw, frs, &mut parent_cache, &mut lookup_buf)
        });
        tombstones.push(Tombstone {
            path,
            size: entry.size,
            modified: entry.modified,
            is_dir: entry.is_dir,
            path_complete: complete,
        });
    }

    if parsed.json {
        print_json(&tombstones, total, truncated);
    } else {
        print_human(&tombstones, total, truncated, drive);
    }
    Ok(())
}

/// Resolve a parent record's `(name, its-parent FRS)` from the raw MFT,
/// memoizing the result (including a `None` miss) so shared ancestors are
/// parsed once.
fn lookup_parent(
    raw: &RawMftData,
    frs: u64,
    cache: &mut HashMap<u64, Option<(String, u64)>>,
    buf: &mut Vec<u8>,
) -> Option<(String, u64)> {
    if let Some(cached) = cache.get(&frs) {
        return cached.clone();
    }
    let resolved = raw.get_record(frs).and_then(|data| {
        buf.clear();
        buf.extend_from_slice(data);
        let fixup_ok = apply_fixup(buf);
        if let ParseResult::Base(record) =
            parse_record_forensic(buf, frs, ParseOptions::FORENSIC, !fixup_ok)
        {
            Some((record.name, record.parent_frs.raw()))
        } else {
            None
        }
    });
    cache.insert(frs, resolved.clone());
    resolved
}

/// Parse the `--deleted` argument vector.
///
/// A source is required: `--mft-file <PATH>` (offline) or `--drive <D>` (live,
/// Windows). `--limit`, `--json` optional.
fn parse_deleted_args(args: &[String]) -> Result<DeletedArgs> {
    let mut mft_file: Option<PathBuf> = None;
    let mut drive: Option<DriveLetter> = None;
    let mut limit: u32 = 0;
    let mut json = false;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--mft-file" => {
                let val = iter
                    .next()
                    .with_context(|| "`--mft-file` requires a path")?;
                mft_file = Some(PathBuf::from(val));
            }
            "--drive" | "-d" => {
                let val = iter
                    .next()
                    .with_context(|| "`--drive` requires a drive letter (e.g. C)")?;
                drive = Some(parse_drive_letter(val)?);
            }
            "--limit" | "-n" => {
                let val = iter.next().with_context(|| "`--limit` requires a number")?;
                limit = val
                    .parse::<u32>()
                    .with_context(|| format!("invalid --limit value '{val}'"))?;
            }
            "--json" => json = true,
            other => anyhow::bail!("unknown argument '{other}'; see `uffs --deleted --help`"),
        }
    }

    if mft_file.is_none() && drive.is_none() {
        anyhow::bail!(
            "missing a source: pass `--mft-file <PATH>` (offline capture) or \
             `--drive <D>` (live volume, Windows)"
        );
    }
    Ok(DeletedArgs {
        mft_file,
        drive,
        limit,
        json,
    })
}

/// Read the live raw MFT of `drive` into an in-memory [`RawMftData`] (Windows).
///
/// Uses the fast parallel reader ([`uffs_mft::MftReader::read_raw`]); the
/// header is synthesised from the returned record size (the raw bytes carry no
/// UFFS header). `iter_records` only consults `record_size`/`record_count`, so
/// this is a faithful in-memory equivalent of an offline capture.
#[cfg(windows)]
fn read_live_raw(drive: DriveLetter) -> Result<RawMftData> {
    use uffs_mft::MftReader;
    use uffs_mft::raw::RawMftHeader;

    let reader = MftReader::open(drive)
        .with_context(|| format!("failed to open drive {drive}: (needs Administrator)"))?;
    let (data, record_size) = reader.read_raw()?;
    let data_len = uffs_mft::usize_to_u64(data.len());
    let record_count = if record_size == 0 {
        0
    } else {
        data_len / u64::from(record_size)
    };
    let header = RawMftHeader {
        // Format version of the equivalent on-disk capture; unused by
        // `iter_records`, set for a well-formed in-memory header.
        version: 3,
        flags: 0,
        record_size,
        record_count,
        original_size: data_len,
        compressed_size: 0,
        volume_letter: drive,
        reserved_allocated_bytes: 0,
    };
    Ok(RawMftData { header, data })
}

/// Non-Windows stub: reading a live volume is Windows-only.
#[cfg(not(windows))]
fn read_live_raw(drive: DriveLetter) -> Result<RawMftData> {
    anyhow::bail!(
        "a live `--drive {drive}` scan reads the NTFS volume directly and requires \
         Windows (elevated); on other platforms use `--mft-file <CAPTURE>`"
    )
}

/// Reconstruct a deleted record's full path by walking `parent` up via
/// `lookup` until the volume root. Returns `(path, complete)`; `complete` is
/// `false` when a parent FRS is absent (the path is prefixed with `…`).
fn resolve_path(
    name: &str,
    parent: u64,
    drive: DriveLetter,
    mut lookup: impl FnMut(u64) -> Option<(String, u64)>,
) -> (String, bool) {
    let mut parts: Vec<String> = vec![name.to_owned()];
    let mut current = parent;
    let mut complete = true;

    // Bounded walk: NTFS paths are far shallower than this, and the guard stops
    // a cycle from a reused/self-referential parent slot.
    for _ in 0_u32..256 {
        if current == ROOT_FRS {
            break;
        }
        let Some((parent_name, grandparent)) = lookup(current) else {
            complete = false;
            break;
        };
        parts.push(parent_name);
        current = grandparent;
    }
    if current != ROOT_FRS {
        complete = false;
    }

    parts.reverse();
    let joined = parts.join("\\");
    let path = if complete {
        format!("{drive}:\\{joined}")
    } else {
        format!("{drive}:\\…\\{joined}")
    };
    (path, complete)
}

/// Render the tombstones as a human-readable table.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_human(tombstones: &[Tombstone], total: usize, truncated: bool, drive: DriveLetter) {
    let complete = tombstones.iter().filter(|tomb| tomb.path_complete).count();
    println!(
        "Deleted (tombstone) records on {drive} — best-effort; recoverable until the MFT slot \
         is reused:"
    );
    println!(
        "  {total} tombstone(s){}; {complete} of the shown {} have a fully-resolved path",
        if truncated {
            " (showing the first --limit)"
        } else {
            ""
        },
        tombstones.len(),
    );
    if tombstones.is_empty() {
        return;
    }
    println!();
    for tomb in tombstones {
        let kind = if tomb.is_dir { "  [dir]" } else { "" };
        println!(
            "  {}  ({}, modified {}){kind}",
            tomb.path,
            human_bytes(tomb.size),
            format_filetime_local(tomb.modified),
        );
    }
    println!(
        "\nNote: the timestamp is the file's last-write time, not when it was deleted; \
         a `…`-prefixed path had a parent whose MFT slot was already reused."
    );
}

/// Emit the tombstones as JSON for scripting.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_json(tombstones: &[Tombstone], total: usize, truncated: bool) {
    let rows: Vec<serde_json::Value> = tombstones
        .iter()
        .map(|tomb| {
            serde_json::json!({
                "path": tomb.path,
                "size": tomb.size,
                "modified": tomb.modified,
                "is_dir": tomb.is_dir,
                "path_complete": tomb.path_complete,
            })
        })
        .collect();
    let doc = serde_json::json!({
        "total_deleted": total,
        "truncated": truncated,
        "tombstones": rows,
    });
    match serde_json::to_string_pretty(&doc) {
        Ok(json) => println!("{json}"),
        Err(err) => println!("{{\"error\":\"failed to serialize tombstones: {err}\"}}"),
    }
}

/// Humanise a byte count with binary units (integer arithmetic — no floats).
fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        let whole = bytes / GIB;
        let hundredths = (bytes % GIB).saturating_mul(100) / GIB;
        format!("{whole}.{hundredths:02} GiB")
    } else if bytes >= MIB {
        format!("{} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use uffs_mft::platform::DriveLetter;

    use super::{parse_deleted_args, resolve_path};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|item| (*item).to_owned()).collect()
    }

    /// A `by_frs` map → the `lookup` closure `resolve_path` expects.
    fn lookup_from(
        map: &HashMap<u64, (String, u64)>,
    ) -> impl FnMut(u64) -> Option<(String, u64)> + '_ {
        move |frs| map.get(&frs).cloned()
    }

    #[test]
    fn parses_required_mft_file_and_options() {
        let parsed = parse_deleted_args(&args(&[
            "--mft-file",
            "C.bin",
            "-d",
            "C",
            "--limit",
            "5",
            "--json",
        ]))
        .expect("parse");
        assert_eq!(
            parsed.mft_file.as_deref().and_then(std::path::Path::to_str),
            Some("C.bin")
        );
        assert_eq!(parsed.drive, Some(DriveLetter::C));
        assert_eq!(parsed.limit, 5);
        assert!(parsed.json);
    }

    #[test]
    fn a_bare_drive_is_a_valid_live_source() {
        // `-d C` with no --mft-file is a live scan (Windows); parsing accepts it.
        let parsed = parse_deleted_args(&args(&["-d", "C"])).expect("live drive parses");
        assert!(parsed.mft_file.is_none());
        assert_eq!(parsed.drive, Some(DriveLetter::C));
    }

    #[test]
    fn no_source_is_an_error() {
        let err = parse_deleted_args(&args(&["--limit", "5"])).expect_err("must require a source");
        assert!(err.to_string().contains("source"), "{err}");
    }

    #[test]
    fn resolves_through_a_live_parent_to_the_root() {
        // Root(5) → docs(100). A deleted a.txt(parent 100) resolves fully.
        let mut map = HashMap::new();
        map.insert(100_u64, ("docs".to_owned(), ROOT_FRS_T));
        let (path, complete) = resolve_path("a.txt", 100, DriveLetter::C, lookup_from(&map));
        assert_eq!(path, r"C:\docs\a.txt");
        assert!(complete);
    }

    #[test]
    fn resolves_through_a_deleted_parent_still_in_the_mft() {
        // The parent dir `gone`(100) is itself deleted but its record survives,
        // so lookup still returns it and the path reconstructs completely.
        let mut map = HashMap::new();
        map.insert(100_u64, ("gone".to_owned(), ROOT_FRS_T));
        let (path, complete) = resolve_path("file.txt", 100, DriveLetter::C, lookup_from(&map));
        assert_eq!(path, r"C:\gone\file.txt");
        assert!(complete);
    }

    #[test]
    fn a_missing_parent_marks_the_path_incomplete() {
        // Parent 999 is not in the capture (slot reused / evicted).
        let map: HashMap<u64, (String, u64)> = HashMap::new();
        let (path, complete) = resolve_path("orphan.log", 999, DriveLetter::C, lookup_from(&map));
        assert!(!complete, "missing parent → incomplete");
        assert!(path.contains('…'), "incomplete path is flagged: {path}");
        assert!(path.ends_with("orphan.log"));
    }

    #[test]
    fn a_file_directly_under_root_needs_no_lookup() {
        let map: HashMap<u64, (String, u64)> = HashMap::new();
        let (path, complete) =
            resolve_path("boot.ini", ROOT_FRS_T, DriveLetter::C, lookup_from(&map));
        assert_eq!(path, r"C:\boot.ini");
        assert!(complete);
    }

    /// Root FRS mirrored into the test module (the production const is private
    /// to the parent module's non-test scope).
    const ROOT_FRS_T: u64 = 5;
}
