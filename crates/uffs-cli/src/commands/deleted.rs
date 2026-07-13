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

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use uffs_mft::parse::{
    ParseOptions, ParseResult, ParsedRecord, apply_fixup, parse_record_forensic,
};
use uffs_mft::platform::DriveLetter;
use uffs_mft::raw::{LoadRawOptions, load_raw_mft};

use crate::args::parse_drive_letter;
use crate::commands::output::format_filetime_local;

/// NTFS reserves File Record Segment 5 for the volume root directory; every
/// path walk terminates here.
const ROOT_FRS: u64 = 5;

/// Parsed `uffs --deleted` invocation.
#[derive(Debug)]
struct DeletedArgs {
    /// MFT capture to scan (raw `$MFT` dump).
    mft_file: PathBuf,
    /// Drive letter to label reconstructed paths with (default `X`).
    drive: Option<DriveLetter>,
    /// Max tombstones to print (0 = all).
    limit: u32,
    /// Emit JSON instead of the human table.
    json: bool,
}

/// One reconstructed deleted-file tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tombstone {
    /// Reconstructed full path (best-effort — see module docs).
    path: String,
    /// Logical file size in bytes (from the surviving record).
    size: u64,
    /// The file's own last-write time (raw FILETIME) — NOT the deletion time.
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

    let options = LoadRawOptions {
        header_only: false,
        volume_letter: Some(drive),
        forensic: true,
    };
    let raw = load_raw_mft(&parsed.mft_file, &options)
        .with_context(|| format!("failed to read MFT capture '{}'", parsed.mft_file.display()))?;

    // Forensic-parse every slot: this keeps the not-in-use (deleted) records
    // that the default parser drops, and the live records we need to resolve
    // deleted files' parent chains.
    let capacity = usize::try_from(raw.record_count()).unwrap_or(0);
    let mut records = Vec::with_capacity(capacity);
    for (frs, data) in raw.iter_records() {
        let mut record_buf = data.to_vec();
        let fixup_ok = apply_fixup(&mut record_buf);
        if let ParseResult::Base(parsed_record) =
            parse_record_forensic(&record_buf, frs, ParseOptions::FORENSIC, !fixup_ok)
        {
            records.push(parsed_record);
        }
    }

    let (tombstones, total, truncated) =
        collect_tombstones(&records, drive, uffs_mft::u32_as_usize(parsed.limit));

    if parsed.json {
        print_json(&tombstones, total, truncated);
    } else {
        print_human(&tombstones, total, truncated, drive);
    }
    Ok(())
}

/// Parse the `--deleted` argument vector.
///
/// `--mft-file <PATH>` is required; `--drive`, `--limit`, `--json` optional.
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

    let mft_path = mft_file.with_context(|| {
        "missing `--mft-file <PATH>`; a live `--drive` scan is not wired yet — \
         point at an MFT capture"
    })?;
    Ok(DeletedArgs {
        mft_file: mft_path,
        drive,
        limit,
        json,
    })
}

/// Collect and path-resolve every deleted record. Returns the (capped)
/// tombstones, the total deleted count (before the cap), and whether the cap
/// dropped any.
fn collect_tombstones(
    records: &[ParsedRecord],
    drive: DriveLetter,
    limit: usize,
) -> (Vec<Tombstone>, usize, bool) {
    // FRS -> (name, parent FRS) for *every* record, so a deleted file's parent
    // chain resolves even through intermediate deleted directories.
    let mut by_frs: HashMap<u64, (&str, u64)> = HashMap::with_capacity(records.len());
    for record in records {
        by_frs.insert(
            record.frs.raw(),
            (record.name.as_str(), record.parent_frs.raw()),
        );
    }

    let deleted: Vec<&ParsedRecord> = records.iter().filter(|rec| rec.is_deleted).collect();
    let total = deleted.len();
    let truncated = limit > 0 && total > limit;
    let take = if truncated { limit } else { total };

    let tombstones = deleted
        .iter()
        .take(take)
        .map(|rec| {
            let (path, complete) =
                resolve_deleted_path(&rec.name, rec.parent_frs.raw(), &by_frs, drive);
            Tombstone {
                path,
                size: rec.size,
                modified: rec.std_info.modified,
                is_dir: rec.is_directory,
                path_complete: complete,
            }
        })
        .collect();

    (tombstones, total, truncated)
}

/// Reconstruct a deleted record's full path by walking `parent` up `by_frs`
/// until the volume root. Returns `(path, complete)`; `complete` is `false`
/// when a parent FRS is absent (the path is prefixed with `…` to flag it).
fn resolve_deleted_path(
    name: &str,
    parent: u64,
    by_frs: &HashMap<u64, (&str, u64)>,
    drive: DriveLetter,
) -> (String, bool) {
    let mut parts: Vec<&str> = vec![name];
    let mut current = parent;
    let mut complete = true;

    // Bounded walk: NTFS paths are far shallower than this, and the guard stops
    // a cycle from a reused/self-referential parent slot.
    for _ in 0_u32..256 {
        if current == ROOT_FRS {
            break;
        }
        let Some(&(parent_name, grandparent)) = by_frs.get(&current) else {
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
    use uffs_mft::parse::ParsedRecord;
    use uffs_mft::platform::DriveLetter;

    use super::{collect_tombstones, parse_deleted_args};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|item| (*item).to_owned()).collect()
    }

    /// Build a record: `frs`, `parent` FRS, name, size, deleted?, dir?.
    fn record(
        frs: u64,
        parent: u64,
        name: &str,
        size: u64,
        deleted: bool,
        dir: bool,
    ) -> ParsedRecord {
        ParsedRecord {
            frs: uffs_mft::frs::Frs::new(frs),
            parent_frs: uffs_mft::frs::ParentFrs::new(parent),
            name: name.to_owned(),
            size,
            is_deleted: deleted,
            is_directory: dir,
            ..ParsedRecord::default()
        }
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
        assert_eq!(parsed.mft_file.to_str(), Some("C.bin"));
        assert_eq!(parsed.drive, Some(DriveLetter::C));
        assert_eq!(parsed.limit, 5);
        assert!(parsed.json);
    }

    #[test]
    fn missing_mft_file_is_an_error() {
        let err = parse_deleted_args(&args(&["-d", "C"])).expect_err("must require --mft-file");
        assert!(err.to_string().contains("--mft-file"), "{err}");
    }

    #[test]
    fn only_deleted_records_become_tombstones_with_resolved_paths() {
        // Root(5) → docs(100) → [a.txt(200) deleted, live.txt(201) alive].
        let records = vec![
            record(100, ROOT_FRS_T, "docs", 0, false, true),
            record(200, 100, "a.txt", 100, true, false),
            record(201, 100, "live.txt", 50, false, false),
        ];
        let (tombs, total, truncated) = collect_tombstones(&records, DriveLetter::C, 0);
        assert_eq!(total, 1, "only a.txt is deleted");
        assert!(!truncated);
        let tomb = tombs.first().expect("one tombstone");
        assert_eq!(
            tomb.path, r"C:\docs\a.txt",
            "resolved through the live parent"
        );
        assert_eq!(tomb.size, 100);
        assert!(tomb.path_complete);
    }

    #[test]
    fn a_deleted_dir_on_the_chain_still_resolves() {
        // Root(5) → gone(100, deleted dir) → file(200, deleted). The deleted
        // parent is still in the MFT, so the path reconstructs completely.
        let records = vec![
            record(100, ROOT_FRS_T, "gone", 0, true, true),
            record(200, 100, "file.txt", 10, true, false),
        ];
        let (tombs, total, _) = collect_tombstones(&records, DriveLetter::C, 0);
        assert_eq!(total, 2);
        let file = tombs
            .iter()
            .find(|tomb| tomb.path.ends_with("file.txt"))
            .expect("file tombstone");
        assert_eq!(file.path, r"C:\gone\file.txt");
        assert!(file.path_complete);
    }

    #[test]
    fn a_missing_parent_marks_the_path_incomplete() {
        // The parent FRS (999) is not in the capture (slot reused / evicted).
        let records = vec![record(200, 999, "orphan.log", 44, true, false)];
        let (tombs, _, _) = collect_tombstones(&records, DriveLetter::C, 0);
        let tomb = tombs.first().expect("one tombstone");
        assert!(!tomb.path_complete, "missing parent → incomplete");
        assert!(
            tomb.path.contains('…'),
            "incomplete path is flagged: {}",
            tomb.path
        );
        assert!(tomb.path.ends_with("orphan.log"));
    }

    #[test]
    fn limit_caps_and_flags_truncation() {
        let records = vec![
            record(200, ROOT_FRS_T, "a", 1, true, false),
            record(201, ROOT_FRS_T, "b", 2, true, false),
            record(202, ROOT_FRS_T, "c", 3, true, false),
        ];
        let (tombs, total, truncated) = collect_tombstones(&records, DriveLetter::C, 2);
        assert_eq!(total, 3, "total counts all deleted");
        assert_eq!(tombs.len(), 2, "cap keeps 2");
        assert!(truncated);
    }

    /// Root FRS mirrored into the test module (the production const is private
    /// to the parent module's non-test scope).
    const ROOT_FRS_T: u64 = 5;
}
