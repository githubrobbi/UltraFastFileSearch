// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `uffs --snapshot --drive C --out FILE` — capture the live MFT to a file.
//!
//! The first step of the snapshot-diff workflow: save a baseline MFT capture
//! now so `uffs --diff <FILE> --drive C` can later surface what was deleted.
//! Thin wrapper over the same proven library primitives the `uffs-mft save`
//! diagnostic uses (`MftReader::open` + `save_raw_to_file`).
//!
//! Reading the live MFT requires Windows + Administrator; on other platforms
//! the command returns an actionable error rather than failing obscurely.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use uffs_mft::platform::DriveLetter;

use crate::args::parse_drive_letter;

/// Parsed `uffs --snapshot` invocation.
#[derive(Debug)]
struct SnapshotArgs {
    /// Drive whose live MFT to capture.
    drive: DriveLetter,
    /// Output `.bin` path.
    out: PathBuf,
    /// Disable zstd compression (default: compressed).
    no_compress: bool,
    /// Headerless raw mode (compatible with other MFT tools; implies
    /// no-compress). NOT loadable by `uffs --diff`, which needs the UFFS
    /// header.
    raw: bool,
    /// zstd compression level (1-22).
    compression_level: i32,
}

/// Run `uffs --snapshot --drive <D> --out <FILE> [--no-compress] [--raw]`.
///
/// # Errors
///
/// Returns an error on bad arguments, on a non-Windows host, or when the live
/// MFT read / file write fails.
pub(crate) fn run_snapshot(args: &[String]) -> Result<()> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        crate::args::print_snapshot_help();
        return Ok(());
    }
    let parsed = parse_snapshot_args(args)?;
    capture(&parsed)
}

/// Parse the `--snapshot` argument vector. `--drive` + `--out` are required.
fn parse_snapshot_args(args: &[String]) -> Result<SnapshotArgs> {
    let mut drive: Option<DriveLetter> = None;
    let mut out: Option<PathBuf> = None;
    let mut no_compress = false;
    let mut raw = false;
    let mut compression_level: i32 = 3;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--drive" | "-d" => {
                let val = iter
                    .next()
                    .with_context(|| "`--drive` requires a drive letter (e.g. C)")?;
                drive = Some(parse_drive_letter(val)?);
            }
            "--out" | "-o" => {
                let val = iter.next().with_context(|| "`--out` requires a path")?;
                out = Some(PathBuf::from(val));
            }
            "--no-compress" => no_compress = true,
            "--raw" => raw = true,
            "--compression-level" => {
                let val = iter
                    .next()
                    .with_context(|| "`--compression-level` requires a number (1-22)")?;
                compression_level = val
                    .parse::<i32>()
                    .with_context(|| format!("invalid --compression-level '{val}'"))?;
            }
            other => anyhow::bail!("unknown argument '{other}'; see `uffs --snapshot --help`"),
        }
    }

    let drive_letter =
        drive.with_context(|| "missing `--drive <LETTER>` (which drive to capture)")?;
    let out_path = out.with_context(|| "missing `--out <FILE>` (where to write the capture)")?;
    Ok(SnapshotArgs {
        drive: drive_letter,
        out: out_path,
        no_compress,
        raw,
        compression_level,
    })
}

/// Read the live MFT for `args.drive` and write it to `args.out` (Windows).
#[cfg(windows)]
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn capture(args: &SnapshotArgs) -> Result<()> {
    use uffs_mft::{MftReader, SaveRawOptions};

    let reader = MftReader::open(args.drive)
        .with_context(|| format!("failed to open drive {}: (needs Administrator)", args.drive))?;
    let options = SaveRawOptions {
        // `--raw` (headerless, for other tools) implies no compression.
        compress: !args.no_compress && !args.raw,
        compression_level: args.compression_level,
        volume_letter: args.drive,
        raw_compat: args.raw,
        reserved_allocated_bytes: 0,
    };
    let header = reader
        .save_raw_to_file(&args.out, &options)
        .with_context(|| format!("failed to write snapshot to {}", args.out.display()))?;

    println!(
        "Saved MFT snapshot of {}: -> {} ({} records)",
        args.drive,
        args.out.display(),
        header.record_count,
    );
    if args.raw {
        println!(
            "  Format: raw (headerless) — NOT loadable by `uffs --diff`; drop --raw for that."
        );
    } else {
        println!(
            "  Diff it later with:  uffs --diff {} --drive {}",
            args.out.display(),
            args.drive,
        );
    }
    Ok(())
}

/// Non-Windows stub: the live MFT read is Windows-only. Every field is consumed
/// by the Windows path; the error references them all so the struct has no dead
/// fields on non-Windows hosts.
#[cfg(not(windows))]
fn capture(args: &SnapshotArgs) -> Result<()> {
    anyhow::bail!(
        "uffs --snapshot ({} -> {}, no_compress={}, raw={}, level={}) reads the live NTFS MFT \
         and requires Windows (elevated). On other platforms, diff two existing captures with \
         `uffs --diff <BASELINE> --mft-file <CURRENT>` instead.",
        args.drive,
        args.out.display(),
        args.no_compress,
        args.raw,
        args.compression_level,
    )
}

#[cfg(test)]
mod tests {
    use super::parse_snapshot_args;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn parses_drive_out_and_options() {
        let parsed = parse_snapshot_args(&args(&[
            "--drive",
            "C",
            "--out",
            "C_base.bin",
            "--no-compress",
        ]))
        .expect("parse");
        assert_eq!(parsed.drive, uffs_mft::platform::DriveLetter::C);
        assert_eq!(parsed.out.to_str(), Some("C_base.bin"));
        assert!(parsed.no_compress);
        assert!(!parsed.raw);
        assert_eq!(parsed.compression_level, 3_i32);
    }

    #[test]
    fn missing_drive_is_an_error() {
        let err = parse_snapshot_args(&args(&["--out", "x.bin"])).expect_err("needs --drive");
        assert!(err.to_string().contains("--drive"), "{err}");
    }

    #[test]
    fn missing_out_is_an_error() {
        let err = parse_snapshot_args(&args(&["--drive", "C"])).expect_err("needs --out");
        assert!(err.to_string().contains("--out"), "{err}");
    }
}
