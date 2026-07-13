// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `uffs --diff <BASELINE> --drive <D>` — snapshot delete-visibility diff.
//!
//! Answers "what was created, deleted, or modified on a drive since a baseline
//! MFT capture" — the deletion-visible companion to `--newer`. Thin client:
//! parse args, fire the daemon's `diff` RPC (which diffs the baseline against
//! the drive's live in-memory index), render the classified delta.

use anyhow::{Context as _, Result};
use uffs_client::connect_sync::UffsClientSync;
use uffs_client::protocol::{DiffEntryWire, DiffParams, DiffResultWire};
use uffs_mft::platform::DriveLetter;

use crate::args::parse_drive_letter;

/// Parsed `uffs --diff` invocation.
#[derive(Debug)]
struct DiffArgs {
    /// Baseline snapshot path (raw MFT capture) to diff against.
    baseline: String,
    /// Drive letter the baseline covers and whose live index is the current
    /// side.
    drive: DriveLetter,
    /// Max entries per class (0 = unlimited).
    limit: u32,
    /// Emit JSON instead of the human table.
    json: bool,
}

/// Run `uffs --diff <BASELINE> --drive <D> [--limit N] [--json]`.
///
/// # Errors
///
/// Returns an error on bad arguments, when the daemon is not running, or when
/// the `diff` RPC itself fails (drive not loaded / baseline unreadable).
pub(crate) fn run_diff(args: &[String]) -> Result<()> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        crate::args::print_diff_help();
        return Ok(());
    }

    let parsed = parse_diff_args(args)?;
    let mut client = UffsClientSync::connect_raw()
        .map_err(|err| anyhow::anyhow!("Daemon is not running: {err}"))?;

    let params = DiffParams {
        baseline: parsed.baseline,
        drive: parsed.drive,
        limit: parsed.limit,
    };
    let result = client.diff(&params).with_context(|| "diff RPC failed")?;

    if parsed.json {
        print_json(&result);
    } else {
        print_human(&params, &result);
    }
    Ok(())
}

/// Parse the `--diff` argument vector into a [`DiffArgs`].
///
/// The first non-flag token is the baseline path; `--drive`/`-d` is required;
/// `--limit`/`-n` and `--json` are optional.
fn parse_diff_args(args: &[String]) -> Result<DiffArgs> {
    let mut baseline: Option<String> = None;
    let mut drive: Option<DriveLetter> = None;
    let mut limit: u32 = 0;
    let mut json = false;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
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
            other if other.starts_with('-') => {
                anyhow::bail!("unknown flag '{other}'; see `uffs --diff --help`");
            }
            other => {
                if baseline.replace(other.to_owned()).is_some() {
                    anyhow::bail!("only one baseline path may be given; got a second: '{other}'");
                }
            }
        }
    }

    let baseline_path = baseline.with_context(
        || "missing baseline snapshot path; usage: uffs --diff <BASELINE> --drive <D>",
    )?;
    let drive_letter =
        drive.with_context(|| "missing `--drive <LETTER>`; the diff needs to know which drive")?;
    Ok(DiffArgs {
        baseline: baseline_path,
        drive: drive_letter,
        limit,
        json,
    })
}

/// Render the delta as a human-readable table grouped by change class.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_human(params: &DiffParams, result: &DiffResultWire) {
    println!(
        "Diff of drive {} vs baseline {}:",
        params.drive, params.baseline
    );
    println!(
        "  deleted {}, added {}, modified {}{}",
        result.deleted.len(),
        result.added.len(),
        result.modified.len(),
        if result.truncated {
            " (truncated — pass a larger --limit for the full list)"
        } else {
            ""
        },
    );

    print_section("Deleted", &result.deleted, true);
    print_section("Added", &result.added, false);
    print_section("Modified", &result.modified, false);
}

/// Print one non-empty class section. `with_size` appends the byte size (the
/// "what did I lose" figure that matters most for deletes).
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_section(label: &str, entries: &[DiffEntryWire], with_size: bool) {
    if entries.is_empty() {
        return;
    }
    println!("\n{label}:");
    for entry in entries {
        if with_size {
            println!("  {}  ({})", entry.path, human_bytes(entry.size));
        } else {
            println!("  {}", entry.path);
        }
    }
}

/// Emit the raw wire result as pretty JSON for scripting.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_json(result: &DiffResultWire) {
    match serde_json::to_string_pretty(result) {
        Ok(json) => println!("{json}"),
        Err(err) => println!("{{\"error\":\"failed to serialize diff result: {err}\"}}"),
    }
}

/// Humanise a byte count with binary units (integer arithmetic — no floats,
/// to satisfy the strict `clippy::float_arithmetic` gate).
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
    use super::parse_diff_args;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn parses_baseline_drive_and_limit() {
        let parsed =
            parse_diff_args(&args(&["C_old.bin", "--drive", "C", "--limit", "50"])).expect("parse");
        assert_eq!(parsed.baseline, "C_old.bin");
        assert_eq!(parsed.drive, uffs_mft::platform::DriveLetter::C);
        assert_eq!(parsed.limit, 50);
        assert!(!parsed.json);
    }

    #[test]
    fn drive_may_precede_the_positional_baseline() {
        let parsed = parse_diff_args(&args(&["-d", "D", "snap.bin", "--json"])).expect("parse");
        assert_eq!(parsed.baseline, "snap.bin");
        assert_eq!(parsed.drive, uffs_mft::platform::DriveLetter::D);
        assert_eq!(parsed.limit, 0, "no --limit → unlimited");
        assert!(parsed.json);
    }

    #[test]
    fn missing_drive_is_an_error() {
        let err = parse_diff_args(&args(&["snap.bin"])).expect_err("must require --drive");
        assert!(err.to_string().contains("--drive"), "{err}");
    }

    #[test]
    fn missing_baseline_is_an_error() {
        let err = parse_diff_args(&args(&["--drive", "C"])).expect_err("must require baseline");
        assert!(err.to_string().contains("baseline"), "{err}");
    }

    #[test]
    fn a_second_baseline_is_rejected() {
        let err = parse_diff_args(&args(&["a.bin", "b.bin", "-d", "C"]))
            .expect_err("two baselines must error");
        assert!(err.to_string().contains("second"), "{err}");
    }

    #[test]
    fn unknown_flag_is_rejected() {
        let err = parse_diff_args(&args(&["snap.bin", "-d", "C", "--bogus"]))
            .expect_err("unknown flag must error");
        assert!(err.to_string().contains("unknown flag"), "{err}");
    }
}
