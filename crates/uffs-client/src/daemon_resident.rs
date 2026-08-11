// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Resident-marker support for the daemon auto-spawn path.
//!
//! `uffs --daemon resident on` writes a marker file (`resident.args`,
//! next to the daemon PID file — see
//! [`crate::daemon_ctl::resident_args_path`]) holding the daemon argv
//! the login item uses, one argument per line. [`spawn_daemon`] merges
//! that marker into every implicit auto-spawn, so a crashed or
//! manually stopped resident daemon is revived *resident* by the next
//! search instead of silently falling back to the default idle-retire
//! lifetime.
//!
//! Extracted from `daemon_spawn.rs` to keep that file under the
//! workspace 800-LOC policy ceiling.
//!
//! [`spawn_daemon`]: crate::daemon_spawn

/// Load the resident marker and merge it into `args` (see
/// [`merge_resident_args`]). A missing or unreadable marker leaves the
/// caller's args untouched.
pub(crate) fn apply_resident_marker(args: &[std::ffi::OsString]) -> Vec<std::ffi::OsString> {
    let marker =
        std::fs::read_to_string(crate::daemon_ctl::resident_args_path()).unwrap_or_default();
    merge_resident_args(args, &marker)
}

/// Merge the resident-marker argv (one argument per line — what
/// `uffs --daemon resident on` baked into the login item) into a
/// caller's spawn args.
///
/// Merging is conservative: the caller's flags always win. A marker
/// flag group (the `--flag` line plus the value lines that follow it)
/// is appended only when the caller did not pass that flag itself, so
/// an explicit `--data-dir` from a search command overrides the
/// resident one while a bare auto-spawn inherits the full resident
/// configuration — most importantly `--no-retire`.
///
/// Ephemeral instances (`--ephemeral-id`) are never made resident:
/// their args pass through unchanged.
fn merge_resident_args(caller: &[std::ffi::OsString], marker: &str) -> Vec<std::ffi::OsString> {
    let mut merged = caller.to_vec();
    if caller.iter().any(|arg| arg == "--ephemeral-id") {
        return merged;
    }
    let mut lines = marker
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .peekable();
    while let Some(flag) = lines.next() {
        let mut group = vec![flag];
        while lines.peek().is_some_and(|next| !next.starts_with("--")) {
            if let Some(value) = lines.next() {
                group.push(value);
            }
        }
        if flag.starts_with("--") && !caller.iter().any(|arg| arg == flag) {
            merged.extend(group.iter().map(std::ffi::OsString::from));
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::merge_resident_args;

    /// Shorthand: caller args from strs.
    fn args(raw: &[&str]) -> Vec<OsString> {
        raw.iter().map(OsString::from).collect()
    }

    /// An empty (or missing → read as empty) marker changes nothing.
    #[test]
    fn empty_marker_is_a_passthrough() {
        let caller = args(&["--data-dir", "/data"]);
        assert_eq!(merge_resident_args(&caller, ""), caller);
    }

    /// A bare auto-spawn inherits the full resident configuration in
    /// marker order — most importantly `--no-retire`.
    #[test]
    fn bare_spawn_inherits_full_resident_argv() {
        let merged = merge_resident_args(
            &[],
            "--no-retire\n--data-dir\n/Users/me/uffs data\n--log-file\n/logs/uffsd.log\n",
        );
        assert_eq!(
            merged,
            args(&[
                "--no-retire",
                "--data-dir",
                "/Users/me/uffs data",
                "--log-file",
                "/logs/uffsd.log",
            ])
        );
    }

    /// The caller's own flag wins: its `--data-dir` suppresses the
    /// marker's group, while `--no-retire` is still inherited.
    #[test]
    fn caller_flags_override_marker_groups() {
        let caller = args(&["--data-dir", "/theirs"]);
        let merged = merge_resident_args(&caller, "--no-retire\n--data-dir\n/resident\n");
        assert_eq!(merged, args(&["--data-dir", "/theirs", "--no-retire"]));
    }

    /// Repeatable marker flags (two `--drive` groups) are both
    /// appended when the caller passed none.
    #[test]
    fn repeated_marker_flags_all_append() {
        let merged = merge_resident_args(&[], "--no-retire\n--drive\nC\n--drive\nD\n");
        assert_eq!(
            merged,
            args(&["--no-retire", "--drive", "C", "--drive", "D"])
        );
    }

    /// Ephemeral job-scoped instances must never become resident —
    /// `--no-retire` on a snapshot daemon would leak it forever.
    #[test]
    fn ephemeral_instances_are_exempt() {
        let caller = args(&["--ephemeral-id", "job-7"]);
        assert_eq!(
            merge_resident_args(&caller, "--no-retire\n"),
            caller,
            "ephemeral spawn must pass through unchanged"
        );
    }

    /// A malformed marker (value lines with no leading flag) appends
    /// nothing — the merge never invents arguments.
    #[test]
    fn stray_value_lines_are_dropped() {
        let merged = merge_resident_args(&[], "stray\nvalue\n--no-retire\n");
        assert_eq!(merged, args(&["--no-retire"]));
    }
}
