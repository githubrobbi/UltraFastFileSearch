// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Consistent `--version` output for every UFFS binary.
//!
//! Every UFFS executable prints the same shape: a short one-liner by default
//! and a multi-line build fingerprint with `--version --verbose` / `-v`.
//!
//! - [`version_short!`] → `"<name>[.exe] <semver> (<sha>)"`
//! - [`version_long!`] → the short line plus commit date, rustc, target,
//!   profile
//!
//! The macros expand **in the calling crate**, so `CARGO_PKG_VERSION` resolves
//! to that binary's version and `option_env!("UFFS_GIT_SHA")` (and the other
//! `UFFS_*` build vars) resolve to what its `build.rs` stamped via
//! [`emit_build_env`]. On Windows the name carries the real `.exe` suffix so
//! `--version` matches the on-disk filename.

/// Executable-name suffix for the compiled target.
///
/// `.exe` on Windows, empty elsewhere — so the version macros print a name that
/// matches the actual on-disk filename.
#[must_use]
pub const fn exe_suffix() -> &'static str {
    if cfg!(windows) { ".exe" } else { "" }
}

/// Short one-line version: `"<name>[.exe] <semver> (<sha>)"`.
///
/// Expands in the caller, so `CARGO_PKG_VERSION` and `UFFS_GIT_SHA` are that
/// binary's. `$name` is the bare binary stem (e.g. `"uffsd"`); the `.exe`
/// suffix is appended automatically on Windows.
#[macro_export]
macro_rules! version_short {
    ($name:literal) => {
        format!(
            "{}{} {} ({})",
            $name,
            $crate::exe_suffix(),
            env!("CARGO_PKG_VERSION"),
            option_env!("UFFS_GIT_SHA").unwrap_or("unknown"),
        )
    };
}

/// Multi-line build fingerprint for bug reports (`--version --verbose` / `-v`).
///
/// The short line followed by `commit` (sha + date), `rustc`, `target`, and
/// `profile`, each read from the `UFFS_*` env this crate's [`emit_build_env`]
/// stamps at build time (`"unknown"` when a field could not be resolved).
#[macro_export]
macro_rules! version_long {
    ($name:literal) => {
        format!(
            "{}{} {}\n\
             commit:   {} ({})\n\
             rustc:    {}\n\
             target:   {}\n\
             profile:  {}",
            $name,
            $crate::exe_suffix(),
            env!("CARGO_PKG_VERSION"),
            option_env!("UFFS_GIT_SHA").unwrap_or("unknown"),
            option_env!("UFFS_COMMIT_DATE").unwrap_or("unknown"),
            option_env!("UFFS_RUSTC").unwrap_or("unknown"),
            option_env!("UFFS_TARGET").unwrap_or("unknown"),
            option_env!("UFFS_PROFILE").unwrap_or("unknown"),
        )
    };
}

/// Intercept `--version` / `-V` at the top of `main` and exit.
///
/// Prints the short line, or the multi-line fingerprint when `--verbose` / `-v`
/// follows. `$name` is the bare binary stem (`"uffsd"`). Only fires when the
/// version flag is the **first** argument (matching the search-first CLI
/// grammar, where a later `--version` is a search term). Writes straight to
/// stdout (not `println!`) so callers need no `print_stdout` allow. Put it as
/// the very first statement in `main`.
#[macro_export]
macro_rules! handle_version {
    ($name:literal) => {
        // A single call, so `main` gains ~no cognitive complexity (some UFFS
        // mains sit right at the `cognitive_complexity` ceiling). The closures
        // defer the (caller-expanded) version macros so each reads the caller's
        // own `CARGO_PKG_VERSION` + `UFFS_GIT_SHA`; only the requested form is
        // built. On `--version` the helper prints and exits.
        $crate::print_version_if_requested(
            || $crate::version_short!($name),
            || $crate::version_long!($name),
        );
    };
}

/// When `--version` / `-V` is the first argument, print the version and **exit
/// the process**; otherwise return so the caller proceeds.
///
/// Prints the `long` form when `--verbose` / `-v` follows, else `short`. The
/// caller passes closures so the version strings expand in *its* crate (its own
/// `CARGO_PKG_VERSION` + `UFFS_GIT_SHA`). Writes straight to stdout (not
/// `println!`). See [`handle_version!`].
// Exiting is this function's contract (a `--version` handler); there is no
// resource cleanup to skip at version-print time, and doing the exit here (not
// in the macro) keeps callers' `main` free of an extra branch.
#[expect(
    clippy::exit,
    reason = "version handler exits by contract after printing; no cleanup to skip"
)]
pub fn print_version_if_requested<Short, Long>(short: Short, long: Long)
where
    Short: FnOnce() -> String,
    Long: FnOnce() -> String,
{
    use std::io::Write as _;

    let args: Vec<String> = std::env::args().collect();
    if !matches!(args.get(1).map(String::as_str), Some("--version" | "-V")) {
        return;
    }
    let verbose = args
        .iter()
        .skip(2)
        .any(|arg| arg == "--verbose" || arg == "-v");
    let line = if verbose { long() } else { short() };
    let mut out = std::io::stdout();
    let _written = out
        .write_all(line.as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush());
    std::process::exit(0);
}

/// Stamp the build metadata the version macros read into `cargo:rustc-env`.
///
/// Call once from a binary crate's `build.rs` (with the `build` feature on).
/// Emits `UFFS_GIT_SHA` (short HEAD sha, `-dirty` when the tree is modified),
/// `UFFS_COMMIT_DATE`, `UFFS_RUSTC`, `UFFS_TARGET`, and `UFFS_PROFILE`.
/// Best-effort: any field that cannot be resolved is stamped `unknown`, so a
/// build with no git available still succeeds.
#[cfg(feature = "build")]
#[expect(
    clippy::print_stdout,
    reason = "build-script API: values are passed to cargo via stdout directives"
)]
pub fn emit_build_env() {
    println!("cargo:rustc-env=UFFS_GIT_SHA={}", git_sha());
    println!(
        "cargo:rustc-env=UFFS_COMMIT_DATE={}",
        git_output(&["show", "-s", "--format=%cs", "HEAD"])
    );
    println!("cargo:rustc-env=UFFS_RUSTC={}", rustc_version());
    println!("cargo:rustc-env=UFFS_TARGET={}", env_or_unknown("TARGET"));
    println!("cargo:rustc-env=UFFS_PROFILE={}", env_or_unknown("PROFILE"));
    // Re-stamp when the checked-out commit or the compiler changes.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-env-changed=RUSTC");
}

/// Run `git <args>`, returning trimmed stdout or `"unknown"`.
#[cfg(feature = "build")]
fn git_output(args: &[&str]) -> String {
    std::process::Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|raw| raw.trim().to_owned())
        .filter(|trimmed| !trimmed.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Short HEAD sha with a `-dirty` suffix when the working tree has uncommitted
/// changes (so a hand-tweaked local build is never mistaken for the commit).
#[cfg(feature = "build")]
fn git_sha() -> String {
    let sha = git_output(&["rev-parse", "--short", "HEAD"]);
    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .is_some_and(|out| !out.stdout.is_empty());
    if dirty && sha != "unknown" {
        format!("{sha}-dirty")
    } else {
        sha
    }
}

/// The building compiler's `rustc --version` line (via the `RUSTC` cargo sets).
#[cfg(feature = "build")]
fn rustc_version() -> String {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    std::process::Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|raw| raw.trim().to_owned())
        .filter(|trimmed| !trimmed.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// A cargo-provided build env var (e.g. `TARGET`, `PROFILE`) or `"unknown"`.
#[cfg(feature = "build")]
fn env_or_unknown(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::exe_suffix;

    #[test]
    fn exe_suffix_matches_target() {
        if cfg!(windows) {
            assert_eq!(exe_suffix(), ".exe");
        } else {
            assert_eq!(exe_suffix(), "");
        }
    }

    #[test]
    fn version_short_has_name_semver_and_sha_shape() {
        // Expands in this (test) crate: CARGO_PKG_VERSION is uffs-version's.
        let line = version_short!("uffs-version");
        assert!(line.starts_with("uffs-version"));
        assert!(line.contains(env!("CARGO_PKG_VERSION")));
        assert!(line.contains('(') && line.ends_with(')'));
        #[cfg(windows)]
        assert!(line.starts_with("uffs-version.exe "));
    }

    #[test]
    fn version_long_is_multiline_with_fields() {
        let text = version_long!("uffs-version");
        assert!(text.lines().count() >= 5, "short line + 4 metadata lines");
        assert!(text.contains("commit:"));
        assert!(text.contains("rustc:"));
        assert!(text.contains("target:"));
        assert!(text.contains("profile:"));
    }
}
