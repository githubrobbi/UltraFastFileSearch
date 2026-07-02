// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Argument parsing for `uffs --uninstall` (task U-03 of
//! `docs/dev/architecture/UFFS-Uninstall-Implementation-Plan.md`).
//!
//! Pure and fully unit-tested: no IO, no side effects. The flag set mirrors the
//! design doc §9 CLI surface.

use anyhow::{Result, anyhow, bail};

/// Which install scope `uffs --uninstall` is allowed to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum UninstallScope {
    /// Current user's per-user install only (`%LOCALAPPDATA%`, user PATH).
    User,
    /// Machine-wide install only (`%PROGRAMFILES%`, the service, machine PATH).
    Machine,
    /// Everything the run is permitted to touch (the default).
    #[default]
    All,
}

impl UninstallScope {
    /// Parse a `--scope` value (`user` | `machine` | `all`).
    ///
    /// # Errors
    ///
    /// Returns an error for any other value.
    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "user" => Self::User,
            "machine" => Self::Machine,
            "all" => Self::All,
            other => bail!("invalid --scope `{other}` (expected: user | machine | all)"),
        })
    }
}

/// Parsed `uffs --uninstall` flags (design §9).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "a CLI flag bag: each field is an independent user-facing on/off toggle"
)]
pub(crate) struct UninstallArgs {
    /// `--dry-run`: print the analysis + removal plan, change nothing.
    pub(crate) dry_run: bool,
    /// `--yes` / `--assume-yes` / `-y`: skip the confirmation prompt.
    pub(crate) assume_yes: bool,
    /// `--keep-config`: remove binaries + caches but preserve settings/config.
    pub(crate) keep_config: bool,
    /// `--no-deep-sweep`: skip the cross-drive search for stray family files.
    pub(crate) no_deep_sweep: bool,
    /// `--no-path`: do not edit PATH (print a manual hint instead).
    pub(crate) no_path: bool,
    /// `--json`: emit the analysis + plan as machine-readable JSON.
    pub(crate) json: bool,
    /// `-v` / `--verbose`: show the full binary resolution table, artifact
    /// inventory, and deep-sweep diagnostics (default: a one-line summary).
    pub(crate) verbose: bool,
    /// `--scope`: restrict to user / machine / all (default `all`).
    pub(crate) scope: UninstallScope,
    /// `--help` / `-h`: print usage and exit.
    pub(crate) help: bool,
    /// `--remove-service-helper <name>`: **internal, undocumented.** The
    /// elevated child mode spawned via UAC by the non-elevated uninstall's
    /// "elevate at removal time" choice: remove exactly this Windows service,
    /// then exit. Never passed by users; deliberately absent from `--help`.
    pub(crate) admin_helper_service: Option<String>,
}

impl UninstallArgs {
    /// Parse the tokens after `--uninstall` into an [`UninstallArgs`].
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown flag, a `--scope` missing its value, or
    /// an invalid `--scope` value.
    pub(crate) fn parse(args: &[String]) -> Result<Self> {
        let mut parsed = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--dry-run" => parsed.dry_run = true,
                "--yes" | "--assume-yes" | "-y" => parsed.assume_yes = true,
                "--keep-config" => parsed.keep_config = true,
                "--no-deep-sweep" => parsed.no_deep_sweep = true,
                "--no-path" => parsed.no_path = true,
                "--json" => parsed.json = true,
                "--verbose" | "-v" => parsed.verbose = true,
                "--help" | "-h" => parsed.help = true,
                "--scope" => {
                    let value = iter
                        .next()
                        .ok_or_else(|| anyhow!("--scope requires a value: user | machine | all"))?;
                    parsed.scope = UninstallScope::parse(value)?;
                }
                "--remove-service-helper" => {
                    let value = iter.next().ok_or_else(|| {
                        anyhow!("--remove-service-helper requires a service name")
                    })?;
                    parsed.admin_helper_service = Some(value.clone());
                }
                flag if flag.starts_with("--scope=") => {
                    let value = flag.strip_prefix("--scope=").unwrap_or_default();
                    parsed.scope = UninstallScope::parse(value)?;
                }
                other => bail!("unknown `uffs --uninstall` flag: {other}"),
            }
        }
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::{UninstallArgs, UninstallScope};

    fn parse(tokens: &[&str]) -> anyhow::Result<UninstallArgs> {
        let owned: Vec<String> = tokens.iter().map(|tok| (*tok).to_owned()).collect();
        UninstallArgs::parse(&owned)
    }

    #[test]
    fn defaults_are_conservative() {
        let out = parse(&[]).unwrap();
        assert_eq!(out, UninstallArgs::default());
        assert!(!out.dry_run && !out.assume_yes && !out.json);
        assert_eq!(out.scope, UninstallScope::All);
    }

    #[test]
    fn each_flag_sets_its_field() {
        let out = parse(&[
            "--dry-run",
            "--yes",
            "--keep-config",
            "--no-deep-sweep",
            "--no-path",
            "--json",
            "--verbose",
        ])
        .unwrap();
        assert!(
            out.dry_run
                && out.assume_yes
                && out.keep_config
                && out.no_deep_sweep
                && out.no_path
                && out.json
                && out.verbose
        );
    }

    #[test]
    fn verbose_short_form_maps() {
        assert!(parse(&["-v"]).unwrap().verbose);
    }

    #[test]
    fn hidden_service_helper_flag_parses_and_requires_a_name() {
        assert_eq!(
            parse(&["--remove-service-helper", "UffsAccessBroker"])
                .unwrap()
                .admin_helper_service
                .as_deref(),
            Some("UffsAccessBroker")
        );
        parse(&["--remove-service-helper"]).unwrap_err();
    }

    #[test]
    fn yes_aliases_all_map() {
        for tok in ["--yes", "--assume-yes", "-y"] {
            assert!(parse(&[tok]).unwrap().assume_yes, "alias {tok}");
        }
    }

    #[test]
    fn scope_spaced_and_equals_forms() {
        assert_eq!(
            parse(&["--scope", "user"]).unwrap().scope,
            UninstallScope::User
        );
        assert_eq!(
            parse(&["--scope=machine"]).unwrap().scope,
            UninstallScope::Machine
        );
        assert_eq!(
            parse(&["--scope", "all"]).unwrap().scope,
            UninstallScope::All
        );
    }

    #[test]
    fn scope_requires_a_value() {
        parse(&["--scope"]).unwrap_err();
    }

    #[test]
    fn invalid_scope_is_rejected() {
        parse(&["--scope", "everything"]).unwrap_err();
        parse(&["--scope=bogus"]).unwrap_err();
    }

    #[test]
    fn unknown_flag_is_rejected() {
        parse(&["--purge-the-universe"]).unwrap_err();
    }

    #[test]
    fn help_flag_both_forms() {
        assert!(parse(&["--help"]).unwrap().help);
        assert!(parse(&["-h"]).unwrap().help);
    }
}
