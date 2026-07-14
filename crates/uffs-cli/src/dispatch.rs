// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! First-token command dispatch for `uffs` (design:
//! `docs/architecture/cli-grammar.md`).
//!
//! UFFS is **search-first**: `uffs <anything>` searches for `<anything>`.
//! The first token decides the mode — a known `--command` runs that command;
//! anything else (bare word, glob, single dash, or a search flag) is a
//! search. The command set is deliberately **disjoint** from every
//! search-flag long name, so `uffs --ext pdf` is a (pattern-less) search
//! while `uffs --update` is the updater.

use anyhow::Result;

use crate::commands;

/// A management command — the ONLY first tokens that switch `uffs` out of
/// search mode. Every variant's token is `--<command>` and is disjoint from
/// every search-flag long name (`--sort`, `--ext`, `--drive`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    /// Explicit search (the bare positional default also routes here).
    Search,
    /// `--stats [path]`.
    Stats,
    /// `--agg <preset>`.
    Agg,
    /// `--deleted --mft-file <path>`.
    Deleted,
    /// `--snapshot --drive C --out <file>`.
    Snapshot,
    /// `--daemon <action>`.
    Daemon,
    /// `--mcp <action>`.
    Mcp,
    /// `--update [action]`.
    Update,
    /// `--uninstall [flags]`.
    Uninstall,
    /// `--status`.
    Status,
}

impl Command {
    /// Map a first token to its [`Command`], or `None` when it is not a
    /// management command (→ the token is treated as a search pattern/flag).
    pub(crate) fn from_token(token: &str) -> Option<Self> {
        Some(match token {
            "--search" => Self::Search,
            "--stats" => Self::Stats,
            "--agg" | "--aggregate" => Self::Agg,
            "--deleted" => Self::Deleted,
            "--snapshot" => Self::Snapshot,
            "--daemon" => Self::Daemon,
            "--mcp" => Self::Mcp,
            // `--upgrade` is a HIDDEN alias for `--update` (winget/apt muscle
            // memory) — deliberately absent from `COMMAND_TOKENS`, so it never
            // appears in help or "did you mean" suggestions.
            "--update" | "--upgrade" => Self::Update,
            "--uninstall" => Self::Uninstall,
            "--status" => Self::Status,
            _ => return None,
        })
    }
}

/// Every command token (incl. the `--aggregate` alias) — the canonical set
/// the CLI suggests over for a `--`-flag typo. Kept in lock-step with
/// [`Command::from_token`] by `command_tokens_all_resolve` (test).
const COMMAND_TOKENS: &[&str] = &[
    "--search",
    "--stats",
    "--agg",
    "--aggregate",
    "--deleted",
    "--snapshot",
    "--daemon",
    "--mcp",
    "--update",
    "--uninstall",
    "--status",
];

/// Maximum edit distance for a `--`-flag typo to be read as a command miss.
/// `2` catches a one- or two-character slip (`--updat`, `--statu`, `--mc`)
/// while leaving an unrelated unknown flag (`--bogus`) without a (wrong)
/// command suggestion.
const MAX_COMMAND_TYPO_DISTANCE: usize = 2;

/// If `flag` (a `--`-token the shared search parser already **rejected** as
/// an unknown flag) is a near-miss of a management command, return that
/// command token. The CLI suggests over its **own** command set only —
/// search-flag validation stays in `uffs-client::from_cli_args`, so the
/// daemon never learns CLI commands.
///
/// Returns the closest command within [`MAX_COMMAND_TYPO_DISTANCE`], or
/// `None` when nothing is close enough (→ the parser's flag error stands).
pub(crate) fn suggest_command(flag: &str) -> Option<&'static str> {
    COMMAND_TOKENS
        .iter()
        .map(|cmd| (*cmd, strsim::levenshtein(flag, cmd)))
        .filter(|&(_, dist)| dist <= MAX_COMMAND_TYPO_DISTANCE)
        .min_by_key(|&(_, dist)| dist)
        .map(|(cmd, _)| cmd)
}

/// Dispatch a resolved [`Command`] to its handler. `args` is everything
/// after the `--<command>` token.
///
/// # Errors
///
/// Propagates the underlying command's failure.
pub(crate) fn dispatch_command(command: Command, args: &[String]) -> Result<()> {
    match command {
        Command::Search => crate::run_search(args),
        Command::Stats => crate::run_stats(args),
        Command::Agg => crate::run_aggregate(args),
        Command::Deleted => commands::deleted::run_deleted(args),
        Command::Snapshot => commands::snapshot::run_snapshot(args),
        Command::Daemon => crate::run_daemon(args),
        Command::Mcp => commands::mcp_mgmt::mcp_from_args(args),
        Command::Update => commands::update::run_update(args),
        Command::Uninstall => commands::uninstall::run_uninstall(args),
        Command::Status => {
            run_status(args);
            Ok(())
        }
    }
}

/// `--status [-v] [--json]` — combined daemon + broker + MCP status (never
/// fails). `-v`/`--verbose` expands every section; `--json` emits the
/// machine-readable superset.
fn run_status(args: &[String]) {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        crate::args::print_status_help();
        return;
    }
    let verbose = args.iter().any(|arg| arg == "-v" || arg == "--verbose");
    let json = args.iter().any(|arg| arg == "--json");
    commands::system_status::system_status(verbose, json);
}

#[cfg(test)]
mod tests {
    use super::Command;

    #[test]
    fn command_tokens_resolve() {
        assert_eq!(Command::from_token("--update"), Some(Command::Update));
        // Hidden alias: resolves, but is not in COMMAND_TOKENS (so it never
        // appears in help or "did you mean" suggestions).
        assert_eq!(Command::from_token("--upgrade"), Some(Command::Update));
        assert!(!super::COMMAND_TOKENS.contains(&"--upgrade"));
        assert_eq!(Command::from_token("--uninstall"), Some(Command::Uninstall));
        assert_eq!(Command::from_token("--daemon"), Some(Command::Daemon));
        assert_eq!(Command::from_token("--mcp"), Some(Command::Mcp));
        assert_eq!(Command::from_token("--stats"), Some(Command::Stats));
        assert_eq!(Command::from_token("--agg"), Some(Command::Agg));
        assert_eq!(Command::from_token("--aggregate"), Some(Command::Agg));
        assert_eq!(Command::from_token("--status"), Some(Command::Status));
        assert_eq!(Command::from_token("--search"), Some(Command::Search));
    }

    #[test]
    fn bare_and_single_dash_tokens_are_patterns_not_commands() {
        // The whole point of the grammar: the old reserved words are
        // searchable again, and single-dash tokens stay patterns.
        for pattern in [
            "update", "status", "daemon", "mcp", "stats", "agg", "report", "help", "version",
            "-update", "*.pdf", "-x",
        ] {
            assert_eq!(
                Command::from_token(pattern),
                None,
                "`{pattern}` must be a search pattern, not a command"
            );
        }
    }

    #[test]
    fn flag_only_names_are_never_commands() {
        // Position invariant (cli-grammar.md §3.2): a *flag-only* name as the
        // FIRST token stays in search mode (e.g. `uffs --ext pdf` is a
        // pattern-less search), so it must never resolve to a command.
        //
        // NOTE: `--stats` and `--agg` are deliberately ABSENT here — they are
        // the two dual-use names (command as first token, search modifier
        // later), pinned by `dual_use_names_are_commands_as_first_token`.
        // Do not add them to this list.
        for flag in [
            "--ext",
            "--sort",
            "--drive",
            "--limit",
            "--format",
            "--tz-offset",
            "--out",
            "--no-output",
            "--profile",
            "--agg-format",
        ] {
            assert_eq!(
                Command::from_token(flag),
                None,
                "search flag `{flag}` must NOT be a management command"
            );
        }
    }

    #[test]
    fn dual_use_names_are_commands_as_first_token() {
        // `--stats` / `--agg` are BOTH commands (first token) and inline search
        // modifiers (after a pattern). The grammar resolves this by position:
        // as the first token they are their command. Pin that here so the
        // dual-use contract (cli-grammar.md §3.2) can't silently regress.
        assert_eq!(Command::from_token("--stats"), Some(Command::Stats));
        assert_eq!(Command::from_token("--agg"), Some(Command::Agg));
    }

    #[test]
    fn command_tokens_all_resolve() {
        // The suggestion set must stay in lock-step with the dispatcher:
        // every COMMAND_TOKENS entry (incl. the `--aggregate` alias) must
        // resolve via `from_token`, so a typo can never suggest a token the
        // grammar would not actually accept.
        for token in super::COMMAND_TOKENS {
            assert!(
                Command::from_token(token).is_some(),
                "`{token}` is in COMMAND_TOKENS but is not a dispatchable command"
            );
        }
    }

    #[test]
    fn suggest_command_maps_near_misses() {
        // One- or two-character slips map to their command.
        assert_eq!(super::suggest_command("--updat"), Some("--update"));
        assert_eq!(super::suggest_command("--daemo"), Some("--daemon"));
        assert_eq!(super::suggest_command("--mc"), Some("--mcp"));
        assert_eq!(super::suggest_command("--searc"), Some("--search"));
    }

    #[test]
    fn suggest_command_ignores_unrelated_or_valid_flags() {
        // An unrelated unknown flag has no close command → no (wrong) hint;
        // and a real search flag must not be mistaken for a command typo.
        for token in ["--bogus", "--ext", "--sort", "--newer-created", "--xyz"] {
            assert_eq!(
                super::suggest_command(token),
                None,
                "`{token}` must not be suggested as a command typo"
            );
        }
    }
}
