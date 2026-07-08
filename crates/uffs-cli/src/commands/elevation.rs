// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Shared elevation gate for the mutating flows.
//!
//! A non-elevated run that has admin-only work is told **up front** what needs
//! Administrator and decides once — continue without the admin items (they are
//! dropped so the summary never lists work that will not happen), or abort and
//! re-run from an elevated terminal. Surfacing this before any mutation is what
//! keeps a flow from failing halfway through (the uninstall flow pioneered it;
//! `uffs --update` reuses this gate so both behave alike).
//!
//! Unlike the uninstall flow — which has a one-shot elevated helper it can
//! spawn via a single UAC prompt at removal time — the update flow has no
//! in-flow elevation (and `winget` itself *refuses* to upgrade a user package
//! from an elevated shell), so the elevated path here is simply "re-run
//! elevated". The choice is therefore binary on every platform.

use anyhow::{Context as _, Result, bail};

/// A plan the elevation gate can reason about: some of its work needs
/// Administrator, and those items can be dropped to "continue without".
pub(crate) trait ElevatablePlan {
    /// Whether any item in the plan needs elevation.
    fn requires_elevation(&self) -> bool;

    /// Drop the elevation-requiring items, returning their human-readable
    /// descriptions (for the "not done in this run" summary).
    fn drop_elevation_required(&mut self) -> Vec<String>;

    /// Print the flow-specific "these items need Administrator" preamble.
    fn render_elevation_needed(&self);
}

/// Flow-specific wording woven into the gate prompt.
pub(crate) struct GateWording {
    /// The command to re-run elevated — `"uffs --update"` / `"uffs
    /// --uninstall"`.
    pub(crate) rerun_cmd: &'static str,
}

/// What the elevation gate decided for this run.
pub(crate) enum ElevationChoice {
    /// Elevated, dry-run, or nothing needs Administrator — plan untouched.
    NotNeeded,
    /// Continuing without the admin items: they were dropped from the plan;
    /// carries their descriptions for the final summary.
    ContinueWithout(Vec<String>),
}

/// The elevation gate — the first question, before any mutation. Returns
/// [`ElevationChoice::NotNeeded`] when elevated, under `dry_run`, or when
/// nothing needs Administrator. `assume_yes` continues without asking (a
/// scripted run must never block on a prompt it cannot answer).
///
/// # Errors
///
/// Propagates a prompt I/O error, or aborts (bails) when the user declines.
pub(crate) fn elevation_gate(
    plan: &mut impl ElevatablePlan,
    dry_run: bool,
    assume_yes: bool,
    wording: &GateWording,
) -> Result<ElevationChoice> {
    if dry_run || !plan.requires_elevation() || uffs_mft::platform::is_elevated() {
        return Ok(ElevationChoice::NotNeeded);
    }
    plan.render_elevation_needed();
    if assume_yes {
        return Ok(ElevationChoice::ContinueWithout(
            plan.drop_elevation_required(),
        ));
    }
    let choice = prompt_line(
        "\n  c = continue without it (the item(s) above are left as-is)\n\
         \x20 a = abort\n\n\
         Choice [c/A]: ",
    )?;
    match choice.as_str() {
        "c" | "continue" => Ok(ElevationChoice::ContinueWithout(
            plan.drop_elevation_required(),
        )),
        _ => bail!(
            "aborted — re-run `{}` from an elevated (Administrator) terminal to include the item(s) above",
            wording.rerun_cmd
        ),
    }
}

/// Read a line from stdin after printing `prompt`, trimmed + lowercased.
///
/// # Errors
///
/// Fails if stdout cannot be flushed or stdin cannot be read.
#[expect(clippy::print_stdout, reason = "interactive CLI prompt")]
fn prompt_line(prompt: &str) -> Result<String> {
    use std::io::Write as _;
    print!("{prompt}");
    std::io::stdout().flush().context("flushing the prompt")?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading input")?;
    Ok(line.trim().to_ascii_lowercase())
}
