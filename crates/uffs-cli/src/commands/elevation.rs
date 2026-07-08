// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Shared elevation gate for the mutating flows (`uffs --uninstall`,
//! `uffs --update`).
//!
//! A non-elevated run that has admin-only work is told **up front** what needs
//! Administrator and decides once. Surfacing this before any mutation is what
//! keeps a flow from failing halfway through. Both flows drive this identically
//! so their elevation UX stays in lockstep.
//!
//! The one difference is whether the flow can elevate **in place**:
//!
//! - `uffs --uninstall` has a one-shot elevated helper it spawns via a single
//!   UAC prompt at removal time, so on Windows it offers a 3-way choice —
//!   elevate now / continue without / abort (`offer_inflow_elevation = true`).
//! - `uffs --update` has no in-flow elevation (and `winget` itself *refuses* to
//!   upgrade a user package elevated), so its elevated path is simply "re-run
//!   elevated" and the choice stays binary (`offer_inflow_elevation = false`).
//!
//! Non-Windows has no UAC to request, so the choice is always binary there.

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
    /// The mutating action — `"removal"` / `"update"` — used in
    /// "elevate at &lt;action&gt; time" (only on the in-flow-elevation prompt).
    #[cfg_attr(
        not(windows),
        expect(
            dead_code,
            reason = "read only by the Windows in-flow-elevation prompt"
        )
    )]
    pub(crate) action: &'static str,
    /// The command to re-run elevated — `"uffs --uninstall"` / `"uffs
    /// --update"`.
    pub(crate) rerun_cmd: &'static str,
}

/// What the elevation gate decided for this run.
pub(crate) enum ElevationChoice {
    /// Elevated, dry-run, or nothing needs Administrator — plan untouched.
    NotNeeded,
    /// Windows in-flow elevation: keep the admin items; the mutating step
    /// routes them through a one-shot elevated helper (a single UAC
    /// prompt). Produced only when the caller offers in-flow elevation AND
    /// on Windows.
    #[cfg_attr(
        not(windows),
        expect(dead_code, reason = "constructed only on the Windows in-flow-UAC path")
    )]
    ElevateLater,
    /// Continuing without the admin items: they were dropped from the plan;
    /// carries their descriptions for the final summary.
    ContinueWithout(Vec<String>),
}

/// The elevation gate — the first question, before any mutation. Returns
/// [`ElevationChoice::NotNeeded`] when elevated, under `dry_run`, or when
/// nothing needs Administrator. `assume_yes` continues without asking (a
/// scripted run must never block on a prompt it cannot answer, nor trigger a
/// surprise UAC). `offer_inflow_elevation` enables the Windows 3-way choice for
/// flows that can elevate in place.
///
/// # Errors
///
/// Propagates a prompt I/O error, or aborts (bails) when the user declines.
pub(crate) fn elevation_gate(
    plan: &mut impl ElevatablePlan,
    dry_run: bool,
    assume_yes: bool,
    offer_inflow_elevation: bool,
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
    platform_elevation_choice(plan, offer_inflow_elevation, wording)
}

/// Windows: the 3-way choice when the flow can elevate in place (`e` records
/// the decision — the single UAC prompt appears later, when the mutating step
/// runs); otherwise the binary continue-without / abort.
#[cfg(windows)]
fn platform_elevation_choice(
    plan: &mut impl ElevatablePlan,
    offer_inflow_elevation: bool,
    wording: &GateWording,
) -> Result<ElevationChoice> {
    if !offer_inflow_elevation {
        return binary_choice(plan, wording);
    }
    let choice = prompt_line(&format!(
        "\n  e = elevate at {} time (Windows shows one UAC prompt)\n\
         \x20 c = continue without it (the item(s) above are left as-is)\n\
         \x20 a = abort\n\n\
         Choice [e/c/A]: ",
        wording.action,
    ))?;
    match choice.as_str() {
        "e" | "elevate" => Ok(ElevationChoice::ElevateLater),
        "c" | "continue" => Ok(ElevationChoice::ContinueWithout(
            plan.drop_elevation_required(),
        )),
        _ => bail!(
            "aborted — re-run `{}` from an elevated (Administrator) terminal to include the item(s) above",
            wording.rerun_cmd
        ),
    }
}

/// Non-Windows: there is no UAC to request, so the choice is always binary.
#[cfg(not(windows))]
fn platform_elevation_choice(
    plan: &mut impl ElevatablePlan,
    _offer_inflow_elevation: bool,
    wording: &GateWording,
) -> Result<ElevationChoice> {
    binary_choice(plan, wording)
}

/// The continue-without / abort choice (no in-flow elevation available).
fn binary_choice(plan: &mut impl ElevatablePlan, wording: &GateWording) -> Result<ElevationChoice> {
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
