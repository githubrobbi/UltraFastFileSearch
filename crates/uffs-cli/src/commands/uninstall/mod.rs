// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `uffs --uninstall` — full removal of the UFFS family from the machine.
//!
//! Design + plan:
//! - `docs/dev/architecture/UFFS-Uninstall-Feasibility-and-Design.md`
//! - `docs/dev/architecture/UFFS-Uninstall-Implementation-Plan.md`
//!
//! This is the command entry point. M1 implements the read-only **analysis**
//! (the binary resolution table); the plan, consent, and removal phases land in
//! sibling modules as the later milestones progress.

mod analyze;
mod args;
#[cfg(windows)]
mod coverage;
mod effects;
mod inventory;
mod journal;
mod plan;
mod remove;
mod render;
mod resolve_order;
/// Deep-sweep for stray copies on the live drives — Windows-only (off Windows
/// UFFS indexes offline captures, not the live filesystem).
#[cfg(windows)]
mod sweep;
mod verify;

use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use args::UninstallArgs;
use plan::{PlanTarget, RemovalPlan};

/// Entry point for `uffs --uninstall`. `args` is every token after the
/// `--uninstall` command token.
///
/// # Errors
///
/// Propagates argument-parse failures (and, in later milestones, analysis and
/// removal failures).
pub(crate) fn run_uninstall(args: &[String]) -> Result<()> {
    let parsed = UninstallArgs::parse(args)?;
    if parsed.help {
        print_help();
        return Ok(());
    }
    // Hidden elevated-child mode (see `UninstallArgs::admin_helper_service`):
    // remove exactly the named service and exit. Spawned via UAC by the
    // effects layer's service-removal routing; never part of the interactive
    // flow.
    if let Some(service) = parsed.admin_helper_service.as_deref() {
        return run_admin_helper(service);
    }

    // M9 crash-awareness: if a prior uninstall was interrupted, say so. Because
    // removal is idempotent, this (re-)run simply completes it.
    if journal::was_interrupted() {
        render::print_resumed_note();
    }

    let (resolved, inventory, mut removal_plan) = analyze_and_plan(&parsed);

    if parsed.json {
        render::print_json(&resolved, &inventory, &removal_plan);
        return Ok(());
    }

    render::print_run_header();

    // `-v` also unlocks the deep-sweep diagnostics printed via
    // [`sweep::dbg_line`] during the stray search below.
    #[cfg(windows)]
    sweep::set_verbose(parsed.verbose);

    let gate = elevation_gate(&parsed, &mut removal_plan)?;
    let skipped_elevation: Vec<String> = match &gate {
        ElevationChoice::ContinueWithout(items) => items.clone(),
        ElevationChoice::NotNeeded | ElevationChoice::ElevateAtRemoval => Vec::new(),
    };

    // Scan overview: a one-line summary by default; the full binary resolution
    // table + artifact inventory under `-v`.
    if parsed.verbose {
        render::print_resolution_table(&resolved);
        render::print_inventory(&inventory);
    } else {
        render::print_scan_summary(&resolved, &inventory);
    }

    // M7 deep sweep: ask UFFS itself for stray family files elsewhere on the
    // live drives, version them, and build a separate plan removed only under
    // its own confirmation (one may be a copy the user placed themselves). This
    // is Windows-only — off Windows UFFS indexes offline captures, not the live
    // filesystem, so PATH/standard-location copies (already folded into the main
    // plan above) are all we can find.
    let stray_plan = platform_stray_plan(&parsed, &removal_plan);

    // The FINAL summary — everything is gathered, so say exactly what this run
    // will (and will not) do, then ask. The stray list printed just above by
    // the sweep is part of this picture.
    render::print_plan(&removal_plan);
    render::print_skipped_elevation(&skipped_elevation);
    if matches!(gate, ElevationChoice::ElevateAtRemoval) {
        render::print_uac_note();
    }

    if parsed.dry_run {
        if removal_plan.requires_elevation() && !uffs_mft::platform::is_elevated() {
            render::print_dry_run_elevation_note();
        }
        print_dry_run_footer();
        return Ok(());
    }

    // Nothing to remove at all: no install in the standard locations, and the
    // deep sweep found no strays.
    if removal_plan.is_empty() && stray_plan.is_empty() {
        return Ok(());
    }

    // Gather every decision UP FRONT, then execute once — never ask after
    // removal has started. The broker keep/skip was decided at the elevation
    // gate above. On Windows, decide the deep-sweep strays here too (a separate
    // opt-in: a copy you placed yourself may be among them).
    #[cfg(windows)]
    let remove_strays = !stray_plan.is_empty()
        && (parsed.assume_yes
            || confirm(&format!(
                "\nAlso remove the {} file(s) found elsewhere (listed above)? [y/N] ",
                stray_plan.item_count()
            ))?);

    // M4 consent (U-21): the final go. Declining aborts the whole uninstall.
    if !removal_plan.is_empty() && !parsed.assume_yes && !confirm("\nProceed with removal? [y/N] ")?
    {
        print_aborted();
        return Ok(());
    }

    // M9: mark the run in progress (survives the lifecycle-dir deletion) so an
    // interruption is detectable next launch. Best-effort: a failed marker write
    // must not block the uninstall, but we surface it honestly.
    if let Err(err) = journal::begin() {
        render::print_journal_warning(&err);
    }

    // The running uffs.exe (+ uffs-update.exe) are locked by the OS, so the
    // executor must SKIP them in place — deleting them directly is the "access
    // denied" the user hits — and a deferred [`schedule_self_delete`] removes
    // them after this process exits.
    let self_paths = self_binaries();

    // M4 execute (U-40..42): run the plan(s) once against the live effects sink,
    // accumulating a single outcome so the summary + retry hint print once.
    let mut effects = effects::SystemEffects::new(
        self_paths.clone(),
        matches!(gate, ElevationChoice::ElevateAtRemoval),
    );
    let mut outcome = remove::RemovalOutcome::default();
    if !removal_plan.is_empty() {
        outcome.absorb(remove::execute(&removal_plan, &mut effects));
    }
    #[cfg(windows)]
    if remove_strays {
        outcome.absorb(remove::execute(&stray_plan, &mut effects));
    }
    if !outcome.is_empty() {
        render::print_outcome(&outcome);
    }
    #[cfg(windows)]
    if !stray_plan.is_empty() && !remove_strays {
        render::print_strays_kept();
    }

    // M8 self-delete (U-80): finish the deferred delete of the running
    // self-binaries the executor skipped. If even scheduling fails, say so.
    if !self_paths.is_empty() {
        render::print_self_delete_scheduled(&self_paths);
        if let Err(err) = effects::schedule_self_delete(&self_paths) {
            render::print_self_delete_warning(&err);
        }
    }

    // M8 verify (U-81): confirm the targeted locations are gone, excluding the
    // reboot-deferred self-binaries handled above.
    let to_check: Vec<PathBuf> = plan_dirs(&removal_plan)
        .into_iter()
        .filter(|dir| {
            !self_paths
                .iter()
                .any(|self_path| self_path.starts_with(dir))
        })
        .collect();
    render::print_verification(&verify::still_present(&to_check));

    // M9: clear the in-progress marker now the run finished.
    if let Err(err) = journal::finish() {
        render::print_journal_warning(&err);
    }
    Ok(())
}

/// M1+M2 analysis (read-only, no output): reuse the self-update Phase-A
/// detection, sweep in PATH/standard-location copies and retired/optional
/// binary names lingering from old installs, inventory the non-binary
/// artifacts, and build the ordered removal plan. Only PATH entries pointing
/// at a *dedicated* UFFS dir are offered for removal — a shared bin dir
/// (`~/bin`, `~/.local/bin`) we never created is left alone.
fn analyze_and_plan(
    parsed: &UninstallArgs,
) -> (
    Vec<resolve_order::StemResolution>,
    inventory::Inventory,
    RemovalPlan,
) {
    let mut report = crate::commands::update::detect();
    analyze::augment_with_path_locations(&mut report);
    analyze::augment_with_extra_binaries(&mut report);
    let candidates = analyze::build_candidates(&report);
    let resolved = resolve_order::group_and_resolve(&candidates, &analyze::search_dirs());
    let inventory = inventory::collect();
    let removable_path = analyze::removable_path_dirs(&report, &analyze::path_entries());
    let removal_plan = plan::build_plan(&report, &inventory, parsed, &removable_path);
    (resolved, inventory, removal_plan)
}

/// What the elevation gate decided for this run.
enum ElevationChoice {
    /// Elevated, `--dry-run`, or nothing needs Administrator — plan untouched.
    NotNeeded,
    /// Windows, non-elevated: keep the admin items in the plan; removal routes
    /// them through a one-shot elevated helper (a single UAC prompt at removal
    /// time — see [`effects`]).
    #[cfg_attr(
        not(windows),
        expect(dead_code, reason = "constructed only on the Windows UAC path")
    )]
    ElevateAtRemoval,
    /// Non-elevated, continuing without the admin items: they are dropped from
    /// the plan; carries their descriptions for the final summary's "NOT
    /// removed in this run" note.
    ContinueWithout(Vec<String>),
}

/// M3 elevation gate (U-30): THE FIRST question, before any analysis output.
/// The broker (its `LocalSystem` service) is the only admin-only part; a
/// non-elevated run is told immediately what needs Administrator and decides
/// once — elevate at removal time (Windows: one UAC prompt), continue without
/// (items dropped so the final summary never lists work that will not happen),
/// or abort. Skipped when elevated, under `--dry-run` (preview keeps the
/// markers), or when nothing needs Administrator. `--yes` continues without
/// asking — a scripted run must never trigger a surprise UAC prompt.
/// `uffs_mft::platform::is_elevated` is cross-platform (Windows token check;
/// Unix effective-uid 0).
fn elevation_gate(
    parsed: &UninstallArgs,
    removal_plan: &mut RemovalPlan,
) -> Result<ElevationChoice> {
    if parsed.dry_run || !removal_plan.requires_elevation() || uffs_mft::platform::is_elevated() {
        return Ok(ElevationChoice::NotNeeded);
    }
    render::print_elevation_gate(removal_plan);
    if parsed.assume_yes {
        return Ok(ElevationChoice::ContinueWithout(
            removal_plan.drop_elevation_required(),
        ));
    }
    platform_elevation_choice(removal_plan)
}

/// Windows: the interactive 3-way elevation choice. `e` records the decision —
/// the single UAC prompt appears later, when removal actually starts, so
/// nothing is elevated before the final confirmation.
#[cfg(windows)]
fn platform_elevation_choice(removal_plan: &mut RemovalPlan) -> Result<ElevationChoice> {
    let choice = prompt_choice(
        "\n  e = elevate at removal time (Windows shows one UAC prompt)\n\
         \x20 c = continue without it (the item(s) above stay installed)\n\
         \x20 a = abort\n\
         Choice [e/c/A]: ",
    )?;
    match choice.as_str() {
        "e" | "elevate" => Ok(ElevationChoice::ElevateAtRemoval),
        "c" | "continue" => Ok(ElevationChoice::ContinueWithout(
            removal_plan.drop_elevation_required(),
        )),
        _ => bail!(
            "aborted — re-run `uffs --uninstall` from an elevated (Administrator) terminal to remove everything"
        ),
    }
}

/// Non-Windows: there is no UAC to request, so the choice stays binary —
/// continue without the elevation-required items, or abort to re-run elevated.
#[cfg(not(windows))]
fn platform_elevation_choice(removal_plan: &mut RemovalPlan) -> Result<ElevationChoice> {
    if confirm(
        "\nContinue without elevation? Everything else is still uninstalled; the\n\
         item(s) above are left in place. (No aborts so you can re-run elevated) [y/N] ",
    )? {
        Ok(ElevationChoice::ContinueWithout(
            removal_plan.drop_elevation_required(),
        ))
    } else {
        bail!("aborted — re-run `uffs --uninstall` elevated (sudo) to remove everything")
    }
}

/// Read one line of input for a multi-choice prompt, trimmed and lowercased.
#[cfg(windows)]
#[expect(clippy::print_stdout, reason = "interactive CLI prompt")]
fn prompt_choice(prompt: &str) -> Result<String> {
    use std::io::Write as _;

    print!("{prompt}");
    std::io::stdout()
        .flush()
        .context("flushing the choice prompt")?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading the choice")?;
    Ok(line.trim().to_ascii_lowercase())
}

/// Hidden `--remove-service-helper` mode: the elevated child spawned (via a UAC
/// prompt) by [`effects`]' service-removal routing. Performs exactly the same
/// removal the elevated in-process path uses, then exits; refuses to run
/// non-elevated as a guard against direct invocation.
fn run_admin_helper(service: &str) -> Result<()> {
    if !uffs_mft::platform::is_elevated() {
        bail!(
            "--remove-service-helper must run elevated (it is spawned via a UAC prompt by `uffs --uninstall`)"
        );
    }
    effects::remove_windows_service(service)
}

/// The running self-binaries that cannot be deleted in place: the current
/// `uffs` executable and its sibling `uffs-update`.
fn self_binaries() -> Vec<PathBuf> {
    let Ok(raw_exe) = std::env::current_exe() else {
        return Vec::new();
    };
    // Match the verbatim-stripped form the plan carries, so the executor's
    // self-skip and the verify exclusion compare equal.
    let exe = crate::commands::update::strip_verbatim_prefix(raw_exe);
    let mut paths = vec![exe.clone()];
    if let Some(dir) = exe.parent() {
        let updater = if cfg!(windows) {
            "uffs-update.exe"
        } else {
            "uffs-update"
        };
        paths.push(dir.join(updater));
    }
    paths
}

/// The directories the plan acts on, used to dedup deep-sweep hits (a stray
/// already inside a planned dir is not a separate finding).
fn plan_dirs(plan: &RemovalPlan) -> Vec<PathBuf> {
    plan.items()
        .filter_map(|item| match &item.target {
            PlanTarget::DeleteBinaries { dir, .. }
            | PlanTarget::DelegateWinget { dir, .. }
            | PlanTarget::RemovePathEntry { dir } => Some(dir.clone()),
            PlanTarget::DeleteDir { path, .. } => Some(path.clone()),
            #[cfg(windows)]
            PlanTarget::DeleteFile { .. } => None,
            PlanTarget::StopProcess { .. } | PlanTarget::RemoveService { .. } => None,
        })
        .collect()
}

/// Build the deep-sweep stray plan for the current platform.
///
/// Windows: ensure the daemon covers every NTFS drive (offering to start it /
/// index the missing drives), then ask UFFS for stray copies outside the known
/// roots and present them for a separate confirmation. The coverage offer runs
/// under `--dry-run` too — starting the daemon and indexing drives are
/// non-destructive, and a dry run should preview the *complete* picture; only
/// the deletions themselves are withheld (the caller returns before executing).
#[cfg(windows)]
fn platform_stray_plan(parsed: &UninstallArgs, removal_plan: &RemovalPlan) -> RemovalPlan {
    if parsed.no_deep_sweep {
        return RemovalPlan::default();
    }
    // Indexing every drive is a non-elevated, non-destructive read the sweep
    // needs, so it always runs (no prompt) — including under --dry-run, to make
    // the preview accurate.
    coverage::ensure_drive_coverage();
    let known = plan_dirs(removal_plan);
    let mut search = sweep::DaemonSearch;

    let find_started = std::time::Instant::now();
    let candidates = sweep::find_strays(&mut search, &known).unwrap_or_default();
    sweep::dbg_line(&format!(
        "found {} candidate file(s) in {:.2?} (after filtering)",
        candidates.len(),
        find_started.elapsed()
    ));

    let probe_started = std::time::Instant::now();
    let strays = sweep::version_strays(&candidates);
    sweep::dbg_line(&format!(
        "versioned {} stray(s) in {:.2?}",
        strays.len(),
        probe_started.elapsed()
    ));

    render::print_strays(&strays);
    plan::build_stray_plan(&strays)
}

/// Build the deep-sweep stray plan for the current platform.
///
/// Off Windows the daemon indexes offline captures, not the live filesystem, so
/// it cannot find local stray binaries; PATH/standard-location copies are
/// already folded into the main plan, leaving no separate stray phase.
#[cfg(not(windows))]
fn platform_stray_plan(_parsed: &UninstallArgs, _removal_plan: &RemovalPlan) -> RemovalPlan {
    RemovalPlan::default()
}

/// Prompt for a yes/no confirmation. Default (empty / anything but `y`/`yes`)
/// is **No**. `prompt` is written verbatim (caller includes any leading
/// newline).
#[expect(clippy::print_stdout, reason = "interactive CLI prompt")]
fn confirm(prompt: &str) -> Result<bool> {
    use std::io::Write as _;

    print!("{prompt}");
    std::io::stdout()
        .flush()
        .context("flushing the confirmation prompt")?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading confirmation")?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Footer printed after a `--dry-run` plan.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_dry_run_footer() {
    println!("\nDry run: nothing was removed.");
}

/// Message printed when the user declines the confirmation.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn print_aborted() {
    println!("Aborted. Nothing was removed.");
}

/// Print `uffs --uninstall` usage.
#[expect(clippy::print_stdout, reason = "intentional help output")]
fn print_help() {
    println!(
        "uffs --uninstall — remove UFFS and all of its data from this machine\n\
         \n\
         USAGE:\n\
         \x20 uffs --uninstall [flags]\n\
         \n\
         FLAGS:\n\
         \x20 --dry-run         Show the analysis + removal plan, change nothing\n\
         \x20 --yes, -y         Skip the confirmation prompt\n\
         \x20 --keep-config     Remove binaries + caches but keep settings/config\n\
         \x20 --no-deep-sweep   Skip the cross-drive search for stray UFFS files\n\
         \x20 --no-path         Do not edit PATH (print a manual hint instead)\n\
         \x20 --scope <s>       Restrict to user | machine | all (default: all)\n\
         \x20 --json            Emit the analysis + plan as JSON\n\
         \x20 --verbose, -v     Show the full binary table, inventory, and sweep detail\n\
         \x20 --help, -h        Show this help"
    );
}
