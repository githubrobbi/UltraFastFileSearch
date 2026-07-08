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

use crate::commands::elevation::{self, ElevatablePlan as _, ElevationChoice};

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
    // [`sweep::dbg_line`] during the stray search.
    #[cfg(windows)]
    sweep::set_verbose(parsed.verbose);

    // The deep-sweep decision comes first: a broker-less, non-elevated sweep
    // needs the user to opt into a UAC daemon start (or skip the sweep).
    #[cfg(windows)]
    let sweep = sweep_decision(&parsed)?;

    // Overlap the slow work with the user's next decision: the drive-coverage
    // reload + deep sweep start (quietly) in the background right away, while
    // the elevation question is on screen. `-v` runs sequentially instead so
    // its live diagnostics stay readable.
    #[cfg(windows)]
    let gather = start_stray_gather(&parsed, &removal_plan, sweep);

    let gate = elevation_gate(&parsed, &mut removal_plan)?;
    let skipped_elevation: Vec<String> = match &gate {
        ElevationChoice::ContinueWithout(items) => items.clone(),
        ElevationChoice::NotNeeded | ElevationChoice::ElevateLater => Vec::new(),
    };

    // Wait for the gather (spinner) / run it now (`-v`), then present the
    // COMPLETE picture at once: CORE table + inventory, EXTRA table, the action
    // plan, and the gate notes. Nothing was shown while data was in flight.
    #[cfg(windows)]
    let gathered = finish_stray_gather(&removal_plan, gather, sweep);
    // The deep sweep may have STARTED the daemon (the no-broker UAC start) after
    // the plan was snapshotted with none running — make sure the plan stops that
    // live daemon before its binary is deleted, or its locked image would fail
    // the runtime-binary delete with Access-denied.
    #[cfg(windows)]
    if let Some(pid) = running_daemon_pid() {
        removal_plan.ensure_daemon_shutdown(pid);
    }
    #[cfg(windows)]
    let stray_plan = &gathered.stray_plan;
    #[cfg(not(windows))]
    let no_strays = RemovalPlan::default();
    #[cfg(not(windows))]
    let stray_plan = &no_strays;

    #[cfg(windows)]
    render::print_coverage_notes(&gathered.coverage_notes);
    render::print_inventory(&inventory);
    render::print_resolution_table(&resolved);
    #[cfg(windows)]
    render::print_extra_table(&gathered.strays);
    render::print_plan(&removal_plan, stray_plan);
    render::print_skipped_elevation(&skipped_elevation);
    if matches!(gate, ElevationChoice::ElevateLater) {
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

    // The single end-of-flow decision (design: decide -> gather -> present ->
    // confirm). Every choice was collected before anything is touched.
    let choice = final_consent(&parsed, &removal_plan, stray_plan)?;
    if matches!(choice, FinalChoice::Abort) {
        print_aborted();
        return Ok(());
    }
    let remove_strays = matches!(choice, FinalChoice::All) && !stray_plan.is_empty();
    // The broker service stays installed whenever the plan won't remove it (the
    // non-elevated "continue without" choice dropped it), so its binary is
    // locked and must be LEFT, not fought. A declined UAC on the `e` path is
    // detected during execution.
    let broker_remains = matches!(
        inventory.broker_service,
        inventory::BrokerServiceState::Installed
    ) && !removal_plan
        .items()
        .any(|item| matches!(item.target, PlanTarget::RemoveService { .. }));
    execute_all(
        &removal_plan,
        stray_plan,
        remove_strays,
        matches!(gate, ElevationChoice::ElevateLater),
        broker_remains,
    );
    Ok(())
}

/// M4/M8/M9 execution: journal the run, execute the consented plan(s) once
/// against the live effects sink, print the outcome, schedule the deferred
/// self-delete, and verify the targeted locations are gone. Runs only after
/// [`final_consent`] — no questions are asked past this point, and every
/// failure is reported (never propagated: the run always finishes its
/// best-effort pass).
fn execute_all(
    removal_plan: &RemovalPlan,
    stray_plan: &RemovalPlan,
    remove_strays: bool,
    elevate_via_uac: bool,
    broker_remains: bool,
) {
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
    let mut effects =
        effects::SystemEffects::new(self_paths.clone(), elevate_via_uac, broker_remains);
    let mut outcome = remove::RemovalOutcome::default();
    if !removal_plan.is_empty() {
        outcome.absorb(remove::execute(removal_plan, &mut effects, broker_remains));
    }
    if remove_strays {
        // Strays are loose files, never the broker service's binary.
        outcome.absorb(remove::execute(stray_plan, &mut effects, false));
    }
    if !outcome.is_empty() {
        render::print_outcome(&outcome);
    }
    if !stray_plan.is_empty() && !remove_strays {
        render::print_strays_kept();
    }

    // M8 self-delete (U-80): finish the deferred delete of the running
    // self-binaries the executor skipped. If even scheduling fails, say so.
    // When the running uffs.exe is INSIDE the winget package, the deferred
    // `winget uninstall` owns deleting the whole package dir (self included)
    // — running the plain del script too would race winget over the same
    // files, so it is skipped in favour of the owner-driven cleanup.
    if effects.winget_deferred() {
        render::print_winget_deferred();
    } else if !self_paths.is_empty() {
        render::print_self_delete_scheduled();
        if let Err(err) = effects::schedule_self_delete(&self_paths) {
            render::print_self_delete_warning(&err);
        }
    }

    // M8 verify (U-81): confirm the targeted locations are gone, excluding the
    // reboot-deferred self-binaries handled above.
    let to_check: Vec<PathBuf> = plan_dirs(removal_plan)
        .into_iter()
        .filter(|dir| {
            !self_paths
                .iter()
                .any(|self_path| self_path.starts_with(dir))
        })
        .collect();
    render::print_verification(&verify::still_present(&to_check), outcome.is_clean());

    // M9: clear the in-progress marker now the run finished.
    if let Err(err) = journal::finish() {
        render::print_journal_warning(&err);
    }
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
    let mut removal_plan = plan::build_plan(&report, &inventory, parsed, &removable_path);
    // Fold each binary's on-disk size into the plan (statting is IO the pure
    // plan module leaves to us), so the "Reclaims ~N" line counts the binaries,
    // not just the data dirs.
    removal_plan.size_binaries(binary_dir_bytes);
    (resolved, inventory, removal_plan)
}

/// Best-effort total on-disk size of the named binary stems inside `dir`
/// (`uffsd` -> `uffsd.exe` on Windows). An absent / unreadable file contributes
/// 0 — sizing must never fail the plan.
fn binary_dir_bytes(dir: &std::path::Path, stems: &[String]) -> u64 {
    stems
        .iter()
        .map(|stem| {
            std::fs::metadata(dir.join(effects::exe_file_name(stem))).map_or(0, |meta| meta.len())
        })
        .fold(0, u64::saturating_add)
}

/// M3 elevation gate (U-30): THE FIRST question, before any analysis output.
/// Delegates to the shared [`elevation`] gate. The broker (its `LocalSystem`
/// service) is the only admin-only part, and uninstall CAN elevate **in place**
/// — a one-shot elevated helper at removal time (one UAC prompt) — so it offers
/// the Windows 3-way choice (`offer_inflow_elevation = true`). Skipped when
/// elevated, under `--dry-run`, or when nothing needs Administrator; `--yes`
/// continues without asking (a scripted run never triggers a surprise UAC).
fn elevation_gate(
    parsed: &UninstallArgs,
    removal_plan: &mut RemovalPlan,
) -> Result<ElevationChoice> {
    elevation::elevation_gate(
        removal_plan,
        parsed.dry_run,
        parsed.assume_yes,
        true,
        &elevation::GateWording {
            action: "removal",
            rerun_cmd: "uffs --uninstall",
        },
    )
}

/// Read one line of input for a multi-choice prompt, trimmed and lowercased.
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

/// The up-front deep-sweep decision. Windows-only.
#[cfg(windows)]
#[derive(Clone, Copy)]
enum SweepDecision {
    /// Run the sweep; `elevate_daemon` = start the index daemon with a UAC
    /// prompt (the no-broker path the user opted into at the sweep gate).
    Proceed {
        /// Whether the daemon start requests elevation (`--elevate`).
        elevate_daemon: bool,
    },
    /// Skip the sweep entirely (`--no-deep-sweep`, or the user/mode declined
    /// the elevation a broker-less sweep would need).
    Skip,
}

/// Decide up front whether (and how) the deep sweep runs. A complete sweep
/// needs the index daemon covering every drive; without the Access Broker a
/// daemon can only read the MFT **elevated**, so when coverage is incomplete,
/// this run is not elevated, and no broker pipe is serving, the user chooses:
/// start the daemon with a UAC prompt now, or skip the sweep. `--yes` and
/// `--dry-run` never pop a surprise UAC — they skip with a note instead.
#[cfg(windows)]
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
fn sweep_decision(parsed: &UninstallArgs) -> Result<SweepDecision> {
    /// Short broker-pipe probe (same budget as the daemon-management gate).
    const BROKER_PROBE_MS: u32 = 600;

    if parsed.no_deep_sweep {
        return Ok(SweepDecision::Skip);
    }
    if coverage::coverage_complete()
        || uffs_mft::platform::is_elevated()
        || uffs_winsvc::pipe_serving(uffs_broker_protocol::PIPE_NAME, BROKER_PROBE_MS)
    {
        return Ok(SweepDecision::Proceed {
            elevate_daemon: false,
        });
    }
    // A complete sweep would need an elevated daemon start.
    if parsed.dry_run || parsed.assume_yes {
        println!(
            "\nDeep sweep skipped: without the Access Broker the index daemon needs\n\
             Administrator to start. Run elevated (or install the broker) for a full sweep."
        );
        return Ok(SweepDecision::Skip);
    }
    println!(
        "\nA thorough uninstall deep-sweeps every drive for stray UFFS files. Without\n\
         the Access Broker, the index daemon can only start from an elevated process."
    );
    let choice = prompt_choice(
        "\n  d = deep sweep — start the daemon now (Windows shows one UAC prompt)\n\
         \x20 s = skip the deep sweep (standard locations only)\n\
         \n\
         Choice [d/S]: ",
    )?;
    if matches!(choice.as_str(), "d" | "deep" | "deep sweep") {
        // Breathing room between the answered prompt and the gather spinner
        // (emitted here, not in the spinner, so the silent no-question paths
        // do not accumulate stray blank lines under the run header).
        println!();
        Ok(SweepDecision::Proceed {
            elevate_daemon: true,
        })
    } else {
        println!("Deep sweep skipped; only the standard locations are cleaned.");
        Ok(SweepDecision::Skip)
    }
}

/// Everything the deep-sweep gather produces for the final presentation.
/// Windows-only — off Windows the daemon indexes offline captures, not the
/// live filesystem, so there is no stray phase at all.
#[cfg(windows)]
#[derive(Default)]
struct GatherOutcome {
    /// The stray-removal plan (the EXTRA section), removed only on ALL.
    stray_plan: RemovalPlan,
    /// The stray hits behind that plan, for the EXTRA table.
    strays: Vec<sweep::StrayHit>,
    /// Deferred coverage narration from the quiet background mode.
    coverage_notes: Vec<String>,
}

/// Which stage the background gather is in, for the spinner label:
/// 0 = drive coverage (indexing), 1 = searching the index.
#[cfg(windows)]
static GATHER_PHASE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Start the drive-coverage check/reload + deep sweep on a background thread
/// the moment the sweep decision is made, so the daemon index work overlaps
/// the elevation question instead of costing wall-clock time after it. Quiet:
/// all narration is deferred into the returned [`GatherOutcome`]. `None` when
/// the sweep was skipped at the gate or is running sequentially (`-v`).
///
/// The known-dirs snapshot is taken before the elevation gate mutates the
/// plan; that is safe because the gate only drops service/process items, which
/// never contribute directories.
#[cfg(windows)]
fn start_stray_gather(
    parsed: &UninstallArgs,
    removal_plan: &RemovalPlan,
    sweep: SweepDecision,
) -> Option<std::thread::JoinHandle<GatherOutcome>> {
    let SweepDecision::Proceed { elevate_daemon } = sweep else {
        return None;
    };
    if parsed.verbose {
        return None;
    }
    GATHER_PHASE.store(0, core::sync::atomic::Ordering::Relaxed);
    let known = plan_dirs(removal_plan);
    Some(std::thread::spawn(move || {
        gather_strays(&known, true, elevate_daemon)
    }))
}

/// The gather body: ensure drive coverage (quiet = narration deferred), then
/// search the live index for stray family files and build their plan. Runs
/// under `--dry-run` too — coverage and searching are non-destructive, and a
/// dry run should preview the *complete* picture.
#[cfg(windows)]
fn gather_strays(known: &[PathBuf], quiet: bool, elevate_daemon: bool) -> GatherOutcome {
    let coverage_notes = coverage::ensure_drive_coverage(quiet, elevate_daemon);
    GATHER_PHASE.store(1, core::sync::atomic::Ordering::Relaxed);

    sweep::dbg_gap();
    let mut search = sweep::DaemonSearch;
    let find_started = std::time::Instant::now();
    let candidates = sweep::find_strays(&mut search, known).unwrap_or_default();
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

    let stray_plan = plan::build_stray_plan(&strays);
    GatherOutcome {
        stray_plan,
        strays,
        coverage_notes,
    }
}

/// Collect the gather results: join the background thread behind a spinner
/// (default), run the gather synchronously and loudly (`-v`), or return empty
/// (the sweep was skipped at the gate). A panicked gather degrades to "no
/// strays found".
#[cfg(windows)]
fn finish_stray_gather(
    removal_plan: &RemovalPlan,
    gather: Option<std::thread::JoinHandle<GatherOutcome>>,
    sweep: SweepDecision,
) -> GatherOutcome {
    if let Some(handle) = gather {
        spinner_wait(&handle);
        return handle.join().unwrap_or_default();
    }
    let SweepDecision::Proceed { elevate_daemon } = sweep else {
        return GatherOutcome::default();
    };
    gather_strays(&plan_dirs(removal_plan), false, elevate_daemon)
}

/// The pid of the daemon that is running right now, or `None` if none answers.
/// Used after the gather to fold a sweep-started daemon into the shutdown plan.
#[cfg(windows)]
fn running_daemon_pid() -> Option<u32> {
    uffs_client::connect_sync::UffsClientSync::connect_raw()
        .ok()
        .and_then(|mut client| client.status().ok())
        .map(|status| status.pid)
        .filter(|&pid| pid != 0)
}

/// Animate a small spinner on the current line until `handle` finishes, with a
/// label tracking the gather stage; the line is cleared before returning so
/// the presentation starts clean.
#[cfg(windows)]
#[expect(clippy::print_stdout, reason = "interactive progress spinner")]
fn spinner_wait<T>(handle: &std::thread::JoinHandle<T>) {
    use std::io::Write as _;

    const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let mut frame = 0_usize;
    while !handle.is_finished() {
        let label = if GATHER_PHASE.load(core::sync::atomic::Ordering::Relaxed) == 0 {
            "indexing the drives for the deep sweep"
        } else {
            "searching the drives for UFFS files"
        };
        let glyph = FRAMES.get(frame % FRAMES.len()).copied().unwrap_or("*");
        print!("\r{glyph} Gathering artifacts ({label})...      ");
        let _flushed = std::io::stdout().flush();
        std::thread::sleep(core::time::Duration::from_millis(120));
        frame = frame.wrapping_add(1);
    }
    print!("\r{:74}\r", "");
    let _flushed = std::io::stdout().flush();
}

/// The single end-of-flow decision (design: decide -> gather -> present ->
/// confirm), asked only once the complete picture is on screen.
enum FinalChoice {
    /// Remove everything: the CORE install and the EXTRA files found elsewhere.
    All,
    /// Remove the CORE install only; leave the EXTRA files in place.
    CoreOnly,
    /// Remove nothing.
    Abort,
}

/// Ask the final consent question. With EXTRA files present this is a 3-way
/// ALL / CORE / ABORT tied to the section names above; without them it stays
/// the classic proceed-yes/no. `--yes` means ALL (the pre-existing semantics:
/// a scripted uninstall removes everything it found).
fn final_consent(
    parsed: &UninstallArgs,
    removal_plan: &RemovalPlan,
    stray_plan: &RemovalPlan,
) -> Result<FinalChoice> {
    if parsed.assume_yes {
        return Ok(FinalChoice::All);
    }
    if stray_plan.is_empty() {
        return Ok(if confirm("\nProceed with removal? [y/N] ")? {
            FinalChoice::All
        } else {
            FinalChoice::Abort
        });
    }
    if removal_plan.is_empty() {
        return Ok(
            if confirm(&format!(
                "\nRemove the {} EXTRA file(s) found elsewhere? [y/N] ",
                stray_plan.item_count()
            ))? {
                FinalChoice::All
            } else {
                FinalChoice::Abort
            },
        );
    }
    let choice = prompt_choice(&format!(
        "\nRemove:\n\
         \x20 a = ALL   — CORE and the {n} EXTRA file(s) found elsewhere\n\
         \x20 c = CORE  — the standard install only (leave the EXTRA files)\n\
         \x20 q = ABORT — nothing is removed\n\
         \n\
         Choice [a/c/Q]: ",
        n = stray_plan.item_count()
    ))?;
    Ok(match choice.as_str() {
        "a" | "all" => FinalChoice::All,
        "c" | "core" => FinalChoice::CoreOnly,
        _ => FinalChoice::Abort,
    })
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
