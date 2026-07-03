// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Rendering of the `uffs --uninstall` analysis (task U-12): the binary
//! resolution table + the artifact inventory, in human form and as `--json`.
//! The removal plan is layered on in later milestones.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::inventory::Inventory;
use super::plan::{PlanTarget, RemovalPlan};
use super::remove::{ItemStatus, RemovalOutcome};
use super::resolve_order::{ResolutionState, StemResolution};
#[cfg(windows)]
use super::sweep::StrayHit;
use crate::commands::update::model::{Channel, Scope};

/// Print the running build's version + git commit at the top of an uninstall
/// run, so a dry-run or live log is unambiguously tied to the exact binary that
/// produced it (the same stamp `uffs --version` shows).
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_run_header() {
    println!(
        "uffs {} ({}) — uninstall\n",
        env!("CARGO_PKG_VERSION"),
        option_env!("UFFS_GIT_SHA").unwrap_or("unknown")
    );
}

/// One flattened row of the resolution table (one per discovered copy), so each
/// binary is a single line rather than a stem header plus an indented row.
struct ResolutionRow {
    /// Binary name (`uffs`, `uffs-mft`, …).
    binary: String,
    /// On-disk version, or `legacy` when it could not be read.
    version: String,
    /// PATH-resolution standing: `runs` / `shadowed` / `off PATH`.
    status: &'static str,
    /// Where the copy came from (`hand-placed`, `winget (user)`, `dev build`,
    /// …).
    source: String,
    /// The directory the copy lives in.
    location: String,
}

/// Plain-language PATH-resolution standing of a copy: the one a bare command
/// runs (`runs`), a copy on PATH that another shadows (`shadowed`), or a copy
/// not on PATH at all (`off PATH`).
const fn status_label(state: ResolutionState, on_search_path: bool) -> &'static str {
    match (state, on_search_path) {
        (ResolutionState::Active, _) => "runs",
        (ResolutionState::Shadowed, true) => "shadowed",
        (ResolutionState::Shadowed, false) => "off PATH",
    }
}

/// Human "source" label: how the copy got there. Install scope (user/machine)
/// only means something for a `winget` install, so it is folded in there and
/// omitted from the hand-placed / dev-build cases (which is why the old table
/// showed a bare `-`).
fn source_label(channel: Channel, scope: Scope) -> String {
    match channel {
        Channel::WinGet => match scope {
            Scope::User => "winget (user)".to_owned(),
            Scope::Machine => "winget (machine)".to_owned(),
            Scope::Unknown => "winget".to_owned(),
        },
        Channel::Unmanaged => "hand-placed".to_owned(),
        Channel::DevBuild => "dev build".to_owned(),
        Channel::Unknown => "unknown".to_owned(),
    }
}

/// Print the discovered-binary resolution table: one aligned row per copy, with
/// a header and a STATUS legend. `runs` is the copy a bare command executes.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_resolution_table(stems: &[StemResolution]) {
    if stems.is_empty() {
        println!("No UFFS binaries found in any install root or on PATH.");
        return;
    }
    let rows: Vec<ResolutionRow> = stems
        .iter()
        .flat_map(|stem| {
            stem.copies.iter().map(move |copy| ResolutionRow {
                binary: stem.stem.clone(),
                version: copy.version.clone().unwrap_or_else(|| "legacy".to_owned()),
                status: status_label(copy.state, copy.on_search_path),
                source: source_label(copy.channel, copy.scope),
                location: copy.dir.display().to_string(),
            })
        })
        .collect();

    // Size each fixed column to the widest of its header and its cells so the
    // table stays aligned; LOCATION is last and free-width.
    let width = |header: &str, cell: fn(&ResolutionRow) -> usize| {
        rows.iter()
            .map(cell)
            .chain(core::iter::once(header.len()))
            .max()
            .unwrap_or(0)
    };
    let w_bin = width("BINARY", |row| row.binary.len());
    let w_ver = width("VERSION", |row| row.version.len());
    let w_status = width("STATUS", |row| row.status.len());
    let w_source = width("SOURCE", |row| row.source.len());

    println!(
        "\nCORE — the UFFS install (binaries, data, caches). STATUS: 'runs' = the copy a\n\
         bare command executes (first on PATH); 'shadowed' = on PATH but another runs\n\
         first; 'off PATH' = present but not on PATH.\n"
    );
    // One printer for the header and every row, so the columns share widths and
    // there are no bare format literals.
    let print_row = |binary: &str, version: &str, status: &str, source: &str, location: &str| {
        println!(
            "  {binary:<w_bin$}  {version:<w_ver$}  {status:<w_status$}  {source:<w_source$}  {location}"
        );
    };
    print_row("BINARY", "VERSION", "STATUS", "SOURCE", "LOCATION");
    for row in &rows {
        print_row(
            &row.binary,
            &row.version,
            row.status,
            &row.source,
            &row.location,
        );
    }
}

/// Print the non-binary artifact inventory (data / cache / legacy / config)
/// plus the broker-service state.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_inventory(inventory: &Inventory) {
    println!("\nData / cache / config:");
    for dir in &inventory.dirs {
        let size = if dir.exists {
            human_bytes(dir.size_bytes)
        } else {
            "absent".to_owned()
        };
        println!(
            "  {kind:<13}  {size:<10}  {path}",
            kind = dir.kind.label(),
            path = dir.path.display(),
        );
    }
    println!(
        "\nBroker service ({name}): {state}",
        name = uffs_broker_protocol::SERVICE_NAME,
        state = inventory.broker_service.label(),
    );
}

/// Print the ordered removal plan (consent surface, U-21). Items are numbered
/// across groups; ones needing Administrator are flagged.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_plan(plan: &RemovalPlan, extra: &RemovalPlan) {
    if plan.is_empty() && extra.is_empty() {
        println!("\nNothing to remove: no UFFS install or artifacts were found.");
        return;
    }
    println!("\nThe following will be PERMANENTLY removed (no recovery):\n");
    let mut index: usize = 1;
    let mut shown_binary_dirs: Vec<PathBuf> = Vec::new();
    for item in plan.items() {
        // Coalesce all binary deletes for one directory into a single
        // "N binaries in <dir>" line. The internal tools-vs-runtime split (and
        // its group headings) is a teardown-ordering detail — the user just
        // wants to know how many binaries in which folder go away.
        if let PlanTarget::DeleteBinaries { dir, .. } = &item.target {
            if shown_binary_dirs.iter().any(|shown| shown == dir) {
                continue;
            }
            shown_binary_dirs.push(dir.clone());
            let (count, needs_admin) = binary_dir_totals(plan, dir);
            println!(
                "  [{index}] {count} binaries in {}{}",
                dir.display(),
                admin_flag(needs_admin),
            );
            index = index.saturating_add(1);
            continue;
        }
        println!(
            "  [{index}] {desc}{elevated}",
            desc = item.target.describe(),
            elevated = admin_flag(item.needs_elevation),
        );
        index = index.saturating_add(1);
    }
    // The EXTRA files ride the same summary so nothing is hidden from the
    // final picture, but they are a separate choice: the ALL/CORE question.
    if !extra.is_empty() {
        println!(
            "  [{index}] {count} file(s) found elsewhere (removed only with ALL)",
            count = extra.item_count(),
        );
    }
    if extra.is_empty() {
        println!("\nReclaims ~{}.", human_bytes(plan.total_bytes()));
    } else {
        println!(
            "\nReclaims ~{}, plus {} file(s) removed only with ALL.",
            human_bytes(plan.total_bytes()),
            extra.item_count(),
        );
    }
}

/// The `  (needs Administrator)` suffix, or empty when the item is removable
/// as the current user.
const fn admin_flag(needs_elevation: bool) -> &'static str {
    if needs_elevation {
        "  (needs Administrator)"
    } else {
        ""
    }
}

/// Sum the binary stems across every `DeleteBinaries` item targeting `dir` (the
/// tools and runtime passes land in separate groups), and whether any of them
/// needs Administrator. Used to fold the split into one consent line.
fn binary_dir_totals(plan: &RemovalPlan, dir: &Path) -> (usize, bool) {
    let mut count: usize = 0;
    let mut needs_admin = false;
    for item in plan.items() {
        if let PlanTarget::DeleteBinaries {
            dir: item_dir,
            stems,
        } = &item.target
            && item_dir == dir
        {
            count = count.saturating_add(stems.len());
            needs_admin |= item.needs_elevation;
        }
    }
    (count, needs_admin)
}

/// The up-front elevation gate (U-30): the FIRST thing a non-elevated run says.
/// Explains which items need an Administrator terminal and why, before any
/// analysis output — the question that follows is the only elevation decision.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_elevation_gate(plan: &RemovalPlan) {
    println!(
        "\nThis terminal is not elevated (Administrator). The following can only be\n\
         removed from an elevated terminal (the broker runs as LocalSystem):\n"
    );
    for group in &plan.groups {
        for item in &group.items {
            if item.needs_elevation {
                println!("  - {}", item.target.describe());
            }
        }
    }
}

/// Final-summary note listing what this run skips because it needs
/// Administrator (decided once, up front, at the elevation gate).
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_skipped_elevation(skipped: &[String]) {
    if skipped.is_empty() {
        return;
    }
    println!("\nNOT removed in this run (needs Administrator):");
    for item in skipped {
        println!("  - {item}");
    }
    println!("  Re-run `uffs --uninstall` from an elevated terminal to remove these.");
}

/// Note printed under the final summary when the user chose "elevate at
/// removal time" at the gate: exactly one UAC prompt appears once removal
/// starts (never before the final confirmation).
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_uac_note() {
    println!(
        "\nThe item(s) marked (needs Administrator) will show one Windows UAC prompt\n\
         when removal starts."
    );
}

/// Dry-run note shown when the plan carries admin-only items but this terminal
/// is not elevated: a real run will offer to skip them.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_dry_run_elevation_note() {
    println!(
        "\nNote: items marked (needs Administrator) require an elevated terminal; a\n\
         non-elevated run asks up front whether to continue without them."
    );
}

/// Print the EXTRA section: stray UFFS files the deep sweep found outside the
/// standard install locations, as an aligned BINARY / VERSION / LOCATION table
/// (matching the CORE table's shape). Removed only when the final choice is
/// ALL — one may be a copy the user placed themselves. Windows-only.
#[cfg(windows)]
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_extra_table(strays: &[StrayHit]) {
    if strays.is_empty() {
        return;
    }
    let rows: Vec<(String, String, String)> = strays
        .iter()
        .map(|stray| {
            let binary = stray.path.file_name().map_or_else(
                || stray.path.display().to_string(),
                |name| name.to_string_lossy().into_owned(),
            );
            let location = stray
                .path
                .parent()
                .map_or_else(String::new, |dir| dir.display().to_string());
            let version = stray.version.clone().unwrap_or_else(|| "legacy".to_owned());
            (binary, version, location)
        })
        .collect();
    let width = |header: &str, cell: fn(&(String, String, String)) -> usize| {
        rows.iter()
            .map(cell)
            .chain(core::iter::once(header.len()))
            .max()
            .unwrap_or(0)
    };
    let w_bin = width("BINARY", |row| row.0.len());
    let w_ver = width("VERSION", |row| row.1.len());

    println!(
        "\nEXTRA — UFFS files found elsewhere by the deep sweep (removed only with ALL;\n\
         one may be a copy you placed yourself):\n"
    );
    let print_row = |binary: &str, version: &str, location: &str| {
        println!("  {binary:<w_bin$}  {version:<w_ver$}  {location}");
    };
    print_row("BINARY", "VERSION", "LOCATION");
    for row in &rows {
        print_row(&row.0, &row.1, &row.2);
    }
}

/// Print the deferred coverage narration collected by the quiet background
/// gather (empty when coverage was already complete or the run was loud).
/// Windows-only.
#[cfg(windows)]
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_coverage_notes(notes: &[String]) {
    for note in notes {
        println!("{note}");
    }
}

/// Note that the user kept the deep-sweep EXTRA files (chose CORE). Reachable
/// only on Windows in practice (off Windows the stray plan is always empty),
/// but compiled everywhere because the shared executor references it.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_strays_kept() {
    println!("Left the EXTRA file(s) (found elsewhere) in place.");
}

/// Note that a prior uninstall was interrupted and this run completes it.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_resumed_note() {
    println!(
        "A previous uninstall did not finish. Removal is idempotent, so this run \
         will complete it.\n"
    );
}

/// Warn that the in-progress journal marker could not be written/cleared.
#[expect(clippy::print_stderr, reason = "CLI user-facing error")]
pub(crate) fn print_journal_warning(error: &anyhow::Error) {
    eprintln!("note: uninstall progress marker could not be updated ({error:#}).");
}

/// Note that the running `uffs` binary finishes removing itself after the
/// process exits (the OS locks a running image). One quiet line — the exact
/// paths are a mechanism detail the user does not need.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_self_delete_scheduled() {
    println!("\nThe uffs command removes itself once this process exits.");
}

/// Warn that the running self-binary could not be scheduled for deletion.
#[expect(clippy::print_stderr, reason = "CLI user-facing error")]
pub(crate) fn print_self_delete_warning(error: &anyhow::Error) {
    eprintln!(
        "\nCould not schedule deletion of the running uffs binary ({error:#}).\n\
         Delete it manually once this process has exited."
    );
}

/// Print the post-removal verification. The upbeat "all gone" is claimed only
/// when the run was `clean` — nothing failed and nothing was left (a declined
/// broker removal is NOT "all gone", even though the leftover service/binary
/// are not among the stat-checked `remaining` paths). `print_outcome` already
/// explained any leftovers, so this stays quiet in that case.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_verification(remaining: &[PathBuf], clean: bool) {
    if remaining.is_empty() {
        if clean {
            println!("\nVerified: all targeted UFFS locations are gone.");
        }
        return;
    }
    println!(
        "\nVerification: {} location(s) still present (a reboot may be pending, or \
         elevation/sudo is needed):",
        remaining.len()
    );
    for path in remaining {
        println!("  {}", path.display());
    }
}

/// Print the outcome of a removal run: counts, any failures / left items, and
/// the matching next-step hint.
#[expect(clippy::print_stdout, reason = "CLI user-facing output")]
pub(crate) fn print_outcome(outcome: &RemovalOutcome) {
    let failed = outcome.failed_count();
    let skipped = outcome.skipped_count();
    let mut parts = vec![format!("{} removed", outcome.done_count())];
    if failed > 0 {
        parts.push(format!("{failed} failed"));
    }
    if skipped > 0 {
        parts.push(format!("{skipped} left"));
    }
    println!("\nRemoval finished: {}.", parts.join(", "));

    for (description, status) in &outcome.results {
        match status {
            ItemStatus::Failed(error) => println!("  FAILED  {description}  ({error})"),
            ItemStatus::Skipped(reason) => println!("  LEFT    {description}  ({reason})"),
            ItemStatus::Done => {}
        }
    }

    // Left items are always the broker after a declined elevation (Windows-only):
    // one clear next step, not the generic file-in-use hint.
    if skipped > 0 {
        println!(
            "\nThe Access Broker was left because elevation was declined. Re-run\n\
             `uffs --uninstall` from an Administrator terminal to remove it."
        );
    }
    if failed > 0 {
        println!(
            "\nSome items could not be removed (a file may be in use). Close anything \
             using them and re-run."
        );
    }
}

/// Emit the full analysis (binaries + artifacts + broker state + plan) as JSON.
#[expect(clippy::print_stdout, reason = "machine-readable CLI output")]
pub(crate) fn print_json(resolution: &[StemResolution], inventory: &Inventory, plan: &RemovalPlan) {
    let value = analysis_json(resolution, inventory, plan);
    let text = serde_json::to_string_pretty(&value)
        .unwrap_or_else(|_| "{\"error\":\"serialize\"}".to_owned());
    println!("{text}");
}

/// Build the plan JSON value (pure).
fn plan_json(plan: &RemovalPlan) -> Value {
    let groups: Vec<Value> = plan
        .groups
        .iter()
        .map(|group| {
            let items: Vec<Value> = group
                .items
                .iter()
                .map(|item| {
                    json!({
                        "action": item.target.action_label(),
                        "description": item.target.describe(),
                        "needs_elevation": item.needs_elevation,
                        "bytes": item.bytes,
                    })
                })
                .collect();
            json!({ "title": group.title, "items": items })
        })
        .collect();
    json!({
        "total_bytes": plan.total_bytes(),
        "item_count": plan.item_count(),
        "requires_elevation": plan.requires_elevation(),
        "groups": groups,
    })
}

/// Build the analysis JSON value (pure; unit-testable without IO).
fn analysis_json(
    resolution: &[StemResolution],
    inventory: &Inventory,
    plan: &RemovalPlan,
) -> Value {
    let binaries: Vec<Value> = resolution
        .iter()
        .map(|stem| {
            let copies: Vec<Value> = stem
                .copies
                .iter()
                .map(|copy| {
                    json!({
                        "state": match copy.state {
                            ResolutionState::Active => "active",
                            ResolutionState::Shadowed => "shadowed",
                        },
                        "on_search_path": copy.on_search_path,
                        "version": copy.version,
                        "channel": copy.channel.label(),
                        "scope": copy.scope.label(),
                        "dir": copy.dir.display().to_string(),
                    })
                })
                .collect();
            json!({ "stem": stem.stem, "copies": copies })
        })
        .collect();
    let artifacts: Vec<Value> = inventory
        .dirs
        .iter()
        .map(|dir| {
            json!({
                "kind": dir.kind.label(),
                "path": dir.path.display().to_string(),
                "exists": dir.exists,
                "size_bytes": dir.size_bytes,
            })
        })
        .collect();
    json!({
        "binaries": binaries,
        "artifacts": artifacts,
        "broker_service": inventory.broker_service.label(),
        "plan": plan_json(plan),
    })
}

/// Format a byte count for humans using integer math (no float casts, which the
/// workspace `cast_precision_loss` lint forbids). One decimal place.
fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    let (unit, label) = if bytes >= GIB {
        (GIB, "GB")
    } else if bytes >= MIB {
        (MIB, "MB")
    } else if bytes >= KIB {
        (KIB, "KB")
    } else {
        return format!("{bytes} B");
    };
    let whole = bytes / unit;
    let frac = (bytes % unit).saturating_mul(10) / unit;
    format!("{whole}.{frac} {label}")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::super::inventory::{ArtifactDir, ArtifactKind, BrokerServiceState, Inventory};
    use super::super::plan::RemovalPlan;
    use super::{Value, analysis_json, human_bytes};

    #[test]
    fn human_bytes_picks_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(
            human_bytes(1024 * 1024 * 1024 + 512 * 1024 * 1024),
            "1.5 GB"
        );
    }

    #[test]
    fn json_has_top_level_sections() {
        let inventory = Inventory {
            dirs: vec![ArtifactDir {
                kind: ArtifactKind::Cache,
                path: PathBuf::from("/x/cache"),
                exists: true,
                size_bytes: 10,
            }],
            broker_service: BrokerServiceState::Absent,
        };
        let value = analysis_json(&[], &inventory, &RemovalPlan::default());
        assert!(value.get("binaries").is_some());
        assert!(value.get("artifacts").is_some());
        assert!(value.get("plan").is_some());
        assert_eq!(
            value.get("broker_service").and_then(Value::as_str),
            Some("absent")
        );
    }
}
