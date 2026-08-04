// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `uffs-update doctor` — an end-to-end health check for the self-update
//! flow, in the spirit of `brew doctor`.
//!
//! It inspects every moving part the update touches — install detection
//! (via the snapshot the CLI hands us), version alignment, the update
//! working dir and staging, a stale or in-flight journal, leftover `.bak`
//! files, live services, the broker pipe, plus GitHub release
//! reachability and per-binary asset presence — and prints a `[ OK ]` /
//! `[WARN]` / `[FAIL]` report. With `--repair` it actively self-heals the
//! conditions it can (resume/rollback an interrupted update, sweep stale
//! backups, restart a stopped service) by calling the same in-crate
//! primitives the real update uses, so the repair path is exercised
//! identically.

use std::path::{Path, PathBuf};

use anyhow::Result;
use uffs_fetch::github;

use crate::orchestrate::asset_name;
use crate::{apply, journal, plan, proc, restore};

/// How long the doctor waits on the broker pipe before calling it down
/// (short — this is a probe, not the restore-time readiness gate; off
/// Windows the probe is a vacuous `true` and ignores this).
const DOCTOR_PIPE_PROBE_MS: u32 = 1_000;

/// Options for a doctor run.
pub(crate) struct DoctorOpts {
    /// Snapshot to read install/version/service context from (optional —
    /// without it the install-specific checks are skipped).
    pub(crate) snapshot: Option<PathBuf>,
    /// Staging dir (locates the update working dir if no snapshot).
    pub(crate) stage: Option<PathBuf>,
    /// Upstream `owner/repo` for the release-reachability check.
    pub(crate) repo: String,
    /// Specific release tag, or `None` for latest.
    pub(crate) tag: Option<String>,
    /// Actively repair what we can, not just report.
    pub(crate) repair: bool,
    /// Skip the network checks entirely.
    pub(crate) offline: bool,
    /// Print every check (`-v`); default shows only problems + a one-line
    /// healthy summary.
    pub(crate) verbose: bool,
}

/// Severity of a single finding.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Health {
    /// All good.
    Ok,
    /// Works, but worth attention (or healed by `--repair`).
    Warn,
    /// Broken — the update would not succeed in this state.
    Fail,
}

impl Health {
    /// Fixed-width tag for aligned output.
    const fn tag(self) -> &'static str {
        match self {
            Self::Ok => "[ OK ]",
            Self::Warn => "[WARN]",
            Self::Fail => "[FAIL]",
        }
    }
}

/// One line of the report.
struct Finding {
    /// Severity.
    health: Health,
    /// Short title.
    title: String,
    /// Optional detail / remedy.
    detail: Option<String>,
}

/// Accumulates findings and renders the report.
#[derive(Default)]
struct Report {
    /// Findings in check order.
    findings: Vec<Finding>,
}

impl Report {
    /// Record a finding.
    fn add(&mut self, health: Health, title: impl Into<String>, detail: Option<String>) {
        self.findings.push(Finding {
            health,
            title: title.into(),
            detail,
        });
    }

    /// `true` if no finding is a hard failure.
    fn healthy(&self) -> bool {
        self.findings
            .iter()
            .all(|finding| finding.health != Health::Fail)
    }

    /// Counts of (ok, warn, fail).
    fn tally(&self) -> (usize, usize, usize) {
        self.findings
            .iter()
            .fold((0, 0, 0), |(ok, warn, fail), finding| {
                match finding.health {
                    Health::Ok => (ok + 1, warn, fail),
                    Health::Warn => (ok, warn + 1, fail),
                    Health::Fail => (ok, warn, fail + 1),
                }
            })
    }

    /// Print the report. Default shows only the findings that need attention
    /// (`[WARN]`/`[FAIL]`) plus a one-line health summary; `verbose` lists
    /// every check (including the `[ OK ]`s).
    #[expect(clippy::print_stdout, reason = "doctor user-facing report")]
    fn render(&self, repair: bool, verbose: bool) {
        println!(
            "UFFS update doctor (uffs-update {})\n",
            env!("CARGO_PKG_VERSION")
        );
        let (ok, warn, fail) = self.tally();
        for item in &self.findings {
            // Default view: skip the passing checks — surface only problems.
            if !verbose && item.health == Health::Ok {
                continue;
            }
            println!("{} {}", item.health.tag(), item.title);
            if let Some(detail) = &item.detail {
                println!("        {detail}");
            }
        }
        if !verbose && warn == 0 && fail == 0 {
            // Brew-doctor style: nothing wrong → one reassuring line.
            println!("\u{2713} Healthy — all {ok} checks passed.");
        } else {
            println!("\nsummary: {ok} ok, {warn} warning(s), {fail} failure(s)");
            if !verbose {
                println!("(run with -v to see every check)");
            }
        }
        if !repair && (warn > 0 || fail > 0) {
            println!(
                "hint: run `uffs --update repair` to self-heal what can be fixed automatically."
            );
        }
    }
}

/// Run the doctor. Returns `true` when no hard failure was found. Never
/// errors out — every check degrades to a `[WARN]`/`[FAIL]` finding.
pub(crate) fn run(opts: &DoctorOpts) -> bool {
    let mut report = Report::default();

    check_helper(&mut report);
    let snapshot = check_snapshot(opts, &mut report);
    if let Some(snap) = snapshot.as_ref() {
        check_version_alignment(snap, &mut report);
    }
    let update_dir = resolve_update_dir(opts);
    check_dirs(update_dir.as_deref(), opts.stage.as_deref(), &mut report);
    check_journal(update_dir.as_deref(), opts.repair, &mut report);
    if let Some(snap) = snapshot.as_ref() {
        check_stale_backups(snap, opts.repair, &mut report);
        check_services(snap, opts.repair, &mut report);
    }
    check_broker(&mut report);
    if opts.offline {
        report.add(
            Health::Warn,
            "Release reachability skipped (--offline)",
            None,
        );
    } else {
        check_release(opts, snapshot.as_ref(), &mut report);
    }

    report.render(opts.repair, opts.verbose);
    report.healthy()
}

/// Locate the running helper itself.
fn check_helper(report: &mut Report) {
    match std::env::current_exe() {
        Ok(path) => report.add(
            Health::Ok,
            "Update helper present",
            Some(path.display().to_string()),
        ),
        Err(err) => report.add(
            Health::Fail,
            "Update helper path unresolved",
            Some(err.to_string()),
        ),
    }
}

/// Load the snapshot (if any) and summarise it.
fn check_snapshot(opts: &DoctorOpts, report: &mut Report) -> Option<plan::Snapshot> {
    let Some(path) = opts.snapshot.as_ref() else {
        report.add(
            Health::Warn,
            "No snapshot — install/version/service checks skipped",
            Some("run via `uffs --update doctor` to include them".to_owned()),
        );
        return None;
    };
    match plan::Snapshot::load(path) {
        Ok(snap) => {
            let detail = format!(
                "{} unmanaged binary target(s), {} running component(s)",
                snap.installed_binaries().len(),
                snap.running.len()
            );
            report.add(Health::Ok, "Snapshot loaded", Some(detail));
            Some(snap)
        }
        Err(err) => {
            report.add(Health::Fail, "Snapshot unreadable", Some(err.to_string()));
            None
        }
    }
}

/// All installed binaries should be at the same on-disk version.
fn check_version_alignment(snapshot: &plan::Snapshot, report: &mut Report) {
    let mut versions: Vec<String> = snapshot
        .unmanaged_targets()
        .flat_map(|target| target.binaries.iter())
        .filter_map(|binary| binary.on_disk_version.clone())
        .collect();
    versions.sort();
    versions.dedup();
    match versions.as_slice() {
        [] => report.add(Health::Warn, "No on-disk versions recorded", None),
        [one] => report.add(Health::Ok, "Versions aligned", Some(one.clone())),
        many => report.add(
            Health::Warn,
            "Version drift across binaries",
            Some(format!("found: {}", many.join(", "))),
        ),
    }
}

/// The update working dir + staging must be writable.
fn check_dirs(update_dir: Option<&Path>, stage: Option<&Path>, report: &mut Report) {
    match update_dir {
        Some(dir) => match writable(dir) {
            Ok(()) => report.add(
                Health::Ok,
                "Update dir writable",
                Some(dir.display().to_string()),
            ),
            Err(err) => report.add(
                Health::Fail,
                "Update dir not writable",
                Some(err.to_string()),
            ),
        },
        None => report.add(Health::Warn, "Update dir unknown (no snapshot/stage)", None),
    }
    if let Some(dir) = stage {
        match writable(dir) {
            Ok(()) => report.add(
                Health::Ok,
                "Stage dir writable",
                Some(dir.display().to_string()),
            ),
            Err(err) => report.add(
                Health::Warn,
                "Stage dir not writable yet",
                Some(err.to_string()),
            ),
        }
    }
}

/// Probe-write + delete a temp file to confirm a dir accepts writes.
fn writable(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let probe = dir.join(format!(".uffs-doctor-{}", std::process::id()));
    std::fs::write(&probe, b"")?;
    let _removed = std::fs::remove_file(&probe);
    Ok(())
}

/// Report (and optionally heal) an in-flight or interrupted update.
fn check_journal(update_dir: Option<&Path>, repair: bool, report: &mut Report) {
    let Some(dir) = update_dir else { return };
    let path = dir.join("journal.json");
    if !path.exists() {
        report.add(Health::Ok, "No in-flight update", None);
        return;
    }
    let Ok(jrnl) = journal::Journal::load(&path) else {
        report.add(
            Health::Warn,
            "Journal present but unreadable",
            Some(path.display().to_string()),
        );
        return;
    };
    let owner_alive = proc::is_alive(jrnl.owner_pid);
    if owner_alive {
        report.add(
            Health::Warn,
            "An update is in progress",
            Some("owner process alive".to_owned()),
        );
        return;
    }
    if !repair {
        report.add(
            Health::Warn,
            "Interrupted update found",
            Some("owner gone — run `uffs --update repair` to resume or roll back".to_owned()),
        );
        return;
    }
    match crate::recover::recover(&path) {
        Ok(outcome) => report.add(
            Health::Ok,
            "Interrupted update healed",
            Some(format!("{outcome:?}")),
        ),
        Err(err) => report.add(Health::Fail, "Recovery failed", Some(err.to_string())),
    }
}

/// Count (and optionally sweep) leftover `.bak` files in install roots.
fn check_stale_backups(snapshot: &plan::Snapshot, repair: bool, report: &mut Report) {
    let roots: Vec<&Path> = snapshot
        .unmanaged_targets()
        .map(|target| target.root.as_path())
        .collect();
    if repair {
        let swept: usize = roots
            .iter()
            .map(|root| apply::sweep_stale_backups(root))
            .sum();
        report.add(
            Health::Ok,
            "Stale backups swept",
            Some(format!("{swept} leftover .bak removed")),
        );
        return;
    }
    let stale: usize = roots.iter().map(|root| count_stale_backups(root)).sum();
    if stale == 0 {
        report.add(Health::Ok, "No leftover backups", None);
    } else {
        report.add(
            Health::Warn,
            "Leftover .bak files",
            Some(format!("{stale} present — `--repair` reclaims them")),
        );
    }
}

/// Count `.bak` files in `dir` whose live sibling exists (sweepable).
fn count_stale_backups(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            let bak = entry.path();
            bak.extension().is_some_and(|ext| ext == "bak") && bak.with_extension("").exists()
        })
        .count()
}

/// Report each running component's liveness, and (optionally) restart any
/// that have died using the captured restore recipe.
fn check_services(snapshot: &plan::Snapshot, repair: bool, report: &mut Report) {
    let mut down = Vec::new();
    for running in &snapshot.running {
        // The broker runs as a LocalSystem service. A non-elevated uffs-update
        // can't `OpenProcess` a SYSTEM-owned pid, so `proc::is_alive` false-
        // negatives on it — which would flag a perfectly healthy broker as
        // "down" and then trigger a doomed (also elevation-gated) restart.
        // Its authoritative liveness is the serving pipe (what check_broker
        // probes too), so use that for the broker instead of pid liveness.
        let alive = if running.component == "broker" {
            restore::broker_pipe_ready(DOCTOR_PIPE_PROBE_MS)
        } else {
            proc::is_alive(running.pid)
        };
        if alive {
            report.add(
                Health::Ok,
                format!("Service up: {}", running.component),
                None,
            );
        } else {
            down.push(running.component.clone());
        }
    }
    if down.is_empty() {
        return;
    }
    if !repair {
        report.add(
            Health::Warn,
            "Service(s) not running",
            Some(format!("{} — `--repair` restarts them", down.join(", "))),
        );
        return;
    }
    let failed = restore::restore(snapshot);
    if failed.is_empty() {
        report.add(
            Health::Ok,
            "Stopped service(s) restarted",
            Some(down.join(", ")),
        );
    } else {
        report.add(
            Health::Fail,
            "Service restart failed",
            Some(failed.join(", ")),
        );
    }
}

/// Broker pipe readiness (Windows-only; vacuous elsewhere).
fn check_broker(report: &mut Report) {
    if !cfg!(windows) {
        report.add(Health::Ok, "Broker check skipped (non-Windows)", None);
        return;
    }
    if restore::broker_pipe_ready(DOCTOR_PIPE_PROBE_MS) {
        report.add(Health::Ok, "Broker pipe serving", None);
    } else {
        report.add(
            Health::Warn,
            "Broker pipe not serving",
            Some("broker stopped or not installed (`uffs-broker --install`)".to_owned()),
        );
    }
}

/// Reach the release, report update availability, and confirm every
/// installed binary has a downloadable asset + a checksum entry.
fn check_release(opts: &DoctorOpts, snapshot: Option<&plan::Snapshot>, report: &mut Report) {
    let release = match github::fetch_release(crate::USER_AGENT, &opts.repo, opts.tag.as_deref()) {
        Ok(rel) => rel,
        Err(err) => {
            report.add(
                Health::Warn,
                "Release unreachable (offline?)",
                Some(err.to_string()),
            );
            return;
        }
    };
    let installed = snapshot.map(plan::Snapshot::prior_version);
    let detail = installed.map_or_else(
        || format!("latest = {}", release.tag_name),
        |cur| format!("installed = {cur}, latest = {}", release.tag_name),
    );
    report.add(Health::Ok, "Release reachable", Some(detail));

    let Some(snap) = snapshot else { return };
    let sums_present = release.asset("SHA256SUMS").is_some();
    let mut missing = Vec::new();
    for stem in snap.installed_binaries() {
        let asset = asset_name(&stem);
        if release.asset(&asset).is_none() {
            missing.push(asset);
        }
    }
    if !sums_present {
        report.add(Health::Fail, "SHA256SUMS asset missing from release", None);
    }
    if missing.is_empty() {
        report.add(Health::Ok, "All per-binary assets present", None);
    } else {
        report.add(
            Health::Fail,
            "Release missing binary asset(s)",
            Some(missing.join(", ")),
        );
    }
}

/// Resolve the update working dir from the snapshot or stage path.
fn resolve_update_dir(opts: &DoctorOpts) -> Option<PathBuf> {
    if let Some(stage) = opts.stage.as_ref() {
        return stage.parent().map(Path::to_path_buf);
    }
    opts.snapshot
        .as_ref()
        .and_then(|snap| snap.parent())
        .map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::{Health, Report, count_stale_backups};

    #[test]
    fn report_healthy_until_a_failure() {
        let mut report = Report::default();
        report.add(Health::Ok, "a", None);
        report.add(Health::Warn, "b", None);
        assert!(report.healthy(), "warnings do not make it unhealthy");
        report.add(Health::Fail, "c", None);
        assert!(!report.healthy(), "a failure flips it unhealthy");
        assert_eq!(report.tally(), (1, 1, 1));
    }

    #[test]
    fn counts_only_sweepable_backups() {
        let dir = std::env::temp_dir().join(format!("uffs-doctor-bak-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        // Completed swap: live + .bak → sweepable.
        std::fs::write(dir.join("uffsd.exe"), "NEW").expect("live");
        std::fs::write(dir.join("uffsd.exe.bak"), "OLD").expect("bak");
        // Orphan .bak (no live sibling) → not counted.
        std::fs::write(dir.join("gone.exe.bak"), "OLD").expect("orphan");
        assert_eq!(count_stale_backups(&dir), 1);
        let _cleanup = std::fs::remove_dir_all(&dir);
    }
}
