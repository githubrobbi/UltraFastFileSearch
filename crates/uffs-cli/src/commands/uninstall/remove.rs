// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! The `uffs --uninstall` removal executor (task U-40).
//!
//! [`execute`] walks a [`RemovalPlan`] in order and dispatches each item to an
//! injected [`Effects`] implementation, recording a per-item outcome. It is
//! **best-effort**: a failing item is recorded and the rest still run, so one
//! locked file never strands the cleanup (crash-resume is added in M9).
//!
//! All side effects live behind the [`Effects`] trait, so the orchestration is
//! unit-tested with a recording fake — zero real deletions in tests. The live
//! implementation is `super::effects::SystemEffects`.

use std::path::Path;

use anyhow::Result;

use super::plan::{PlanItem, PlanTarget, RemovalPlan};
use crate::commands::update::model::Scope;

/// Marker error: the elevation an item needed was declined at the UAC prompt.
/// The executor recognises it (via downcast) and LEAVES the Access Broker —
/// service plus its still-locked binary — as a clean "left" outcome, instead of
/// attempting-and-failing each with a raw Access-denied.
#[derive(Debug)]
pub(crate) struct ElevationDeclined;

impl core::fmt::Display for ElevationDeclined {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("elevation was declined at the UAC prompt")
    }
}

impl core::error::Error for ElevationDeclined {}

/// Marker error: winget refuses to uninstall a USER-scope package from an
/// elevated session ("The package installed for user scope cannot be
/// uninstalled when running with administrator privileges") — winget's
/// deliberate scope-safety, not a failure to force through. The executor
/// records the delegation as LEFT with the exact non-admin instruction.
#[derive(Debug)]
pub(crate) struct WingetNeedsNonElevated;

impl core::fmt::Display for WingetNeedsNonElevated {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("winget cannot uninstall a user-scope package from an elevated session")
    }
}

impl core::error::Error for WingetNeedsNonElevated {}

/// Marker error: the running uffs.exe lives INSIDE the winget package dir, so
/// a synchronous `winget uninstall` would hit its own locked image. The
/// effects layer schedules the uninstall to run right after this process
/// exits (same detached-script mechanism as the self-delete) and returns this
/// marker; the executor records the item as deliberately deferred.
#[derive(Debug)]
pub(crate) struct WingetDeferred;

impl core::fmt::Display for WingetDeferred {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("winget uninstall deferred until this process exits")
    }
}

impl core::error::Error for WingetDeferred {}

/// Marker error: the Access Broker service is staying (elevation declined or
/// deliberately kept) and it runs FROM the winget package dir, so even a
/// deferred `winget uninstall` would hit the service's locked image — the
/// exact `remove_all: Access is denied` failure seen live. The delegation is
/// left with the two-step instruction instead of a doomed attempt.
#[derive(Debug)]
pub(crate) struct WingetBlockedByBroker;

impl core::fmt::Display for WingetBlockedByBroker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the broker service still runs from the winget package")
    }
}

impl core::error::Error for WingetBlockedByBroker {}

/// Reason recorded when the winget uninstall is blocked by the kept broker.
const WINGET_BLOCKED_BY_BROKER: &str = "the Access Broker service still runs from this winget package and locks its      files; remove the service from an Administrator terminal (`uffs --uninstall`),      then run `winget uninstall SkyLLC.UFFS`";

/// Reason recorded when the winget uninstall is deferred past process exit.
const WINGET_DEFERRED: &str = "winget uninstall runs right after this process exits (the running      uffs.exe is part of the winget package)";

/// Reason recorded when the winget package is left because this run is
/// elevated: the user needs one command in a normal terminal.
const WINGET_LEFT: &str = "user-scope winget packages cannot be uninstalled from an admin session; run      `winget uninstall SkyLLC.UFFS` in a normal (non-admin) terminal";

/// Reason recorded when the broker service is left because elevation was
/// declined at the UAC prompt.
const BROKER_SERVICE_LEFT: &str = "the Access Broker (a LocalSystem service) needs Administrator";

/// Reason recorded when the broker binary is left: its service is still
/// running, so the image is locked and cannot be deleted without stopping the
/// service.
const BROKER_BINARY_LEFT: &str = "the Access Broker service is still running";

/// Whether `stem` names the broker binary (locked while its service runs).
const fn is_broker_stem(stem: &str) -> bool {
    stem.eq_ignore_ascii_case("uffs-broker")
}

/// The side effects the executor performs, injected so the walk is testable.
pub(crate) trait Effects {
    /// Stop a running UFFS process by component label + pid.
    fn stop_process(&mut self, component: &str, pid: u32) -> Result<()>;
    /// Stop and delete the broker Windows service.
    fn remove_service(&mut self, service: &str) -> Result<()>;
    /// Delete the named binary stems inside `dir` (absent ones are a no-op).
    fn delete_binaries(&mut self, dir: &Path, stems: &[String]) -> Result<()>;
    /// Delete one stray file by absolute path (absent is a no-op). Used for the
    /// Windows deep-sweep hits found outside the known roots.
    #[cfg(windows)]
    fn delete_file(&mut self, path: &Path) -> Result<()>;
    /// Hand a `WinGet`-managed root to `winget uninstall`. `dir` is the
    /// package root (used to detect the running-self-inside-the-package case).
    fn delegate_winget(&mut self, package_id: &str, scope: Scope, dir: &Path) -> Result<()>;
    /// Recursively delete a directory (absent is a no-op).
    fn remove_dir(&mut self, path: &Path) -> Result<()>;
    /// Remove `dir` from the user's PATH (Windows: the registry; Unix: print a
    /// manual hint, since the shell owns PATH).
    fn remove_path_entry(&mut self, dir: &Path) -> Result<()>;
}

/// Per-item outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ItemStatus {
    /// The item completed (or was already absent).
    Done,
    /// The item failed; carries the error text.
    Failed(String),
    /// The item was deliberately left in place — not a failure to fix, but a
    /// consequence of a choice (elevation declined at the UAC prompt, so the
    /// broker and its locked binary stay). Carries the plain-language reason.
    Skipped(String),
}

/// The result of executing a whole plan: one entry per item, in order.
#[derive(Debug, Clone, Default)]
pub(crate) struct RemovalOutcome {
    /// `(description, status)` for every item the executor touched.
    pub(crate) results: Vec<(String, ItemStatus)>,
}

impl RemovalOutcome {
    /// Record an item's description + status.
    fn record(&mut self, description: String, status: ItemStatus) {
        self.results.push((description, status));
    }

    /// Fold another outcome's results into this one, so the main plan and the
    /// stray removal report as a single combined outcome (one summary line, one
    /// retry hint) rather than two.
    pub(crate) fn absorb(&mut self, other: Self) {
        self.results.extend(other.results);
    }

    /// Whether nothing was executed (no items recorded).
    pub(crate) const fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Number of items that completed.
    pub(crate) fn done_count(&self) -> usize {
        self.results
            .iter()
            .filter(|(_, status)| *status == ItemStatus::Done)
            .count()
    }

    /// Number of items that failed.
    pub(crate) fn failed_count(&self) -> usize {
        self.results
            .iter()
            .filter(|(_, status)| matches!(status, ItemStatus::Failed(_)))
            .count()
    }

    /// Number of items deliberately left in place (e.g. the broker after a
    /// declined elevation).
    pub(crate) fn skipped_count(&self) -> usize {
        self.results
            .iter()
            .filter(|(_, status)| matches!(status, ItemStatus::Skipped(_)))
            .count()
    }

    /// Whether the run removed everything it set out to — nothing failed and
    /// nothing was left behind. Gates the "all gone" verification claim.
    pub(crate) fn is_clean(&self) -> bool {
        self.failed_count() == 0 && self.skipped_count() == 0
    }
}

/// Execute `plan` in order against `effects`, recording each item's outcome.
/// Best-effort: a failing item is recorded and the walk continues.
///
/// `broker_remains` is `true` when the Access Broker service will still be
/// installed after this run — the non-elevated "continue without" choice drops
/// the service item up front — so its binary is locked from the start and is
/// *left* rather than fought. It also flips `true` if an in-plan service
/// removal is declined at the UAC prompt. Either way the broker's binary is
/// recorded as [`ItemStatus::Skipped`], never a raw Access-denied failure.
pub(crate) fn execute(
    plan: &RemovalPlan,
    effects: &mut dyn Effects,
    broker_remains: bool,
) -> RemovalOutcome {
    let mut outcome = RemovalOutcome::default();
    let mut remains = broker_remains;
    for item in plan.items() {
        run_item(item, effects, &mut remains, &mut outcome);
    }
    outcome
}

/// Execute one plan item, folding its result into `outcome`. Sets
/// `broker_remains` when an in-plan broker service removal is declined at the
/// UAC prompt, so the later broker binary is left rather than fought.
fn run_item(
    item: &PlanItem,
    effects: &mut dyn Effects,
    broker_remains: &mut bool,
    outcome: &mut RemovalOutcome,
) {
    let description = item.target.describe();
    if let PlanTarget::RemoveService { service } = &item.target {
        match effects.remove_service(service) {
            Ok(()) => outcome.record(description, ItemStatus::Done),
            Err(err) if err.downcast_ref::<ElevationDeclined>().is_some() => {
                *broker_remains = true;
                outcome.record(
                    description,
                    ItemStatus::Skipped(BROKER_SERVICE_LEFT.to_owned()),
                );
            }
            Err(err) => outcome.record(description, ItemStatus::Failed(format!("{err:#}"))),
        }
        return;
    }
    // Winget refuses user-scope uninstalls from an elevated session — record
    // the delegation as deliberately LEFT with the exact next step, instead of
    // a raw failure.
    if let PlanTarget::DelegateWinget { .. } = &item.target {
        let status = match dispatch(&item.target, effects) {
            Ok(()) => ItemStatus::Done,
            Err(err) if err.downcast_ref::<WingetNeedsNonElevated>().is_some() => {
                ItemStatus::Skipped(WINGET_LEFT.to_owned())
            }
            Err(err) if err.downcast_ref::<WingetDeferred>().is_some() => {
                ItemStatus::Skipped(WINGET_DEFERRED.to_owned())
            }
            Err(err) if err.downcast_ref::<WingetBlockedByBroker>().is_some() => {
                ItemStatus::Skipped(WINGET_BLOCKED_BY_BROKER.to_owned())
            }
            Err(err) => ItemStatus::Failed(format!("{err:#}")),
        };
        outcome.record(description, status);
        return;
    }
    // The broker service is staying (declined, or the non-elevated run left it),
    // so it still runs and locks uffs-broker.exe: delete the other runtime
    // binaries, leave the broker's alongside its service.
    if let PlanTarget::DeleteBinaries { dir, stems } = &item.target
        && *broker_remains
        && stems.iter().any(|stem| is_broker_stem(stem))
    {
        delete_binaries_leaving_broker(dir, stems, effects, outcome);
        return;
    }
    let status = match dispatch(&item.target, effects) {
        Ok(()) => ItemStatus::Done,
        Err(err) => ItemStatus::Failed(format!("{err:#}")),
    };
    outcome.record(description, status);
}

/// Delete every runtime binary in `dir` EXCEPT the broker's (whose service is
/// still running): the deletable ones are removed as one item, the broker
/// binary is recorded as left — a clean outcome, not an Access-denied failure.
fn delete_binaries_leaving_broker(
    dir: &Path,
    stems: &[String],
    effects: &mut dyn Effects,
    outcome: &mut RemovalOutcome,
) {
    let (broker, rest): (Vec<String>, Vec<String>) =
        stems.iter().cloned().partition(|stem| is_broker_stem(stem));
    if !rest.is_empty() {
        let description = format!("{} binaries in {}", rest.len(), dir.display());
        let status = match effects.delete_binaries(dir, &rest) {
            Ok(()) => ItemStatus::Done,
            Err(err) => ItemStatus::Failed(format!("{err:#}")),
        };
        outcome.record(description, status);
    }
    for stem in broker {
        outcome.record(
            format!(
                "{} in {}",
                super::effects::exe_file_name(&stem),
                dir.display()
            ),
            ItemStatus::Skipped(BROKER_BINARY_LEFT.to_owned()),
        );
    }
}

/// Route one target to the matching [`Effects`] call.
fn dispatch(target: &PlanTarget, effects: &mut dyn Effects) -> Result<()> {
    match target {
        PlanTarget::StopProcess { component, pid } => effects.stop_process(component, *pid),
        PlanTarget::RemoveService { service } => effects.remove_service(service),
        PlanTarget::DeleteBinaries { dir, stems } => effects.delete_binaries(dir, stems),
        #[cfg(windows)]
        PlanTarget::DeleteFile { path, .. } => effects.delete_file(path),
        PlanTarget::DelegateWinget {
            package_id,
            scope,
            dir,
        } => effects.delegate_winget(package_id, *scope, dir),
        PlanTarget::DeleteDir { path, .. } => effects.remove_dir(path),
        PlanTarget::RemovePathEntry { dir } => effects.remove_path_entry(dir),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use anyhow::{Result, anyhow};

    use super::{Effects, ItemStatus, execute};
    use crate::commands::uninstall::args::UninstallArgs;
    use crate::commands::uninstall::inventory::{
        ArtifactDir, ArtifactKind, BrokerServiceState, Inventory,
    };
    use crate::commands::uninstall::plan::build_plan;
    use crate::commands::update::model::{
        BinaryInfo, Channel, Component, DetectionReport, InstallRoot, RunningProcess, Scope,
    };

    /// Records the call sequence; never touches the filesystem. `fail_dir`
    /// makes the matching `remove_dir`/`delete_binaries` call fail, to
    /// exercise the best-effort path.
    #[derive(Default)]
    struct RecordingEffects {
        calls: Vec<String>,
        fail_marker: Option<String>,
        /// When set, `remove_service` returns [`super::ElevationDeclined`], as
        /// a declined UAC prompt does.
        decline_service: bool,
        /// When set, `delegate_winget` returns
        /// [`super::WingetNeedsNonElevated`], as an elevated session does.
        winget_elevated: bool,
    }

    impl Effects for RecordingEffects {
        fn stop_process(&mut self, component: &str, pid: u32) -> Result<()> {
            self.calls.push(format!("stop_process:{component}:{pid}"));
            Ok(())
        }
        fn remove_service(&mut self, service: &str) -> Result<()> {
            self.calls.push(format!("remove_service:{service}"));
            if self.decline_service {
                return Err(super::ElevationDeclined.into());
            }
            Ok(())
        }
        fn delete_binaries(&mut self, dir: &Path, stems: &[String]) -> Result<()> {
            self.calls
                .push(format!("delete_binaries:{}:{}", dir.display(), stems.len()));
            Ok(())
        }
        #[cfg(windows)]
        fn delete_file(&mut self, path: &Path) -> Result<()> {
            self.calls.push(format!("delete_file:{}", path.display()));
            Ok(())
        }
        fn delegate_winget(&mut self, package_id: &str, _scope: Scope, _dir: &Path) -> Result<()> {
            self.calls.push(format!("delegate_winget:{package_id}"));
            if self.winget_elevated {
                return Err(super::WingetNeedsNonElevated.into());
            }
            Ok(())
        }
        fn remove_dir(&mut self, path: &Path) -> Result<()> {
            let shown = path.display().to_string();
            self.calls.push(format!("remove_dir:{shown}"));
            if self.fail_marker.as_deref() == Some(shown.as_str()) {
                return Err(anyhow!("simulated permission denied"));
            }
            Ok(())
        }
        fn remove_path_entry(&mut self, dir: &Path) -> Result<()> {
            self.calls
                .push(format!("remove_path_entry:{}", dir.display()));
            Ok(())
        }
    }

    fn full_plan() -> crate::commands::uninstall::plan::RemovalPlan {
        let report = DetectionReport {
            roots: vec![InstallRoot {
                dir: PathBuf::from("/opt/uffs"),
                channel: Channel::Unmanaged,
                scope: Scope::User,
                anchored_by: Vec::new(),
                binaries: vec![BinaryInfo {
                    name: "uffs".to_owned(),
                    version: None,
                }],
            }],
            running: vec![RunningProcess {
                component: Component::Daemon,
                pid: 7,
                image_path: None,
                command_line: None,
                version: None,
            }],
        };
        let inventory = Inventory {
            dirs: vec![ArtifactDir {
                kind: ArtifactKind::Cache,
                path: PathBuf::from("/x/cache"),
                exists: true,
                size_bytes: 1,
            }],
            broker_service: BrokerServiceState::Absent,
        };
        build_plan(&report, &inventory, &UninstallArgs::default(), &[])
    }

    #[test]
    fn executes_every_item_in_group_order() {
        let plan = full_plan();
        let mut effects = RecordingEffects::default();
        let outcome = execute(&plan, &mut effects, false);
        // Teardown-last ordering: tool binaries first (the tooling stays
        // usable during the run), then the daemon shutdown, then the data
        // dirs it had open handles in.
        assert_eq!(effects.calls, vec![
            "delete_binaries:/opt/uffs:1".to_owned(),
            "stop_process:daemon:7".to_owned(),
            "remove_dir:/x/cache".to_owned(),
        ]);
        assert!(outcome.is_clean());
        assert_eq!(outcome.done_count(), 3);
    }

    /// A plan with the broker service installed + a root holding the broker
    /// binary alongside another runtime binary, so the decline path has both a
    /// service to leave and a broker image to leave.
    fn broker_plan() -> crate::commands::uninstall::plan::RemovalPlan {
        let report = DetectionReport {
            roots: vec![InstallRoot {
                dir: PathBuf::from("/opt/uffs"),
                channel: Channel::Unmanaged,
                scope: Scope::User,
                anchored_by: Vec::new(),
                binaries: ["uffsd", "uffs-broker"]
                    .into_iter()
                    .map(|name| BinaryInfo {
                        name: name.to_owned(),
                        version: None,
                    })
                    .collect(),
            }],
            running: Vec::new(),
        };
        let inventory = Inventory {
            dirs: Vec::new(),
            broker_service: BrokerServiceState::Installed,
        };
        build_plan(&report, &inventory, &UninstallArgs::default(), &[])
    }

    #[test]
    fn declined_elevation_leaves_the_broker_service_and_binary_not_fails_them() {
        let plan = broker_plan();
        let mut effects = RecordingEffects {
            decline_service: true,
            ..RecordingEffects::default()
        };
        // Broker is in the plan (an `e` run); the declined UAC flips the flag.
        let outcome = execute(&plan, &mut effects, false);

        // The broker binary is never even attempted (its service still runs);
        // only the service removal + the OTHER runtime binary were called.
        assert!(
            !effects
                .calls
                .iter()
                .any(|call| call.contains("uffs-broker")),
            "the broker binary delete must not be attempted: {:?}",
            effects.calls
        );
        // Two items LEFT (the service + the broker binary), zero hard failures.
        assert_eq!(outcome.skipped_count(), 2, "service + broker binary left");
        assert_eq!(outcome.failed_count(), 0, "nothing is a hard failure");
        assert!(!outcome.is_clean(), "leftovers mean the run is not clean");
        // The deletable runtime binary (uffsd) still went through as one item.
        assert!(
            effects
                .calls
                .iter()
                .any(|call| call == "delete_binaries:/opt/uffs:1"),
            "the non-broker runtime binary is still removed: {:?}",
            effects.calls
        );
    }

    #[test]
    fn broker_remains_leaves_the_broker_binary_up_front() {
        // The `c` path leaves the broker: the gate dropped the service item, so
        // the plan has NO RemoveService (modelled here with the service absent)
        // and `broker_remains` is true from the start. The broker binary is then
        // left without any remove_service call — no Access-denied.
        let report = DetectionReport {
            roots: vec![InstallRoot {
                dir: PathBuf::from("/opt/uffs"),
                channel: Channel::Unmanaged,
                scope: Scope::User,
                anchored_by: Vec::new(),
                binaries: ["uffsd", "uffs-broker"]
                    .into_iter()
                    .map(|name| BinaryInfo {
                        name: name.to_owned(),
                        version: None,
                    })
                    .collect(),
            }],
            running: Vec::new(),
        };
        let inventory = Inventory {
            dirs: Vec::new(),
            broker_service: BrokerServiceState::Absent,
        };
        let plan = build_plan(&report, &inventory, &UninstallArgs::default(), &[]);
        let mut effects = RecordingEffects::default();
        let outcome = execute(&plan, &mut effects, true);

        assert!(
            !effects
                .calls
                .iter()
                .any(|call| call.contains("remove_service")),
            "no service removal is attempted: {:?}",
            effects.calls
        );
        assert!(
            !effects
                .calls
                .iter()
                .any(|call| call.contains("uffs-broker")),
            "the locked broker binary is not attempted: {:?}",
            effects.calls
        );
        assert_eq!(outcome.skipped_count(), 1, "just the broker binary is left");
        assert_eq!(outcome.failed_count(), 0, "no Access-denied failure");
        // uffsd still deleted (the non-broker runtime binary).
        assert!(
            effects
                .calls
                .iter()
                .any(|call| call == "delete_binaries:/opt/uffs:1"),
            "the non-broker runtime binary is still removed: {:?}",
            effects.calls
        );
    }

    #[test]
    fn elevated_winget_refusal_is_left_with_the_non_admin_instruction() {
        // An elevated run delegating to winget: winget refuses user-scope
        // uninstalls from an admin session — the item must be LEFT (with the
        // run-it-non-admin reason), never a raw failure, and the rest of the
        // plan still executes.
        let report = DetectionReport {
            roots: vec![InstallRoot {
                dir: PathBuf::from(r"C:\winget\uffs"),
                channel: Channel::WinGet,
                scope: Scope::User,
                anchored_by: Vec::new(),
                binaries: vec![BinaryInfo {
                    name: "uffs".to_owned(),
                    version: None,
                }],
            }],
            running: Vec::new(),
        };
        let inventory = Inventory {
            dirs: vec![ArtifactDir {
                kind: ArtifactKind::Cache,
                path: PathBuf::from("/x/cache"),
                exists: true,
                size_bytes: 1,
            }],
            broker_service: BrokerServiceState::Absent,
        };
        let plan = build_plan(&report, &inventory, &UninstallArgs::default(), &[]);
        let mut effects = RecordingEffects {
            winget_elevated: true,
            ..RecordingEffects::default()
        };
        let outcome = execute(&plan, &mut effects, false);

        assert_eq!(outcome.failed_count(), 0, "no raw failure");
        assert_eq!(outcome.skipped_count(), 1, "the delegation is LEFT");
        let left = outcome
            .results
            .iter()
            .find_map(|(_, status)| {
                if let ItemStatus::Skipped(reason) = status {
                    Some(reason.clone())
                } else {
                    None
                }
            })
            .expect("a LEFT item");
        assert!(
            left.contains("non-admin"),
            "the reason carries the non-admin instruction: {left}"
        );
        // The cache dir still got removed (best-effort continues).
        assert!(
            effects
                .calls
                .iter()
                .any(|call| call == "remove_dir:/x/cache"),
            "rest of the plan still ran: {:?}",
            effects.calls
        );
    }

    #[test]
    fn a_failing_item_is_recorded_and_the_rest_continue() {
        let plan = full_plan();
        let mut effects = RecordingEffects {
            fail_marker: Some("/x/cache".to_owned()),
            ..RecordingEffects::default()
        };
        let outcome = execute(&plan, &mut effects, false);
        // All three were attempted; the cache dir failed, the other two done.
        assert_eq!(effects.calls.len(), 3);
        assert_eq!(outcome.failed_count(), 1);
        assert_eq!(outcome.done_count(), 2);
        assert!(!outcome.is_clean());
        let failed = outcome
            .results
            .iter()
            .find(|(_, status)| matches!(status, ItemStatus::Failed(_)))
            .expect("a failed item");
        assert!(failed.0.contains("cache"));
    }
}
