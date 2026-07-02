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

use super::plan::{PlanTarget, RemovalPlan};
use crate::commands::update::model::Scope;

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
    /// Hand a `WinGet`-managed root to `winget uninstall`.
    fn delegate_winget(&mut self, package_id: &str, scope: Scope) -> Result<()>;
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

    /// Whether every item completed.
    pub(crate) fn all_done(&self) -> bool {
        self.failed_count() == 0
    }
}

/// Execute `plan` in order against `effects`, recording each item's outcome.
/// Best-effort: a failing item is recorded and the walk continues.
pub(crate) fn execute(plan: &RemovalPlan, effects: &mut dyn Effects) -> RemovalOutcome {
    let mut outcome = RemovalOutcome::default();
    for item in plan.items() {
        let description = item.target.describe();
        let status = match dispatch(&item.target, effects) {
            Ok(()) => ItemStatus::Done,
            Err(err) => ItemStatus::Failed(format!("{err:#}")),
        };
        outcome.record(description, status);
    }
    outcome
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
            package_id, scope, ..
        } => effects.delegate_winget(package_id, *scope),
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
    }

    impl Effects for RecordingEffects {
        fn stop_process(&mut self, component: &str, pid: u32) -> Result<()> {
            self.calls.push(format!("stop_process:{component}:{pid}"));
            Ok(())
        }
        fn remove_service(&mut self, service: &str) -> Result<()> {
            self.calls.push(format!("remove_service:{service}"));
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
        fn delegate_winget(&mut self, package_id: &str, _scope: Scope) -> Result<()> {
            self.calls.push(format!("delegate_winget:{package_id}"));
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
        let outcome = execute(&plan, &mut effects);
        // Teardown-last ordering: tool binaries first (the tooling stays
        // usable during the run), then the daemon shutdown, then the data
        // dirs it had open handles in.
        assert_eq!(effects.calls, vec![
            "delete_binaries:/opt/uffs:1".to_owned(),
            "stop_process:daemon:7".to_owned(),
            "remove_dir:/x/cache".to_owned(),
        ]);
        assert!(outcome.all_done());
        assert_eq!(outcome.done_count(), 3);
    }

    #[test]
    fn a_failing_item_is_recorded_and_the_rest_continue() {
        let plan = full_plan();
        let mut effects = RecordingEffects {
            fail_marker: Some("/x/cache".to_owned()),
            ..RecordingEffects::default()
        };
        let outcome = execute(&plan, &mut effects);
        // All three were attempted; the cache dir failed, the other two done.
        assert_eq!(effects.calls.len(), 3);
        assert_eq!(outcome.failed_count(), 1);
        assert_eq!(outcome.done_count(), 2);
        assert!(!outcome.all_done());
        let failed = outcome
            .results
            .iter()
            .find(|(_, status)| matches!(status, ItemStatus::Failed(_)))
            .expect("a failed item");
        assert!(failed.0.contains("cache"));
    }
}
