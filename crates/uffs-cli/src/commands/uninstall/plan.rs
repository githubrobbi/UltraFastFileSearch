// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Removal-plan construction for `uffs --uninstall` (task U-20 of
//! `docs/dev/architecture/UFFS-Uninstall-Implementation-Plan.md`).
//!
//! Pure: turns the analysis ([`DetectionReport`] + [`Inventory`]) into an
//! ordered, itemized [`RemovalPlan`], honoring `--keep-config` / `--scope`.
//! No IO, fully unit-tested. `WinGet` roots become a `winget uninstall`
//! delegation, never a hand-delete (design §7).
//!
//! Each [`PlanItem`] carries a structured [`PlanTarget`] — the single source of
//! truth that both the renderer (description / `--json`) and the executor
//! (M4 `remove`) consume, so what is shown is exactly what is removed.

use std::path::{Path, PathBuf};

use super::args::{UninstallArgs, UninstallScope};
use super::inventory::{ArtifactKind, BrokerServiceState, Inventory};
#[cfg(windows)]
use super::sweep::StrayHit;
use crate::commands::update::model::{Channel, Component, DetectionReport, InstallRoot, Scope};

/// The `WinGet` package id UFFS publishes under.
pub(crate) const WINGET_PACKAGE_ID: &str = "SkyLLC.UFFS";

/// The concrete target of a plan item: everything the executor needs, and
/// everything the renderer describes. Group ordering (in [`build_plan`]) plus
/// this discriminant define the safe removal order.
#[derive(Debug, Clone)]
pub(crate) enum PlanTarget {
    /// Stop a running UFFS process (daemon / MCP gateway).
    StopProcess {
        /// Component label (e.g. `daemon`).
        component: String,
        /// OS process id.
        pid: u32,
    },
    /// Stop + delete the broker Windows service.
    RemoveService {
        /// Service name (`UffsAccessBroker`).
        service: String,
    },
    /// Delete the UFFS binaries in an unmanaged / dev-build root.
    DeleteBinaries {
        /// The root directory.
        dir: PathBuf,
        /// The binary stems present in the root (no `.exe` suffix).
        stems: Vec<String>,
    },
    /// Delegate a `WinGet`-managed root to `winget uninstall`.
    DelegateWinget {
        /// The package id to uninstall.
        package_id: String,
        /// The root's install scope (user / machine).
        scope: Scope,
        /// The root directory (for the description).
        dir: PathBuf,
    },
    /// Recursively delete a data / cache / config directory.
    DeleteDir {
        /// The directory to remove.
        path: PathBuf,
        /// The artifact-kind label (e.g. `cache`), for the description.
        label: &'static str,
    },
    /// Remove a (provably UFFS) directory from PATH.
    RemovePathEntry {
        /// The PATH entry to remove.
        dir: PathBuf,
    },
    /// Delete a single stray UFFS file the deep sweep found outside the known
    /// roots. Confirmed separately from the main plan. Windows-only (the deep
    /// sweep does not run off Windows).
    #[cfg(windows)]
    DeleteFile {
        /// Absolute path of the stray file.
        path: PathBuf,
        /// Parsed `--version` if it is a probeable binary (display only).
        version: Option<String>,
    },
}

impl PlanTarget {
    /// Short verb label (used in `--json`).
    pub(crate) const fn action_label(&self) -> &'static str {
        match *self {
            Self::StopProcess { .. } => "stop-process",
            Self::RemoveService { .. } => "remove-service",
            Self::DeleteBinaries { .. } => "delete-binaries",
            Self::DelegateWinget { .. } => "delegate-winget",
            Self::DeleteDir { .. } => "delete-dir",
            Self::RemovePathEntry { .. } => "remove-path-entry",
            #[cfg(windows)]
            Self::DeleteFile { .. } => "delete-file",
        }
    }

    /// Human, one-line description of the target.
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::StopProcess { component, pid } => format!("{component} (pid {pid})"),
            Self::RemoveService { service } => format!("Stop + delete service {service}"),
            Self::DeleteBinaries { dir, stems } => {
                format!("{} binaries in {}", stems.len(), dir.display())
            }
            Self::DelegateWinget {
                package_id,
                scope,
                dir,
            } => format!(
                "winget uninstall {package_id}  ({} root: {})",
                scope.label(),
                dir.display()
            ),
            Self::DeleteDir { path, label } => format!("{label} ({})", path.display()),
            Self::RemovePathEntry { dir } => format!("PATH entry {}", dir.display()),
            #[cfg(windows)]
            Self::DeleteFile { path, version } => version.as_ref().map_or_else(
                || path.display().to_string(),
                |ver| format!("{} (v{ver})", path.display()),
            ),
        }
    }
}

/// Coarse scope of a plan item, for `--scope` filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ItemScope {
    /// A per-user artifact (`%LOCALAPPDATA%`, a user-scope root).
    User,
    /// A machine-wide artifact (the service, a `%PROGRAMFILES%` root).
    Machine,
    /// Scope-agnostic (a running process).
    Any,
}

/// One unit of removal work.
#[derive(Debug, Clone)]
pub(crate) struct PlanItem {
    /// What to remove (structured; drives both render and execute).
    pub(crate) target: PlanTarget,
    /// Whether performing it requires Administrator.
    pub(crate) needs_elevation: bool,
    /// Coarse scope, for `--scope` filtering.
    pub(crate) scope: ItemScope,
    /// Bytes this item reclaims (0 for non-filesystem actions).
    pub(crate) bytes: u64,
}

/// A named, ordered group of plan items (Services, Processes, ...).
#[derive(Debug, Clone)]
pub(crate) struct PlanGroup {
    /// Group heading.
    pub(crate) title: &'static str,
    /// Items in the group.
    pub(crate) items: Vec<PlanItem>,
}

/// The full ordered removal plan.
#[derive(Debug, Clone, Default)]
pub(crate) struct RemovalPlan {
    /// Groups in safe removal order.
    pub(crate) groups: Vec<PlanGroup>,
}

impl RemovalPlan {
    /// Iterate every item across all groups, in order.
    pub(crate) fn items(&self) -> impl Iterator<Item = &PlanItem> {
        self.groups.iter().flat_map(|group| &group.items)
    }

    /// Total bytes the plan would reclaim.
    pub(crate) fn total_bytes(&self) -> u64 {
        self.items()
            .map(|item| item.bytes)
            .fold(0, u64::saturating_add)
    }

    /// Whether any item requires Administrator.
    pub(crate) fn requires_elevation(&self) -> bool {
        self.items().any(|item| item.needs_elevation)
    }

    /// Drop every item that needs Administrator (the broker service + its
    /// process), removing any group left empty. Lets a non-elevated run remove
    /// everything it *can* and leave the broker for an elevated re-run. Returns
    /// the dropped items' descriptions so the final summary can list exactly
    /// what this run skips.
    pub(crate) fn drop_elevation_required(&mut self) -> Vec<String> {
        let mut dropped: Vec<String> = Vec::new();
        for group in &mut self.groups {
            group.items.retain(|item| {
                if item.needs_elevation {
                    dropped.push(item.target.describe());
                    return false;
                }
                true
            });
        }
        self.groups.retain(|group| !group.items.is_empty());
        dropped
    }

    /// Number of items across all groups.
    pub(crate) fn item_count(&self) -> usize {
        self.groups.iter().map(|group| group.items.len()).sum()
    }

    /// True when there is nothing to remove.
    pub(crate) fn is_empty(&self) -> bool {
        self.item_count() == 0
    }
}

/// Build the ordered removal plan from the analysis + flags.
/// `removable_path_dirs` is the already-vetted set of PATH directories safe to
/// drop — dedicated UFFS roots only (see
/// [`super::analyze::removable_path_dirs`]). A shared bin dir is never in it,
/// so PATH cleanup never touches the user's general toolchain location.
pub(crate) fn build_plan(
    report: &DetectionReport,
    inventory: &Inventory,
    args: &UninstallArgs,
    removable_path_dirs: &[PathBuf],
) -> RemovalPlan {
    let mut groups: Vec<PlanGroup> = Vec::new();

    // 1. Services (the broker, elevated) — removed first conceptually.
    if inventory.broker_service == BrokerServiceState::Installed {
        let item = PlanItem {
            target: PlanTarget::RemoveService {
                service: uffs_broker_protocol::SERVICE_NAME.to_owned(),
            },
            needs_elevation: true,
            scope: ItemScope::Machine,
            bytes: 0,
        };
        push_group(&mut groups, "Services", vec![item], args.scope);
    }

    // 2. Processes (stopped before their binaries are deleted). The broker is a
    // LocalSystem **service** — `taskkill` can't stop it (returns exit 128, and
    // the SCM would just restart it), so it is never a StopProcess item; the
    // RemoveService item above stops + deletes it via `sc`. The daemon / MCP are
    // ordinary user-owned processes, so a plain stop applies and needs no admin.
    let processes: Vec<PlanItem> = report
        .running
        .iter()
        .filter(|process| !matches!(process.component, Component::Broker))
        .map(|process| PlanItem {
            target: PlanTarget::StopProcess {
                component: process.component.label().to_owned(),
                pid: process.pid,
            },
            needs_elevation: false,
            scope: ItemScope::Any,
            bytes: 0,
        })
        .collect();
    push_group(
        &mut groups,
        "Processes (stopped first)",
        processes,
        args.scope,
    );

    // 3. Binaries — per root: unmanaged/dev delete, winget delegate.
    let binaries: Vec<PlanItem> = report.roots.iter().filter_map(binary_item).collect();
    push_group(&mut groups, "Binaries", binaries, args.scope);

    // 4. Data / cache / config dirs that exist (skip config under --keep-config).
    let dirs: Vec<PlanItem> = inventory
        .dirs
        .iter()
        .filter(|dir| dir.exists)
        .filter(|dir| !(args.keep_config && dir.kind == ArtifactKind::Config))
        .map(|dir| PlanItem {
            target: PlanTarget::DeleteDir {
                path: dir.path.clone(),
                label: dir.kind.label(),
            },
            needs_elevation: false,
            scope: ItemScope::User,
            bytes: dir.size_bytes,
        })
        .collect();
    push_group(&mut groups, "Data / cache / config", dirs, args.scope);

    // 5. PATH entries that point at a removed unmanaged/dev root that is
    // *dedicated* to UFFS (only uffs* files) — provably ours, so safe to drop. A
    // shared bin dir (~/bin, ~/.local/bin) is filtered out upstream and never
    // appears here. WinGet roots are managed by winget. Skipped under --no-path.
    if !args.no_path {
        let path_items: Vec<PlanItem> = report
            .roots
            .iter()
            .filter(|root| !root.binaries.is_empty() && !matches!(root.channel, Channel::WinGet))
            .filter(|root| {
                removable_path_dirs
                    .iter()
                    .any(|dir| paths_equal_ignore_case(dir, &root.dir))
            })
            .map(|root| {
                let machine = matches!(root.scope, Scope::Machine);
                PlanItem {
                    target: PlanTarget::RemovePathEntry {
                        dir: root.dir.clone(),
                    },
                    needs_elevation: machine,
                    scope: if machine {
                        ItemScope::Machine
                    } else {
                        ItemScope::User
                    },
                    bytes: 0,
                }
            })
            .collect();
        push_group(&mut groups, "PATH", path_items, args.scope);
    }

    RemovalPlan { groups }
}

/// Build a one-group plan for the stray files the deep sweep found outside the
/// known roots. Presented + confirmed **separately** from the main plan (a copy
/// the user placed themselves might be among them). Each item is a best-effort
/// single-file delete; none require elevation up front — a protected location
/// simply fails best-effort and is reported. Windows-only (the deep sweep does
/// not run off Windows).
#[cfg(windows)]
pub(crate) fn build_stray_plan(strays: &[StrayHit]) -> RemovalPlan {
    if strays.is_empty() {
        return RemovalPlan::default();
    }
    let items: Vec<PlanItem> = strays
        .iter()
        .map(|stray| PlanItem {
            target: PlanTarget::DeleteFile {
                path: stray.path.clone(),
                version: stray.version.clone(),
            },
            needs_elevation: false,
            scope: ItemScope::Any,
            bytes: 0,
        })
        .collect();
    RemovalPlan {
        groups: vec![PlanGroup {
            title: "Found elsewhere (deep sweep)",
            items,
        }],
    }
}

/// Case-insensitive path equality (Windows file systems + PATH entries vary in
/// case; a redundant exact match is what we require before touching PATH).
fn paths_equal_ignore_case(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

/// Build the per-root binary plan item, or `None` for an empty root.
fn binary_item(root: &InstallRoot) -> Option<PlanItem> {
    if root.binaries.is_empty() {
        return None;
    }
    let needs_elevation = binaries_need_escalation(root.scope, &root.dir);
    let item_scope = if needs_elevation {
        ItemScope::Machine
    } else {
        ItemScope::User
    };
    let target = match root.channel {
        Channel::WinGet => PlanTarget::DelegateWinget {
            package_id: WINGET_PACKAGE_ID.to_owned(),
            scope: root.scope,
            dir: root.dir.clone(),
        },
        Channel::Unmanaged | Channel::DevBuild | Channel::Unknown => PlanTarget::DeleteBinaries {
            dir: root.dir.clone(),
            stems: root.binaries.iter().map(|bin| bin.name.clone()).collect(),
        },
    };
    Some(PlanItem {
        target,
        needs_elevation,
        scope: item_scope,
        bytes: 0,
    })
}

/// Whether removing the UFFS binaries in `dir` (of install `scope`) needs
/// privilege escalation the current user may not have.
///
/// Windows: machine-scope roots (`%PROGRAMFILES%`) need Administrator; the
/// classified scope already captures this.
#[cfg(windows)]
const fn binaries_need_escalation(scope: Scope, _dir: &Path) -> bool {
    matches!(scope, Scope::Machine)
}

/// Unix variant (see the Windows declaration): probe `dir` with a POSIX
/// `access(W_OK)` check — a user-owned root (`~/bin`, `~/.cargo/bin`, a dev
/// build) is removable without `sudo`, while a root-owned one
/// (`/usr/local/bin`) is flagged before the executor tries.
#[cfg(unix)]
fn binaries_need_escalation(_scope: Scope, dir: &Path) -> bool {
    !uffs_mft::platform::dir_user_writable(dir)
}

/// Fallback for non-Windows, non-Unix targets: never require escalation.
#[cfg(not(any(windows, unix)))]
fn binaries_need_escalation(_scope: Scope, _dir: &Path) -> bool {
    false
}

/// Apply the `--scope` filter and append the group only if it has items left.
fn push_group(
    groups: &mut Vec<PlanGroup>,
    title: &'static str,
    items: Vec<PlanItem>,
    scope: UninstallScope,
) {
    let kept: Vec<PlanItem> = items
        .into_iter()
        .filter(|item| scope_admits(scope, item.scope))
        .collect();
    if !kept.is_empty() {
        groups.push(PlanGroup { title, items: kept });
    }
}

/// Whether a `--scope` request admits an item of the given scope.
const fn scope_admits(requested: UninstallScope, item: ItemScope) -> bool {
    match (requested, item) {
        (UninstallScope::All, _)
        | (_, ItemScope::Any)
        | (UninstallScope::User, ItemScope::User)
        | (UninstallScope::Machine, ItemScope::Machine) => true,
        (UninstallScope::User, ItemScope::Machine) | (UninstallScope::Machine, ItemScope::User) => {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    #[cfg(windows)]
    use super::build_stray_plan;
    use super::{PlanTarget, RemovalPlan, build_plan};
    use crate::commands::uninstall::args::{UninstallArgs, UninstallScope};
    use crate::commands::uninstall::inventory::{
        ArtifactDir, ArtifactKind, BrokerServiceState, Inventory,
    };
    use crate::commands::update::model::{
        BinaryInfo, Channel, Component, DetectionReport, InstallRoot, RunningProcess, Scope,
    };

    fn root(channel: Channel, scope: Scope, dir: &str) -> InstallRoot {
        InstallRoot {
            dir: PathBuf::from(dir),
            channel,
            scope,
            anchored_by: Vec::new(),
            binaries: vec![BinaryInfo {
                name: "uffs".to_owned(),
                version: Some("0.6.16".to_owned()),
            }],
        }
    }

    fn inventory(broker: BrokerServiceState, config_size: u64) -> Inventory {
        Inventory {
            dirs: vec![
                ArtifactDir {
                    kind: ArtifactKind::Cache,
                    path: PathBuf::from("/x/cache"),
                    exists: true,
                    size_bytes: 2048,
                },
                ArtifactDir {
                    kind: ArtifactKind::Config,
                    path: PathBuf::from("/x/config"),
                    exists: true,
                    size_bytes: config_size,
                },
            ],
            broker_service: broker,
        }
    }

    fn has_target(plan: &RemovalPlan, predicate: impl Fn(&PlanTarget) -> bool) -> bool {
        plan.items().any(|item| predicate(&item.target))
    }

    /// Build a plan with no PATH entries (PATH has its own dedicated test).
    fn built(report: &DetectionReport, inventory: &Inventory, args: &UninstallArgs) -> RemovalPlan {
        build_plan(report, inventory, args, &[])
    }

    #[test]
    fn winget_root_is_delegated_not_deleted() {
        let report = DetectionReport {
            roots: vec![root(Channel::WinGet, Scope::User, r"C:\winget\uffs")],
            running: Vec::new(),
        };
        let plan = built(
            &report,
            &inventory(BrokerServiceState::Absent, 1024),
            &UninstallArgs::default(),
        );
        assert!(has_target(&plan, |target| matches!(
            target,
            PlanTarget::DelegateWinget { .. }
        )));
        assert!(!has_target(&plan, |target| matches!(
            target,
            PlanTarget::DeleteBinaries { .. }
        )));
    }

    #[test]
    fn machine_root_needs_elevation() {
        let report = DetectionReport {
            roots: vec![root(
                Channel::Unmanaged,
                Scope::Machine,
                r"C:\Program Files\uffs",
            )],
            running: Vec::new(),
        };
        let plan = built(
            &report,
            &inventory(BrokerServiceState::Absent, 1024),
            &UninstallArgs::default(),
        );
        assert!(plan.requires_elevation());
    }

    #[test]
    fn service_present_requires_elevation_and_is_first() {
        let report = DetectionReport {
            roots: Vec::new(),
            running: Vec::new(),
        };
        let plan = built(
            &report,
            &inventory(BrokerServiceState::Installed, 1024),
            &UninstallArgs::default(),
        );
        assert!(plan.requires_elevation());
        assert!(has_target(&plan, |target| matches!(
            target,
            PlanTarget::RemoveService { .. }
        )));
        assert_eq!(plan.groups.first().expect("a group").title, "Services");
    }

    #[test]
    fn keep_config_drops_the_config_dir() {
        let report = DetectionReport {
            roots: Vec::new(),
            running: Vec::new(),
        };
        let inv = inventory(BrokerServiceState::Absent, 4096);
        let with_config = built(&report, &inv, &UninstallArgs::default());
        let keep = UninstallArgs {
            keep_config: true,
            ..UninstallArgs::default()
        };
        let without_config = built(&report, &inv, &keep);
        assert!(with_config.total_bytes() > without_config.total_bytes());
    }

    #[test]
    fn scope_user_excludes_the_machine_service() {
        let report = DetectionReport {
            roots: Vec::new(),
            running: Vec::new(),
        };
        let user_only = UninstallArgs {
            scope: UninstallScope::User,
            ..UninstallArgs::default()
        };
        let plan = built(
            &report,
            &inventory(BrokerServiceState::Installed, 1024),
            &user_only,
        );
        assert!(!has_target(&plan, |target| matches!(
            target,
            PlanTarget::RemoveService { .. }
        )));
        assert!(!plan.requires_elevation());
    }

    #[test]
    fn running_process_becomes_a_stop_item() {
        let report = DetectionReport {
            roots: Vec::new(),
            running: vec![RunningProcess {
                component: Component::Daemon,
                pid: 4242,
                image_path: None,
                command_line: None,
                version: None,
            }],
        };
        let plan = built(
            &report,
            &inventory(BrokerServiceState::Absent, 1024),
            &UninstallArgs::default(),
        );
        assert!(has_target(&plan, |target| matches!(
            target,
            PlanTarget::StopProcess { .. }
        )));
    }

    #[test]
    fn drop_elevation_required_removes_broker_keeps_the_rest() {
        let report = DetectionReport {
            roots: Vec::new(),
            running: vec![
                RunningProcess {
                    component: Component::Broker,
                    pid: 11,
                    image_path: None,
                    command_line: None,
                    version: None,
                },
                RunningProcess {
                    component: Component::Daemon,
                    pid: 22,
                    image_path: None,
                    command_line: None,
                    version: None,
                },
            ],
        };
        // Broker service installed -> an admin-only RemoveService item. The
        // broker *process* is filtered out (it's a service, stopped via sc, not
        // taskkill); only the user-owned daemon stop remains, needing no admin.
        let mut plan = built(
            &report,
            &inventory(BrokerServiceState::Installed, 1024),
            &UninstallArgs::default(),
        );
        assert!(
            plan.requires_elevation(),
            "broker service + process need admin"
        );

        let dropped = plan.drop_elevation_required();
        assert!(!plan.requires_elevation(), "admin-only items were dropped");
        assert!(
            !dropped.is_empty() && dropped.iter().all(|desc| !desc.is_empty()),
            "the dropped items are returned as human descriptions for the summary"
        );
        assert!(
            !has_target(&plan, |target| matches!(
                target,
                PlanTarget::RemoveService { .. }
            )),
            "the broker service item is gone"
        );
        let stop_pids: Vec<u32> = plan
            .items()
            .filter_map(|item| {
                if let PlanTarget::StopProcess { pid, .. } = &item.target {
                    Some(*pid)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(stop_pids, vec![22], "only the daemon stop survives");
    }

    #[test]
    #[cfg(windows)]
    fn stray_plan_is_one_group_of_unprivileged_delete_file_items() {
        use crate::commands::uninstall::sweep::StrayHit;

        assert!(build_stray_plan(&[]).is_empty(), "no strays -> empty plan");
        let strays = vec![
            StrayHit {
                path: PathBuf::from("/home/me/Downloads/uffs"),
                version: Some("0.5.0".to_owned()),
            },
            StrayHit {
                path: PathBuf::from("/tmp/x_compact.uffs"),
                version: None,
            },
        ];
        let plan = build_stray_plan(&strays);
        assert_eq!(plan.item_count(), 2);
        assert!(
            plan.items()
                .all(|item| matches!(item.target, PlanTarget::DeleteFile { .. })),
            "every stray item is a DeleteFile"
        );
        assert!(
            !plan.requires_elevation(),
            "strays never require up-front elevation (best-effort on failure)"
        );
    }

    #[test]
    fn path_entry_matching_a_removed_root_is_offered_and_respects_no_path() {
        let report = DetectionReport {
            roots: vec![root(Channel::Unmanaged, Scope::User, r"C:\Users\me\bin")],
            running: Vec::new(),
        };
        let inv = inventory(BrokerServiceState::Absent, 1024);
        // The 4th arg is the already-vetted removable-dir set; a case-insensitive
        // match to the removed root → offered. (Exclusivity vetting is tested in
        // analyze::removable_path_dirs; here we exercise build_plan's emission.)
        let on_path = [PathBuf::from(r"c:\users\me\bin")];
        let offered = build_plan(&report, &inv, &UninstallArgs::default(), &on_path);
        assert!(has_target(&offered, |target| matches!(
            target,
            PlanTarget::RemovePathEntry { .. }
        )));
        // --no-path suppresses the PATH group entirely.
        let no_path = UninstallArgs {
            no_path: true,
            ..UninstallArgs::default()
        };
        let suppressed = build_plan(&report, &inv, &no_path, &on_path);
        assert!(!has_target(&suppressed, |target| matches!(
            target,
            PlanTarget::RemovePathEntry { .. }
        )));
        // A PATH entry that does not match any root is never touched.
        let unrelated = [PathBuf::from(r"C:\unrelated")];
        let untouched = build_plan(&report, &inv, &UninstallArgs::default(), &unrelated);
        assert!(!has_target(&untouched, |target| matches!(
            target,
            PlanTarget::RemovePathEntry { .. }
        )));
    }

    #[cfg(unix)]
    #[test]
    fn unix_user_writable_root_skips_escalation_root_owned_flags_it() {
        use std::path::Path;

        use super::binaries_need_escalation;
        // The temp dir is user-writable → removable without sudo.
        assert!(!binaries_need_escalation(
            Scope::Unknown,
            &std::env::temp_dir()
        ));
        // A non-existent / unwritable path → flagged for escalation.
        assert!(binaries_need_escalation(
            Scope::Unknown,
            Path::new("/nonexistent/uffs-escalation-probe")
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_escalation_follows_machine_scope() {
        use std::path::Path;

        use super::binaries_need_escalation;
        assert!(binaries_need_escalation(
            Scope::Machine,
            Path::new(r"C:\Program Files\uffs")
        ));
        assert!(!binaries_need_escalation(
            Scope::User,
            Path::new(r"C:\Users\me\bin")
        ));
    }
}
