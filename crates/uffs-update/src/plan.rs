// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Typed read of the Phase-B snapshot (design §13) — the input to apply,
//! quiesce, and restore.
//!
//! The snapshot is written by `uffs --update --snapshot` (in `uffs-cli`);
//! the apply helper reads it back here. Only the fields the mutating
//! phases need are modelled; unknown fields are ignored so the schema can
//! grow without breaking older helpers.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::Deserialize;

/// Snapshot binary stem for the Access Broker (`uffs-broker.exe`).
const BROKER_STEM: &str = "uffs-broker";
/// Snapshot running-component name for the Access Broker (vs. its binary stem).
const BROKER_COMPONENT: &str = "broker";

/// A parsed Phase-B snapshot.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Snapshot {
    /// Target version the snapshot was captured against (if recorded).
    #[serde(default)]
    pub(crate) to_version: Option<String>,
    /// Install roots = update targets.
    #[serde(default)]
    pub(crate) targets: Vec<SnapTarget>,
    /// Live processes (how to stop + restart each).
    #[serde(default)]
    pub(crate) running: Vec<SnapRunning>,
}

/// One install root from the snapshot.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SnapTarget {
    /// Install directory.
    pub(crate) root: PathBuf,
    /// Channel (`winget` / `unmanaged` / `dev-build`).
    pub(crate) channel: String,
    /// Binaries present in this root.
    #[serde(default)]
    pub(crate) binaries: Vec<SnapBinary>,
}

/// One binary entry from the snapshot.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SnapBinary {
    /// Logical stem (e.g. `uffsd`).
    pub(crate) name: String,
    /// On-disk version at snapshot time.
    #[serde(default)]
    pub(crate) on_disk_version: Option<String>,
}

/// One live process from the snapshot (the restart recipe).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SnapRunning {
    /// Component kind: `daemon` / `broker` / `mcp`.
    pub(crate) component: String,
    /// OS process id at snapshot time. The doctor probes its liveness;
    /// quiesce/restore act via the PID file + native SCM (`uffs-winsvc`) +
    /// the captured command line, never this (stale-by-restart) raw pid.
    pub(crate) pid: u32,
    /// Image path.
    #[serde(default)]
    pub(crate) image_path: Option<PathBuf>,
    /// Exact launch command line (the restart recipe).
    #[serde(default)]
    pub(crate) command_line: Option<String>,
}

impl Snapshot {
    /// Load + parse a snapshot file.
    ///
    /// # Errors
    ///
    /// Fails if the file is missing or not valid snapshot JSON.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading snapshot {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing snapshot {}", path.display()))
    }

    /// The version this update is moving *to* (falls back to `unknown`).
    pub(crate) fn to_version(&self) -> &str {
        self.to_version.as_deref().unwrap_or("unknown")
    }

    /// Remove the Access Broker from this snapshot so a non-elevated apply
    /// leaves it alone.
    ///
    /// The broker is a `LocalSystem` service: stopping it (to unlock its
    /// `.exe`) and restarting it both need elevation, and its wire protocol is
    /// fixed/back-compatible — so a slightly-older broker keeps serving a newer
    /// daemon. Drops the `broker` running entry and every `uffs-broker` binary
    /// target. Returns the broker's on-disk version (for a user hint), or
    /// `None` when the snapshot had no broker at all (e.g. off Windows).
    pub(crate) fn drop_broker(&mut self) -> Option<String> {
        let present = self
            .running
            .iter()
            .any(|run| run.component == BROKER_COMPONENT)
            || self
                .targets
                .iter()
                .any(|tgt| tgt.binaries.iter().any(|bin| bin.name == BROKER_STEM));
        if !present {
            return None;
        }
        let version = self
            .targets
            .iter()
            .flat_map(|tgt| &tgt.binaries)
            .find(|bin| bin.name == BROKER_STEM)
            .and_then(|bin| bin.on_disk_version.clone())
            .unwrap_or_else(|| "?".to_owned());
        self.running.retain(|run| run.component != BROKER_COMPONENT);
        for target in &mut self.targets {
            target.binaries.retain(|bin| bin.name != BROKER_STEM);
        }
        Some(version)
    }

    /// Whether a broker service is actually **running** in this snapshot (a
    /// `broker` entry in `running`). Only then does updating `uffs-broker.exe`
    /// require elevation (to stop/restart the `LocalSystem` service). A plain
    /// `uffs-broker.exe` file with no running service is just another binary
    /// and can be swapped in place like the rest.
    pub(crate) fn broker_is_running(&self) -> bool {
        self.running
            .iter()
            .any(|run| run.component == BROKER_COMPONENT)
    }

    /// Whether the Access Broker binary lives under a `WinGet`-delegated root.
    /// When it does, a non-elevated apply skips the broker here, but the
    /// caller's `winget upgrade` refreshes `uffs-broker.exe` and cycles the
    /// service — so the broker is NOT left at the old version and the
    /// "left running and NOT updated" hint would be wrong. Must be read
    /// **before** [`Self::drop_broker`], which strips the broker entries.
    pub(crate) fn broker_in_winget_root(&self) -> bool {
        self.targets.iter().any(|target| {
            target.channel == "winget" && target.binaries.iter().any(|bin| bin.name == BROKER_STEM)
        })
    }

    /// Names of running components whose image lives under a `WinGet`-delegated
    /// root. Their lifecycle is owned by the caller's `winget upgrade` + resume
    /// (in `uffs-cli`), so a non-elevated apply that could not restart them
    /// here has not actually left anything broken — the caller relaunches
    /// them on the new binary. Used to keep these out of the alarming
    /// "failed to restart" warning (they are stopped-on-purpose, not a
    /// fault).
    pub(crate) fn winget_delegated_components(&self) -> Vec<String> {
        let winget_roots: Vec<&Path> = self
            .targets
            .iter()
            .filter(|target| target.channel == "winget")
            .map(|target| target.root.as_path())
            .collect();
        self.running
            .iter()
            .filter(|run| {
                run.image_path
                    .as_deref()
                    .is_some_and(|img| winget_roots.iter().any(|root| img.starts_with(root)))
            })
            .map(|run| run.component.clone())
            .collect()
    }

    /// Roots the **updater** owns: `unmanaged` only. `WinGet` roots are
    /// delegated to `winget upgrade` by `uffs-cli`; dev-build roots are
    /// never auto-updated.
    pub(crate) fn unmanaged_targets(&self) -> impl Iterator<Item = &SnapTarget> {
        self.targets
            .iter()
            .filter(|target| target.channel == "unmanaged")
    }

    /// `WinGet`-managed roots. The updater never swaps these (§19.6): their
    /// update path is `winget upgrade`, which is atomic and not `.bak`-
    /// rollback-able. We surface them so a winget-managed install is never
    /// silently left at the old version.
    pub(crate) fn winget_targets(&self) -> impl Iterator<Item = &SnapTarget> {
        self.targets
            .iter()
            .filter(|target| target.channel == "winget")
    }

    /// The deduplicated set of binary stems installed across every
    /// **unmanaged** root (e.g. `["uffs", "uffsd"]`) — the subset the
    /// updater acquires + applies. Sorted for stable output.
    pub(crate) fn installed_binaries(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .unmanaged_targets()
            .flat_map(|target| target.binaries.iter().map(|binary| binary.name.clone()))
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// The lowest `on_disk_version` across all targets (the "from" version),
    /// or `unknown` if none recorded.
    pub(crate) fn prior_version(&self) -> String {
        self.targets
            .iter()
            .flat_map(|target| target.binaries.iter())
            .filter_map(|binary| binary.on_disk_version.clone())
            .min()
            .unwrap_or_else(|| "unknown".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::Snapshot;

    const SNAP: &str = r#"{
      "schema": 2, "to_version": "0.6.2",
      "targets": [
        { "root": "C:\\uffs", "channel": "unmanaged",
          "binaries": [ { "name": "uffsd", "on_disk_version": "0.6.1" } ] },
        { "root": "C:\\wg", "channel": "winget",
          "binaries": [ { "name": "uffs", "on_disk_version": "0.6.2" } ] }
      ],
      "running": [
        { "component": "daemon", "pid": 42, "image_path": "C:\\uffs\\uffsd.exe",
          "command_line": "uffsd --no-retire" }
      ]
    }"#;

    #[test]
    fn parses_and_filters_unmanaged() {
        let snap: Snapshot = serde_json::from_str(SNAP).expect("parse");
        assert_eq!(snap.to_version(), "0.6.2");
        assert_eq!(snap.prior_version(), "0.6.1");
        let unmanaged: Vec<_> = snap.unmanaged_targets().collect();
        assert_eq!(unmanaged.len(), 1, "winget root excluded");
        let winget: Vec<_> = snap.winget_targets().collect();
        assert_eq!(winget.len(), 1, "winget root surfaced separately");
        assert_eq!(winget.first().expect("one").channel, "winget");
        let binary = unmanaged
            .first()
            .and_then(|target| target.binaries.first())
            .expect("one binary");
        assert_eq!(binary.name, "uffsd");
        let running = snap.running.first().expect("one running");
        assert_eq!(running.component, "daemon");
        assert_eq!(running.command_line.as_deref(), Some("uffsd --no-retire"));
    }

    #[test]
    fn tolerates_missing_optional_fields() {
        let snap: Snapshot = serde_json::from_str(r#"{ "targets": [] }"#).expect("parse");
        assert_eq!(snap.to_version(), "unknown");
        assert_eq!(snap.prior_version(), "unknown");
        assert_eq!(snap.unmanaged_targets().count(), 0);
    }

    #[test]
    fn drop_broker_removes_broker_and_reports_version() {
        const WITH_BROKER: &str = r#"{
          "to_version": "0.6.11",
          "targets": [
            { "root": "C:\\uffs", "channel": "unmanaged", "binaries": [
              { "name": "uffsd", "on_disk_version": "0.6.10" },
              { "name": "uffs-broker", "on_disk_version": "0.6.10" }
            ] }
          ],
          "running": [
            { "component": "daemon", "pid": 42 },
            { "component": "broker", "pid": 7 }
          ]
        }"#;
        let mut snap: Snapshot = serde_json::from_str(WITH_BROKER).expect("parse");
        assert_eq!(
            snap.drop_broker().as_deref(),
            Some("0.6.10"),
            "returns the broker's version for the user hint"
        );
        assert!(
            snap.targets
                .iter()
                .flat_map(|tgt| &tgt.binaries)
                .all(|bin| bin.name != "uffs-broker"),
            "broker binary target removed"
        );
        assert!(
            snap.running.iter().all(|run| run.component != "broker"),
            "broker running entry removed"
        );
        assert!(
            snap.running.iter().any(|run| run.component == "daemon"),
            "non-broker components are untouched"
        );
        assert_eq!(
            snap.drop_broker(),
            None,
            "a second call finds no broker left to drop"
        );
    }

    #[test]
    fn drop_broker_is_none_when_absent() {
        let mut snap: Snapshot = serde_json::from_str(SNAP).expect("parse");
        assert_eq!(snap.drop_broker(), None, "snapshot has no broker");
    }

    #[test]
    fn broker_in_winget_root_detects_delegated_broker() {
        // Broker binary sits in the winget root → delegated `winget upgrade`
        // will refresh it, so the "left NOT updated" note must be suppressed.
        const WINGET_BROKER: &str = r#"{
          "to_version": "0.6.21",
          "targets": [
            { "root": "C:\\bin", "channel": "unmanaged", "binaries": [
              { "name": "uffs", "on_disk_version": "0.6.21" }
            ] },
            { "root": "C:\\wg", "channel": "winget", "binaries": [
              { "name": "uffsd", "on_disk_version": "0.6.18" },
              { "name": "uffs-broker", "on_disk_version": "0.6.18" }
            ] }
          ]
        }"#;
        let snap: Snapshot = serde_json::from_str(WINGET_BROKER).expect("parse");
        assert!(
            snap.broker_in_winget_root(),
            "broker under a winget root is delegated"
        );
    }

    #[test]
    fn broker_is_running_needs_a_running_entry_not_just_a_binary() {
        // A uffs-broker.exe file present, but no running broker service.
        const BINARY_ONLY: &str = r#"{
          "targets": [ { "root": "C:\\bin", "channel": "unmanaged", "binaries": [
            { "name": "uffs-broker", "on_disk_version": "0.6.22" }
          ] } ]
        }"#;
        // A running broker service (a `broker` entry in `running`).
        const RUNNING: &str = r#"{
          "targets": [],
          "running": [ { "component": "broker", "pid": 7 } ]
        }"#;
        let snap: Snapshot = serde_json::from_str(BINARY_ONLY).expect("parse");
        assert!(
            !snap.broker_is_running(),
            "a broker binary with no running service is not running"
        );
        let running: Snapshot = serde_json::from_str(RUNNING).expect("parse");
        assert!(
            running.broker_is_running(),
            "a running broker entry means the service is running"
        );
    }

    #[test]
    fn winget_delegated_components_matches_images_under_winget_root() {
        // Forward slashes so the path component-split works on Unix CI too;
        // on Windows the real backslash paths split the same way.
        const SNAP_RUN: &str = r#"{
          "to_version": "0.6.21",
          "targets": [
            { "root": "/bin", "channel": "unmanaged", "binaries": [] },
            { "root": "/wg",  "channel": "winget",    "binaries": [] }
          ],
          "running": [
            { "component": "daemon", "pid": 1, "image_path": "/wg/uffsd.exe" },
            { "component": "mcp",    "pid": 2, "image_path": "/bin/uffsmcp.exe" }
          ]
        }"#;
        let snap: Snapshot = serde_json::from_str(SNAP_RUN).expect("parse");
        assert_eq!(
            snap.winget_delegated_components(),
            vec!["daemon".to_owned()],
            "only the component whose image is under the winget root is delegated"
        );
    }

    #[test]
    fn broker_in_winget_root_false_for_unmanaged_broker() {
        // Broker in an unmanaged root: nothing else refreshes it, so the
        // note stays. (Also false when there is no broker at all.)
        const UNMANAGED_BROKER: &str = r#"{
          "to_version": "0.6.21",
          "targets": [
            { "root": "C:\\bin", "channel": "unmanaged", "binaries": [
              { "name": "uffs-broker", "on_disk_version": "0.6.20" }
            ] }
          ]
        }"#;
        let snap: Snapshot = serde_json::from_str(UNMANAGED_BROKER).expect("parse");
        assert!(
            !snap.broker_in_winget_root(),
            "broker in an unmanaged root is not delegated"
        );
        let no_broker: Snapshot = serde_json::from_str(SNAP).expect("parse");
        assert!(
            !no_broker.broker_in_winget_root(),
            "no broker at all is not delegated"
        );
    }
}
