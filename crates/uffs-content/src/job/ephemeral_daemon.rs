// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Spawns a single ephemeral `uffsd` instance covering every VSS
//! snapshot device this job's drives were leased for, connects to it
//! over the standard daemon RPC protocol, and tears it down when done.
//!
//! This is the revised design behind
//! `docs/dev/architecture/uffs-ingest-implementation-plan.md` §6.2
//! (supersedes a literal reading of that section, per direct user
//! clarification): target selection is answered by an ephemeral daemon
//! instance loaded from the leased snapshot device(s) via `uffsd
//! --device <path>=<letter>`, not by this crate reading or querying the
//! MFT directly — the daemon already owns all `uffs-mft`/`uffs-core`
//! usage (see [`super::snapshot_client`]'s doc comment for the parallel
//! rationale on the lease side).

use core::time::Duration;
use std::process::{Child, Command, Stdio};
use std::time::Instant;

use anyhow::{Context as _, Result};
use uffs_client::connect_sync::UffsClientSync;
use uffs_client::daemon_ctl::{ephemeral_endpoint, find_daemon_exe};

/// How long [`EphemeralDaemon::spawn`] waits for the daemon to finish
/// loading every device source before giving up.
const READY_TIMEOUT: Duration = Duration::from_secs(120);

/// How long [`EphemeralDaemon::spawn`] retries connecting to the
/// freshly spawned daemon's pipe/socket before treating it as dead on
/// arrival.
const CONNECT_RETRY_BUDGET: Duration = Duration::from_secs(10);

/// Delay between connect retries while the daemon finishes binding its
/// endpoint.
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// A running ephemeral `uffsd` instance covering one or more VSS
/// snapshot devices.
pub(crate) struct EphemeralDaemon {
    /// The spawned `uffsd` child process. Killed directly on
    /// [`Self::shutdown`]/[`Drop`] rather than via the RPC `shutdown`
    /// method — see [`Self::shutdown`]'s doc comment for why.
    child: Child,
    /// This instance's IPC endpoint (Unix socket path, or Windows named
    /// pipe path), from [`uffs_client::daemon_ctl::ephemeral_endpoint`].
    endpoint: String,
}

impl EphemeralDaemon {
    /// Spawn `uffsd --ephemeral-id <ephemeral_id> --device
    /// <device_path>=<drive_letter> ...` for every `(device_path,
    /// drive_letter)` pair in `devices`, and wait until it reports
    /// every device loaded.
    ///
    /// # Errors
    /// Returns an error if `devices` is empty, the `uffsd` binary can't
    /// be spawned, the pipe/socket never comes up, or the daemon
    /// doesn't reach `Ready` within [`READY_TIMEOUT`].
    pub(crate) fn spawn(ephemeral_id: &str, devices: &[(String, char)]) -> Result<Self> {
        anyhow::ensure!(
            !devices.is_empty(),
            "at least one device source is required to spawn an ephemeral daemon"
        );

        let exe = find_daemon_exe();
        // `--stdout/--stderr(Stdio::null())` used to discard every one of
        // uffsd's own `tracing::info!` events (it defaults to logging to
        // stdout at `info` level — see `uffs-daemon::log_init`) — meaning
        // none of its internal timing (e.g. a slow `search` against a
        // freshly-loaded, uncached device source) was ever visible,
        // however much this crate's own logging improved. `--log-file`
        // routes it to a discoverable file instead, and `--log-level`
        // pins the level explicitly rather than relying on uffsd's own
        // default matching ours.
        let log_file = std::env::temp_dir().join(format!("uffsd-ephemeral-{ephemeral_id}.log"));
        let mut command = Command::new(&exe);
        command
            .arg("--ephemeral-id")
            .arg(ephemeral_id)
            .arg("--log-level")
            .arg("info")
            .arg("--log-file")
            .arg(&log_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (device_path, letter) in devices {
            command
                .arg("--device")
                .arg(format!("{device_path}={letter}"));
        }

        tracing::info!(
            exe = %exe.display(),
            device_count = devices.len(),
            log_file = %log_file.display(),
            "ephemeral daemon: spawning uffsd"
        );
        let child = command
            .spawn()
            .with_context(|| format!("failed to spawn {}", exe.display()))?;
        let pid = child.id();

        let instance = Self {
            child,
            endpoint: ephemeral_endpoint(ephemeral_id),
        };
        tracing::info!(pid, endpoint = %instance.endpoint, "ephemeral daemon: waiting for Ready");
        instance.await_ready()?;
        tracing::info!(pid, "ephemeral daemon: Ready");
        Ok(instance)
    }

    /// Connect to this instance's pipe/socket, retrying briefly while
    /// the daemon finishes binding it, then block until it reports
    /// `Ready` (every device source loaded).
    fn await_ready(&self) -> Result<()> {
        let connect_deadline = Instant::now() + CONNECT_RETRY_BUDGET;
        let last_err = loop {
            match UffsClientSync::connect_at(&self.endpoint) {
                Ok(mut client) => {
                    return client
                        .await_ready(READY_TIMEOUT)
                        .context("ephemeral daemon did not become ready");
                }
                Err(err) => {
                    if Instant::now() >= connect_deadline {
                        break err;
                    }
                    std::thread::sleep(CONNECT_RETRY_INTERVAL);
                }
            }
        };
        Err(anyhow::anyhow!(
            "could not connect to ephemeral daemon at {}: {last_err}",
            self.endpoint
        ))
    }

    /// Open a fresh RPC connection to this running instance.
    ///
    /// # Errors
    /// Returns an error if the connection can't be established.
    pub(crate) fn connect(&self) -> Result<UffsClientSync> {
        UffsClientSync::connect_at(&self.endpoint)
            .with_context(|| format!("failed to connect to ephemeral daemon at {}", self.endpoint))
    }

    /// Tear down this instance.
    ///
    /// Kills the process directly rather than using the RPC `shutdown`
    /// method: that method reads the *resident* daemon's well-known PID
    /// file for its shutdown nonce, which is meaningless (and unsafe to
    /// reuse) for an ephemeral instance's own, differently located PID
    /// file. Since this process spawned the child itself, a direct kill
    /// is simpler and correct.
    ///
    /// # Errors
    /// Returns an error if the process couldn't be killed. The process
    /// is still waited on best-effort even on error.
    pub(crate) fn shutdown(mut self) -> Result<()> {
        self.child
            .kill()
            .context("failed to kill ephemeral daemon process")?;
        drop(self.child.wait());
        Ok(())
    }
}

impl Drop for EphemeralDaemon {
    /// Best-effort safety net: if [`Self::shutdown`] was never called
    /// explicitly (e.g. an earlier step returned an error), don't leak
    /// the child process. A no-op if it was already reaped.
    fn drop(&mut self) {
        drop(self.child.kill());
    }
}
