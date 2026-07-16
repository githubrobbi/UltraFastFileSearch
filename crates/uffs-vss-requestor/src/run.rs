// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Top-level orchestration: parse arguments, create the snapshot,
//! report readiness, then wait for `Release`/`Cancel`/pipe-closed/
//! parent-death and tear down accordingly.

use std::io::BufReader;
use std::sync::mpsc;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

use crate::pipe;
use crate::protocol::{self, BrokerCommand, HelperEvent};
use crate::snapshot::VssSnapshotSession;

/// Parsed command-line arguments.
struct Args {
    /// Name of the private control pipe to connect to.
    pipe_name: String,
    /// Canonical volume path to snapshot.
    volume_path: String,
    /// PID of the spawning Broker, watched for early exit.
    parent_pid: u32,
}

impl Args {
    /// Parse `std::env::args()`, skipping argv\[0\].
    ///
    /// # Errors
    /// Returns an error if a required flag is missing or a value fails
    /// to parse.
    fn parse() -> anyhow::Result<Self> {
        let mut pipe_name = None;
        let mut volume_path = None;
        let mut parent_pid = None;

        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--pipe-name" => pipe_name = Some(next_value(&mut args, "--pipe-name")?),
                "--volume-path" => volume_path = Some(next_value(&mut args, "--volume-path")?),
                "--parent-pid" => {
                    let value = next_value(&mut args, "--parent-pid")?;
                    parent_pid = Some(
                        value
                            .parse::<u32>()
                            .map_err(|err| anyhow::anyhow!("invalid --parent-pid: {err}"))?,
                    );
                }
                other => anyhow::bail!("unrecognized argument: {other}"),
            }
        }

        Ok(Self {
            pipe_name: pipe_name.ok_or_else(|| anyhow::anyhow!("--pipe-name is required"))?,
            volume_path: volume_path.ok_or_else(|| anyhow::anyhow!("--volume-path is required"))?,
            parent_pid: parent_pid.ok_or_else(|| anyhow::anyhow!("--parent-pid is required"))?,
        })
    }
}

/// Take the next positional value for `flag`, or an error if argv ran
/// out.
fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> anyhow::Result<String> {
    args.next()
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}

/// An event the main loop reacts to — a decoded command from the
/// Broker, the pipe closing, or the parent process dying (a second,
/// independent safety net alongside the Job Object the Broker assigns
/// this process to).
enum MainEvent {
    /// A decoded command arrived from the Broker.
    Command(BrokerCommand),
    /// The control pipe closed (EOF) or a read failed.
    PipeClosed,
    /// The watched parent process exited.
    ParentDied,
}

/// Run the helper end to end.
///
/// # Errors
/// Returns an error if arguments are invalid, the pipe can't be
/// connected, or the initial snapshot creation fails (after reporting
/// [`HelperEvent::Failed`] to the Broker).
pub(crate) fn run() -> anyhow::Result<()> {
    let args = Args::parse()?;
    let mut writer = pipe::connect(&args.pipe_name)?;
    let reader_file = writer
        .try_clone()
        .map_err(|err| anyhow::anyhow!("failed to clone pipe handle for reading: {err}"))?;

    let mut session = match VssSnapshotSession::create(&args.volume_path) {
        Ok((session, descriptor)) => {
            protocol::write_event(&mut writer, &HelperEvent::Ready {
                snapshot_set_id: descriptor.snapshot_set_id,
                snapshot_id: descriptor.snapshot_id,
                provider_id: descriptor.provider_id,
                original_volume_name: descriptor.original_volume_name,
                snapshot_device_object: descriptor.snapshot_device_object,
                created_at_unix_ms: descriptor.created_at_unix_ms,
            })?;
            session
        }
        Err(err) => {
            let stage = err.stage;
            let hresult = err.hresult;
            protocol::write_event(&mut writer, &HelperEvent::Failed {
                stage: err.stage,
                hresult: err.hresult,
                message: err.message,
            })?;
            anyhow::bail!("snapshot creation failed: stage={stage} hresult={hresult:#x}");
        }
    };

    let (event_tx, event_rx) = mpsc::channel::<MainEvent>();

    let reader_tx = event_tx.clone();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(reader_file);
        loop {
            if let Ok(Some(command)) = protocol::read_command(&mut reader) {
                if reader_tx.send(MainEvent::Command(command)).is_err() {
                    return;
                }
            } else {
                drop(reader_tx.send(MainEvent::PipeClosed));
                return;
            }
        }
    });

    let watchdog_tx = event_tx.clone();
    let parent_pid = args.parent_pid;
    std::thread::spawn(move || {
        wait_for_process_exit(parent_pid);
        drop(watchdog_tx.send(MainEvent::ParentDied));
    });
    drop(event_tx);

    for event in event_rx {
        match event {
            MainEvent::Command(BrokerCommand::Ping) => {
                drop(protocol::write_event(&mut writer, &HelperEvent::Pong));
            }
            MainEvent::Command(BrokerCommand::Release) => {
                match session.delete_snapshot_set() {
                    Ok(()) => {
                        drop(protocol::write_event(&mut writer, &HelperEvent::Released));
                    }
                    Err(err) => {
                        drop(protocol::write_event(&mut writer, &HelperEvent::Failed {
                            stage: err.stage,
                            hresult: err.hresult,
                            message: err.message,
                        }));
                    }
                }
                drop(session);
                return Ok(());
            }
            MainEvent::Command(BrokerCommand::Cancel)
            | MainEvent::PipeClosed
            | MainEvent::ParentDied => {
                // Auto-release path: dropping `session` releases the
                // last `IVssBackupComponents` reference, which is where
                // `VSS_CTX_FILE_SHARE_BACKUP`'s auto-delete happens if
                // the snapshot set was never explicitly deleted.
                drop(session);
                return Ok(());
            }
        }
    }

    drop(session);
    Ok(())
}

/// Block until the process identified by `pid` exits, or return
/// immediately if it can't be opened (already gone, or never existed —
/// either way, "wait for it to die" is trivially satisfied).
#[expect(
    unsafe_code,
    reason = "OpenProcess, WaitForSingleObject, and CloseHandle are FFI calls"
)]
fn wait_for_process_exit(pid: u32) {
    // SAFETY: `pid` is a plain integer; a failed open (process already
    // gone) is handled by returning immediately, never dereferenced.
    let handle_result = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    };
    let Ok(handle) = handle_result else {
        return;
    };
    // SAFETY: `handle` is the valid handle just opened above; waiting
    // indefinitely is intentional — this whole thread's job is to block
    // until the parent exits.
    let _wait_result = unsafe { WaitForSingleObject(handle, u32::MAX) };
    close_handle(handle);
}

/// Close `handle`, logging nothing on failure (this is best-effort
/// cleanup in a thread that's about to signal process exit anyway).
#[expect(unsafe_code, reason = "CloseHandle is an FFI call")]
fn close_handle(handle: HANDLE) {
    // SAFETY: `handle` was opened by this module and is not used again
    // after this call.
    drop(unsafe { CloseHandle(handle) });
}
