// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! [`crate::snapshot_lease::VssProvider`] implementation backed by
//! `uffs-vss-requestor`: spawns one helper process per snapshot, keeps
//! it alive (assigned to a `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` Job
//! Object) for the lease's entire lifetime, and drives it over a private
//! JSON-lines control pipe. See
//! `docs/dev/architecture/uffs-vss-rust-cpp-shim-implementation-guide.md`
//! for the full design.
//!
//! The wire shape here (`HelperEvent`/`BrokerCommand`) is a deliberate,
//! documented duplicate of `uffs-vss-requestor::protocol` — that crate
//! is bin-only (no library target) and this protocol is tiny, private,
//! and owned end-to-end by this same Broker↔helper pairing, so a
//! dedicated shared protocol crate (the pattern this workspace otherwise
//! uses for every cross-process wire boundary) would be overhead without
//! benefit here. Keep the two definitions in sync by hand if either side
//! changes.

use core::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::FromRawHandle as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use uffs_broker_protocol::snapshot_manager::VolumeIdentity;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW,
};
use windows::core::PCWSTR;

use crate::snapshot_lease::{SnapshotHandle, VssError, VssProvider};

/// Mirrors `uffs_vss_requestor::protocol::HelperEvent` — see this
/// module's doc comment.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
enum HelperEvent {
    /// The snapshot was created.
    Ready {
        /// This specific snapshot's GUID, canonical `{...}` string form.
        snapshot_id: String,
        /// The snapshot's device path, if the helper reported one.
        snapshot_device_object: Option<String>,
    },
    /// The snapshot set was explicitly deleted.
    Released,
    /// A VSS requestor operation failed.
    Failed {
        /// Which step of the requestor sequence failed.
        stage: i32,
        /// The failing `HRESULT`.
        hresult: i32,
        /// Human-readable diagnostic message.
        message: String,
    },
    /// Reply to [`BrokerCommand::Ping`].
    Pong,
}

/// Mirrors `uffs_vss_requestor::protocol::BrokerCommand` — see this
/// module's doc comment.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
enum BrokerCommand {
    /// Delete the snapshot set and exit.
    Release,
}

/// One live helper-process session.
struct HelperSession {
    /// Reader half of the control pipe (a clone of `writer`'s handle).
    reader: BufReader<File>,
    /// Writer half of the control pipe.
    writer: File,
    /// The helper process, kept open so the Job Object's kill-on-close
    /// net stays armed until this session is dropped.
    process_handle: HANDLE,
    /// The Job Object the helper was assigned to.
    job_handle: HANDLE,
}

#[expect(
    unsafe_code,
    reason = "kernel HANDLEs have no thread affinity, so moving them between \
              threads is sound; `File`/`BufReader<File>` are themselves already \
              Send, so this only concerns the two raw HANDLEs"
)]
// SAFETY: `process_handle` and `job_handle` are process-wide kernel object
// handles with no thread affinity — moving a `HelperSession` between threads
// (e.g. into the `SnapshotLeaseManager`'s session map, itself behind a
// `Mutex`) is sound. Concurrent *use* of the same handle would still need
// external synchronization, exactly as with the raw Win32 API; `Send` only
// makes the *move* type-safe.
unsafe impl Send for HelperSession {}

impl Drop for HelperSession {
    #[expect(
        unsafe_code,
        reason = "CloseHandle is an FFI call; see the inline SAFETY comment"
    )]
    fn drop(&mut self) {
        // SAFETY: both handles were opened by `spawn_helper` and are
        // closed exactly once here. If the helper already exited
        // gracefully (the normal `Release` path), this is inert; if it
        // is still alive for any other reason, closing the job's last
        // handle triggers `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
        let _job_close_result = unsafe { CloseHandle(self.job_handle) };
        // SAFETY: see above.
        let _process_close_result = unsafe { CloseHandle(self.process_handle) };
    }
}

/// Cleanup guard for a spawned-but-not-yet-adopted helper: closes the
/// process and Job Object handles (killing the helper via
/// kill-on-close) unless [`PendingSpawn::into_handles`] transfers
/// ownership to a [`HelperSession`] first.
struct PendingSpawn {
    /// The helper process, not yet confirmed ready.
    process_handle: HANDLE,
    /// The Job Object the helper was assigned to.
    job_handle: HANDLE,
}

impl PendingSpawn {
    /// Disarm cleanup and take ownership of the raw handles.
    fn into_handles(self) -> (HANDLE, HANDLE) {
        let this = core::mem::ManuallyDrop::new(self);
        (this.process_handle, this.job_handle)
    }
}

impl Drop for PendingSpawn {
    #[expect(
        unsafe_code,
        reason = "CloseHandle is an FFI call; see the inline SAFETY comment"
    )]
    fn drop(&mut self) {
        // SAFETY: both handles were opened by `spawn_helper`; closing
        // the job's last handle here (before the helper ever confirmed
        // readiness) kills the abandoned helper process.
        let _job_close_result = unsafe { CloseHandle(self.job_handle) };
        // SAFETY: see above.
        let _process_close_result = unsafe { CloseHandle(self.process_handle) };
    }
}

/// [`VssProvider`] backed by per-lease `uffs-vss-requestor` helper
/// processes.
pub(crate) struct WindowsVssProvider {
    /// Live sessions, keyed by snapshot ID bytes.
    sessions: Mutex<HashMap<Vec<u8>, HelperSession>>,
    /// Monotonic counter for unique per-lease pipe names.
    next_pipe_id: AtomicU64,
}

impl WindowsVssProvider {
    /// Construct an empty provider.
    pub(crate) fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            next_pipe_id: AtomicU64::new(1),
        }
    }

    /// Lock the session map, recovering from a poisoned mutex.
    fn lock_sessions(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<u8>, HelperSession>> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl VssProvider for WindowsVssProvider {
    #[expect(
        unsafe_code,
        reason = "wraps a freshly connected pipe HANDLE in a File; see the inline SAFETY comment"
    )]
    fn create_snapshot(
        &self,
        _volume: &VolumeIdentity,
        requested_root: &[u8],
    ) -> Result<SnapshotHandle, VssError> {
        let volume_path = decode_utf16le(requested_root).ok_or_else(|| {
            VssError::InvalidVolume("requested_root is not valid UTF-16LE".to_owned())
        })?;

        let pipe_id = self.next_pipe_id.fetch_add(1, Ordering::Relaxed);
        let pipe_name = format!(r"\\.\pipe\uffs-vss-requestor-{pipe_id:016x}");

        let pipe_handle = create_control_pipe(&pipe_name).map_err(|err| {
            VssError::CreateFailed(format!("failed to create control pipe: {err}"))
        })?;

        let pending = spawn_helper(&pipe_name, &volume_path).map_err(|err| {
            VssError::CreateFailed(format!("failed to spawn uffs-vss-requestor: {err}"))
        })?;

        if let Err(err) = connect_pipe(pipe_handle) {
            close_pipe_handle(pipe_handle);
            return Err(VssError::CreateFailed(format!(
                "helper did not connect to control pipe: {err}"
            )));
        }

        // SAFETY: `pipe_handle` is a valid, connected, exclusively owned
        // duplex pipe HANDLE; `File` takes ownership and closes it on drop.
        let pipe_file = unsafe { File::from_raw_handle(pipe_handle.0.cast::<core::ffi::c_void>()) };
        let writer = pipe_file
            .try_clone()
            .map_err(|err| VssError::CreateFailed(format!("failed to clone pipe handle: {err}")))?;
        let mut reader = BufReader::new(pipe_file);

        let event = read_helper_event(&mut reader)
            .map_err(|err| VssError::CreateFailed(format!("failed to read helper event: {err}")))?
            .ok_or_else(|| {
                VssError::CreateFailed(
                    "helper closed the control pipe before reporting readiness".to_owned(),
                )
            })?;

        match event {
            HelperEvent::Ready {
                snapshot_id,
                snapshot_device_object,
            } => {
                let (process_handle, job_handle) = pending.into_handles();
                let snapshot_id_bytes = snapshot_id.into_bytes();
                let session = HelperSession {
                    reader,
                    writer,
                    process_handle,
                    job_handle,
                };
                self.lock_sessions()
                    .insert(snapshot_id_bytes.clone(), session);
                Ok(SnapshotHandle {
                    snapshot_id: snapshot_id_bytes,
                    device_identity: snapshot_device_object.unwrap_or_default(),
                })
            }
            HelperEvent::Failed {
                stage,
                hresult,
                message,
            } => Err(VssError::CreateFailed(format!(
                "stage={stage} hresult={hresult:#x}: {message}"
            ))),
            HelperEvent::Released | HelperEvent::Pong => Err(VssError::CreateFailed(
                "unexpected event from helper before Ready".to_owned(),
            )),
        }
    }

    fn delete_snapshot(&self, snapshot_id: &[u8]) -> Result<(), VssError> {
        let mut session = self.lock_sessions().remove(snapshot_id).ok_or_else(|| {
            VssError::DeleteFailed("no live session for this snapshot".to_owned())
        })?;

        let command = BrokerCommand::Release;
        let write_result = serde_json::to_string(&command)
            .map_err(|err| VssError::DeleteFailed(format!("failed to encode Release: {err}")))
            .and_then(|line| {
                writeln!(session.writer, "{line}")
                    .and_then(|()| session.writer.flush())
                    .map_err(|err| VssError::DeleteFailed(format!("failed to send Release: {err}")))
            });
        write_result?;

        let event = read_helper_event(&mut session.reader).map_err(|err| {
            VssError::DeleteFailed(format!("failed to read helper response: {err}"))
        })?;
        match event {
            Some(HelperEvent::Released) | None => Ok(()),
            Some(HelperEvent::Failed {
                stage,
                hresult,
                message,
            }) => Err(VssError::DeleteFailed(format!(
                "stage={stage} hresult={hresult:#x}: {message}"
            ))),
            Some(HelperEvent::Ready { .. } | HelperEvent::Pong) => Err(VssError::DeleteFailed(
                "unexpected event from helper after Release".to_owned(),
            )),
        }
        // `session` drops here regardless of outcome, closing the
        // process/job handles.
    }

    fn list_existing_snapshots(&self) -> Result<Vec<Vec<u8>>, VssError> {
        // `VSS_CTX_FILE_SHARE_BACKUP` is ephemeral and auto-release: a
        // snapshot's lifetime is tied to its helper process/Job Object,
        // which the OS itself tears down if the Broker dies (closing
        // every handle it held, including each Job Object — see
        // `docs/dev/architecture/uffs-vss-rust-cpp-shim-implementation-guide.md`
        // §6/§7). There is nothing left to reconcile at startup.
        Ok(Vec::new())
    }
}

/// Decode `bytes` as UTF-16LE, or `None` if the length is odd or the
/// units don't form valid UTF-16.
fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let (chunks, _remainder) = bytes.as_chunks::<2>();
    let units: Vec<u16> = chunks.iter().copied().map(u16::from_le_bytes).collect();
    String::from_utf16(&units).ok()
}

/// Read one [`HelperEvent`] line, or `Ok(None)` at EOF.
fn read_helper_event(reader: &mut BufReader<File>) -> std::io::Result<Option<HelperEvent>> {
    let mut line = String::new();
    let bytes_read = reader.read_line(&mut line)?;
    if bytes_read == 0 {
        return Ok(None);
    }
    let event = serde_json::from_str(line.trim_end())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    Ok(Some(event))
}

/// Close a raw pipe `HANDLE` that was never adopted into a [`File`].
#[expect(unsafe_code, reason = "CloseHandle is an FFI call")]
fn close_pipe_handle(handle: HANDLE) {
    // SAFETY: `handle` was opened by `create_control_pipe` and has not
    // been wrapped in a `File` (which would otherwise double-close it).
    let _close_result = unsafe { CloseHandle(handle) };
}

/// Create the Broker-side control pipe instance for one snapshot lease.
///
/// Uses default security: the helper runs under the same identity as
/// the Broker (`CreateProcessW` inherits the parent's token unless told
/// otherwise), so no custom SDDL is needed the way the Coordinator- and
/// daemon-facing pipes require.
#[expect(unsafe_code, reason = "CreateNamedPipeW is an FFI call")]
fn create_control_pipe(pipe_name: &str) -> anyhow::Result<HANDLE> {
    let wide_name: Vec<u16> = std::ffi::OsStr::new(pipe_name)
        .encode_wide()
        .chain(Some(0))
        .collect();

    // SAFETY: `wide_name` is a NUL-terminated UTF-16 buffer valid for the
    // duration of this call; `None` security attributes fall back to the
    // creating thread's default DACL, which already permits the
    // same-identity helper process to connect.
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(wide_name.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            8192,
            8192,
            0,
            None,
        )
    };
    if handle.is_invalid() {
        anyhow::bail!(
            "CreateNamedPipeW failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(handle)
}

/// Block until the helper connects to `pipe_handle`.
#[expect(unsafe_code, reason = "ConnectNamedPipe is an FFI call")]
fn connect_pipe(pipe_handle: HANDLE) -> anyhow::Result<()> {
    // SAFETY: `pipe_handle` is a valid, freshly created pipe instance
    // HANDLE; `None` requests a synchronous (blocking) connect wait.
    let result = unsafe { ConnectNamedPipe(pipe_handle, None) };
    if let Err(win_err) = result {
        // ERROR_PIPE_CONNECTED means the client connected before this
        // call ran — not an error.
        if win_err.code().0 != 535_i32 {
            anyhow::bail!("ConnectNamedPipe failed: {win_err}");
        }
    }
    Ok(())
}

/// Locate `uffs-vss-requestor.exe`, assumed to live alongside this
/// Broker binary (the same install directory).
fn helper_exe_path() -> anyhow::Result<PathBuf> {
    let current_exe = std::env::current_exe()
        .map_err(|err| anyhow::anyhow!("failed to resolve current_exe: {err}"))?;
    let parent = current_exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("current_exe has no parent directory"))?;
    Ok(parent.join("uffs-vss-requestor.exe"))
}

/// Spawn `uffs-vss-requestor.exe`, suspended, assign it to a fresh
/// kill-on-close Job Object, then resume it.
#[expect(
    unsafe_code,
    reason = "CreateProcessW, CreateJobObjectW, SetInformationJobObject, \
              AssignProcessToJobObject, and ResumeThread are FFI calls"
)]
fn spawn_helper(pipe_name: &str, volume_path: &str) -> anyhow::Result<PendingSpawn> {
    let exe_path = helper_exe_path()?;
    let parent_pid = std::process::id();
    let mut command_line = build_command_line(&exe_path, pipe_name, volume_path, parent_pid);

    let startup_info = STARTUPINFOW {
        cb: u32::try_from(size_of::<STARTUPINFOW>()).unwrap_or(0),
        ..Default::default()
    };
    let mut process_information = PROCESS_INFORMATION::default();

    // SAFETY: `command_line` is a mutable, NUL-terminated UTF-16 buffer
    // (required: `CreateProcessW` may write into it); `startup_info` and
    // `process_information` are stack-owned and exclusively borrowed for
    // the call.
    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(windows::core::PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            PCWSTR::null(),
            &raw const startup_info,
            &raw mut process_information,
        )
    }
    .map_err(|err| anyhow::anyhow!("CreateProcessW failed: {err}"))?;

    let process_handle = process_information.hProcess;
    let thread_handle = process_information.hThread;

    // SAFETY: `None` name creates an anonymous Job Object; the returned
    // handle is owned by this function until transferred via
    // `PendingSpawn`.
    let job_handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
        .map_err(|err| anyhow::anyhow!("CreateJobObjectW failed: {err}"))?;

    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: `job_handle` is a valid, freshly created Job Object handle;
    // `limits` is a stack-owned, correctly sized structure for
    // `JobObjectExtendedLimitInformation`.
    let set_info_result = unsafe {
        SetInformationJobObject(
            job_handle,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast::<core::ffi::c_void>(),
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(0),
        )
    };
    if let Err(err) = set_info_result {
        close_pipe_handle(job_handle);
        close_pipe_handle(process_handle);
        close_pipe_handle(thread_handle);
        anyhow::bail!("SetInformationJobObject failed: {err}");
    }

    // SAFETY: `job_handle` and `process_handle` are both valid; assigning
    // a suspended process to the job before it ever runs means it can
    // never escape the job's kill-on-close net.
    let assign_result = unsafe { AssignProcessToJobObject(job_handle, process_handle) };
    if let Err(err) = assign_result {
        close_pipe_handle(job_handle);
        close_pipe_handle(process_handle);
        close_pipe_handle(thread_handle);
        anyhow::bail!("AssignProcessToJobObject failed: {err}");
    }

    // SAFETY: `thread_handle` is the valid main-thread handle from
    // `CreateProcessW`, still suspended.
    let resume_result = unsafe { ResumeThread(thread_handle) };
    close_pipe_handle(thread_handle);
    if resume_result == u32::MAX {
        close_pipe_handle(job_handle);
        close_pipe_handle(process_handle);
        anyhow::bail!("ResumeThread failed: {}", std::io::Error::last_os_error());
    }

    Ok(PendingSpawn {
        process_handle,
        job_handle,
    })
}

/// Build the helper's command line: `"<exe>" --pipe-name <name>
/// --volume-path "<path>" --parent-pid <pid>`, NUL-terminated UTF-16.
fn build_command_line(
    exe_path: &Path,
    pipe_name: &str,
    volume_path: &str,
    parent_pid: u32,
) -> Vec<u16> {
    let command = format!(
        "\"{}\" --pipe-name {pipe_name} --volume-path \"{volume_path}\" --parent-pid {parent_pid}",
        exe_path.display(),
    );
    command.encode_utf16().chain(Some(0)).collect()
}
