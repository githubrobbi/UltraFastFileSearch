// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! The dependency-injection seam: every side effect goes through [`Host`].
//!
//! The trait is deliberately small and synchronous — it models exactly the host
//! interactions the orchestrator needs (filesystem, process spawning, clock,
//! TTY detection, single-key input, console output). Keeping it minimal means
//! the [`MockHost`] is cheap to maintain and the transparency guarantee
//! (the command *shown* equals the command *run*) is trivially assertable.

mod mock;
mod system;

use std::io;
use std::path::Path;

use chrono::{DateTime, Utc};
pub use mock::{Call, MockHost};
pub use system::SystemHost;

/// Captured result of a spawned child process.
#[derive(Debug, Clone)]
pub struct ProcOutput {
    /// Process exit code (`None` if terminated by a signal).
    pub code: Option<i32>,
    /// Captured standard output, decoded lossily as UTF-8.
    pub stdout: String,
    /// Captured standard error, decoded lossily as UTF-8.
    pub stderr: String,
}

impl ProcOutput {
    /// Whether the process exited successfully (exit code `0`).
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// Abstraction over all host interactions performed by the orchestrator.
///
/// Implemented by [`SystemHost`] (real OS) and [`MockHost`] (in-memory, for
/// tests). Methods are intentionally low-level wrappers; higher-level logic in
/// `state`, `restore`, and `fingerprint` composes them and maps their
/// [`std::io::Error`]s into [`crate::error::BenchError`] with path context.
pub trait Host {
    /// Read the entire contents of a file.
    ///
    /// # Errors
    /// Returns an error if the path does not exist or cannot be read.
    fn read_file(&self, path: &Path) -> io::Result<Vec<u8>>;

    /// Write `bytes` to `path`, truncating any existing file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be created or written.
    fn write_file(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;

    /// Remove a file.
    ///
    /// # Errors
    /// Returns an error if the file does not exist or cannot be removed.
    fn remove_file(&self, path: &Path) -> io::Result<()>;

    /// Atomically replace `to` with `from` (used for crash-safe state saves).
    ///
    /// # Errors
    /// Returns an error if the rename fails.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;

    /// Copy `from` to `to`, overwriting any existing destination.
    ///
    /// Distinct from [`read_file`](Host::read_file) +
    /// [`write_file`](Host::write_file) so a multi-GB resource (a UFFS
    /// cache snapshot for R2) is streamed by the OS rather than buffered
    /// through the orchestrator's heap.
    ///
    /// # Errors
    /// Returns an error if the source cannot be read or the destination
    /// written.
    fn copy_file(&self, from: &Path, to: &Path) -> io::Result<()>;

    /// Recursively create a directory and all missing parents.
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created.
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;

    /// Whether a path exists on the host.
    fn path_exists(&self, path: &Path) -> bool;

    /// Spawn `exe` with `args`, capturing status, stdout, and stderr.
    ///
    /// # Errors
    /// Returns an error if the process cannot be spawned.
    fn run(&self, exe: &str, args: &[&str]) -> io::Result<ProcOutput>;

    /// Spawn `exe` with `args`, inheriting the parent's stdout and stderr so
    /// the child's output streams live to the operator's terminal.
    ///
    /// Returns the process exit code (`None` if the OS did not provide one).
    /// Use this for long-running harness scripts (Stage 1, Stage 2) where
    /// buffering all output and returning it at the end would leave the
    /// operator watching a blank screen for several minutes.
    ///
    /// # Errors
    /// Returns an error if the process cannot be spawned.
    fn run_streaming(&self, exe: &str, args: &[&str]) -> io::Result<Option<i32>>;

    /// Spawn `exe` with `args` as a detached background process.
    ///
    /// The child's stdout and stderr are discarded and the bench tool does not
    /// wait for it to exit.  Used for long-running GUI processes (e.g.
    /// `Everything.exe`) that must run concurrently while the bench polls them
    /// via the CLI.
    ///
    /// # Errors
    /// Returns an error if the process cannot be spawned.
    fn spawn(&self, exe: &str, args: &[&str]) -> io::Result<()>;

    /// Read an environment variable, if present and valid UTF-8.
    fn env(&self, key: &str) -> Option<String>;

    /// The current wall-clock time, in UTC.
    fn now(&self) -> DateTime<Utc>;

    /// Pause execution for `millis` milliseconds.
    ///
    /// Used by readiness polls (for example waiting for a competitor index to
    /// finish loading) so the cadence is injectable: the [`MockHost`] records
    /// the request and returns immediately, keeping tests instant.
    fn sleep_ms(&self, millis: u64);

    /// Whether the standard input/output is an interactive terminal.
    fn is_tty(&self) -> bool;

    /// Whether the current process has administrator/root privileges.
    ///
    /// Captured for the Stage 0a environment fingerprint (a benchmark run on an
    /// unelevated host cannot read the MFT, so the report must record this).
    /// Implementations make a best-effort, non-failing determination; the value
    /// is informational and never gates control flow or a security decision.
    fn is_elevated(&self) -> bool;

    /// Read a single keypress for an interactive gate.
    ///
    /// # Errors
    /// Returns an error if input cannot be read (for example, EOF).
    fn read_key(&self) -> io::Result<char>;

    /// Emit one line of user-facing console output (best-effort).
    ///
    /// UI rendering is non-critical, so implementations swallow write errors
    /// rather than surfacing them; this keeps gate code free of `Result`
    /// plumbing for purely cosmetic output.
    fn out(&self, line: &str);
}
