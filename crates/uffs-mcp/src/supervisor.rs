// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! The self-upgrading MCP supervisor: zero-downtime binary switches
//! for `uffsmcp` stdio sessions.
//!
//! The problem: `just use-local` (and any installer) atomically
//! replaces `uffsmcp` on disk, but every RUNNING stdio server keeps
//! executing its old image until someone kills it — and killing it
//! breaks the AI-host session that spawned it. The fix is a tiny
//! supervisor that OWNS the client's stdio pipes for the whole
//! session and serves through a worker child it can replace:
//!
//! - `uffsmcp` (stdio mode) runs the supervisor (the MCP client config never
//!   changes); the supervisor spawns `<current-exe> … --worker` with piped
//!   stdio and pumps newline-delimited JSON-RPC between client and child,
//!   byte-for-byte.
//! - It remembers the client's `initialize` request and `initialized`
//!   notification verbatim, and tracks in-flight request ids (client requests
//!   forwarded minus child responses returned).
//! - A ticker stats the executable; when the on-disk identity changes (a
//!   rename-replace install) and NOTHING is in flight, it spawns a fresh child,
//!   replays the handshake into it (swallowing the duplicate response the
//!   client must never see), atomically routes traffic to it, kills the old
//!   child, and nudges the client with `notifications/tools/list_changed` so a
//!   changed toolset is re-listed. The client's pipes never close: zero visible
//!   downtime.
//! - The same replay path restarts a CRASHED child, so the supervisor is also
//!   the server's crash hatch (rate-limited; a child that dies repeatedly ends
//!   the session honestly).
//!
//! Deliberately a byte pump, not a proxy that re-frames: the
//! supervisor parses each line only enough to classify it (request id
//! / response id / the two handshake messages) and always forwards
//! the ORIGINAL bytes. Cross-platform by construction — plain
//! `std::process` and threads, no exec(2), identical on Windows.
//!
//! # Environment
//!
//! | Variable | Effect | Default |
//! |---|---|---|
//! | `UFFS_MCP_WORKER_EXE` | Program spawned as the worker | the supervisor's own executable |
//! | `UFFS_MCP_WATCH_PATH` | File whose identity change triggers a swap | the worker executable |
//! | `UFFS_MCP_POLL_MS`    | Ticker interval in milliseconds | `5000` |

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashSet;
use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Mutex;

use anyhow::{Context as _, Result, anyhow};

/// How often the ticker checks the executable for replacement.
const POLL_MS_DEFAULT: u64 = 5_000;

/// Child crashes tolerated inside [`CRASH_WINDOW_SECS`] before the
/// supervisor gives up and ends the session.
const CRASH_LIMIT: usize = 3;

/// The crash-rate window (see [`CRASH_LIMIT`]).
const CRASH_WINDOW_SECS: u64 = 60;

/// The on-disk identity of the served binary: replaced-in-place is a
/// changed (len, mtime) pair — installers replace by rename, so a
/// swap always changes mtime even when the length matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BinaryIdentity {
    /// File length in bytes.
    len: u64,
    /// Modification time (unix millis; 0 when unavailable).
    mtime_ms: u128,
}

impl BinaryIdentity {
    /// Reads the identity of `path`; `None` when it cannot be stat'ed
    /// (a transient install window — the ticker just retries).
    fn of(path: &std::path::Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        let mtime_ms = meta
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |elapsed| elapsed.as_millis());
        Some(Self {
            len: meta.len(),
            mtime_ms,
        })
    }
}

/// What one JSON-RPC line means to the pump (classification only; the
/// original bytes are always what gets forwarded).
#[derive(Debug, Clone, PartialEq, Eq)]
enum LineKind {
    /// A request carrying an id (the client expects a response).
    Request(String),
    /// A response carrying an id (settles an in-flight request).
    Response(String),
    /// The `initialize` request (also a [`LineKind::Request`]; carries
    /// the id the replay must swallow).
    Initialize(String),
    /// The `notifications/initialized` notification.
    Initialized,
    /// Anything else (notifications, malformed lines): forward as-is.
    Other,
}

/// Classifies one JSON-RPC line. A malformed line is [`LineKind::Other`]:
/// the pump never drops bytes it does not understand.
fn classify(line: &str) -> LineKind {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return LineKind::Other;
    };
    let request_id = value.get("id").map(ToString::to_string);
    let method = value.get("method").and_then(serde_json::Value::as_str);
    match (method, request_id) {
        (Some("initialize"), Some(found)) => LineKind::Initialize(found),
        (Some("notifications/initialized"), None) => LineKind::Initialized,
        (Some(_), Some(found)) => LineKind::Request(found),
        (None, Some(found)) => LineKind::Response(found),
        (Some(_) | None, None) => LineKind::Other,
    }
}

/// The captured client handshake, replayed into every fresh child.
#[derive(Debug, Default, Clone)]
struct Handshake {
    /// The verbatim `initialize` request line and its id.
    initialize: Option<(String, String)>,
    /// The verbatim `notifications/initialized` line.
    initialized: Option<String>,
}

/// The live worker child: process handle plus its stdin (the stdout
/// pump thread owns the read half).
struct Worker {
    /// The child process.
    child: Child,
    /// Its stdin, for forwarded client bytes.
    stdin: ChildStdin,
    /// Generation counter (stdout pumps of dead generations exit).
    generation: u64,
}

/// The shared pump state.
struct Shared {
    /// The current worker (swapped under this lock).
    worker: Mutex<Option<Worker>>,
    /// Ids of requests forwarded to the child and not yet answered.
    in_flight: Mutex<HashSet<String>>,
    /// The captured handshake.
    handshake: Mutex<Handshake>,
    /// The client-facing stdout (one writer at a time).
    client_out: Mutex<std::io::Stdout>,
    /// Set when the session is over (client EOF or fatal error).
    done: AtomicBool,
}

/// Runs the supervisor until the client disconnects.
///
/// `worker_args` is the argv (minus the program) the worker child is
/// spawned with — the caller passes its own arguments plus `--worker`.
///
/// # Errors
///
/// Returns an error when the executable cannot be resolved or the
/// first worker fails to spawn; later worker crashes are handled by
/// the respawn path (rate-limited).
pub(crate) fn run(worker_args: &[std::ffi::OsString]) -> Result<()> {
    let exe = std::env::var_os("UFFS_MCP_WORKER_EXE").map_or_else(
        || std::env::current_exe().context("resolving the uffsmcp executable"),
        |raw| Ok(std::path::PathBuf::from(raw)),
    )?;
    let watch_path = std::env::var_os("UFFS_MCP_WATCH_PATH")
        .map_or_else(|| exe.clone(), std::path::PathBuf::from);
    let poll_ms = std::env::var("UFFS_MCP_POLL_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(POLL_MS_DEFAULT);
    let shared = Arc::new(Shared {
        worker: Mutex::new(None),
        in_flight: Mutex::new(HashSet::new()),
        handshake: Mutex::new(Handshake::default()),
        client_out: Mutex::new(std::io::stdout()),
        done: AtomicBool::new(false),
    });
    let first = spawn_worker(&exe, worker_args, 0)?;
    install_worker(&shared, first, None);
    tracing::info!(exe = %exe.display(), poll_ms, "mcp supervisor armed (self-upgrading)");

    let ticker = {
        let shared_for_ticker = Arc::clone(&shared);
        let exe_for_ticker = exe;
        let args: Vec<std::ffi::OsString> = worker_args.to_vec();
        std::thread::spawn(move || {
            ticker_loop(
                &shared_for_ticker,
                &exe_for_ticker,
                &watch_path,
                &args,
                poll_ms,
            );
        })
    };
    pump_client_stdin(&shared);
    shared.done.store(true, Ordering::SeqCst);
    if let Ok(mut slot) = shared.worker.lock()
        && let Some(mut worker) = slot.take()
    {
        let _kill = worker.child.kill();
        let _wait = worker.child.wait();
    }
    let _join = ticker.join();
    Ok(())
}

/// Reads the client's stdin to EOF, classifying and forwarding each
/// line to the current worker.
fn pump_client_stdin(shared: &Arc<Shared>) {
    let mut line = String::new();
    loop {
        line.clear();
        let read = std::io::stdin().lock().read_line(&mut line);
        match read {
            Ok(0) | Err(_) => break,
            Ok(_bytes) => {}
        }
        match classify(line.trim_end()) {
            LineKind::Initialize(id) => {
                if let Ok(mut handshake) = shared.handshake.lock() {
                    handshake.initialize = Some((line.clone(), id.clone()));
                }
                track(shared, &id);
            }
            LineKind::Initialized => {
                if let Ok(mut handshake) = shared.handshake.lock() {
                    handshake.initialized = Some(line.clone());
                }
            }
            LineKind::Request(id) => track(shared, &id),
            LineKind::Response(_) | LineKind::Other => {}
        }
        if forward_to_worker(shared, &line).is_err() {
            // The child is gone mid-write; the respawn path owns
            // recovery. Dropping a request here would strand the
            // client, so the session ends honestly instead.
            tracing::warn!("worker write failed; ending session");
            break;
        }
    }
}

/// Records one in-flight request id.
fn track(shared: &Shared, id: &str) {
    if let Ok(mut in_flight) = shared.in_flight.lock() {
        in_flight.insert(id.to_owned());
    }
}

/// Writes one raw line to the current worker's stdin.
fn forward_to_worker(shared: &Shared, line: &str) -> Result<()> {
    let mut slot = shared
        .worker
        .lock()
        .map_err(|_poison| anyhow!("worker slot poisoned"))?;
    let outcome = match slot.as_mut() {
        Some(worker) => worker
            .stdin
            .write_all(line.as_bytes())
            .and_then(|()| worker.stdin.flush())
            .map_err(|error| anyhow!("writing to the worker: {error}")),
        None => Err(anyhow!("no live worker")),
    };
    drop(slot);
    outcome
}

/// Spawns one worker child of `exe` with piped stdin/stdout (stderr
/// passes through to the supervisor's own stderr).
fn spawn_worker(
    exe: &std::path::Path,
    worker_args: &[std::ffi::OsString],
    generation: u64,
) -> Result<Worker> {
    let mut child = Command::new(exe)
        .args(worker_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawning the uffsmcp worker")?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("worker stdin missing"))?;
    Ok(Worker {
        child,
        stdin,
        generation,
    })
}

/// Installs `worker` as current and starts its stdout pump.
/// `swallow_id` is the replayed-initialize response id the pump must
/// NOT forward (the client already holds the original response).
fn install_worker(shared: &Arc<Shared>, mut worker: Worker, swallow_id: Option<String>) {
    let stdout = worker.child.stdout.take();
    let generation = worker.generation;
    if let Ok(mut slot) = shared.worker.lock() {
        *slot = Some(worker);
    }
    if let Some(taken) = stdout {
        let shared_for_pump = Arc::clone(shared);
        std::thread::spawn(move || {
            pump_worker_stdout(&shared_for_pump, taken, generation, swallow_id);
        });
    }
}

/// Reads one worker's stdout to EOF, forwarding to the client and
/// settling in-flight ids. Exits quietly when its generation was
/// superseded by a swap.
fn pump_worker_stdout(
    shared: &Arc<Shared>,
    stdout: std::process::ChildStdout,
    generation: u64,
    swallow_id: Option<String>,
) {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut swallow = swallow_id;
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_bytes) => {}
        }
        if let LineKind::Response(id) = classify(line.trim_end()) {
            if swallow.as_deref() == Some(id.as_str()) {
                // The duplicate response to the replayed initialize:
                // the client must never see it twice.
                swallow = None;
                continue;
            }
            if let Ok(mut in_flight) = shared.in_flight.lock() {
                in_flight.remove(&id);
            }
        }
        let forwarded = shared.client_out.lock().ok().and_then(|mut out| {
            out.write_all(line.as_bytes())
                .and_then(|()| out.flush())
                .ok()
        });
        if forwarded.is_none() {
            break;
        }
    }
    let superseded = shared.worker.lock().is_ok_and(|slot| {
        slot.as_ref()
            .is_some_and(|live| live.generation != generation)
    });
    if !superseded && !shared.done.load(Ordering::SeqCst) {
        tracing::warn!(generation, "uffsmcp worker exited unexpectedly");
    }
}

/// The upgrade/respawn ticker: polls the binary identity and the
/// worker's liveness, swapping at quiet moments.
fn ticker_loop(
    shared: &Arc<Shared>,
    exe: &std::path::Path,
    watch_path: &std::path::Path,
    worker_args: &[std::ffi::OsString],
    poll_ms: u64,
) {
    let mut installed = BinaryIdentity::of(watch_path);
    let mut generation = 0_u64;
    let mut crashes: Vec<std::time::Instant> = Vec::new();
    while !shared.done.load(Ordering::SeqCst) {
        std::thread::sleep(core::time::Duration::from_millis(poll_ms));
        let worker_died = worker_exited(shared);
        let current = BinaryIdentity::of(watch_path);
        let replaced = current.is_some() && current != installed;
        if !replaced && !worker_died {
            continue;
        }
        if worker_died && crash_limit_hit(&mut crashes) {
            tracing::error!("uffsmcp worker crash-looping; ending session");
            shared.done.store(true, Ordering::SeqCst);
            return;
        }
        let quiet = shared
            .in_flight
            .lock()
            .is_ok_and(|in_flight| in_flight.is_empty());
        if !quiet && !worker_died {
            continue; // a request is mid-air; try again next tick
        }
        generation += 1;
        if perform_swap(shared, exe, worker_args, generation, worker_died) {
            installed = current;
        } else {
            return;
        }
    }
}

/// True when the current worker process has exited.
fn worker_exited(shared: &Shared) -> bool {
    shared.worker.lock().is_ok_and(|mut slot| {
        slot.as_mut()
            .is_some_and(|live| matches!(live.child.try_wait(), Ok(Some(_status))))
    })
}

/// One swap attempt with its logging; `false` ends the ticker (the
/// session is marked done on failure).
fn perform_swap(
    shared: &Arc<Shared>,
    exe: &std::path::Path,
    worker_args: &[std::ffi::OsString],
    generation: u64,
    worker_died: bool,
) -> bool {
    match swap_worker(shared, exe, worker_args, generation) {
        Ok(()) => {
            tracing::info!(
                generation,
                reason = if worker_died {
                    "crash"
                } else {
                    "binary replaced"
                },
                "uffsmcp worker swapped in place"
            );
            true
        }
        Err(error) => {
            tracing::error!(%error, "worker swap failed; ending session");
            shared.done.store(true, Ordering::SeqCst);
            false
        }
    }
}

/// Records one worker crash and prunes the rate window; `true` when
/// the limit is exceeded and the supervisor should give up.
fn crash_limit_hit(crashes: &mut Vec<std::time::Instant>) -> bool {
    let now = std::time::Instant::now();
    crashes.retain(|at| now.duration_since(*at).as_secs() < CRASH_WINDOW_SECS);
    crashes.push(now);
    crashes.len() > CRASH_LIMIT
}

/// Spawns a fresh worker, replays the captured handshake into it,
/// installs it (its stdout pump swallows the duplicate initialize
/// response), and kills the predecessor.
fn swap_worker(
    shared: &Arc<Shared>,
    exe: &std::path::Path,
    worker_args: &[std::ffi::OsString],
    generation: u64,
) -> Result<()> {
    let handshake = shared
        .handshake
        .lock()
        .map_err(|_poison| anyhow!("handshake poisoned"))?
        .clone();
    let mut fresh = spawn_worker(exe, worker_args, generation)?;
    let swallow_id = if let Some((line, id)) = &handshake.initialize {
        fresh
            .stdin
            .write_all(line.as_bytes())
            .context("replaying initialize")?;
        Some(id.clone())
    } else {
        None
    };
    if let Some(line) = &handshake.initialized {
        fresh
            .stdin
            .write_all(line.as_bytes())
            .context("replaying initialized")?;
    }
    fresh
        .stdin
        .flush()
        .context("flushing the handshake replay")?;
    let previous = shared
        .worker
        .lock()
        .map_err(|_poison| anyhow!("worker slot poisoned"))?
        .take();
    install_worker(shared, fresh, swallow_id);
    if let Some(mut old) = previous {
        let _kill = old.child.kill();
        let _wait = old.child.wait();
    }
    // A changed binary may carry a changed toolset: nudge the client
    // to re-list (spec notification; clients without the capability
    // ignore it).
    if handshake.initialize.is_some()
        && let Ok(mut out) = shared.client_out.lock()
    {
        let _nudge = out
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n")
            .and_then(|()| out.flush());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{LineKind, classify};

    /// Requests, responses, and the two handshake messages classify by
    /// shape; malformed lines are passthrough.
    #[test]
    fn lines_classify_by_jsonrpc_shape() {
        assert_eq!(
            classify(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#),
            LineKind::Initialize(String::from("1"))
        );
        assert_eq!(
            classify(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            LineKind::Initialized
        );
        assert_eq!(
            classify(r#"{"jsonrpc":"2.0","id":"a-7","method":"tools/call","params":{}}"#),
            LineKind::Request(String::from("\"a-7\""))
        );
        assert_eq!(
            classify(r#"{"jsonrpc":"2.0","id":"a-7","result":{}}"#),
            LineKind::Response(String::from("\"a-7\""))
        );
        assert_eq!(
            classify(r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#),
            LineKind::Other
        );
        assert_eq!(classify("not json at all"), LineKind::Other);
    }

    /// A request and its response settle to the same id string, number
    /// and string ids alike.
    #[test]
    fn request_and_response_ids_agree() {
        let request = classify(r#"{"jsonrpc":"2.0","id":42,"method":"tools/list"}"#);
        let response = classify(r#"{"jsonrpc":"2.0","id":42,"result":{"tools":[]}}"#);
        match (request, response) {
            (LineKind::Request(sent), LineKind::Response(settled)) => {
                assert_eq!(sent, settled);
            }
            other => panic!("unexpected classification: {other:?}"),
        }
    }
}
