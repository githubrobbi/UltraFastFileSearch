// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! IPC server: Unix domain socket (macOS/Linux) / named pipe (Windows).
//!
//! Listens for newline-delimited JSON-RPC messages, dispatches to the
//! request handler, and writes responses back.

use alloc::sync::Arc;
use std::path::PathBuf;

use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use uffs_client::protocol::{ERR_PARSE, RpcErrorResponse, RpcRequest};

use crate::events::{EventReceiver, event_to_json_line};
use crate::handler::RequestHandler;
use crate::index::IndexManager;
use crate::lifecycle::LifecycleHandle;

/// Maximum concurrent connections.
///
/// Raised to 256 to support concurrent queries (searches no longer hold
/// an exclusive write lock — see `daemon-concurrent-queries` design doc).
const MAX_CONNECTIONS: usize = 256;

/// Maximum message size (16 MB).
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Idle connection timeout — disconnect if no messages for this long (S4.4.8).
const IDLE_CONNECTION_SECS: u64 = 300; // 5 minutes

/// Per-connection rate limit: max queries per second (S4.4.6).
const MAX_QUERIES_PER_SEC: u32 = 100;

/// IPC server for daemon-client communication.
pub(crate) struct IpcServer;

impl IpcServer {
    /// Returns the platform-specific socket path.
    pub(crate) fn socket_path() -> PathBuf {
        let base = dirs_next::data_local_dir().unwrap_or_else(|| PathBuf::from("/tmp"));

        #[cfg(target_os = "macos")]
        {
            base.join("uffs").join("daemon.sock")
        }
        #[cfg(target_os = "linux")]
        {
            std::env::var("XDG_RUNTIME_DIR").map_or_else(
                |_| base.join("uffs").join("daemon.sock"),
                |runtime_dir| PathBuf::from(runtime_dir).join("uffs").join("daemon.sock"),
            )
        }
        #[cfg(target_os = "windows")]
        {
            base.join("uffs").join("daemon.sock")
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            base.join("uffs").join("daemon.sock")
        }
    }

    /// Verify that the connecting client has the same UID as the daemon.
    ///
    /// - **macOS/BSD**: uses `getpeereid()` via the raw fd
    /// - **Linux**: uses `SO_PEERCRED` via `getsockopt`
    /// - **Windows**: always returns `true` (named pipe DACL handles this)
    #[cfg(unix)]
    #[expect(
        clippy::single_call_fn,
        reason = "security boundary — must stay separate"
    )]
    fn verify_peer_credentials(stream: &tokio::net::UnixStream) -> bool {
        use std::os::unix::io::AsRawFd as _;

        let fd = stream.as_raw_fd();

        // SAFETY: `getuid()` is a pure read of the process UID — no side effects.
        #[expect(unsafe_code, reason = "getuid is a standard POSIX call")]
        let my_uid = unsafe { libc::getuid() };

        let Some(peer_uid) = Self::get_peer_uid(fd) else {
            tracing::warn!("peer credential check failed, rejecting connection");
            return false;
        };

        if peer_uid != my_uid {
            tracing::warn!(
                peer_uid,
                daemon_uid = my_uid,
                "Peer UID mismatch — rejecting connection"
            );
            return false;
        }

        true
    }

    /// macOS/BSD: retrieve peer UID via `getpeereid()`.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    fn get_peer_uid(fd: std::os::unix::io::RawFd) -> Option<libc::uid_t> {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;

        // SAFETY: `getpeereid()` writes into the two out-params.  We pass valid
        // mutable pointers and a valid fd obtained from the stream.
        #[expect(unsafe_code, reason = "getpeereid is a standard POSIX call")]
        let rc = unsafe {
            libc::getpeereid(
                fd,
                core::ptr::addr_of_mut!(uid),
                core::ptr::addr_of_mut!(gid),
            )
        };

        if rc != 0_i32 {
            return None;
        }
        Some(uid)
    }

    /// Linux: retrieve peer UID via `SO_PEERCRED` / `getsockopt`.
    #[cfg(target_os = "linux")]
    fn get_peer_uid(fd: std::os::unix::io::RawFd) -> Option<libc::uid_t> {
        let mut cred: libc::ucred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        // `ucred` is 12 bytes (3 × i32) on every supported platform, so
        // `try_from` is the lossless, lint-free conversion to
        // `socklen_t` (u32 on Linux, u32 on macOS); the saturating
        // fallback exists only to satisfy the type-system contract and
        // is unreachable in practice.
        let mut len =
            libc::socklen_t::try_from(size_of::<libc::ucred>()).unwrap_or(libc::socklen_t::MAX);

        // SAFETY: `getsockopt` with `SO_PEERCRED` reads the ucred struct for
        // the peer of a Unix domain socket.  We pass a valid fd and correctly
        // sized buffer.
        #[expect(unsafe_code, reason = "getsockopt SO_PEERCRED is standard Linux")]
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                core::ptr::addr_of_mut!(cred).cast(),
                core::ptr::addr_of_mut!(len),
            )
        };

        if rc != 0_i32 {
            return None;
        }
        Some(cred.uid)
    }

    /// Windows: peer credential verification via ACL (handled at socket level).
    #[cfg(windows)]
    const fn verify_peer_credentials_win() -> bool {
        true
    }

    /// Handle a single client connection (shared across all platforms).
    ///
    /// Uses a split-writer architecture:
    /// - **Reader task**: reads JSON-RPC requests, dispatches to handler, sends
    ///   responses via an outbound channel.
    /// - **Notification task**: subscribes to the broadcast event channel,
    ///   serializes events as JSON-RPC notifications, sends via the same
    ///   outbound channel.
    /// - **Writer task**: drains the outbound channel and writes to the socket
    ///   (single writer, no concurrent writes).
    ///
    /// Enforces:
    /// - S4.4.8: 5-minute idle connection timeout
    /// - S4.4.6: Per-connection rate limit (100 queries/sec)
    async fn handle_connection(
        reader: impl tokio::io::AsyncRead + Unpin + Send + 'static,
        writer: impl tokio::io::AsyncWrite + Unpin + Send + 'static,
        handler: Arc<RequestHandler>,
        event_rx: EventReceiver,
    ) -> anyhow::Result<()> {
        // Outbound channel — both responses and notifications funnel here.
        let (out_tx, out_rx) = tokio::sync::mpsc::channel::<String>(128);

        // ── Writer task: drains outbound channel → socket ────────────
        let writer_task = tokio::spawn(Self::writer_loop(writer, out_rx));

        // ── Notification task: broadcast events → outbound channel ───
        let notif_tx = out_tx.clone();
        let notif_task = tokio::spawn(Self::notification_loop(event_rx, notif_tx));

        // ── Reader task: reads requests → handler → outbound channel ─
        let reader_result = Self::reader_loop(reader, handler, out_tx).await;

        // Reader done (client disconnected or error) — cancel helpers.
        notif_task.abort();
        writer_task.abort();

        reader_result
    }

    /// Reads JSON-RPC requests from the client, dispatches to the handler,
    /// and sends responses via the outbound channel.
    #[expect(
        clippy::single_call_fn,
        reason = "structural separation — reader/writer/notifier split"
    )]
    async fn reader_loop(
        reader: impl tokio::io::AsyncRead + Unpin,
        handler: Arc<RequestHandler>,
        out_tx: tokio::sync::mpsc::Sender<String>,
    ) -> anyhow::Result<()> {
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        let mut queries_this_second: u32 = 0;
        let mut rate_limit_epoch = std::time::Instant::now();

        loop {
            line.clear();

            let read_result = tokio::time::timeout(
                core::time::Duration::from_secs(IDLE_CONNECTION_SECS),
                buf_reader.read_line(&mut line),
            )
            .await;

            let bytes_read = match read_result {
                Ok(Ok(count)) => count,
                Ok(Err(io_err)) => return Err(io_err.into()),
                Err(_) => {
                    tracing::debug!(
                        "Idle connection timeout ({}s), disconnecting",
                        IDLE_CONNECTION_SECS
                    );
                    return Ok(());
                }
            };

            if bytes_read == 0 {
                return Ok(());
            }

            if line.len() > MAX_MESSAGE_SIZE {
                let err_resp = RpcErrorResponse::error(None, ERR_PARSE, "Message too large");
                let json_out = serde_json::to_string(&err_resp).unwrap_or_default();
                let mut msg = json_out;
                msg.push('\n');
                let _ignore = out_tx.send(msg).await;
                return Ok(());
            }

            let now = std::time::Instant::now();
            if now.duration_since(rate_limit_epoch).as_secs() >= 1_u64 {
                queries_this_second = 0;
                rate_limit_epoch = now;
            }
            queries_this_second += 1;
            if queries_this_second > MAX_QUERIES_PER_SEC {
                let rate_err = RpcErrorResponse::error(
                    None,
                    -32000_i32,
                    &format!("Rate limit exceeded ({MAX_QUERIES_PER_SEC} queries/sec)"),
                );
                let json_out = serde_json::to_string(&rate_err).unwrap_or_default();
                let mut msg = json_out;
                msg.push('\n');
                let _ignore = out_tx.send(msg).await;
                continue;
            }

            handler.lifecycle.reset_idle_timer();

            let req: RpcRequest = match serde_json::from_str(line.trim()) {
                Ok(parsed) => parsed,
                Err(parse_err) => {
                    let err_resp = RpcErrorResponse::error(
                        None,
                        ERR_PARSE,
                        &format!("Invalid JSON: {parse_err}"),
                    );
                    let json_out = serde_json::to_string(&err_resp).unwrap_or_default();
                    let mut msg = json_out;
                    msg.push('\n');
                    let _ignore = out_tx.send(msg).await;
                    continue;
                }
            };

            let response = handler.handle(&req).await;
            let mut msg = response;
            msg.push('\n');
            if out_tx.send(msg).await.is_err() {
                // Writer task dropped — connection is dead.
                return Ok(());
            }
        }
    }

    /// Subscribes to daemon events and forwards them as JSON-RPC
    /// notifications to the outbound channel.
    #[expect(
        clippy::single_call_fn,
        reason = "structural separation — reader/writer/notifier split"
    )]
    async fn notification_loop(
        mut event_rx: EventReceiver,
        out_tx: tokio::sync::mpsc::Sender<String>,
    ) {
        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    if let Some(json_line) = event_to_json_line(&event)
                        && out_tx.send(json_line).await.is_err()
                    {
                        // Client disconnected.
                        return;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::debug!(skipped, "Client lagged on event broadcast");
                    // Continue — just skip the missed events.
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    // Daemon shutting down — broadcast channel closed.
                    return;
                }
            }
        }
    }

    /// Drains the outbound channel and writes each message to the socket.
    #[expect(
        clippy::single_call_fn,
        reason = "structural separation — reader/writer/notifier split"
    )]
    async fn writer_loop(
        mut writer: impl tokio::io::AsyncWrite + Unpin,
        mut out_rx: tokio::sync::mpsc::Receiver<String>,
    ) {
        while let Some(msg) = out_rx.recv().await {
            if writer.write_all(msg.as_bytes()).await.is_err() {
                return;
            }
            if writer.flush().await.is_err() {
                return;
            }
        }
    }
}

/// Run the IPC server on a Unix domain socket.
///
/// Returns when the lifecycle manager signals shutdown.
#[cfg(unix)]
pub(crate) async fn run_ipc_server(
    index: Arc<IndexManager>,
    lifecycle: LifecycleHandle,
    ephemeral_id: Option<&str>,
) -> anyhow::Result<()> {
    let listener = bind_unix_listener(ephemeral_id)?;
    let events = index.event_sender().clone();
    let handler = Arc::new(RequestHandler {
        index,
        lifecycle: lifecycle.clone(),
    });

    loop {
        let (stream, _addr) = listener.accept().await?;
        if !accept_unix_connection_is_admitted(&stream, &lifecycle) {
            continue;
        }
        spawn_unix_connection(stream, &handler, &lifecycle, &events);
    }
}

/// Create the UDS listener used by [`run_ipc_server`].
///
/// Folds together the secure-directory bootstrap, stale-socket
/// cleanup, bind, and 0600-permission lockdown so the orchestrator
/// can stay focused on the accept loop.
#[cfg(unix)]
fn bind_unix_listener(ephemeral_id: Option<&str>) -> anyhow::Result<tokio::net::UnixListener> {
    let sock_path = ephemeral_id.map_or_else(IpcServer::socket_path, |id| {
        PathBuf::from(uffs_client::daemon_ctl::ephemeral_endpoint(id))
    });

    if let Some(parent) = sock_path.parent() {
        uffs_security::fs::create_secure_dir(parent)?;
    }

    if sock_path.exists() {
        std::fs::remove_file(&sock_path)?;
    }

    let listener = tokio::net::UnixListener::bind(&sock_path)?;

    // Set socket permissions to owner-only (0600).
    uffs_security::fs::set_file_permissions_owner_only(&sock_path)?;

    tracing::info!(path = %sock_path.display(), "IPC server listening");
    Ok(listener)
}

/// Run the per-accept gatekeeping and return whether the connection
/// should be handed off to a worker task.
///
/// Two checks: S4.2 peer-credential verification (reject foreign UIDs)
/// and the [`MAX_CONNECTIONS`] cap.  `false` means the stream has
/// already been dropped and the caller's loop should `continue`.
#[cfg(unix)]
fn accept_unix_connection_is_admitted(
    stream: &tokio::net::UnixStream,
    lifecycle: &LifecycleHandle,
) -> bool {
    if !IpcServer::verify_peer_credentials(stream) {
        tracing::warn!("Rejected connection from different UID");
        return false;
    }

    let active = lifecycle.active_connections();
    if active >= MAX_CONNECTIONS {
        tracing::warn!(
            active,
            max = MAX_CONNECTIONS,
            "Max connections reached, rejecting"
        );
        return false;
    }

    true
}

/// Hand off an admitted UDS connection to a dedicated worker task,
/// keeping the connection counter and tracing in sync.
#[cfg(unix)]
fn spawn_unix_connection(
    stream: tokio::net::UnixStream,
    handler: &Arc<RequestHandler>,
    lifecycle: &LifecycleHandle,
    events: &crate::events::EventSender,
) {
    lifecycle.connection_opened();
    let handler_clone = Arc::clone(handler);
    let lc_clone = lifecycle.clone();
    let event_rx = events.subscribe();
    let (read_half, write_half) = stream.into_split();

    tokio::spawn(async move {
        let total_conns = lc_clone.active_connections();
        tracing::debug!(connections = total_conns, "Client connected");

        if let Err(conn_err) =
            IpcServer::handle_connection(read_half, write_half, handler_clone, event_rx).await
        {
            tracing::debug!(error = %conn_err, "Connection ended");
        }

        lc_clone.connection_closed();
        let remaining = lc_clone.active_connections();
        tracing::debug!(connections = remaining, "Client disconnected");
    });
}

/// Run the IPC server on a Windows named pipe.
///
/// This is the **preferred** transport on Windows — replaces the earlier
/// `AF_UNIX` path, which pulled in `ws2_32.dll` (13 imports, +54 ms launch
/// overhead per client invocation).
///
/// The daemon is typically elevated (MFT read requires admin).  The pipe
/// DACL grants `GENERIC_ALL` to the *unelevated* user SID (resolved via
/// `TokenLinkedToken` — see `uffs_security::pipe`) so that the client CLI
/// running as the regular user can connect, while other local admins
/// cannot.
///
/// `FIRST_PIPE_INSTANCE` on the initial server instance protects against
/// name-squatting attacks from other processes on the same machine.
///
/// Returns when the accept loop errors terminally.  The `AF_UNIX` listener
/// (below) continues running as a fallback during the transition.
#[cfg(windows)]
pub(crate) async fn run_pipe_server(
    index: Arc<IndexManager>,
    lifecycle: LifecycleHandle,
    ephemeral_id: Option<&str>,
) -> anyhow::Result<()> {
    let pipe_name = resolve_pipe_name(ephemeral_id)?;

    // DACL: allow the linked-token user only.  Kept alive for the entire
    // lifetime of the listener — every server instance borrows from it.
    let sd = uffs_security::pipe::OwnerOnlySd::for_current_user()
        .map_err(|sd_err| anyhow::anyhow!("owner-only DACL build failed: {sd_err}"))?;

    tracing::info!(pipe = %pipe_name, "IPC server listening (named pipe)");

    let events = index.event_sender().clone();
    let handler = Arc::new(RequestHandler {
        index,
        lifecycle: lifecycle.clone(),
    });

    // Create the FIRST server instance with FIRST_PIPE_INSTANCE to
    // prevent name squatting.
    let mut server = create_pipe_server(&pipe_name, &sd, /* first= */ true)?;

    loop {
        // Wait for a client to connect to THIS instance.
        if let Err(connect_err) = server.connect().await {
            tracing::warn!(error = %connect_err, "named-pipe connect failed, retrying");
            // Rebuild the server instance and continue.
            server = create_pipe_server(&pipe_name, &sd, /* first= */ false)?;
            continue;
        }

        // Hand off the connected instance, and spin up the NEXT listener
        // BEFORE awaiting any further (named-pipe idiom: the next server
        // instance must exist before the previous one is fully consumed,
        // otherwise there is a window where new clients race and fail).
        let connected = server;
        server = create_pipe_server(&pipe_name, &sd, /* first= */ false)?;

        let active = lifecycle.active_connections();
        if active >= MAX_CONNECTIONS {
            tracing::warn!(
                active,
                max = MAX_CONNECTIONS,
                "[daemon-pipe] Max connections reached — dropping"
            );
            drop(connected);
            continue;
        }

        lifecycle.connection_opened();
        let handler_clone = Arc::clone(&handler);
        let lc_clone = lifecycle.clone();
        let event_rx = events.subscribe();

        // Split the duplex pipe into owned read/write halves.
        let (read_half, write_half) = tokio::io::split(connected);

        tokio::spawn(async move {
            let total_conns = lc_clone.active_connections();
            tracing::debug!(
                connections = total_conns,
                transport = "pipe",
                "Client connected"
            );

            if let Err(conn_err) =
                IpcServer::handle_connection(read_half, write_half, handler_clone, event_rx).await
            {
                tracing::debug!(error = %conn_err, transport = "pipe", "Connection ended");
            }

            lc_clone.connection_closed();
            let remaining = lc_clone.active_connections();
            tracing::debug!(
                connections = remaining,
                transport = "pipe",
                "Client disconnected"
            );
        });
    }
}

/// Resolve the pipe name [`run_pipe_server`] should bind: the per-user
/// well-known name, or (when `ephemeral_id` is set) the isolated
/// ephemeral-instance name. Extracted so `run_pipe_server` stays under
/// clippy's cognitive-complexity budget.
#[cfg(windows)]
fn resolve_pipe_name(ephemeral_id: Option<&str>) -> anyhow::Result<uffs_security::pipe::PipeName> {
    ephemeral_id.map_or_else(
        || {
            uffs_security::pipe::PipeName::for_current_user()
                .map_err(|sid_err| anyhow::anyhow!("pipe name resolution failed: {sid_err}"))
        },
        |id| {
            uffs_security::pipe::PipeName::parse(uffs_client::daemon_ctl::ephemeral_endpoint(id))
                .map_err(|err| anyhow::anyhow!("invalid ephemeral pipe name: {err}"))
        },
    )
}

/// Build a single named-pipe server instance bound to `pipe_name` with
/// the owner-only `sd`.  Set `first = true` ONLY for the initial
/// instance (enables `FIRST_PIPE_INSTANCE` squat protection).
#[cfg(windows)]
fn create_pipe_server(
    pipe_name: &uffs_security::pipe::PipeName,
    sd: &uffs_security::pipe::OwnerOnlySd,
    first: bool,
) -> anyhow::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};

    let mut sa = sd.as_security_attributes();

    let mut opts = ServerOptions::new();
    opts.access_inbound(true)
        .access_outbound(true)
        .pipe_mode(PipeMode::Byte)
        .in_buffer_size(65_536)
        .out_buffer_size(65_536)
        .reject_remote_clients(true);
    if first {
        opts.first_pipe_instance(true);
    }

    // SAFETY: `name_wide` is a valid null-terminated UTF-16 buffer;
    // `sa` is a valid SECURITY_ATTRIBUTES borrowing a SECURITY_DESCRIPTOR
    // owned by `sd` (outlives this call).
    #[expect(unsafe_code, reason = "Win32 FFI — create named-pipe server")]
    let server = unsafe {
        opts.create_with_security_attributes_raw(
            pipe_name.as_str(),
            core::ptr::from_mut(&mut sa).cast(),
        )
    }?;

    Ok(server)
}

/// Windows AF_UNIX accept loop + std-socket↔tokio-duplex bridge
/// threads.  Lives in its own file so this module stays under the
/// 800-LOC file-size policy.
#[cfg(windows)]
mod windows_unix_bridge;

#[cfg(windows)]
pub(crate) use windows_unix_bridge::run_ipc_server;
