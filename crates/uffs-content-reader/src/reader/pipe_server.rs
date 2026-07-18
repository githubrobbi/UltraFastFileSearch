// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Named-pipe server for [`READER_PIPE_NAME`].
//!
//! Accepts every connection the Coordinator opens — one per leased
//! drive, for read parallelism (see the local-only content-engine
//! architecture doc's Reader-parallelism section) — and serves framed
//! `ReadRequest`/`ReadResponse` messages on each independently, until
//! that connection's own peer disconnects. Each request's disk I/O runs
//! via [`tokio::task::spawn_blocking`], so concurrent connections'
//! reads actually execute in parallel instead of serializing behind one
//! current-thread runtime.
//!
//! This process has no "last connection closed" lifecycle logic of its
//! own to worry about: the Coordinator kills it directly
//! (`ContentReader::shutdown`) once the job is done, mirroring
//! `uffs-ingest-implementation-plan.md`'s one-Reader-per-job lifecycle —
//! the accept loop below just runs for as long as the process does,
//! same shape as `uffs-content::serve`'s own command-pipe accept loop.

use alloc::sync::Arc;
use std::collections::HashMap;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use uffs_content_reader_protocol::{READER_PIPE_NAME, ReadRequest, ReadResponse, ReaderErrorCode};

/// Matches the Coordinator-side `MAX_REQUEST_BYTES`-style bound used
/// for the Broker's Snapshot Manager pipe — a generous ceiling for this
/// small, narrow API.
const MAX_REQUEST_BYTES: u32 = 64 * 1024;

/// How long to back off before retrying pipe-instance creation after a
/// transient failure.
const PIPE_RETRY_BACKOFF: core::time::Duration = core::time::Duration::from_millis(100);

/// Run the Reader's pipe server for the process's whole lifetime.
///
/// # Errors
/// Returns an error only if the pipe itself cannot be created at all.
pub(crate) fn run(devices: &HashMap<u64, String>) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve(devices))
}

/// Accept every connection the Coordinator opens, spawning one task per
/// connection so multiple drives' reads run concurrently — the async
/// body of [`run`].
#[expect(
    clippy::infinite_loop,
    reason = "process-lifetime accept loop: this process is killed externally by the \
              Coordinator once the job is done, matching uffs-content::serve's own \
              command-pipe accept loop"
)]
async fn serve(devices: &HashMap<u64, String>) -> anyhow::Result<()> {
    let pipe_name = uffs_security::pipe::PipeName::parse(READER_PIPE_NAME)
        .map_err(|err| anyhow::anyhow!("invalid READER_PIPE_NAME: {err}"))?;
    let sd = uffs_security::pipe::OwnerOnlySd::for_current_user()
        .map_err(|err| anyhow::anyhow!("owner-only DACL build failed: {err}"))?;
    let shared_devices = Arc::new(devices.clone());

    let mut first_instance = true;
    loop {
        let mut server = match create_server(&pipe_name, &sd, first_instance) {
            Ok(server) => server,
            Err(err) => {
                tracing::warn!(error = %err, "pipe instance unavailable; retrying shortly");
                tokio::time::sleep(PIPE_RETRY_BACKOFF).await;
                continue;
            }
        };
        first_instance = false;
        if server.connect().await.is_err() {
            continue;
        }
        tracing::info!("Coordinator connected");

        let devices_for_connection = Arc::clone(&shared_devices);
        tokio::spawn(async move {
            serve_requests(&mut server, &devices_for_connection).await;
        });
    }
}

/// Drain requests off `server` until the Coordinator disconnects that
/// connection (or sends a malformed request, which also ends it — see
/// [`read_one_request`]). Every request's blocking disk I/O runs via
/// `spawn_blocking`, so a slow read on one connection never blocks any
/// other connection.
///
/// Owns this connection's [`super::logical::ReadHandleCache`] for the
/// connection's whole lifetime, starting empty and threading the
/// updated cache back out of every `dispatch_request_blocking` call —
/// see that type's own doc comment for why a per-connection cache is
/// safe and effective here (the Coordinator pins one connection per
/// candidate's whole sequential read).
async fn serve_requests(server: &mut NamedPipeServer, devices: &Arc<HashMap<u64, String>>) {
    let mut cache = super::logical::ReadHandleCache::empty();
    loop {
        match read_one_request(server).await {
            Ok(Some(request)) => {
                match respond_to_one_request(server, request, devices, cache).await {
                    Some(updated_cache) => cache = updated_cache,
                    None => return,
                }
            }
            Ok(None) => {
                tracing::info!("Coordinator disconnected this connection");
                return;
            }
            Err(err) => {
                tracing::warn!(error = %err, "malformed request; closing connection");
                return;
            }
        }
    }
}

/// Dispatch one request and write its response. Returns the updated
/// [`super::logical::ReadHandleCache`] for the caller to keep using on
/// this connection's next request, or `None` if the connection should
/// close (a write failure — the read side already handles its own
/// EOF/malformed-request cases in [`serve_requests`]).
async fn respond_to_one_request(
    server: &mut NamedPipeServer,
    request: ReadRequest,
    devices: &Arc<HashMap<u64, String>>,
    cache: super::logical::ReadHandleCache,
) -> Option<super::logical::ReadHandleCache> {
    let (response, updated_cache) =
        dispatch_request_blocking(request, Arc::clone(devices), cache).await;
    if let Err(err) = write_one_response(server, &response).await {
        tracing::warn!(error = %err, "failed to write response; closing connection");
        return None;
    }
    Some(updated_cache)
}

/// Run [`super::dispatch_request`]'s blocking disk I/O on tokio's
/// blocking thread pool, turning a panic there into a
/// [`ReaderErrorCode::InternalError`] response (with an emptied cache)
/// rather than propagating it (a single request's panic must not tear
/// down the whole connection, matching `dispatch_request`'s own
/// never-panics contract).
async fn dispatch_request_blocking(
    request: ReadRequest,
    devices: Arc<HashMap<u64, String>>,
    cache: super::logical::ReadHandleCache,
) -> (ReadResponse, super::logical::ReadHandleCache) {
    tokio::task::spawn_blocking(move || super::dispatch_request(&request, &devices, cache))
        .await
        .unwrap_or_else(|join_err| {
            (
                ReadResponse::Error {
                    code: ReaderErrorCode::InternalError,
                    message: format!("read task panicked: {join_err}"),
                },
                super::logical::ReadHandleCache::empty(),
            )
        })
}

/// Read one `[u32 LE length][payload]`-framed [`ReadRequest`], or `Ok(None)`
/// on a clean EOF (the Coordinator disconnected between requests).
async fn read_one_request(server: &mut NamedPipeServer) -> anyhow::Result<Option<ReadRequest>> {
    let mut length_bytes = [0_u8; 4];
    match server.read_exact(&mut length_bytes).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let length = u32::from_le_bytes(length_bytes);
    anyhow::ensure!(
        length <= MAX_REQUEST_BYTES,
        "request length {length} exceeds maximum {MAX_REQUEST_BYTES}"
    );
    let mut payload = vec![0_u8; length as usize];
    server.read_exact(&mut payload).await?;
    let mut reader = uffs_content_reader_protocol::codec::Reader::new(&payload);
    let request = ReadRequest::decode(&mut reader)?;
    Ok(Some(request))
}

/// Write one `[u32 LE length][payload]`-framed [`ReadResponse`].
async fn write_one_response(
    server: &mut NamedPipeServer,
    response: &ReadResponse,
) -> anyhow::Result<()> {
    let payload = response.encode();
    let length = u32::try_from(payload.len())
        .map_err(|err| anyhow::anyhow!("response payload too large to frame: {err}"))?;
    server.write_all(&length.to_le_bytes()).await?;
    server.write_all(&payload).await?;
    server.flush().await?;
    Ok(())
}

/// Build a single named-pipe server instance bound to `pipe_name` with
/// the owner-only `sd`. Set `first = true` ONLY for the initial
/// instance (enables `FIRST_PIPE_INSTANCE` squat protection) — mirrors
/// `uffs-daemon`'s own `create_pipe_server` exactly.
fn create_server(
    pipe_name: &uffs_security::pipe::PipeName,
    sd: &uffs_security::pipe::OwnerOnlySd,
    first: bool,
) -> anyhow::Result<NamedPipeServer> {
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

    #[expect(unsafe_code, reason = "Win32 FFI — create named-pipe server")]
    // SAFETY: `sa` is a valid `SECURITY_ATTRIBUTES` borrowing a
    // `SECURITY_DESCRIPTOR` owned by `sd`, which outlives this call.
    let server = unsafe {
        opts.create_with_security_attributes_raw(
            pipe_name.as_str(),
            core::ptr::from_mut(&mut sa).cast(),
        )
    }?;

    Ok(server)
}
