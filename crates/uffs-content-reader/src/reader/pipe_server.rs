// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Named-pipe server for [`READER_PIPE_NAME`].
//!
//! Accepts exactly one client connection (the Coordinator that spawned
//! this process) and serves framed `ReadRequest`/`ReadResponse`
//! messages on it until the Coordinator disconnects, then this process
//! exits — mirrors the one-Reader-per-job lifecycle
//! `uffs-ingest-implementation-plan.md` describes.

use std::collections::HashMap;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use uffs_content_reader_protocol::{READER_PIPE_NAME, ReadRequest, ReadResponse};

/// Matches the Coordinator-side `MAX_REQUEST_BYTES`-style bound used
/// for the Broker's Snapshot Manager pipe — a generous ceiling for this
/// small, narrow API.
const MAX_REQUEST_BYTES: u32 = 64 * 1024;

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

/// Bind, accept one connection, and serve requests on it until the
/// Coordinator disconnects — the async body of [`run`].
async fn serve(devices: &HashMap<u64, String>) -> anyhow::Result<()> {
    let pipe_name = uffs_security::pipe::PipeName::parse(READER_PIPE_NAME)
        .map_err(|err| anyhow::anyhow!("invalid READER_PIPE_NAME: {err}"))?;
    let sd = uffs_security::pipe::OwnerOnlySd::for_current_user()
        .map_err(|err| anyhow::anyhow!("owner-only DACL build failed: {err}"))?;

    let mut server = create_server(&pipe_name, &sd, /* first= */ true)?;
    tracing::info!(pipe = READER_PIPE_NAME, "Reader pipe listening");
    server.connect().await?;
    tracing::info!("Coordinator connected");

    serve_requests(&mut server, devices).await
}

/// Drain requests off `server` until the Coordinator disconnects (or
/// sends a malformed request, which also ends the connection — see
/// [`read_one_request`]). Extracted from [`serve`] to keep it under
/// clippy's cognitive-complexity budget.
async fn serve_requests(
    server: &mut NamedPipeServer,
    devices: &HashMap<u64, String>,
) -> anyhow::Result<()> {
    loop {
        match read_one_request(server).await {
            Ok(Some(request)) => {
                let response = super::dispatch_request(&request, devices);
                write_one_response(server, &response).await?;
            }
            Ok(None) => {
                tracing::info!("Coordinator disconnected — exiting");
                return Ok(());
            }
            Err(err) => {
                tracing::warn!(error = %err, "malformed request; closing connection");
                return Ok(());
            }
        }
    }
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
