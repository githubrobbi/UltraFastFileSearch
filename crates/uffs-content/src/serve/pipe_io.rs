// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Shared named-pipe helpers: pipe-instance creation (owner-only DACL)
//! and `[u32 LE length][payload]`-framed read/write.
//!
//! Reused by both the command pipe and each job's data-pipe connection
//! — mirrors `uffs-content-reader`'s own `pipe_server.rs` helpers (and,
//! further back, `uffs-daemon`'s named-pipe server), just parameterized
//! over the pipe name instead of hardcoding one.

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};

/// Maximum single framed message size accepted on either pipe — a
/// generous ceiling matching this codebase's other narrow private IPC
/// APIs (the Broker's Snapshot Manager pipe, the content Reader's pipe).
pub(super) const MAX_MESSAGE_BYTES: u32 = 64 * 1024;

/// How long to back off before retrying pipe-instance creation after a
/// transient failure.
const PIPE_RETRY_BACKOFF: core::time::Duration = core::time::Duration::from_millis(100);

/// Build a single named-pipe server instance bound to `pipe_name` with
/// an owner-only DACL. Set `first = true` ONLY for the initial instance
/// (enables `FIRST_PIPE_INSTANCE` squat protection).
pub(super) fn create_server(pipe_name: &str, first: bool) -> anyhow::Result<NamedPipeServer> {
    let parsed = uffs_security::pipe::PipeName::parse(pipe_name)
        .map_err(|err| anyhow::anyhow!("invalid pipe name {pipe_name:?}: {err}"))?;
    let sd = uffs_security::pipe::OwnerOnlySd::for_current_user()
        .map_err(|err| anyhow::anyhow!("owner-only DACL build failed: {err}"))?;
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

    // SAFETY: `sa` is a valid `SECURITY_ATTRIBUTES` borrowing a
    // `SECURITY_DESCRIPTOR` owned by `sd`, which outlives this call.
    #[expect(unsafe_code, reason = "Win32 FFI — create named-pipe server")]
    let server = unsafe {
        opts.create_with_security_attributes_raw(
            parsed.as_str(),
            core::ptr::from_mut(&mut sa).cast(),
        )
    }?;
    Ok(server)
}

/// Read one `[u32 LE length][payload]`-framed message, or `Ok(None)` on
/// a clean EOF (the peer disconnected between messages).
pub(super) async fn read_one_message(
    pipe: &mut NamedPipeServer,
) -> anyhow::Result<Option<Vec<u8>>> {
    let mut length_bytes = [0_u8; 4];
    match pipe.read_exact(&mut length_bytes).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let length = u32::from_le_bytes(length_bytes);
    anyhow::ensure!(
        length <= MAX_MESSAGE_BYTES,
        "message length {length} exceeds maximum {MAX_MESSAGE_BYTES}"
    );
    let mut payload = vec![0_u8; length as usize];
    pipe.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

/// Write one `[u32 LE length][payload]`-framed message.
pub(super) async fn write_one_message(
    pipe: &mut NamedPipeServer,
    payload: &[u8],
) -> anyhow::Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|err| anyhow::anyhow!("payload too large to frame: {err}"))?;
    pipe.write_all(&length.to_le_bytes()).await?;
    pipe.write_all(payload).await?;
    pipe.flush().await?;
    Ok(())
}

/// Repeatedly create a pipe instance and wait for a client to connect,
/// backing off on transient creation failures. Shared by the
/// server-lifetime command pipe and each job's data pipe — both need the
/// exact same "create, back off on failure, wait for connect" sequence,
/// only the pipe name differs.
pub(super) async fn accept_connection(
    pipe_name: &str,
    first_instance: &mut bool,
) -> NamedPipeServer {
    loop {
        let pipe = match create_server(pipe_name, *first_instance) {
            Ok(pipe) => pipe,
            Err(err) => {
                tracing::warn!(error = %err, pipe_name, "pipe instance unavailable; retrying shortly");
                tokio::time::sleep(PIPE_RETRY_BACKOFF).await;
                continue;
            }
        };
        *first_instance = false;
        if pipe.connect().await.is_ok() {
            return pipe;
        }
    }
}

/// Render a `job_id` as a short hex string for logging.
pub(super) fn hex_job_id(job_id: [u8; 16]) -> String {
    use core::fmt::Write as _;
    job_id
        .iter()
        .fold(String::with_capacity(32), |mut out, byte| {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "String::write_fmt never fails"
            )]
            let _ = write!(out, "{byte:02x}");
            out
        })
}
