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

/// Fixed overhead every encoded frame carries before its payload: the
/// 48-byte envelope header plus its two `u32` checksums (see
/// `uffs_content_protocol::frame::FrameEnvelope`'s own doc comment).
const FRAME_ENVELOPE_OVERHEAD_BYTES: u32 = 56;

/// `ContentChunk`'s own fixed fields plus its payload's `u32` length
/// prefix, preceding the chunk payload itself: `candidate_id`(8) +
/// `chunk_sequence`(8) + `logical_offset`(8) + `logical_length`(8) +
/// length-prefix(4) = 36.
const CONTENT_CHUNK_FIXED_OVERHEAD_BYTES: u32 = 36;

/// `FileBegin`'s own fixed fields plus a `WindowsPath`'s own encoding
/// byte + `u32` length prefix, preceding the path bytes themselves:
/// `candidate_id`(8) + `file_reference`(8) + path-encoding(1) +
/// path-length-prefix(4) + `logical_size`(8) + `mtime`(8) +
/// `read_mode`(1) + `attempt_number`(4) + `content_object_id`(1 + 8
/// worst case) = 51.
const FILE_BEGIN_FIXED_OVERHEAD_BYTES: u32 = 51;

/// Extra headroom absorbing a small future addition to any frame's fixed
/// fields (e.g. one more optional field) without silently reintroducing
/// the exact ceiling-vs-payload mismatch this constant's derivation
/// exists to prevent.
const FRAME_SIZE_SAFETY_MARGIN_BYTES: u32 = 4096;

/// `a` if greater, else `b` — `u32::max` as a `const fn`, spelled out
/// directly rather than relying on `Ord::max`'s const-stability version
/// (this workspace's pinned toolchain predates it becoming reliably
/// const across all the targets this crate builds for).
const fn max_u32(lhs: u32, rhs: u32) -> u32 {
    if lhs > rhs { lhs } else { rhs }
}

/// Maximum single framed message size accepted on either pipe.
///
/// Must comfortably exceed the largest frame this crate can actually
/// produce, so a spec-compliant consumer reader never rejects a
/// legitimate frame. The two candidates for "largest frame" are a full
/// `CONTENT_CHUNK` (`crate::job::workflow::DEFAULT_MAX_CHUNK_BYTES`
/// payload bytes) and a `FILE_BEGIN` carrying a maximum-length path
/// (`uffs_content_protocol::manifest::MAX_PATH_BYTES`) — this ceiling is
/// derived from both plus a safety margin specifically so the three
/// constants can never silently drift out of sync again. A prior version
/// of this constant was a bare `64 * 1024`, smaller than either worst
/// case by construction — any file whose content reached the (also
/// `64 * 1024`) default max chunk size, or any path near the protocol's
/// own 32,767-UTF-16-code-unit maximum, would have produced a frame a
/// consumer built to this same ceiling would reject outright.
pub(super) const MAX_MESSAGE_BYTES: u32 = max_u32(
    FRAME_ENVELOPE_OVERHEAD_BYTES
        + CONTENT_CHUNK_FIXED_OVERHEAD_BYTES
        + crate::job::workflow::DEFAULT_MAX_CHUNK_BYTES,
    FRAME_ENVELOPE_OVERHEAD_BYTES
        + FILE_BEGIN_FIXED_OVERHEAD_BYTES
        + uffs_content_protocol::manifest::MAX_PATH_BYTES,
) + FRAME_SIZE_SAFETY_MARGIN_BYTES;

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

#[cfg(test)]
mod tests {
    use uffs_content_protocol::frame::{
        ContentChunk, FileBegin, FrameEnvelope, FrameType, PROTOCOL_VERSION, ReadMode,
    };
    use uffs_content_protocol::manifest::MAX_PATH_BYTES;
    use uffs_content_protocol::path_encoding::WindowsPath;

    use super::MAX_MESSAGE_BYTES;
    use crate::job::workflow::DEFAULT_MAX_CHUNK_BYTES;

    fn encoded_len(frame_type: FrameType, payload: &[u8]) -> u32 {
        let bytes = FrameEnvelope {
            protocol_version: PROTOCOL_VERSION,
            frame_type,
            flags: 0,
            job_id: [0; 16],
            frame_sequence: 0,
        }
        .encode(payload);
        u32::try_from(bytes.len()).unwrap_or(u32::MAX)
    }

    /// Locks the exact bug this constant's derivation replaced: a full
    /// `CONTENT_CHUNK` at the current max chunk size must always fit
    /// under the pipe's own message ceiling.
    #[test]
    fn max_message_bytes_fits_a_full_content_chunk() {
        let payload = vec![0_u8; DEFAULT_MAX_CHUNK_BYTES as usize];
        let chunk = ContentChunk {
            candidate_id: u64::MAX,
            chunk_sequence: u64::MAX,
            logical_offset: u64::MAX,
            logical_length: u64::from(DEFAULT_MAX_CHUNK_BYTES),
            payload,
        };
        let encoded = encoded_len(FrameType::ContentChunk, &chunk.encode());
        assert!(
            encoded <= MAX_MESSAGE_BYTES,
            "a full CONTENT_CHUNK frame ({encoded} bytes) must fit under \
             MAX_MESSAGE_BYTES ({MAX_MESSAGE_BYTES} bytes)"
        );
    }

    /// Same, for a `FILE_BEGIN` carrying the protocol's own maximum path
    /// length — the other worst-case frame this ceiling must cover.
    #[test]
    fn max_message_bytes_fits_a_file_begin_with_a_maximum_length_path() {
        let max_code_units = (MAX_PATH_BYTES / 2) as usize;
        let path = WindowsPath::from_code_units(vec![u16::from(b'x'); max_code_units]);
        let file_begin = FileBegin {
            candidate_id: u64::MAX,
            file_reference: u64::MAX,
            path,
            logical_size: u64::MAX,
            mtime: i64::MAX,
            read_mode: ReadMode::LogicalSnapshot,
            attempt_number: u32::MAX,
            content_object_id: Some(u64::MAX),
        };
        let encoded = encoded_len(FrameType::FileBegin, &file_begin.encode());
        assert!(
            encoded <= MAX_MESSAGE_BYTES,
            "a maximum-length-path FILE_BEGIN frame ({encoded} bytes) must fit under \
             MAX_MESSAGE_BYTES ({MAX_MESSAGE_BYTES} bytes)"
        );
    }
}
