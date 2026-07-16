// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! The private Broker↔helper control protocol: one JSON object per line
//! over the pipe [`super::pipe::connect`] returns. This is a narrow,
//! internal-only protocol (never shared with any other process or
//! language), so a JSON-lines encoding is simpler and safer than
//! hand-rolled binary framing for this crate's tiny message set.

use std::io::BufRead;

use serde::{Deserialize, Serialize};

/// Helper → Broker messages.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub(crate) enum HelperEvent {
    /// The snapshot was created; the Broker may now hand out a read
    /// lease against `snapshot_device_object`.
    Ready {
        /// The snapshot set's GUID, canonical `{...}` string form.
        snapshot_set_id: String,
        /// This specific snapshot's GUID, canonical `{...}` string form.
        snapshot_id: String,
        /// The VSS provider's GUID, canonical `{...}` string form.
        provider_id: String,
        /// The original volume's name, if the shim reported one.
        original_volume_name: Option<String>,
        /// The snapshot's device path, if the shim reported one.
        snapshot_device_object: Option<String>,
        /// Snapshot creation time, Unix milliseconds.
        created_at_unix_ms: i64,
    },
    /// The snapshot set was explicitly deleted in response to
    /// [`BrokerCommand::Release`].
    Released,
    /// A VSS requestor operation failed — either the initial creation,
    /// or an explicit [`BrokerCommand::Release`]'s deletion.
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

/// Broker → Helper messages.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum BrokerCommand {
    /// Delete the snapshot set and exit.
    Release,
    /// Exit without explicit deletion (relies on
    /// `VSS_CTX_FILE_SHARE_BACKUP`'s auto-release on session drop).
    Cancel,
    /// Liveness check; expects a [`HelperEvent::Pong`] reply.
    Ping,
}

/// Write one [`HelperEvent`] as a single JSON line, flushing
/// immediately.
pub(crate) fn write_event(
    writer: &mut impl std::io::Write,
    event: &HelperEvent,
) -> std::io::Result<()> {
    let line = serde_json::to_string(event)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    crate::run::debug_log(&format!("write_event: about to writeln! {line:?}"));
    writeln!(writer, "{line}")?;
    crate::run::debug_log("write_event: writeln! returned; about to flush");
    let flush_result = writer.flush();
    crate::run::debug_log("write_event: flush returned");
    flush_result
}

/// Read one [`BrokerCommand`] line, or `Ok(None)` at EOF — the pipe
/// closing is treated as an implicit [`BrokerCommand::Cancel`] by the
/// caller, not an error.
pub(crate) fn read_command(reader: &mut impl BufRead) -> std::io::Result<Option<BrokerCommand>> {
    let mut line = String::new();
    let bytes_read = reader.read_line(&mut line)?;
    if bytes_read == 0 {
        return Ok(None);
    }
    let command = serde_json::from_str(line.trim_end())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    Ok(Some(command))
}
