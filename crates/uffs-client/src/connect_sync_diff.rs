// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Snapshot-diff RPC helper for [`crate::connect_sync::UffsClientSync`].
//!
//! Paired with the daemon-side `handle_diff` in
//! `crates/uffs-daemon/src/handler.rs` and the wire types in
//! [`crate::protocol::diff_wire`]. Same typed-envelope dance as the tiering
//! cluster: serialise the params, fire the JSON-RPC, deserialise the result.

use crate::connect_sync::UffsClientSync;
use crate::error::ClientError;
use crate::protocol::{DiffParams, DiffResultWire};

impl UffsClientSync {
    /// Diff a baseline snapshot against the live index for a drive via the
    /// daemon's `diff` RPC (delete-visible companion to `--newer`).
    ///
    /// # Errors
    ///
    /// Returns `ClientError` on I/O / protocol failure, or when the daemon
    /// rejects the request (drive not loaded → `ERR_NOT_READY`; baseline
    /// unreadable → `ERR_INTERNAL`), surfaced as [`ClientError::Protocol`].
    pub fn diff(&mut self, params: &DiffParams) -> Result<DiffResultWire, ClientError> {
        let payload =
            serde_json::to_value(params).map_err(|err| ClientError::Protocol(err.to_string()))?;
        let result = self.send_request("diff", Some(payload))?;
        serde_json::from_value(result).map_err(|err| ClientError::Protocol(err.to_string()))
    }
}
