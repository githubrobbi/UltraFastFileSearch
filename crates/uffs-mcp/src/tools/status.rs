// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `uffs_status` tool — daemon health and loading progress.

use rmcp::model::{CallToolResult, ContentBlock};
use uffs_client::connect::UffsClient;

use crate::error::BridgeError;
use crate::schemas::StatusOutput;

/// Execute the status tool (no arguments).
///
/// # Errors
///
/// Returns [`BridgeError`] if the daemon call fails.
pub(crate) async fn run(client: &mut UffsClient) -> Result<CallToolResult, BridgeError> {
    let response = client
        .status()
        .await
        .map_err(|err| BridgeError::Daemon(format!("Failed to get status: {err}")))?;

    let status_str = serde_json::to_string_pretty(&response.status)?;

    // The running `uffsmcp` build version — a read-only freshness signal the
    // agent can surface (UFFS self-updates via `uffs --update`).
    let server_version = env!("CARGO_PKG_VERSION");

    let text = format!(
        "Daemon Status: {status_str}\nUptime: {}s\nConnections: {}\nPID: {}\nUFFS server version: {server_version}\n",
        response.uptime_secs, response.connections, response.pid
    );

    let structured = StatusOutput {
        status: serde_json::to_value(&response.status)?,
        uptime_secs: response.uptime_secs,
        connections: response.connections,
        pid: response.pid,
        server_version: server_version.to_owned(),
    };

    let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
    result.structured_content = Some(serde_json::to_value(structured)?);
    Ok(result)
}
