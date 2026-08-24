// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `uffs_info` tool — file/directory detail lookup by path.

use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::Deserialize;
use uffs_client::connect::UffsClient;

use crate::error::BridgeError;

/// Input parameters for the `uffs_info` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct InfoArgs {
    /// Full file or directory path to look up.
    pub path: String,
}

/// Execute the info tool.
///
/// # Errors
///
/// Returns [`BridgeError`] if the daemon call fails or path is missing.
pub(crate) async fn run(
    client: &mut UffsClient,
    args: InfoArgs,
) -> Result<CallToolResult, BridgeError> {
    if args.path.is_empty() {
        return Err(BridgeError::MissingParam("path"));
    }

    // Cold-index contract, scoped to the path's own drive: an info
    // lookup on a parked drive must not block for the re-warm either.
    // Minimal match-all params: an info lookup has no ext filter, so
    // the daemon's plan is "promote every Parked/Cold drive in scope"
    // — the body genuinely is needed to resolve the path.
    let scope: Vec<uffs_mft::platform::DriveLetter> = args
        .path
        .chars()
        .next()
        .and_then(|ch| uffs_mft::platform::DriveLetter::parse(ch).ok())
        .into_iter()
        .collect();
    let scope_params = uffs_client::protocol::SearchParams {
        pattern: "*".to_owned(),
        drives: scope,
        ..Default::default()
    };
    super::warm::warm_gate(client, &scope_params).await?;

    let response = client
        .info(&args.path)
        .await
        .map_err(|err| BridgeError::Daemon(format!("Failed to get info: {err}")))?;

    let structured = crate::schemas::InfoOutput {
        found: response.found,
        record: response.record.clone(),
    };

    let text = if response.found {
        match response.record {
            Some(record) => serde_json::to_string_pretty(&record)?,
            None => format!("File found but no details available: {}", args.path),
        }
    } else {
        format!("File not found: {}", args.path)
    };

    let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
    result.structured_content = Some(serde_json::to_value(structured)?);
    Ok(result)
}
