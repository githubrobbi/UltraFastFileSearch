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
