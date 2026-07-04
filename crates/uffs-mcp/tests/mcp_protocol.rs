// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! MCP protocol tests (D4.3).
//!
//! Uses `tokio::io::duplex` to create in-process transport pairs,
//! connects an rmcp client to our `UffsMcpServer` handler, and verifies
//! tools/list, resources/list, and prompts/list responses.

#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are inherently outside cfg(test)"
)]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::min_ident_chars,
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::panic,
    reason = "integration test — relaxed linting for test clarity"
)]

// Acknowledge crates used by the lib/bin but not this test target.
// Linked via the crate's `[dependencies]` (its binaries call
// `uffs_version::handle_version!`); this target does not reference it.
use anyhow as _;
#[cfg(feature = "streamable-http")]
use axum as _;
use clap as _;
use rmcp::{ClientHandler, ServiceExt as _};
use schemars as _;
use serde as _;
use thiserror as _;
#[cfg(feature = "streamable-http")]
use tower_service as _;
use tracing as _;
use tracing_appender as _;
use tracing_subscriber as _;
use uffs_client as _;
use uffs_mcp::handler::UffsMcpServer;
use uffs_mft as _;
use uffs_security as _;
use uffs_version as _;

/// Spin up an in-process MCP server + client pair over a duplex channel.
///
/// Returns the client peer which can call `list_tools`, `list_resources`,
/// `list_prompts`, `get_prompt`, etc.
async fn setup_client() -> rmcp::service::RunningService<rmcp::RoleClient, impl ClientHandler> {
    let (server_io, client_io) = tokio::io::duplex(8192);

    // Server side — spawn in background and keep alive until client disconnects.
    let server = UffsMcpServer::new_unconnected();
    tokio::spawn(async move {
        let server_handle = server.serve(server_io).await.unwrap();
        // Keep the server alive until the transport closes.
        let _ = server_handle.waiting().await;
    });

    // Client side — connect.
    ().serve(client_io).await.unwrap()
}

// ── tools/list ──────────────────────────────────────────────────────

#[tokio::test]
async fn mcp_tools_list() {
    let client = setup_client().await;
    let tools = client.list_tools(None).await.unwrap();

    assert_eq!(tools.tools.len(), 6, "expected 6 tools");

    let names: Vec<_> = tools.tools.iter().map(|t| t.name.as_ref()).collect();
    assert!(names.contains(&"uffs_search"));
    assert!(names.contains(&"uffs_info"));
    assert!(names.contains(&"uffs_drives"));
    assert!(names.contains(&"uffs_status"));
    assert!(names.contains(&"uffs_aggregate"));
    assert!(names.contains(&"uffs_facet_values"));

    client.cancel().await.unwrap();
}

// ── resources/list ──────────────────────────────────────────────────

#[tokio::test]
async fn mcp_resources_list() {
    let client = setup_client().await;
    let resources = client.list_resources(None).await.unwrap();

    assert_eq!(resources.resources.len(), 7, "expected 7 resources");

    let uris: Vec<_> = resources.resources.iter().map(|r| r.uri.as_str()).collect();
    // Live metadata resources
    assert!(uris.contains(&"uffs://drives"));
    assert!(uris.contains(&"uffs://status"));
    // Static schema resources
    assert!(uris.contains(&"uffs://schema/fields"));
    assert!(uris.contains(&"uffs://schema/search"));
    assert!(uris.contains(&"uffs://schema/aggregate"));
    assert!(uris.contains(&"uffs://presets/aggregate"));
    // Agent cookbook
    assert!(uris.contains(&"uffs://cookbook"));

    client.cancel().await.unwrap();
}

// ── resources/read (static schemas) ──────────────────────────────────

/// Extract text content from a `ResourceContents` enum variant.
fn extract_text(rc: &rmcp::model::ResourceContents) -> &str {
    match rc {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text.as_str(),
        rmcp::model::ResourceContents::BlobResourceContents { .. } | _ => {
            panic!("expected TextResourceContents")
        }
    }
}

#[tokio::test]
async fn mcp_read_schema_fields() {
    let client = setup_client().await;
    let result = client
        .read_resource(rmcp::model::ReadResourceRequestParams::new(
            "uffs://schema/fields",
        ))
        .await
        .unwrap();

    let text = extract_text(result.contents.first().unwrap());
    let json: serde_json::Value = serde_json::from_str(text).unwrap();
    let arr = json.as_array().unwrap();
    // At least 30 fields in the catalog
    assert!(arr.len() >= 30, "expected ≥30 fields, got {}", arr.len());
    // Check first entry has expected structure
    let first = &arr[0];
    assert!(first.get("name").is_some());
    assert!(first.get("field_type").is_some());
    assert!(first.get("sortable").is_some());

    client.cancel().await.unwrap();
}

#[tokio::test]
async fn mcp_read_schema_search() {
    let client = setup_client().await;
    let result = client
        .read_resource(rmcp::model::ReadResourceRequestParams::new(
            "uffs://schema/search",
        ))
        .await
        .unwrap();

    let text = extract_text(result.contents.first().unwrap());
    let json: serde_json::Value = serde_json::from_str(text).unwrap();
    // Should be a JSON Schema with "properties"
    assert!(
        json.get("properties").is_some() || json.get("$defs").is_some(),
        "search schema should have properties or $defs"
    );

    client.cancel().await.unwrap();
}

#[tokio::test]
async fn mcp_read_aggregate_presets() {
    let client = setup_client().await;
    let result = client
        .read_resource(rmcp::model::ReadResourceRequestParams::new(
            "uffs://presets/aggregate",
        ))
        .await
        .unwrap();

    let text = extract_text(result.contents.first().unwrap());
    let json: serde_json::Value = serde_json::from_str(text).unwrap();
    let arr = json.as_array().unwrap();
    assert!(arr.len() >= 10, "expected ≥10 presets, got {}", arr.len());
    let names: Vec<&str> = arr.iter().filter_map(|p| p["name"].as_str()).collect();
    assert!(names.contains(&"overview"));
    assert!(names.contains(&"by_extension"));
    assert!(names.contains(&"duplicates"));

    client.cancel().await.unwrap();
}

// ── resources/templates ──────────────────────────────────────────────

#[tokio::test]
async fn mcp_resource_templates_list() {
    let client = setup_client().await;
    let templates = client.list_resource_templates(None).await.unwrap();

    assert!(
        !templates.resource_templates.is_empty(),
        "expected at least 1 resource template"
    );

    let uris: Vec<&str> = templates
        .resource_templates
        .iter()
        .map(|t| t.uri_template.as_str())
        .collect();
    assert!(
        uris.contains(&"uffs://info/{path}"),
        "expected uffs://info/{{path}} template, got: {uris:?}"
    );

    client.cancel().await.unwrap();
}

// ── prompts/list ────────────────────────────────────────────────────

#[tokio::test]
async fn mcp_prompts_list() {
    let client = setup_client().await;
    let prompts = client.list_prompts(None).await.unwrap();

    assert_eq!(prompts.prompts.len(), 7, "expected 7 prompts");

    let names: Vec<_> = prompts.prompts.iter().map(|p| p.name.as_ref()).collect();
    assert!(names.contains(&"find_large_files"));
    assert!(names.contains(&"recent_changes"));
    assert!(names.contains(&"find_by_extension"));
    assert!(names.contains(&"find_duplicates_by_name"));
    assert!(names.contains(&"disk_usage_report"));
    assert!(names.contains(&"cleanup_report"));
    assert!(names.contains(&"duplicate_investigation"));

    client.cancel().await.unwrap();
}

// ── get_prompt ──────────────────────────────────────────────────────

#[tokio::test]
async fn mcp_get_prompt_find_large_files() {
    let client = setup_client().await;

    let result = client
        .get_prompt(
            rmcp::model::GetPromptRequestParams::new("find_large_files").with_arguments(
                serde_json::Map::from_iter([("limit".to_owned(), serde_json::json!("10"))]),
            ),
        )
        .await
        .unwrap();

    assert_eq!(result.messages.len(), 1);
    let msg_text = format!("{:?}", result.messages[0]);
    assert!(msg_text.contains("10"), "limit 10: {msg_text}");

    client.cancel().await.unwrap();
}

#[tokio::test]
async fn mcp_get_prompt_unknown_returns_error() {
    let client = setup_client().await;

    let result = client
        .get_prompt(rmcp::model::GetPromptRequestParams::new("does_not_exist"))
        .await;

    assert!(result.is_err(), "unknown prompt should error");

    client.cancel().await.unwrap();
}

// ── call_tool with unknown name ─────────────────────────────────────

#[tokio::test]
async fn mcp_call_unknown_tool_returns_error() {
    let client = setup_client().await;

    let result = client
        .call_tool(rmcp::model::CallToolRequestParams::new("uffs.nonexistent"))
        .await;

    assert!(result.is_err(), "unknown tool should error");

    client.cancel().await.unwrap();
}

/// D4.3.2: Claude Desktop MCP configuration example.
///
/// Add this to `~/Library/Application
/// Support/Claude/claude_desktop_config.json`:
/// ```json
/// {
///   "mcpServers": {
///     "uffs": {
///       "command": "uffs-mcp"
///     }
///   }
/// }
/// ```
///
/// Or with an explicit path:
/// ```json
/// {
///   "mcpServers": {
///     "uffs": {
///       "command": "/path/to/uffs-mcp"
///     }
///   }
/// }
/// ```
#[test]
fn claude_desktop_config_example() {
    // This is a documentation test — verifies the config JSON is valid
    let config = r#"{
        "mcpServers": {
            "uffs": {
                "command": "uffs-mcp"
            }
        }
    }"#;
    let parsed: serde_json::Value = serde_json::from_str(config).expect("valid JSON");
    let command = parsed
        .get("mcpServers")
        .and_then(|servers| servers.get("uffs"))
        .and_then(|uffs| uffs.get("command"));
    assert!(command.is_some_and(serde_json::Value::is_string));
}

/// D4.3.3: Cursor / Windsurf MCP configuration example.
///
/// Add to `.cursor/mcp.json` or Windsurf MCP settings:
/// ```json
/// {
///   "uffs": {
///     "command": "uffs-mcp"
///   }
/// }
/// ```
#[test]
fn cursor_windsurf_config_example() {
    let config = r#"{
        "uffs": {
            "command": "uffs-mcp"
        }
    }"#;
    let parsed: serde_json::Value = serde_json::from_str(config).expect("valid JSON");
    let command = parsed.get("uffs").and_then(|uffs| uffs.get("command"));
    assert!(command.is_some_and(serde_json::Value::is_string));
}
