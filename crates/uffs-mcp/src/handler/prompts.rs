// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Prompt argument helpers and `prompts/get` message builders.

use rmcp::ErrorData as McpError;
use rmcp::model::PromptMessage;
use serde_json::Value;

/// Helper to extract a string argument from the prompt args map.
#[must_use]
pub(crate) fn str_arg<'a>(args: &'a serde_json::Map<String, Value>, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|val| val.as_str())
}

/// Helper to extract a numeric argument from the prompt args map.
#[must_use]
pub(crate) fn u64_arg(args: &serde_json::Map<String, Value>, key: &str, default: u64) -> u64 {
    str_arg(args, key)
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(default)
}

/// Build a single user-role prompt message.
fn user_msg(text: String) -> Vec<PromptMessage> {
    vec![PromptMessage::new_text(rmcp::model::Role::User, text)]
}

/// Build the messages for a given prompt name and arguments.
///
/// # Errors
///
/// Returns `McpError::invalid_params` if the prompt name is unknown.
pub(crate) fn build_prompt_messages(
    name: &str,
    args: &serde_json::Map<String, Value>,
) -> Result<Vec<PromptMessage>, McpError> {
    match name {
        "find_large_files" => {
            let limit = u64_arg(args, "limit", 50);
            Ok(user_msg(format!(
                "Use the uffs_search tool to find the {limit} largest files. \
                 Use pattern '*', sort by 'size' descending, limit {limit}, \
                 filter 'files'. Show results as a table with name, size, and path."
            )))
        }
        "recent_changes" => {
            let days = u64_arg(args, "days", 1);
            Ok(user_msg(format!(
                "Use the uffs_search tool to find files modified in the last \
                 {days} day(s). Use pattern '*', sort by 'modified' descending, \
                 limit 100. Show results as a table."
            )))
        }
        "find_by_extension" => {
            let ext = str_arg(args, "extension").unwrap_or("txt");
            let limit = u64_arg(args, "limit", 100);
            Ok(user_msg(format!(
                "Use the uffs_search tool to find all *.{ext} files. Use pattern \
                 '*.{ext}', sort by 'modified' descending, limit {limit}. \
                 Show results as a table."
            )))
        }
        "find_duplicates_by_name" => {
            let filename = str_arg(args, "filename").unwrap_or("*");
            Ok(user_msg(format!(
                "Use the uffs_search tool to find all files named '{filename}' \
                 across all drives. This helps identify duplicate files. \
                 Show the full path for each result."
            )))
        }
        "disk_usage_report" => {
            let drive = str_arg(args, "drive").unwrap_or("");
            let scope = if drive.is_empty() {
                String::new()
            } else {
                format!(" Scope to drive {drive}: only.")
            };
            Ok(user_msg(format!(
                "Generate a disk usage report.{scope}\n\n\
                 Step 1: Call uffs_aggregate with preset 'overview' to get total \
                 file count and size.\n\
                 Step 2: Call uffs_aggregate with preset 'by_type' to see breakdown \
                 by file type (documents, images, video, audio, archives, etc.).\n\
                 Step 3: Call uffs_aggregate with preset 'by_extension' (top 20) to \
                 see the most common extensions.\n\
                 Step 4: Call uffs_aggregate with preset 'storage' to see size \
                 distribution buckets.\n\n\
                 Present the results as a clear, structured report with totals, \
                 percentages, and top contributors. Highlight anything unusual."
            )))
        }
        "cleanup_report" => {
            let min_size = u64_arg(args, "min_size_mb", 100);
            Ok(user_msg(format!(
                "Generate a cleanup candidates report.\n\n\
                 Step 1: Call uffs_aggregate with preset 'cleanup' to identify \
                 temporary files, caches, and other cleanup candidates.\n\
                 Step 2: Call uffs_search to find the top 50 largest files \
                 over {min_size}MB, sorted by size descending.\n\
                 Step 3: Call uffs_aggregate with preset 'duplicates' to find \
                 potential duplicate files.\n\n\
                 Present the results as an actionable cleanup report. Show total \
                 reclaimable space, list the biggest space hogs, and highlight \
                 duplicate groups. Be clear about which files are safe to review."
            )))
        }
        "duplicate_investigation" => {
            let ext = str_arg(args, "extension").unwrap_or("");
            let scope = if ext.is_empty() {
                String::new()
            } else {
                format!(" Focus on *.{ext} files.")
            };
            Ok(user_msg(format!(
                "Investigate duplicate files.{scope}\n\n\
                 Step 1: Call uffs_aggregate with preset 'duplicates' to find \
                 groups of files with identical names and sizes.\n\
                 Step 2: For the top 5 largest duplicate groups, show all file \
                 paths using uffs_search.\n\
                 Step 3: Summarise total wasted space and recommend which copies \
                 might be safe to remove (e.g. copies in temp/cache directories).\n\n\
                 Present findings as a structured report with duplicate groups, \
                 file paths, sizes, and total reclaimable space."
            )))
        }
        other => Err(McpError::invalid_params(
            format!("Unknown prompt: {other}"),
            None,
        )),
    }
}
