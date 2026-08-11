// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! End-to-end proof of the self-upgrading stdio supervisor: one client
//! connection survives a binary "replacement" (the watch file is
//! touched) with the worker hot-swapped underneath it — the
//! zero-downtime contract, exercised over real processes and pipes.
//!
//! The real worker refuses to serve without a live daemon, so the test
//! points `UFFS_MCP_WORKER_EXE` at a tiny scripted JSON-RPC responder
//! that stamps every reply with its own PID — which is exactly what
//! makes the swap observable: the same session sees two different
//! worker PIDs across the "install".

#![expect(
    clippy::tests_outside_test_module,
    reason = "integration tests are inherently outside cfg(test)"
)]
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "integration test — relaxed linting for test clarity"
)]

// Acknowledge crates used by the lib/bin but not this test target.
use anyhow as _;
#[cfg(feature = "streamable-http")]
use axum as _;
use clap as _;
use rmcp as _;
use schemars as _;
use serde as _;
use thiserror as _;
use tokio as _;
#[cfg(feature = "streamable-http")]
use tower_service as _;
use tracing as _;
use tracing_appender as _;
use tracing_subscriber as _;
use uffs_client as _;
use uffs_mcp as _;
use uffs_mft as _;
use uffs_security as _;
use uffs_version as _;

#[cfg(unix)]
mod unix {
    use std::io::{BufRead, BufReader, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Stdio;

    /// A scripted stand-in for the real worker: answers `initialize`
    /// and `tools/list` with canned results stamped with its own PID,
    /// so a hot swap is visible as a PID change on the same session.
    const FAKE_WORKER: &str = r#"#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      id=`printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'`
      printf '{"jsonrpc":"2.0","id":%s,"result":{"serverInfo":{"name":"fake-worker"},"workerPid":%s}}\n' "$id" "$$"
      ;;
    *'"method":"tools/list"'*)
      id=`printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'`
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[],"workerPid":%s}}\n' "$id" "$$"
      ;;
  esac
done
"#;

    /// A scratch dir holding the fake worker script + the watch file,
    /// removed on drop.
    struct Scratch {
        /// The directory itself.
        dir: std::path::PathBuf,
    }

    impl Scratch {
        /// Creates the scratch dir with the executable fake worker and
        /// an initial watch file inside.
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("uffs-mcp-sup-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            let script = dir.join("fake-worker.sh");
            std::fs::write(&script, FAKE_WORKER).expect("write fake worker");
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
                .expect("chmod +x fake worker");
            std::fs::write(dir.join("watch"), b"original-binary-identity").expect("seed watch");
            Self { dir }
        }

        /// Path of the fake worker script.
        fn worker(&self) -> std::path::PathBuf {
            self.dir.join("fake-worker.sh")
        }

        /// Path of the watch file.
        fn watch(&self) -> std::path::PathBuf {
            self.dir.join("watch")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _cleanup = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Sends one JSON-RPC line and reads lines until the response with
    /// `id` arrives (collecting skipped notifications), returning it
    /// parsed.
    fn call(
        stdin: &mut impl std::io::Write,
        reader: &mut impl BufRead,
        line: &str,
        id: u64,
        skipped: &mut Vec<String>,
    ) -> serde_json::Value {
        stdin.write_all(line.as_bytes()).expect("write request");
        stdin.write_all(b"\n").expect("write newline");
        stdin.flush().expect("flush request");
        let mut buffer = String::new();
        loop {
            buffer.clear();
            let bytes = reader.read_line(&mut buffer).expect("read response line");
            assert!(bytes > 0, "server closed the pipe waiting for id {id}");
            let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&buffer) else {
                continue;
            };
            if parsed.get("id").and_then(serde_json::Value::as_u64) == Some(id) {
                return parsed;
            }
            skipped.push(buffer.clone());
        }
    }

    /// The worker PID a fake-worker response was stamped with.
    fn worker_pid(response: &serde_json::Value) -> u64 {
        response["result"]["workerPid"]
            .as_u64()
            .expect("workerPid stamp")
    }

    /// One session: initialize, call, "replace" the binary (touch the
    /// watch file), wait past the poll interval, call again. The
    /// connection never breaks, both calls succeed, and the second is
    /// served by a DIFFERENT worker process on the same pipes.
    #[test]
    fn one_session_survives_a_binary_swap() {
        let scratch = Scratch::new();
        let mut supervisor = std::process::Command::new(env!("CARGO_BIN_EXE_uffsmcp"))
            .env("UFFS_MCP_WORKER_EXE", scratch.worker())
            .env("UFFS_MCP_WATCH_PATH", scratch.watch())
            .env("UFFS_MCP_POLL_MS", "150")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("supervisor spawns");
        let mut stdin = supervisor.stdin.take().expect("supervisor stdin");
        let mut reader = BufReader::new(supervisor.stdout.take().expect("supervisor stdout"));

        let mut skipped: Vec<String> = Vec::new();
        let initialize = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"swap-test","version":"0"}}}"#;
        let response = call(&mut stdin, &mut reader, initialize, 1, &mut skipped);
        assert!(
            response.get("result").is_some(),
            "initialize succeeds: {response}"
        );
        stdin
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .expect("initialized notification");
        stdin.flush().expect("flush");

        let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        let first = call(&mut stdin, &mut reader, list, 2, &mut skipped);
        let first_pid = worker_pid(&first);

        // "Replace the binary": touch the watch file, then give the
        // ticker time to notice and swap at the quiet moment.
        std::fs::write(scratch.watch(), b"new-binary-identity").expect("touch watch file");
        std::thread::sleep(core::time::Duration::from_millis(700));

        let list_again = r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#;
        let second = call(&mut stdin, &mut reader, list_again, 3, &mut skipped);
        let second_pid = worker_pid(&second);

        assert_ne!(
            first_pid, second_pid,
            "the post-swap call is served by a FRESH worker process"
        );
        assert!(
            skipped
                .iter()
                .any(|line| line.contains("notifications/tools/list_changed")),
            "the swap nudged the client to re-list tools: {skipped:?}"
        );

        drop(stdin);
        let _status = supervisor.wait();
    }
}
