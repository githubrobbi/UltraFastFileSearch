// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Integration tests for the daemon IPC layer.
//!
//! Runs a SINGLE daemon process and tests all JSON-RPC methods through
//! one connection. This avoids socket conflicts from parallel tests.
//!
//! Unix-only: uses `UnixStream` + `libc` to talk to the daemon over a
//! Unix-domain socket.  The Windows daemon transport (named pipes) is
//! covered by a separate integration test.
#![cfg(test)]

// ─────────────────────────────────────────────────────────────────────
// Crate-dependency acknowledgements — unconditional.
//
// `uffs-daemon`'s dev + lib deps are linked into this integration-test
// binary on every platform, but every test body below is gated by
// `#[cfg(unix)]` (the transport is a Unix domain socket).  Putting the
// `use X as _;` suppressions at crate root keeps `unused-crate-
// dependencies` quiet on Windows, where the inner `unix_tests` module
// is compiled out entirely.
// ─────────────────────────────────────────────────────────────────────
// Linked via the crate's `[dependencies]` (its binaries call
// `uffs_version::handle_version!`); this target does not reference it.
use anyhow as _;
use clap as _;
use dirs_next as _;
use futures as _;
#[cfg(unix)]
use libc as _;
use libmimalloc_sys as _;
use mimalloc as _;
use proptest as _;
use rand as _;
use serde as _;
use serde_json as _;
use tempfile as _;
use thiserror as _;
use tokio as _;
use toml as _;
use tracing as _;
use tracing_appender as _;
use tracing_subscriber as _;
// F5 / issue #205 — `uffs_broker_protocol` is in
// `[target.'cfg(windows)'.dependencies]` of `uffs-daemon`, consumed by
// `broker_client.rs` on Windows.  This Unix-focused integration test
// never touches it, so on Windows the extern crate is in scope but
// unused.  Marker gated to `cfg(windows)` because on non-Windows the
// dep doesn't exist as an extern crate.
#[cfg(windows)]
use uffs_broker_protocol as _;
use uffs_client as _;
use uffs_core as _;
use uffs_daemon as _;
use uffs_format as _;
use uffs_mft as _;
use uffs_security as _;
use uffs_version as _;
#[cfg(windows)]
use windows as _;

/// All actual test code is Unix-only because the transport is a Unix
/// domain socket.  Tests are discovered by `cargo test` through this
/// inner module just as they would be at crate root.
#[cfg(unix)]
mod unix_tests {
    use core::time::Duration;
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::process::Command;

    /// Find the daemon binary (`uffsd`).
    fn daemon_exe() -> PathBuf {
        let current = std::env::current_exe().expect("current_exe");

        // Try: pop binary name, pop deps/, look for uffsd
        let mut candidate = current.clone();
        candidate.pop(); // remove test binary
        candidate.pop(); // remove deps/
        candidate.push("uffsd");
        if candidate.exists() {
            return candidate;
        }

        // Try without deps/ (in case test isn't in deps/)
        let mut alt = current;
        alt.pop();
        alt.push("uffsd");
        if alt.exists() {
            return alt;
        }

        // Fallback: assume it's in PATH
        PathBuf::from("uffsd")
    }

    /// Get the platform socket path.
    fn socket_path() -> PathBuf {
        let base = dirs_next::data_local_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        #[cfg(target_os = "macos")]
        {
            base.join("uffs").join("daemon.sock")
        }
        #[cfg(not(target_os = "macos"))]
        {
            base.join("uffs").join("daemon.sock")
        }
    }

    /// PID file path.
    fn pid_path() -> PathBuf {
        let base = dirs_next::data_local_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        base.join("uffs").join("daemon.pid")
    }

    /// Send a request and read one response line.
    fn rpc(ws: &mut UnixStream, reader: &mut BufReader<UnixStream>, req: &str) -> String {
        ws.write_all(req.as_bytes()).expect("write");
        ws.write_all(b"\n").expect("newline");
        ws.flush().expect("flush");
        let mut line = String::new();
        reader.read_line(&mut line).expect("read");
        line
    }

    /// Start a daemon, wait for socket, return the child process.
    ///
    /// Returns `None` if the daemon binary is missing or the socket doesn't
    /// appear.
    fn start_daemon(exe: &std::path::Path, extra_args: &[&str]) -> Option<std::process::Child> {
        if !exe.exists() {
            return None;
        }
        drop(std::fs::remove_file(socket_path()));
        drop(std::fs::remove_file(pid_path()));

        let mut args = vec!["--idle-timeout", "30", "--log-level", "warn"];
        args.extend_from_slice(extra_args);

        let mut daemon = Command::new(exe)
            .args(&args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn daemon");

        let sock = socket_path();
        for _tick in 0_i32..40_i32 {
            std::thread::sleep(Duration::from_millis(100));
            if sock.exists() {
                return Some(daemon);
            }
        }
        drop(daemon.kill());
        drop(daemon.wait());
        None
    }

    /// Gracefully shut down a daemon using nonce-based shutdown, or kill it.
    fn shutdown_daemon(
        daemon: &mut std::process::Child,
        ws: &mut UnixStream,
        reader: &mut BufReader<UnixStream>,
    ) {
        let nonce = std::fs::read_to_string(pid_path())
            .ok()
            .and_then(|pid_content| {
                pid_content
                    .lines()
                    .nth(3)
                    .map(|line| line.trim().to_owned())
            })
            .unwrap_or_default();
        if nonce.is_empty() {
            drop(daemon.kill());
        } else {
            let _shutdown_resp = rpc(
                ws,
                reader,
                &format!(
                    r#"{{"jsonrpc":"2.0","id":9999,"method":"shutdown","params":{{"nonce":"{nonce}"}}}}"#
                ),
            );
        }
        drop(daemon.wait());
    }

    /// D2/D3 integration tests — all run against one daemon instance.
    #[test]
    #[ignore = "requires pre-built daemon binary — run with --ignored"]
    fn daemon_ipc_all_methods() {
        let exe = daemon_exe();
        let Some(mut daemon) = start_daemon(&exe, &[]) else {
            return;
        };

        let stream = UnixStream::connect(socket_path()).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut ws = stream.try_clone().expect("clone");
        let mut reader = BufReader::new(stream);

        // Test 1: status
        let status_resp = rpc(
            &mut ws,
            &mut reader,
            r#"{"jsonrpc":"2.0","id":1,"method":"status"}"#,
        );
        assert!(
            status_resp.contains("\"pid\""),
            "status should have pid: {status_resp}"
        );
        assert!(
            status_resp.contains("\"uptime_secs\""),
            "status should have uptime: {status_resp}"
        );

        // Test 2: drives (empty)
        let drives_resp = rpc(
            &mut ws,
            &mut reader,
            r#"{"jsonrpc":"2.0","id":2,"method":"drives"}"#,
        );
        assert!(
            drives_resp.contains("\"drives\":[]"),
            "drives should be empty: {drives_resp}"
        );

        // Test 3: search (no data)
        let search_resp = rpc(
            &mut ws,
            &mut reader,
            r#"{"jsonrpc":"2.0","id":3,"method":"search","params":{"pattern":"*.rs"}}"#,
        );
        assert!(
            search_resp.contains("\"rows\":[]"),
            "search should be empty: {search_resp}"
        );
        assert!(
            search_resp.contains("\"records_scanned\":0"),
            "should scan 0: {search_resp}"
        );

        // Test 4: unknown method → -32601
        let unknown_resp = rpc(
            &mut ws,
            &mut reader,
            r#"{"jsonrpc":"2.0","id":4,"method":"nonexistent"}"#,
        );
        assert!(
            unknown_resp.contains("-32601"),
            "should be method not found: {unknown_resp}"
        );

        // Test 5: keepalive
        let keepalive_resp = rpc(
            &mut ws,
            &mut reader,
            r#"{"jsonrpc":"2.0","id":5,"method":"keepalive"}"#,
        );
        assert!(
            keepalive_resp.contains("\"ok\":true"),
            "keepalive should return ok: {keepalive_resp}"
        );

        // Test 6: invalid JSON → -32700
        let parse_err_resp = rpc(&mut ws, &mut reader, "this is not json");
        assert!(
            parse_err_resp.contains("-32700"),
            "should be parse error: {parse_err_resp}"
        );

        // Test 7: shutdown without nonce → rejected
        let nonce_err_resp = rpc(
            &mut ws,
            &mut reader,
            r#"{"jsonrpc":"2.0","id":7,"method":"shutdown","params":{}}"#,
        );
        assert!(
            nonce_err_resp.contains("nonce"),
            "should mention nonce: {nonce_err_resp}"
        );

        // Test 8: shutdown with correct nonce → accepted
        shutdown_daemon(&mut daemon, &mut ws, &mut reader);
    }

    /// Real-data integration test: loads `G_mft.bin` fixture, verifies actual
    /// search.
    #[test]
    #[ignore = "requires pre-built daemon binary — run with --ignored"]
    fn real_data_search() {
        let exe = daemon_exe();
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/drive_g/G_mft.bin");
        if !fixture.exists() {
            return;
        }

        let fixture_str = fixture.to_str().unwrap();
        let Some(mut daemon) = start_daemon(&exe, &["--mft-file", fixture_str, "--no-cache"])
        else {
            return;
        };

        let stream = UnixStream::connect(socket_path()).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut ws = stream.try_clone().expect("clone");
        let mut reader = BufReader::new(stream);

        // Poll until daemon finishes loading
        let mut loaded = false;
        for _poll in 0_i32..60_i32 {
            let resp = rpc(
                &mut ws,
                &mut reader,
                r#"{"jsonrpc":"2.0","id":0,"method":"drives"}"#,
            );
            if resp.contains("\"letter\":\"G\"") {
                loaded = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        if !loaded {
            drop(daemon.kill());
            drop(daemon.wait());
            return;
        }

        let drives_resp = rpc(
            &mut ws,
            &mut reader,
            r#"{"jsonrpc":"2.0","id":1,"method":"drives"}"#,
        );
        assert!(
            drives_resp.contains("\"letter\":\"G\""),
            "should have drive G: {drives_resp}"
        );

        let search_all = rpc(
            &mut ws,
            &mut reader,
            r#"{"jsonrpc":"2.0","id":2,"method":"search","params":{"pattern":"*","limit":10}}"#,
        );
        assert!(
            search_all.contains("\"name\""),
            "search * should return results with name: {search_all}"
        );

        let search_txt = rpc(
            &mut ws,
            &mut reader,
            r#"{"jsonrpc":"2.0","id":3,"method":"search","params":{"pattern":"*.txt","limit":50}}"#,
        );
        assert!(
            search_txt.contains("\"rows\""),
            "search *.txt should have rows field: {search_txt}"
        );

        let status_resp = rpc(
            &mut ws,
            &mut reader,
            r#"{"jsonrpc":"2.0","id":4,"method":"status"}"#,
        );
        assert!(
            status_resp.contains("\"ready\"") || status_resp.contains("\"Ready\""),
            "status should be ready: {status_resp}"
        );

        shutdown_daemon(&mut daemon, &mut ws, &mut reader);
    }

    /// D3.5.4: Benchmark — measure client round-trip latency (target <15ms).
    #[test]
    #[ignore = "requires pre-built daemon binary — run with --ignored"]
    fn benchmark_round_trip_latency() {
        let exe = daemon_exe();
        let Some(mut daemon) = start_daemon(&exe, &[]) else {
            return;
        };

        let stream = UnixStream::connect(socket_path()).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut ws = stream.try_clone().expect("clone");
        let mut reader = BufReader::new(stream);

        // Warm up
        std::thread::sleep(Duration::from_millis(200));
        for _warmup in 0_i32..10_i32 {
            let resp = rpc(
                &mut ws,
                &mut reader,
                r#"{"jsonrpc":"2.0","id":0,"method":"keepalive"}"#,
            );
            if resp.is_empty() {
                drop(daemon.kill());
                return;
            }
        }

        // Benchmark: 100 keepalive requests
        let iterations = 100_usize;
        let mut latencies = Vec::with_capacity(iterations);
        for i in 0_usize..iterations {
            let start = std::time::Instant::now();
            let resp = rpc(
                &mut ws,
                &mut reader,
                &format!(
                    r#"{{"jsonrpc":"2.0","id":{},"method":"keepalive"}}"#,
                    i + 1000_usize
                ),
            );
            let elapsed = start.elapsed();
            if resp.contains("\"ok\"") {
                latencies.push(elapsed);
            }
        }

        let total: Duration = latencies.iter().sum();
        let count = u32::try_from(iterations).unwrap_or(100_u32);
        let avg = total / count;

        assert!(
            avg.as_millis() < 15_u128,
            "average latency {avg:?} exceeds 15ms target"
        );

        shutdown_daemon(&mut daemon, &mut ws, &mut reader);
    }

    /// D2.7.4: Concurrent clients — 3 connections, interleaved queries.
    #[test]
    #[ignore = "requires pre-built daemon binary — run with --ignored"]
    fn concurrent_clients() {
        let exe = daemon_exe();
        let Some(mut daemon) = start_daemon(&exe, &[]) else {
            return;
        };

        let sock = socket_path();
        let mut clients: Vec<(UnixStream, BufReader<UnixStream>)> = (0_i32..3_i32)
            .filter_map(|_conn_idx| {
                let stream = UnixStream::connect(&sock).ok()?;
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
                let ws = stream.try_clone().ok()?;
                let rdr = BufReader::new(stream);
                Some((ws, rdr))
            })
            .collect();

        assert_eq!(clients.len(), 3_usize, "should connect 3 clients");

        let requests = [
            r#"{"jsonrpc":"2.0","id":100,"method":"status"}"#,
            r#"{"jsonrpc":"2.0","id":200,"method":"drives"}"#,
            r#"{"jsonrpc":"2.0","id":300,"method":"keepalive"}"#,
        ];
        for (req_line, (ws, _)) in requests.iter().zip(clients.iter_mut()) {
            ws.write_all(req_line.as_bytes()).expect("write");
            ws.write_all(b"\n").expect("newline");
            ws.flush().expect("flush");
        }

        let mut responses = Vec::new();
        for (_, rdr) in &mut clients {
            let mut line = String::new();
            rdr.read_line(&mut line).expect("read response");
            responses.push(line);
        }

        #[expect(clippy::indexing_slicing, reason = "test with known 3-element vec")]
        {
            assert!(
                responses[0].contains("\"id\":100"),
                "client 0 should get id 100: {}",
                responses[0]
            );
            assert!(
                responses[0].contains("\"pid\""),
                "client 0 should get status: {}",
                responses[0]
            );
            assert!(
                responses[1].contains("\"id\":200"),
                "client 1 should get id 200: {}",
                responses[1]
            );
            assert!(
                responses[1].contains("\"drives\""),
                "client 1 should get drives: {}",
                responses[1]
            );
            assert!(
                responses[2].contains("\"id\":300"),
                "client 2 should get id 300: {}",
                responses[2]
            );
            assert!(
                responses[2].contains("\"ok\":true"),
                "client 2 should get keepalive ok: {}",
                responses[2]
            );
        };

        let Some(&mut (ref mut ws, ref mut rdr)) = clients.first_mut() else {
            return;
        };
        shutdown_daemon(&mut daemon, ws, rdr);
    }
}
