// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit tests for [`crate::connect::UffsClient`] (the async client)
//! that exercise the wire-protocol path without opening a real socket.
//!
//! The tests inject in-memory tokio `AsyncRead` / `AsyncWrite` halves
//! via [`UffsClient::from_parts_for_test`], pre-populate the reader
//! with canned JSON-RPC responses, and assert that the client
//! interprets them correctly.
//!
//! These are the async siblings of the `connect_sync_tests` suite —
//! the Run 10 Part B (2026-04-19) `cached_status` short-circuit ships
//! on both clients, and both code paths deserve regression pins.
//!
//! # Scope
//!
//! * `deep_health_check` happy path (probe succeeds → `Ok(())`, method must be
//!   `status`, not the pre-Run-10-B `drives`).
//! * `deep_health_check` probe-error path (daemon returns a JSON-RPC error →
//!   `ConnectionFailed` with remediation guidance).
//! * `deep_health_check` populates `cached_status` so `await_ready`
//!   short-circuits without a second RPC.
//! * `deep_health_check` clears `cached_status` on probe failure so a stale
//!   `Ready` cannot lie.
//! * `await_ready` short-circuits on a cached `Ready` and falls through to
//!   polling on any other cached state.

#![cfg(test)]
#![cfg(feature = "async")]

extern crate alloc;

use alloc::sync::Arc;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Mutex;

use tokio::io::{AsyncRead, AsyncWrite, BufReader, ReadBuf};

use crate::connect::UffsClient;
use crate::error::ClientError;
use crate::protocol::response::DaemonStatus;

// ── In-memory I/O doubles ──────────────────────────────────────────────

/// Tokio `AsyncRead` that yields a fixed byte slice and then EOF.
///
/// The sync tests use `std::io::Cursor` for the same purpose; tokio's
/// ecosystem has no equivalent in `std`, so we roll the smallest
/// possible `AsyncRead` impl by hand.  Trivially `Unpin` (no
/// self-references).
struct CannedReader {
    /// Canned response bytes.
    data: Vec<u8>,
    /// Bytes already returned to the caller.
    offset: usize,
}

impl CannedReader {
    fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            offset: 0,
        }
    }
}

impl AsyncRead for CannedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let remaining = self.data.get(self.offset..).unwrap_or(&[]);
        let to_copy = remaining.len().min(buf.remaining());
        if let Some(slice) = remaining.get(..to_copy) {
            buf.put_slice(slice);
            self.offset = self.offset.saturating_add(to_copy);
        }
        // Zero-length read is the canonical EOF signal — identical to
        // what `std::io::Cursor<Vec<u8>>` does in the sync suite.
        Poll::Ready(Ok(()))
    }
}

/// Tokio `AsyncWrite` that records everything written to it.
///
/// Cloneable so the test can keep a handle for inspection after
/// ownership has moved into the client.  `Arc<Mutex<Vec<u8>>>`
/// matches the sync sibling's pattern.
#[derive(Clone)]
struct CapturingWriter(Arc<Mutex<Vec<u8>>>);

impl CapturingWriter {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    fn take(&self) -> Vec<u8> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl AsyncWrite for CapturingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Poisoning is ignored for the same reason as the sync helper:
        // a panicked peer is already surfaced by cargo's test harness,
        // and fabricating an `io::Error` would mask the real panic.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Build a [`UffsClient`] wired to fixed in-memory halves.
///
/// The `response_body` bytes are pre-loaded into the reader so the
/// first `send_request` call will immediately see a complete
/// JSON-RPC response.  The returned [`CapturingWriter`] snapshots
/// whatever the client writes — tests use it to assert the request
/// shape when that matters.
fn client_with_canned_response(response_body: &[u8]) -> (UffsClient, CapturingWriter) {
    let reader: Box<dyn AsyncRead + Unpin + Send> = Box::new(CannedReader::new(response_body));
    let writer = CapturingWriter::new();
    let writer_box: Box<dyn AsyncWrite + Unpin + Send> = Box::new(writer.clone());
    let client = UffsClient::from_parts_for_test(BufReader::new(reader), writer_box);
    (client, writer)
}

// ── `deep_health_check` wire-protocol regression pins ──────────────────

/// Happy path: the daemon returns a valid `status` result, so
/// `deep_health_check` returns `Ok(())` and the caller's retry
/// loop proceeds normally.
///
/// Also verifies that the client sent a JSON-RPC request with
/// `method:"status"` — the 2026-04-19 Run 10 Part B patch consolidated
/// what used to be two separate RPCs (`drives` for liveness via
/// `deep_health_check`, plus `status` for readiness via `await_ready`)
/// into a single `status` probe.  A future regression that silently
/// reverts to the `drives` method would give a false sense of coverage
/// here and silently re-introduce the ~5–10 ms per-invocation tax on
/// Windows named pipes — this assertion pins the method name.
#[tokio::test]
async fn deep_health_check_happy_path() {
    let canned = br#"{"jsonrpc":"2.0","id":1,"result":{"status":{"state":"ready"},"uptime_secs":42,"connections":1,"pid":1234}}
"#;
    let (mut client, writer) = client_with_canned_response(canned);

    client
        .deep_health_check()
        .await
        .expect("happy path must succeed");

    let sent = writer.take();
    let sent_str = core::str::from_utf8(&sent).expect("request must be valid UTF-8");
    assert!(
        sent_str.contains(r#""method":"status""#),
        "the probe must use the `status` method (consolidated in Run 10 Part B); \
         saw: {sent_str:?}",
    );
    assert!(
        !sent_str.contains(r#""method":"drives""#),
        "the probe must not hit `drives` — that would re-introduce the extra \
         RPC round-trip the Run 10 Part B patch eliminated; saw: {sent_str:?}",
    );
    assert!(
        sent_str.ends_with('\n'),
        "JSON-RPC framing requires a trailing newline; saw: {sent_str:?}",
    );
}

/// Probe-error path: the daemon is reachable (a valid JSON-RPC
/// envelope comes back) but the response carries an `error` object.
/// `deep_health_check` must wrap that into a
/// [`ClientError::ConnectionFailed`] whose message includes the
/// remediation guidance (`uffs --daemon kill`, skip-env hint) so the
/// user has an actionable next step.
#[tokio::test]
async fn deep_health_check_maps_daemon_error_to_connection_failed() {
    let canned = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"index unavailable"}}
"#;
    let (mut client, _writer) = client_with_canned_response(canned);

    let err = client
        .deep_health_check()
        .await
        .expect_err("daemon error must propagate as Err");
    let ClientError::ConnectionFailed(msg) = &err else {
        panic!("expected ConnectionFailed, got {err:?}");
    };
    assert!(
        msg.contains("Deep health check failed"),
        "error must identify itself as a health-check failure: {msg}",
    );
    assert!(
        msg.contains("uffs --daemon kill"),
        "error must include the remediation command: {msg}",
    );
    assert!(
        msg.contains("UFFS_CLIENT_SKIP_HEALTH_CHECK"),
        "error must mention the opt-out env var: {msg}",
    );
    assert!(
        msg.contains("index unavailable"),
        "error must preserve the underlying daemon message: {msg}",
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Run 10 Part B — `await_ready` short-circuit regression pins
// ═══════════════════════════════════════════════════════════════════════
//
// Behavioural mirror of the sync suite's Part B pins — the async
// client has the same `cached_status` short-circuit in `await_ready`
// and the same cache-clear on probe error in `deep_health_check`.  A
// silent divergence between the two would re-introduce the ~5–10 ms
// per-invocation tax on the async path (which is what the MCP gateway
// and daemon use internally).

/// Regression pin — 2026-04-19: a successful `deep_health_check`
/// probe caches the returned `DaemonStatus::Ready` so the next
/// `await_ready` call on the same client can short-circuit without
/// issuing any RPC.  Pre-fix the cache did not exist and every
/// invocation paid for a redundant `status` round-trip.
///
/// Proof-by-behavior: after probing and then calling `await_ready`,
/// the capturing writer must record exactly **one** RPC (the probe
/// itself).  A second RPC would mean the cache was not consulted.
#[tokio::test]
async fn deep_health_check_caches_ready_status_for_short_circuit() {
    let canned = br#"{"jsonrpc":"2.0","id":1,"result":{"status":{"state":"ready"},"uptime_secs":10,"connections":1,"pid":42}}
"#;
    let (mut client, writer) = client_with_canned_response(canned);

    client
        .deep_health_check()
        .await
        .expect("probe must succeed");

    // No more canned bytes in the reader — if `await_ready` tried to
    // issue a fresh `status` RPC it would observe EOF and, after the
    // reconnect threshold, eventually time out.  That it returns
    // `Ok(())` immediately is precisely the proof that the cache was
    // consulted and no RPC was sent.
    client
        .await_ready(core::time::Duration::from_millis(10))
        .await
        .expect("cached Ready must let await_ready return without any RPC");

    let sent = core::str::from_utf8(&writer.take())
        .expect("captured bytes must be UTF-8")
        .to_owned();
    let rpc_count = sent.matches("\"jsonrpc\"").count();
    assert_eq!(
        rpc_count, 1,
        "exactly one RPC (the probe) must be sent; saw {rpc_count} in {sent:?}",
    );
}

/// Regression pin — 2026-04-19: a failing `deep_health_check` probe
/// must clear `cached_status`.  Otherwise a stale `Ready` left over
/// from a previous connect (on a reused client) could trick
/// `await_ready` into short-circuiting even though the current probe
/// just failed.  We exercise the error path explicitly to pin the
/// invariant.
///
/// On the async client `await_ready` returns
/// `ClientError::ConnectionFailed("Timed out waiting for daemon to
/// finish loading")` when its deadline elapses — distinct from the
/// sync client's `ClientError::Timeout`.  The test matches on the
/// async-side shape.
#[tokio::test]
async fn deep_health_check_clears_cache_on_probe_error() {
    let canned = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"wedged"}}
"#;
    let (mut client, _writer) = client_with_canned_response(canned);

    // Pre-seed a stale `Ready` cache to simulate the leak scenario.
    client.set_cached_status_for_test(DaemonStatus::Ready);

    let err = client
        .deep_health_check()
        .await
        .expect_err("probe must fail");
    let ClientError::ConnectionFailed(_) = &err else {
        panic!("expected ConnectionFailed, got {err:?}");
    };

    // After the probe error, `await_ready` must NOT short-circuit.
    // The reader has no more canned bytes so each retry observes EOF;
    // the loop will trigger a reconnect attempt (which also fails
    // because there is no daemon) and eventually hit its deadline.
    let outcome = client
        .await_ready(core::time::Duration::from_millis(120))
        .await;
    match outcome {
        Err(ClientError::ConnectionFailed(msg)) => {
            assert!(
                msg.contains("Timed out"),
                "expected the async timeout message, got {msg}",
            );
        }
        other => panic!("expected Err(ConnectionFailed(\"Timed out…\")), got {other:?}"),
    }
}

/// Regression pin — 2026-04-19: when `cached_status` is
/// `DaemonStatus::Ready`, `await_ready` must return `Ok(())`
/// immediately without sending a `status` RPC.
///
/// Proof-by-silence: the reader holds no bytes.  If `await_ready`
/// attempted an RPC it would EOF and eventually time out — instead
/// we assert it returns `Ok(())` and the writer captured nothing.
#[tokio::test]
async fn await_ready_short_circuits_when_cached_status_is_ready() {
    let (mut client, writer) = client_with_canned_response(b"");
    client.set_cached_status_for_test(DaemonStatus::Ready);

    client
        .await_ready(core::time::Duration::from_millis(10))
        .await
        .expect("cached Ready must short-circuit");

    let sent = writer.take();
    assert!(
        sent.is_empty(),
        "no RPC may be sent when the cache says Ready; captured: {sent:?}",
    );
}

/// Regression pin — 2026-04-19: when `cached_status` is not
/// `Ready` (e.g. `Loading`), `await_ready` must fall through to its
/// original polling path rather than short-circuit on the stale
/// non-Ready value.  Preserves cold-start semantics (wait-until-
/// loaded) while only taking the fast path when the daemon has
/// actually reached `Ready`.
#[tokio::test]
async fn await_ready_polls_when_cached_status_is_loading() {
    let (mut client, writer) = client_with_canned_response(b"");
    client.set_cached_status_for_test(DaemonStatus::Loading {
        drives_loaded: 1,
        drives_total: 3,
    });

    // No canned response → the poll will hit EOF on its first
    // `status` RPC.  The async loop tolerates the error, retries
    // with backoff, and eventually hits the deadline.  The important
    // invariant is that at least one RPC *was attempted* (i.e. the
    // cache did not short-circuit).
    let outcome = client
        .await_ready(core::time::Duration::from_millis(120))
        .await;
    match outcome {
        Err(ClientError::ConnectionFailed(msg)) => {
            assert!(
                msg.contains("Timed out"),
                "expected the async timeout message, got {msg}",
            );
        }
        other => panic!(
            "non-Ready cache must fall through to polling (expected \
             Err(ConnectionFailed(\"Timed out…\"))); got {other:?}"
        ),
    }

    let sent = core::str::from_utf8(&writer.take())
        .expect("captured bytes must be UTF-8")
        .to_owned();
    assert!(
        sent.contains(r#""method":"status""#),
        "poll loop must issue at least one `status` RPC when the cache is \
         not Ready; saw: {sent:?}",
    );
}

/// Regression — heavy-system-load daemon-start resilience (async sibling of
/// the same-named test in `connect_sync_tests.rs`): `await_ready`'s
/// `timeout` is an idle budget, not a fixed wall-clock cutoff. Every
/// `Loading` response whose `drives_loaded` advances resets the deadline, so
/// a big multi-drive load that keeps visibly progressing under heavy system
/// load is never killed by an arbitrary cutoff. Feeds two progress ticks (1
/// drive, then 2) ahead of `Ready` with a 250ms idle budget; the real sleeps
/// between polls push total wall-clock past 250ms, proving the deadline
/// followed the progress instead of staying fixed at start+250ms.
#[tokio::test]
async fn await_ready_extends_deadline_on_drive_load_progress() {
    let canned = concat!(
        r#"{"jsonrpc":"2.0","id":1,"result":{"status":{"state":"loading","drives_loaded":1,"drives_total":3},"uptime_secs":1,"connections":1,"pid":1}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"result":{"status":{"state":"loading","drives_loaded":2,"drives_total":3},"uptime_secs":1,"connections":1,"pid":1}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"result":{"status":{"state":"ready"},"uptime_secs":1,"connections":1,"pid":1}}"#,
        "\n",
    )
    .as_bytes();
    let (mut client, _writer) = client_with_canned_response(canned);

    let outcome = client
        .await_ready(core::time::Duration::from_millis(250))
        .await;
    assert!(
        outcome.is_ok(),
        "progress ticks (1 drive, then 2) must each extend the idle deadline \
         so the loop reaches the eventual Ready response instead of timing \
         out at the fixed start+250ms mark; got {outcome:?}",
    );
}

/// Companion to the progress-extends-deadline test above: a daemon that
/// reports the *same* `drives_loaded` on every poll (a genuine stall) must
/// NOT get free deadline extensions forever.
#[tokio::test]
async fn await_ready_times_out_when_drive_load_progress_stalls() {
    let canned = concat!(
        r#"{"jsonrpc":"2.0","id":1,"result":{"status":{"state":"loading","drives_loaded":1,"drives_total":3},"uptime_secs":1,"connections":1,"pid":1}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"result":{"status":{"state":"loading","drives_loaded":1,"drives_total":3},"uptime_secs":1,"connections":1,"pid":1}}"#,
        "\n",
    )
    .as_bytes();
    let (mut client, _writer) = client_with_canned_response(canned);

    let outcome = client
        .await_ready(core::time::Duration::from_millis(120))
        .await;
    match outcome {
        Err(ClientError::ConnectionFailed(msg)) => {
            assert!(
                msg.contains("Timed out"),
                "expected the async timeout message, got {msg}",
            );
        }
        other => panic!(
            "an unchanged drives_loaded across polls is a stall, not \
             progress — it must not extend the idle deadline indefinitely; \
             got {other:?}"
        ),
    }
}
