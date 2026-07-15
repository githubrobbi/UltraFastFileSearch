// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit tests for [`crate::connect_sync::UffsClientSync`] that
//! exercise the wire-protocol path without opening a real socket.
//!
//! The tests inject in-memory reader/writer halves via
//! [`UffsClientSync::from_parts_for_test`], pre-populate the reader
//! with canned JSON-RPC responses, and assert that the client
//! interprets them correctly.
//!
//! # Scope
//!
//! * `deep_health_check` happy path (probe succeeds → `Ok(())`).
//! * `deep_health_check` probe-error path (daemon returns a JSON-RPC error →
//!   `ConnectionFailed` with remediation guidance).
//! * `deep_health_check` transport-error path (reader closed before any bytes
//!   arrive → `ConnectionFailed`).
//! * `deep_health_check` populates the [`UffsClientSync`] status cache so
//!   [`UffsClientSync::await_ready`] can short-circuit without a second RPC.
//! * `await_ready` short-circuits on a cached `Ready` and falls through to
//!   polling on any other cached state (Run 10 Part B regression pins).

#![cfg(test)]

extern crate alloc;

use alloc::sync::Arc;
use std::io::{BufReader, Read, Write};
use std::sync::Mutex;

use crate::connect_sync::UffsClientSync;
use crate::error::ClientError;
use crate::protocol::response::DaemonStatus;

/// In-memory writer that records everything written to it.
///
/// We wrap a `Vec<u8>` in `Arc<Mutex<…>>` so the test can inspect
/// the captured bytes *after* handing ownership to
/// [`UffsClientSync::from_parts_for_test`].  Without the `Arc`,
/// the moved writer would be inaccessible.
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

impl Write for CapturingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Recover from a poisoned mutex rather than propagating a
        // fabricated `io::Error` — the only way the lock can be
        // poisoned in this test is another test-helper panic, which
        // is already surfaced by cargo.  Inline the lock so clippy's
        // `significant_drop_tightening` lint sees the guard released
        // immediately after the single use.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Build a `UffsClientSync` wired to fixed in-memory halves.
///
/// The `response_body` bytes are pre-loaded into the reader so the
/// first `send_request` call will immediately see a complete
/// JSON-RPC response.  The returned [`CapturingWriter`] snapshots
/// whatever the client writes — tests use it to assert the request
/// shape when that matters.
fn client_with_canned_response(response_body: &'static [u8]) -> (UffsClientSync, CapturingWriter) {
    // `&[u8]` already implements `Read` (stdlib blanket impl) — no need for
    // an intermediate owning wrapper.  All callers pass byte-string literals
    // (`b""`, `br#"..."#`), which are `&'static [u8]`, so the `'static` bound
    // on `Box<dyn Read + Send>` is satisfied without an owning Vec.
    let reader: Box<dyn Read + Send> = Box::new(response_body);
    let writer = CapturingWriter::new();
    let writer_box: Box<dyn Write + Send> = Box::new(writer.clone());
    let client = UffsClientSync::from_parts_for_test(BufReader::new(reader), writer_box);
    (client, writer)
}

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
#[test]
fn deep_health_check_happy_path() {
    let canned = br#"{"jsonrpc":"2.0","id":1,"result":{"status":{"state":"ready"},"uptime_secs":42,"connections":1,"pid":1234}}
"#;
    let (mut client, writer) = client_with_canned_response(canned);

    client.deep_health_check().expect("happy path must succeed");

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
#[test]
fn deep_health_check_maps_daemon_error_to_connection_failed() {
    let canned = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"index unavailable"}}
"#;
    let (mut client, _writer) = client_with_canned_response(canned);

    let err = client
        .deep_health_check()
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
    assert!(
        msg.contains("`status` RPC"),
        "error must identify the consolidated probe method (status, not \
         drives) so an operator can correlate to daemon-side tracing: {msg}",
    );
}

/// Transport-error path: the reader is empty (EOF on first read).
/// The client observes `ConnectionClosed` from its read loop and
/// `deep_health_check` remaps it into a `ConnectionFailed` — same
/// remediation surface, different underlying cause string.
#[test]
fn deep_health_check_maps_connection_closed_to_connection_failed() {
    let (mut client, _writer) = client_with_canned_response(b"");

    let err = client
        .deep_health_check()
        .expect_err("closed connection must produce Err");
    let ClientError::ConnectionFailed(msg) = &err else {
        panic!("expected ConnectionFailed, got {err:?}");
    };
    assert!(
        msg.contains("Deep health check failed"),
        "error must identify itself as a health-check failure: {msg}",
    );
    // The underlying error is ConnectionClosed — its Display string
    // (from `#[error(...)]`) is substring-matched here so a future
    // error-message tweak is self-documenting.
    assert!(
        msg.to_lowercase().contains("closed") || msg.contains("ConnectionClosed"),
        "wrapped error must reference the closed connection: {msg}",
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Run 10 Part B — `await_ready` short-circuit regression pins
// ═══════════════════════════════════════════════════════════════════════
//
// The 2026-04-19 patch consolidated the connect-time health probe (what
// used to be a `drives` RPC) and the pre-search readiness poll (a
// `status` RPC) into a single `status` round-trip.  `deep_health_check`
// now caches the returned `DaemonStatus`; `await_ready` consults the
// cache first and skips its own RPC when the daemon is already Ready.
// The tests below pin both directions of that behaviour:
//
//   1. `deep_health_check_caches_ready_status_for_short_circuit` — a successful
//      probe must populate `cached_status`.
//   2. `deep_health_check_clears_cache_on_probe_error` — a failed probe must
//      clear the cache (so a stale `Ready` can never cause `await_ready` to
//      short-circuit on a lie).
//   3. `await_ready_short_circuits_when_cached_status_is_ready` — no RPC on the
//      wire when the cache is `Ready`.
//   4. `await_ready_polls_when_cached_status_is_loading` — cache != Ready must
//      fall back to the original polling path.

/// Regression pin — 2026-04-19: a successful `deep_health_check`
/// probe caches the returned `DaemonStatus::Ready` so the next
/// `await_ready` call on the same client can short-circuit without
/// issuing any RPC.  Pre-fix the cache did not exist and every CLI
/// invocation paid for a redundant `status` round-trip (~5–10 ms on
/// Windows named pipes).
///
/// The verification is *behavioural*: after probing and then calling
/// `await_ready`, the capturing writer must record exactly one RPC
/// (the probe itself).  A second RPC would mean the cache was not
/// consulted.
#[test]
fn deep_health_check_caches_ready_status_for_short_circuit() {
    let canned = br#"{"jsonrpc":"2.0","id":1,"result":{"status":{"state":"ready"},"uptime_secs":10,"connections":1,"pid":42}}
"#;
    let (mut client, writer) = client_with_canned_response(canned);

    client.deep_health_check().expect("probe must succeed");

    // No more canned bytes in the reader — if `await_ready` tried to
    // issue a fresh `status` RPC it would observe EOF and return
    // `ConnectionClosed`.  That it returns `Ok(())` is precisely the
    // proof that the cache was consulted and no RPC was sent.
    client
        .await_ready(core::time::Duration::from_millis(10))
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
/// just failed — a silent-staleness bug that would only surface
/// under retry churn.  We exercise the error path explicitly to pin
/// the invariant.
#[test]
fn deep_health_check_clears_cache_on_probe_error() {
    let canned = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"wedged"}}
"#;
    let (mut client, _writer) = client_with_canned_response(canned);

    // Pre-seed a stale `Ready` cache to simulate the leak scenario.
    client.set_cached_status_for_test(DaemonStatus::Ready);

    let err = client.deep_health_check().expect_err("probe must fail");
    let ClientError::ConnectionFailed(_) = &err else {
        panic!("expected ConnectionFailed, got {err:?}");
    };

    // After the probe error, `await_ready` must NOT short-circuit.
    // With no more canned bytes it should observe `ConnectionClosed`
    // (proving an RPC was actually attempted) rather than returning
    // `Ok(())` immediately.
    let outcome = client.await_ready(core::time::Duration::from_millis(10));
    assert!(
        matches!(outcome, Err(ClientError::Timeout)),
        "await_ready after a cleared cache must poll until timeout; got {outcome:?}",
    );
}

/// Regression pin — 2026-04-19: when `cached_status` is
/// `DaemonStatus::Ready`, `await_ready` must return `Ok(())`
/// immediately without sending a `status` RPC.  Pre-fix there was no
/// cache and every hot-path invocation paid ~5–10 ms for the extra
/// round-trip on Windows named pipes.
///
/// Proof-by-silence: the reader holds no bytes.  If `await_ready`
/// attempted an RPC it would EOF and eventually time out — instead
/// we assert it returns `Ok(())` and the writer captured nothing.
#[test]
fn await_ready_short_circuits_when_cached_status_is_ready() {
    let (mut client, writer) = client_with_canned_response(b"");
    client.set_cached_status_for_test(DaemonStatus::Ready);

    client
        .await_ready(core::time::Duration::from_millis(10))
        .expect("cached Ready must short-circuit");

    let sent = writer.take();
    assert!(
        sent.is_empty(),
        "no RPC may be sent when the cache says Ready; captured: {sent:?}",
    );
}

/// Regression pin — 2026-05-07 Phase 7 soak: a non-I/O `status`
/// error (here a JSON-RPC error → `ClientError::Protocol`) must
/// **not** abort `await_ready`; it must keep polling until the
/// deadline.
///
/// **Background.**  The 2026-05-07 Phase 7 24-h soak attempt failed
/// with `Daemon did not become ready in time / request timed out`
/// even though the captured `daemon.log` showed the daemon up and
/// IPC-listening 1.3 s after spawn.  Root cause: the sync
/// `await_ready` matched `Err(other) => return Err(other)`, so a
/// single transient error during the Windows `AF_UNIX` socket-bind
/// race aborted the readiness probe while the daemon was healthy.
///
/// **Contract pinned here.**  Any non-Ready, non-success outcome
/// (Loading status, I/O error, connection closed, RPC timeout, or
/// a transient protocol error) keeps the loop running until the
/// `timeout` deadline.  The async sibling at
/// `connect.rs::await_ready` has always behaved this way via
/// `PollOutcome::OtherError`; this test pins the sync path's
/// alignment.
///
/// **Test mechanics.**  We canned-feed a JSON-RPC error response
/// to the first poll, which the client surfaces as
/// `ClientError::Protocol("...")` (per `connect_sync.rs::send_request`
/// line 408 in the async sibling — same shape in the sync path).
/// Subsequent polls hit EOF on the cursor and surface as
/// `ConnectionClosed` (already retried).  Pre-fix the very first
/// poll's `Protocol` error would have returned immediately; post-fix
/// the loop continues until the 120 ms deadline elapses and we get
/// the canonical `ClientError::Timeout` instead.
#[test]
fn await_ready_retries_on_protocol_error_until_deadline() {
    // JSON-RPC error response → `send_request` returns
    // `Err(ClientError::Protocol("...message..."))`.  Pre-fix this
    // would have bubbled out of `await_ready` immediately; post-fix
    // it must be treated as transient and retried.
    let canned = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"transient mid-handshake error"}}
"#;
    let (mut client, _writer) = client_with_canned_response(canned);

    let outcome = client.await_ready(core::time::Duration::from_millis(120));

    // Critical assertion: the outcome is `Timeout`, NOT `Protocol`.
    // Pre-fix this test fails with `Err(Protocol("transient ..."))`
    // because the very first poll's protocol error short-circuits the
    // loop.  Post-fix the loop swallows the protocol error, retries
    // (subsequent reads hit EOF → `ConnectionClosed`, already retried
    // pre-fix), and bails with `Timeout` only after the 120 ms
    // deadline elapses.
    assert!(
        matches!(outcome, Err(ClientError::Timeout)),
        "non-Ready, non-success status results must keep polling \
         until the deadline; got {outcome:?}",
    );
}

/// Regression pin — 2026-04-19: when `cached_status` is not
/// `Ready` (e.g. `Loading`), `await_ready` must fall through to its
/// original polling path rather than short-circuit on the stale
/// non-Ready value.  This preserves the cold-start semantics
/// (wait-until-loaded) while only taking the fast path when the
/// daemon has actually reached `Ready`.
#[test]
fn await_ready_polls_when_cached_status_is_loading() {
    let (mut client, writer) = client_with_canned_response(b"");
    client.set_cached_status_for_test(DaemonStatus::Loading {
        drives_loaded: 1,
        drives_total: 3,
    });

    // No canned response → the poll will hit EOF on its first
    // `status` RPC.  The loop tolerates `ConnectionClosed` and
    // retries until the deadline, so we expect `Timeout`.  The
    // important invariant is that at least one RPC *was attempted*
    // (i.e. the cache did not short-circuit).
    let outcome = client.await_ready(core::time::Duration::from_millis(120));
    assert!(
        matches!(outcome, Err(ClientError::Timeout)),
        "non-Ready cache must fall through to polling; got {outcome:?}",
    );

    let sent = core::str::from_utf8(&writer.take())
        .expect("captured bytes must be UTF-8")
        .to_owned();
    assert!(
        sent.contains(r#""method":"status""#),
        "poll loop must issue at least one `status` RPC when the cache is \
         not Ready; saw: {sent:?}",
    );
}

/// Regression — heavy-system-load daemon-start resilience: a real report
/// showed `uffs --daemon start` failing with "Daemon did not become ready
/// in time / request timed out" on a 7-drive / 25M-record production
/// machine whose load legitimately took 2m27s — 27s past the (then-fixed)
/// 2-minute client timeout — even though `--daemon status` moments later
/// showed the daemon healthy and fully loaded.
///
/// `await_ready`'s `timeout` is now an *idle* budget: every `Loading`
/// response whose `drives_loaded` advances resets the deadline. This test
/// feeds two distinct progress ticks (1 drive, then 2 drives) ahead of
/// `Ready`, with a 250ms idle budget. Real time elapses sleeping between
/// polls (100ms → 200ms), so total wall-clock exceeds 250ms — proving the
/// deadline was pushed out by progress rather than left fixed at start+250ms
/// (which would have expired before the third poll ever ran).
#[test]
fn await_ready_extends_deadline_on_drive_load_progress() {
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

    let outcome = client.await_ready(core::time::Duration::from_millis(250));
    assert!(
        outcome.is_ok(),
        "progress ticks (1 drive, then 2) must each extend the idle deadline \
         so the loop reaches the eventual Ready response instead of timing \
         out at the fixed start+250ms mark; got {outcome:?}",
    );
}

/// Companion to the progress-extends-deadline test above: a daemon that
/// reports the *same* `drives_loaded` on every poll (a genuine stall, e.g.
/// wedged on one drive) must NOT get free deadline extensions forever —
/// the idle budget still applies when there is no real progress.
#[test]
fn await_ready_times_out_when_drive_load_progress_stalls() {
    let canned = concat!(
        r#"{"jsonrpc":"2.0","id":1,"result":{"status":{"state":"loading","drives_loaded":1,"drives_total":3},"uptime_secs":1,"connections":1,"pid":1}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"result":{"status":{"state":"loading","drives_loaded":1,"drives_total":3},"uptime_secs":1,"connections":1,"pid":1}}"#,
        "\n",
    )
    .as_bytes();
    let (mut client, _writer) = client_with_canned_response(canned);

    let outcome = client.await_ready(core::time::Duration::from_millis(120));
    assert!(
        matches!(outcome, Err(ClientError::Timeout)),
        "an unchanged drives_loaded across polls is a stall, not progress — \
         it must not extend the idle deadline indefinitely; got {outcome:?}",
    );
}
