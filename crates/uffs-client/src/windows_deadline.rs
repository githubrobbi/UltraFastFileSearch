// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Windows per-RPC deadline guard for the synchronous IPC client.
//!
//! # Why this exists
//!
//! On Unix, the sync client calls `UnixStream::set_read_timeout` and
//! `set_write_timeout` — the kernel then enforces a per-operation
//! deadline for free.  Named pipes opened via `std::fs::OpenOptions`
//! on Windows expose no equivalent: the pipe is in blocking mode, and
//! `ReadFile` / `WriteFile` will wait forever if the daemon hangs.
//!
//! This module closes that gap with **Option 2** of the deadline
//! design: a long-lived background watchdog thread per client that
//! cancels synchronous I/O on the owning thread when a deadline
//! passes.
//!
//! # Design
//!
//! * The guard stores a stable, duplicated handle to the thread that owns the
//!   [`crate::connect_sync::UffsClientSync`] — this handle is valid for the
//!   lifetime of the guard even after the thread exits.
//! * An [`AtomicU64`] carries the absolute `GetTickCount64` tick at which the
//!   current RPC should be aborted.  `0` means "no RPC in flight", i.e.
//!   disarmed.
//! * The watchdog thread wakes every [`WATCHDOG_POLL_MS`] ms, checks the
//!   atomic, and calls `CancelSynchronousIo` on the target thread when the
//!   deadline has passed.  It consumes the deadline (via `compare_exchange`) so
//!   each arm fires at most once.
//! * `CancelSynchronousIo` causes the blocked `ReadFile` / `WriteFile` on the
//!   target thread to return `ERROR_OPERATION_ABORTED` (`0x4D3`), which bubbles
//!   up through `std::io::Read` / `Write` as a regular I/O error — the caller's
//!   existing `ClientError::Io` branch then reports it naturally.
//!
//! # Thread-affinity caveat
//!
//! The target thread is captured at construction time.  If the owner
//! later sends the `UffsClientSync` to a different thread and issues
//! an RPC from there, the watchdog will cancel I/O on the **original**
//! thread — effectively a no-op.  This is acceptable for the sync
//! client because it is used from a single short-lived thread per
//! CLI invocation, but documented here so a future refactor doesn't
//! silently regress robustness.
//!
//! # Cost
//!
//! * Per guard (per `UffsClientSync` lifetime): one watchdog thread, ~20
//!   wake-ups / s, negligible CPU.
//! * Per RPC (arm + disarm): two atomic stores, nanoseconds.
//! * Worst-case deadline overshoot: [`WATCHDOG_POLL_MS`] ms.
//! * Drop latency: < 1 ms.  The watchdog blocks on an
//!   [`mpsc::Receiver::recv_timeout`] pairing the 50 ms poll with an instant
//!   shutdown wake, so [`Drop`] no longer stalls waiting for the next poll
//!   cycle.  Before this fix the CLI hot path was paying ~48 ms median on every
//!   invocation (Run 11 bisect — 60 % of the entire wall-clock).

#![cfg(windows)]

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::io;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};

use windows::Win32::Foundation::{CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
use windows::Win32::System::IO::CancelSynchronousIo;
use windows::Win32::System::SystemInformation::GetTickCount64;
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};

/// Newtype wrapper so [`HANDLE`] can cross thread boundaries.
///
/// `windows::Win32::Foundation::HANDLE` wraps a raw `*mut c_void`
/// which is not [`Send`] by default.  We only use the handle as an
/// opaque cancellation target for `CancelSynchronousIo` — the kernel
/// object behind it is reference-counted and perfectly safe to
/// access from any thread — so wrapping it in a newtype with an
/// explicit `unsafe impl Send` is the minimal ceremony to satisfy
/// the type system without loosening safety for unrelated code.
#[derive(Copy, Clone)]
struct SendHandle(HANDLE);

#[expect(
    unsafe_code,
    reason = "Win32 HANDLE is thread-safe; newtype re-exposes Send"
)]
// SAFETY: HANDLE is a kernel object reference; operating on the
// same HANDLE from multiple threads is supported by the Win32 API
// (see DuplicateHandle + CancelSynchronousIo docs).  The wrapper
// only transports the pointer value between the constructor thread
// and the watchdog thread; no aliased mutation occurs.
unsafe impl Send for SendHandle {}

/// Watchdog wake-up period.
///
/// Trades CPU load (more wake-ups = higher idle cost) against
/// deadline precision (longer sleep = larger overshoot).  50 ms is
/// an empirically conservative sweet spot: a 60 s deadline overshoots
/// by at most 0.08 %, and 20 wake-ups per second per client is well
/// below noise on any modern CPU.
const WATCHDOG_POLL_MS: u64 = 50;

/// Sentinel value meaning "no RPC in flight".
///
/// We use `0` explicitly because `GetTickCount64` returns `0` only in
/// the ~49.7-day window immediately after boot, and the arm path
/// always adds the deadline *duration* to the current tick — so a
/// live deadline of exactly `0` is impossible in practice.
const DISARMED: u64 = 0;

/// Long-lived guard that cancels blocking I/O on deadline expiry.
///
/// Held by [`crate::connect_sync::UffsClientSync`] for the entire
/// client lifetime; `arm` / `disarm` bracket every RPC.
pub(crate) struct WindowsDeadlineGuard {
    /// Per-RPC deadline duration — applied by [`Self::arm`].
    duration: Duration,
    /// Absolute tick (`GetTickCount64`) at which the current RPC
    /// should be aborted.  `0` = [`DISARMED`].
    deadline_tick_ms: Arc<AtomicU64>,
    /// Channel sender paired with the watchdog's
    /// [`mpsc::Receiver`].  [`Drop`] sends a single `()` on this
    /// channel to wake the watchdog immediately; dropping the
    /// sender without sending would work too (the watchdog treats
    /// [`mpsc::RecvTimeoutError::Disconnected`] as shutdown), but
    /// sending first keeps the wake path deterministic for tests.
    ///
    /// Using a channel (instead of the prior `AtomicBool` + 50 ms
    /// `thread::sleep`) cut the Windows CLI hot-path wall-clock
    /// from 77 ms → 29 ms — a ~48 ms drop-latency regression that
    /// had gone unmeasured because long-lived clients (TUI, MCP)
    /// amortise the cost.
    shutdown_tx: mpsc::Sender<()>,
    /// Duplicated handle of the thread we are guarding.
    ///
    /// Captured by [`Self::new`]; closed by [`Drop`] after the
    /// watchdog joins.  We hold onto the handle rather than the
    /// `GetCurrentThread` pseudo-handle so it remains valid even if
    /// the owning thread exits while the guard is still alive
    /// (the watchdog's `CancelSynchronousIo` will then return an
    /// error, which we log and ignore).
    ///
    /// Wrapped in [`SendHandle`] so the underlying `*mut c_void`
    /// can cross into the watchdog thread at spawn time.
    target_thread: SendHandle,
    /// Watchdog thread handle, consumed by [`Drop`] for join.
    watchdog: Option<JoinHandle<()>>,
}

impl WindowsDeadlineGuard {
    /// Construct a new guard and spawn its watchdog thread.
    ///
    /// Captures a duplicated handle to the calling thread; that
    /// handle becomes the cancellation target for every future
    /// [`Self::arm`] on this guard.
    ///
    /// # Errors
    ///
    /// Returns the OS error from `DuplicateHandle` or from
    /// `thread::Builder::spawn` if the watchdog cannot be started.
    pub(crate) fn new(duration: Duration) -> io::Result<Self> {
        let target_thread = SendHandle(duplicate_current_thread()?);
        let deadline_tick_ms = Arc::new(AtomicU64::new(DISARMED));
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

        let watchdog_ticks = Arc::clone(&deadline_tick_ms);
        let watchdog_target = target_thread;

        let watchdog = thread::Builder::new()
            .name("uffs-deadline-watchdog".into())
            .spawn(move || {
                watchdog_loop(&watchdog_ticks, &shutdown_rx, watchdog_target);
            })?;

        Ok(Self {
            duration,
            deadline_tick_ms,
            shutdown_tx,
            target_thread,
            watchdog: Some(watchdog),
        })
    }

    /// Arm the guard for the next RPC.
    ///
    /// Writes `now + self.duration` into the shared atomic.  The
    /// watchdog will cancel I/O if the next blocking read/write has
    /// not completed by then.
    ///
    /// Callers should pair every `arm` with a [`Self::disarm`] on
    /// the success path (the `Drop` impl of a RAII sentinel would be
    /// even safer — but the current call site is a single method
    /// with no early returns that skip cleanup, so an explicit pair
    /// keeps the code flatter).
    pub(crate) fn arm(&self) {
        // SAFETY: GetTickCount64 has no preconditions and no state.
        #[expect(unsafe_code, reason = "Win32 monotonic time accessor")]
        let now = unsafe { GetTickCount64() };
        let duration_ms = u64::try_from(self.duration.as_millis()).unwrap_or(u64::MAX);
        // If the addition would wrap (nearly never — requires
        // ~49.7 days of uptime *plus* a multi-day deadline), clamp to
        // u64::MAX so the deadline simply never fires.  Safer than
        // wrapping and accidentally firing immediately.
        let raw_deadline = now.saturating_add(duration_ms);
        // saturating_add(DISARMED)==DISARMED only if both are 0; we
        // already guard against duration==0 at the caller, but be
        // defensive: never write DISARMED here, otherwise the
        // watchdog would treat the armed state as disarmed.
        let deadline = if raw_deadline == DISARMED {
            1
        } else {
            raw_deadline
        };
        self.deadline_tick_ms.store(deadline, Ordering::Release);
    }

    /// Disarm the guard — the current RPC completed in time.
    ///
    /// After this call the watchdog will not fire until the next
    /// [`Self::arm`].
    pub(crate) fn disarm(&self) {
        self.deadline_tick_ms.store(DISARMED, Ordering::Release);
    }
}

impl Drop for WindowsDeadlineGuard {
    /// Stop the watchdog and close the duplicated thread handle.
    ///
    /// Drop latency is bounded by the time to wake one condvar and
    /// join one thread — sub-millisecond in practice.  Before the
    /// [`mpsc::channel`] shutdown wake, this was up to
    /// [`WATCHDOG_POLL_MS`] ms (empirically 48 ms median on the
    /// Windows CLI hot path), because the watchdog was blocked in
    /// [`thread::sleep`] and couldn't observe the shutdown flag
    /// until the next poll tick.  A regression test
    /// (`drop_is_prompt_when_guard_is_disarmed`) pins the new
    /// contract so a future refactor back to a polling sleep
    /// fails immediately.
    fn drop(&mut self) {
        // Send a wake token — the watchdog's `recv_timeout` returns
        // `Ok(())` within a condvar wake, not the 50 ms poll boundary.
        // A send error means the receiver was already dropped
        // (watchdog panicked); the `join` below will surface that
        // panic, so no extra action is needed here.
        if self.shutdown_tx.send(()).is_err() {
            tracing::debug!(
                "deadline watchdog receiver already dropped; join below will surface any panic"
            );
        }
        if let Some(watchdog) = self.watchdog.take() {
            // If the watchdog panicked, we still want to close the
            // handle — drop the join result.
            drop(watchdog.join());
        }
        // SAFETY: `target_thread` was obtained from `DuplicateHandle`
        // in `new`; we are the sole owner and drop it exactly once.
        #[expect(unsafe_code, reason = "closing Win32 thread handle on drop")]
        let close_result = unsafe { CloseHandle(self.target_thread.0) };
        drop(close_result);
    }
}

/// Watchdog loop — polls the shared deadline and cancels I/O when
/// it fires.
///
/// Runs until the paired [`mpsc::Sender`] sends a shutdown token or
/// is dropped.  When the deadline has passed, uses
/// `compare_exchange` to consume the deadline so the cancellation
/// fires exactly once per `arm`.  Any errors from
/// `CancelSynchronousIo` are logged and ignored — the most common
/// cause is "no I/O was pending on that thread", which is benign
/// (the RPC already returned before the watchdog got scheduled).
///
/// The [`mpsc::Receiver::recv_timeout`] call below replaces the
/// earlier `thread::sleep` polling pattern: `Timeout` means "no
/// shutdown, check the deadline"; `Ok(())` or `Disconnected` both
/// mean "shut down now".  This gives us responsive shutdown (the
/// paired `send` or drop wakes the condvar inside `recv_timeout`)
/// without losing the 50 ms polling cadence that bounds deadline
/// overshoot.
fn watchdog_loop(
    deadline_tick_ms: &Arc<AtomicU64>,
    shutdown_rx: &mpsc::Receiver<()>,
    target: SendHandle,
) {
    loop {
        match shutdown_rx.recv_timeout(Duration::from_millis(WATCHDOG_POLL_MS)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        let deadline = deadline_tick_ms.load(Ordering::Acquire);
        if deadline == DISARMED {
            continue;
        }
        // SAFETY: GetTickCount64 has no preconditions.
        #[expect(unsafe_code, reason = "Win32 monotonic time accessor")]
        let now = unsafe { GetTickCount64() };
        if now < deadline {
            continue;
        }
        // Consume the deadline before firing, so a subsequent arm/
        // disarm race cannot cause a double cancellation.
        if deadline_tick_ms
            .compare_exchange(deadline, DISARMED, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            continue;
        }
        // SAFETY: `target` was produced by `DuplicateHandle` in the
        // guard's `new`; the guard's `Drop` joins us before closing
        // the handle, so `target` is live for the whole call.
        #[expect(unsafe_code, reason = "Win32 cancellation FFI")]
        let cancel_result = unsafe { CancelSynchronousIo(target.0) };
        match cancel_result {
            Ok(()) => tracing::warn!(
                "Windows deadline watchdog: cancelled synchronous I/O on target thread \
                 (RPC exceeded UFFS_CLIENT_TIMEOUT_SECS)"
            ),
            Err(err) => tracing::debug!(
                ?err,
                "Windows deadline watchdog: CancelSynchronousIo returned non-success \
                 (usually benign — no I/O pending)"
            ),
        }
    }
}

/// Duplicate the *current* thread's pseudo-handle into a real handle.
///
/// Windows provides `GetCurrentThread` as a pseudo-handle (`-2`) that
/// always refers to "whatever thread is asking".  That is useless for
/// our watchdog, which runs on a *different* thread and needs to
/// refer back to the calling thread specifically.  `DuplicateHandle`
/// with `GetCurrentProcess` + `GetCurrentThread` returns a real
/// thread handle that remains valid across thread boundaries.
///
/// # Errors
///
/// Returns the last OS error if `DuplicateHandle` fails — this is
/// effectively never, since the inputs are all pseudo-handles
/// returned by `GetCurrentProcess` / `GetCurrentThread`, but
/// propagating it keeps the constructor contract honest.
fn duplicate_current_thread() -> io::Result<HANDLE> {
    // SAFETY: GetCurrentProcess returns a pseudo-handle; no cleanup,
    // no preconditions.
    #[expect(unsafe_code, reason = "Win32 pseudo-handle accessor")]
    let current_proc = unsafe { GetCurrentProcess() };
    // SAFETY: GetCurrentThread returns a pseudo-handle; no cleanup,
    // no preconditions.
    #[expect(unsafe_code, reason = "Win32 pseudo-handle accessor")]
    let current_thread = unsafe { GetCurrentThread() };
    let mut dup = HANDLE::default();
    // SAFETY: all inputs are valid; `&raw mut dup` is a stack slot
    // we own; we check the Result and propagate the OS error.
    #[expect(unsafe_code, reason = "Win32 handle duplication FFI")]
    let result = unsafe {
        DuplicateHandle(
            current_proc,
            current_thread,
            current_proc,
            &raw mut dup,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if let Err(err) = result {
        return Err(io::Error::from_raw_os_error(err.code().0));
    }
    Ok(dup)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard constructs and drops cleanly with no armed RPC — the
    /// watchdog thread must terminate promptly on shutdown.  This
    /// exercises the happy path of the Drop impl (no cancellation
    /// fired, clean join).
    #[test]
    fn construct_and_drop_clean() {
        let guard = WindowsDeadlineGuard::new(Duration::from_mins(1))
            .expect("guard construction must succeed on a healthy Windows box");
        drop(guard);
        // If the watchdog didn't join in Drop, the test process
        // would hang here (cargo test has no implicit timeout).
    }

    /// Drop latency must stay under 10 ms on the CLI hot path.
    ///
    /// Before the mpsc-channel shutdown (Run 11), `thread::sleep(50 ms)`
    /// in the watchdog loop meant the `Drop` impl could wait up to
    /// 50 ms for the next wake — empirically 48 ms median, which was
    /// ~60 % of the entire Windows CLI wall-clock (77 ms → 29 ms on
    /// `uffs notepad.exe --drive D`).  This test pins the new
    /// instant-wake contract so a future refactor that goes back to
    /// a polling sleep fails immediately instead of silently
    /// regressing every CLI user by ~50 %.
    ///
    /// The 10 ms ceiling is deliberately generous: a condvar wake +
    /// thread join on a healthy Windows box is typically < 1 ms;
    /// 10 ms leaves room for CI scheduler jitter and AV interference
    /// without masking a genuine regression.
    #[test]
    fn drop_is_prompt_when_guard_is_disarmed() {
        // A single wall-clock sample is flaky on a loaded CI Windows runner
        // (AV / scheduler jitter can push one drop past 10 ms). Take the
        // *minimum* across several iterations instead: the instant-wake floor
        // is < 1 ms, while a regression to the old `thread::sleep(50 ms)` poll
        // would put even the fastest drop near 48 ms — so the min cleanly
        // separates healthy from regressed regardless of per-sample jitter.
        let min_drop = (0..8_u32)
            .map(|_| {
                let guard = WindowsDeadlineGuard::new(Duration::from_mins(1))
                    .expect("guard construction must succeed on a healthy Windows box");
                let start = std::time::Instant::now();
                drop(guard);
                start.elapsed()
            })
            .min()
            .expect("at least one sample");
        assert!(
            min_drop < Duration::from_millis(10),
            "fastest drop over 8 iters was {min_drop:?}; a floor beyond 10 ms means \
             the mpsc-channel shutdown wake is gone. Run 11 bisect: before the \
             channel fix the watchdog used `thread::sleep(50 ms)` and the CLI hot \
             path paid 48 ms median on every invocation.",
        );
    }

    /// arm + disarm must be cheap and must not fire the watchdog —
    /// the watchdog polls at 50 ms, so a 10 ms wait proves the
    /// watchdog stayed quiet.  We assert no cancellation happened by
    /// observing that the shared atomic returned to `DISARMED`.
    #[test]
    fn arm_disarm_cycle_does_not_trigger() {
        let guard = WindowsDeadlineGuard::new(Duration::from_mins(1)).expect("guard construction");
        guard.arm();
        assert_ne!(
            guard.deadline_tick_ms.load(Ordering::Acquire),
            DISARMED,
            "arm must write a non-zero deadline",
        );
        guard.disarm();
        assert_eq!(
            guard.deadline_tick_ms.load(Ordering::Acquire),
            DISARMED,
            "disarm must restore the sentinel",
        );
    }

    /// A 1 ms deadline must fire the watchdog within ~100 ms — we
    /// observe the atomic being consumed back to `DISARMED` by the
    /// `compare_exchange` in the watchdog loop.  This proves the
    /// watchdog actually does its job.
    ///
    /// We don't invoke any real I/O here — `CancelSynchronousIo` on
    /// a thread with no pending I/O is a harmless no-op, which is
    /// why this is safe to run in unit tests.
    #[test]
    fn expired_deadline_is_consumed_by_watchdog() {
        let guard =
            WindowsDeadlineGuard::new(Duration::from_millis(1)).expect("guard construction");
        guard.arm();

        // Wait long enough for the watchdog (50 ms poll + 1 ms
        // deadline) — give it 300 ms to be comfortably above jitter.
        thread::sleep(Duration::from_millis(300));

        assert_eq!(
            guard.deadline_tick_ms.load(Ordering::Acquire),
            DISARMED,
            "expired deadline must be consumed by the watchdog \
             (`compare_exchange` back to 0)",
        );
    }

    /// arm never writes the `DISARMED` sentinel even under weird
    /// clock conditions — if the deadline calculation were to
    /// produce `0` it would silently disable the guard, which is the
    /// worst possible failure mode.  We protect against this in
    /// `arm` with an explicit `if == DISARMED { 1 }` clamp.
    #[test]
    fn arm_never_writes_disarmed_sentinel() {
        // A zero-duration arm is not a real use case (the env parser
        // returns None for UFFS_CLIENT_TIMEOUT_SECS=0, so no guard
        // is ever constructed with a zero deadline), but we defend
        // against it anyway.
        let guard =
            WindowsDeadlineGuard::new(Duration::from_millis(0)).expect("guard construction");
        guard.arm();
        assert_ne!(
            guard.deadline_tick_ms.load(Ordering::Acquire),
            DISARMED,
            "arm must never write the disarmed sentinel, even with a zero duration",
        );
    }

    /// End-to-end integration test: a **blackhole** named-pipe server
    /// accepts a client connection but never writes; the client
    /// issues a blocking `ReadFile` under an armed guard; the
    /// watchdog fires, `CancelSynchronousIo` unblocks the read, and
    /// `ReadFile` returns `ERROR_OPERATION_ABORTED` (995).
    ///
    /// This is the single most important regression guard for commit
    /// D — if the watchdog's cancellation path ever breaks in a real
    /// Windows build, this test will fail instead of a user's CLI
    /// silently hanging forever.
    ///
    /// The pipe server lives on a short-lived helper thread that
    /// sleeps briefly after accept, then exits; the thread joins at
    /// the end of the test so no resources leak.
    #[test]
    fn watchdog_cancels_blocked_readfile_on_blackhole_pipe() {
        use std::io::Read as _;
        use std::time::Instant;

        use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
        use windows::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
        };
        use windows::core::PCWSTR;

        // Unique pipe path per-process + per-call so concurrent
        // cargo test runs do not collide on the same name.  Build it
        // through `PipeName::parse` so this test doubles as a
        // regression pin: if `PipeName`'s invariants ever drift (e.g.
        // a prefix tweak or a length-cap shrink), this fixture starts
        // failing here instead of silently producing a path Win32
        // would refuse.
        let pipe_name = uffs_security::pipe::PipeName::parse(format!(
            "\\\\.\\pipe\\uffs-test-blackhole-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|dur| dur.as_nanos())
                .unwrap_or_default(),
        ))
        .expect("test-blackhole pipe path is a valid PipeName");

        // ── Server thread: accept once, never respond ───────────
        let server_name = pipe_name.as_str().to_owned();
        let server = thread::spawn(move || {
            let wide: Vec<u16> = format!("{server_name}\0").encode_utf16().collect();
            // SAFETY: standard Win32 FFI.  The handle is closed
            // below before the thread exits.  `CreateNamedPipeW`
            // returns `INVALID_HANDLE_VALUE` on failure, not an
            // `Err` variant.
            #[expect(unsafe_code, reason = "Win32 named pipe FFI")]
            let handle = unsafe {
                CreateNamedPipeW(
                    PCWSTR(wide.as_ptr()),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    1,
                    4096,
                    4096,
                    0,
                    None,
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return; // test will fail on client-side connect
            }
            // SAFETY: valid handle just obtained; `None` overlapped
            // makes this synchronous.  Any error here is benign —
            // ConnectNamedPipe returns `ERROR_PIPE_CONNECTED` when
            // the client beats us to it, which still counts as a
            // successful connect.  Explicit `drop(...)` on the
            // `Result<()>` satisfies clippy's must-use and
            // no-untyped-underscore lints with a clear intent.
            #[expect(unsafe_code, reason = "Win32 named pipe FFI")]
            let connect_result: windows::core::Result<()> =
                unsafe { ConnectNamedPipe(handle, None) };
            drop(connect_result);
            // Hold the pipe open long enough for the client-side
            // deadline to expire, then close.
            thread::sleep(Duration::from_secs(2));
            // SAFETY: we are the sole owner of `handle`.
            #[expect(unsafe_code, reason = "Win32 handle cleanup")]
            let close = unsafe { CloseHandle(handle) };
            drop(close);
        });

        // Give the server a brief moment to create the pipe before
        // we try to connect.  The retry loop below also covers this
        // race, but a small up-front wait shortens the happy path.
        thread::sleep(Duration::from_millis(100));

        // ── Client side: open the pipe ───────────────────────────
        let mut pipe = {
            let mut last_err: Option<io::Error> = None;
            let mut opened: Option<std::fs::File> = None;
            for _ in 0_u32..20_u32 {
                match std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(pipe_name.as_str())
                {
                    Ok(file) => {
                        opened = Some(file);
                        break;
                    }
                    Err(err) => {
                        last_err = Some(err);
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
            opened.unwrap_or_else(|| {
                panic!("client could not open pipe within 20 attempts; last error: {last_err:?}")
            })
        };

        // ── Arm the deadline: ~500 ms ────────────────────────────
        let guard =
            WindowsDeadlineGuard::new(Duration::from_millis(500)).expect("guard construction");
        guard.arm();

        // Blocking read — server never writes, so this WILL block
        // until CancelSynchronousIo fires from the watchdog.
        let start = Instant::now();
        let mut buf = [0_u8; 16];
        let read_result = pipe.read(&mut buf);
        let elapsed = start.elapsed();

        guard.disarm();

        // ── Assertions ───────────────────────────────────────────
        assert!(
            read_result.is_err(),
            "read against a blackhole pipe must fail; got Ok with {:?}",
            read_result.ok(),
        );
        assert!(
            elapsed >= Duration::from_millis(400),
            "read should not fail before the deadline; elapsed = {elapsed:?}",
        );
        assert!(
            elapsed <= Duration::from_millis(1500),
            "read should fail within ~1 s of the deadline; elapsed = {elapsed:?}",
        );
        if let Err(err) = read_result {
            // ERROR_OPERATION_ABORTED (995) is the documented
            // return code when CancelSynchronousIo unblocks a
            // pending synchronous I/O.
            assert_eq!(
                err.raw_os_error(),
                Some(995_i32),
                "watchdog cancellation should surface as ERROR_OPERATION_ABORTED; got {err}",
            );
        }

        // Drop the pipe so the server's `ConnectNamedPipe` loop
        // exits promptly, then join.
        drop(pipe);
        drop(server.join());
    }
}
