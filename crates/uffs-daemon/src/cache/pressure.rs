// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Process-level memory-pressure signal pipeline (Phase 5 task 5.3).
//!
//! Cooperates with Windows's
//! [`MEMORY_RESOURCE_NOTIFICATION_TYPE`][win32-mem]:
//! `LowMemoryResourceNotification` fires when free RAM drops below the
//! kernel's threshold; `HighMemoryResourceNotification` fires when it
//! rises back above.  The daemon's subscriber loop translates `Low`
//! into a cascade demote of LRU Warm shards
//! (see [`crate::index::IndexManager::cascade_demote_one_step`])
//! until either the registry has no Warm shards left or `High` arrives.
//!
//! On Windows, [`PlatformPressureSignal::new`] spawns a dedicated
//! kernel thread (`uffs-pressure`) that owns the two notification
//! handles plus a manual-reset shutdown event.  Its main loop calls
//! `WaitForMultipleObjects` with `INFINITE` and translates the
//! signaled handle into a `PressureLevel::Low` / `PressureLevel::High`
//! send on the inner [`watch::Sender`].  On `Drop`, the struct
//! signals the shutdown event, joins the watcher, and closes the
//! handles.  Handle-creation failure (very old or stripped Windows
//! editions, or handle exhaustion at startup) is logged at warn-level
//! and the signal degrades to "never-fires" — the daemon falls back
//! to TTL-driven demotion alone.
//!
//! Mac/Linux ship a never-fires stub — there is no portable
//! process-wide notification API on those targets and the kernel
//! handles reclaim itself; demotions are TTL-driven via
//! [`crate::index::IndexManager::demote_idle_shards`].
//!
//! ## Wire shape
//!
//! [`IndexManager`][im] holds the trait as
//! `Arc<dyn PressureSignal>`.  Production wires
//! [`PlatformPressureSignal`]; the Phase 5 unit tests inject
//! `tests::ControllablePressureSignal` so the test can `set(Low)` /
//! `set(High)` and assert the cascade behaviour deterministically
//! without any real OS pressure.
//!
//! The signal is delivered as a [`tokio::sync::watch::Receiver`]
//! returned by [`PressureSignal::subscribe`].  `watch` is the right
//! primitive here: it carries the *latest* value (so a subscriber
//! that joined late still sees the current pressure level) and
//! `changed().await` only wakes on transitions.  Multiple subscribers
//! are supported but the production daemon only needs one (in
//! `lib.rs::spawn_pressure_subscriber`).
//!
//! [im]: crate::index::IndexManager
//! [win32-mem]: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-creatememoryresourcenotification

use tokio::sync::watch;

/// Memory-pressure level reported by [`PressureSignal::subscribe`].
///
/// `Normal` is always present — it's the initial value before any
/// notification arrives and the steady state on every platform.
/// `Low` and `High` are **platform-conditional** — they only exist
/// on Windows (where the kernel's
/// `LowMemoryResourceNotification` / `HighMemoryResourceNotification`
/// surface them via `windows_handles::watcher_loop`) and under
/// `cfg(test)` (so `tests::ControllablePressureSignal` can drive
/// deterministic transitions on every host).  Mac/Linux production
/// builds expose only `Normal`: there is no portable process-wide
/// memory-resource-notification API on those targets, and the
/// kernel handles reclaim itself — demotion is TTL-driven via
/// [`crate::index::IndexManager::demote_idle_shards`] alone.
///
/// Consumers that want to react to `Low` should use
/// [`Self::requires_cascade_demote`] rather than pattern-matching
/// the variant directly — the method has platform-specific
/// implementations that compile cleanly on Mac/Linux production
/// builds (where `Low` does not exist) and short-circuit to the
/// correct answer (`false`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PressureLevel {
    /// No pressure signal yet, or steady state.  Subscriber takes no
    /// action.
    Normal,
    /// Free RAM has fallen below the kernel's low-memory threshold.
    /// Subscriber cascade-demotes LRU Warm shards.
    ///
    /// Only present on Windows production builds (constructed by
    /// `windows_handles::watcher_loop`) and under `cfg(test)`
    /// (constructed by `tests::ControllablePressureSignal`).
    #[cfg(any(target_os = "windows", test))]
    Low,
    /// Free RAM has risen back above the kernel's high-memory
    /// threshold; pressure cleared.  Subscriber stops the cascade.
    ///
    /// Only present on Windows production builds (constructed by
    /// `windows_handles::watcher_loop`) and under `cfg(test)`
    /// (constructed by `tests::ControllablePressureSignal`).
    #[cfg(any(target_os = "windows", test))]
    High,
}

impl PressureLevel {
    /// Returns `true` when this level should drive the daemon's
    /// cascade-demote loop.
    ///
    /// On Windows production / under `cfg(test)`: returns `true`
    /// for `Self::Low` and `false` otherwise.  On Mac/Linux
    /// production builds the only constructible variant is
    /// [`Self::Normal`], so this method always returns `false`
    /// — the platform-gated `match` arm below evaluates only
    /// when `Self::Low` exists.
    ///
    /// Used by `lib.rs::spawn_pressure_subscriber` so the
    /// subscriber loop body stays portable across every target
    /// without spreading `#[cfg]` gates through the daemon's main
    /// runtime path.
    pub(crate) const fn requires_cascade_demote(self) -> bool {
        match self {
            #[cfg(any(target_os = "windows", test))]
            Self::Low => true,
            _ => false,
        }
    }
}

/// Process-level memory-pressure subscriber.
///
/// Implementations are held as `Arc<dyn PressureSignal>` on
/// [`crate::index::IndexManager`].  The daemon's
/// `spawn_pressure_subscriber` calls [`Self::subscribe`] to get a
/// [`watch::Receiver`] and reacts to transitions.
///
/// Implementors must be `Send + Sync + 'static` to satisfy the
/// `Arc<dyn ...>` bound.
pub(crate) trait PressureSignal: Send + Sync + 'static {
    /// Subscribe to pressure-level transitions.
    ///
    /// The returned receiver carries the *current* pressure value
    /// (so a late subscriber still sees the right state) and
    /// `changed().await` wakes on every transition.  Multiple
    /// subscribers are supported.
    fn subscribe(&self) -> watch::Receiver<PressureLevel>;
}

/// Production pressure-signal implementation.
///
/// On Windows: [`Self::new`] creates handles for the kernel's
/// `LowMemoryResourceNotification` and `HighMemoryResourceNotification`
/// notifications plus a manual-reset shutdown event, then spawns a
/// dedicated kernel thread that translates kernel notifications into
/// `PressureLevel::Low` / `PressureLevel::High` sends on the inner
/// [`watch::Sender`].  On Mac/Linux: never-fires sender held
/// internally — receivers always see [`PressureLevel::Normal`] and
/// `changed()` never returns.
///
/// Phase 5 task 5.3 — paired with the Phase 5 dogfood gate
/// "stress test … daemon log shows `cache.pressure { level: \"Low\" }`
/// and demotion cascade".
pub(crate) struct PlatformPressureSignal {
    /// The watch sender held internally.  On Mac/Linux nothing ever
    /// `send`s on this; on Windows the watcher thread does.
    /// Holding the sender keeps the channel open for as long as the
    /// `IndexManager` lives, even when no subscriber is currently
    /// attached (e.g. during the brief startup window before
    /// `spawn_pressure_subscriber` runs).
    sender: watch::Sender<PressureLevel>,
    /// Manual-reset event signaled by [`Drop::drop`] to break the
    /// watcher thread out of `WaitForMultipleObjects`.  `None` when
    /// handle creation failed at startup and we degraded to dormant
    /// mode (the daemon falls back to TTL-driven demotion alone).
    #[cfg(target_os = "windows")]
    shutdown_event: Option<windows_handles::OwnedHandle>,
    /// Watcher thread join handle; consumed in [`Drop::drop`] after
    /// signaling shutdown.  `None` when handle creation failed at
    /// startup or we are running on a non-Windows platform.
    #[cfg(target_os = "windows")]
    watcher_thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(not(target_os = "windows"))]
impl PlatformPressureSignal {
    /// Create a never-fires pressure signal for Mac/Linux.
    ///
    /// The watch channel is initialised at [`PressureLevel::Normal`]
    /// and stays there forever — there is no portable process-wide
    /// notification API on these targets.  The daemon's
    /// `spawn_pressure_subscriber` will simply park on
    /// `changed().await` and never wake; demotion happens via
    /// [`crate::index::IndexManager::demote_idle_shards`] alone.
    #[must_use]
    pub(crate) fn new() -> Self {
        let (sender, _initial_rx) = watch::channel(PressureLevel::Normal);
        Self { sender }
    }
}

#[cfg(target_os = "windows")]
impl PlatformPressureSignal {
    /// Create a Windows pressure signal and spawn the Win32 watcher
    /// thread.
    ///
    /// Best-effort: if any kernel handle creation fails or the
    /// `std::thread::spawn` fails, the signal degrades to
    /// "never-fires" (equivalent to the Mac/Linux stub) and a
    /// warn-level log line is emitted.  This keeps the daemon
    /// resilient against stripped Windows editions or transient
    /// resource exhaustion at startup — the cascade demote is a
    /// *best-effort optimisation* on top of the always-available
    /// TTL-driven demotion path.
    #[must_use]
    pub(crate) fn new() -> Self {
        let (sender, _initial_rx) = watch::channel(PressureLevel::Normal);
        match windows_handles::spawn_watcher(sender.clone()) {
            Ok((shutdown_event, watcher_thread)) => Self {
                sender,
                shutdown_event: Some(shutdown_event),
                watcher_thread: Some(watcher_thread),
            },
            Err(err) => {
                tracing::warn!(
                    target: "cache.pressure",
                    error = %err,
                    "Win32 memory-resource-notification setup failed; \
                     pressure pipeline degraded to never-fires — daemon \
                     falls back to TTL-driven demotion alone",
                );
                Self {
                    sender,
                    shutdown_event: None,
                    watcher_thread: None,
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for PlatformPressureSignal {
    /// Signal the watcher thread to exit and join it.
    ///
    /// Order is critical: we **must** signal the shutdown event
    /// **before** joining, otherwise the watcher's
    /// `WaitForMultipleObjects` never returns and `join()` hangs.
    /// We **must** join **before** the `shutdown_event` field's
    /// own `Drop` (which closes the kernel handle) runs, otherwise
    /// the watcher would race against a closed handle value.  Rust
    /// runs this manual `Drop::drop` first, then field `Drop`s in
    /// declaration order — so the sequence is guaranteed.
    fn drop(&mut self) {
        if let Some(shutdown) = &self.shutdown_event {
            windows_handles::signal_shutdown(shutdown);
        }
        if let Some(handle) = self.watcher_thread.take()
            && let Err(payload) = handle.join()
        {
            tracing::warn!(
                target: "cache.pressure",
                "Pressure watcher thread panicked: {payload:?}",
            );
        }
        // shutdown_event drops automatically here, closing the
        // kernel handle exactly once via OwnedHandle's Drop.
    }
}

impl Default for PlatformPressureSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl PressureSignal for PlatformPressureSignal {
    fn subscribe(&self) -> watch::Receiver<PressureLevel> {
        self.sender.subscribe()
    }
}

#[cfg(target_os = "windows")]
mod windows_handles {
    //! Win32 watcher thread + kernel-handle ownership for
    //! [`super::PlatformPressureSignal`].
    //!
    //! Encapsulates every `unsafe` FFI call so the surrounding module
    //! stays free of `unsafe { \u2026 }` blocks.  Each call site has a
    //! tightly-scoped `#[expect(unsafe_code, reason = "\u2026")]` plus a
    //! SAFETY comment explaining why the kernel contract is upheld.

    use std::io;

    use tokio::sync::watch;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Memory::{
        CreateMemoryResourceNotification, HighMemoryResourceNotification,
        LowMemoryResourceNotification, MEMORY_RESOURCE_NOTIFICATION_TYPE,
    };
    use windows::Win32::System::Threading::{
        CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects,
    };
    use windows::core::PCWSTR;

    use super::PressureLevel;

    /// Owns a Win32 kernel handle; closes it on `Drop`.
    ///
    /// Single-ownership wrapper that ensures `CloseHandle` is called
    /// exactly once even if the owner panics.
    pub(super) struct OwnedHandle(HANDLE);

    #[expect(
        unsafe_code,
        reason = "HANDLE is a thread-safe kernel-object reference"
    )]
    // SAFETY: HANDLE is an opaque kernel-object reference (an
    // `isize`-sized identifier); the kernel arbitrates concurrent
    // access to the underlying object and Win32 APIs that take
    // handles are documented as thread-safe.  We only ever pass
    // the value across threads, never share Rust-level mutability
    // — the only mutation site is `Drop::drop` which takes
    // `&mut self`, so `&OwnedHandle` shared between threads is
    // race-free.
    unsafe impl Send for OwnedHandle {}
    #[expect(
        unsafe_code,
        reason = "HANDLE is a thread-safe kernel-object reference"
    )]
    // SAFETY: same rationale as `OwnedHandle: Send` — see immediately
    // above.  Sync is sound because the only mutation site
    // (`Drop::drop`) takes `&mut self`, so shared `&OwnedHandle`
    // observers across threads cannot race against the close.
    unsafe impl Sync for OwnedHandle {}

    impl OwnedHandle {
        /// Borrow the wrapped Win32 handle for use in syscalls that
        /// take a `HANDLE` by value (e.g. `WaitForMultipleObjects`).
        ///
        /// The returned `HANDLE` is a Copy bit-pattern — callers must
        /// **not** close it; ownership stays with `self` and the
        /// underlying kernel handle is released exactly once via
        /// its own `Drop`.
        const fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                #[expect(unsafe_code, reason = "Win32 CloseHandle FFI for handle cleanup")]
                // SAFETY: `self.0` is a valid handle returned by a
                // Win32 `Create*`-family API and not yet closed
                // (single-ownership invariant).  `CloseHandle` is
                // sync and the documented Win32 idiom for releasing
                // handles.  Errors are debug-logged — we are already
                // in `Drop` and have no useful recovery beyond
                // visibility.
                let close_result = unsafe { CloseHandle(self.0) };
                if let Err(err) = close_result {
                    tracing::debug!(
                        target: "cache.pressure",
                        err = ?err,
                        "CloseHandle failed in OwnedHandle::Drop",
                    );
                }
            }
        }
    }

    /// Value-copy of a `HANDLE` that is safe to send across threads.
    ///
    /// Used by [`watcher_loop`] to receive a borrowed reference to
    /// the shutdown event whose [`OwnedHandle`] lives in
    /// [`super::PlatformPressureSignal`].  The watcher must **not**
    /// close this handle — the owner does so in its `Drop` after
    /// joining the watcher thread.
    #[derive(Clone, Copy)]
    struct SendableHandle(HANDLE);

    #[expect(
        unsafe_code,
        reason = "HANDLE is a thread-safe kernel-object reference"
    )]
    // SAFETY: same rationale as `OwnedHandle: Send` — HANDLE values
    // are kernel-arbitrated identifiers, safe to pass across threads.
    unsafe impl Send for SendableHandle {}

    /// Signal the shutdown event so the watcher thread breaks out
    /// of `WaitForMultipleObjects`.
    pub(super) fn signal_shutdown(shutdown: &OwnedHandle) {
        // SAFETY: shutdown is a valid handle owned by the caller;
        // SetEvent is sync, takes no ownership, and is the
        // documented Win32 idiom for signaling a manual-reset
        // event.  Errors are logged but never propagated — we are
        // called from Drop and propagating a panic here aborts the
        // process.
        #[expect(unsafe_code, reason = "Win32 SetEvent FFI for shutdown signaling")]
        let result = unsafe { SetEvent(shutdown.raw()) };
        if let Err(err) = result {
            tracing::warn!(
                target: "cache.pressure",
                error = %err,
                "Failed to signal pressure-watcher shutdown event",
            );
        }
    }

    /// Spawn the watcher thread and return owned handles.
    ///
    /// On success, returns `(shutdown_event, join_handle)`.  On
    /// failure (handle exhaustion, thread spawn failure, stripped
    /// Windows edition), returns the underlying `io::Error` and any
    /// partially-created handles are closed via `OwnedHandle::Drop`.
    pub(super) fn spawn_watcher(
        sender: watch::Sender<PressureLevel>,
    ) -> io::Result<(OwnedHandle, std::thread::JoinHandle<()>)> {
        let low = create_memory_resource_notification(LowMemoryResourceNotification)?;
        let high = create_memory_resource_notification(HighMemoryResourceNotification)?;
        let shutdown = create_manual_reset_event()?;
        let shutdown_value = SendableHandle(shutdown.raw());

        let thread = std::thread::Builder::new()
            .name("uffs-pressure".to_owned())
            .spawn(move || {
                watcher_loop(low, high, shutdown_value, sender);
            })
            .map_err(|err| {
                io::Error::other(format!("failed to spawn pressure watcher thread: {err}"))
            })?;

        Ok((shutdown, thread))
    }

    /// Watcher thread main loop.
    ///
    /// Owns `low` + `high` notification handles (closed on thread
    /// exit via `OwnedHandle::Drop`).  Borrows the shutdown handle's
    /// value — the owning `OwnedHandle` lives in
    /// [`super::PlatformPressureSignal`] and closes it on its own
    /// `Drop` *after* this thread has joined.
    ///
    /// State machine: a `Low` notification means we transition to
    /// the Low pressure level; subsequent waits ignore further Low
    /// signals (the kernel keeps the event set until memory
    /// recovers) and listen only for High.  Symmetric for High.
    /// Initial `Normal` waits for either.  Index 0 is always the
    /// shutdown event so a clean exit preempts pressure transitions.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "watcher_loop takes ownership of `low` / `high` / `sender` for the \
                  thread's lifetime: the OwnedHandles must be closed exactly once via \
                  Drop on thread exit, and the watch sender must outlive the loop so \
                  every iteration can broadcast.  Passing by reference would force \
                  the spawn site to hold borrows across the join, breaking the \
                  ownership-transfer pattern"
    )]
    fn watcher_loop(
        low: OwnedHandle,
        high: OwnedHandle,
        shutdown: SendableHandle,
        sender: watch::Sender<PressureLevel>,
    ) {
        let mut current = PressureLevel::Normal;
        loop {
            let handles = compute_handle_set(current, &low, &high, shutdown);
            let signaled_index = wait_for_signal(&handles);
            match interpret_signal(current, signaled_index, handles.len()) {
                SignalAction::Exit => return,
                SignalAction::Transition(next_level) => {
                    current = next_level;
                    broadcast_pressure_change(&sender, next_level);
                }
            }
        }
    }

    /// Build the per-level `WaitForMultipleObjects` handle slice.
    ///
    /// Index 0 is always the shutdown event so a clean exit
    /// preempts pressure transitions.  At `Normal`, both Low and
    /// High notification handles are included; once a transition
    /// fires the kernel keeps the source event set until memory
    /// recovers, so subsequent waits drop the redundant handle and
    /// listen only for the opposite transition.
    fn compute_handle_set(
        current: PressureLevel,
        low: &OwnedHandle,
        high: &OwnedHandle,
        shutdown: SendableHandle,
    ) -> Vec<HANDLE> {
        match current {
            PressureLevel::Normal => vec![shutdown.0, low.raw(), high.raw()],
            PressureLevel::Low => vec![shutdown.0, high.raw()],
            PressureLevel::High => vec![shutdown.0, low.raw()],
        }
    }

    /// Block on `WaitForMultipleObjects(handles, bWaitAll = false,
    /// INFINITE)` and return the raw `WAIT_OBJECT_<n>` index.
    ///
    /// Returns the raw `u32` so [`interpret_signal`] can dispatch
    /// without knowing about the Win32 result type.  Out-of-range
    /// values (`WAIT_FAILED` / `WAIT_TIMEOUT` / `WAIT_ABANDONED`)
    /// flow through unchanged so the caller can warn and exit the
    /// watcher cleanly.
    fn wait_for_signal(handles: &[HANDLE]) -> u32 {
        #[expect(unsafe_code, reason = "Win32 WaitForMultipleObjects FFI")]
        // SAFETY: `handles` is a non-null aligned slice of valid
        // HANDLE values; all handles are kept alive by the
        // OwnedHandle bindings in `watcher_loop` and the borrowed-
        // but-owned-by-caller shutdown event.  `INFINITE` is safe —
        // the caller signals shutdown via `SetEvent` to release the
        // wait.  `bWaitAll = false` so the call returns as soon as
        // any one handle signals.
        let result = unsafe { WaitForMultipleObjects(handles, false, INFINITE) };
        result.0
    }

    /// Translate a `WaitForMultipleObjects` index into a watcher
    /// loop control-flow decision.
    ///
    /// Index 0 is always shutdown.  Indices `1..max_index` are
    /// pressure-event signals; their meaning depends on the current
    /// pressure level (the handle slice changes shape across
    /// levels).  Out-of-range values (`WAIT_FAILED`, `WAIT_TIMEOUT`,
    /// `WAIT_ABANDONED`) and impossible state combinations both
    /// resolve to `Exit` after a warn-log.
    fn interpret_signal(
        current: PressureLevel,
        signaled_index: u32,
        max_index: usize,
    ) -> SignalAction {
        if signaled_index == 0 {
            tracing::debug!(
                target: "cache.pressure",
                "Pressure watcher exiting on shutdown signal",
            );
            return SignalAction::Exit;
        }
        if (signaled_index as usize) >= max_index {
            tracing::warn!(
                target: "cache.pressure",
                code = signaled_index,
                "WaitForMultipleObjects returned unexpected code; \
                 pressure watcher exiting",
            );
            return SignalAction::Exit;
        }
        match (current, signaled_index) {
            (PressureLevel::Normal | PressureLevel::High, 1) => {
                SignalAction::Transition(PressureLevel::Low)
            }
            (PressureLevel::Normal, 2) | (PressureLevel::Low, 1) => {
                SignalAction::Transition(PressureLevel::High)
            }
            _ => {
                tracing::warn!(
                    target: "cache.pressure",
                    index = signaled_index,
                    state = ?current,
                    "Pressure watcher saw unexpected handle index for current state",
                );
                SignalAction::Exit
            }
        }
    }

    /// Broadcast a pressure-level change to every subscriber and
    /// emit the operator-visible info log.
    ///
    /// `send_replace` never fails — it stores the value
    /// unconditionally and notifies any receivers in place.  We
    /// discard the previous value (subscribers track via
    /// `changed()` + `borrow_and_update`).
    fn broadcast_pressure_change(sender: &watch::Sender<PressureLevel>, next_level: PressureLevel) {
        let _previous = sender.send_replace(next_level);
        tracing::info!(
            target: "cache.pressure",
            level = ?next_level,
            "Memory resource notification fired",
        );
    }

    /// Control-flow result of [`interpret_signal`].
    enum SignalAction {
        /// Exit the watcher loop — either a clean shutdown signal
        /// or an unrecoverable wait failure.
        Exit,
        /// Transition the watcher's tracked pressure level.  The
        /// caller updates `current`, broadcasts via
        /// [`broadcast_pressure_change`], and re-enters the wait.
        Transition(PressureLevel),
    }

    /// Create a Win32 memory-resource-notification handle for the
    /// given notification type (`Low` or `High`).
    ///
    /// Wraps [`CreateMemoryResourceNotification`] and returns the
    /// resulting `HANDLE` boxed in an [`OwnedHandle`] so the watcher
    /// thread closes it exactly once on exit via its own `Drop`.
    /// Maps any windows-rs error into
    /// `io::Error::other` so the surrounding orchestrator's error
    /// path stays platform-agnostic.
    fn create_memory_resource_notification(
        notification_type: MEMORY_RESOURCE_NOTIFICATION_TYPE,
    ) -> io::Result<OwnedHandle> {
        // SAFETY: CreateMemoryResourceNotification is a kernel API
        // returning `Result<HANDLE>`.  Passing one of the two
        // documented MEMORY_RESOURCE_NOTIFICATION_TYPE values
        // (Low/High) is the documented contract.  The returned
        // handle is owned by the caller and must be closed via
        // CloseHandle — handled by OwnedHandle::Drop.
        #[expect(unsafe_code, reason = "Win32 CreateMemoryResourceNotification FFI")]
        let handle = unsafe { CreateMemoryResourceNotification(notification_type) }
            .map_err(|err| io::Error::other(err.to_string()))?;
        Ok(OwnedHandle(handle))
    }

    /// Create an unnamed manual-reset Win32 event handle.
    ///
    /// Used as the watcher thread's shutdown signal: the owning
    /// [`super::PlatformPressureSignal`]'s own `Drop` calls
    /// [`signal_shutdown`] (which pulses `SetEvent`) so the next
    /// `WaitForMultipleObjects` returns and the thread exits.  The
    /// returned [`OwnedHandle`] closes the event on its own `Drop`
    /// after the watcher has joined.
    fn create_manual_reset_event() -> io::Result<OwnedHandle> {
        // SAFETY: CreateEventW with (None, manual_reset = true,
        // initial_state = false, name = NULL) creates a private
        // unnamed manual-reset event whose ownership is transferred
        // to the caller.  OwnedHandle::Drop closes the handle.
        #[expect(unsafe_code, reason = "Win32 CreateEventW FFI for shutdown event")]
        let handle = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
            .map_err(|err| io::Error::other(err.to_string()))?;
        Ok(OwnedHandle(handle))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{PressureLevel, PressureSignal, watch};

    /// Phase 5 task 5.10 fake.  Holds the watch sender so tests can
    /// broadcast pressure transitions deterministically and assert
    /// the daemon's cascade-demote behaviour without any real OS
    /// pressure.
    ///
    /// `set(level)` is a thin wrapper over [`watch::Sender::send_replace`]
    /// (rather than [`watch::Sender::send`]) so the stored value is
    /// **always** updated even when no subscribers are attached.
    /// `send` returns `Err` and leaves the slot untouched when
    /// `receiver_count() == 0`, which would silently drop the
    /// transition for late subscribers — defeating the late-attach
    /// contract that this fake is designed to model.
    pub(crate) struct ControllablePressureSignal {
        sender: watch::Sender<PressureLevel>,
    }

    impl ControllablePressureSignal {
        pub(crate) fn new() -> Self {
            let (sender, _initial_rx) = watch::channel(PressureLevel::Normal);
            Self { sender }
        }

        /// Broadcast a new pressure level.  Always stores the value
        /// (so a future subscriber will see it on first
        /// `borrow_and_update`).  Returns `true` when at least one
        /// subscriber was attached at the time of the call (and
        /// therefore observed the transition); `false` otherwise.
        ///
        /// The `receiver_count` read is racy under concurrent
        /// subscribe/drop, but tests using this fake drive the
        /// timeline serially so the read is sufficient.
        pub(crate) fn set(&self, level: PressureLevel) -> bool {
            let had_receivers = self.sender.receiver_count() > 0;
            // `send_replace` never fails — it stores the value
            // unconditionally and notifies any receivers in place.
            // We discard the previous value (the test fake doesn't
            // need it; production never calls `set`).
            let _previous = self.sender.send_replace(level);
            had_receivers
        }

        /// Number of currently attached subscribers.  Used by the
        /// 5.10 test to spin until the daemon's
        /// `spawn_pressure_subscriber` has called `subscribe()`
        /// before broadcasting the first `Low` transition.
        pub(crate) fn receiver_count(&self) -> usize {
            self.sender.receiver_count()
        }
    }

    impl PressureSignal for ControllablePressureSignal {
        fn subscribe(&self) -> watch::Receiver<PressureLevel> {
            self.sender.subscribe()
        }
    }

    /// Smoke-test the production stub on Mac/Linux: a fresh
    /// signal is at `Normal`, `subscribe()` returns a usable
    /// receiver, and `changed().await` would never fire (we
    /// don't actually await it here — that would hang the test).
    #[test]
    fn platform_pressure_signal_initial_value_is_normal() {
        let signal = super::PlatformPressureSignal::new();
        let rx = signal.subscribe();
        assert_eq!(*rx.borrow(), PressureLevel::Normal);
    }

    /// Controllable fake delivers transitions to live subscribers.
    /// Pinned here (not in `index/tests.rs`) so the fake's contract
    /// is colocated with its definition.
    #[tokio::test]
    async fn controllable_pressure_signal_delivers_transitions() {
        let signal = ControllablePressureSignal::new();
        let mut rx = signal.subscribe();

        assert_eq!(*rx.borrow(), PressureLevel::Normal);
        assert_eq!(signal.receiver_count(), 1);

        assert!(signal.set(PressureLevel::Low));
        rx.changed()
            .await
            .expect("watch::Sender still alive — changed() must succeed");
        assert_eq!(*rx.borrow_and_update(), PressureLevel::Low);

        assert!(signal.set(PressureLevel::High));
        rx.changed().await.expect("changed() must succeed");
        assert_eq!(*rx.borrow_and_update(), PressureLevel::High);
    }

    /// Setting a level with no subscribers attached returns `false`
    /// but the latest value is preserved on the channel — a future
    /// subscriber will see it on first `borrow_and_update`.
    #[tokio::test]
    async fn controllable_pressure_signal_preserves_value_for_late_subscribers() {
        let signal = ControllablePressureSignal::new();

        assert_eq!(signal.receiver_count(), 0);
        assert!(
            !signal.set(PressureLevel::Low),
            "no subscribers — send returns false",
        );

        let rx = signal.subscribe();
        assert_eq!(
            *rx.borrow(),
            PressureLevel::Low,
            "late subscriber still sees the most recent value",
        );
    }
}
