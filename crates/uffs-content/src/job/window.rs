// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Credit-based backpressure (design-doc §13.1 "Byte-based limits" /
//! §13.2 "Slow consumer").
//!
//! Same mechanism as HTTP/2 stream-level flow control (RFC 7540 §6.9)
//! and TCP's receive-window advertisement: the consumer grants the
//! producer a byte budget up front; the producer consumes budget as it
//! sends `CONTENT_CHUNK` bytes and must stop admitting new read work
//! once the budget is exhausted; a `WINDOW_UPDATE` frame from the
//! consumer raises the ceiling as it frees buffer space. Deliberately
//! independent of `FILE_ACK` (a separate, file-granularity, digest-
//! verified concern — see `crate::job::registry`) — a consumer may grant
//! window credit as soon as it has buffer room, without having verified
//! or durably persisted any specific file yet.

/// Tracks how many bytes the producer may still send before it must
/// pause and wait for a `WINDOW_UPDATE`.
#[cfg_attr(
    not(any(windows, test)),
    expect(
        dead_code,
        reason = "only constructed by the Windows-only `serve` module's streaming \
                  task in production; exercised cross-platform by this module's own \
                  unit tests, which is why the type still lives here rather than \
                  behind `#[cfg(windows)]`"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WindowTracker {
    /// Total bytes ever granted: the initial negotiated
    /// `max_unacknowledged_bytes` plus every `WINDOW_UPDATE` grant since.
    granted_bytes: u64,
    /// Total bytes sent so far.
    sent_bytes: u64,
}

#[cfg_attr(
    not(any(windows, test)),
    expect(dead_code, reason = "see the `WindowTracker` doc comment above")
)]
impl WindowTracker {
    /// A new tracker starting with `initial_window_bytes` of budget
    /// (the negotiated `max_unacknowledged_bytes`).
    pub(crate) const fn new(initial_window_bytes: u64) -> Self {
        Self {
            granted_bytes: initial_window_bytes,
            sent_bytes: 0,
        }
    }

    /// Bytes still available to send before the window is exhausted.
    pub(crate) const fn available(&self) -> u64 {
        self.granted_bytes.saturating_sub(self.sent_bytes)
    }

    /// Whether `bytes` more may be sent without exceeding the current
    /// window.
    pub(crate) const fn can_admit(&self, bytes: u64) -> bool {
        bytes <= self.available()
    }

    /// Record that `bytes` were just sent (now counted against the
    /// window until a matching `WINDOW_UPDATE` arrives).
    pub(crate) const fn record_sent(&mut self, bytes: u64) {
        self.sent_bytes = self.sent_bytes.saturating_add(bytes);
    }

    /// Apply a `WINDOW_UPDATE { additional_window_bytes }` frame,
    /// raising the ceiling.
    pub(crate) const fn grant(&mut self, additional_window_bytes: u64) {
        self.granted_bytes = self.granted_bytes.saturating_add(additional_window_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::WindowTracker;

    #[test]
    fn fresh_tracker_has_the_full_initial_window_available() {
        let tracker = WindowTracker::new(1000);
        assert_eq!(tracker.available(), 1000);
        assert!(tracker.can_admit(1000));
        assert!(!tracker.can_admit(1001));
    }

    #[test]
    fn sending_bytes_reduces_availability() {
        let mut tracker = WindowTracker::new(1000);
        tracker.record_sent(400);
        assert_eq!(tracker.available(), 600);
        assert!(tracker.can_admit(600));
        assert!(!tracker.can_admit(601));
    }

    #[test]
    fn exhausting_the_window_admits_nothing_further() {
        let mut tracker = WindowTracker::new(500);
        tracker.record_sent(500);
        assert_eq!(tracker.available(), 0);
        assert!(!tracker.can_admit(1));
        assert!(tracker.can_admit(0));
    }

    #[test]
    fn window_update_raises_the_ceiling() {
        let mut tracker = WindowTracker::new(500);
        tracker.record_sent(500);
        assert_eq!(tracker.available(), 0);
        tracker.grant(300);
        assert_eq!(tracker.available(), 300);
        assert!(tracker.can_admit(300));
        assert!(!tracker.can_admit(301));
    }

    #[test]
    fn sent_bytes_never_underflow_available_below_zero() {
        // Sending exactly up to the ceiling, never past it (can_admit is
        // the caller's contract to honor), leaves available() at exactly
        // zero rather than wrapping.
        let mut tracker = WindowTracker::new(100);
        tracker.record_sent(100);
        assert_eq!(tracker.available(), 0);
    }

    #[test]
    fn multiple_grants_accumulate() {
        let mut tracker = WindowTracker::new(0);
        assert_eq!(tracker.available(), 0);
        tracker.grant(100);
        tracker.grant(50);
        assert_eq!(tracker.available(), 150);
    }
}
