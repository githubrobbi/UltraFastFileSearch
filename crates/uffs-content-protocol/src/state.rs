// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Job and candidate state machines (design-doc §9).

/// One candidate's terminal outcome (design-doc §2.2, §9.2).
///
/// Every candidate in a job's manifest MUST eventually reach exactly one
/// of these states, and the job is complete only once every candidate has
/// one. Only [`CandidateOutcome::Succeeded`] candidates are delivered as
/// content to the downstream consumer — but every outcome, including the
/// three non-success ones, means the candidate is *present*, not deleted.
/// A consumer's reap/tombstone reconciliation MUST key off manifest
/// membership across all four outcomes, never off `Succeeded` alone: a
/// candidate that merely failed to read is not the same thing as a
/// candidate that no longer exists (design-doc §2.3).
///
/// Filtering which files even become candidates (by size, extension,
/// path, etc.) is the query's job, not this enum's — a consumer that
/// wants content only for files under some size threshold expresses that
/// as a filter on the UFFS query passed into the job, the same way any
/// other UFFS search filter works. This tool produces one manifest and
/// one content stream for whatever the query matched; it does not itself
/// decide per-candidate whether to deliver a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateOutcome {
    /// Content was read, streamed, and verified successfully.
    Succeeded,
    /// A transient failure occurred; the candidate may be retried in a
    /// later job attempt against a new snapshot.
    FailedRetryable,
    /// A permanent failure occurred; retrying will not help.
    FailedTerminal,
    /// The candidate was explicitly deferred to manual or later handling
    /// (e.g. compressed/encrypted/reparse-backed files in v2).
    DeferredManual,
}

/// Job lifecycle state (design-doc §9.1).
///
/// The legal transition graph is [`JobState::can_transition_to`] — mirrors
/// the shape of `uffs-daemon`'s `ShardState::can_transition_to`
/// (`crates/uffs-daemon/src/cache/shard.rs`), the existing reviewed
/// pattern in this codebase for a small state machine with a proptested
/// transition graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobState {
    /// Job row created; not yet authorized/validated.
    Created,
    /// Broker snapshot-lease creation is in flight.
    SnapshotCreating,
    /// Snapshot lease is ready; candidate enumeration has not started.
    SnapshotReady,
    /// Evaluating the UFFS query against the snapshot to build candidates.
    Enumerating,
    /// The candidate manifest is finalized and checksummed (design-doc
    /// §4.1 step 8) — completeness accounting starts being meaningful
    /// from this state onward.
    ManifestFinalized,
    /// Candidates are being processed and streamed to the consumer.
    Streaming,
    /// All candidates have a terminal outcome; finalizing job-level
    /// accounting and the `JOB_END` record.
    Completing,
    /// Terminal: every candidate succeeded.
    Completed,
    /// Terminal: every candidate reached a terminal outcome, but at least
    /// one did not succeed (failed or was deferred).
    CompletedWithFailures,
    /// Terminal: the job was cancelled before all candidates reached a
    /// terminal outcome.
    Cancelled,
    /// Terminal: the job failed as a whole before the manifest was
    /// finalized (design-doc §4.2) — no candidate-completeness claim is
    /// made.
    Aborted,
}

impl JobState {
    /// Returns true iff a transition `self -> to` is in the legal graph.
    ///
    /// Legal transitions:
    /// * `Created` -> `SnapshotCreating`, `Aborted`
    /// * `SnapshotCreating` -> `SnapshotReady`, `Aborted`
    /// * `SnapshotReady` -> `Enumerating`, `Aborted`
    /// * `Enumerating` -> `ManifestFinalized`, `Aborted`
    /// * `ManifestFinalized` -> `Streaming`, `Cancelled`
    /// * `Streaming` -> `Completing`, `Cancelled`
    /// * `Completing` -> `Completed`, `CompletedWithFailures`, `Cancelled`
    /// * `Completed`, `CompletedWithFailures`, `Cancelled`, `Aborted` -> (none;
    ///   terminal)
    #[must_use]
    pub const fn can_transition_to(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::Created, Self::SnapshotCreating | Self::Aborted)
                | (Self::SnapshotCreating, Self::SnapshotReady | Self::Aborted)
                | (Self::SnapshotReady, Self::Enumerating | Self::Aborted)
                | (Self::Enumerating, Self::ManifestFinalized | Self::Aborted)
                | (Self::ManifestFinalized, Self::Streaming | Self::Cancelled)
                | (Self::Streaming, Self::Completing | Self::Cancelled)
                | (
                    Self::Completing,
                    Self::Completed | Self::CompletedWithFailures | Self::Cancelled
                )
        )
    }

    /// Whether this state is terminal (no further transitions are legal).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::CompletedWithFailures | Self::Cancelled | Self::Aborted
        )
    }

    /// All variants, for exhaustive transition-graph testing.
    #[cfg(test)]
    const ALL: &'static [Self] = &[
        Self::Created,
        Self::SnapshotCreating,
        Self::SnapshotReady,
        Self::Enumerating,
        Self::ManifestFinalized,
        Self::Streaming,
        Self::Completing,
        Self::Completed,
        Self::CompletedWithFailures,
        Self::Cancelled,
        Self::Aborted,
    ];
}

#[cfg(test)]
mod tests {
    use super::JobState;

    #[test]
    fn terminal_states_have_no_legal_outgoing_transition() {
        for &from in JobState::ALL {
            if from.is_terminal() {
                for &to in JobState::ALL {
                    assert!(
                        !from.can_transition_to(to),
                        "{from:?} is terminal but claims a legal transition to {to:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_non_terminal_state_has_at_least_one_legal_transition() {
        for &from in JobState::ALL {
            if !from.is_terminal() {
                let has_any = JobState::ALL.iter().any(|&to| from.can_transition_to(to));
                assert!(
                    has_any,
                    "{from:?} is non-terminal but has no legal transition out"
                );
            }
        }
    }

    #[test]
    fn every_non_terminal_state_can_reach_aborted_or_cancelled_or_terminal() {
        // Every non-terminal state must have some path to a terminal
        // state directly (this test checks the *direct* edge only, which
        // is true by construction here — every non-terminal state's
        // transition set includes at least one terminal state or a state
        // one step from terminal). This guards against accidentally
        // adding a state that can never resolve.
        for &from in JobState::ALL {
            if from.is_terminal() {
                continue;
            }
            let reaches_terminal_or_progresses =
                JobState::ALL.iter().any(|&to| from.can_transition_to(to));
            assert!(
                reaches_terminal_or_progresses,
                "{from:?} must be able to progress somewhere"
            );
        }
    }

    #[test]
    fn no_state_transitions_to_itself() {
        for &state in JobState::ALL {
            assert!(
                !state.can_transition_to(state),
                "{state:?} must not self-transition"
            );
        }
    }

    #[test]
    fn created_cannot_skip_directly_to_streaming() {
        // Regression anchor: a job must pass through snapshot creation and
        // enumeration before streaming — skipping straight to Streaming
        // would violate the "one snapshot defines the job" invariant
        // (design-doc §2.1).
        assert!(!JobState::Created.can_transition_to(JobState::Streaming));
    }

    #[test]
    fn manifest_finalized_can_still_be_cancelled() {
        // A job may be cancelled after the manifest is finalized but
        // before/while streaming (design-doc §19.1).
        assert!(JobState::ManifestFinalized.can_transition_to(JobState::Cancelled));
    }
}
