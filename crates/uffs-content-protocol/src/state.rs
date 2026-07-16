// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Job and candidate terminal states (scaffold).

/// One candidate's terminal outcome (design-doc §2.2, §9.2).
///
/// Every candidate in a job's manifest MUST eventually reach exactly one
/// of these states, and the job is complete only once every candidate has
/// one. Only [`CandidateOutcome::Succeeded`] candidates are delivered as
/// content to the downstream consumer.
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
