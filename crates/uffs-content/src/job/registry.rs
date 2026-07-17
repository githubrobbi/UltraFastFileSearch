// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! In-memory, per-process job registry: the resume state a `JOB_RESUME`
//! reconnect consults to skip candidates the consumer already
//! acknowledged, instead of re-streaming the whole job.
//!
//! Deliberately **not** durable. This is scoped to the specific gap
//! between two already-decided positions:
//!
//! - [`crate::run`]'s own doc comment: no durable per-candidate ledger, no
//!   crash-recovery reconciliation — a producer-*process* crash means a fresh
//!   job attempt with a fresh VSS snapshot, relying on the consumer's own
//!   content-hash dedup to make re-streaming already- ingested content a no-op.
//! - A live producer process losing its *connection* to the consumer (a
//!   transport blip, the consumer process restarting) is a much more common
//!   event than a producer crash, and re-streaming everything already streamed
//!   and acknowledged before the blip (potentially most of a large job) is
//!   real, avoidable waste — not a correctness requirement, since the
//!   consumer's dedup would absorb it either way.
//!
//! So: while the producer *process* is alive, it keeps this registry in
//! memory; a reconnecting consumer names the `job_id` it wants to
//! resume, and the registry reports which candidates still need
//! streaming. If the producer process itself has died, the registry
//! (and the job with it) is gone — that falls through to the existing,
//! already-decided "start a fresh job" path, unchanged.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// One job's resume-relevant state: which candidate ids exist, and
/// which of them the consumer has already acknowledged.
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
struct ActiveJob {
    /// Every candidate id this job's manifest assigned, in enumeration
    /// order.
    candidate_ids: Vec<u64>,
    /// Candidate ids the consumer has sent `FILE_ACK` for.
    acked: HashSet<u64>,
}

/// Registry of jobs the current producer process is actively serving.
///
/// Cheap to hold for a job's whole lifetime: `acked` is a `HashSet<u64>`,
/// a few bytes per candidate — negligible even for a job with hundreds
/// of thousands of candidates, and nothing here is written to disk.
pub(crate) struct JobRegistry {
    /// Active jobs keyed by `job_id`.
    jobs: Mutex<HashMap<[u8; 16], ActiveJob>>,
}

impl JobRegistry {
    /// An empty registry.
    pub(crate) fn new() -> Self {
        Self {
            jobs: Mutex::new(HashMap::new()),
        }
    }

    /// Register a freshly started job with its full candidate id list.
    /// Replaces any prior registration under the same `job_id` (there
    /// shouldn't be one — job ids are fresh UUIDs per job — but a
    /// pathological duplicate submission overwrites rather than panics).
    #[cfg_attr(
        not(any(windows, test)),
        expect(dead_code, reason = "see the `ActiveJob` doc comment above")
    )]
    pub(crate) fn register(&self, job_id: [u8; 16], candidate_ids: Vec<u64>) {
        let mut jobs = self
            .jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        jobs.insert(job_id, ActiveJob {
            candidate_ids,
            acked: HashSet::new(),
        });
    }

    /// Record a `FILE_ACK` for `candidate_id` under `job_id`.
    ///
    /// Returns `true` if `job_id` is a known, still-registered job
    /// (regardless of whether `candidate_id` was already acked — acking
    /// twice is a harmless no-op, matching the wire protocol's own
    /// idempotency contract).
    #[cfg_attr(
        not(any(windows, test)),
        expect(dead_code, reason = "see the `ActiveJob` doc comment above")
    )]
    pub(crate) fn ack(&self, job_id: [u8; 16], candidate_id: u64) -> bool {
        let mut jobs = self
            .jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(job) = jobs.get_mut(&job_id) else {
            return false;
        };
        job.acked.insert(candidate_id);
        drop(jobs);
        true
    }

    /// Candidate ids for `job_id` that have **not** yet been acked, in
    /// their original enumeration order — what a fresh connection or a
    /// `JOB_RESUME` reconnect should stream. `None` if `job_id` isn't a
    /// currently-registered job (producer restarted, job finished and
    /// was removed, or it was never this producer's job).
    #[cfg_attr(
        not(any(windows, test)),
        expect(dead_code, reason = "see the `ActiveJob` doc comment above")
    )]
    pub(crate) fn pending(&self, job_id: [u8; 16]) -> Option<Vec<u64>> {
        let jobs = self
            .jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let job = jobs.get(&job_id)?;
        let pending_ids: Vec<u64> = job
            .candidate_ids
            .iter()
            .copied()
            .filter(|id| !job.acked.contains(id))
            .collect();
        drop(jobs);
        Some(pending_ids)
    }

    /// Whether every candidate registered for `job_id` has been acked.
    /// `None` if `job_id` isn't currently registered.
    #[cfg_attr(
        not(any(windows, test)),
        expect(dead_code, reason = "see the `ActiveJob` doc comment above")
    )]
    pub(crate) fn is_complete(&self, job_id: [u8; 16]) -> Option<bool> {
        let jobs = self
            .jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let job = jobs.get(&job_id)?;
        let complete = job.candidate_ids.iter().all(|id| job.acked.contains(id));
        drop(jobs);
        Some(complete)
    }

    /// Drop `job_id`'s state — once a job is fully acked (or explicitly
    /// cancelled), there is nothing left to resume.
    #[cfg_attr(
        not(any(windows, test)),
        expect(dead_code, reason = "see the `ActiveJob` doc comment above")
    )]
    pub(crate) fn remove(&self, job_id: [u8; 16]) {
        let mut jobs = self
            .jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        jobs.remove(&job_id);
    }

    /// Whether `job_id` is currently registered (alive in this
    /// producer process).
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "exercised by this module's own unit tests only; no production \
                      call site needs it yet (JOB_RESUME handling keys off \
                      `ServerState::active` instead) — kept because it is the natural \
                      complement to `pending`/`is_complete` and cheap to maintain"
        )
    )]
    pub(crate) fn contains(&self, job_id: [u8; 16]) -> bool {
        let jobs = self
            .jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        jobs.contains_key(&job_id)
    }
}

impl Default for JobRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::JobRegistry;

    const JOB_A: [u8; 16] = [1; 16];
    const JOB_B: [u8; 16] = [2; 16];

    #[test]
    fn unregistered_job_reports_no_pending_and_not_complete() {
        let registry = JobRegistry::new();
        assert_eq!(registry.pending(JOB_A), None);
        assert_eq!(registry.is_complete(JOB_A), None);
        assert!(!registry.contains(JOB_A));
        assert!(!registry.ack(JOB_A, 1));
    }

    #[test]
    fn fresh_registration_has_every_candidate_pending() {
        let registry = JobRegistry::new();
        registry.register(JOB_A, vec![1, 2, 3]);
        assert!(registry.contains(JOB_A));
        assert_eq!(registry.pending(JOB_A), Some(vec![1, 2, 3]));
        assert_eq!(registry.is_complete(JOB_A), Some(false));
    }

    #[test]
    fn acking_a_candidate_removes_it_from_pending() {
        let registry = JobRegistry::new();
        registry.register(JOB_A, vec![1, 2, 3]);
        assert!(registry.ack(JOB_A, 2));
        assert_eq!(registry.pending(JOB_A), Some(vec![1, 3]));
        assert_eq!(registry.is_complete(JOB_A), Some(false));
    }

    #[test]
    fn acking_every_candidate_marks_the_job_complete() {
        let registry = JobRegistry::new();
        registry.register(JOB_A, vec![1, 2]);
        assert!(registry.ack(JOB_A, 1));
        assert!(registry.ack(JOB_A, 2));
        assert_eq!(registry.pending(JOB_A), Some(vec![]));
        assert_eq!(registry.is_complete(JOB_A), Some(true));
    }

    #[test]
    fn acking_the_same_candidate_twice_is_a_harmless_no_op() {
        let registry = JobRegistry::new();
        registry.register(JOB_A, vec![1, 2]);
        assert!(registry.ack(JOB_A, 1));
        assert!(registry.ack(JOB_A, 1));
        assert_eq!(registry.pending(JOB_A), Some(vec![2]));
    }

    #[test]
    fn acking_an_unknown_candidate_id_is_recorded_but_never_appears_pending() {
        // Defends against a malicious/buggy consumer acking an id that
        // was never in the manifest: it's silently absorbed (the ack
        // just never removes anything from `pending`, since `pending`
        // is built from `candidate_ids`, not from `acked`), never
        // fabricates a phantom pending entry.
        let registry = JobRegistry::new();
        registry.register(JOB_A, vec![1, 2]);
        assert!(registry.ack(JOB_A, 999));
        assert_eq!(registry.pending(JOB_A), Some(vec![1, 2]));
    }

    #[test]
    fn jobs_are_independent() {
        let registry = JobRegistry::new();
        registry.register(JOB_A, vec![1, 2]);
        registry.register(JOB_B, vec![10, 20]);
        assert!(registry.ack(JOB_A, 1));
        assert_eq!(registry.pending(JOB_A), Some(vec![2]));
        assert_eq!(registry.pending(JOB_B), Some(vec![10, 20]));
    }

    #[test]
    fn removing_a_job_drops_its_resume_state() {
        let registry = JobRegistry::new();
        registry.register(JOB_A, vec![1, 2]);
        registry.remove(JOB_A);
        assert!(!registry.contains(JOB_A));
        assert_eq!(registry.pending(JOB_A), None);
    }

    #[test]
    fn re_registering_the_same_job_id_replaces_prior_state() {
        let registry = JobRegistry::new();
        registry.register(JOB_A, vec![1, 2]);
        assert!(registry.ack(JOB_A, 1));
        registry.register(JOB_A, vec![5, 6, 7]);
        assert_eq!(registry.pending(JOB_A), Some(vec![5, 6, 7]));
    }
}
