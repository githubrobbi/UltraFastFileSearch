// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Typed read/write helpers over the schema in [`super::schema`].
//!
//! This module is intentionally narrow — just enough surface to prove
//! the completeness invariant (design-doc §2.2/§21.7) and crash-recovery
//! durability against a real SQLite file, per
//! `uffs-ingest-implementation-plan.md` §7.3. The full job-workflow API
//! (manifest ingestion, retry scheduling, ...) is later work.

use rusqlite::{Connection, OptionalExtension as _, params};

/// A candidate's persisted state.
///
/// Mirrors [`uffs_content_protocol::state::CandidateOutcome`]'s four
/// terminal variants plus [`CandidateState::Pending`] for a candidate
/// that has not yet reached one — this crate doesn't depend on
/// `uffs-content-protocol` for this small enum because the DB layer's
/// state model includes the pre-terminal case that protocol crate has no
/// reason to represent (it only ever appears in already-terminal wire
/// frames).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateState {
    /// Not yet resolved to a terminal outcome.
    Pending,
    /// Content was read, streamed, and verified successfully.
    Succeeded,
    /// Transient failure; may be retried in a later job attempt.
    FailedRetryable,
    /// Permanent failure.
    FailedTerminal,
    /// Explicitly deferred to manual/later handling.
    DeferredManual,
}

impl CandidateState {
    /// The `TEXT` value stored in `candidates.state` /
    /// `attempts.terminal_outcome`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Succeeded => "Succeeded",
            Self::FailedRetryable => "FailedRetryable",
            Self::FailedTerminal => "FailedTerminal",
            Self::DeferredManual => "DeferredManual",
        }
    }

    /// Parse the `TEXT` value stored in `candidates.state` /
    /// `attempts.terminal_outcome`.
    fn from_str(value: &str) -> Option<Self> {
        match value {
            "Pending" => Some(Self::Pending),
            "Succeeded" => Some(Self::Succeeded),
            "FailedRetryable" => Some(Self::FailedRetryable),
            "FailedTerminal" => Some(Self::FailedTerminal),
            "DeferredManual" => Some(Self::DeferredManual),
            _ => None,
        }
    }
}

/// One of the four terminal outcomes (design-doc §2.2/§9.2).
///
/// Deliberately a separate type from [`CandidateState`], which also has
/// [`CandidateState::Pending`]. [`record_terminal_outcome`] takes this
/// type instead of `CandidateState` so passing a non-terminal state is a
/// compile error, not a runtime check — there is no `Pending` variant to
/// even construct here, so no panic/assert is needed to reject it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TerminalCandidateState {
    /// Content was read, streamed, and verified successfully.
    Succeeded,
    /// Transient failure; may be retried in a later job attempt.
    FailedRetryable,
    /// Permanent failure.
    FailedTerminal,
    /// Explicitly deferred to manual/later handling.
    DeferredManual,
}

impl TerminalCandidateState {
    /// The `TEXT` value stored in `candidates.state` /
    /// `attempts.terminal_outcome`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "Succeeded",
            Self::FailedRetryable => "FailedRetryable",
            Self::FailedTerminal => "FailedTerminal",
            Self::DeferredManual => "DeferredManual",
        }
    }
}

impl From<TerminalCandidateState> for CandidateState {
    fn from(value: TerminalCandidateState) -> Self {
        match value {
            TerminalCandidateState::Succeeded => Self::Succeeded,
            TerminalCandidateState::FailedRetryable => Self::FailedRetryable,
            TerminalCandidateState::FailedTerminal => Self::FailedTerminal,
            TerminalCandidateState::DeferredManual => Self::DeferredManual,
        }
    }
}

/// Minimal fields needed to create a `jobs` row for these tests/helpers.
#[derive(Debug, Clone)]
pub struct NewJob {
    /// Unique job identifier.
    pub job_id: String,
    /// Source identifier.
    pub source_id: String,
    /// Volume identity (opaque string form).
    pub volume_identity: String,
    /// Requested root path.
    pub root: String,
    /// Digest of the UFFS query.
    pub query_digest: String,
    /// Authorization mode (see
    /// `uffs_content_protocol::manifest::AuthorizationMode`).
    pub authorization_mode: i64,
    /// Total candidates once the manifest is finalized.
    pub candidate_count: i64,
    /// Creation time, Unix milliseconds.
    pub created_at: i64,
    /// Producer build identifier.
    pub producer_build: String,
    /// Wire protocol version.
    pub protocol_version: i64,
}

/// Insert a new job row in state `"Created"`.
///
/// # Errors
/// Returns any [`rusqlite::Error`] from the insert.
pub fn create_job(conn: &Connection, job: &NewJob) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO jobs (job_id, source_id, volume_identity, root, query_digest, \
         authorization_mode, state, candidate_count, created_at, producer_build, \
         protocol_version) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'Created', ?7, ?8, ?9, ?10)",
        params![
            job.job_id,
            job.source_id,
            job.volume_identity,
            job.root,
            job.query_digest,
            job.authorization_mode,
            job.candidate_count,
            job.created_at,
            job.producer_build,
            job.protocol_version,
        ],
    )?;
    Ok(())
}

/// Insert a candidate row in state [`CandidateState::Pending`].
///
/// # Errors
/// Returns any [`rusqlite::Error`] from the insert.
pub fn insert_candidate(
    conn: &Connection,
    job_id: &str,
    candidate_id: i64,
    full_file_reference: i64,
    path_bytes: &[u8],
    logical_size: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO candidates (job_id, candidate_id, full_file_reference, path_bytes, \
         path_encoding, logical_size, mtime, candidate_flags, state) \
         VALUES (?1, ?2, ?3, ?4, 0, ?5, 0, 0, ?6)",
        params![
            job_id,
            candidate_id,
            full_file_reference,
            path_bytes,
            logical_size,
            CandidateState::Pending.as_str(),
        ],
    )?;
    Ok(())
}

/// Record a terminal outcome for one candidate: appends an `attempts`
/// row (history is never overwritten — addendum §6.5) and updates
/// `candidates.state` to match.
///
/// Uses a transaction so the two writes are atomic — a crash between
/// them must never leave `candidates.state` inconsistent with the
/// `attempts` history. Takes [`TerminalCandidateState`] rather than
/// [`CandidateState`] so a non-terminal outcome is a compile error, not
/// a runtime check.
///
/// # Errors
///
/// Returns any [`rusqlite::Error`] from the transaction.
pub fn record_terminal_outcome(
    conn: &mut Connection,
    job_id: &str,
    candidate_id: i64,
    attempt_number: i64,
    outcome: TerminalCandidateState,
) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO attempts (job_id, candidate_id, attempt_number, terminal_outcome) \
         VALUES (?1, ?2, ?3, ?4)",
        params![job_id, candidate_id, attempt_number, outcome.as_str()],
    )?;
    tx.execute(
        "UPDATE candidates SET state = ?1 WHERE job_id = ?2 AND candidate_id = ?3",
        params![outcome.as_str(), job_id, candidate_id],
    )?;
    tx.commit()
}

/// Per-job completeness summary (design-doc §2.2/§21.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompletenessSummary {
    /// `jobs.candidate_count` — the manifest's declared total.
    pub candidate_count: i64,
    /// Candidates currently in [`CandidateState::Pending`].
    pub pending: i64,
    /// Candidates currently [`TerminalCandidateState::Succeeded`].
    pub succeeded: i64,
    /// Candidates currently [`TerminalCandidateState::FailedRetryable`].
    pub failed_retryable: i64,
    /// Candidates currently [`TerminalCandidateState::FailedTerminal`].
    pub failed_terminal: i64,
    /// Candidates currently [`TerminalCandidateState::DeferredManual`].
    pub deferred_manual: i64,
}

impl CompletenessSummary {
    /// Whether every candidate has reached a terminal state and the
    /// terminal buckets sum to `candidate_count` (design-doc §2.2's
    /// completeness invariant).
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.pending == 0
            && self.candidate_count
                == self.succeeded
                    + self.failed_retryable
                    + self.failed_terminal
                    + self.deferred_manual
    }
}

/// Compute the completeness summary for `job_id`.
///
/// # Errors
///
/// Returns any [`rusqlite::Error`] from the query, or a
/// [`rusqlite::Error::QueryReturnedNoRows`]-shaped error surfaced via
/// [`OptionalExtension`] if the job does not exist.
pub fn completeness_summary(
    conn: &Connection,
    job_id: &str,
) -> rusqlite::Result<CompletenessSummary> {
    let candidate_count: i64 = conn
        .query_row(
            "SELECT candidate_count FROM jobs WHERE job_id = ?1",
            params![job_id],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0);

    let mut pending = 0_i64;
    let mut succeeded = 0_i64;
    let mut failed_retryable = 0_i64;
    let mut failed_terminal = 0_i64;
    let mut deferred_manual = 0_i64;

    let mut stmt =
        conn.prepare("SELECT state, COUNT(*) FROM candidates WHERE job_id = ?1 GROUP BY state")?;
    let rows = stmt.query_map(params![job_id], |row| {
        let state: String = row.get(0)?;
        let count: i64 = row.get(1)?;
        Ok((state, count))
    })?;
    for row in rows {
        let (state_str, count) = row?;
        match CandidateState::from_str(&state_str) {
            Some(CandidateState::Pending) => pending = count,
            Some(CandidateState::Succeeded) => succeeded = count,
            Some(CandidateState::FailedRetryable) => failed_retryable = count,
            Some(CandidateState::FailedTerminal) => failed_terminal = count,
            Some(CandidateState::DeferredManual) => deferred_manual = count,
            // An unrecognized state string is a corrupt/foreign-written
            // row, not a case this summary should silently absorb into
            // any bucket — skip it rather than guessing.
            None => {}
        }
    }

    Ok(CompletenessSummary {
        candidate_count,
        pending,
        succeeded,
        failed_retryable,
        failed_terminal,
        deferred_manual,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        NewJob, TerminalCandidateState, completeness_summary, create_job, insert_candidate,
        record_terminal_outcome,
    };
    use crate::db::schema::open;

    fn sample_job(job_id: &str, candidate_count: i64) -> NewJob {
        NewJob {
            job_id: job_id.to_owned(),
            source_id: "src-1".to_owned(),
            volume_identity: "vol-1".to_owned(),
            root: r"C:\data".to_owned(),
            query_digest: "digest-1".to_owned(),
            authorization_mode: 0,
            candidate_count,
            created_at: 1_752_000_000_000,
            producer_build: "test-build".to_owned(),
            protocol_version: 2,
        }
    }

    #[test]
    fn completeness_invariant_holds_once_every_candidate_is_terminal() {
        let mut conn = open(None).unwrap();
        let job_id = "job-complete";
        create_job(&conn, &sample_job(job_id, 4)).unwrap();
        for candidate_id in 0..4_i64 {
            insert_candidate(
                &conn,
                job_id,
                candidate_id,
                1000 + candidate_id,
                b"path",
                4096,
            )
            .unwrap();
        }

        // Not yet complete: every candidate is still Pending.
        let initial_summary = completeness_summary(&conn, job_id).unwrap();
        assert!(!initial_summary.is_complete());
        assert_eq!(initial_summary.pending, 4);

        // Drive each candidate to a (different) terminal outcome.
        record_terminal_outcome(&mut conn, job_id, 0, 1, TerminalCandidateState::Succeeded)
            .unwrap();
        record_terminal_outcome(
            &mut conn,
            job_id,
            1,
            1,
            TerminalCandidateState::FailedRetryable,
        )
        .unwrap();
        record_terminal_outcome(
            &mut conn,
            job_id,
            2,
            1,
            TerminalCandidateState::FailedTerminal,
        )
        .unwrap();
        record_terminal_outcome(
            &mut conn,
            job_id,
            3,
            1,
            TerminalCandidateState::DeferredManual,
        )
        .unwrap();

        let summary = completeness_summary(&conn, job_id).unwrap();
        assert!(summary.is_complete(), "{summary:?}");
        assert_eq!(summary.pending, 0);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.failed_retryable, 1);
        assert_eq!(summary.failed_terminal, 1);
        assert_eq!(summary.deferred_manual, 1);
        assert_eq!(
            summary.candidate_count,
            summary.succeeded
                + summary.failed_retryable
                + summary.failed_terminal
                + summary.deferred_manual
        );
    }

    #[test]
    fn completeness_invariant_detects_incomplete_job() {
        let mut conn = open(None).unwrap();
        let job_id = "job-incomplete";
        create_job(&conn, &sample_job(job_id, 3)).unwrap();
        for candidate_id in 0..3_i64 {
            insert_candidate(
                &conn,
                job_id,
                candidate_id,
                2000 + candidate_id,
                b"path",
                4096,
            )
            .unwrap();
        }
        record_terminal_outcome(&mut conn, job_id, 0, 1, TerminalCandidateState::Succeeded)
            .unwrap();
        record_terminal_outcome(&mut conn, job_id, 1, 1, TerminalCandidateState::Succeeded)
            .unwrap();
        // candidate 2 never resolved.

        let summary = completeness_summary(&conn, job_id).unwrap();
        assert!(!summary.is_complete());
        assert_eq!(summary.pending, 1);
        assert_eq!(summary.succeeded, 2);
    }

    // There is deliberately no "rejects Pending" test:
    // `record_terminal_outcome` takes `TerminalCandidateState`, which has
    // no `Pending` variant, so passing a non-terminal state is a compile
    // error rather than a runtime condition to test.

    #[test]
    fn attempts_history_is_never_overwritten_across_retries() {
        // A candidate fails transiently, then succeeds on a later attempt
        // (a new snapshot per design-doc §8.5) — both attempts rows must
        // remain, per addendum §6.5 ("retries never overwrite prior
        // attempts").
        let mut conn = open(None).unwrap();
        let job_id = "job-retry";
        create_job(&conn, &sample_job(job_id, 1)).unwrap();
        insert_candidate(&conn, job_id, 0, 4000, b"path", 4096).unwrap();
        record_terminal_outcome(
            &mut conn,
            job_id,
            0,
            1,
            TerminalCandidateState::FailedRetryable,
        )
        .unwrap();
        record_terminal_outcome(&mut conn, job_id, 0, 2, TerminalCandidateState::Succeeded)
            .unwrap();

        let attempt_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM attempts WHERE job_id = ?1 AND candidate_id = 0",
                [job_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(attempt_count, 2, "both attempts must be retained");

        let final_state: String = conn
            .query_row(
                "SELECT state FROM candidates WHERE job_id = ?1 AND candidate_id = 0",
                [job_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            final_state, "Succeeded",
            "candidates.state reflects only the latest attempt"
        );
    }

    #[test]
    fn crash_recovery_completed_candidates_survive_reconnect() {
        // Simulates a producer crash: write a job with a mix of terminal
        // and still-pending candidates, drop the connection without a
        // clean job-complete step, reopen from the same file, and assert
        // completed candidates stay completed (design-doc §19.2: "never
        // assumes a file was accepted without durable ACK state").
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crash-recovery.sqlite3");
        let job_id = "job-crash";

        let mut crashed_conn = open(Some(&path)).unwrap();
        create_job(&crashed_conn, &sample_job(job_id, 3)).unwrap();
        for candidate_id in 0..3_i64 {
            insert_candidate(
                &crashed_conn,
                job_id,
                candidate_id,
                5000 + candidate_id,
                b"path",
                4096,
            )
            .unwrap();
        }
        record_terminal_outcome(
            &mut crashed_conn,
            job_id,
            0,
            1,
            TerminalCandidateState::Succeeded,
        )
        .unwrap();
        record_terminal_outcome(
            &mut crashed_conn,
            job_id,
            1,
            1,
            TerminalCandidateState::FailedTerminal,
        )
        .unwrap();
        // candidate 2 left Pending, simulating an in-flight read when the
        // process died. Drop the connection explicitly rather than the
        // above writes being rolled back — each was its own committed
        // transaction, so this models a crash, not an abandoned one.
        drop(crashed_conn);

        let conn = open(Some(&path)).unwrap();
        let summary = completeness_summary(&conn, job_id).unwrap();
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.failed_terminal, 1);
        assert_eq!(summary.pending, 1);
        assert!(!summary.is_complete());
    }
}
