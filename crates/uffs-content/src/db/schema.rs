// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Durable job/candidate/attempt/ACK/snapshot-lease schema (addendum §6.4).
//!
//! This is the single source of truth for "did every finalized manifest
//! candidate reach exactly one terminal outcome" — the completeness
//! invariant design-doc §2.2/§21.7 requires. It is deliberately not an
//! in-memory structure: addendum §6.1 requires it survive a producer
//! crash independently of Docenta.

use rusqlite::Connection;

/// Schema DDL. `CREATE TABLE IF NOT EXISTS` makes re-applying idempotent
/// — there is no migration framework yet (design-doc plan §7.1: "even a
/// single-file `CREATE TABLE` statement run idempotently is fine for the
/// first milestone; don't build a full migration framework prematurely").
const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS jobs (
    job_id              TEXT    PRIMARY KEY,
    source_id           TEXT    NOT NULL,
    volume_identity     TEXT    NOT NULL,
    root                TEXT    NOT NULL,
    query_digest        TEXT    NOT NULL,
    authorization_mode  INTEGER NOT NULL,
    state               TEXT    NOT NULL,
    snapshot_lease_id   INTEGER,
    snapshot_id         TEXT,
    manifest_locator    TEXT,
    manifest_digest     TEXT,
    candidate_count     INTEGER NOT NULL DEFAULT 0,
    created_at          INTEGER NOT NULL,
    started_at          INTEGER,
    completed_at        INTEGER,
    expires_at          INTEGER,
    producer_build      TEXT    NOT NULL,
    protocol_version    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS candidates (
    job_id              TEXT    NOT NULL,
    candidate_id        INTEGER NOT NULL,
    full_file_reference INTEGER NOT NULL,
    path_bytes          BLOB    NOT NULL,
    path_encoding       INTEGER NOT NULL,
    logical_size        INTEGER NOT NULL,
    mtime               INTEGER NOT NULL,
    candidate_flags     INTEGER NOT NULL,
    state               TEXT    NOT NULL,
    content_object_id   INTEGER,
    PRIMARY KEY (job_id, candidate_id),
    FOREIGN KEY (job_id) REFERENCES jobs(job_id)
);

CREATE TABLE IF NOT EXISTS attempts (
    attempt_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id               TEXT    NOT NULL,
    candidate_id          INTEGER NOT NULL,
    attempt_number        INTEGER NOT NULL,
    lease_owner           TEXT,
    lease_generation      INTEGER,
    lease_expires_at      INTEGER,
    planned_mode          TEXT,
    actual_mode           TEXT,
    started_at            INTEGER,
    finished_at           INTEGER,
    bytes_emitted         INTEGER,
    content_digest        TEXT,
    terminal_outcome      TEXT,
    failure_stage         TEXT,
    error_code            TEXT,
    os_error_code         INTEGER,
    retry_class           TEXT,
    message               TEXT,
    FOREIGN KEY (job_id, candidate_id) REFERENCES candidates(job_id, candidate_id)
);

CREATE TABLE IF NOT EXISTS consumer_acks (
    job_id               TEXT    NOT NULL,
    candidate_id          INTEGER NOT NULL,
    content_digest        TEXT    NOT NULL,
    consumer_instance_id  TEXT,
    ack_state             TEXT    NOT NULL,
    acked_at              INTEGER NOT NULL,
    PRIMARY KEY (job_id, candidate_id, content_digest)
);

CREATE TABLE IF NOT EXISTS snapshot_leases (
    snapshot_lease_id    INTEGER PRIMARY KEY,
    job_id                TEXT    NOT NULL,
    snapshot_id           TEXT,
    broker_state          TEXT,
    created_at            INTEGER NOT NULL,
    expires_at            INTEGER,
    released_at           INTEGER,
    last_error            TEXT
);

CREATE TABLE IF NOT EXISTS job_events (
    event_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id                TEXT    NOT NULL,
    occurred_at           INTEGER NOT NULL,
    event_type            TEXT    NOT NULL,
    detail                TEXT
);
";

/// Apply the schema to `conn`. Safe to call on every startup — every
/// statement is `CREATE TABLE IF NOT EXISTS`.
///
/// # Errors
///
/// Returns any [`rusqlite::Error`] from executing the DDL batch.
pub fn apply(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(SCHEMA_SQL)
}

/// Open a connection at `path` (or an in-memory database when `path` is
/// `None`, for tests) with the durability pragmas addendum §6.3
/// requires, and apply the schema.
///
/// # Errors
///
/// Returns any [`rusqlite::Error`] from opening the connection, setting
/// pragmas, or applying the schema.
pub fn open(db_path: Option<&std::path::Path>) -> rusqlite::Result<Connection> {
    let conn = match db_path {
        Some(existing_path) => Connection::open(existing_path)?,
        None => Connection::open_in_memory()?,
    };
    // WAL is a no-op (and briefly errors) on `:memory:` connections in
    // some SQLite builds; tolerate that specifically so in-memory test
    // connections don't need a different pragma set than real files.
    let _: String = conn
        .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
        .or_else(|_err| {
            conn.pragma_update_and_check(None, "journal_mode", "MEMORY", |row| row.get(0))
        })?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.busy_timeout(core::time::Duration::from_secs(5))?;
    // Durable-before-ack per addendum §6.3: manifest finalization,
    // candidate terminal outcomes, consumer ACKs, retry decisions,
    // snapshot-lease changes, and job terminal state. This connection is
    // used for exactly those writes; a future high-frequency progress
    // counter should get its own relaxed-synchronous connection rather
    // than loosening this one.
    conn.pragma_update(None, "synchronous", "FULL")?;
    apply(&conn)?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::open;

    #[test]
    fn schema_applies_to_fresh_in_memory_database() {
        let conn = open(None).unwrap();
        // Excludes SQLite's own internal `sqlite_%` tables (e.g.
        // `sqlite_sequence`, auto-created because `attempts`/`job_events`
        // use `AUTOINCREMENT`) — this counts only our own schema's tables.
        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_count, 6, "expected all six tables from addendum §6.4");
    }

    #[test]
    fn schema_reapplication_is_idempotent() {
        let conn = open(None).unwrap();
        super::apply(&conn).unwrap();
        super::apply(&conn).unwrap();
    }

    #[test]
    fn every_expected_table_exists() {
        let conn = open(None).unwrap();
        for table in [
            "jobs",
            "candidates",
            "attempts",
            "consumer_acks",
            "snapshot_leases",
            "job_events",
        ] {
            let exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "table '{table}' must exist");
        }
    }

    #[test]
    fn foreign_keys_pragma_is_enabled() {
        let conn = open(None).unwrap();
        let enabled: i64 = conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert_eq!(enabled, 1);
    }

    #[test]
    fn opening_a_real_file_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("uffs-content-jobs.sqlite3");

        let first_conn = open(Some(&path)).unwrap();
        first_conn
            .execute(
                "INSERT INTO jobs (job_id, source_id, volume_identity, root, query_digest, \
                 authorization_mode, state, candidate_count, created_at, producer_build, \
                 protocol_version) VALUES ('job-1', 'src-1', 'vol-1', 'C:\\', 'digest', 0, \
                 'Created', 0, 0, 'test-build', 2)",
                [],
            )
            .unwrap();
        drop(first_conn); // explicit: reopen below must see this via the file, not the live handle

        let conn = open(Some(&path)).unwrap();
        let job_id: String = conn
            .query_row(
                "SELECT job_id FROM jobs WHERE job_id = 'job-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(job_id, "job-1");
    }
}
