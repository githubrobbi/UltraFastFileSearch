// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Job intake: the structured request that starts a content-ingest run.

use std::path::PathBuf;

/// A request to ingest content under `root`.
///
/// This is the local job-submission format — ordinary JSON, unlike the
/// Docenta-facing frame protocol, which uses the explicit binary codec
/// (addendum §5.4).
///
/// `query` carries the UFFS query expression (e.g. `"*.txt"`, or `"*"`
/// to match everything), matching the daemon's own query grammar so the
/// real, VSS+MFT-query-backed `CandidateSource` can forward it verbatim
/// to an ephemeral `uffsd` instance rather than re-implementing query
/// parsing in this crate. [`super::candidate_source::DirWalkCandidateSource`]
/// (the fake backend) ignores this field entirely — it always matches
/// every regular file under `root`, equivalent to `query: "*"`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct JobRequest {
    /// Identifier for the source this job's candidates came from.
    /// `ManifestHeader::source_id` is derived deterministically from this
    /// string (see [`super::workflow::run_job`]).
    pub source_id: String,
    /// Root directory to enumerate candidates under.
    pub root: PathBuf,
    /// UFFS query expression to evaluate against the snapshot's MFT
    /// (e.g. `"*.txt"`); `"*"` matches every regular file.
    pub query: String,
}
