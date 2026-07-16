// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Job intake: the structured request that starts a content-ingest run.

use std::path::PathBuf;

/// A request to ingest content under `root`.
///
/// This is the local job-submission format — ordinary JSON, unlike the
/// Docenta-facing frame protocol, which uses the explicit binary codec
/// (addendum §5.4). Query filtering (extension/date/size) is not wired up
/// yet: every job currently matches every regular file under `root`
/// (equivalent to a `"*"` query) — see [`super::candidate_source`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct JobRequest {
    /// Identifier for the source this job's candidates came from.
    /// `ManifestHeader::source_id` is derived deterministically from this
    /// string (see [`super::workflow::run_job`]).
    pub source_id: String,
    /// Root directory to enumerate candidates under.
    pub root: PathBuf,
}
