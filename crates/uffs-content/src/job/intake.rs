// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Job intake: the structured request that starts a content-ingest run.

use std::path::PathBuf;

/// A request to ingest content under `roots`.
///
/// This is the local job-submission format — ordinary JSON, unlike the
/// Docenta-facing frame protocol, which uses the explicit binary codec
/// (addendum §5.4).
///
/// `query` carries the UFFS name/path pattern (glob, regex with a `>`
/// prefix, or substring — e.g. `"*.txt"`, or `"*"` to match everything).
/// The remaining fields mirror a narrow, deliberately curated subset of
/// the daemon's own `SearchParams` filter surface (`uffs-client`'s
/// `search` method — the same one the CLI's `--ext`/`--min-size`/etc.
/// flags and `scripts/windows/api-validation.rs` exercise) so a job can
/// express the size/extension/date-bounded queries a real content-ingest
/// consumer (e.g. Docenta) actually needs, without this crate
/// re-implementing query parsing. All are forwarded verbatim to an
/// ephemeral `uffsd` instance by the real,
/// VSS+MFT-query-backed `super::candidate_source::VssCandidateSource`.
/// [`super::candidate_source::DirWalkCandidateSource`] (the fake,
/// cross-platform backend) ignores every filter field — it always
/// matches every regular file under a root, equivalent to `query: "*"`
/// with no other filters set.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Deserialize)]
pub struct JobRequest {
    /// Identifier for the source this job's candidates came from.
    /// `ManifestHeader::source_id` is derived deterministically from this
    /// string (see [`super::workflow::run_job`]).
    pub source_id: String,
    /// Root directories to enumerate candidates under — one job may span
    /// multiple drives (`super::vss_orchestrator` already leases one VSS
    /// snapshot per distinct drive letter among these and serves them all
    /// from a single combined ephemeral daemon). Empty means "every local
    /// NTFS drive" — see `super::vss_job::run_vss_job`'s own doc
    /// comment for how that default is resolved (Windows-only; the
    /// cross-platform fake `DirWalkCandidateSource` path requires an
    /// explicit, non-empty list, since "every drive" isn't a concept a
    /// plain directory walk has).
    #[serde(default)]
    pub roots: Vec<PathBuf>,
    /// UFFS name/path pattern to evaluate against the snapshot's MFT
    /// (e.g. `"*.txt"`); `"*"` matches every regular file.
    pub query: String,
    /// Comma-separated extension filter (e.g. `"txt"` or `"rs,toml,md"`).
    /// Mirrors `SearchParams::ext`.
    #[serde(default)]
    pub ext: Option<String>,
    /// Minimum file size in bytes. Mirrors `SearchParams::min_size`.
    #[serde(default)]
    pub min_size: Option<u64>,
    /// Maximum file size in bytes. Mirrors `SearchParams::max_size`.
    #[serde(default)]
    pub max_size: Option<u64>,
    /// Modified-time lower bound (e.g. `"7d"`, `"24h"`, `"2026-01-15"`).
    /// Mirrors `SearchParams::newer`.
    #[serde(default)]
    pub newer: Option<String>,
    /// Modified-time upper bound. Mirrors `SearchParams::older`.
    #[serde(default)]
    pub older: Option<String>,
    /// Exclude glob pattern (e.g. `"backup*"`). Mirrors
    /// `SearchParams::exclude`.
    #[serde(default)]
    pub exclude: Option<String>,
    /// Attribute filter spec (e.g. `"hidden,compressed,!system"`).
    /// Mirrors `SearchParams::attr`.
    #[serde(default)]
    pub attr: Option<String>,
    /// Content-delivery ceiling: a candidate whose `logical_size` exceeds
    /// this is still enumerated in the manifest (so reap/tombstone
    /// completeness holds — see
    /// [`uffs_content_protocol::frame::ReadMode::MetadataOnly`]'s own doc
    /// comment) but its body is not streamed. `None` means no ceiling —
    /// every matched candidate's content is delivered regardless of size.
    ///
    /// Independent of `query`/`ext`/`min_size`/etc.: those decide which
    /// files become candidates at all; this decides which already-
    /// matched candidates are worth paying to stream, e.g. so a consumer
    /// doesn't wait on a 100 GB file it has no intention of extracting
    /// text from. Forwarded verbatim into
    /// `JOB_BEGIN.max_content_delivery_bytes`
    /// (see [`super::workflow::run_job`]).
    #[serde(default)]
    pub max_content_delivery_bytes: Option<u64>,
}
