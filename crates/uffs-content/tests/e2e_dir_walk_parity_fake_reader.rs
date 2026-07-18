// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Fast, cross-platform end-to-end validation: does `uffs-content`'s
//! fake (`std::fs`-backed) pipeline produce exactly the same file set and
//! content as a plain, independent directory walk?
//!
//! This is `uffs-ingest-implementation-plan.md` §9.5's "fast" harness —
//! it substitutes `std::fs`-backed candidate/content sources
//! (`uffs_content::job::candidate_source::DirWalkCandidateSource`,
//! `uffs_content::job::content_source::FsContentSource`) for the real
//! VSS-snapshot/privileged-Reader machinery (not yet built — UFI.1/UFI.2),
//! so it runs everywhere, on every PR, with no elevation and no Windows
//! dependency. It still exercises the real Coordinator: candidate
//! enumeration, manifest construction and wire encoding, protocol
//! framing, and the ephemeral run-state bookkeeping — only the "how do
//! we get the candidate list and bytes" step is faked.
//!
//! The real-VSS variant (§9.4, Windows-only, `#[ignore]`) is not wired
//! up as an end-to-end test yet — `uffs-content-reader` and the Broker
//! Snapshot Manager both exist now (see `crates/uffs-content-reader/`
//! and `crates/uffs-broker/src/broker/snapshot_manager/`), but nothing
//! yet calls `job::vss_orchestrator`/`job::reader_client` end to end
//! from `workflow::run_job`.

// `#[cfg(test)]` so clippy's test-code relaxations (`allow-expect-in-tests`
// et al. in `clippy.toml`) apply inside `support/`'s helper files too —
// those relaxations key off the enclosing item chain carrying
// `#[cfg(test)]`, which a plain `mod support;` here would not provide.
#[cfg(test)]
mod support;

// This crate's own dependencies (shared across the lib, bin, and every
// integration test binary), not used directly from this particular test.
// Windows-only deps, not used directly from this cross-platform fake-
// pipeline test — see `src/main.rs`'s matching markers for the same
// per-target rationale (each test binary is its own compilation unit).
#[cfg(windows)]
use anyhow as _;
// Used by `uffs_content::job::workflow`'s pipelined content reader,
// exercised by this cross-platform test via `run_job` itself.
use crossbeam_channel as _;
use serde as _;
use serde_json as _;
#[cfg(windows)]
use tokio as _;
// Unconditional dependency of `uffs-content` (see that crate's
// `Cargo.toml`) — not named directly by this cross-platform test.
use tracing as _;
#[cfg(windows)]
use tracing_subscriber as _;
#[cfg(windows)]
use uffs_broker_protocol as _;
#[cfg(windows)]
use uffs_client as _;
#[cfg(windows)]
use uffs_content_reader_protocol as _;
#[cfg(windows)]
use uffs_mft as _;
#[cfg(windows)]
use uffs_security as _;
use uffs_version as _;
use uuid as _;

#[cfg(test)]
mod tests {
    use uffs_content::job::candidate_source::DirWalkCandidateSource;
    use uffs_content::job::content_source::FsContentSource;
    use uffs_content::job::intake::JobRequest;
    use uffs_content::job::workflow::{JobOutcome, ReadConcurrency, run_job};

    use crate::support;
    use crate::support::fixture_tree::FixtureFile;
    use crate::support::plain_walk::PlainWalkEntry;
    use crate::support::test_consumer::ConsumedJob;

    #[test]
    fn ingest_output_matches_plain_directory_walk() {
        let source_dir = tempfile::tempdir().expect("create source temp dir");
        let fixture_files = support::fixture_tree::build(source_dir.path());
        assert!(
            fixture_files
                .iter()
                .any(|file| file.relative_path.to_string_lossy().contains("hardlink")),
            "fixture must include a hard-linked file"
        );

        // 1. Independent oracle — shares no code with the pipeline under test.
        let mut expected = support::plain_walk::plain_walk(source_dir.path());
        expected.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        assert_fixture_matches_oracle(&fixture_files, &expected);

        // 2. Run the real pipeline against the fake (std::fs) sources.
        let run_dir = tempfile::tempdir().expect("create run temp dir");
        let request = JobRequest {
            source_id: "fixture-source".to_owned(),
            roots: vec![source_dir.path().to_path_buf()],
            query: "*".to_owned(),
            ..Default::default()
        };
        let mut frames = Vec::new();
        let outcome = run_job(
            &request,
            &DirWalkCandidateSource,
            &FsContentSource,
            run_dir.path(),
            // >1, and smaller than the fixture's own file count, so this
            // parity check also exercises the sliding-window concurrent-
            // read path (`read_lease_run_pipelined`) with more candidates
            // than the window is wide, not just a single pass.
            &ReadConcurrency::flat(3),
            &[],
            0,
            |frame| {
                frames.push(frame);
                Ok(())
            },
        )
        .expect("run_job must succeed");

        // 3. Structural assertions (design-doc §21.7) before content is even compared.
        assert_structural_invariants(&outcome, expected.len());

        // 4. Decode the actual wire bytes as a real consumer would — this is what
        //    catches a framing bug a structure-passthrough shortcut would miss
        //    entirely.
        let consumed = support::test_consumer::consume(&outcome.manifest_bytes, &frames);
        assert_eq!(
            consumed.candidate_count, outcome.run_summary.candidate_count,
            "manifest header's candidate_count must match the run summary's"
        );
        assert!(consumed.failed_retryable.is_empty());
        assert!(consumed.failed_terminal.is_empty());
        assert!(consumed.deferred_manual.is_empty());

        assert_content_matches_oracle(&consumed, &expected);

        // 5. Every FILE_END digest must equal recomputing BLAKE3 over the actual
        //    emitted bytes the consumer buffered — not just the producer's
        //    self-reported digest — catching a "digest computed over the wrong bytes"
        //    bug that a self-reported-digest-only check would miss entirely.
        assert_digests_recompute(&consumed);
    }

    /// Sanity-checks the fixture generator itself before trusting it as
    /// the oracle's input: every file it says it wrote must appear in
    /// the oracle's own independent walk with matching size/content.
    fn assert_fixture_matches_oracle(fixture_files: &[FixtureFile], expected: &[PlainWalkEntry]) {
        for file in fixture_files {
            let found = expected
                .iter()
                .find(|entry| entry.relative_path == file.relative_path)
                .unwrap_or_else(|| {
                    panic!(
                        "fixture file {:?} must appear in the oracle walk",
                        file.relative_path
                    )
                });
            assert_eq!(
                found.size,
                u64::try_from(file.content.len()).unwrap_or(u64::MAX)
            );
            assert_eq!(
                *found.digest.as_bytes(),
                *blake3::hash(&file.content).as_bytes()
            );
        }
    }

    /// Checks the completeness invariant (design-doc §21.7) and that
    /// plain, ordinary fixture files never fail or defer.
    fn assert_structural_invariants(outcome: &JobOutcome, expected_count: usize) {
        assert_eq!(
            outcome.run_summary.candidate_count,
            outcome.run_summary.succeeded_count
                + outcome.run_summary.failed_retryable_count
                + outcome.run_summary.failed_terminal_count
                + outcome.run_summary.deferred_manual_count
        );
        assert_eq!(
            outcome.run_summary.failed_retryable_count, 0,
            "plain ordinary fixture files must not fail"
        );
        assert_eq!(
            outcome.run_summary.failed_terminal_count, 0,
            "plain ordinary fixture files must not fail"
        );
        assert_eq!(
            outcome.run_summary.deferred_manual_count, 0,
            "plain ordinary fixture files must not defer"
        );
        assert_eq!(
            outcome.run_summary.candidate_count,
            u64::try_from(expected_count).unwrap_or(u64::MAX)
        );
    }

    /// The actual "matches a plain dir walk" check: every succeeded
    /// candidate's `(path, size, digest)` must exactly match the oracle.
    fn assert_content_matches_oracle(consumed: &ConsumedJob, expected: &[PlainWalkEntry]) {
        let mut actual: Vec<_> = consumed
            .succeeded
            .iter()
            .map(|file| {
                (
                    file.relative_path.clone(),
                    file.total_logical_bytes,
                    file.reported_digest,
                )
            })
            .collect();
        actual.sort();
        let expected_tuples: Vec<_> = expected
            .iter()
            .map(|entry| {
                (
                    entry.relative_path.clone(),
                    entry.size,
                    *entry.digest.as_bytes(),
                )
            })
            .collect();
        assert_eq!(
            actual, expected_tuples,
            "ingest output must exactly match a plain directory walk"
        );
    }

    /// Recomputes BLAKE3 over the consumer-buffered bytes for every
    /// succeeded file, independently of the producer's self-reported
    /// digest.
    fn assert_digests_recompute(consumed: &ConsumedJob) {
        for file in &consumed.succeeded {
            let recomputed = blake3::hash(&file.buffered_content);
            assert_eq!(
                *recomputed.as_bytes(),
                file.reported_digest,
                "producer's self-reported digest must match independent recomputation for {:?}",
                file.relative_path
            );
        }
    }
}
