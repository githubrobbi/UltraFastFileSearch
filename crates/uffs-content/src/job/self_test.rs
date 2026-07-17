// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Elevated smoke test: real VSS snapshot + real privileged Reader,
//! creating a unique sample file and proving playback through
//! [`super::vss_job::run_vss_job`] reproduces its content exactly.
//!
//! Mirrors `uffs-broker`'s own `--self-test-vss` design
//! (`crates/uffs-broker/src/broker.rs`/`broker/snapshot_manager/
//! vss_self_test.rs`): the round-trip logic lives once, here, in
//! production code — reused by both the `--self-test-vss-playback` CLI
//! flag (`main.rs`) and `cargo test -p uffs-content -- --ignored`
//! (`tests/e2e_real_vss_content_reader.rs`), so none of the three ever
//! drift apart.

use std::path::Path;

use anyhow::{Context as _, Result};
use uffs_content_protocol::codec::Reader as WireReader;
use uffs_content_protocol::frame::{ContentChunk, FileEnd, FrameEnvelope, FrameType};
use uffs_content_protocol::manifest::ManifestHeader;

use super::intake::JobRequest;
use super::vss_job::run_vss_job;

/// Run the real create-snapshot -> select-target -> read-content round trip.
///
/// Uses a freshly created, uniquely-named sample file under `test_dir`,
/// and verifies the streamed bytes exactly match what was written.
///
/// # Errors
/// Returns an error if the sample file can't be created, `run_vss_job`
/// fails, the job doesn't find exactly the one sample file, or the
/// played-back content doesn't match what was written.
pub fn self_test_vss_playback(test_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(test_dir)
        .with_context(|| format!("failed to create test dir {}", test_dir.display()))?;

    let unique_name = format!(
        "uffs-content-self-test-{}.txt",
        uuid::Uuid::new_v4().simple()
    );
    let content =
        b"UFFS content-reader self-test: real VSS snapshot + real Reader playback.\n".as_slice();
    let sample_path = test_dir.join(&unique_name);
    std::fs::write(&sample_path, content)
        .with_context(|| format!("failed to write sample file {}", sample_path.display()))?;

    let run_dir = test_dir.join("run");
    std::fs::create_dir_all(&run_dir)
        .with_context(|| format!("failed to create run dir {}", run_dir.display()))?;

    let request = JobRequest {
        source_id: "uffs-content-self-test".to_owned(),
        root: test_dir.to_path_buf(),
        query: unique_name,
    };

    let outcome = run_vss_job(&request, &run_dir).context("run_vss_job failed")?;

    anyhow::ensure!(
        outcome.run_summary.candidate_count == 1,
        "expected exactly 1 candidate (the unique sample file), found {}",
        outcome.run_summary.candidate_count
    );
    anyhow::ensure!(
        outcome.run_summary.succeeded_count == 1,
        "expected the sample file to succeed, got {} succeeded / {} failed-retryable / {} \
         failed-terminal / {} deferred",
        outcome.run_summary.succeeded_count,
        outcome.run_summary.failed_retryable_count,
        outcome.run_summary.failed_terminal_count,
        outcome.run_summary.deferred_manual_count
    );

    let played_back = decode_single_file_content(&outcome.manifest_bytes, &outcome.frames)
        .context("failed to decode the job's own manifest/frame output")?;
    anyhow::ensure!(
        played_back == content,
        "playback content does not match the original sample file (got {} bytes, expected {})",
        played_back.len(),
        content.len()
    );

    Ok(())
}

/// Decode a manifest + frame stream that is known to describe exactly
/// one candidate, returning the bytes its `CONTENT_CHUNK` frames
/// carried.
///
/// A narrow, self-test-only decoder — see
/// `tests/support/test_consumer.rs` for the fuller, general-purpose
/// version the parity harness uses; duplicated here (not shared)
/// because this one is production code (compiled into the shipped
/// binary), matching `uffs-content-reader-protocol`'s own "small,
/// independent duplicate" precedent for the same reason.
fn decode_single_file_content(manifest_bytes: &[u8], frames: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut manifest_reader = WireReader::new(manifest_bytes);
    let header = ManifestHeader::decode(&mut manifest_reader)
        .map_err(|err| anyhow::anyhow!("decode manifest header: {err}"))?;
    anyhow::ensure!(
        header.candidate_count == 1,
        "expected exactly 1 candidate in the manifest, found {}",
        header.candidate_count
    );

    let mut buffered = Vec::new();
    let mut saw_file_end = false;
    for frame_bytes in frames {
        let mut frame_reader = WireReader::new(frame_bytes);
        let (envelope, payload) = FrameEnvelope::decode(&mut frame_reader, u64::MAX)
            .map_err(|err| anyhow::anyhow!("decode frame envelope: {err}"))?;
        let mut payload_reader = WireReader::new(&payload);
        match envelope.frame_type {
            FrameType::ContentChunk => {
                let chunk = ContentChunk::decode(&mut payload_reader, u32::MAX)
                    .map_err(|err| anyhow::anyhow!("decode CONTENT_CHUNK: {err}"))?;
                buffered.extend_from_slice(&chunk.payload);
            }
            FrameType::FileEnd => {
                FileEnd::decode(&mut payload_reader)
                    .map_err(|err| anyhow::anyhow!("decode FILE_END: {err}"))?;
                saw_file_end = true;
            }
            FrameType::FileFailed | FrameType::FileDeferred => {
                anyhow::bail!("candidate did not succeed (saw {:?})", envelope.frame_type);
            }
            FrameType::JobBegin
            | FrameType::FileBegin
            | FrameType::FileAck
            | FrameType::Progress
            | FrameType::Heartbeat
            | FrameType::JobEnd
            | FrameType::JobCancel
            | FrameType::WindowUpdate => {}
        }
    }
    anyhow::ensure!(
        saw_file_end,
        "never saw a FILE_END frame for the sample file"
    );

    Ok(buffered)
}
