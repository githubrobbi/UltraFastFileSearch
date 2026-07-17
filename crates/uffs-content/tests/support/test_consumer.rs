// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Minimal stand-in for a downstream consumer (e.g. Docenta): decodes the
//! public wire protocol — the manifest and every frame — using only
//! `uffs-content-protocol`'s decoders, exactly as a real consumer would.
//! This is what lets the parity test catch a framing bug that a
//! structure-passthrough shortcut would miss (design-doc §21's intent).

use std::collections::HashMap;
use std::path::PathBuf;

use uffs_content_protocol::codec::{Digest, Reader};
use uffs_content_protocol::frame::{
    ContentChunk, FailedOutcome, FileBegin, FileDeferred, FileEnd, FileFailed, FrameEnvelope,
    FrameType,
};
use uffs_content_protocol::manifest::{CandidateRecord, ManifestHeader, ManifestTrailer};

/// One candidate's fully consumed success outcome.
#[derive(Debug, Clone)]
pub(crate) struct ConsumedSuccess {
    /// Path from the manifest's candidate record.
    pub relative_path: PathBuf,
    /// `FILE_END.total_logical_bytes`.
    pub total_logical_bytes: u64,
    /// The producer's self-reported `FILE_END.content_digest`.
    pub reported_digest: Digest,
    /// Every byte this consumer actually received via `CONTENT_CHUNK`
    /// frames for this candidate, in the order received.
    pub buffered_content: Vec<u8>,
}

/// Everything decoded from one job's manifest + frame stream.
#[derive(Debug, Clone, Default)]
pub(crate) struct ConsumedJob {
    /// `ManifestHeader::candidate_count`.
    pub candidate_count: u64,
    /// Candidates that reached `FILE_END`.
    pub succeeded: Vec<ConsumedSuccess>,
    /// Candidate IDs that reached `FILE_FAILED` with a retryable outcome.
    pub failed_retryable: Vec<u64>,
    /// Candidate IDs that reached `FILE_FAILED` with a terminal outcome.
    pub failed_terminal: Vec<u64>,
    /// Candidate IDs that reached `FILE_DEFERRED`.
    pub deferred_manual: Vec<u64>,
}

/// Decode `manifest_bytes` + `frames` (each already a complete,
/// envelope-wrapped frame, as emitted by
/// `uffs_content::job::workflow::run_job`) into a [`ConsumedJob`].
#[must_use]
pub(crate) fn consume(manifest_bytes: &[u8], frames: &[Vec<u8>]) -> ConsumedJob {
    let mut manifest_reader = Reader::new(manifest_bytes);
    let header = ManifestHeader::decode(&mut manifest_reader).expect("decode manifest header");

    let mut paths_by_candidate_id: HashMap<u64, PathBuf> = HashMap::new();
    for _ in 0..header.candidate_count {
        let record =
            CandidateRecord::decode(&mut manifest_reader).expect("decode candidate record");
        paths_by_candidate_id.insert(
            record.candidate_id,
            PathBuf::from(record.path.display_lossy()),
        );
    }
    ManifestTrailer::decode(&mut manifest_reader).expect("decode manifest trailer");

    let mut job = ConsumedJob {
        candidate_count: header.candidate_count,
        ..ConsumedJob::default()
    };
    let mut buffers: HashMap<u64, Vec<u8>> = HashMap::new();

    for frame_bytes in frames {
        let mut frame_reader = Reader::new(frame_bytes);
        let (envelope, payload) =
            FrameEnvelope::decode(&mut frame_reader, u64::MAX).expect("decode frame envelope");
        let mut payload_reader = Reader::new(&payload);
        apply_frame(
            envelope.frame_type,
            &mut payload_reader,
            &paths_by_candidate_id,
            &mut buffers,
            &mut job,
        );
    }

    job
}

/// Applies one decoded frame to the in-progress [`ConsumedJob`]/buffer
/// state. Split out of [`consume`] purely to keep that function's body
/// short — not a reusable abstraction on its own.
fn apply_frame(
    frame_type: FrameType,
    payload_reader: &mut Reader<'_>,
    paths_by_candidate_id: &HashMap<u64, PathBuf>,
    buffers: &mut HashMap<u64, Vec<u8>>,
    job: &mut ConsumedJob,
) {
    match frame_type {
        FrameType::FileBegin => {
            let file_begin = FileBegin::decode(payload_reader).expect("decode FILE_BEGIN");
            buffers.insert(file_begin.candidate_id, Vec::new());
        }
        FrameType::ContentChunk => {
            let chunk =
                ContentChunk::decode(payload_reader, u32::MAX).expect("decode CONTENT_CHUNK");
            buffers
                .entry(chunk.candidate_id)
                .or_default()
                .extend_from_slice(&chunk.payload);
        }
        FrameType::FileEnd => {
            let file_end = FileEnd::decode(payload_reader).expect("decode FILE_END");
            let buffered_content = buffers.remove(&file_end.candidate_id).unwrap_or_default();
            let relative_path = paths_by_candidate_id
                .get(&file_end.candidate_id)
                .cloned()
                .unwrap_or_default();
            let reported_digest = file_end
                .content_digest
                .expect("a succeeded file must report a digest in this harness (no delivery ceiling is set)");
            job.succeeded.push(ConsumedSuccess {
                relative_path,
                total_logical_bytes: file_end.total_logical_bytes,
                reported_digest,
                buffered_content,
            });
        }
        FrameType::FileFailed => {
            let file_failed = FileFailed::decode(payload_reader).expect("decode FILE_FAILED");
            match file_failed.outcome {
                FailedOutcome::Retryable => job.failed_retryable.push(file_failed.candidate_id),
                FailedOutcome::Terminal => job.failed_terminal.push(file_failed.candidate_id),
            }
        }
        FrameType::FileDeferred => {
            let file_deferred = FileDeferred::decode(payload_reader).expect("decode FILE_DEFERRED");
            job.deferred_manual.push(file_deferred.candidate_id);
        }
        FrameType::JobBegin
        | FrameType::FileAck
        | FrameType::Progress
        | FrameType::Heartbeat
        | FrameType::JobEnd
        | FrameType::JobCancel
        | FrameType::WindowUpdate
        | FrameType::JobResume
        | FrameType::JobSubmit => {}
    }
}
