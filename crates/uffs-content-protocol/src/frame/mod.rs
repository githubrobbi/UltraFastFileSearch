// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Frame envelope and per-frame-type payloads (design-doc §12).
//!
//! [`FrameEnvelope`] is deliberately payload-agnostic: it validates and
//! frames an opaque byte blob (checking `payload_length` against a
//! caller-supplied maximum *before* allocating, per Finding H10), and
//! hands the payload bytes back to the caller. Decoding those bytes into
//! a concrete frame (`JobBegin`, `FileEnd`, ...) is a second step, keyed
//! on [`FrameType`]. This mirrors [`crate::manifest`]'s
//! header/record split and keeps the bounds-checking chokepoint in one
//! place regardless of which of the 12 frame types is inside.
//!
//! # Wire layout
//!
//! Every frame is this exact byte sequence, all integers little-endian.
//! There is no separate outer length prefix — `header_length` and
//! `payload_length` below are it — so a consumer reading frames directly
//! off a stream (a named pipe, a socket) reads this sequence in order:
//!
//! | Bytes | Field | Notes |
//! |---|---|---|
//! | 4 | `magic` | [`FRAME_MAGIC`] (`b"UFS2"`) |
//! | 2 | `protocol_version` | must equal [`PROTOCOL_VERSION`] |
//! | 2 | `frame_type` | [`FrameType`] discriminant |
//! | 4 | `flags` | reserved, `0` in v2 |
//! | 4 | `header_length` | bytes from `magic` through `frame_sequence`, inclusive (always `48` in v2) |
//! | 8 | `payload_length` | byte length of `payload` below |
//! | 16 | `job_id` | |
//! | 8 | `frame_sequence` | |
//! | 4 | `header_checksum` | [`crate::codec::checksum32`] over the 48 bytes above |
//! | 4 | `payload_checksum` | `checksum32` over `payload` |
//! | `payload_length` | `payload` | opaque bytes; decode per `frame_type` (e.g. [`JobBegin::decode`]) |
//!
//! So: read 24 bytes to learn `payload_length`, read 56 bytes total
//! (`header_length` + both checksums) before you can validate anything,
//! then read exactly `payload_length` more bytes for the payload — 56 +
//! `payload_length` bytes per frame, back to back, no gaps. Validate
//! `header_checksum` against bytes `0..48` and `payload_checksum`
//! against the payload before trusting either; [`FrameEnvelope::decode`]
//! already does all of this for an in-memory buffer holding a whole
//! frame. For assembling frames out of arbitrary read-sized chunks off a
//! live stream, use [`FrameStreamReader`] instead of reimplementing this
//! table — it performs exactly the above and needs no more wiring than a
//! `feed()` call per read plus a `try_next()` loop.

use crate::codec::{
    Reader, checksum32, write_bytes_u16_prefixed, write_i64_le, write_u16_le, write_u32_le,
    write_u64_le,
};
use crate::path_encoding::PathDecodeError;

mod content_chunk;
mod control;
mod file_ack;
mod file_begin;
mod file_deferred;
mod file_end;
mod file_failed;
mod job_begin;
mod job_end;
mod stream_reader;

pub use content_chunk::ContentChunk;
pub use control::{Heartbeat, JobCancel, JobResume, JobSubmit, Progress, WindowUpdate};
pub use file_ack::FileAck;
pub use file_begin::FileBegin;
pub use file_deferred::FileDeferred;
pub use file_end::FileEnd;
pub use file_failed::{FailedOutcome, FileFailed};
pub use job_begin::JobBegin;
pub use job_end::JobEnd;
pub use stream_reader::FrameStreamReader;

/// Frame envelope magic (design-doc §12.1).
pub const FRAME_MAGIC: [u8; 4] = *b"UFS2";

/// Wire format version this build produces and requires on decode.
///
/// Every [`FrameEnvelope`] encoded by this crate sets `protocol_version`
/// to this value, and [`FrameEnvelope::decode`] rejects any other value
/// explicitly (see [`FrameError::ProtocolVersionMismatch`]) rather than
/// attempting to parse a header shape it was never validated against —
/// a future wire-breaking change should bump this constant, not
/// silently reinterpret old bytes under a new layout.
pub const PROTOCOL_VERSION: u16 = 2;

/// Bytes of the fixed envelope header preceding `header_checksum`:
/// magic(4) + `protocol_version`(2) + `frame_type`(2) + flags(4) +
/// `header_length`(4) + `payload_length`(8) + `job_id`(16) +
/// `frame_sequence`(8) = 48.
const ENVELOPE_HEADER_LEN: usize = 48;

/// Errors decoding a frame envelope or a typed frame payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// Underlying bounds/length-prefix decode failure.
    #[error(transparent)]
    Decode(#[from] crate::codec::DecodeError),
    /// Path field failed to decode.
    #[error(transparent)]
    Path(#[from] PathDecodeError),
    /// Envelope magic did not match [`FRAME_MAGIC`].
    #[error("bad frame magic: {0:?}")]
    BadMagic([u8; 4]),
    /// `protocol_version` did not match [`PROTOCOL_VERSION`] — a peer
    /// speaking a different wire format, not a corrupt frame. Rejected
    /// before any version-shape-dependent field is parsed, so a future
    /// breaking wire change fails loud instead of misparsing.
    #[error("protocol_version mismatch: expected {expected}, got {actual}")]
    ProtocolVersionMismatch {
        /// This build's [`PROTOCOL_VERSION`].
        expected: u16,
        /// The version the peer actually sent.
        actual: u16,
    },
    /// The declared `header_length` did not match bytes actually consumed.
    #[error("header_length mismatch: declared {declared}, actual {actual}")]
    HeaderLengthMismatch {
        /// Declared length from the wire.
        declared: u32,
        /// Bytes actually consumed decoding the fixed header.
        actual: usize,
    },
    /// The header checksum did not match the bytes it covers.
    #[error("header checksum mismatch: expected 0x{expected:08x}, computed 0x{computed:08x}")]
    HeaderChecksumMismatch {
        /// Checksum read from the wire.
        expected: u32,
        /// Checksum recomputed locally.
        computed: u32,
    },
    /// The payload checksum did not match the bytes it covers.
    #[error("payload checksum mismatch: expected 0x{expected:08x}, computed 0x{computed:08x}")]
    PayloadChecksumMismatch {
        /// Checksum read from the wire.
        expected: u32,
        /// Checksum recomputed locally.
        computed: u32,
    },
    /// `payload_length` exceeded the caller's configured
    /// `max_frame_payload_bytes` (design-doc §12.1/§13.1).
    #[error("payload_length {declared} exceeds max_frame_payload_bytes {max}")]
    PayloadTooLarge {
        /// Declared payload length from the wire.
        declared: u64,
        /// Caller-configured maximum.
        max: u64,
    },
    /// `frame_type` did not match a known [`FrameType`] discriminant.
    #[error("unknown frame_type: {0}")]
    UnknownFrameType(u16),
    /// A string field (e.g. `message`) was not valid UTF-8.
    #[error("field '{0}' is not valid UTF-8")]
    InvalidUtf8(&'static str),
    /// A discriminant byte did not match any known enum variant.
    #[error("unknown discriminant for '{field}': {value}")]
    UnknownDiscriminant {
        /// Name of the field being decoded, for diagnostics.
        field: &'static str,
        /// The unrecognized value.
        value: u64,
    },
}

/// The 12 required frame types (design-doc §12.2), plus
/// [`Self::JobResume`] and [`Self::JobSubmit`].
///
/// Both additions cover ground the design doc leaves unspecified: how a
/// consumer starts a job and how it reconnects to one after a transport
/// blip (§10 "Transport model" names the channels but not a submission/
/// reconnect handshake). `JobResume` has an empty payload — the frame
/// envelope's own `job_id` already names which job to resume.
/// `JobSubmit`'s payload is a JSON-encoded job spec; the consumer
/// chooses the `job_id` up front (in the envelope) and the producer
/// adopts it for the whole job, including its own `JOB_BEGIN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum FrameType {
    /// First frame of a job: query/manifest identity and negotiated limits.
    JobBegin = 1,
    /// Announces a candidate is about to stream; does not imply success.
    FileBegin = 2,
    /// One bounded chunk of a file's logical bytes.
    ContentChunk = 3,
    /// Terminal success for one candidate.
    FileEnd = 4,
    /// Terminal failure (retryable or terminal) for one candidate.
    FileFailed = 5,
    /// Terminal manual deferral for one candidate.
    FileDeferred = 6,
    /// Consumer acknowledgement of a successful file.
    FileAck = 7,
    /// Periodic job progress metrics.
    Progress = 8,
    /// Keeps an idle long-file operation from looking dead.
    Heartbeat = 9,
    /// Final frame of a job: totals and reconciliation.
    JobEnd = 10,
    /// Consumer-initiated job cancellation.
    JobCancel = 11,
    /// Consumer-initiated backpressure window increase.
    WindowUpdate = 12,
    /// Consumer reconnect: resume streaming the job named by this
    /// frame's envelope `job_id`, skipping any candidate already
    /// acknowledged before the connection dropped.
    JobResume = 13,
    /// Consumer-initiated job submission: payload is a JSON job spec;
    /// the envelope's `job_id` is the consumer-chosen id for the new job.
    JobSubmit = 14,
}

impl FrameType {
    /// Serialize to the two-byte wire representation.
    #[must_use]
    pub const fn encode(self) -> u16 {
        self as u16
    }

    /// Parse the two-byte wire representation.
    ///
    /// # Errors
    ///
    /// Returns the offending value if it does not match a known variant.
    pub const fn decode(value: u16) -> Result<Self, u16> {
        match value {
            1 => Ok(Self::JobBegin),
            2 => Ok(Self::FileBegin),
            3 => Ok(Self::ContentChunk),
            4 => Ok(Self::FileEnd),
            5 => Ok(Self::FileFailed),
            6 => Ok(Self::FileDeferred),
            7 => Ok(Self::FileAck),
            8 => Ok(Self::Progress),
            9 => Ok(Self::Heartbeat),
            10 => Ok(Self::JobEnd),
            11 => Ok(Self::JobCancel),
            12 => Ok(Self::WindowUpdate),
            13 => Ok(Self::JobResume),
            14 => Ok(Self::JobSubmit),
            other => Err(other),
        }
    }
}

/// Frame envelope (design-doc §12.1): the fixed header every frame
/// shares, wrapping an opaque payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameEnvelope {
    /// Wire format version.
    pub protocol_version: u16,
    /// Which of the 12 frame types this is.
    pub frame_type: FrameType,
    /// Reserved bitfield; no bits defined in v2.
    pub flags: u32,
    /// Job this frame belongs to.
    pub job_id: [u8; 16],
    /// Session-global monotonic frame sequence number.
    pub frame_sequence: u64,
}

impl FrameEnvelope {
    /// Encode this envelope wrapping `payload`, computing `header_length`,
    /// `payload_length`, `header_checksum`, and `payload_checksum`
    /// automatically.
    #[must_use]
    pub fn encode(&self, payload: &[u8]) -> Vec<u8> {
        // Saturates rather than errors: a >16 EiB payload is not a
        // realistic input this crate needs to reject gracefully, and
        // saturating keeps this function infallible (no unwrap/expect,
        // no manufactured error path for an unreachable case).
        let payload_length = u64::try_from(payload.len()).unwrap_or(u64::MAX);

        let mut header = Vec::with_capacity(ENVELOPE_HEADER_LEN);
        header.extend_from_slice(&FRAME_MAGIC);
        write_u16_le(&mut header, self.protocol_version);
        write_u16_le(&mut header, self.frame_type.encode());
        write_u32_le(&mut header, self.flags);
        write_u32_le(
            &mut header,
            u32::try_from(ENVELOPE_HEADER_LEN).unwrap_or(u32::MAX),
        );
        write_u64_le(&mut header, payload_length);
        header.extend_from_slice(&self.job_id);
        write_u64_le(&mut header, self.frame_sequence);

        let header_checksum = checksum32(&header);
        let payload_checksum = checksum32(payload);

        let mut out = header;
        write_u32_le(&mut out, header_checksum);
        write_u32_le(&mut out, payload_checksum);
        out.extend_from_slice(payload);
        out
    }

    /// Decode an envelope and its payload from `reader`, rejecting a
    /// `payload_length` exceeding `max_payload_bytes` before allocating
    /// the payload buffer (design-doc §12.1/§13.1).
    ///
    /// # Errors
    ///
    /// See [`FrameError`] variants.
    pub fn decode(
        reader: &mut Reader<'_>,
        max_payload_bytes: u64,
    ) -> Result<(Self, Vec<u8>), FrameError> {
        let start = reader.position();

        let magic: [u8; 4] = reader.read_array()?;
        if magic != FRAME_MAGIC {
            return Err(FrameError::BadMagic(magic));
        }
        let protocol_version = reader.read_u16_le()?;
        if protocol_version != PROTOCOL_VERSION {
            return Err(FrameError::ProtocolVersionMismatch {
                expected: PROTOCOL_VERSION,
                actual: protocol_version,
            });
        }
        let frame_type_raw = reader.read_u16_le()?;
        let frame_type = FrameType::decode(frame_type_raw).map_err(FrameError::UnknownFrameType)?;
        let flags = reader.read_u32_le()?;
        let header_length = reader.read_u32_le()?;
        let payload_length = reader.read_u64_le()?;
        let job_id: [u8; 16] = reader.read_array()?;
        let frame_sequence = reader.read_u64_le()?;

        let end = reader.position();
        let consumed = end - start;
        if consumed != header_length as usize {
            return Err(FrameError::HeaderLengthMismatch {
                declared: header_length,
                actual: consumed,
            });
        }

        let expected_header_checksum = reader.read_u32_le()?;
        let header_bytes =
            reader
                .full_buffer()
                .get(start..end)
                .ok_or(FrameError::HeaderLengthMismatch {
                    declared: header_length,
                    actual: consumed,
                })?;
        let computed_header_checksum = checksum32(header_bytes);
        if expected_header_checksum != computed_header_checksum {
            return Err(FrameError::HeaderChecksumMismatch {
                expected: expected_header_checksum,
                computed: computed_header_checksum,
            });
        }

        let expected_payload_checksum = reader.read_u32_le()?;

        if payload_length > max_payload_bytes {
            return Err(FrameError::PayloadTooLarge {
                declared: payload_length,
                max: max_payload_bytes,
            });
        }
        let payload_len_usize = usize::try_from(payload_length).unwrap_or(usize::MAX);
        let payload = reader.read_bytes_exact(payload_len_usize)?;

        let computed_payload_checksum = checksum32(&payload);
        if expected_payload_checksum != computed_payload_checksum {
            return Err(FrameError::PayloadChecksumMismatch {
                expected: expected_payload_checksum,
                computed: computed_payload_checksum,
            });
        }

        Ok((
            Self {
                protocol_version,
                frame_type,
                flags,
                job_id,
                frame_sequence,
            },
            payload,
        ))
    }
}

// ───────────────────────── shared small enums ─────────────────────────

/// `ordering` (design-doc §12.3): fixed at `NONE` for v2, modeled as an
/// enum so a future version can add variants without breaking the field
/// shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameOrdering {
    /// No cross-file ordering contract (design-doc §2.4) — the only
    /// value in v2.
    None = 0,
}

/// `content_semantics` (design-doc §12.3): fixed at
/// `UNNAMED_LOGICAL_STREAM` for v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ContentSemantics {
    /// Logical bytes of the unnamed/default data stream (design-doc §6.1)
    /// — the only value in v2.
    UnnamedLogicalStream = 0,
}

/// `digest_algorithm` (design-doc §12.3, §15.1): fixed at `BLAKE3` for v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DigestAlgorithm {
    /// Full-length, plain unkeyed BLAKE3-256 — see
    /// [`crate::codec::digest`]'s consumer-contract note. The only value
    /// in v2.
    Blake3 = 0,
}

/// `read_mode` (design-doc §6, §20.1; addendum §3.6 planner naming).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ReadMode {
    /// Read from the MFT-resident attribute value.
    Resident = 0,
    /// Logical open + read against the VSS snapshot namespace (the
    /// default nonresident path per addendum §3).
    LogicalSnapshot = 1,
    /// Benchmark-gated raw runlist/extent reconstruction against the
    /// snapshot (addendum §3.6) — disabled until UFI.3 approves it.
    RawSnapshotAccelerator = 2,
    /// The candidate matched the job's query but its content body was
    /// intentionally not read or streamed, because its logical size
    /// exceeds the job's separate content-delivery ceiling
    /// (`JobBegin::max_content_delivery_bytes`). The candidate is still
    /// present in the manifest and this `FILE_END` still reports
    /// `Succeeded` — nothing failed. See [`FileEnd::content_digest`].
    ///
    /// This is a deliberate two-tier design, not a producer-invented
    /// policy: query filters (ext/date/size-min/etc., matching existing
    /// UFFS CLI filters) determine which files become candidates at all
    /// — including huge files a consumer only wants recorded as
    /// metadata — while the content-delivery ceiling is a second,
    /// independent knob controlling which already-matched candidates
    /// actually get bodies streamed. A consumer that wants metadata for
    /// every file under a root, regardless of size, but content only for
    /// small ones expresses that as one job: broad query + a tight
    /// delivery ceiling, not as two jobs or a query that silently drops
    /// large files from the candidate set (which would break reap/
    /// tombstone completeness — see design-doc §2.3).
    MetadataOnly = 3,
}

/// `failure_stage` (design-doc §8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FailureStage {
    /// VSS snapshot creation.
    SnapshotCreate = 0,
    /// VSS snapshot device open.
    SnapshotOpen = 1,
    /// Candidate enumeration against the snapshot.
    Enumeration = 2,
    /// Candidate/file identity validation.
    Identity = 3,
    /// Unnamed-stream resolution.
    StreamResolution = 4,
    /// Nonresident runlist validation.
    RunlistValidation = 5,
    /// The physical/logical read itself.
    Read = 6,
    /// Logical-byte reconstruction (VDL/EOF/sparse rules).
    Reconstruction = 7,
    /// Incremental digest computation.
    Hash = 8,
    /// Frame transport to the consumer.
    Transport = 9,
    /// Waiting on consumer acknowledgement.
    ConsumerAck = 10,
    /// An internal producer error not attributable to another stage.
    Internal = 11,
}

/// `retry_class` (design-doc §8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RetryClass {
    /// Retry within the same job/snapshot.
    RetrySameJob = 0,
    /// Retry only under a new snapshot.
    RetryNewSnapshot = 1,
    /// Retry after an external resource condition changes.
    RetryAfterResourceChange = 2,
    /// Retry only via a manual/special-case handler.
    RetryWithManualHandler = 3,
    /// Retry only with different credentials/keys (e.g. EFS).
    RetryWithCredentialOrKey = 4,
    /// Not retryable.
    DoNotRetry = 5,
}

/// `consumer_status` (design-doc §12.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ConsumerAckStatus {
    /// Consumer validated byte count and digest successfully.
    Accepted = 0,
    /// Consumer rejected the file (e.g. digest mismatch on its side).
    Rejected = 1,
}

/// Terminal job status (design-doc §12.10 `job_status`). Reuses
/// [`crate::state::JobState`] rather than duplicating a second status
/// enum — `JOB_END.job_status` is always one of that machine's terminal
/// states.
pub use crate::state::JobState as JobStatus;

impl FrameOrdering {
    /// Serialize to the wire byte.
    #[must_use]
    pub const fn encode(self) -> u8 {
        self as u8
    }

    /// Parse the wire byte.
    ///
    /// # Errors
    /// Returns the offending byte if unrecognized.
    pub const fn decode(byte: u8) -> Result<Self, u8> {
        match byte {
            0 => Ok(Self::None),
            other => Err(other),
        }
    }
}

impl ContentSemantics {
    /// Serialize to the wire byte.
    #[must_use]
    pub const fn encode(self) -> u8 {
        self as u8
    }

    /// Parse the wire byte.
    ///
    /// # Errors
    /// Returns the offending byte if unrecognized.
    pub const fn decode(byte: u8) -> Result<Self, u8> {
        match byte {
            0 => Ok(Self::UnnamedLogicalStream),
            other => Err(other),
        }
    }
}

impl DigestAlgorithm {
    /// Serialize to the wire byte.
    #[must_use]
    pub const fn encode(self) -> u8 {
        self as u8
    }

    /// Parse the wire byte.
    ///
    /// # Errors
    /// Returns the offending byte if unrecognized.
    pub const fn decode(byte: u8) -> Result<Self, u8> {
        match byte {
            0 => Ok(Self::Blake3),
            other => Err(other),
        }
    }
}

impl ReadMode {
    /// Serialize to the wire byte.
    #[must_use]
    pub const fn encode(self) -> u8 {
        self as u8
    }

    /// Parse the wire byte.
    ///
    /// # Errors
    /// Returns the offending byte if unrecognized.
    pub const fn decode(byte: u8) -> Result<Self, u8> {
        match byte {
            0 => Ok(Self::Resident),
            1 => Ok(Self::LogicalSnapshot),
            2 => Ok(Self::RawSnapshotAccelerator),
            3 => Ok(Self::MetadataOnly),
            other => Err(other),
        }
    }
}

impl FailureStage {
    /// Serialize to the wire byte.
    #[must_use]
    pub const fn encode(self) -> u8 {
        self as u8
    }

    /// Parse the wire byte.
    ///
    /// # Errors
    /// Returns the offending byte if unrecognized.
    pub const fn decode(byte: u8) -> Result<Self, u8> {
        match byte {
            0 => Ok(Self::SnapshotCreate),
            1 => Ok(Self::SnapshotOpen),
            2 => Ok(Self::Enumeration),
            3 => Ok(Self::Identity),
            4 => Ok(Self::StreamResolution),
            5 => Ok(Self::RunlistValidation),
            6 => Ok(Self::Read),
            7 => Ok(Self::Reconstruction),
            8 => Ok(Self::Hash),
            9 => Ok(Self::Transport),
            10 => Ok(Self::ConsumerAck),
            11 => Ok(Self::Internal),
            other => Err(other),
        }
    }
}

impl RetryClass {
    /// Serialize to the wire byte.
    #[must_use]
    pub const fn encode(self) -> u8 {
        self as u8
    }

    /// Parse the wire byte.
    ///
    /// # Errors
    /// Returns the offending byte if unrecognized.
    pub const fn decode(byte: u8) -> Result<Self, u8> {
        match byte {
            0 => Ok(Self::RetrySameJob),
            1 => Ok(Self::RetryNewSnapshot),
            2 => Ok(Self::RetryAfterResourceChange),
            3 => Ok(Self::RetryWithManualHandler),
            4 => Ok(Self::RetryWithCredentialOrKey),
            5 => Ok(Self::DoNotRetry),
            other => Err(other),
        }
    }
}

impl ConsumerAckStatus {
    /// Serialize to the wire byte.
    #[must_use]
    pub const fn encode(self) -> u8 {
        self as u8
    }

    /// Parse the wire byte.
    ///
    /// # Errors
    /// Returns the offending byte if unrecognized.
    pub const fn decode(byte: u8) -> Result<Self, u8> {
        match byte {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::Rejected),
            other => Err(other),
        }
    }
}

// ───────────────────────── string/option helpers ─────────────────────────

/// Maximum byte length for a free-text `message` field.
const MAX_MESSAGE_BYTES: u16 = 4096;

/// Append a `u16`-length-prefixed UTF-8 `message` field.
fn write_message(out: &mut Vec<u8>, message: &str) {
    write_bytes_u16_prefixed(out, message.as_bytes());
}

/// Read and UTF-8-validate a `u16`-length-prefixed `message` field.
fn read_message(reader: &mut Reader<'_>) -> Result<String, FrameError> {
    let bytes = reader.read_bytes_u16_prefixed("message", MAX_MESSAGE_BYTES)?;
    String::from_utf8(bytes).map_err(|_err| FrameError::InvalidUtf8("message"))
}

/// Append an `Option<i64>` as a presence byte followed by the value if present.
fn write_optional_i64(out: &mut Vec<u8>, value: Option<i64>) {
    match value {
        Some(present_value) => {
            out.push(1);
            write_i64_le(out, present_value);
        }
        None => out.push(0),
    }
}

/// Read an `Option<i64>` encoded by [`write_optional_i64`].
fn read_optional_i64(reader: &mut Reader<'_>) -> Result<Option<i64>, FrameError> {
    let present = reader.read_u8()?;
    match present {
        0 => Ok(None),
        _ => Ok(Some(reader.read_i64_le()?)),
    }
}

/// Append an `Option<u64>` as a presence byte followed by the value if present.
fn write_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(present_value) => {
            out.push(1);
            write_u64_le(out, present_value);
        }
        None => out.push(0),
    }
}

/// Read an `Option<u64>` encoded by [`write_optional_u64`].
fn read_optional_u64(reader: &mut Reader<'_>) -> Result<Option<u64>, FrameError> {
    let present = reader.read_u8()?;
    match present {
        0 => Ok(None),
        _ => Ok(Some(reader.read_u64_le()?)),
    }
}

#[cfg(test)]
mod tests;
