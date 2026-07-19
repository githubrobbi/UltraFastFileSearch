// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Private wire protocol between `uffs-content` (the unprivileged Content
//! Coordinator) and the privileged Snapshot Reader process.
//!
//! Addendum §2.1-§2.4: the Coordinator never receives the snapshot
//! handle, LCNs, extents, or raw MFT records. It sends a typed
//! [`ReadRequest`] naming a candidate and a logical byte range; the
//! Reader resolves the stream itself, validates the range against the
//! snapshot's own EOF/VDL, and returns bounded logical bytes or a typed
//! error — never accepting an arbitrary `(physical_offset, length)`.
//!
//! # Status
//!
//! Scaffold: types and wire codec only. No transport (named pipe)
//! implementation yet — that lives in `uffs-content` (client side) and
//! the Snapshot Reader binary (server side) once they exist.

pub mod codec;

use codec::{
    DecodeError, Reader, write_bytes_u32_prefixed, write_string_u16_prefixed, write_u32_le,
    write_u64_le,
};

/// Named-pipe path the Snapshot Reader listens on.
///
/// Deliberately separate from `uffs-broker-protocol::PIPE_NAME` (daemon
/// <-> Broker) and from the Broker's Snapshot Manager endpoint
/// (`uffs-broker-protocol::SNAPSHOT_PIPE_NAME`, once that lands) —
/// Coordinator<->Reader is a distinct channel with a distinct peer and
/// distinct trust check, per
/// `uffs-ingest-implementation-plan.md` §3.3.
pub const READER_PIPE_NAME: &str = r"\\.\pipe\uffs-content-reader";

/// Maximum byte length for `snapshot_device_identity`-style opaque
/// identifier fields in this protocol.
pub const MAX_IDENTIFIER_BYTES: u32 = 512;

/// Maximum byte length for a free-text diagnostic message.
const MAX_MESSAGE_BYTES: u16 = 4096;

/// Append an `Option<u64>` as a presence byte followed by the value if
/// present — mirrors `uffs-content-protocol::frame::write_optional_u64`
/// (this crate deliberately duplicates rather than depends on that
/// Layer-0 crate; see [`codec`]'s own module doc).
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
fn read_optional_u64(reader: &mut Reader<'_>) -> Result<Option<u64>, DecodeError> {
    let present = reader.read_u8()?;
    match present {
        0 => Ok(None),
        _ => Ok(Some(reader.read_u64_le()?)),
    }
}

/// A volume's identity, as carried in a [`ReadRequest`] (addendum §2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeIdentity {
    /// NTFS volume serial number.
    pub volume_serial: u64,
    /// Opaque volume GUID bytes.
    pub volume_guid: Vec<u8>,
}

impl VolumeIdentity {
    /// Append this identity's wire encoding to `out`.
    fn encode(&self, out: &mut Vec<u8>) {
        write_u64_le(out, self.volume_serial);
        write_bytes_u32_prefixed(out, &self.volume_guid);
    }

    /// Decode an identity from `reader`.
    fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let volume_serial = reader.read_u64_le()?;
        let volume_guid = reader.read_bytes_u32_prefixed("volume_guid", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            volume_serial,
            volume_guid,
        })
    }
}

/// Which stream a [`ReadRequest`] targets.
///
/// Only [`StreamKind::UnnamedData`] exists in v2 (design-doc §2.6: no ADS
/// in this version) — modeled as an enum so a future version can add
/// variants without breaking the field shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StreamKind {
    /// The unnamed/default `$DATA` stream.
    UnnamedData = 0,
}

impl StreamKind {
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
            0 => Ok(Self::UnnamedData),
            other => Err(other),
        }
    }
}

/// The read mode a [`ReadRequest`] asks the Reader to use.
///
/// Addendum §2.3/§3.6 planner. Distinct from
/// `uffs_content_protocol::frame::ReadMode` (which reports what mode was
/// *actually* used, after the fact, and includes `Resident`/`MetadataOnly`
/// — concepts that don't apply to an outgoing request).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RequestedReadMode {
    /// Let the Reader choose the best available mode (including resident
    /// inline reads where applicable).
    Auto = 0,
    /// Require a logical snapshot-namespace read.
    Logical = 1,
    /// Require the benchmark-gated raw accelerator (only valid once
    /// UFI.3 approves it — see addendum §3).
    RawAccelerator = 2,
}

impl RequestedReadMode {
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
            0 => Ok(Self::Auto),
            1 => Ok(Self::Logical),
            2 => Ok(Self::RawAccelerator),
            other => Err(other),
        }
    }
}

/// The read mode a [`ReadResponse::Bytes`] reports as actually used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ActualReadMode {
    /// Read from the MFT-resident attribute value.
    Resident = 0,
    /// Logical open + read against the snapshot namespace.
    Logical = 1,
    /// Raw runlist/extent reconstruction.
    RawAccelerator = 2,
}

impl ActualReadMode {
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
            1 => Ok(Self::Logical),
            2 => Ok(Self::RawAccelerator),
            other => Err(other),
        }
    }
}

/// Stable error codes for a [`ReadResponse::Error`].
///
/// A narrow subset of `uffs_content_protocol::error::ErrorCode` relevant
/// specifically to a single read — duplicated rather than shared, per
/// this crate's Layer-0-independence rationale (see `Cargo.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum ReaderErrorCode {
    /// The requested snapshot lease is not known to the Reader.
    LeaseInvalid = 0,
    /// The requested snapshot lease has expired.
    LeaseExpired = 1,
    /// The candidate is not part of the finalized manifest the Reader
    /// was given for this job.
    CandidateNotInManifest = 2,
    /// The opened object's identity does not match the manifest
    /// (design-doc §5.2/§16 `IDENTITY_MISMATCH`).
    IdentityMismatch = 3,
    /// The requested stream was not found.
    StreamNotFound = 4,
    /// The requested logical range violates the EOF/VDL relationship.
    VdlEofInvalid = 5,
    /// The requested range falls outside validated bounds.
    ExtentOutOfBounds = 6,
    /// A transient I/O error occurred.
    ReadIoTransient = 7,
    /// A permanent I/O error occurred.
    ReadIoPermanent = 8,
    /// An internal Reader error not covered by another code.
    InternalError = 9,
}

impl ReaderErrorCode {
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
            0 => Ok(Self::LeaseInvalid),
            1 => Ok(Self::LeaseExpired),
            2 => Ok(Self::CandidateNotInManifest),
            3 => Ok(Self::IdentityMismatch),
            4 => Ok(Self::StreamNotFound),
            5 => Ok(Self::VdlEofInvalid),
            6 => Ok(Self::ExtentOutOfBounds),
            7 => Ok(Self::ReadIoTransient),
            8 => Ok(Self::ReadIoPermanent),
            9 => Ok(Self::InternalError),
            other => Err(other),
        }
    }
}

/// A read request from the Coordinator to the Reader (addendum §2.3).
///
/// The Reader MUST treat every field here as untrusted input to be
/// revalidated against the snapshot itself — `logical_offset` +
/// `maximum_logical_length` is never trusted as an in-bounds range purely
/// because the Coordinator sent it (design-doc §15.4, this crate's
/// `README`-level contract in the implementation plan §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    /// Job this read belongs to.
    pub job_id: [u8; 16],
    /// Snapshot lease this read is scoped to.
    pub snapshot_lease_id: u64,
    /// Candidate being read.
    pub candidate_id: u64,
    /// Volume the candidate lives on.
    pub volume_identity: VolumeIdentity,
    /// Full NTFS file reference (never a bare MFT record index).
    pub full_file_reference: u64,
    /// The candidate's logical size, if the Coordinator already knows it
    /// from the manifest that named this candidate. `Some` lets the
    /// Reader skip its own `GetFileSizeEx` re-resolution and trust this
    /// value directly — a real (if rare) trust tradeoff, so this is
    /// opt-in per request, not a blanket assumption: only the real VSS
    /// Coordinator (`uffs-content::job::content_source::VssContentSource`)
    /// populates it today, since its manifest size was itself read from
    /// the same frozen snapshot this request targets. Any other/future
    /// caller that leaves this `None` gets the Reader's original
    /// always-re-verify behavior with no code changes required on its
    /// part — see `uffs-content-reader::reader::logical`'s module doc.
    pub known_logical_size: Option<u64>,
    /// Which stream to read.
    pub stream_kind: StreamKind,
    /// Logical byte offset to start reading at.
    pub logical_offset: u64,
    /// Maximum bytes to return for this request.
    pub maximum_logical_length: u32,
    /// Which read mode to use.
    pub requested_mode: RequestedReadMode,
    /// Caller-chosen nonce, echoed back for request/response correlation.
    pub request_nonce: u64,
}

impl ReadRequest {
    /// Encode this request.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.job_id);
        write_u64_le(&mut out, self.snapshot_lease_id);
        write_u64_le(&mut out, self.candidate_id);
        self.volume_identity.encode(&mut out);
        write_u64_le(&mut out, self.full_file_reference);
        write_optional_u64(&mut out, self.known_logical_size);
        out.push(self.stream_kind.encode());
        write_u64_le(&mut out, self.logical_offset);
        write_u32_le(&mut out, self.maximum_logical_length);
        out.push(self.requested_mode.encode());
        write_u64_le(&mut out, self.request_nonce);
        out
    }

    /// Decode a request from `reader`.
    ///
    /// # Errors
    /// See [`DecodeError`].
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let job_id: [u8; 16] = reader.read_array()?;
        let snapshot_lease_id = reader.read_u64_le()?;
        let candidate_id = reader.read_u64_le()?;
        let volume_identity = VolumeIdentity::decode(reader)?;
        let full_file_reference = reader.read_u64_le()?;
        let known_logical_size = read_optional_u64(reader)?;
        let stream_kind_byte = reader.read_u8()?;
        let stream_kind = StreamKind::decode(stream_kind_byte).map_err(|byte| {
            DecodeError::UnknownDiscriminant {
                field: "stream_kind",
                value: u64::from(byte),
            }
        })?;
        let logical_offset = reader.read_u64_le()?;
        let maximum_logical_length = reader.read_u32_le()?;
        let requested_mode_byte = reader.read_u8()?;
        let requested_mode = RequestedReadMode::decode(requested_mode_byte).map_err(|byte| {
            DecodeError::UnknownDiscriminant {
                field: "requested_mode",
                value: u64::from(byte),
            }
        })?;
        let request_nonce = reader.read_u64_le()?;
        Ok(Self {
            job_id,
            snapshot_lease_id,
            candidate_id,
            volume_identity,
            full_file_reference,
            known_logical_size,
            stream_kind,
            logical_offset,
            maximum_logical_length,
            requested_mode,
            request_nonce,
        })
    }
}

/// A read response from the Reader to the Coordinator (addendum §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadResponse {
    /// The request succeeded; `payload` is bounded by the request's
    /// `maximum_logical_length`.
    Bytes {
        /// Logical offset these bytes start at (echoes the request).
        logical_offset: u64,
        /// Which mode the Reader actually used.
        actual_mode: ActualReadMode,
        /// The logical bytes read.
        payload: Vec<u8>,
    },
    /// The request failed.
    Error {
        /// Stable error code.
        code: ReaderErrorCode,
        /// Human-readable diagnostic message.
        message: String,
    },
}

/// Wire discriminant for [`ReadResponse`]'s two variants.
const RESPONSE_TAG_BYTES: u8 = 0;
/// Wire discriminant for [`ReadResponse`]'s two variants.
const RESPONSE_TAG_ERROR: u8 = 1;

/// Bound on a single [`ReadResponse::Bytes`] payload.
///
/// A conservative chunk ceiling; the Coordinator's own `max_chunk_bytes`
/// (see `uffs_content_protocol::frame::JobBegin`) governs the real
/// negotiated value.
pub const MAX_RESPONSE_PAYLOAD_BYTES: u32 = 64 * 1024 * 1024;

impl ReadResponse {
    /// Encode this response.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Bytes {
                logical_offset,
                actual_mode,
                payload,
            } => {
                out.push(RESPONSE_TAG_BYTES);
                write_u64_le(&mut out, *logical_offset);
                out.push(actual_mode.encode());
                write_bytes_u32_prefixed(&mut out, payload);
            }
            Self::Error { code, message } => {
                out.push(RESPONSE_TAG_ERROR);
                out.push(code.encode());
                write_string_u16_prefixed(&mut out, message);
            }
        }
        out
    }

    /// Decode a response from `reader`.
    ///
    /// `max_payload_bytes` bounds the `Bytes` payload before allocation.
    ///
    /// # Errors
    /// See [`DecodeError`].
    pub fn decode(reader: &mut Reader<'_>, max_payload_bytes: u32) -> Result<Self, DecodeError> {
        let tag = reader.read_u8()?;
        match tag {
            RESPONSE_TAG_BYTES => {
                let logical_offset = reader.read_u64_le()?;
                let mode_byte = reader.read_u8()?;
                let actual_mode = ActualReadMode::decode(mode_byte).map_err(|byte| {
                    DecodeError::UnknownDiscriminant {
                        field: "actual_mode",
                        value: u64::from(byte),
                    }
                })?;
                let payload = reader.read_bytes_u32_prefixed("payload", max_payload_bytes)?;
                Ok(Self::Bytes {
                    logical_offset,
                    actual_mode,
                    payload,
                })
            }
            RESPONSE_TAG_ERROR => {
                let code_byte = reader.read_u8()?;
                let code = ReaderErrorCode::decode(code_byte).map_err(|byte| {
                    DecodeError::UnknownDiscriminant {
                        field: "code",
                        value: u64::from(byte),
                    }
                })?;
                let message = reader.read_string_u16_prefixed("message", MAX_MESSAGE_BYTES)?;
                Ok(Self::Error { code, message })
            }
            other => Err(DecodeError::UnknownDiscriminant {
                field: "response_tag",
                value: u64::from(other),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{
        ActualReadMode, DecodeError, ReadRequest, ReadResponse, Reader, ReaderErrorCode,
        RequestedReadMode, StreamKind, VolumeIdentity,
    };

    fn sample_request() -> ReadRequest {
        ReadRequest {
            job_id: [1_u8; 16],
            snapshot_lease_id: 42,
            candidate_id: 12345,
            volume_identity: VolumeIdentity {
                volume_serial: 0x0102_0304_0506_0708,
                volume_guid: b"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}".to_vec(),
            },
            full_file_reference: 0xABCD_EF01_2345_6789,
            known_logical_size: Some(65536),
            stream_kind: StreamKind::UnnamedData,
            logical_offset: 4096,
            maximum_logical_length: 65536,
            requested_mode: RequestedReadMode::Auto,
            request_nonce: 999,
        }
    }

    #[test]
    fn read_request_round_trips() {
        let request = sample_request();
        let bytes = request.encode();
        let mut reader = Reader::new(&bytes);
        let decoded = ReadRequest::decode(&mut reader).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn read_request_with_no_known_logical_size_round_trips() {
        let request = ReadRequest {
            known_logical_size: None,
            ..sample_request()
        };
        let bytes = request.encode();
        let mut reader = Reader::new(&bytes);
        let decoded = ReadRequest::decode(&mut reader).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn read_response_bytes_round_trips() {
        let response = ReadResponse::Bytes {
            logical_offset: 4096,
            actual_mode: ActualReadMode::Logical,
            payload: vec![1, 2, 3, 4, 5],
        };
        let bytes = response.encode();
        let mut reader = Reader::new(&bytes);
        let decoded = ReadResponse::decode(&mut reader, 1024).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn read_response_error_round_trips() {
        let response = ReadResponse::Error {
            code: ReaderErrorCode::VdlEofInvalid,
            message: "requested range past EOF".to_owned(),
        };
        let bytes = response.encode();
        let mut reader = Reader::new(&bytes);
        let decoded = ReadResponse::decode(&mut reader, 1024).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn read_response_bytes_rejects_payload_over_max_before_allocation() {
        let response = ReadResponse::Bytes {
            logical_offset: 0,
            actual_mode: ActualReadMode::Resident,
            payload: vec![0_u8; 100],
        };
        let bytes = response.encode();
        let mut reader = Reader::new(&bytes);
        let err = ReadResponse::decode(&mut reader, 10).unwrap_err();
        assert!(matches!(err, DecodeError::LengthOutOfBounds { .. }));
    }

    #[test]
    fn read_response_rejects_unknown_tag() {
        let bytes = vec![0xFF];
        let mut reader = Reader::new(&bytes);
        let err = ReadResponse::decode(&mut reader, 1024).unwrap_err();
        assert!(matches!(err, DecodeError::UnknownDiscriminant {
            field: "response_tag",
            ..
        }));
    }

    #[test]
    fn requested_read_mode_round_trips_all_variants() {
        for value in 0_u8..=2 {
            let mode = RequestedReadMode::decode(value).unwrap();
            assert_eq!(mode.encode(), value);
        }
        assert_eq!(RequestedReadMode::decode(3), Err(3));
    }

    #[test]
    fn actual_read_mode_round_trips_all_variants() {
        for value in 0_u8..=2 {
            let mode = ActualReadMode::decode(value).unwrap();
            assert_eq!(mode.encode(), value);
        }
        assert_eq!(ActualReadMode::decode(3), Err(3));
    }

    #[test]
    fn reader_error_code_round_trips_all_variants() {
        for value in 0_u8..=9 {
            let code = ReaderErrorCode::decode(value).unwrap();
            assert_eq!(code.encode(), value);
        }
        assert_eq!(ReaderErrorCode::decode(10), Err(10));
    }

    #[test]
    fn stream_kind_round_trips() {
        assert_eq!(StreamKind::decode(0).unwrap(), StreamKind::UnnamedData);
        assert_eq!(StreamKind::decode(1), Err(1));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        #[test]
        fn read_request_round_trips_for_arbitrary_fields(
            snapshot_lease_id: u64,
            candidate_id: u64,
            volume_serial: u64,
            full_file_reference: u64,
            known_logical_size: Option<u64>,
            logical_offset: u64,
            maximum_logical_length: u32,
            request_nonce: u64,
        ) {
            let request = ReadRequest {
                job_id: [7_u8; 16],
                snapshot_lease_id,
                candidate_id,
                volume_identity: VolumeIdentity {
                    volume_serial,
                    volume_guid: b"{guid}".to_vec(),
                },
                full_file_reference,
                known_logical_size,
                stream_kind: StreamKind::UnnamedData,
                logical_offset,
                maximum_logical_length,
                requested_mode: RequestedReadMode::Logical,
                request_nonce,
            };
            let bytes = request.encode();
            let mut reader = Reader::new(&bytes);
            let decoded = ReadRequest::decode(&mut reader).unwrap();
            prop_assert_eq!(decoded, request);
        }
    }
}
