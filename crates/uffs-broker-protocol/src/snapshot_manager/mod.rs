// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Snapshot Manager wire protocol: the Broker's VSS-lifecycle API.
//!
//! Per the ingest-protocol addendum §4, the Broker (already the trusted
//! `LocalSystem` boundary for MFT handle vending) is extended with a
//! narrow Snapshot Manager subsystem that creates, leases, monitors, and
//! deletes VSS snapshots on behalf of `uffs-content` (the Content
//! Coordinator), and duplicates a read-only snapshot handle only to the
//! Snapshot Reader process — never to the Coordinator itself.
//!
//! This is deliberately **not** a general-purpose VSS administration API
//! (addendum §4.3): five narrow operations plus a status query.
//!
//! Uses a separate named pipe from [`crate::PIPE_NAME`] (the existing
//! Broker↔daemon MFT-handle channel) — Coordinator↔Broker is a distinct
//! channel with a distinct peer and distinct trust check, per
//! `uffs-ingest-implementation-plan.md` §4.1.

mod codec;
mod messages;

pub use codec::SnapshotProtocolError;
use codec::{Reader, write_i64_le, write_optional_i32, write_string_u16_prefixed};
pub use messages::{
    CreateSnapshotLease, CreateSnapshotLeaseResult, DuplicateSnapshotHandle, QuerySnapshotLease,
    ReleaseSnapshotLease, RenewSnapshotLease, SnapshotLeaseState, SnapshotLeaseStatus,
    SnapshotManagerErrorCode, VolumeIdentity,
};

/// Named-pipe path the Broker's Snapshot Manager listens on.
///
/// Distinct from [`crate::PIPE_NAME`] (daemon↔Broker MFT handle vending)
/// and from `uffs-content-reader-protocol::READER_PIPE_NAME`
/// (Coordinator↔Snapshot Reader).
pub const SNAPSHOT_PIPE_NAME: &str = r"\\.\pipe\uffs-broker-snapshot";

/// Maximum byte length for opaque identifier fields (volume GUIDs,
/// snapshot IDs, device identity strings) in this protocol.
pub const MAX_IDENTIFIER_BYTES: u32 = 1024;

/// Maximum byte length for a lossless UTF-16LE `requested_root` path.
pub const MAX_PATH_BYTES: u32 = 32_767 * 2;

/// Maximum byte length for a free-text diagnostic message.
const MAX_MESSAGE_BYTES: u16 = 4096;

/// Tagged union of every Snapshot Manager request (addendum §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotManagerRequest {
    /// See [`CreateSnapshotLease`].
    Create(CreateSnapshotLease),
    /// See [`DuplicateSnapshotHandle`].
    Duplicate(DuplicateSnapshotHandle),
    /// See [`RenewSnapshotLease`].
    Renew(RenewSnapshotLease),
    /// See [`ReleaseSnapshotLease`].
    Release(ReleaseSnapshotLease),
    /// See [`QuerySnapshotLease`].
    Query(QuerySnapshotLease),
}

/// Wire discriminant tags for [`SnapshotManagerRequest`].
pub(crate) mod request_tag {
    /// Tag for [`super::SnapshotManagerRequest::Create`].
    pub(crate) const CREATE: u8 = 0;
    /// Tag for [`super::SnapshotManagerRequest::Duplicate`].
    pub(crate) const DUPLICATE: u8 = 1;
    /// Tag for [`super::SnapshotManagerRequest::Renew`].
    pub(crate) const RENEW: u8 = 2;
    /// Tag for [`super::SnapshotManagerRequest::Release`].
    pub(crate) const RELEASE: u8 = 3;
    /// Tag for [`super::SnapshotManagerRequest::Query`].
    pub(crate) const QUERY: u8 = 4;
}

impl SnapshotManagerRequest {
    /// Encode this request.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Create(request) => {
                out.push(request_tag::CREATE);
                out.extend_from_slice(&request.encode());
            }
            Self::Duplicate(request) => {
                out.push(request_tag::DUPLICATE);
                out.extend_from_slice(&request.encode());
            }
            Self::Renew(request) => {
                out.push(request_tag::RENEW);
                out.extend_from_slice(&request.encode());
            }
            Self::Release(request) => {
                out.push(request_tag::RELEASE);
                out.extend_from_slice(&request.encode());
            }
            Self::Query(request) => {
                out.push(request_tag::QUERY);
                out.extend_from_slice(&request.encode());
            }
        }
        out
    }

    /// Decode a request from raw bytes.
    ///
    /// # Errors
    /// See [`SnapshotProtocolError`].
    pub fn decode(bytes: &[u8]) -> Result<Self, SnapshotProtocolError> {
        let mut reader = Reader::new(bytes);
        let tag = reader.read_u8()?;
        match tag {
            request_tag::CREATE => Ok(Self::Create(CreateSnapshotLease::decode(&mut reader)?)),
            request_tag::DUPLICATE => Ok(Self::Duplicate(DuplicateSnapshotHandle::decode(
                &mut reader,
            )?)),
            request_tag::RENEW => Ok(Self::Renew(RenewSnapshotLease::decode(&mut reader)?)),
            request_tag::RELEASE => Ok(Self::Release(ReleaseSnapshotLease::decode(&mut reader)?)),
            request_tag::QUERY => Ok(Self::Query(QuerySnapshotLease::decode(&mut reader)?)),
            other => Err(SnapshotProtocolError::UnknownDiscriminant {
                field: "request_tag",
                value: u64::from(other),
            }),
        }
    }
}

/// Tagged union of every Snapshot Manager response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotManagerResponse {
    /// Response to [`SnapshotManagerRequest::Create`].
    Created(CreateSnapshotLeaseResult),
    /// Response to [`SnapshotManagerRequest::Duplicate`]: the handle was
    /// duplicated out of band; this just acknowledges success.
    Duplicated,
    /// Response to [`SnapshotManagerRequest::Renew`].
    Renewed {
        /// The lease's new expiry, Unix milliseconds.
        new_expires_at_unix_ms: i64,
    },
    /// Response to [`SnapshotManagerRequest::Release`].
    Released,
    /// Response to [`SnapshotManagerRequest::Query`].
    Status(SnapshotLeaseStatus),
    /// Any request failed.
    Error {
        /// Stable error code.
        code: SnapshotManagerErrorCode,
        /// The underlying `HRESULT`, when the failure came from a VSS
        /// call and one is available (e.g. `VSS_E_VOLUME_NOT_SUPPORTED`
        /// for a [`SnapshotManagerErrorCode::SnapshotCreateFailed`] on a
        /// volume VSS doesn't support, such as removable media) — lets
        /// callers distinguish specific, permanent VSS failure reasons
        /// from `message`'s free text instead of string-matching it.
        hresult: Option<i32>,
        /// Human-readable diagnostic message.
        message: String,
    },
}

/// Wire discriminant tags for [`SnapshotManagerResponse`].
pub(crate) mod response_tag {
    /// Tag for [`super::SnapshotManagerResponse::Created`].
    pub(crate) const CREATED: u8 = 0;
    /// Tag for [`super::SnapshotManagerResponse::Duplicated`].
    pub(crate) const DUPLICATED: u8 = 1;
    /// Tag for [`super::SnapshotManagerResponse::Renewed`].
    pub(crate) const RENEWED: u8 = 2;
    /// Tag for [`super::SnapshotManagerResponse::Released`].
    pub(crate) const RELEASED: u8 = 3;
    /// Tag for [`super::SnapshotManagerResponse::Status`].
    pub(crate) const STATUS: u8 = 4;
    /// Tag for [`super::SnapshotManagerResponse::Error`].
    pub(crate) const ERROR: u8 = 5;
}

impl SnapshotManagerResponse {
    /// Encode this response.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Created(result) => {
                out.push(response_tag::CREATED);
                out.extend_from_slice(&result.encode());
            }
            Self::Duplicated => out.push(response_tag::DUPLICATED),
            Self::Renewed {
                new_expires_at_unix_ms,
            } => {
                out.push(response_tag::RENEWED);
                write_i64_le(&mut out, *new_expires_at_unix_ms);
            }
            Self::Released => out.push(response_tag::RELEASED),
            Self::Status(status) => {
                out.push(response_tag::STATUS);
                out.extend_from_slice(&status.encode());
            }
            Self::Error {
                code,
                hresult,
                message,
            } => {
                out.push(response_tag::ERROR);
                out.push(code.encode());
                write_optional_i32(&mut out, *hresult);
                write_string_u16_prefixed(&mut out, message);
            }
        }
        out
    }

    /// Decode a response from raw bytes.
    ///
    /// # Errors
    /// See [`SnapshotProtocolError`].
    pub fn decode(bytes: &[u8]) -> Result<Self, SnapshotProtocolError> {
        let mut reader = Reader::new(bytes);
        let tag = reader.read_u8()?;
        match tag {
            response_tag::CREATED => Ok(Self::Created(CreateSnapshotLeaseResult::decode(
                &mut reader,
            )?)),
            response_tag::DUPLICATED => Ok(Self::Duplicated),
            response_tag::RENEWED => Ok(Self::Renewed {
                new_expires_at_unix_ms: reader.read_i64_le()?,
            }),
            response_tag::RELEASED => Ok(Self::Released),
            response_tag::STATUS => Ok(Self::Status(SnapshotLeaseStatus::decode(&mut reader)?)),
            response_tag::ERROR => {
                let code_byte = reader.read_u8()?;
                let code = SnapshotManagerErrorCode::decode(code_byte).map_err(|byte| {
                    SnapshotProtocolError::UnknownDiscriminant {
                        field: "code",
                        value: u64::from(byte),
                    }
                })?;
                let hresult = reader.read_optional_i32()?;
                let message = reader.read_string_u16_prefixed("message", MAX_MESSAGE_BYTES)?;
                Ok(Self::Error {
                    code,
                    hresult,
                    message,
                })
            }
            other => Err(SnapshotProtocolError::UnknownDiscriminant {
                field: "response_tag",
                value: u64::from(other),
            }),
        }
    }
}

#[cfg(test)]
mod tests;
