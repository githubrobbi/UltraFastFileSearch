// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Individual Snapshot Manager request/response message types
//! (addendum §4.3). See [`super`] for the tagged
//! [`super::SnapshotManagerRequest`]/[`super::SnapshotManagerResponse`]
//! envelopes that wrap these for transport.

use super::codec::{
    Reader, SnapshotProtocolError, write_bytes_u32_prefixed, write_i64_le,
    write_string_u16_prefixed, write_u32_le, write_u64_le,
};
use super::{MAX_IDENTIFIER_BYTES, MAX_PATH_BYTES};

/// A source volume's identity (matches the shape carried elsewhere in
/// the UFFS content-ingest protocols; duplicated here for the same
/// Layer-0-independence reason).
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
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self, SnapshotProtocolError> {
        let volume_serial = reader.read_u64_le()?;
        let volume_guid = reader.read_bytes_u32_prefixed("volume_guid", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            volume_serial,
            volume_guid,
        })
    }
}

/// `CreateSnapshotLease` request (addendum §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSnapshotLease {
    /// Job this snapshot is being created for.
    pub authenticated_job_id: [u8; 16],
    /// Identity of the volume to snapshot.
    pub source_volume_identity: VolumeIdentity,
    /// Requested root, as lossless UTF-16LE code-unit bytes.
    pub requested_root: Vec<u8>,
    /// Maximum lease lifetime, in seconds.
    pub maximum_lifetime_secs: u64,
    /// Policy this job was authorized under.
    pub policy_id: u32,
}

impl CreateSnapshotLease {
    /// Encode this request.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.authenticated_job_id);
        self.source_volume_identity.encode(&mut out);
        write_bytes_u32_prefixed(&mut out, &self.requested_root);
        write_u64_le(&mut out, self.maximum_lifetime_secs);
        write_u32_le(&mut out, self.policy_id);
        out
    }

    /// Decode this request.
    ///
    /// # Errors
    /// See [`SnapshotProtocolError`].
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self, SnapshotProtocolError> {
        let authenticated_job_id: [u8; 16] = reader.read_array()?;
        let source_volume_identity = VolumeIdentity::decode(reader)?;
        let requested_root = reader.read_bytes_u32_prefixed("requested_root", MAX_PATH_BYTES)?;
        let maximum_lifetime_secs = reader.read_u64_le()?;
        let policy_id = reader.read_u32_le()?;
        Ok(Self {
            authenticated_job_id,
            source_volume_identity,
            requested_root,
            maximum_lifetime_secs,
            policy_id,
        })
    }
}

/// `CreateSnapshotLeaseResult` response (addendum §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSnapshotLeaseResult {
    /// Lease identifier the Coordinator uses in all subsequent calls.
    pub snapshot_lease_id: u64,
    /// Opaque VSS snapshot identifier.
    pub snapshot_id: Vec<u8>,
    /// Device path the snapshot is reachable at (e.g.
    /// `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`), as a UTF-8
    /// string — this device identity is safe to hand to the Coordinator;
    /// it is not a handle or LCN/extent information.
    pub snapshot_device_identity: String,
    /// Snapshot creation time, Unix milliseconds.
    pub snapshot_created_at_unix_ms: i64,
    /// Current lease expiry time, Unix milliseconds.
    pub expires_at_unix_ms: i64,
}

impl CreateSnapshotLeaseResult {
    /// Encode this result.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.snapshot_lease_id);
        write_bytes_u32_prefixed(&mut out, &self.snapshot_id);
        write_string_u16_prefixed(&mut out, &self.snapshot_device_identity);
        write_i64_le(&mut out, self.snapshot_created_at_unix_ms);
        write_i64_le(&mut out, self.expires_at_unix_ms);
        out
    }

    /// Decode this result.
    ///
    /// # Errors
    /// See [`SnapshotProtocolError`].
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self, SnapshotProtocolError> {
        let snapshot_lease_id = reader.read_u64_le()?;
        let snapshot_id = reader.read_bytes_u32_prefixed("snapshot_id", MAX_IDENTIFIER_BYTES)?;
        let snapshot_device_identity =
            reader.read_string_u16_prefixed("snapshot_device_identity", 2048)?;
        let snapshot_created_at_unix_ms = reader.read_i64_le()?;
        let expires_at_unix_ms = reader.read_i64_le()?;
        Ok(Self {
            snapshot_lease_id,
            snapshot_id,
            snapshot_device_identity,
            snapshot_created_at_unix_ms,
            expires_at_unix_ms,
        })
    }
}

/// `DuplicateSnapshotHandle` request (addendum §4.3).
///
/// The actual `DuplicateHandle` call happens Broker-side, out of band;
/// this wire message only names which already-authenticated reader
/// process the Broker should duplicate the handle *into* — the Broker
/// verifies that process's identity itself (reusing the same
/// `check_client_identity` pattern already used for daemon
/// verification), it does not trust this PID as proof of anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateSnapshotHandle {
    /// Lease the handle should be scoped to.
    pub snapshot_lease_id: u64,
    /// PID of the Snapshot Reader process to duplicate the handle into.
    pub approved_reader_process_id: u32,
}

impl DuplicateSnapshotHandle {
    /// Encode this request.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.snapshot_lease_id);
        write_u32_le(&mut out, self.approved_reader_process_id);
        out
    }

    /// Decode this request.
    ///
    /// # Errors
    /// See [`SnapshotProtocolError`].
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self, SnapshotProtocolError> {
        let snapshot_lease_id = reader.read_u64_le()?;
        let approved_reader_process_id = reader.read_u32_le()?;
        Ok(Self {
            snapshot_lease_id,
            approved_reader_process_id,
        })
    }
}

/// `RenewSnapshotLease` request (addendum §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenewSnapshotLease {
    /// Lease to renew.
    pub snapshot_lease_id: u64,
    /// Requested new expiry, Unix milliseconds.
    pub requested_expiry_unix_ms: i64,
}

impl RenewSnapshotLease {
    /// Encode this request.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.snapshot_lease_id);
        write_i64_le(&mut out, self.requested_expiry_unix_ms);
        out
    }

    /// Decode this request.
    ///
    /// # Errors
    /// See [`SnapshotProtocolError`].
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self, SnapshotProtocolError> {
        let snapshot_lease_id = reader.read_u64_le()?;
        let requested_expiry_unix_ms = reader.read_i64_le()?;
        Ok(Self {
            snapshot_lease_id,
            requested_expiry_unix_ms,
        })
    }
}

/// `ReleaseSnapshotLease` request (addendum §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseSnapshotLease {
    /// Lease to release.
    pub snapshot_lease_id: u64,
}

impl ReleaseSnapshotLease {
    /// Encode this request.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.snapshot_lease_id);
        out
    }

    /// Decode this request.
    ///
    /// # Errors
    /// See [`SnapshotProtocolError`].
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self, SnapshotProtocolError> {
        Ok(Self {
            snapshot_lease_id: reader.read_u64_le()?,
        })
    }
}

/// `QuerySnapshotLease` request (addendum §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuerySnapshotLease {
    /// Lease to query.
    pub snapshot_lease_id: u64,
}

impl QuerySnapshotLease {
    /// Encode this request.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.snapshot_lease_id);
        out
    }

    /// Decode this request.
    ///
    /// # Errors
    /// See [`SnapshotProtocolError`].
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self, SnapshotProtocolError> {
        Ok(Self {
            snapshot_lease_id: reader.read_u64_le()?,
        })
    }
}

/// Current state of a snapshot lease, reported by [`QuerySnapshotLease`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SnapshotLeaseState {
    /// Lease is active and the snapshot is retained.
    Active = 0,
    /// Lease expired without renewal.
    Expired = 1,
    /// Lease was explicitly released.
    Released = 2,
    /// The Broker has no record of this lease (unknown or already reaped).
    Unknown = 3,
}

impl SnapshotLeaseState {
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
            0 => Ok(Self::Active),
            1 => Ok(Self::Expired),
            2 => Ok(Self::Released),
            3 => Ok(Self::Unknown),
            other => Err(other),
        }
    }
}

/// `QuerySnapshotLease` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotLeaseStatus {
    /// Lease being reported on.
    pub snapshot_lease_id: u64,
    /// Current state.
    pub state: SnapshotLeaseState,
    /// Opaque VSS snapshot identifier (empty if
    /// [`SnapshotLeaseState::Unknown`]).
    pub snapshot_id: Vec<u8>,
    /// Creation time, Unix milliseconds.
    pub created_at_unix_ms: i64,
    /// Expiry time, Unix milliseconds.
    pub expires_at_unix_ms: i64,
}

impl SnapshotLeaseStatus {
    /// Encode this status.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.snapshot_lease_id);
        out.push(self.state.encode());
        write_bytes_u32_prefixed(&mut out, &self.snapshot_id);
        write_i64_le(&mut out, self.created_at_unix_ms);
        write_i64_le(&mut out, self.expires_at_unix_ms);
        out
    }

    /// Decode this status.
    ///
    /// # Errors
    /// See [`SnapshotProtocolError`].
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self, SnapshotProtocolError> {
        let snapshot_lease_id = reader.read_u64_le()?;
        let state_byte = reader.read_u8()?;
        let state = SnapshotLeaseState::decode(state_byte).map_err(|byte| {
            SnapshotProtocolError::UnknownDiscriminant {
                field: "state",
                value: u64::from(byte),
            }
        })?;
        let snapshot_id = reader.read_bytes_u32_prefixed("snapshot_id", MAX_IDENTIFIER_BYTES)?;
        let created_at_unix_ms = reader.read_i64_le()?;
        let expires_at_unix_ms = reader.read_i64_le()?;
        Ok(Self {
            snapshot_lease_id,
            state,
            snapshot_id,
            created_at_unix_ms,
            expires_at_unix_ms,
        })
    }
}

/// Stable error codes for a [`super::SnapshotManagerResponse::Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum SnapshotManagerErrorCode {
    /// VSS snapshot creation failed.
    SnapshotCreateFailed = 0,
    /// The requested volume could not be validated.
    VolumeValidationFailed = 1,
    /// The caller's identity/authorization failed validation.
    Unauthorized = 2,
    /// The named lease is not known to the Broker.
    LeaseNotFound = 3,
    /// The named lease has already expired or been released.
    LeaseNotActive = 4,
    /// The approved reader process failed identity verification.
    ReaderIdentityRejected = 5,
    /// Copy-on-write storage pressure prevents further retention.
    SnapshotStorageExhausted = 6,
    /// An internal Broker error not covered by another code.
    InternalError = 7,
}

impl SnapshotManagerErrorCode {
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
            0 => Ok(Self::SnapshotCreateFailed),
            1 => Ok(Self::VolumeValidationFailed),
            2 => Ok(Self::Unauthorized),
            3 => Ok(Self::LeaseNotFound),
            4 => Ok(Self::LeaseNotActive),
            5 => Ok(Self::ReaderIdentityRejected),
            6 => Ok(Self::SnapshotStorageExhausted),
            7 => Ok(Self::InternalError),
            other => Err(other),
        }
    }
}
