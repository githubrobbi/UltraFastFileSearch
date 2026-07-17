// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit tests for [`super`] (`snapshot_manager`).

use super::{
    CreateSnapshotLease, CreateSnapshotLeaseResult, DuplicateSnapshotHandle, QuerySnapshotLease,
    ReleaseSnapshotLease, RenewSnapshotLease, SnapshotLeaseState, SnapshotLeaseStatus,
    SnapshotManagerErrorCode, SnapshotManagerRequest, SnapshotManagerResponse,
    SnapshotProtocolError, VolumeIdentity,
};

fn sample_create_request() -> CreateSnapshotLease {
    CreateSnapshotLease {
        authenticated_job_id: [1_u8; 16],
        source_volume_identity: VolumeIdentity {
            volume_serial: 0x0102_0304_0506_0708,
            volume_guid: b"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}".to_vec(),
        },
        requested_root: b"C\0:\0\\\0d\0a\0t\0a\0".to_vec(), // toy UTF-16LE-ish bytes
        maximum_lifetime_secs: 3600,
        policy_id: 1,
    }
}

fn sample_create_result() -> CreateSnapshotLeaseResult {
    CreateSnapshotLeaseResult {
        snapshot_lease_id: 42,
        snapshot_id: b"vss-snap-0001".to_vec(),
        snapshot_device_identity: r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1".to_owned(),
        snapshot_created_at_unix_ms: 1_752_000_000_000,
        expires_at_unix_ms: 1_752_003_600_000,
    }
}

#[test]
fn create_snapshot_lease_round_trips() {
    let request = sample_create_request();
    let wrapped = SnapshotManagerRequest::Create(request.clone());
    let bytes = wrapped.encode();
    let decoded = SnapshotManagerRequest::decode(&bytes).unwrap();
    assert_eq!(decoded, SnapshotManagerRequest::Create(request));
}

#[test]
fn create_snapshot_lease_result_round_trips() {
    let result = sample_create_result();
    let wrapped = SnapshotManagerResponse::Created(result.clone());
    let bytes = wrapped.encode();
    let decoded = SnapshotManagerResponse::decode(&bytes).unwrap();
    assert_eq!(decoded, SnapshotManagerResponse::Created(result));
}

#[test]
fn duplicate_snapshot_handle_round_trips() {
    let request = DuplicateSnapshotHandle {
        snapshot_lease_id: 42,
        approved_reader_process_id: 4321,
    };
    let wrapped = SnapshotManagerRequest::Duplicate(request);
    let bytes = wrapped.encode();
    let decoded = SnapshotManagerRequest::decode(&bytes).unwrap();
    assert_eq!(decoded, SnapshotManagerRequest::Duplicate(request));
}

#[test]
fn duplicated_response_round_trips() {
    let wrapped = SnapshotManagerResponse::Duplicated;
    let bytes = wrapped.encode();
    let decoded = SnapshotManagerResponse::decode(&bytes).unwrap();
    assert_eq!(decoded, SnapshotManagerResponse::Duplicated);
}

#[test]
fn renew_snapshot_lease_round_trips() {
    let request = RenewSnapshotLease {
        snapshot_lease_id: 42,
        requested_expiry_unix_ms: 1_752_010_000_000,
    };
    let wrapped = SnapshotManagerRequest::Renew(request);
    let bytes = wrapped.encode();
    let decoded = SnapshotManagerRequest::decode(&bytes).unwrap();
    assert_eq!(decoded, SnapshotManagerRequest::Renew(request));
}

#[test]
fn renewed_response_round_trips() {
    let wrapped = SnapshotManagerResponse::Renewed {
        new_expires_at_unix_ms: 1_752_010_000_000,
    };
    let bytes = wrapped.encode();
    let decoded = SnapshotManagerResponse::decode(&bytes).unwrap();
    assert_eq!(decoded, wrapped);
}

#[test]
fn release_snapshot_lease_round_trips() {
    let request = ReleaseSnapshotLease {
        snapshot_lease_id: 42,
    };
    let wrapped = SnapshotManagerRequest::Release(request);
    let bytes = wrapped.encode();
    let decoded = SnapshotManagerRequest::decode(&bytes).unwrap();
    assert_eq!(decoded, SnapshotManagerRequest::Release(request));
}

#[test]
fn released_response_round_trips() {
    let wrapped = SnapshotManagerResponse::Released;
    let bytes = wrapped.encode();
    let decoded = SnapshotManagerResponse::decode(&bytes).unwrap();
    assert_eq!(decoded, SnapshotManagerResponse::Released);
}

#[test]
fn query_snapshot_lease_round_trips() {
    let request = QuerySnapshotLease {
        snapshot_lease_id: 42,
    };
    let wrapped = SnapshotManagerRequest::Query(request);
    let bytes = wrapped.encode();
    let decoded = SnapshotManagerRequest::decode(&bytes).unwrap();
    assert_eq!(decoded, SnapshotManagerRequest::Query(request));
}

#[test]
fn status_response_round_trips_for_every_state() {
    for state in [
        SnapshotLeaseState::Active,
        SnapshotLeaseState::Expired,
        SnapshotLeaseState::Released,
        SnapshotLeaseState::Unknown,
    ] {
        let status = SnapshotLeaseStatus {
            snapshot_lease_id: 42,
            state,
            snapshot_id: b"vss-snap-0001".to_vec(),
            created_at_unix_ms: 1_752_000_000_000,
            expires_at_unix_ms: 1_752_003_600_000,
        };
        let wrapped = SnapshotManagerResponse::Status(status.clone());
        let bytes = wrapped.encode();
        let decoded = SnapshotManagerResponse::decode(&bytes).unwrap();
        assert_eq!(
            decoded,
            SnapshotManagerResponse::Status(status),
            "failed for {state:?}"
        );
    }
}

#[test]
fn error_response_round_trips() {
    let wrapped = SnapshotManagerResponse::Error {
        code: SnapshotManagerErrorCode::LeaseNotFound,
        hresult: None,
        message: "no such lease".to_owned(),
    };
    let bytes = wrapped.encode();
    let decoded = SnapshotManagerResponse::decode(&bytes).unwrap();
    assert_eq!(decoded, wrapped);
}

#[test]
fn error_response_with_hresult_round_trips() {
    let wrapped = SnapshotManagerResponse::Error {
        code: SnapshotManagerErrorCode::SnapshotCreateFailed,
        hresult: Some(0x8004_230C_u32.cast_signed()),
        message: "stage=6 hresult=0x8004230c: AddToSnapshotSet failed".to_owned(),
    };
    let bytes = wrapped.encode();
    let decoded = SnapshotManagerResponse::decode(&bytes).unwrap();
    assert_eq!(decoded, wrapped);
}

#[test]
fn request_decode_rejects_unknown_tag() {
    let bytes = vec![0xFF];
    let err = SnapshotManagerRequest::decode(&bytes).unwrap_err();
    assert!(matches!(err, SnapshotProtocolError::UnknownDiscriminant {
        field: "request_tag",
        ..
    }));
}

#[test]
fn response_decode_rejects_unknown_tag() {
    let bytes = vec![0xFF];
    let err = SnapshotManagerResponse::decode(&bytes).unwrap_err();
    assert!(matches!(err, SnapshotProtocolError::UnknownDiscriminant {
        field: "response_tag",
        ..
    }));
}

#[test]
fn request_decode_rejects_truncated_input() {
    let bytes = vec![0_u8]; // CREATE tag, but no body
    let err = SnapshotManagerRequest::decode(&bytes).unwrap_err();
    assert!(matches!(err, SnapshotProtocolError::Truncated { .. }));
}

#[test]
fn snapshot_lease_state_round_trips_all_variants() {
    for value in 0_u8..=3 {
        let state = SnapshotLeaseState::decode(value).unwrap();
        assert_eq!(state.encode(), value);
    }
    assert_eq!(SnapshotLeaseState::decode(4), Err(4));
}

#[test]
fn snapshot_manager_error_code_round_trips_all_variants() {
    for value in 0_u8..=7 {
        let code = SnapshotManagerErrorCode::decode(value).unwrap();
        assert_eq!(code.encode(), value);
    }
    assert_eq!(SnapshotManagerErrorCode::decode(8), Err(8));
}

#[test]
fn create_snapshot_lease_rejects_oversized_requested_root() {
    let mut request = sample_create_request();
    request.requested_root = vec![0_u8; (super::MAX_PATH_BYTES + 2) as usize];
    let wrapped = SnapshotManagerRequest::Create(request);
    let bytes = wrapped.encode();
    let err = SnapshotManagerRequest::decode(&bytes).unwrap_err();
    assert!(matches!(
        err,
        SnapshotProtocolError::LengthOutOfBounds { .. }
    ));
}
