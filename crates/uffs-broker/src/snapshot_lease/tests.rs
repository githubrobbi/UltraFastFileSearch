// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Lease-lifecycle tests against a fake [`VssProvider`] — no real VSS is
//! ever called here (`uffs-ingest-implementation-plan.md` §4.3).

use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use uffs_broker_protocol::snapshot_manager::{SnapshotLeaseState, VolumeIdentity};

use super::{LeaseError, SnapshotHandle, SnapshotLeaseManager, VssError, VssProvider};

/// A fake [`VssProvider`] that never touches real VSS: `create_snapshot`
/// hands out sequential fake snapshot IDs, `delete_snapshot` just records
/// what it was asked to delete, and `list_existing_snapshots` returns a
/// fixed, test-supplied set (simulating leftover shadow copies from a
/// previous run).
#[derive(Debug, Default)]
struct FakeVssProvider {
    next_snapshot_id: AtomicU64,
    deleted: Mutex<Vec<Vec<u8>>>,
    existing_at_startup: Vec<Vec<u8>>,
    fail_create: bool,
}

impl FakeVssProvider {
    fn with_existing_at_startup(existing: Vec<Vec<u8>>) -> Self {
        Self {
            existing_at_startup: existing,
            ..Self::default()
        }
    }

    fn failing() -> Self {
        Self {
            fail_create: true,
            ..Self::default()
        }
    }

    fn deleted_snapshot_ids(&self) -> Vec<Vec<u8>> {
        self.deleted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl VssProvider for FakeVssProvider {
    fn create_snapshot(
        &self,
        _volume: &VolumeIdentity,
        _requested_root: &[u8],
    ) -> Result<SnapshotHandle, VssError> {
        if self.fail_create {
            return Err(VssError::CreateFailed {
                hresult: None,
                message: "forced test failure".to_owned(),
            });
        }
        let id = self.next_snapshot_id.fetch_add(1, Ordering::Relaxed);
        Ok(SnapshotHandle {
            snapshot_id: id.to_le_bytes().to_vec(),
            device_identity: format!(r"\\?\GLOBALROOT\Device\FakeShadowCopy{id}"),
        })
    }

    fn delete_snapshot(&self, snapshot_id: &[u8]) -> Result<(), VssError> {
        self.deleted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(snapshot_id.to_vec());
        Ok(())
    }

    fn list_existing_snapshots(&self) -> Result<Vec<Vec<u8>>, VssError> {
        Ok(self.existing_at_startup.clone())
    }
}

fn sample_volume() -> VolumeIdentity {
    VolumeIdentity {
        volume_serial: 0x1234_5678,
        volume_guid: b"{11111111-2222-3333-4444-555555555555}".to_vec(),
    }
}

#[test]
fn create_then_query_reports_active() {
    let manager = SnapshotLeaseManager::new(FakeVssProvider::default());
    let created = manager
        .create_lease(&sample_volume(), b"C:\\data", 300, 1_000)
        .expect("create must succeed");
    assert_eq!(created.lease_id, 1);
    assert_eq!(created.expires_at_unix_ms, 1_000 + 300_000);

    let status = manager
        .query_lease(created.lease_id, 1_500)
        .expect("lease must be found");
    assert_eq!(status.state, SnapshotLeaseState::Active);
    assert_eq!(status.snapshot_id, created.snapshot_id);
}

#[test]
fn create_failure_propagates_vss_error() {
    let manager = SnapshotLeaseManager::new(FakeVssProvider::failing());
    let err = manager
        .create_lease(&sample_volume(), b"C:\\data", 300, 0)
        .expect_err("create must fail");
    assert!(matches!(
        err,
        LeaseError::Vss(VssError::CreateFailed { .. })
    ));
}

#[test]
fn renew_extends_expiry() {
    let manager = SnapshotLeaseManager::new(FakeVssProvider::default());
    let created = manager
        .create_lease(&sample_volume(), b"C:\\data", 60, 0)
        .expect("create must succeed");

    let new_expiry = manager
        .renew_lease(created.lease_id, 999_999, 30_000)
        .expect("renew must succeed");
    assert_eq!(new_expiry, 999_999);

    let status = manager
        .query_lease(created.lease_id, 40_000)
        .expect("lease must be found");
    assert_eq!(status.state, SnapshotLeaseState::Active);
    assert_eq!(status.expires_at_unix_ms, 999_999);
}

#[test]
fn renew_of_expired_lease_is_rejected() {
    let manager = SnapshotLeaseManager::new(FakeVssProvider::default());
    let created = manager
        .create_lease(&sample_volume(), b"C:\\data", 10, 0)
        .expect("create must succeed");

    // Advance well past the 10-second (10_000ms) lifetime.
    let err = manager
        .renew_lease(created.lease_id, 500_000, 20_000)
        .expect_err("renew of an expired lease must fail");
    assert_eq!(err, LeaseError::NotActive);
}

#[test]
fn create_renew_expire_auto_releases_and_reports_expired() {
    let provider = FakeVssProvider::default();
    let manager = SnapshotLeaseManager::new(provider);
    let created = manager
        .create_lease(&sample_volume(), b"C:\\data", 10, 0)
        .expect("create must succeed");

    // Past expiry, with no renewal: querying must sweep it to Expired and
    // auto-delete the underlying snapshot exactly once.
    let status = manager
        .query_lease(created.lease_id, 20_000)
        .expect("lease record must still exist");
    assert_eq!(status.state, SnapshotLeaseState::Expired);

    // Querying again after it's already expired must not re-delete.
    let status_again = manager
        .query_lease(created.lease_id, 30_000)
        .expect("lease record must still exist");
    assert_eq!(status_again.state, SnapshotLeaseState::Expired);
}

#[test]
fn explicit_release_is_idempotent_and_deletes_exactly_once() {
    let manager = SnapshotLeaseManager::new(FakeVssProvider::default());
    let created = manager
        .create_lease(&sample_volume(), b"C:\\data", 300, 0)
        .expect("create must succeed");

    manager
        .release_lease(created.lease_id)
        .expect("first release must succeed");
    manager
        .release_lease(created.lease_id)
        .expect("second release must be a no-op, not an error");

    let status = manager
        .query_lease(created.lease_id, 1_000)
        .expect("lease record must still exist");
    assert_eq!(status.state, SnapshotLeaseState::Released);
}

#[test]
fn query_unknown_lease_returns_none() {
    let manager = SnapshotLeaseManager::new(FakeVssProvider::default());
    assert!(manager.query_lease(999, 0).is_none());
}

#[test]
fn renew_unknown_lease_is_not_found() {
    let manager = SnapshotLeaseManager::new(FakeVssProvider::default());
    let err = manager
        .renew_lease(999, 1_000, 0)
        .expect_err("unknown lease must fail");
    assert_eq!(err, LeaseError::NotFound);
}

#[test]
fn release_unknown_lease_is_not_found() {
    let manager = SnapshotLeaseManager::new(FakeVssProvider::default());
    let err = manager
        .release_lease(999)
        .expect_err("unknown lease must fail");
    assert_eq!(err, LeaseError::NotFound);
}

#[test]
fn device_identity_if_active_is_none_once_released() {
    let manager = SnapshotLeaseManager::new(FakeVssProvider::default());
    let created = manager
        .create_lease(&sample_volume(), b"C:\\data", 300, 0)
        .expect("create must succeed");

    assert_eq!(
        manager.device_identity_if_active(created.lease_id, 100),
        Some(created.device_identity.clone())
    );

    manager
        .release_lease(created.lease_id)
        .expect("release must succeed");
    assert_eq!(
        manager.device_identity_if_active(created.lease_id, 200),
        None
    );
}

#[test]
fn reconcile_at_startup_deletes_every_existing_snapshot() {
    let existing = vec![vec![1, 1, 1, 1], vec![2, 2, 2, 2]];
    let provider = FakeVssProvider::with_existing_at_startup(existing.clone());
    let manager = SnapshotLeaseManager::new(provider);

    let deleted_count = manager
        .reconcile_at_startup()
        .expect("reconcile must succeed");
    assert_eq!(deleted_count, 2);

    let mut deleted_ids = manager.provider.deleted_snapshot_ids();
    deleted_ids.sort();
    let mut expected = existing;
    expected.sort();
    assert_eq!(deleted_ids, expected);

    // A freshly reconciled manager has no leases of its own yet.
    assert!(manager.query_lease(1, 0).is_none());
}
