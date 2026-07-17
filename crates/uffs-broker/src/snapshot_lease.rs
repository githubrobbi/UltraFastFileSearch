// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Snapshot lease lifecycle: the Broker's in-memory VSS-lease bookkeeping,
//! decoupled from the real Win32 VSS calls behind the [`VssProvider`]
//! trait.
//!
//! Deliberately cross-platform, unlike the rest of this crate (`broker`
//! and everything under it are `#[cfg(windows)]`): the implementation
//! plan (`uffs-ingest-implementation-plan.md` §4.2) calls for the
//! lease-lifecycle state machine (create/renew/release/expire/reconcile)
//! to be unit-tested against a fake `VssProvider` on every host, so a
//! logic bug here doesn't need a Windows box to catch. Only the real
//! Win32 VSS backend (`broker/snapshot_manager/vss.rs`), the named-pipe
//! wiring (`broker/snapshot_manager/pipe.rs`), and startup reconciliation
//! (`broker/snapshot_manager/reconcile.rs`) are `#[cfg(windows)]`.
//!
//! Lease state lives entirely in memory — there is no durable lease
//! table surviving a Broker restart (matching the same
//! "restart-from-zero" philosophy `uffs-content::run` uses). That's why
//! [`SnapshotLeaseManager::reconcile_at_startup`] can be so blunt: a
//! freshly started manager holds no lease for anything, so *every*
//! shadow copy the real VSS backend still finds at startup is, by
//! definition, orphaned from a previous run and gets deleted.

// This module's only production consumer is the Windows-only
// `broker::snapshot_manager` subsystem (the real `WindowsVssProvider` +
// pipe wiring) — on a non-Windows compilation nothing outside `tests`
// below ever constructs a `SnapshotLeaseManager`, which is expected and
// correct, not a bug to fix. See the module docs for why this crate
// makes an exception to compile this logic on every platform at all.
#![cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "only the Windows-only broker::snapshot_manager subsystem constructs \
                  a SnapshotLeaseManager outside of this module's own tests"
    )
)]

use core::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::sync::Mutex;

use uffs_broker_protocol::snapshot_manager::{SnapshotLeaseState, VolumeIdentity};

/// The result of successfully creating a VSS snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SnapshotHandle {
    /// Opaque VSS snapshot identifier.
    pub(crate) snapshot_id: Vec<u8>,
    /// Device path the snapshot is reachable at (e.g.
    /// `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`).
    pub(crate) device_identity: String,
}

/// Errors from the underlying VSS backend (real or fake).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum VssError {
    /// The requested volume could not be validated.
    #[error("volume validation failed: {0}")]
    InvalidVolume(String),
    /// Snapshot creation failed.
    #[error("snapshot creation failed: {message}")]
    CreateFailed {
        /// The underlying `HRESULT`, when the failure came from a real
        /// VSS call and one is available — lets callers (the Snapshot
        /// Manager's wire layer) distinguish specific, permanent
        /// failure reasons (e.g. `VSS_E_VOLUME_NOT_SUPPORTED` for
        /// removable media) from this message's free text.
        hresult: Option<i32>,
        /// Diagnostic message.
        message: String,
    },
    /// Snapshot deletion failed.
    #[error("snapshot deletion failed: {0}")]
    DeleteFailed(String),
}

/// A real or fake VSS snapshot creation/deletion/enumeration backend.
///
/// The real Windows implementation
/// (`broker/snapshot_manager::vss::WindowsVssProvider`) wraps
/// `IVssBackupComponents`. Tests in this module use a fake implementation
/// so the lease-lifecycle logic below is exercised without ever calling
/// real VSS.
pub(crate) trait VssProvider: Send + Sync {
    /// Create a new point-in-time snapshot of `volume`.
    ///
    /// `requested_root` is the lossless UTF-16LE-encoded path the job
    /// wants to read under — most providers don't need it (a VSS
    /// snapshot covers the whole volume), but it's threaded through so a
    /// provider can validate the root actually resolves on `volume`.
    ///
    /// # Errors
    /// See [`VssError`].
    fn create_snapshot(
        &self,
        volume: &VolumeIdentity,
        requested_root: &[u8],
    ) -> Result<SnapshotHandle, VssError>;

    /// Delete a previously created snapshot.
    ///
    /// # Errors
    /// See [`VssError`].
    fn delete_snapshot(&self, snapshot_id: &[u8]) -> Result<(), VssError>;

    /// List every UFFS-owned snapshot the VSS backend currently knows
    /// about, regardless of whether this process instance created it.
    ///
    /// Used only by [`SnapshotLeaseManager::reconcile_at_startup`]. Must
    /// **not** include snapshots created by other software (System
    /// Restore, third-party backup tools, etc.) — the real
    /// implementation is responsible for that filtering (e.g. via a
    /// persisted UFFS-owned backup-components document), not the caller.
    ///
    /// # Errors
    /// See [`VssError`].
    fn list_existing_snapshots(&self) -> Result<Vec<Vec<u8>>, VssError>;
}

/// Errors from a [`SnapshotLeaseManager`] operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum LeaseError {
    /// The named lease is not known to the Broker.
    #[error("lease not found")]
    NotFound,
    /// The named lease has already expired or been released.
    #[error("lease is not active")]
    NotActive,
    /// The underlying VSS backend failed.
    #[error(transparent)]
    Vss(#[from] VssError),
}

/// The result of successfully creating a lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CreatedLease {
    /// Lease identifier the Coordinator uses in all subsequent calls.
    pub(crate) lease_id: u64,
    /// Opaque VSS snapshot identifier.
    pub(crate) snapshot_id: Vec<u8>,
    /// Device path the snapshot is reachable at.
    pub(crate) device_identity: String,
    /// Snapshot creation time, Unix milliseconds.
    pub(crate) created_at_unix_ms: i64,
    /// Initial lease expiry, Unix milliseconds.
    pub(crate) expires_at_unix_ms: i64,
}

/// The result of a successful [`SnapshotLeaseManager::query_lease`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeaseStatus {
    /// Current lease state.
    pub(crate) state: SnapshotLeaseState,
    /// Opaque VSS snapshot identifier.
    pub(crate) snapshot_id: Vec<u8>,
    /// Creation time, Unix milliseconds.
    pub(crate) created_at_unix_ms: i64,
    /// Expiry time, Unix milliseconds.
    pub(crate) expires_at_unix_ms: i64,
}

/// Why a lease reached a terminal state — distinct from
/// [`SnapshotLeaseState::Active`] so [`SnapshotLeaseManager::query_lease`]
/// can report *why* a lease is no longer active, matching the wire
/// protocol's `Expired`/`Released` distinction (a timeout is not the same
/// outcome as an explicit release, even though both mean the underlying
/// snapshot is gone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordState {
    /// Snapshot is retained; the lease has not reached its expiry.
    Active,
    /// The lease's expiry passed before it was renewed or released; the
    /// snapshot has been auto-deleted.
    Expired,
    /// [`SnapshotLeaseManager::release_lease`] was called explicitly.
    Released,
}

impl RecordState {
    /// Map to the wire [`SnapshotLeaseState`] (a 1:1 correspondence for
    /// every state a live record can be in — `Unknown` only applies when
    /// there's no record at all, which [`RecordState`] can't represent).
    const fn to_wire(self) -> SnapshotLeaseState {
        match self {
            Self::Active => SnapshotLeaseState::Active,
            Self::Expired => SnapshotLeaseState::Expired,
            Self::Released => SnapshotLeaseState::Released,
        }
    }
}

/// One tracked lease.
struct LeaseRecord {
    /// Opaque VSS snapshot identifier.
    snapshot_id: Vec<u8>,
    /// Device path the snapshot is reachable at.
    device_identity: String,
    /// Snapshot creation time, Unix milliseconds.
    created_at_unix_ms: i64,
    /// Current expiry, Unix milliseconds (meaningless once `state` is no
    /// longer `Active`, but kept for `query_lease`'s reporting).
    expires_at_unix_ms: i64,
    /// Current lifecycle state.
    state: RecordState,
}

/// In-memory registry of active VSS snapshot leases, backed by a
/// swappable [`VssProvider`].
///
/// Every public method takes `now_unix_ms` explicitly rather than reading
/// the wall clock internally, so the lease-lifecycle tests below are
/// fully deterministic — no sleeping, no flaky timing.
pub(crate) struct SnapshotLeaseManager<P> {
    /// The VSS backend (real or fake) this manager drives.
    provider: P,
    /// Monotonic lease-ID counter; starts at 1 (`0` is never issued).
    next_lease_id: AtomicU64,
    /// All tracked leases, keyed by `lease_id`.
    leases: Mutex<HashMap<u64, LeaseRecord>>,
}

impl<P: VssProvider> SnapshotLeaseManager<P> {
    /// Create a new, empty lease manager over `provider`.
    pub(crate) fn new(provider: P) -> Self {
        Self {
            provider,
            next_lease_id: AtomicU64::new(1),
            leases: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new snapshot and lease it for up to `maximum_lifetime_secs`.
    ///
    /// # Errors
    /// Propagates [`VssError`] from the underlying `create_snapshot` call.
    pub(crate) fn create_lease(
        &self,
        volume: &VolumeIdentity,
        requested_root: &[u8],
        maximum_lifetime_secs: u64,
        now_unix_ms: i64,
    ) -> Result<CreatedLease, LeaseError> {
        self.sweep_expired(now_unix_ms);

        let handle = self.provider.create_snapshot(volume, requested_root)?;
        let lease_id = self.next_lease_id.fetch_add(1, Ordering::Relaxed);
        let expires_at_unix_ms =
            now_unix_ms.saturating_add(secs_to_ms_saturating(maximum_lifetime_secs));

        let record = LeaseRecord {
            snapshot_id: handle.snapshot_id.clone(),
            device_identity: handle.device_identity.clone(),
            created_at_unix_ms: now_unix_ms,
            expires_at_unix_ms,
            state: RecordState::Active,
        };
        self.lock_leases().insert(lease_id, record);

        Ok(CreatedLease {
            lease_id,
            snapshot_id: handle.snapshot_id,
            device_identity: handle.device_identity,
            created_at_unix_ms: now_unix_ms,
            expires_at_unix_ms,
        })
    }

    /// Renew an active lease to a new absolute expiry.
    ///
    /// # Errors
    /// [`LeaseError::NotFound`] if `lease_id` is unknown;
    /// [`LeaseError::NotActive`] if it has already expired or been
    /// released.
    pub(crate) fn renew_lease(
        &self,
        lease_id: u64,
        requested_expiry_unix_ms: i64,
        now_unix_ms: i64,
    ) -> Result<i64, LeaseError> {
        self.sweep_expired(now_unix_ms);
        let mut leases = self.lock_leases();
        let record = leases.get_mut(&lease_id).ok_or(LeaseError::NotFound)?;
        if record.state != RecordState::Active {
            return Err(LeaseError::NotActive);
        }
        record.expires_at_unix_ms = requested_expiry_unix_ms;
        drop(leases);
        Ok(requested_expiry_unix_ms)
    }

    /// Release a lease, deleting its snapshot if it hasn't already been
    /// torn down. Releasing an already-terminal (expired or
    /// already-released) lease is a no-op success, not an error — only
    /// an entirely unknown `lease_id` is an error.
    ///
    /// # Errors
    /// [`LeaseError::NotFound`] if `lease_id` is unknown; propagates
    /// [`VssError`] from `delete_snapshot` if the lease was active.
    pub(crate) fn release_lease(&self, lease_id: u64) -> Result<(), LeaseError> {
        let mut leases = self.lock_leases();
        let record = leases.get_mut(&lease_id).ok_or(LeaseError::NotFound)?;
        if record.state != RecordState::Active {
            return Ok(());
        }
        self.provider.delete_snapshot(&record.snapshot_id)?;
        record.state = RecordState::Released;
        drop(leases);
        Ok(())
    }

    /// Report a lease's current state, or `None` if the Broker has no
    /// record of it (the wire protocol's `Unknown` state).
    pub(crate) fn query_lease(&self, lease_id: u64, now_unix_ms: i64) -> Option<LeaseStatus> {
        self.sweep_expired(now_unix_ms);
        let leases = self.lock_leases();
        let record = leases.get(&lease_id)?;
        let status = LeaseStatus {
            state: record.state.to_wire(),
            snapshot_id: record.snapshot_id.clone(),
            created_at_unix_ms: record.created_at_unix_ms,
            expires_at_unix_ms: record.expires_at_unix_ms,
        };
        drop(leases);
        Some(status)
    }

    /// The device identity a lease's snapshot is reachable at, if the
    /// lease is currently active. Used by `DuplicateSnapshotHandle`
    /// handling to know which device to open before duplicating a handle
    /// to the Reader.
    pub(crate) fn device_identity_if_active(
        &self,
        lease_id: u64,
        now_unix_ms: i64,
    ) -> Option<String> {
        self.sweep_expired(now_unix_ms);
        let leases = self.lock_leases();
        let record = leases.get(&lease_id)?;
        let identity =
            (record.state == RecordState::Active).then(|| record.device_identity.clone());
        drop(leases);
        identity
    }

    /// Auto-release every lease whose expiry has passed and that is
    /// still `Active` — deleting its snapshot and transitioning it to
    /// `Expired`. Called at the start of every other method (so the
    /// lifecycle tests below don't need a background thread), and also
    /// callable directly by a periodic background sweep in the real
    /// Windows serving loop, so an idle manager doesn't leak shadow-copy
    /// storage indefinitely between requests.
    #[expect(
        clippy::iter_over_hash_type,
        reason = "order doesn't matter: every Active-and-past-expiry record \
                  is swept regardless of visitation order, and the map is \
                  small (bounded by concurrently open jobs)"
    )]
    pub(crate) fn sweep_expired(&self, now_unix_ms: i64) {
        let mut leases = self.lock_leases();
        for record in leases.values_mut() {
            if record.state == RecordState::Active && now_unix_ms >= record.expires_at_unix_ms {
                // Best-effort: a delete failure here shouldn't wedge the
                // sweep or crash the Broker. The next `reconcile_at_startup`
                // (or a later successful delete attempt, if this method
                // instead retried failures) would catch a truly stuck
                // snapshot; for v1 this matches the addendum's "monitor,
                // don't guarantee" framing for background cleanup.
                let _ignored = self.provider.delete_snapshot(&record.snapshot_id);
                record.state = RecordState::Expired;
            }
        }
    }

    /// Delete every snapshot the VSS backend reports as existing.
    ///
    /// Safe to call unconditionally at Broker startup, before any lease
    /// is created this run: since lease state is purely in-memory (see
    /// the module docs), a freshly constructed manager holds no lease
    /// for anything the backend might still be retaining from a previous
    /// (crashed or otherwise uncleanly stopped) run — so every entry
    /// [`VssProvider::list_existing_snapshots`] reports is, by
    /// definition, orphaned.
    ///
    /// Returns the number of snapshots successfully deleted (best-effort:
    /// a single failed deletion doesn't stop the rest).
    ///
    /// # Errors
    /// Propagates [`VssError`] only if *listing* existing snapshots
    /// itself fails; individual deletion failures are counted, not
    /// returned as an error.
    pub(crate) fn reconcile_at_startup(&self) -> Result<usize, VssError> {
        let existing = self.provider.list_existing_snapshots()?;
        let deleted = existing
            .iter()
            .filter(|snapshot_id| self.provider.delete_snapshot(snapshot_id).is_ok())
            .count();
        Ok(deleted)
    }

    /// Lock the lease map, recovering from a poisoned mutex (a panic in
    /// one connection-handler thread must not wedge every other lease
    /// operation).
    fn lock_leases(&self) -> std::sync::MutexGuard<'_, HashMap<u64, LeaseRecord>> {
        self.leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Converts seconds to milliseconds, saturating rather than overflowing
/// for an implausibly large `maximum_lifetime_secs`.
fn secs_to_ms_saturating(secs: u64) -> i64 {
    i64::try_from(secs.saturating_mul(1000)).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests;
