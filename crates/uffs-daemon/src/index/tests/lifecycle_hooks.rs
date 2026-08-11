// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Phase 5 lifecycle-hook injection tests + `drives` RPC tier-marker
//! contract.
//!
//! Covers:
//!
//! * Plan task 5.11 — `IndexManager::drives()` enumerates Warm / Parked / Cold
//!   shards with tier markers (the 2026-04-28 dogfood regression).
//! * Plan task 5.8 — `WorkingSetTrim::trim()` invocation contract (once per
//!   batch in `demote_idle_shards`).
//! * Plan task 5.9 — `Prefetch::hint()` invocation with the freshly-loaded
//!   body's records + names regions.
//! * Plan task 5.10 — `cascade_demote_one_step` picks the LRU Warm shard,
//!   drains in order, calls `WorkingSetTrim::trim()` exactly once per cascade
//!   step.

#![expect(
    clippy::indexing_slicing,
    clippy::min_ident_chars,
    clippy::std_instead_of_alloc,
    reason = "test code — assertions index into known-shape vectors, use short \
              drive-letter idents, and pull `Arc` from `std` to match the rest \
              of the daemon's test fixtures"
)]

use std::sync::Arc;

use super::{
    FixedBodyLoader, IndexManager, build_test_drive, build_test_drive_d, build_test_drive_e,
};

/// Plan task **5.11**: `IndexManager::drives()` must enumerate every
/// shard in the registry — Warm, Parked, *and* Cold — tagged with its
/// `ShardTier` so the CLI status formatter can render the tier marker
/// instead of printing `Drives: (none loaded)` when the registry holds
/// only demoted shards.
///
/// Surfaced by the 2026-04-28 dogfood: at t=44m the daemon correctly
/// had all 7 drives Parked (their bloom + path-trie still resident,
/// ready for re-promote on bloom hit), but `daemon status` rendered
/// the empty-registry path because the old `drives()` filtered
/// through `active_index()` (Warm/Hot only).  The fix walks the
/// registry directly; this test pins the contract.
///
/// Topology: 3 drives.  C stays Warm.  D demotes to Parked.  E
/// demotes to Cold.  Assertions cover:
/// * every shard is in the response (no filtering),
/// * tiers map 1:1 from `ShardState` → `ShardTier`,
/// * Warm shards carry the body's `records.len()`,
/// * Parked / Cold shards report `records: 0` and a synthetic `source` label,
/// * load-order is preserved (C, D, E).
#[tokio::test]
async fn drives_rpc_enumerates_warm_parked_and_cold_shards_with_tier_markers() {
    use uffs_client::protocol::response::ShardTier;

    use crate::cache::ShardState;

    let (tx, _rx) = crate::events::event_channel();
    let mgr = IndexManager::new(None, tx, Arc::new(crate::config::Config::default()));
    mgr.add_drive(build_test_drive()).await;
    mgr.add_drive(build_test_drive_d()).await;
    mgr.add_drive(build_test_drive_e()).await;

    // Demote D → Parked (body released; bloom + trie resident).
    assert!(
        mgr.demote_letter_for_test(uffs_mft::platform::DriveLetter::D, ShardState::Parked)
            .await
    );
    // Demote E → Cold (no body, no filters).
    assert!(
        mgr.demote_letter_for_test(uffs_mft::platform::DriveLetter::E, ShardState::Cold)
            .await
    );

    let response = mgr.drives().await;
    assert_eq!(
        response.drives.len(),
        3,
        "every loaded shard must appear, including Parked and Cold"
    );

    // Load-order preserved (matches ShardRegistry::iter()).
    let letters: Vec<uffs_mft::platform::DriveLetter> =
        response.drives.iter().map(|dr| dr.letter).collect();
    assert_eq!(
        letters,
        vec![
            uffs_mft::platform::DriveLetter::C,
            uffs_mft::platform::DriveLetter::D,
            uffs_mft::platform::DriveLetter::E
        ],
        "load order preserved"
    );

    // C — Warm: body present, records nonzero, tier=Warm,
    // source from the body's IndexSource (live MFT path "C:").
    let c = &response.drives[0];
    assert_eq!(c.letter, uffs_mft::platform::DriveLetter::C);
    assert_eq!(c.tier, Some(ShardTier::Warm), "C remains Warm");
    assert!(c.records > 0, "Warm shard reports its body's records.len()");
    assert_eq!(c.source, "live", "Warm shard's body source flows through");

    // D — Parked: no body, records=0, tier=Parked,
    // source synthesized as "parked".
    let d = &response.drives[1];
    assert_eq!(d.letter, uffs_mft::platform::DriveLetter::D);
    assert_eq!(d.tier, Some(ShardTier::Parked), "D demoted to Parked");
    assert_eq!(d.records, 0, "Parked shard has no body in RAM");
    assert_eq!(
        d.source, "parked",
        "Parked shard surfaces a synthetic source label"
    );

    // E — Cold: no body, no filters, records=0, tier=Cold,
    // source synthesized as "cold".
    let e = &response.drives[2];
    assert_eq!(e.letter, uffs_mft::platform::DriveLetter::E);
    assert_eq!(e.tier, Some(ShardTier::Cold), "E demoted to Cold");
    assert_eq!(e.records, 0, "Cold shard has nothing in RAM");
    assert_eq!(
        e.source, "cold",
        "Cold shard surfaces a synthetic source label"
    );
}

/// Counter-test to the enumeration above: empty registry must still
/// render the legacy `(none loaded)` path so cold-boot detection in
/// external scripts (`scripts/windows/api-validation.rs`,
/// `cli-validation.rs`, `mcp-validation.rs`) continues to fire on a
/// truly empty daemon.  Pins that the formatter doesn't accidentally
/// emit a tier-marker line for a registry that holds zero shards.
#[tokio::test]
async fn drives_rpc_returns_empty_vec_when_registry_is_empty() {
    let (tx, _rx) = crate::events::event_channel();
    let mgr = IndexManager::new(None, tx, Arc::new(crate::config::Config::default()));

    let response = mgr.drives().await;
    assert!(
        response.drives.is_empty(),
        "no shards loaded → empty drives vec — CLI renders `(none loaded)`"
    );
}

/// Phase 5 task **5.8** — `demote_idle_shards` invokes the
/// `WorkingSetTrim::trim()` hook **exactly once** per applied
/// batch, not once per shard.  Pins the contract documented on
/// the trait: process-level call, coalesced across the batch
/// (Windows `EmptyWorkingSet` is process-wide so per-shard calls
/// would be wasted syscalls).
///
/// Topology: 3 drives all backdated past `WARM_TO_PARKED_IDLE_SECS`
/// so the controller demotes them in a single batch.  Inject a
/// `CountingWorkingSetTrim` fake; assert `calls() == 1` after the
/// tick.
#[tokio::test]
async fn demote_idle_shards_invokes_working_set_trim_once_per_batch() {
    use crate::cache::policy::WARM_TO_PARKED_IDLE_SECS;
    use crate::cache::working_set::tests::CountingWorkingSetTrim;

    let (tx, _rx) = crate::events::event_channel();
    let counting_trim = Arc::new(CountingWorkingSetTrim::new());
    let hooks = crate::index::constructors::LifecycleHooks {
        working_set_trim: Arc::clone(&counting_trim)
            as Arc<dyn crate::cache::working_set::WorkingSetTrim>,
        ..crate::index::constructors::LifecycleHooks::production()
    };
    let mgr = IndexManager::with_lifecycle_hooks_for_test(
        None,
        tx,
        hooks,
        Arc::new(crate::config::Config::default()),
    );
    mgr.add_drive(build_test_drive()).await;
    mgr.add_drive(build_test_drive_d()).await;
    mgr.add_drive(build_test_drive_e()).await;

    // Backdate every shard's last_query_at_ms past the Warm→Parked
    // threshold so the controller picks up all three in one batch.
    let last_query_ms = 1_000_000_000_u64;
    for letter in [
        uffs_mft::platform::DriveLetter::C,
        uffs_mft::platform::DriveLetter::D,
        uffs_mft::platform::DriveLetter::E,
    ] {
        assert!(
            mgr.backdate_last_query_at_ms_for_test(letter, last_query_ms)
                .await
        );
    }

    // Pre-batch: hook never fired.
    assert_eq!(counting_trim.calls(), 0, "no demote yet → no trim");

    let now_ms = last_query_ms + WARM_TO_PARKED_IDLE_SECS * 1000;
    mgr.demote_idle_shards(now_ms).await;

    // Post-batch: every shard demoted, hook fired exactly once.
    let states = mgr.shard_states_for_test().await;
    assert_eq!(states, vec![
        (
            uffs_mft::platform::DriveLetter::C,
            crate::cache::ShardState::Parked
        ),
        (
            uffs_mft::platform::DriveLetter::D,
            crate::cache::ShardState::Parked
        ),
        (
            uffs_mft::platform::DriveLetter::E,
            crate::cache::ShardState::Parked
        ),
    ]);
    assert_eq!(
        counting_trim.calls(),
        1,
        "WorkingSetTrim::trim() fires once per batch, not per shard"
    );

    // Idempotent on a second tick: nothing to demote → no trim.
    mgr.demote_idle_shards(now_ms).await;
    assert_eq!(
        counting_trim.calls(),
        1,
        "no-op tick must not re-trim — coalescing depends on `applied > 0`",
    );
}

/// Phase 5 task **5.9** — `ensure_warm_for_dispatch` invokes the
/// `Prefetch::hint()` hook with the freshly-loaded body's
/// records + names regions, in that order, before the registry
/// write-lock swap.  Pins the contract that the kernel-prefetch
/// runs while the orchestrator is still in the blocking task so
/// the syscall overlaps with the lock acquisition.
///
/// Topology: 1 drive (C), demoted to Parked.  Inject a
/// `FixedBodyLoader` so the body Arc handed to `Prefetch::hint`
/// is byte-identical to the one we constructed pre-test;
/// `RecordingPrefetch` captures every region as `(ptr-as-usize,
/// len)` so the assertion can match on the body's
/// `records.as_ptr()` and `names.as_ptr()` directly.
#[tokio::test]
async fn ensure_warm_for_dispatch_invokes_prefetch_with_records_and_names_regions() {
    use crate::cache::ShardState;
    use crate::cache::prefetch::tests::RecordingPrefetch;

    let (tx, _rx) = crate::events::event_channel();

    // Build the fixed body up front so we can compare regions
    // against it after promote.
    let body = Arc::new(build_test_drive());
    let recording_prefetch = Arc::new(RecordingPrefetch::new());
    let hooks = crate::index::constructors::LifecycleHooks {
        body_loader: Arc::new(FixedBodyLoader {
            body: Arc::clone(&body),
        }),
        prefetch: Arc::clone(&recording_prefetch) as Arc<dyn crate::cache::prefetch::Prefetch>,
        ..crate::index::constructors::LifecycleHooks::production()
    };
    let mgr = IndexManager::with_lifecycle_hooks_for_test(
        None,
        tx,
        hooks,
        Arc::new(crate::config::Config::default()),
    );
    mgr.add_drive(build_test_drive()).await;
    assert!(
        mgr.demote_letter_for_test(uffs_mft::platform::DriveLetter::C, ShardState::Parked)
            .await
    );

    // Pre-promote: no prefetch calls.
    assert_eq!(
        recording_prefetch.calls(),
        Vec::<Vec<(usize, usize)>>::new()
    );

    mgr.ensure_warm_for_dispatch(&[uffs_mft::platform::DriveLetter::C], &[])
        .await;

    // Shard promoted (the Phase-3 contract this test depends on).
    let states = mgr.shard_states_for_test().await;
    assert_eq!(states, vec![(
        uffs_mft::platform::DriveLetter::C,
        ShardState::Warm
    )]);

    // Prefetch invoked exactly once, with two regions in a fixed
    // order: records first (typed slice → byte length), names
    // second (raw `u8` slice → length is element count == bytes).
    let calls = recording_prefetch.calls();
    assert_eq!(
        calls.len(),
        1,
        "exactly one Prefetch::hint() call per promoted shard"
    );
    let regions = &calls[0];
    assert_eq!(
        regions.len(),
        2,
        "regions: [records, names] — fixed order, no extras"
    );

    let expected_records_ptr = body.records.as_slice().as_ptr() as usize;
    let expected_records_len = size_of_val(body.records.as_slice());
    let expected_names_ptr = body.names.as_slice().as_ptr() as usize;
    let expected_names_len = body.names.as_slice().len();

    assert_eq!(
        regions[0],
        (expected_records_ptr, expected_records_len),
        "records region matches the body's records.as_slice()",
    );
    assert_eq!(
        regions[1],
        (expected_names_ptr, expected_names_len),
        "names region matches the body's names.as_slice()",
    );
}

/// Phase 5 task **5.10** — `cascade_demote_one_step` picks the
/// **least-recently-queried** Warm shard, demotes one shard per
/// call (Warm → Parked), invokes [`WorkingSetTrim::trim`] exactly
/// once per cascade step (not coalesced into a batch like the
/// idle-demote controller), and returns `None` once no Warm shards
/// remain so the subscriber loop stops the cascade.
///
/// This pins the LRU contract that closes the deferred Phase 3
/// task 3.6 — the `last_query_at_ms` timestamp is the LRU key, no
/// separate ordering data structure exists.  The Phase 5 docstring
/// on `cascade_demote_one_step` calls this out explicitly.
///
/// Topology: 3 drives (C, D, E) all Warm, with backdated
/// timestamps that establish a deterministic LRU order:
/// D = 1000 (oldest) → E = 2000 → C = 3000 (newest).  The
/// cascade should drain in that order.
///
/// We inject `ControllablePressureSignal` for completeness even
/// though the test calls `cascade_demote_one_step` directly (per
/// the method docstring contract: "task 5.10 test uses
/// `Self::cascade_demote_one_step` directly without going through
/// the watch channel").  `CountingWorkingSetTrim` asserts the
/// per-step `trim()` invocation count.
///
/// [`WorkingSetTrim::trim`]: crate::cache::working_set::WorkingSetTrim::trim
#[tokio::test]
async fn cascade_demote_one_step_picks_lru_warm_and_drains_in_order() {
    use crate::cache::ShardState;
    use crate::cache::pressure::tests::ControllablePressureSignal;
    use crate::cache::working_set::tests::CountingWorkingSetTrim;

    let (tx, _rx) = crate::events::event_channel();
    let counting_trim = Arc::new(CountingWorkingSetTrim::new());
    let pressure_fake = Arc::new(ControllablePressureSignal::new());
    let hooks = crate::index::constructors::LifecycleHooks {
        working_set_trim: Arc::clone(&counting_trim)
            as Arc<dyn crate::cache::working_set::WorkingSetTrim>,
        pressure: Arc::clone(&pressure_fake) as Arc<dyn crate::cache::pressure::PressureSignal>,
        ..crate::index::constructors::LifecycleHooks::production()
    };
    let mgr = IndexManager::with_lifecycle_hooks_for_test(
        None,
        tx,
        hooks,
        Arc::new(crate::config::Config::default()),
    );
    mgr.add_drive(build_test_drive()).await;
    mgr.add_drive(build_test_drive_d()).await;
    mgr.add_drive(build_test_drive_e()).await;

    // Seed the LRU order: D oldest → E middle → C newest.  `add_drive`
    // already stamped `mark_loaded_at(unix_now_ms())` on each shard, so
    // we backdate to known values to remove wall-clock skew from the
    // assertion.
    assert!(
        mgr.backdate_last_query_at_ms_for_test(uffs_mft::platform::DriveLetter::D, 1_000)
            .await
    );
    assert!(
        mgr.backdate_last_query_at_ms_for_test(uffs_mft::platform::DriveLetter::E, 2_000)
            .await
    );
    assert!(
        mgr.backdate_last_query_at_ms_for_test(uffs_mft::platform::DriveLetter::C, 3_000)
            .await
    );

    // Pre-cascade: trim hook never fired.
    assert_eq!(counting_trim.calls(), 0, "no cascade yet → no trim");

    // ── Step 1: pick D (oldest, ts = 1000) ──────────────────────
    let step1 = mgr.cascade_demote_one_step().await;
    assert_eq!(
        step1,
        Some((uffs_mft::platform::DriveLetter::D, ShardState::Parked)),
        "first cascade step demotes the LRU Warm shard (D, ts=1000)",
    );
    assert_eq!(
        counting_trim.calls(),
        1,
        "trim() fires once per cascade step (not coalesced)",
    );

    // ── Step 2: pick E (next-oldest among Warm, ts = 2000) ─────
    let step2 = mgr.cascade_demote_one_step().await;
    assert_eq!(
        step2,
        Some((uffs_mft::platform::DriveLetter::E, ShardState::Parked)),
        "second cascade step demotes the next-LRU Warm shard (E, ts=2000)",
    );
    assert_eq!(counting_trim.calls(), 2);

    // ── Step 3: pick C (last remaining Warm, ts = 3000) ────────
    let step3 = mgr.cascade_demote_one_step().await;
    assert_eq!(
        step3,
        Some((uffs_mft::platform::DriveLetter::C, ShardState::Parked)),
        "third cascade step demotes the last Warm shard (C, ts=3000)",
    );
    assert_eq!(counting_trim.calls(), 3);

    // ── Step 4: cascade exhausted ──────────────────────────────
    // No Warm shards remain → `None` and `trim()` does NOT fire
    // (no syscall when there's no Warm work to consolidate).
    let step4 = mgr.cascade_demote_one_step().await;
    assert_eq!(
        step4, None,
        "fourth call exhausts the cascade — no Warm shards, returns None",
    );
    assert_eq!(
        counting_trim.calls(),
        3,
        "exhausted cascade must not re-trim — `pick?` short-circuits",
    );

    // Final state: every shard Parked (in alphabetical-by-letter
    // order from `shard_states_for_test`).
    let states = mgr.shard_states_for_test().await;
    assert_eq!(states, vec![
        (uffs_mft::platform::DriveLetter::C, ShardState::Parked),
        (uffs_mft::platform::DriveLetter::D, ShardState::Parked),
        (uffs_mft::platform::DriveLetter::E, ShardState::Parked),
    ]);

    // The pressure fake was never driven — this test exercises the
    // cascade method directly, not the subscriber loop.  Asserting
    // `receiver_count() == 0` documents that contract: the
    // `IndexManager` does NOT auto-subscribe at construction; only
    // `spawn_pressure_subscriber` (in `lib.rs`) does.
    assert_eq!(
        pressure_fake.receiver_count(),
        0,
        "IndexManager holds the Arc but does not auto-subscribe",
    );
}

/// Plan task **5.10 (end-to-end)** + Phase-5 wrap-up regression — the
/// full `spawn_pressure_subscriber` → `cascade_demote_one_step` →
/// preempt loop must:
///
/// 1. Subscribe to the [`PressureSignal`] (`receiver_count` becomes 1 after
///    spawn).
/// 2. On `Low`, drain every Warm shard one step at a time, calling
///    [`WorkingSetTrim::trim`] exactly once per cascade step.
/// 3. On `High`, become a no-op — the cascade body never runs.
/// 4. On a second `Low` after the first cascade exhausted the Warm set,
///    terminate the inner cascade loop on the first `None` return without
///    firing extra trim calls.
///
/// The existing [`cascade_demote_one_step_picks_lru_warm_and_drains_in_order`]
/// test pins the cascade method's contract by calling it directly;
/// this test pins the **subscriber wiring** in `lib.rs` so a future
/// refactor of [`crate::spawn_pressure_subscriber`] can't silently
/// drop the cascade-on-Low contract that the Win32 watcher thread
/// depends on.
///
/// Test architecture mirrors §5.10's direct test (3 shards backdated
/// for a deterministic LRU order) but drives the timeline through
/// the watch channel instead of synchronous calls into the manager.
/// Polling on `shard_states_for_test` plus `receiver_count` keeps
/// the test deterministic without `tokio::time::pause` (which would
/// require a `current_thread` runtime + `start_paused = true`).
///
/// [`PressureSignal`]: crate::cache::pressure::PressureSignal
/// [`WorkingSetTrim::trim`]: crate::cache::working_set::WorkingSetTrim::trim
#[tokio::test]
async fn pressure_subscriber_drains_warm_cascade_on_low_and_no_ops_on_high() {
    use pressure_subscriber_fixtures::{
        CASCADE_DEADLINE, QUIESCENT_WINDOW, build_pressure_subscriber_fixture, poll_until,
    };

    use crate::cache::ShardState;
    use crate::cache::pressure::PressureLevel;

    let fixture = build_pressure_subscriber_fixture().await;

    // ── Spawn the subscriber and wait for it to attach ───────────
    let subscriber = crate::spawn_pressure_subscriber(Arc::clone(&fixture.mgr));
    let attach_deadline = std::time::Instant::now() + CASCADE_DEADLINE;
    while fixture.pressure_fake.receiver_count() == 0 {
        assert!(
            std::time::Instant::now() < attach_deadline,
            "subscriber did not attach to the watch channel within {CASCADE_DEADLINE:?}",
        );
        tokio::task::yield_now().await;
    }
    assert_eq!(
        fixture.pressure_fake.receiver_count(),
        1,
        "exactly one subscriber attaches via spawn_pressure_subscriber",
    );

    // ── Step 1: First Low → drains all Warm in LRU order ─────────
    assert!(
        fixture.pressure_fake.set(PressureLevel::Low),
        "broadcast Low must reach the attached subscriber",
    );
    poll_until(
        &fixture.mgr,
        |states| states.iter().all(|(_, s)| *s == ShardState::Parked),
        "first Low cascade",
    )
    .await;
    assert_eq!(
        fixture.counting_trim.calls(),
        3,
        "trim() fires once per cascade step (3 Warm → 3 calls)",
    );

    // ── Step 2: High → no-op (no additional demotes / trim calls) ─
    assert!(fixture.pressure_fake.set(PressureLevel::High));
    tokio::time::sleep(QUIESCENT_WINDOW).await;
    let post_high_states = fixture.mgr.shard_states_for_test().await;
    assert!(
        post_high_states
            .iter()
            .all(|(_, s)| *s == ShardState::Parked),
        "High transition must not change shard state; got {post_high_states:?}",
    );
    assert_eq!(
        fixture.counting_trim.calls(),
        3,
        "High triggers no additional demotes or trim calls",
    );

    // ── Step 3: Second Low with no Warm left → cascade returns
    // None on first call, no extra trim fires ────────────────────
    assert!(fixture.pressure_fake.set(PressureLevel::Low));
    tokio::time::sleep(QUIESCENT_WINDOW).await;
    assert_eq!(
        fixture.counting_trim.calls(),
        3,
        "second Low with no Warm shards must not call trim() again",
    );

    // Clean shutdown — abort the subscriber explicitly so the test
    // task tree winds down without waiting on the watch sender's
    // own drop (which is racy across the Arc<IndexManager> graph).
    subscriber.abort();
}

/// Test infrastructure for
/// [`pressure_subscriber_drains_warm_cascade_on_low_and_no_ops_on_high`].
///
/// Lifted out of the test body so the test stays under clippy's
/// 100-line ceiling without compromising on assertion coverage.
/// Module-private; only the parent test imports its public surface.
mod pressure_subscriber_fixtures {
    use core::time::Duration;
    use std::sync::Arc;

    use super::{IndexManager, build_test_drive, build_test_drive_d, build_test_drive_e};
    use crate::cache::ShardState;
    use crate::cache::pressure::PressureSignal;
    use crate::cache::pressure::tests::ControllablePressureSignal;
    use crate::cache::working_set::tests::CountingWorkingSetTrim;
    use crate::index::constructors::LifecycleHooks;

    /// Polling deadline for cascade-completion observation.  Wall-clock
    /// bound — generous enough that a busy CI box doesn't false-fail
    /// (cascade is microseconds of pure CPU work; 2 s is 1 000× the
    /// observed worst case) and short enough that a real bug surfaces
    /// fast.
    pub(super) const CASCADE_DEADLINE: Duration = Duration::from_secs(2);

    /// Quiescent observation window — after a non-cascade-driving
    /// transition (`High`) we wait this long to confirm the
    /// subscriber stays idle, then assert no Warm shards demoted and
    /// no trim calls fired.  Tuned to be > one `tokio::task::yield_now`
    /// scheduler pass on every supported runtime.
    pub(super) const QUIESCENT_WINDOW: Duration = Duration::from_millis(50);

    /// Bundle of the three handles the test asserts against:
    /// the `IndexManager` under test, the controllable pressure
    /// fake driving the watch channel, and the trim counter.
    pub(super) struct PressureSubscriberFixture {
        pub mgr: Arc<IndexManager>,
        pub pressure_fake: Arc<ControllablePressureSignal>,
        pub counting_trim: Arc<CountingWorkingSetTrim>,
    }

    /// Build the [`PressureSubscriberFixture`] preconfigured with
    /// 3 Warm shards in deterministic LRU order (D = 1000 →
    /// E = 2000 → C = 3000), zero trim calls, and zero subscribers
    /// — same ordering as the §5.10 direct test so a regression
    /// there surfaces in the subscriber test too.  Asserts the
    /// preconditions before returning so the parent test body
    /// can stay focused on the act / observe sequence.
    pub(super) async fn build_pressure_subscriber_fixture() -> PressureSubscriberFixture {
        let (tx, _rx) = crate::events::event_channel();
        let counting_trim = Arc::new(CountingWorkingSetTrim::new());
        let pressure_fake = Arc::new(ControllablePressureSignal::new());
        let hooks = LifecycleHooks {
            working_set_trim: Arc::clone(&counting_trim)
                as Arc<dyn crate::cache::working_set::WorkingSetTrim>,
            pressure: Arc::clone(&pressure_fake) as Arc<dyn PressureSignal>,
            ..LifecycleHooks::production()
        };
        let mgr = Arc::new(IndexManager::with_lifecycle_hooks_for_test(
            None,
            tx,
            hooks,
            Arc::new(crate::config::Config::default()),
        ));
        mgr.add_drive(build_test_drive()).await;
        mgr.add_drive(build_test_drive_d()).await;
        mgr.add_drive(build_test_drive_e()).await;
        assert!(
            mgr.backdate_last_query_at_ms_for_test(uffs_mft::platform::DriveLetter::D, 1_000)
                .await
        );
        assert!(
            mgr.backdate_last_query_at_ms_for_test(uffs_mft::platform::DriveLetter::E, 2_000)
                .await
        );
        assert!(
            mgr.backdate_last_query_at_ms_for_test(uffs_mft::platform::DriveLetter::C, 3_000)
                .await
        );
        let initial_states = mgr.shard_states_for_test().await;
        assert!(
            initial_states.iter().all(|(_, s)| *s == ShardState::Warm),
            "preconditions: all 3 shards Warm; got {initial_states:?}",
        );
        assert_eq!(
            counting_trim.calls(),
            0,
            "preconditions: no trim calls before subscriber spawn",
        );
        assert_eq!(
            pressure_fake.receiver_count(),
            0,
            "preconditions: no subscribers before spawn",
        );
        PressureSubscriberFixture {
            mgr,
            pressure_fake,
            counting_trim,
        }
    }

    /// Poll [`IndexManager::shard_states_for_test`] until `predicate`
    /// holds or the [`CASCADE_DEADLINE`] expires.  Panics with a
    /// diagnostic message on timeout so a regression surfaces at the
    /// failed assertion site, not as a hung test.
    pub(super) async fn poll_until<F>(mgr: &IndexManager, predicate: F, label: &str)
    where
        F: Fn(&[(uffs_mft::platform::DriveLetter, ShardState)]) -> bool,
    {
        let deadline = std::time::Instant::now() + CASCADE_DEADLINE;
        loop {
            let states = mgr.shard_states_for_test().await;
            if predicate(&states) {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{label} did not converge within {CASCADE_DEADLINE:?}; last states = {states:?}",
            );
            tokio::task::yield_now().await;
        }
    }
}
