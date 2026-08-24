// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Cold-index gate for query tools: never let an MCP call block
//! silently on an index re-warm.
//!
//! # The failure this prevents
//!
//! A shard that has tiered down (`Parked` after 30 min idle, `Cold`
//! after 24 h) is re-warmed on the next search — which can take
//! 30–120 s on HDD-heavy systems (the promote replays the USN journal
//! against the live MFT).  The daemon's readiness gate only reports
//! the *initial* `Loading` state; a parked index reads `Ready`, so a
//! query tool used to sail through the gate and block inside the
//! daemon with **zero feedback**.  To an agent host a silent 90 s
//! block is indistinguishable from a hang: observed in the field as a
//! cold `uffs_search` backgrounded at 120 s and abandoned at the
//! host's 1800 s idle timeout, having never returned.
//!
//! # The contract instead
//!
//! Before a query tool dispatches against drives that are not
//! `Warm`/`Hot`, it:
//!
//! 1. **starts the re-warm in a detached task** — a minimal search scoped to
//!    the cold drives on its own daemon connection, so the warm survives
//!    whatever the host does to the original tool call (the daemon runs each
//!    request to completion once received, and single-flight dedup makes repeat
//!    triggers free), and
//! 2. **returns immediately** with a structured "index warming — poll
//!    `uffs_status`, retry" error the LLM can act on, exactly like the existing
//!    startup readiness gate.
//!
//! The result is a pull-model progress loop: the agent polls
//! `uffs_status` (exempt from every gate) while the warm proceeds,
//! and its retry lands on a warm index in milliseconds.  A push model
//! (MCP progress notifications) was considered and rejected: hosts do
//! not extend their tool-call patience on progress events, so the
//! call would still read as hung.
//!
//! # Who decides "not ready": the daemon, not this gate
//!
//! Since v0.6.38 the gate asks the daemon's `warm_plan` RPC for the
//! exact promote set its dispatch would execute for the query — which
//! includes the Phase-4 bloom pre-check.  A Parked drive whose bloom
//! proves it holds nothing matching the query's extension filter is
//! ready *by definition* (dispatch skips it and it contributes zero
//! rows), so it must neither gate the call nor be force-warmed.  The
//! previous tier-only inference did both (field 2026-08-24, winbox
//! drive E:), and its warm trigger — pattern-only, no ext filter —
//! bypassed the daemon's own bloom skip and paged the body back into
//! RAM.  The tier-based check survives only as `not_ready`, the
//! fallback for pre-`warm_plan` daemons, where it is conservative
//! (over-gates, never under-gates).

use uffs_client::connect::UffsClient;
use uffs_client::error::ClientError;
use uffs_client::protocol::response::{DriveInfo, ShardTier};
use uffs_client::protocol::{ERR_METHOD_NOT_FOUND, SearchParams};

use crate::error::BridgeError;

/// Pattern for the detached warm-trigger search: three repeated rare
/// trigrams, so the post-promote scan is a fast trigram miss.  What it
/// matches is irrelevant — the point is that the daemon's dispatch
/// path promotes every scoped shard before scanning.
const WARM_TRIGGER_PATTERN: &str = "zzqzzqzzq";

/// The drives a query would touch that are not ready to serve it.
///
/// `scope` is the query's drive filter (empty = all drives).  A drive
/// counts as not-ready when the daemon reports a tier other than
/// `Warm`/`Hot` — `Parked` and `Cold` need a body re-load, `Unknown`
/// has never loaded.  A missing tier (pre-v0.5.82 daemon) is treated
/// as ready: those daemons never demote, so their shards are warm by
/// construction.
fn not_ready(
    drives: &[DriveInfo],
    scope: &[uffs_mft::platform::DriveLetter],
) -> Vec<uffs_mft::platform::DriveLetter> {
    drives
        .iter()
        .filter(|info| scope.is_empty() || scope.contains(&info.letter))
        .filter(|info| {
            matches!(
                info.tier,
                Some(ShardTier::Parked | ShardTier::Cold | ShardTier::Unknown)
            )
        })
        .map(|info| info.letter)
        .collect()
}

/// Whether a client error is the daemon saying it does not know the
/// `warm_plan` method (pre-v0.6.38): the signal to fall back to the
/// legacy tier-based gate rather than fail the query tool.
const fn is_method_not_found(err: &ClientError) -> bool {
    matches!(err, ClientError::DaemonError { code, .. } if *code == ERR_METHOD_NOT_FOUND)
}

/// Gate a query tool on index warmth: `Ok(())` when the daemon's own
/// dispatch would promote nothing for `params`; otherwise kick a
/// detached re-warm of exactly the drives the daemon named and return
/// the retry-shaped error described in the module docs.
///
/// The decision is daemon-authoritative (`warm_plan` RPC): the daemon
/// computes the promote set through the same filter resolution + bloom
/// pre-check its dispatch uses, so a Parked drive whose bloom proves it
/// irrelevant to the query's extension filter passes the gate and is
/// never force-promoted.  Deciding from the tier marker alone — the
/// pre-v0.6.38 behaviour, kept as the fallback for older daemons —
/// over-gates exactly that case (field 2026-08-24, winbox drive `E:` — an
/// ext-filtered query the bloom had already answered was reported
/// "warming — retry" while the warm trigger paged the drive's body
/// back into RAM, defeating the Phase-4 zero-RAM-touch contract).
///
/// # Errors
///
/// Returns [`BridgeError::Daemon`] when scoped drives are re-warming
/// (the retry contract) or when the plan/tier probe itself fails.
pub(crate) async fn warm_gate(
    client: &mut UffsClient,
    params: &SearchParams,
) -> Result<(), BridgeError> {
    let cold = match client.warm_plan(params).await {
        Ok(plan) => plan.needs_promote,
        Err(err) if is_method_not_found(&err) => {
            // Pre-`warm_plan` daemon: legacy tier-based gate.  Strictly
            // more conservative than the plan (it cannot consult the
            // bloom), never less — a query is at worst gated when it
            // could have passed, exactly the pre-v0.6.38 behaviour.
            let drives = client.drives().await.map_err(|drives_err| {
                BridgeError::Daemon(format!("warm check failed: {drives_err}"))
            })?;
            not_ready(&drives.drives, &params.drives)
        }
        Err(err) => return Err(BridgeError::Daemon(format!("warm check failed: {err}"))),
    };
    if cold.is_empty() {
        return Ok(());
    }

    // Detached warm trigger: its own connection, its own lifetime.
    // Once the request reaches the daemon it runs to completion there,
    // so the warm finishes even if this MCP session dies; per-letter
    // single-flight dedup in the daemon makes a repeat trigger (an
    // agent retrying early) join the in-flight load instead of
    // duplicating it.
    let trigger_drives = cold.clone();
    drop(tokio::spawn(async move {
        let Ok(mut warm_client) = UffsClient::connect_raw().await else {
            tracing::warn!("warm trigger: daemon connect failed — retry will re-trigger");
            return;
        };
        let mut trigger_params = SearchParams {
            pattern: WARM_TRIGGER_PATTERN.to_owned(),
            drives: trigger_drives.clone(),
            limit: Some(1),
            ..Default::default()
        };
        trigger_params.populate_canonical_fields();
        match warm_client.search(&trigger_params).await {
            Ok(_) => tracing::info!(drives = ?trigger_drives, "warm trigger completed"),
            Err(err) => tracing::warn!(%err, "warm trigger search failed"),
        }
    }));

    let list: Vec<String> = cold.iter().map(ToString::to_string).collect();
    Err(BridgeError::Daemon(format!(
        "⏳ Index warming — drive(s) {} were parked/cold and are being re-warmed now \
         (typically 30–120 s; HDDs are the slow end). This call returned early instead \
         of blocking; nothing is wrong with your query. Poll uffs_status until its \
         `index_ready` field is true — NOT the `status` field, which reads \"Ready\" \
         for the daemon process even while every drive is parked — then retry this \
         exact query unchanged; it will answer in milliseconds.",
        list.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use uffs_client::protocol::response::{DriveInfo, ShardTier};
    use uffs_mft::platform::DriveLetter;

    use super::not_ready;

    /// Build a `DriveInfo` with the given letter and tier.
    fn info(letter: char, tier: Option<ShardTier>) -> DriveInfo {
        DriveInfo {
            letter: DriveLetter::parse(letter).unwrap_or(DriveLetter::C),
            records: 0,
            source: "test".to_owned(),
            tier,
            records_when_warm: None,
            loading: None,
        }
    }

    /// The exact field shape: warm C answers, parked D and cold S gate.
    #[test]
    fn parked_and_cold_drives_gate_warm_ones_do_not() {
        let drives = vec![
            info('C', Some(ShardTier::Warm)),
            info('D', Some(ShardTier::Parked)),
            info('S', Some(ShardTier::Cold)),
        ];
        let cold = not_ready(&drives, &[]);
        assert_eq!(cold, vec![
            DriveLetter::parse('D').unwrap_or(DriveLetter::C),
            DriveLetter::parse('S').unwrap_or(DriveLetter::C),
        ]);
    }

    /// A query scoped to a warm drive must NOT gate on some other
    /// drive being cold — scoping is the whole point of the check.
    #[test]
    fn scope_limits_the_gate_to_touched_drives() {
        let drives = vec![
            info('C', Some(ShardTier::Warm)),
            info('D', Some(ShardTier::Cold)),
        ];
        let scope = vec![DriveLetter::parse('C').unwrap_or(DriveLetter::C)];
        assert_eq!(
            not_ready(&drives, &scope),
            Vec::<DriveLetter>::new(),
            "warm-scoped query must pass while another drive is cold"
        );
    }

    /// Hot counts as ready; Unknown (never loaded) does not.
    #[test]
    fn hot_is_ready_unknown_is_not() {
        let drives = vec![
            info('C', Some(ShardTier::Hot)),
            info('E', Some(ShardTier::Unknown)),
        ];
        let cold = not_ready(&drives, &[]);
        assert_eq!(cold, vec![
            DriveLetter::parse('E').unwrap_or(DriveLetter::C)
        ]);
    }

    /// A pre-tiering daemon (no tier field) never demotes — treat its
    /// shards as warm rather than gating every query forever.
    #[test]
    fn missing_tier_reads_as_ready() {
        let drives = vec![info('C', None)];
        assert_eq!(not_ready(&drives, &[]), Vec::<DriveLetter>::new());
    }

    /// Only the daemon's method-not-found answer selects the legacy
    /// tier-based fallback; every other failure propagates.
    #[test]
    fn only_method_not_found_selects_the_legacy_fallback() {
        use uffs_client::error::ClientError;
        use uffs_client::protocol::ERR_METHOD_NOT_FOUND;

        use super::is_method_not_found;

        assert!(is_method_not_found(&ClientError::DaemonError {
            code: ERR_METHOD_NOT_FOUND,
            message: "Method not found: warm_plan".to_owned(),
        }));
        assert!(!is_method_not_found(&ClientError::DaemonError {
            code: -32_602_i32,
            message: "Missing or invalid search params".to_owned(),
        }));
        assert!(!is_method_not_found(&ClientError::ConnectionClosed));
    }
}
