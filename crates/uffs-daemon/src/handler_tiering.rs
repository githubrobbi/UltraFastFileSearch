// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Memory-tiering RPC handlers: `hibernate`, `preload`, and
//! `warm_plan`.
//!
//! Split out of `handler.rs` to keep the dispatcher under the
//! workspace 800-LOC policy ceiling; `#[path]` in `handler.rs`
//! re-attaches this file to the same `impl RequestHandler`, so the
//! dispatch table calls these as ordinary methods
//! (`self.handle_hibernate(...)` etc.) with no call-site changes.
//!
//! `warm_plan` (v0.6.38) is the daemon-authoritative cold-index
//! answer for external gates: given the SAME `SearchParams` a search
//! would carry, it returns the promote set dispatch would actually
//! execute — Parked/Cold shards in scope whose bloom cannot prove
//! them irrelevant to the resolved extension filter.  Gates that
//! instead infer readiness from the tier marker alone over-gate:
//! a bloom-skippable Parked drive answers its query instantly with
//! zero rows and must not be reported "warming" or force-promoted
//! (field 2026-08-24, winbox drive E:).

use uffs_client::protocol::response::{
    DEFAULT_PRELOAD_PIN_MINUTES, HibernateParams, HibernateResponse, PreloadParams,
    PreloadResponse, WarmPlanResponse,
};
use uffs_client::protocol::{ERR_INVALID_PARAMS, RpcErrorResponse, RpcRequest, RpcResponse};

use super::RequestHandler;

impl RequestHandler {
    /// Handle `warm_plan`: report which drives the given search would
    /// promote, without promoting anything.
    ///
    /// Params are a full [`uffs_client::protocol::SearchParams`] —
    /// the caller sends the SAME params it is about to search with,
    /// and the daemon resolves them through the same
    /// canonicalisation + filter pipeline the search itself uses
    /// ([`crate::index::IndexManager::warm_plan`]), so the answer is
    /// bit-exact with what dispatch will do.  Validation matches
    /// `handle_search` (S4.4.3 pattern-length guard included).
    pub(super) async fn handle_warm_plan(&self, id: u64, req: &RpcRequest) -> String {
        let params = match Self::parse_and_validate_search_params(req) {
            Ok(params) => params,
            Err(parse_err) => return parse_err.to_rpc_error_json(id),
        };
        let needs_promote = self.index.warm_plan(&params).await;
        let result = serde_json::to_value(&WarmPlanResponse { needs_promote }).unwrap_or_default();
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }

    /// Handle `hibernate` method (Phase 8-B).
    ///
    /// Parses [`HibernateParams`] from the JSON-RPC envelope, walks
    /// the registry via [`crate::index::IndexManager::hibernate_shards`], and
    /// returns the structured [`HibernateResponse`] reporting
    /// drives demoted from each pre-call tier plus drives that were
    /// already at the bottom.
    ///
    /// Empty `drives` in the params means "every loaded drive";
    /// non-matching letters in a non-empty `drives` filter are
    /// silently dropped (the operator audit lives on the
    /// `already_cold` field of the response, which lists only
    /// drives the daemon actually knows about).
    ///
    /// Malformed params (anything that fails to deserialise as
    /// [`HibernateParams`]) fall back to the empty-default
    /// (hibernate every drive); the wire contract is "best-effort
    /// match" rather than "strict reject" because the all-loaded
    /// path is always safe and an over-strict reject would surprise
    /// scripts that send slightly-non-canonical JSON.
    pub(super) async fn handle_hibernate(&self, id: u64, req: &RpcRequest) -> String {
        let params: HibernateParams = req
            .params
            .as_ref()
            .and_then(|val| serde_json::from_value(val.clone()).ok())
            .unwrap_or_default();
        let outcome = self.index.hibernate_shards(&params.drives).await;
        let response = HibernateResponse {
            hot_demoted: outcome.hot_demoted,
            warm_demoted: outcome.warm_demoted,
            parked_demoted: outcome.parked_demoted,
            already_cold: outcome.already_cold,
        };
        let result = serde_json::to_value(&response).unwrap_or_default();
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }

    /// Handle `preload` method (Phase 8-C).
    ///
    /// Parses [`PreloadParams`] from the JSON-RPC envelope, loops
    /// over the requested drives calling
    /// [`crate::index::IndexManager::preload_drive`] for each, and aggregates
    /// the per-drive [`crate::index::tiering_ops::PreloadOutcome`]s into
    /// a single [`PreloadResponse`].
    ///
    /// Validates that the params include at least one drive — an
    /// empty `drives` vector returns [`ERR_INVALID_PARAMS`] so a
    /// caller's mistyped script doesn't silently succeed.  The pin
    /// duration defaults to [`DEFAULT_PRELOAD_PIN_MINUTES`] when
    /// the params omit `pin_minutes`.
    pub(super) async fn handle_preload(&self, id: u64, req: &RpcRequest) -> String {
        let params: PreloadParams = req
            .params
            .as_ref()
            .and_then(|val| serde_json::from_value(val.clone()).ok())
            .unwrap_or_default();
        if params.drives.is_empty() {
            return serde_json::to_string(&RpcErrorResponse::error(
                Some(id),
                ERR_INVALID_PARAMS,
                "preload: `drives` must contain at least one drive letter",
            ))
            .unwrap_or_default();
        }
        let pin_minutes = params.pin_minutes.unwrap_or(DEFAULT_PRELOAD_PIN_MINUTES);

        let mut promoted: Vec<uffs_mft::platform::DriveLetter> = Vec::new();
        let mut already_hot: Vec<uffs_mft::platform::DriveLetter> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let mut latest_pin_until_ms: i64 = 0;

        for &letter in &params.drives {
            use crate::index::tiering_ops::PreloadOutcome;
            match self.index.preload_drive(letter, pin_minutes).await {
                PreloadOutcome::Promoted { pin_until_ms, .. } => {
                    promoted.push(letter);
                    latest_pin_until_ms = i64::try_from(pin_until_ms).unwrap_or(i64::MAX);
                }
                PreloadOutcome::AlreadyHot { pin_until_ms } => {
                    already_hot.push(letter);
                    latest_pin_until_ms = i64::try_from(pin_until_ms).unwrap_or(i64::MAX);
                }
                PreloadOutcome::UnknownDrive => {
                    errors.push(format!("{letter}: drive not loaded"));
                }
                PreloadOutcome::LoadFailed => {
                    errors.push(format!("{letter}: body load failed"));
                }
                PreloadOutcome::Busy { from_state } => {
                    errors.push(format!(
                        "{letter}: drive busy in transient state ({from_state})"
                    ));
                }
            }
        }

        let response = PreloadResponse {
            promoted,
            already_hot,
            errors,
            pin_until_unix_ms: latest_pin_until_ms,
        };
        let result = serde_json::to_value(&response).unwrap_or_default();
        serde_json::to_string(&RpcResponse::success(id, result)).unwrap_or_default()
    }
}
