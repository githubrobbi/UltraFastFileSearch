// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! The `diff` method handler for [`super::RequestHandler`].
//!
//! Lifted out of `handler.rs` to keep that file under the 800-line policy
//! ceiling. Re-attached via `#[path = "handler_diff.rs"] mod diff_handler;` in
//! `handler.rs`, so `handle_diff` stays an `impl RequestHandler` method the
//! dispatcher calls as `self.handle_diff(...)`.
//!
//! Parsing + wire-mapping only: the classification, path resolution, baseline
//! load, and live-index snapshot all live in `IndexManager::diff_snapshot`
//! (`crate::index::diff`) and `uffs_core::diff`.

use uffs_client::protocol::{
    DiffParams, ERR_INTERNAL, ERR_INVALID_PARAMS, ERR_NOT_READY, RpcErrorResponse, RpcRequest,
    RpcResponse,
};

use super::RequestHandler;
use crate::index::diff::DiffError;

impl RequestHandler {
    /// Handle the `diff` method — snapshot delete-visibility diff of a baseline
    /// capture against the live index for a drive.
    pub(super) async fn handle_diff(&self, id: u64, req: &RpcRequest) -> String {
        let params: DiffParams = match req
            .params
            .as_ref()
            .map(|val| serde_json::from_value(val.clone()))
        {
            Some(Ok(params)) => params,
            Some(Err(err)) => {
                return serde_json::to_string(&RpcErrorResponse::error(
                    Some(id),
                    ERR_INVALID_PARAMS,
                    &format!("diff: invalid params: {err}"),
                ))
                .unwrap_or_default();
            }
            None => {
                return serde_json::to_string(&RpcErrorResponse::error(
                    Some(id),
                    ERR_INVALID_PARAMS,
                    "diff: missing params (`baseline` + `drive` required)",
                ))
                .unwrap_or_default();
            }
        };

        match self.index.diff_snapshot(&params).await {
            Ok(result) => {
                let value = serde_json::to_value(&result).unwrap_or_default();
                serde_json::to_string(&RpcResponse::success(id, value)).unwrap_or_default()
            }
            Err(DiffError::DriveNotLoaded(letter)) => {
                serde_json::to_string(&RpcErrorResponse::error(
                    Some(id),
                    ERR_NOT_READY,
                    &format!(
                        "diff: drive {letter} is not loaded; load it first \
                         (`uffs --daemon load --drive {letter}`)"
                    ),
                ))
                .unwrap_or_default()
            }
            Err(DiffError::BaselineLoad { path, source }) => {
                serde_json::to_string(&RpcErrorResponse::error(
                    Some(id),
                    ERR_INTERNAL,
                    &format!("diff: could not load baseline '{path}': {source}"),
                ))
                .unwrap_or_default()
            }
        }
    }
}
