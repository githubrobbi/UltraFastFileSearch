// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Shared helpers for split Windows command modules.

use core::time::Duration;

/// Sleeps briefly between benchmark runs so the system can settle.
pub(super) async fn pause_between_benchmark_runs(run: u32, runs: u32) {
    if run < runs {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
