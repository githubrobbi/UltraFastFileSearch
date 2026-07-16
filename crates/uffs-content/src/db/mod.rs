// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Durable job/failure-bucket ledger (addendum §6):
//! `uffs-content-jobs.sqlite3`.
//!
//! A dedicated, UFFS-owned SQLite WAL database — not an in-memory list,
//! not the mutable manifest, not shared with Docenta's database (addendum
//! §6.1/§6.2). [`schema`] owns the DDL and connection setup; [`queries`]
//! is the narrow typed API this milestone needs to prove the
//! completeness invariant and crash-recovery durability.

pub mod queries;
pub mod schema;
