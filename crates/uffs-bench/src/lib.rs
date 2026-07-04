// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! # uffs-bench: Robust Benchmark-Suite Orchestrator (Phase P1 spine)
//!
//! Workspace-only tool crate that drives the reproducible benchmark flow
//! described in `docs/benchmarks/robust-benchmark-flow-execution-plan.md`.
//!
//! ## Guiding principle — "no crumb left behind"
//!
//! Every host-state mutation follows the same cycle: **snapshot → mutate →
//! restore → verify**. The restore is registered *before* the mutation, so a
//! [`Drop`]-guarded [`restore::RestoreRegistry`] undoes it on early return or
//! panic just as reliably as on the happy path.
//!
//! ## Dependency-injection seam
//!
//! All side effects (filesystem, process spawning, clock, TTY, user input,
//! console output) flow through the [`host::Host`] trait. The real
//! [`host::SystemHost`] talks to the OS; the [`host::MockHost`] keeps an
//! in-memory filesystem, records every call, and replays scripted keypresses.
//! This lets the entire orchestrator — including the Windows-only measurement
//! stages added in later phases — be unit-tested on any OS in the same
//! `cargo nextest` lane as `just go`.
//!
//! ## P1 surface (this crate today)
//!
//! - [`error`] — [`error::BenchError`] / [`error::CrumbError`].
//! - [`host`] — the [`host::Host`] seam + `SystemHost` / `MockHost`.
//! - [`restore`] — the LIFO undo registry and its `Drop` guard.
//! - [`gate`] — modes, cards, and the mode-aware [`gate::confirm`] decision.
//! - [`cards`] — gate-card / step-result builders for the staged orchestrator.
//! - [`competitors`] — P8 pinned-competitor manifest parse + fetch/verify.
//! - [`state`] — the `state.json` model + resume engine (`input_hash`).
//! - [`tooling`] — acquired-tool keep/remove dispositions.
//! - [`fingerprint`] — host fingerprint capture + crumb diff.
//! - [`bundle`] — bundle directory creation + tool resolution.
//! - [`mod@env`] — Stage 0a environment fingerprint capture + markdown
//!   renderer.
//! - [`preflight`] — Stage 0c read-only competitor (Everything) preflight.
//! - [`matrix`] — Stage 0d cross-tool vs UFFS-only matrix negotiation.
//! - [`cli`] — the `clap` flag surface ([`cli::Cli`]) and mode resolution.
//! - [`stages`] — Stage 1–3 measurement wrappers + the `percentiles` helper.
//! - [`report`] — Stage 4 bundle assembly + `REPORT-DRAFT.md` scaffold.
//! - [`mod@run`] — Stage 0e plan gate + the staged orchestrator ([`run::run`]).
//!
//! The remaining teardown/verify wiring builds on this foundation in phase P9;
//! the binary entry point (`main.rs`) is a thin shim over [`run::run`].

// Collection types are imported from `alloc` (not `std`) per the workspace
// `std_instead_of_alloc` lint; this brings the crate into scope for those
// paths.
extern crate alloc;

// Linked for this crate's `uffs-bench` binary, which calls
// `uffs_version::handle_version!` in `main`; the library itself does not
// reference it (sanctioned unused-crate-dependencies marker).
use uffs_version as _;

pub mod baseline;
pub mod bundle;
pub mod cards;
pub mod charts;
pub mod cli;
pub mod competitors;
pub mod env;
pub mod error;
pub mod fingerprint;
pub mod gate;
pub mod host;
pub mod matrix;
pub mod preflight;
pub mod report;
pub mod resolve;
pub mod restore;
pub mod run;
pub mod run_state;
pub mod stages;
pub mod state;
pub mod storage;
pub mod summary;
pub mod teardown;
pub mod tooling;

pub use cli::Cli;
pub use error::{BenchError, CrumbError, Result};
pub use host::{Host, MockHost, ProcOutput, SystemHost};
pub use run::run;
