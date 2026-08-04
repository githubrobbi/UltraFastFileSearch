// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Hardened release-asset transport: blocking HTTP fetch + SHA-256 verify.
//!
//! Extracted from `uffs-update`'s acquire step so any product can reuse the
//! same hardened machinery instead of writing a second one:
//!
//! - [`github::fetch_release`] — GitHub Releases metadata lookup (`latest` or a
//!   specific tag).
//! - [`github::download_to`] — streaming download of **any** URL (not just
//!   GitHub) with retry, connect/inactivity timeouts, and a caller-chosen byte
//!   cap.
//! - [`github::with_retry`] — the bounded-exponential-back-off retry wrapper,
//!   usable around any `reqwest` operation.
//! - [`verify`] — `SHA256SUMS` parsing and file-hash verification.
//!
//! Everything is blocking by design (one-shot CLI/installer steps), TLS is
//! rustls with the system trust store, and the caller supplies the
//! user-agent product string — this crate never bakes in a product name.

pub mod github;
pub mod verify;

pub use github::{Asset, Release, download_to, fetch_release, with_retry};
pub use verify::{expected_hash, parse_sha256sums, sha256_file, verify_sha256};
