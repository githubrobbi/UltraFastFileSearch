// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Wire protocol between the UFFS Content Service (producer) and a
//! downstream content consumer such as Docenta.
//!
//! This is a dedicated cross-platform Layer-0 library — pure enum/struct
//! definitions and (eventually) byte-shuffling, no I/O, no Windows FFI, no
//! VSS/MFT access. Both sides of the wire (the `uffs-content` coordinator
//! process and any unprivileged consumer) import the types defined here so
//! the wire format has a single source of truth, matching the pattern
//! `uffs-broker-protocol` already established for the Access Broker.
//!
//! # Design references
//!
//! (all under `docs/dev/architecture/` — local-only, not tracked in git)
//!
//! - `content-stream-tool-design.md` — the original, VSS-less design sketch.
//! - `uffs-content-stream-enterprise-design-review.md` — the replacement-design
//!   review superseding that sketch: content-delivery protocol independent of
//!   read mode, logical file-ID reads as the default, raw/snapshot extent reads
//!   demoted to an optional internal acceleration behind a narrow privileged
//!   helper (never the public coordinator).
//! - Docenta's `uffs-ingest-protocol-v2-vss.md` — the settled v2 contract this
//!   crate's types are scaffolded from: one VSS snapshot per job, an immutable
//!   candidate manifest, a framed chunked content stream, and a durable failure
//!   bucket.
//!
//! # Status
//!
//! Under active implementation per
//! `docs/dev/architecture/uffs-ingest-implementation-plan.md` (local-only,
//! UFI.0). [`codec`] (bounds-checked LE primitives + checksums) and
//! [`state`] are implemented; the manifest header/record/trailer layout
//! (design-doc §11) and the frame envelope + frame types (§12) are next.

pub mod codec;
pub mod error;
pub mod manifest;
pub mod path_encoding;
pub mod state;
