// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Protocol-level error type (scaffold).

use thiserror::Error;

/// Errors that can occur while encoding or decoding a content-protocol
/// manifest or frame.
///
/// This is a placeholder variant set so the crate is constructible before
/// the real error taxonomy lands. The full stable, machine-readable code
/// list (`SNAPSHOT_CREATE_FAILED`, `MANIFEST_CORRUPT`, `DIGEST_MISMATCH`,
/// ...) is design-doc §16 and will replace this enum once the wire
/// encoding is implemented.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Placeholder variant covering every not-yet-implemented protocol
    /// operation. The string names which operation was attempted.
    #[error("content protocol not yet implemented: {0}")]
    NotYetImplemented(&'static str),
}
