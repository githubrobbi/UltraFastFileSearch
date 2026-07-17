// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Minimal bounds-checked little-endian decode primitives for
//! [`super`] (`snapshot_manager`).

use thiserror::Error;

/// Errors decoding wire bytes.
///
/// A deliberately small, independent duplicate of the same bounds-checked
/// LE decode shape used by `uffs-content-protocol` and
/// `uffs-content-reader-protocol` — this crate stays Layer-0-independent
/// of both (see those crates' `Cargo.toml` for the shared rationale).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SnapshotProtocolError {
    /// Fewer bytes remained than the field being read requires.
    #[error("truncated input: needed {needed} bytes, only {available} remained")]
    Truncated {
        /// Bytes required to satisfy the read.
        needed: usize,
        /// Bytes actually remaining in the input.
        available: usize,
    },
    /// A length-prefixed field declared more bytes than the caller's
    /// configured maximum allows, checked before allocation.
    #[error("field '{field}' declared length {declared} exceeds maximum {max}")]
    LengthOutOfBounds {
        /// Name of the offending field, for diagnostics.
        field: &'static str,
        /// Length the wire bytes claimed.
        declared: u64,
        /// Maximum length the caller configured.
        max: u64,
    },
    /// A discriminant byte did not match any known enum/message variant.
    #[error("unknown discriminant for '{field}': {value}")]
    UnknownDiscriminant {
        /// Name of the field being decoded, for diagnostics.
        field: &'static str,
        /// The unrecognized value.
        value: u64,
    },
    /// A string field was not valid UTF-8.
    #[error("field '{0}' is not valid UTF-8")]
    InvalidUtf8(&'static str),
}

/// Bounds-checked little-endian cursor over a decode input buffer.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a> {
    /// Backing bytes being decoded.
    buf: &'a [u8],
    /// Read offset into `buf`; always `<= buf.len()`.
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap `buf` for bounds-checked reading, starting at offset 0.
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub(crate) const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Consume and return exactly `len` bytes, or a
    /// [`SnapshotProtocolError::Truncated`] if fewer remain.
    fn take(&mut self, len: usize) -> Result<&'a [u8], SnapshotProtocolError> {
        let available = self.remaining();
        if available < len {
            return Err(SnapshotProtocolError::Truncated {
                needed: len,
                available,
            });
        }
        let start = self.pos;
        let slice = self
            .buf
            .get(start..start + len)
            .ok_or(SnapshotProtocolError::Truncated {
                needed: len,
                available,
            })?;
        self.pos += len;
        Ok(slice)
    }

    /// Read a single byte.
    pub(crate) fn read_u8(&mut self) -> Result<u8, SnapshotProtocolError> {
        let bytes = self.take(1)?;
        bytes
            .first()
            .copied()
            .ok_or(SnapshotProtocolError::Truncated {
                needed: 1,
                available: 0,
            })
    }

    /// Read exactly `N` raw bytes.
    pub(crate) fn read_array<const N: usize>(&mut self) -> Result<[u8; N], SnapshotProtocolError> {
        let bytes = self.take(N)?;
        let mut out = [0_u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Read a little-endian `u32`.
    pub(crate) fn read_u32_le(&mut self) -> Result<u32, SnapshotProtocolError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    /// Read a little-endian `u64`.
    pub(crate) fn read_u64_le(&mut self) -> Result<u64, SnapshotProtocolError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    /// Read a little-endian `i64`.
    pub(crate) fn read_i64_le(&mut self) -> Result<i64, SnapshotProtocolError> {
        Ok(self.read_u64_le()?.cast_signed())
    }

    /// Read a little-endian `i32`.
    pub(crate) fn read_i32_le(&mut self) -> Result<i32, SnapshotProtocolError> {
        Ok(self.read_u32_le()?.cast_signed())
    }

    /// Read a presence-byte-prefixed optional `i32`: `0` means absent,
    /// `1` means present followed by a little-endian `i32`.
    pub(crate) fn read_optional_i32(&mut self) -> Result<Option<i32>, SnapshotProtocolError> {
        if self.read_u8()? == 0 {
            Ok(None)
        } else {
            Ok(Some(self.read_i32_le()?))
        }
    }

    /// Read a `u32`-length-prefixed byte string, rejecting (before any
    /// allocation) a declared length exceeding `max_len` or the bytes
    /// actually remaining.
    pub(crate) fn read_bytes_u32_prefixed(
        &mut self,
        field: &'static str,
        max_len: u32,
    ) -> Result<Vec<u8>, SnapshotProtocolError> {
        let len = self.read_u32_le()?;
        if len > max_len {
            return Err(SnapshotProtocolError::LengthOutOfBounds {
                field,
                declared: u64::from(len),
                max: u64::from(max_len),
            });
        }
        let bytes = self.take(len as usize)?;
        Ok(bytes.to_vec())
    }

    /// Read a `u16`-length-prefixed UTF-8 string.
    pub(crate) fn read_string_u16_prefixed(
        &mut self,
        field: &'static str,
        max_len: u16,
    ) -> Result<String, SnapshotProtocolError> {
        let len = u16::from_le_bytes(self.read_array()?);
        if len > max_len {
            return Err(SnapshotProtocolError::LengthOutOfBounds {
                field,
                declared: u64::from(len),
                max: u64::from(max_len),
            });
        }
        let bytes = self.take(len as usize)?;
        String::from_utf8(bytes.to_vec()).map_err(|_err| SnapshotProtocolError::InvalidUtf8(field))
    }
}

/// Append a little-endian `u16` to `out`.
pub(crate) fn write_u16_le(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append a little-endian `u32` to `out`.
pub(crate) fn write_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append a little-endian `u64` to `out`.
pub(crate) fn write_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append a little-endian `i64` to `out`.
pub(crate) fn write_i64_le(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.cast_unsigned().to_le_bytes());
}

/// Append a little-endian `i32` to `out`.
pub(crate) fn write_i32_le(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.cast_unsigned().to_le_bytes());
}

/// Append a presence-byte-prefixed optional `i32` to `out`: `0` for
/// `None`, or `1` followed by the little-endian `i32` for `Some`.
pub(crate) fn write_optional_i32(out: &mut Vec<u8>, value: Option<i32>) {
    match value {
        None => out.push(0),
        Some(present) => {
            out.push(1);
            write_i32_le(out, present);
        }
    }
}

/// Append a `u32`-length-prefixed byte string to `out`.
pub(crate) fn write_bytes_u32_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "encode-side only; callers keep byte strings within u32::MAX. \
                  The decode side enforces the real, non-panicking rejection."
    )]
    let len = bytes.len() as u32;
    write_u32_le(out, len);
    out.extend_from_slice(bytes);
}

/// Append a `u16`-length-prefixed UTF-8 string to `out`.
pub(crate) fn write_string_u16_prefixed(out: &mut Vec<u8>, value: &str) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "encode-side only; see write_bytes_u32_prefixed."
    )]
    let len = value.len() as u16;
    write_u16_le(out, len);
    out.extend_from_slice(value.as_bytes());
}
