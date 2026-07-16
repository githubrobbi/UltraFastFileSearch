// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Minimal bounds-checked little-endian decode primitives.
//!
//! A deliberately small, independent duplicate of
//! `uffs-content-protocol::codec::Reader`'s shape — see this crate's
//! `Cargo.toml` for why the two Layer-0 crates don't share this code via
//! an internal dependency. Only the handful of primitives
//! [`ReadRequest`](crate::ReadRequest)/[`ReadResponse`](crate::ReadResponse)
//! actually need are implemented here.

/// Errors decoding wire bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
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
    /// A discriminant byte did not match any known enum variant.
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
pub struct Reader<'a> {
    /// Backing bytes being decoded.
    buf: &'a [u8],
    /// Read offset into `buf`; always `<= buf.len()`.
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap `buf` for bounds-checked reading, starting at offset 0.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Consume and return exactly `len` bytes, or a
    /// [`DecodeError::Truncated`] if fewer remain.
    fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let available = self.remaining();
        if available < len {
            return Err(DecodeError::Truncated {
                needed: len,
                available,
            });
        }
        let start = self.pos;
        let slice = self
            .buf
            .get(start..start + len)
            .ok_or(DecodeError::Truncated {
                needed: len,
                available,
            })?;
        self.pos += len;
        Ok(slice)
    }

    /// Read a single byte.
    ///
    /// # Errors
    /// [`DecodeError::Truncated`] if no bytes remain.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let bytes = self.take(1)?;
        bytes.first().copied().ok_or(DecodeError::Truncated {
            needed: 1,
            available: 0,
        })
    }

    /// Read exactly `N` raw bytes.
    ///
    /// # Errors
    /// [`DecodeError::Truncated`] if fewer than `N` bytes remain.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let bytes = self.take(N)?;
        let mut out = [0_u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Read a little-endian `u32`.
    ///
    /// # Errors
    /// [`DecodeError::Truncated`] if fewer than 4 bytes remain.
    pub fn read_u32_le(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    /// Read a little-endian `u64`.
    ///
    /// # Errors
    /// [`DecodeError::Truncated`] if fewer than 8 bytes remain.
    pub fn read_u64_le(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    /// Read a `u32`-length-prefixed byte string, rejecting (before any
    /// allocation) a declared length exceeding `max_len` or the bytes
    /// actually remaining.
    ///
    /// # Errors
    ///
    /// - [`DecodeError::LengthOutOfBounds`] if the declared length exceeds
    ///   `max_len`.
    /// - [`DecodeError::Truncated`] if the declared length exceeds the bytes
    ///   remaining.
    pub fn read_bytes_u32_prefixed(
        &mut self,
        field: &'static str,
        max_len: u32,
    ) -> Result<Vec<u8>, DecodeError> {
        let len = self.read_u32_le()?;
        if len > max_len {
            return Err(DecodeError::LengthOutOfBounds {
                field,
                declared: u64::from(len),
                max: u64::from(max_len),
            });
        }
        let bytes = self.take(len as usize)?;
        Ok(bytes.to_vec())
    }

    /// Read a `u16`-length-prefixed UTF-8 string, same bounds discipline
    /// as [`read_bytes_u32_prefixed`](Self::read_bytes_u32_prefixed).
    ///
    /// # Errors
    ///
    /// Same as [`read_bytes_u32_prefixed`](Self::read_bytes_u32_prefixed),
    /// plus [`DecodeError::InvalidUtf8`] if the bytes are not valid UTF-8.
    pub fn read_string_u16_prefixed(
        &mut self,
        field: &'static str,
        max_len: u16,
    ) -> Result<String, DecodeError> {
        let len = self.read_u16_le()?;
        if len > max_len {
            return Err(DecodeError::LengthOutOfBounds {
                field,
                declared: u64::from(len),
                max: u64::from(max_len),
            });
        }
        let bytes = self.take(len as usize)?;
        String::from_utf8(bytes.to_vec()).map_err(|_err| DecodeError::InvalidUtf8(field))
    }

    /// Read a little-endian `u16`.
    ///
    /// # Errors
    /// [`DecodeError::Truncated`] if fewer than 2 bytes remain.
    pub fn read_u16_le(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }
}

/// Append a little-endian `u16` to `out`.
pub fn write_u16_le(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append a little-endian `u32` to `out`.
pub fn write_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append a little-endian `u64` to `out`.
pub fn write_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append a `u32`-length-prefixed byte string to `out`.
pub fn write_bytes_u32_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "encode-side only; callers are expected to keep byte strings \
                  within u32::MAX. The decode side enforces the real, \
                  non-panicking rejection via Reader::read_bytes_u32_prefixed."
    )]
    let len = bytes.len() as u32;
    write_u32_le(out, len);
    out.extend_from_slice(bytes);
}

/// Append a `u16`-length-prefixed UTF-8 string to `out`.
pub fn write_string_u16_prefixed(out: &mut Vec<u8>, value: &str) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "encode-side only; see write_bytes_u32_prefixed."
    )]
    let len = value.len() as u16;
    write_u16_le(out, len);
    out.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::{
        DecodeError, Reader, write_bytes_u32_prefixed, write_string_u16_prefixed, write_u16_le,
        write_u32_le, write_u64_le,
    };

    #[test]
    fn read_u8_truncated_on_empty() {
        let mut reader = Reader::new(&[]);
        assert_eq!(reader.read_u8().unwrap_err(), DecodeError::Truncated {
            needed: 1,
            available: 0
        });
    }

    #[test]
    fn read_u32_le_round_trip() {
        let mut buf = Vec::new();
        write_u32_le(&mut buf, 0x1234_5678);
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_u32_le().unwrap(), 0x1234_5678);
    }

    #[test]
    fn read_u64_le_round_trip() {
        let mut buf = Vec::new();
        write_u64_le(&mut buf, 0x0102_0304_0506_0708);
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_u64_le().unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn read_u16_le_round_trip() {
        let mut buf = Vec::new();
        write_u16_le(&mut buf, 0xABCD);
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_u16_le().unwrap(), 0xABCD);
    }

    #[test]
    fn length_prefixed_bytes_round_trip() {
        let mut buf = Vec::new();
        write_bytes_u32_prefixed(&mut buf, b"hello");
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_bytes_u32_prefixed("f", 100).unwrap(), b"hello");
    }

    #[test]
    fn length_prefixed_bytes_rejects_over_max_before_truncation() {
        let mut buf = Vec::new();
        write_u32_le(&mut buf, 1000);
        let mut reader = Reader::new(&buf);
        let err = reader.read_bytes_u32_prefixed("f", 10).unwrap_err();
        assert_eq!(err, DecodeError::LengthOutOfBounds {
            field: "f",
            declared: 1000,
            max: 10,
        });
    }

    #[test]
    fn string_round_trip() {
        let mut buf = Vec::new();
        write_string_u16_prefixed(&mut buf, "hello world");
        let mut reader = Reader::new(&buf);
        assert_eq!(
            reader.read_string_u16_prefixed("f", 100).unwrap(),
            "hello world"
        );
    }

    #[test]
    fn string_rejects_invalid_utf8() {
        let mut buf = Vec::new();
        write_u16_le(&mut buf, 2);
        buf.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        let mut reader = Reader::new(&buf);
        let err = reader.read_string_u16_prefixed("f", 100).unwrap_err();
        assert_eq!(err, DecodeError::InvalidUtf8("f"));
    }

    #[test]
    fn array_read_exact_width() {
        let mut reader = Reader::new(&[1, 2, 3, 4, 5]);
        let arr: [u8; 3] = reader.read_array().unwrap();
        assert_eq!(arr, [1, 2, 3]);
        assert_eq!(reader.remaining(), 2);
    }
}
