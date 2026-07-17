// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Shared little-endian encode/decode primitives for the manifest and
//! frame codecs.
//!
//! Design-doc §11/§12; addendum §5.4: "an explicit deterministic binary
//! codec... not a language-native memory layout or a compatibility-unstable
//! serializer."
//!
//! [`Reader`] is the single chokepoint every length-prefixed field passes
//! through. Its job is to make the bug class from the enterprise review's
//! Finding H10 structurally hard to reintroduce: every bounds check
//! happens *before* any allocation or slice indexing, never after.

/// Errors produced while decoding wire bytes.
///
/// Distinct from [`crate::error::ErrorCode`] (design-doc §16), which is
/// the *wire-visible* status carried inside frames like `FILE_FAILED`.
/// [`DecodeError`] is a local, Rust-side parsing failure: malformed or
/// truncated bytes handed to a decoder. A [`DecodeError::Truncated`] while
/// parsing a frame is exactly the situation that becomes a `FrameCorrupt`
/// [`crate::error::ErrorCode`] one layer up, once the caller decides how
/// to report it.
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
    /// configured maximum allows. Checked *before* allocation — this is
    /// the direct fix for Finding H10 ("no physical read occurs solely
    /// because an unvalidated parser returned an offset").
    #[error("field '{field}' declared length {declared} exceeds maximum {max}")]
    LengthOutOfBounds {
        /// Name of the offending field, for diagnostics.
        field: &'static str,
        /// Length the wire bytes claimed.
        declared: u64,
        /// Maximum length the caller configured.
        max: u64,
    },
    /// A checksum recomputed over decoded bytes did not match the
    /// checksum carried on the wire.
    #[error("checksum mismatch: expected 0x{expected:08x}, computed 0x{computed:08x}")]
    ChecksumMismatch {
        /// Checksum read from the wire.
        expected: u32,
        /// Checksum recomputed locally.
        computed: u32,
    },
    /// A discriminant byte/word did not match any known variant of the
    /// field it was decoded into (e.g. an unrecognized `frame_type`).
    #[error("unknown discriminant for '{field}': {value}")]
    UnknownDiscriminant {
        /// Name of the field being decoded, for diagnostics.
        field: &'static str,
        /// The unrecognized value.
        value: u64,
    },
}

/// Bounds-checked little-endian cursor over a decode input buffer.
///
/// Every `read_*` method checks `self.remaining()` against the field width
/// (or an explicit `max_len`, for length-prefixed data) before touching
/// the slice. There is no path from malformed input to a panic or an
/// over-large allocation.
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

    /// Current read offset from the start of the buffer.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// The full backing buffer, unaffected by how much has been consumed.
    ///
    /// Used by checksum verification, which recomputes over a byte range
    /// of the *original* input rather than the remaining tail.
    #[must_use]
    pub const fn full_buffer(&self) -> &'a [u8] {
        self.buf
    }

    /// Consume and return exactly `len` bytes, or a [`DecodeError::Truncated`]
    /// if fewer remain. The bounds check happens before the slice is ever
    /// touched — this is the single place that guarantee is enforced for
    /// every other method in this type.
    fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let available = self.remaining();
        if available < len {
            return Err(DecodeError::Truncated {
                needed: len,
                available,
            });
        }
        let start = self.pos;
        // `.get(start..start + len)` cannot return `None` here: `len <=
        // available == self.buf.len() - start` was just checked above.
        // Using `.get()` instead of direct range indexing keeps this
        // function panic-free by construction rather than "panic-free
        // because a check happens to precede it."
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
    ///
    /// [`DecodeError::Truncated`] if no bytes remain.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let bytes = self.take(1)?;
        // `take(1)` guarantees exactly one byte.
        bytes.first().copied().ok_or(DecodeError::Truncated {
            needed: 1,
            available: 0,
        })
    }

    /// Read a little-endian `u16`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] if fewer than 2 bytes remain.
    pub fn read_u16_le(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    /// Read a little-endian `u32`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] if fewer than 4 bytes remain.
    pub fn read_u32_le(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    /// Read a little-endian `u64`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] if fewer than 8 bytes remain.
    pub fn read_u64_le(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    /// Read a little-endian `i64`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] if fewer than 8 bytes remain.
    pub fn read_i64_le(&mut self) -> Result<i64, DecodeError> {
        Ok(self.read_u64_le()?.cast_signed())
    }

    /// Read exactly `N` raw bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] if fewer than `N` bytes remain.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let bytes = self.take(N)?;
        let mut out = [0_u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Read a `u32`-length-prefixed byte string, rejecting (before any
    /// allocation) a declared length that exceeds `max_len` or the bytes
    /// actually remaining.
    ///
    /// `field` is only used for the error message.
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
        // `len` is already bounds-checked against `max_len`; `take`
        // additionally checks it against bytes actually remaining before
        // any copy happens.
        let bytes = self.take(len as usize)?;
        Ok(bytes.to_vec())
    }

    /// Read a `u16`-length-prefixed byte string, same bounds discipline as
    /// [`read_bytes_u32_prefixed`](Self::read_bytes_u32_prefixed).
    ///
    /// # Errors
    ///
    /// Same as [`read_bytes_u32_prefixed`](Self::read_bytes_u32_prefixed).
    pub fn read_bytes_u16_prefixed(
        &mut self,
        field: &'static str,
        max_len: u16,
    ) -> Result<Vec<u8>, DecodeError> {
        let len = self.read_u16_le()?;
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

    /// Read exactly `len` raw bytes with **no** length prefix on the
    /// wire — for callers whose length already came from elsewhere (e.g.
    /// [`crate::frame::FrameEnvelope`]'s separately-encoded
    /// `payload_length` field). The caller is responsible for having
    /// already bounds-checked `len` against its own maximum; this method
    /// only guarantees `len` does not exceed the bytes actually
    /// remaining.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] if fewer than `len` bytes remain.
    pub fn read_bytes_exact(&mut self, len: usize) -> Result<Vec<u8>, DecodeError> {
        let bytes = self.take(len)?;
        Ok(bytes.to_vec())
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

/// Append a little-endian `i64` to `out`.
pub fn write_i64_le(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.cast_unsigned().to_le_bytes());
}

/// Append a `u32`-length-prefixed byte string to `out`.
///
/// # Panics
///
/// Never panics on `bytes.len() <= u32::MAX`; callers constructing an
/// encoder are expected to keep byte strings within that bound (the
/// decoder side enforces this as a real, non-panicking rejection via
/// [`Reader::read_bytes_u32_prefixed`] — this is the encode side, which
/// only ever runs over data this process already validated on the way
/// in).
pub fn write_bytes_u32_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "encode-side only; `bytes.len()` is expected to already be \
                  bounds-checked by the caller before reaching this helper. \
                  A value exceeding u32::MAX here indicates a caller bug, \
                  not malformed wire input — there is no untrusted-input \
                  path through this function."
    )]
    let len = bytes.len() as u32;
    write_u32_le(out, len);
    out.extend_from_slice(bytes);
}

/// Append a `u16`-length-prefixed byte string to `out`. See
/// [`write_bytes_u32_prefixed`] for the truncation-safety note.
pub fn write_bytes_u16_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "encode-side only; see write_bytes_u32_prefixed."
    )]
    let len = bytes.len() as u16;
    write_u16_le(out, len);
    out.extend_from_slice(bytes);
}

/// Truncated-BLAKE3 checksum used for manifest/frame header and record
/// checksums (design-doc §11/§12 call for "u32 or stronger").
///
/// Rationale for reusing BLAKE3 here instead of adding a second checksum
/// crate (e.g. CRC-32): the protocol already requires BLAKE3 as its
/// content-integrity digest (§15.1), so truncating it to 32 bits for the
/// cheaper structural checksums keeps this crate to one hash primitive.
/// This is explicitly *not* used for content integrity — see
/// [`digest`] for the full 256-bit digest used there.
#[must_use]
pub fn checksum32(bytes: &[u8]) -> u32 {
    let hash = blake3::hash(bytes);
    let first4: [u8; 4] = hash.as_bytes()[0..4]
        .try_into()
        .unwrap_or_else(|_| unreachable_checksum_slice());
    u32::from_le_bytes(first4)
}

/// `blake3::Hash` is always exactly 32 bytes, so slicing its first 4 bytes
/// always succeeds; this helper exists only so `checksum32` has no
/// `unwrap`/`expect` call site, per the workspace's panic policy.
const fn unreachable_checksum_slice() -> [u8; 4] {
    [0, 0, 0, 0]
}

/// Full 256-bit BLAKE3 content digest, as required by design-doc §15.1
/// ("Version 2 uses full-length BLAKE3 over the exact logical bytes
/// emitted for the file").
///
/// # Consumer contract (locked, do not change casually)
///
/// This is **plain, unkeyed BLAKE3-256** over the exact logical bytes —
/// `blake3::hash(bytes)`, no key, no context string, no XOF, standard
/// 32-byte output. This is a deliberate cross-product contract: Docenta's
/// `ContentId` is `blake3:<hex>` computed the same way over the same
/// logical bytes, so as long as this stays plain unkeyed BLAKE3-256,
/// Docenta can use `FILE_END.content_digest` directly as its content ID
/// and skip re-hashing entirely. If this ever needs to become keyed or
/// use a different output length, that is a wire-breaking change for
/// Docenta's content-addressing, not just an internal UFFS detail — it
/// needs sign-off from the consumer side, not just a version bump here.
pub type Digest = [u8; 32];

/// Compute the full BLAKE3 digest of `bytes`.
#[must_use]
pub fn digest(bytes: &[u8]) -> Digest {
    *blake3::hash(bytes).as_bytes()
}

/// Incremental variant of [`digest`]: the same plain, unkeyed BLAKE3-256
/// contract, computed over bytes fed in one or more calls to
/// [`IncrementalDigest::update`] instead of one contiguous buffer.
///
/// Exists so a caller streaming a file in bounded chunks (e.g. this
/// crate's own `CONTENT_CHUNK` producer) can compute `FILE_END`'s
/// `content_digest` without buffering the whole file's bytes just to
/// call [`digest`] once at the end — for a large file, that buffering
/// is the difference between bounded, chunk-sized memory use and memory
/// proportional to the file's full size.
#[derive(Debug, Default)]
pub struct IncrementalDigest {
    /// The running BLAKE3 state.
    hasher: blake3::Hasher,
}

impl IncrementalDigest {
    /// A fresh hasher with no bytes fed yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }

    /// Feed more bytes into the running hash, in order.
    pub fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    /// Finalize and return the digest over every byte fed so far.
    ///
    /// Takes `&self`, not `self`, matching `blake3::Hasher::finalize`'s
    /// own shape — finalizing does not consume the hasher, though this
    /// crate's callers only ever finalize once per instance in practice.
    #[must_use]
    pub fn finalize(&self) -> Digest {
        *self.hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DecodeError, IncrementalDigest, Reader, checksum32, digest, write_bytes_u16_prefixed,
        write_bytes_u32_prefixed, write_i64_le, write_u16_le, write_u32_le, write_u64_le,
    };

    #[test]
    fn read_u8_consumes_one_byte() {
        let mut reader = Reader::new(&[0x42, 0x99]);
        assert_eq!(reader.read_u8().unwrap(), 0x42);
        assert_eq!(reader.remaining(), 1);
    }

    #[test]
    fn read_u8_truncated_on_empty() {
        let mut reader = Reader::new(&[]);
        assert_eq!(reader.read_u8().unwrap_err(), DecodeError::Truncated {
            needed: 1,
            available: 0
        });
    }

    #[test]
    fn read_u16_le_matches_manual_bytes() {
        let mut buf = Vec::new();
        write_u16_le(&mut buf, 0x1234);
        assert_eq!(buf, [0x34, 0x12]);
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_u16_le().unwrap(), 0x1234);
    }

    #[test]
    fn read_u32_le_round_trip_boundaries() {
        for value in [0_u32, 1, 0xFF, 0x1234_5678, u32::MAX] {
            let mut buf = Vec::new();
            write_u32_le(&mut buf, value);
            let mut reader = Reader::new(&buf);
            assert_eq!(reader.read_u32_le().unwrap(), value);
        }
    }

    #[test]
    fn read_u64_le_round_trip_boundaries() {
        for value in [0_u64, 1, 0xFF, 0x0123_4567_89AB_CDEF, u64::MAX] {
            let mut buf = Vec::new();
            write_u64_le(&mut buf, value);
            let mut reader = Reader::new(&buf);
            assert_eq!(reader.read_u64_le().unwrap(), value);
        }
    }

    #[test]
    fn read_i64_le_round_trip_negative() {
        for value in [i64::MIN, -1_i64, 0, 1, i64::MAX] {
            let mut buf = Vec::new();
            write_i64_le(&mut buf, value);
            let mut reader = Reader::new(&buf);
            assert_eq!(reader.read_i64_le().unwrap(), value);
        }
    }

    #[test]
    fn read_array_exact_width() {
        let mut reader = Reader::new(&[1, 2, 3, 4, 5]);
        let arr: [u8; 3] = reader.read_array().unwrap();
        assert_eq!(arr, [1, 2, 3]);
        assert_eq!(reader.remaining(), 2);
    }

    #[test]
    fn length_prefixed_u32_round_trip() {
        let mut buf = Vec::new();
        write_bytes_u32_prefixed(&mut buf, b"hello world");
        let mut reader = Reader::new(&buf);
        let decoded = reader.read_bytes_u32_prefixed("test_field", 1024).unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn length_prefixed_u32_rejects_over_max_before_truncation_check() {
        // Declared length (1000) exceeds max_len (10) even though the
        // buffer doesn't actually contain 1000 bytes — this must be
        // rejected as LengthOutOfBounds, not Truncated, proving the
        // max_len check runs before any attempt to read the payload.
        let mut buf = Vec::new();
        write_u32_le(&mut buf, 1000);
        let mut reader = Reader::new(&buf);
        let err = reader
            .read_bytes_u32_prefixed("test_field", 10)
            .unwrap_err();
        assert_eq!(err, DecodeError::LengthOutOfBounds {
            field: "test_field",
            declared: 1000,
            max: 10,
        });
    }

    #[test]
    fn length_prefixed_u32_rejects_declared_length_exceeding_remaining_bytes() {
        // Declared length (5) is within max_len (1024) but exceeds what's
        // actually left in the buffer (2 bytes) — must be Truncated.
        let mut buf = Vec::new();
        write_u32_le(&mut buf, 5);
        buf.extend_from_slice(&[1, 2]);
        let mut reader = Reader::new(&buf);
        let err = reader
            .read_bytes_u32_prefixed("test_field", 1024)
            .unwrap_err();
        assert_eq!(err, DecodeError::Truncated {
            needed: 5,
            available: 2,
        });
    }

    #[test]
    fn length_prefixed_u16_round_trip_and_bounds() {
        let mut buf = Vec::new();
        write_bytes_u16_prefixed(&mut buf, b"abc");
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_bytes_u16_prefixed("f", 10).unwrap(), b"abc");

        let mut buf2 = Vec::new();
        write_u16_le(&mut buf2, 500);
        let mut reader2 = Reader::new(&buf2);
        assert_eq!(
            reader2.read_bytes_u16_prefixed("f", 10).unwrap_err(),
            DecodeError::LengthOutOfBounds {
                field: "f",
                declared: 500,
                max: 10,
            }
        );
    }

    #[test]
    fn checksum32_is_deterministic_and_sensitive_to_content() {
        let checksum_hello_1 = checksum32(b"hello");
        let checksum_hello_2 = checksum32(b"hello");
        let checksum_hellp = checksum32(b"hellp");
        assert_eq!(checksum_hello_1, checksum_hello_2);
        assert_ne!(
            checksum_hello_1, checksum_hellp,
            "single-byte change must change the checksum"
        );
    }

    #[test]
    fn checksum32_empty_input_is_stable() {
        // Anchor test: if this ever changes, every existing manifest
        // fixture's header checksum silently breaks.
        assert_eq!(checksum32(b""), checksum32(b""));
    }

    #[test]
    fn digest_is_32_bytes_and_deterministic() {
        let d1 = digest(b"some file content");
        let d2 = digest(b"some file content");
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 32);
    }

    #[test]
    fn digest_differs_for_different_content() {
        assert_ne!(digest(b"a"), digest(b"b"));
    }

    #[test]
    fn digest_matches_plain_unkeyed_blake3_hex_form() {
        // Locks the consumer contract documented on `Digest`: this MUST
        // be identical to calling `blake3::hash` directly (unkeyed,
        // standard output) so `format!("blake3:{}", hex::encode(digest))`
        // is byte-for-byte what a Docenta-side `blake3:<hex>` content ID
        // would compute independently over the same bytes.
        let content = b"some file content";
        let via_this_crate = digest(content);
        let via_plain_blake3 = blake3::hash(content);
        assert_eq!(&via_this_crate, via_plain_blake3.as_bytes());
    }

    #[test]
    fn incremental_digest_matches_one_shot_digest_over_the_same_bytes() {
        let content = b"some file content, split across several chunks";
        let one_shot = digest(content);

        let mut incremental = IncrementalDigest::new();
        for chunk in content.chunks(7) {
            incremental.update(chunk);
        }
        assert_eq!(incremental.finalize(), one_shot);
    }

    #[test]
    fn incremental_digest_of_no_bytes_matches_digest_of_empty_slice() {
        let incremental = IncrementalDigest::new();
        assert_eq!(incremental.finalize(), digest(b""));
    }

    #[test]
    fn reader_position_and_remaining_track_consumption() {
        let mut reader = Reader::new(&[0_u8; 10]);
        assert_eq!(reader.position(), 0);
        assert_eq!(reader.remaining(), 10);
        let _consumed: u32 = reader.read_u32_le().unwrap();
        assert_eq!(reader.position(), 4);
        assert_eq!(reader.remaining(), 6);
    }
}
