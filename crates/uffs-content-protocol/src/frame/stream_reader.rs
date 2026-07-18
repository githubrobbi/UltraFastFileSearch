// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Incremental, transport-agnostic frame assembly.
//!
//! [`FrameEnvelope::decode`] needs a whole frame's bytes (header, both
//! checksums, and the full payload) already in one contiguous buffer —
//! exactly what a consumer reading off a named pipe or socket does *not*
//! have up front: reads return whatever bytes happen to be available,
//! which may split a frame across two reads or bundle several frames
//! into one. [`FrameStreamReader`] closes that gap: feed it bytes as
//! they arrive, in whatever chunks your I/O layer produces, and pull out
//! complete decoded frames as they become available.
//!
//! This crate does no I/O itself (see this crate's `Cargo.toml` header
//! comment) — [`FrameStreamReader`] doesn't change that. The caller
//! still owns the actual `read()` calls (blocking, async, anything);
//! this only assembles the bytes those reads produce into frames.

use super::{ENVELOPE_HEADER_LEN, FrameEnvelope, FrameError};
use crate::codec::Reader;

/// Bytes needed before `payload_length` can even be read: `magic`(4) +
/// `protocol_version`(2) + `frame_type`(2) + `flags`(4) +
/// `header_length`(4) + `payload_length`(8) = 24 — the same leading
/// field order [`FrameEnvelope::decode`] itself reads.
const PAYLOAD_LENGTH_PREFIX_LEN: usize = 24;

/// Bytes needed before a full frame can be decoded: the fixed header
/// ([`ENVELOPE_HEADER_LEN`]) plus `header_checksum`(4) plus
/// `payload_checksum`(4) — everything preceding the payload itself.
const FIXED_PREFIX_LEN: usize = ENVELOPE_HEADER_LEN + 8;

/// Incrementally assembles [`FrameEnvelope`]s from bytes fed in as they
/// arrive off a stream.
///
/// # Example
///
/// ```
/// use uffs_content_protocol::frame::FrameStreamReader;
///
/// let mut assembler = FrameStreamReader::new(1_000_000);
/// // however your I/O layer hands you bytes:
/// // assembler.feed(&bytes_just_read);
/// while let Some((_envelope, _payload)) = assembler.try_next().unwrap() {
///     // handle one fully-decoded frame
/// }
/// // `Ok(None)` means: not enough bytes yet, read more and feed again.
/// ```
#[derive(Debug)]
pub struct FrameStreamReader {
    /// Bytes fed so far that have not yet formed a complete frame.
    buffer: Vec<u8>,
    /// Forwarded to [`FrameEnvelope::decode`] for every frame, and
    /// checked against a peeked `payload_length` before buffering that
    /// many bytes — so a corrupt or hostile length claim is rejected
    /// immediately rather than after accumulating unbounded payload
    /// bytes waiting for the rest of a frame that will never decode.
    max_payload_bytes: u64,
}

impl FrameStreamReader {
    /// Creates an empty assembler. `max_payload_bytes` bounds any single
    /// frame's payload — see [`FrameEnvelope::decode`]'s own parameter of
    /// the same name.
    #[must_use]
    pub const fn new(max_payload_bytes: u64) -> Self {
        Self {
            buffer: Vec::new(),
            max_payload_bytes,
        }
    }

    /// Appends newly-received bytes (e.g. the result of one `read()`
    /// call) to the internal buffer.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Attempts to decode and consume the next complete frame from the
    /// buffered bytes.
    ///
    /// Returns `Ok(None)` when there aren't enough buffered bytes yet
    /// for a complete frame — call [`Self::feed`] with more bytes and
    /// try again. Returns `Ok(Some(..))` once a full frame decoded
    /// successfully; its bytes are removed from the internal buffer, so
    /// calling this again immediately may return a second already-fully-
    /// buffered frame without an intervening `feed`.
    ///
    /// # Errors
    /// Returns [`FrameError`] if the buffered bytes form a malformed
    /// frame (bad magic, a checksum mismatch, an unknown discriminant,
    /// ...) or a `payload_length` exceeding `max_payload_bytes`. Either
    /// way the underlying stream is desynchronized — there is no
    /// well-defined next frame boundary to resume from, so treat this as
    /// fatal for the connection (matching `uffs-content`'s own
    /// command-pipe dispatcher: log and close, don't retry `try_next`).
    pub fn try_next(&mut self) -> Result<Option<(FrameEnvelope, Vec<u8>)>, FrameError> {
        let Some(payload_length) = peek_payload_length(&self.buffer) else {
            return Ok(None);
        };
        if payload_length > self.max_payload_bytes {
            return Err(FrameError::PayloadTooLarge {
                declared: payload_length,
                max: self.max_payload_bytes,
            });
        }
        let payload_len_usize = usize::try_from(payload_length).unwrap_or(usize::MAX);
        let Some(total_len) = FIXED_PREFIX_LEN.checked_add(payload_len_usize) else {
            return Err(FrameError::PayloadTooLarge {
                declared: payload_length,
                max: self.max_payload_bytes,
            });
        };
        if self.buffer.len() < total_len {
            return Ok(None);
        }

        let frame_bytes: Vec<u8> = self.buffer.drain(0..total_len).collect();
        let mut reader = Reader::new(&frame_bytes);
        let (envelope, payload) = FrameEnvelope::decode(&mut reader, self.max_payload_bytes)?;
        Ok(Some((envelope, payload)))
    }
}

/// Peeks `payload_length` out of `buffer` without consuming anything,
/// reading the exact same leading field sequence
/// [`FrameEnvelope::decode`] does. Returns `None` if `buffer` doesn't
/// yet hold [`PAYLOAD_LENGTH_PREFIX_LEN`] bytes.
fn peek_payload_length(buffer: &[u8]) -> Option<u64> {
    if buffer.len() < PAYLOAD_LENGTH_PREFIX_LEN {
        return None;
    }
    let mut reader = Reader::new(buffer);
    let _magic: [u8; 4] = reader.read_array().ok()?;
    let _protocol_version = reader.read_u16_le().ok()?;
    let _frame_type_raw = reader.read_u16_le().ok()?;
    let _flags = reader.read_u32_le().ok()?;
    let _header_length = reader.read_u32_le().ok()?;
    reader.read_u64_le().ok()
}

#[cfg(test)]
mod tests {
    use super::FrameStreamReader;
    use crate::frame::{FrameEnvelope, FrameType, PROTOCOL_VERSION};

    fn sample_frame_bytes(frame_sequence: u64, payload: &[u8]) -> Vec<u8> {
        FrameEnvelope {
            protocol_version: PROTOCOL_VERSION,
            frame_type: FrameType::Heartbeat,
            flags: 0,
            job_id: [9_u8; 16],
            frame_sequence,
        }
        .encode(payload)
    }

    #[test]
    fn returns_none_until_enough_bytes_are_fed() {
        let full = sample_frame_bytes(1, b"hello");
        let mut assembler = FrameStreamReader::new(1_000_000);

        // Feed one byte at a time; only the very last byte should
        // complete the frame.
        for (index, byte) in full.iter().enumerate() {
            assembler.feed(core::slice::from_ref(byte));
            let result = assembler.try_next().expect("no decode error expected");
            if index + 1 < full.len() {
                assert!(result.is_none(), "must not decode before all bytes arrive");
            } else {
                let (envelope, payload) = result.expect("frame must be ready on the last byte");
                assert_eq!(envelope.frame_sequence, 1);
                assert_eq!(payload, b"hello");
            }
        }
    }

    #[test]
    fn assembles_two_frames_delivered_in_one_chunk() {
        let mut all_bytes = sample_frame_bytes(1, b"first");
        all_bytes.extend(sample_frame_bytes(2, b"second"));

        let mut assembler = FrameStreamReader::new(1_000_000);
        assembler.feed(&all_bytes);

        let (first_envelope, first_payload) = assembler
            .try_next()
            .expect("no decode error expected")
            .expect("first frame must be ready");
        assert_eq!(first_envelope.frame_sequence, 1);
        assert_eq!(first_payload, b"first");

        let (second_envelope, second_payload) = assembler
            .try_next()
            .expect("no decode error expected")
            .expect("second frame must be ready without an extra feed");
        assert_eq!(second_envelope.frame_sequence, 2);
        assert_eq!(second_payload, b"second");

        assert!(
            assembler
                .try_next()
                .expect("no decode error expected")
                .is_none(),
            "buffer must be empty after both frames are consumed"
        );
    }

    #[test]
    fn rejects_a_payload_length_over_the_ceiling_without_buffering_it() {
        let big_frame = sample_frame_bytes(1, &[0_u8; 64]);
        // A ceiling smaller than the real payload — the assembler must
        // reject this from the length prefix alone, without needing the
        // full (oversized) payload to ever be fed.
        let mut assembler = FrameStreamReader::new(10);
        assembler.feed(&big_frame);

        let err = assembler
            .try_next()
            .expect_err("payload_length exceeds max_payload_bytes");
        assert!(matches!(err, crate::frame::FrameError::PayloadTooLarge {
            declared: 64,
            max: 10
        }));
    }
}
