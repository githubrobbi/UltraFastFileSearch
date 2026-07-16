// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Lossless Windows path representation (design-doc §5.4).
//!
//! "The authoritative Windows path representation MUST be lossless. The
//! manifest stores either UTF-16LE path code units; or another explicitly
//! lossless Windows path encoding such as WTF-8. A lossy UTF-8 display
//! path MAY also be included for logs and UI, but it MUST NOT be the sole
//! identity or unique key."
//!
//! This module models the authoritative form as raw UTF-16LE code units
//! (`Vec<u16>`), because that is exactly what `GetFileInformationByHandleEx`
//! / NTFS directory entries hand back — no intermediate lossy conversion
//! ever has to happen on the producer side. A Windows path can contain
//! unpaired surrogate code units (rare, but real — some tools and legacy
//! software create them); those are the values a `String`-based
//! representation cannot hold at all, which is exactly why the wire
//! format uses raw code units instead of `String`/`OsString`.

use crate::codec::Reader;

/// The path-encoding discriminant carried on the wire (design-doc §11.2
/// `path_encoding` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PathEncoding {
    /// Raw UTF-16LE code units, exactly as returned by the Windows API.
    /// May contain unpaired surrogates.
    Utf16Le = 0,
}

impl PathEncoding {
    /// Serialize to the single-byte wire representation.
    #[must_use]
    pub const fn encode(self) -> u8 {
        self as u8
    }

    /// Parse the single-byte wire representation.
    ///
    /// # Errors
    ///
    /// Returns `Err` with the offending byte if it does not match a known
    /// encoding.
    pub const fn decode(byte: u8) -> Result<Self, u8> {
        match byte {
            0 => Ok(Self::Utf16Le),
            other => Err(other),
        }
    }
}

/// A lossless Windows path: raw UTF-16LE code units plus a cached lossy
/// UTF-8 display form.
///
/// The lossy `display` string exists only for logs/UI (design-doc §5.4)
/// and MUST NOT be used as an identity key — every comparison and every
/// wire round-trip in this crate operates on `code_units`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsPath {
    /// Authoritative, lossless UTF-16LE code units.
    code_units: Vec<u16>,
}

/// Maximum path length in UTF-16 code units this crate will decode.
///
/// Windows itself has historically allowed paths well beyond `MAX_PATH`
/// (260) via the `\\?\` prefix and long-path opt-in; this is a generous
/// wire-safety bound, not a Windows API limit.
pub const MAX_PATH_CODE_UNITS: u16 = 32_767;

impl WindowsPath {
    /// Build a [`WindowsPath`] from raw UTF-16 code units (e.g. as
    /// returned by a Windows API call). No validation is performed here
    /// beyond what the type system already guarantees — unpaired
    /// surrogates are accepted, matching real-world Windows path data.
    #[must_use]
    pub const fn from_code_units(code_units: Vec<u16>) -> Self {
        Self { code_units }
    }

    /// Build a [`WindowsPath`] from a Rust `&str`. Since `str` is
    /// guaranteed valid UTF-8 (and therefore representable in UTF-16
    /// without unpaired surrogates), this conversion is always lossless.
    #[must_use]
    pub fn from_str_lossless(value: &str) -> Self {
        Self {
            code_units: value.encode_utf16().collect(),
        }
    }

    /// The raw UTF-16LE code units.
    #[must_use]
    pub fn code_units(&self) -> &[u16] {
        &self.code_units
    }

    /// A lossy UTF-8 display form, for logs/UI only. Unpaired surrogates
    /// are replaced with U+FFFD, per [`String::from_utf16_lossy`]-equivalent
    /// semantics (implemented via [`char::decode_utf16`] directly so the
    /// replacement policy is explicit and testable here rather than
    /// inherited implicitly from a std helper).
    #[must_use]
    pub fn display_lossy(&self) -> String {
        char::decode_utf16(self.code_units.iter().copied())
            .map(|result| result.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    }

    /// Encode as a wire `(path_encoding: u8, path_length: u32, path: bytes)`
    /// triple (design-doc §11.2). The length prefix counts *bytes*, not
    /// code units — two bytes per UTF-16 code unit.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(PathEncoding::Utf16Le.encode());
        let mut byte_buf = Vec::with_capacity(self.code_units.len() * 2);
        for unit in &self.code_units {
            byte_buf.extend_from_slice(&unit.to_le_bytes());
        }
        // `write_bytes_u32_prefixed` is the §11.2 layout (u32 path_length);
        // reused here via the u16-style helper's u32 sibling would be
        // clearer, but §11.2 explicitly specifies `path_length u32` — use
        // that variant directly.
        crate::codec::write_bytes_u32_prefixed(out, &byte_buf);
    }

    /// Decode from a `(path_encoding, path_length, path)` wire triple.
    ///
    /// `max_bytes` bounds the length-prefixed path payload before any
    /// allocation (Finding H10 discipline, same as every other
    /// length-prefixed field in this crate).
    ///
    /// # Errors
    ///
    /// - a [`crate::codec::DecodeError`] if the bytes are truncated or the
    ///   declared length exceeds `max_bytes`;
    /// - `Err` wrapping the raw byte if `path_encoding` is not a known
    ///   [`PathEncoding`] variant (surfaced as
    ///   [`crate::codec::DecodeError::UnknownDiscriminant`]);
    /// - `Err` if the payload's byte length is odd (not a whole number of
    ///   UTF-16 code units).
    pub fn decode(reader: &mut Reader<'_>, max_bytes: u32) -> Result<Self, PathDecodeError> {
        let encoding_byte = reader.read_u8()?;
        PathEncoding::decode(encoding_byte).map_err(PathDecodeError::UnsupportedEncoding)?;
        let bytes = reader.read_bytes_u32_prefixed("path", max_bytes)?;
        if bytes.len() % 2 != 0 {
            return Err(PathDecodeError::OddByteLength(bytes.len()));
        }
        #[expect(
            clippy::chunks_exact_to_as_chunks,
            reason = "slice::as_chunks is nightly-unstable library API; adopting it would \
                      require an unstable #![feature(...)] crate-root gate for one call site. \
                      chunks_exact(2) is already panic-free here (see the try_into fallback \
                      below), so there is no correctness reason to take on that commitment."
        )]
        let pairs = bytes.chunks_exact(2);
        let code_units: Vec<u16> = pairs
            .map(|pair| {
                // `chunks_exact(2)` guarantees `pair.len() == 2`; `try_into`
                // therefore never hits the fallback, but expressing it this
                // way (instead of indexing) keeps this closure panic-free
                // by construction rather than "panic-free because
                // chunks_exact happens to guarantee it."
                let array: [u8; 2] = pair.try_into().unwrap_or([0, 0]);
                u16::from_le_bytes(array)
            })
            .collect();
        Ok(Self { code_units })
    }
}

/// Errors decoding a [`WindowsPath`] from the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PathDecodeError {
    /// Underlying bounds/length-prefix decode failure.
    #[error(transparent)]
    Decode(#[from] crate::codec::DecodeError),
    /// The `path_encoding` byte did not match a known [`PathEncoding`] variant.
    #[error("unsupported path encoding byte: {0}")]
    UnsupportedEncoding(u8),
    /// The path payload's byte length was odd (not a whole number of
    /// UTF-16 code units).
    #[error("path payload has odd byte length {0}, not a whole number of UTF-16 code units")]
    OddByteLength(usize),
}

#[cfg(test)]
mod tests {
    use super::{PathDecodeError, PathEncoding, WindowsPath};
    use crate::codec::Reader;

    #[test]
    fn ascii_path_round_trips() {
        let path = WindowsPath::from_str_lossless(r"C:\Users\robert\file.txt");
        let mut buf = Vec::new();
        path.encode(&mut buf);
        let mut reader = Reader::new(&buf);
        let decoded = WindowsPath::decode(&mut reader, 10_000).unwrap();
        assert_eq!(decoded, path);
        assert_eq!(decoded.display_lossy(), r"C:\Users\robert\file.txt");
    }

    #[test]
    fn non_bmp_path_round_trips() {
        // U+1F600 (😀) requires a UTF-16 surrogate pair — this is exactly
        // the class of path the enterprise-review commit history flagged
        // as a past UTF-16 anti-pattern bug source.
        let path = WindowsPath::from_str_lossless("C:\\notes\\😀.txt");
        let mut buf = Vec::new();
        path.encode(&mut buf);
        let mut reader = Reader::new(&buf);
        let decoded = WindowsPath::decode(&mut reader, 10_000).unwrap();
        assert_eq!(decoded, path);
        assert_eq!(decoded.display_lossy(), "C:\\notes\\😀.txt");
    }

    #[test]
    fn unpaired_surrogate_round_trips_losslessly_but_displays_as_replacement_char() {
        // 0xD800 is a lone high surrogate — not representable in `str` at
        // all, which is exactly why the authoritative form is `Vec<u16>`
        // and not `String`. It must still round-trip byte-for-byte.
        let path = WindowsPath::from_code_units(vec![
            u16::from(b'C'),
            u16::from(b':'),
            u16::from(b'\\'),
            0xD800,
            u16::from(b'x'),
        ]);
        let mut buf = Vec::new();
        path.encode(&mut buf);
        let mut reader = Reader::new(&buf);
        let decoded = WindowsPath::decode(&mut reader, 10_000).unwrap();
        assert_eq!(
            decoded, path,
            "lone surrogate must survive the wire round-trip exactly"
        );
        assert!(
            decoded.display_lossy().contains('\u{FFFD}'),
            "lossy display must substitute the replacement character for the unpaired surrogate"
        );
    }

    #[test]
    fn empty_path_round_trips() {
        let path = WindowsPath::from_code_units(vec![]);
        let mut buf = Vec::new();
        path.encode(&mut buf);
        let mut reader = Reader::new(&buf);
        let decoded = WindowsPath::decode(&mut reader, 10_000).unwrap();
        assert_eq!(decoded.code_units(), &[] as &[u16]);
    }

    #[test]
    fn decode_rejects_declared_length_over_max_bytes() {
        let path = WindowsPath::from_str_lossless(r"C:\a\long\enough\path.txt");
        let mut buf = Vec::new();
        path.encode(&mut buf);
        let mut reader = Reader::new(&buf);
        let err = WindowsPath::decode(&mut reader, 4).unwrap_err();
        assert!(matches!(err, PathDecodeError::Decode(_)));
    }

    #[test]
    fn decode_rejects_odd_byte_length_payload() {
        // Hand-craft a wire triple with an odd-length payload: encoding
        // byte, then a u32 length of 3, then 3 raw bytes.
        let mut buf = Vec::new();
        buf.push(PathEncoding::Utf16Le.encode());
        crate::codec::write_bytes_u32_prefixed(&mut buf, &[1, 2, 3]);
        let mut reader = Reader::new(&buf);
        let err = WindowsPath::decode(&mut reader, 10_000).unwrap_err();
        assert_eq!(err, PathDecodeError::OddByteLength(3));
    }

    #[test]
    fn decode_rejects_unknown_encoding_byte() {
        let mut buf = Vec::new();
        buf.push(0xFF); // not a known PathEncoding discriminant
        crate::codec::write_bytes_u32_prefixed(&mut buf, b"");
        let mut reader = Reader::new(&buf);
        let err = WindowsPath::decode(&mut reader, 10_000).unwrap_err();
        assert_eq!(err, PathDecodeError::UnsupportedEncoding(0xFF));
    }

    #[test]
    fn path_encoding_round_trips() {
        assert_eq!(PathEncoding::decode(0).unwrap(), PathEncoding::Utf16Le);
        assert_eq!(PathEncoding::decode(1), Err(1));
    }
}
