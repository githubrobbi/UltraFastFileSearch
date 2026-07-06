// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Minimal `ustar` (tar) archive writer and byte splitter for capture bundles.
//!
//! No third-party archive dependency: a capture bundle is packed as a plain
//! `ustar` archive (readable by any `tar`), which the caller compresses with
//! the existing `zstd` dependency into a `.tar.zst` and optionally splits into
//! fixed-size parts for transfer. Pure and cross-platform, so it is unit-tested
//! on the build host and the offline (macOS/Linux) side can reason about it
//! too.

use crate::error::{MftError, Result};
use crate::usize_to_u64;

/// tar block size in bytes.
const BLOCK: usize = 512;

/// Maximum file name length in the `ustar` name field.
const NAME_MAX: usize = 100;

/// Offset of the 8-byte checksum field within a `ustar` header.
const CHKSUM_OFFSET: usize = 148;

/// Push `content` into `buf`, truncated or zero-padded to exactly `width`
/// bytes.
fn push_field(buf: &mut Vec<u8>, content: &[u8], width: usize) {
    let take = content.len().min(width);
    if let Some(slice) = content.get(..take) {
        buf.extend_from_slice(slice);
    }
    buf.resize(buf.len() + (width - take), 0);
}

/// Append one regular-file entry (`name` → `data`, modified at `mtime` Unix
/// seconds) to a `ustar` archive `buf`.
///
/// A real `mtime` is stored so extraction restores it: the offline parity flow
/// derives its timezone from the baseline file's mtime, which a zeroed mtime
/// would break.
///
/// # Errors
///
/// Returns [`MftError::InvalidData`] if `name` exceeds the 100-byte `ustar`
/// name field.
pub fn push_entry(buf: &mut Vec<u8>, name: &str, data: &[u8], mtime: u64) -> Result<()> {
    if name.len() > NAME_MAX {
        return Err(MftError::InvalidData(format!(
            "tar entry name too long ({} > {NAME_MAX}): {name}",
            name.len()
        )));
    }
    let header_start = buf.len();
    push_field(buf, name.as_bytes(), NAME_MAX); // name
    push_field(buf, b"0000644\0", 8); // mode
    push_field(buf, b"0000000\0", 8); // uid
    push_field(buf, b"0000000\0", 8); // gid
    push_field(
        buf,
        format!("{:011o}\0", usize_to_u64(data.len())).as_bytes(),
        12,
    ); // size
    push_field(buf, format!("{mtime:011o}\0").as_bytes(), 12); // mtime
    push_field(buf, b"        ", 8); // chksum placeholder (spaces)
    push_field(buf, b"0", 1); // typeflag: regular file
    push_field(buf, b"", NAME_MAX); // linkname
    push_field(buf, b"ustar\0", 6); // magic
    push_field(buf, b"00", 2); // version
    push_field(buf, b"", 32); // uname
    push_field(buf, b"", 32); // gname
    push_field(buf, b"", 8); // devmajor
    push_field(buf, b"", 8); // devminor
    push_field(buf, b"", 155); // prefix
    push_field(buf, b"", 12); // pad to 512

    // Header checksum: sum of all header bytes with the checksum field as
    // spaces (the placeholder above), written back as 6 octal digits + NUL + ' '.
    let sum: u32 = buf
        .get(header_start..header_start + BLOCK)
        .map_or(0, |header| header.iter().map(|&byte| u32::from(byte)).sum());
    if let Some(field) = buf.get_mut(header_start + CHKSUM_OFFSET..header_start + CHKSUM_OFFSET + 8)
    {
        for (slot, byte) in field.iter_mut().zip(format!("{sum:06o}\0 ").bytes()) {
            *slot = byte;
        }
    }

    // File data, zero-padded up to a block boundary.
    buf.extend_from_slice(data);
    let rem = data.len() % BLOCK;
    if rem != 0 {
        buf.resize(buf.len() + (BLOCK - rem), 0);
    }
    Ok(())
}

/// Append the two zero blocks that mark end-of-archive.
pub fn finish(buf: &mut Vec<u8>) {
    buf.resize(buf.len() + BLOCK * 2, 0);
}

/// Split `data` into consecutive parts of at most `part_size` bytes (the last
/// part may be smaller). A `part_size` of `0` returns the data as one part.
#[must_use]
pub fn split(data: &[u8], part_size: usize) -> Vec<&[u8]> {
    if part_size == 0 || data.is_empty() {
        return vec![data];
    }
    data.chunks(part_size).collect()
}

#[cfg(test)]
mod tests {
    use super::{BLOCK, CHKSUM_OFFSET, finish, push_entry, split};

    #[test]
    #[expect(
        clippy::indexing_slicing,
        reason = "test inspects fixed ustar header offsets known to be in bounds"
    )]
    fn push_entry_writes_valid_ustar_header() {
        let mut buf = Vec::new();
        push_entry(&mut buf, "c_boot.bin", b"hello", 0o1234).expect("valid name");
        finish(&mut buf);

        // name, magic, size (octal of 5), mtime (octal), and data land at their
        // ustar offsets.
        assert_eq!(&buf[0..10], b"c_boot.bin");
        assert_eq!(&buf[257..263], b"ustar\0");
        assert_eq!(&buf[124..135], b"00000000005");
        assert_eq!(&buf[136..147], b"00000001234");
        assert_eq!(&buf[512..517], b"hello");

        // 512 header + 512 data block + 2×512 end blocks.
        assert_eq!(buf.len(), BLOCK + BLOCK + BLOCK * 2);

        // The stored checksum equals the header sum computed with the checksum
        // field read as spaces.
        let stored = u32::from_str_radix(
            core::str::from_utf8(&buf[CHKSUM_OFFSET..CHKSUM_OFFSET + 6])
                .expect("ascii")
                .trim(),
            8,
        )
        .expect("octal checksum");
        let mut header = buf[0..BLOCK].to_vec();
        for byte in &mut header[CHKSUM_OFFSET..CHKSUM_OFFSET + 8] {
            *byte = b' ';
        }
        let recomputed: u32 = header.iter().map(|&byte| u32::from(byte)).sum();
        assert_eq!(stored, recomputed);
    }

    #[test]
    fn push_entry_rejects_overlong_name() {
        let mut buf = Vec::new();
        push_entry(&mut buf, &"a".repeat(101), b"x", 0).unwrap_err();
    }

    #[test]
    fn split_chunks_data() {
        let data = [1_u8, 2, 3, 4, 5];
        let parts = split(&data, 2);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts.first().copied(), Some(&[1, 2][..]));
        assert_eq!(parts.get(2).copied(), Some(&[5][..]));

        // Zero part size → one part covering all the data.
        assert_eq!(split(&data, 0), vec![&data[..]]);
    }
}
