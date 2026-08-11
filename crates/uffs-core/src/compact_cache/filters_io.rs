// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Cache-format v9 byte serdes for the Phase 4 bloom + path-trie
//! sections.
//!
//! Sibling submodule of `compact_cache` because:
//!
//!   - `compact_cache.rs` is already a permanent file-size-policy exception
//!     (994 LOC, ~1.2× the 800 LOC cap); inlining the ~150 LOC of bloom + trie
//!     serdes would inflate the exception unacceptably.
//!   - Bloom + trie serdes is independent of the records / names / trigram body
//!     parsing — the two sections live at the tail of the v9 cache after the v7
//!     ext-names table.
//!
//! ## Byte layout
//!
//! ### Bloom section (16 + `nbits / 8` bytes)
//!
//! | Offset | Field          | Type   |
//! |-------:|----------------|--------|
//! |      0 | `nbits`        | `u64`  |
//! |      8 | `k_hashes`     | `u32`  |
//! |     12 | `words_count`  | `u32`  |
//! |     16 | `words`        | `[u64; words_count]` |
//!
//! `words_count == nbits / 64`.  `k_hashes` is stored as `u32` for
//! 4-byte alignment of the following words array; the value is
//! always `≤ 32` (clamped by `Bloom::with_size_and_k`).
//!
//! ### Trie section (16 + `12·node_count + names_len + 4·(node_count+1) + 4·indices_count` bytes)
//!
//! | Offset                         | Field             | Type             |
//! |-------------------------------:|-------------------|------------------|
//! |                              0 | `node_count`      | `u32`            |
//! |                              4 | `nodes`           | `[TrieNode; nc]` |
//! |                  `4 + 12·nc`   | `names_len`       | `u32`            |
//! |                  `8 + 12·nc`   | `names`           | `[u8; nl]`       |
//! |             `8 + 12·nc + nl`   | `offsets_count`   | `u32`            |
//! |            `12 + 12·nc + nl`   | `offsets`         | `[u32; nc + 1]`  |
//! |  `12 + 12·nc + nl + 4·(nc+1)`  | `indices_count`   | `u32`            |
//! |  `16 + 12·nc + nl + 4·(nc+1)`  | `indices`         | `[u32; ic]`      |
//!
//! `offsets_count` is redundantly stored alongside `node_count`
//! (it's always `node_count + 1`) for forward-compat: a future
//! variable-arity trie could relax this invariant without breaking
//! the byte-stream layout.
//!
//! All multi-byte fields are little-endian.  `TrieNode` is `Pod` +
//! `repr(C)`, so the nodes array is bit-identical to its in-memory
//! layout on every supported platform (Windows / Linux / macOS, all
//! little-endian).
//!
//! ## Validation
//!
//! Every `read_*_section` call returns `Err("…")` on truncation or
//! invariant violation (mismatched lengths, name slices outside
//! `names`, etc.) so the cache-format dispatch can drop a corrupted
//! file without panicking.  No unsafe code; bounds are checked via
//! `data.get(start..end)` plus the
//! `Bloom::from_raw_parts` / `PathTrie::from_raw_parts` helpers
//! that re-validate the structural invariants.

use std::io;

use super::{aligned_vec_from_bytes, read_u32, write_u32};
use crate::bloom::Bloom;
use crate::path_trie::{PathTrie, TrieNode};

/// Number of bytes the bloom-section header occupies (everything
/// before the words array).
const BLOOM_HEADER_BYTES: usize = 16;

/// Write a bloom-section to `writer`.
///
/// # Errors
///
/// Returns the underlying `io::Error` if any write fails.
pub(super) fn write_bloom_section<W: io::Write>(writer: &mut W, bloom: &Bloom) -> io::Result<()> {
    writer.write_all(&bloom.nbits().to_le_bytes())?;
    writer.write_all(&u32::from(bloom.hash_count()).to_le_bytes())?;
    let words = bloom.bits();
    write_u32(writer, words.len())?;
    writer.write_all(bytemuck::cast_slice(words))?;
    Ok(())
}

/// Append a bloom-section to a byte buffer.  Mirrors
/// [`write_bloom_section`] for the [`Vec<u8>`]-backed
/// `serialize_compact` path.
pub(super) fn push_bloom_section(buf: &mut Vec<u8>, bloom: &Bloom) {
    buf.extend_from_slice(&bloom.nbits().to_le_bytes());
    buf.extend_from_slice(&u32::from(bloom.hash_count()).to_le_bytes());
    let words = bloom.bits();
    let words_count: u32 = u32::try_from(words.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&words_count.to_le_bytes());
    buf.extend_from_slice(bytemuck::cast_slice(words));
}

/// Read a bloom-section from `data` starting at `offset`.
///
/// Returns `(bloom, new_offset)` on success.  `new_offset` points
/// at the byte immediately after the section so the caller can
/// continue parsing.
///
/// # Errors
///
/// Returns `Err("…")` on truncation or `Bloom::from_raw_parts`
/// invariant violation.
pub(super) fn read_bloom_section(
    data: &[u8],
    offset: usize,
) -> Result<(Bloom, usize), &'static str> {
    if data.len() < offset + BLOOM_HEADER_BYTES {
        return Err("truncated bloom header");
    }
    // Bounds-check above guarantees the slice is exactly 8 bytes,
    // so the `<[u8; 8]>::try_from` is infallible — but clippy's
    // `map_err_ignore` rejects `|_| ...`.  Pin down the array form
    // up front so the conversion can be expressed without
    // `try_into`.
    let mut nbits_arr = [0_u8; 8];
    nbits_arr.copy_from_slice(data.get(offset..offset + 8).ok_or("bloom nbits OOB")?);
    let nbits = u64::from_le_bytes(nbits_arr);
    let k_hashes_raw = read_u32(data, offset + 8);
    let k_hashes = u8::try_from(k_hashes_raw).map_err(|_err| "bloom k_hashes out of range")?;
    let words_count = read_u32(data, offset + 12) as usize;
    let words_start = offset + BLOOM_HEADER_BYTES;
    let words_end = words_start
        .checked_add(words_count.checked_mul(8).ok_or("bloom words overflow")?)
        .ok_or("bloom words end overflow")?;
    if data.len() < words_end {
        return Err("truncated bloom words");
    }
    let words: Vec<u64> = aligned_vec_from_bytes(
        data.get(words_start..words_end)
            .ok_or("bloom words slice")?,
    );
    let bloom = Bloom::from_raw_parts(nbits, k_hashes, words).ok_or("bloom invariants")?;
    Ok((bloom, words_end))
}

/// Write a path-trie section to `writer`.
///
/// # Errors
///
/// Returns the underlying `io::Error` if any write fails.
pub(super) fn write_trie_section<W: io::Write>(writer: &mut W, trie: &PathTrie) -> io::Result<()> {
    let nodes = trie.nodes();
    let names = trie.names();
    let offsets = trie.child_offsets();
    let indices = trie.child_indices();

    write_u32(writer, nodes.len())?;
    writer.write_all(bytemuck::cast_slice(nodes))?;

    write_u32(writer, names.len())?;
    writer.write_all(names)?;

    write_u32(writer, offsets.len())?;
    writer.write_all(bytemuck::cast_slice(offsets))?;

    write_u32(writer, indices.len())?;
    writer.write_all(bytemuck::cast_slice(indices))?;

    Ok(())
}

/// Append a path-trie section to a byte buffer.  Mirrors
/// [`write_trie_section`] for the [`Vec<u8>`]-backed
/// `serialize_compact` path.
pub(super) fn push_trie_section(buf: &mut Vec<u8>, trie: &PathTrie) {
    let nodes = trie.nodes();
    let names = trie.names();
    let offsets = trie.child_offsets();
    let indices = trie.child_indices();

    buf.extend_from_slice(&u32_le(nodes.len()));
    buf.extend_from_slice(bytemuck::cast_slice(nodes));

    buf.extend_from_slice(&u32_le(names.len()));
    buf.extend_from_slice(names);

    buf.extend_from_slice(&u32_le(offsets.len()));
    buf.extend_from_slice(bytemuck::cast_slice(offsets));

    buf.extend_from_slice(&u32_le(indices.len()));
    buf.extend_from_slice(bytemuck::cast_slice(indices));
}

/// Encode a `usize` as little-endian `u32` bytes (saturating at
/// `u32::MAX`).  Local helper because the parent module's
/// equivalent `push_u32` writes directly into a `Vec<u8>`; the
/// trie section needs the bytes in a fixed-size array so we can
/// interleave them with the Pod casts.
fn u32_le(value: usize) -> [u8; 4] {
    u32::try_from(value).unwrap_or(u32::MAX).to_le_bytes()
}

/// Read a path-trie section from `data` starting at `offset`.
///
/// Returns `(trie, new_offset)` on success.
///
/// # Errors
///
/// Returns `Err("…")` on truncation, invalid `TrieNode` byte slice
/// (not Pod-castable), or `PathTrie::from_raw_parts` invariant
/// violation.
pub(super) fn read_trie_section(
    data: &[u8],
    offset: usize,
) -> Result<(PathTrie, usize), &'static str> {
    let mut cursor = offset;

    if data.len() < cursor + 4 {
        return Err("truncated trie node_count");
    }
    let node_count = read_u32(data, cursor) as usize;
    cursor += 4;

    let nodes_bytes_len = node_count
        .checked_mul(size_of::<TrieNode>())
        .ok_or("trie nodes overflow")?;
    let nodes_end = cursor
        .checked_add(nodes_bytes_len)
        .ok_or("trie nodes end overflow")?;
    if data.len() < nodes_end {
        return Err("truncated trie nodes");
    }
    let nodes: Vec<TrieNode> = if node_count == 0 {
        Vec::new()
    } else {
        aligned_vec_from_bytes(data.get(cursor..nodes_end).ok_or("trie nodes slice")?)
    };
    cursor = nodes_end;

    if data.len() < cursor + 4 {
        return Err("truncated trie names_len");
    }
    let names_len = read_u32(data, cursor) as usize;
    cursor += 4;
    let names_end = cursor
        .checked_add(names_len)
        .ok_or("trie names end overflow")?;
    if data.len() < names_end {
        return Err("truncated trie names");
    }
    let names = data
        .get(cursor..names_end)
        .ok_or("trie names slice")?
        .to_vec();
    cursor = names_end;

    if data.len() < cursor + 4 {
        return Err("truncated trie offsets_count");
    }
    let offsets_count = read_u32(data, cursor) as usize;
    cursor += 4;
    let offsets_bytes_len = offsets_count
        .checked_mul(4)
        .ok_or("trie offsets overflow")?;
    let offsets_end = cursor
        .checked_add(offsets_bytes_len)
        .ok_or("trie offsets end overflow")?;
    if data.len() < offsets_end {
        return Err("truncated trie offsets");
    }
    let offsets: Vec<u32> = if offsets_count == 0 {
        Vec::new()
    } else {
        aligned_vec_from_bytes(data.get(cursor..offsets_end).ok_or("trie offsets slice")?)
    };
    cursor = offsets_end;

    if data.len() < cursor + 4 {
        return Err("truncated trie indices_count");
    }
    let indices_count = read_u32(data, cursor) as usize;
    cursor += 4;
    let indices_bytes_len = indices_count
        .checked_mul(4)
        .ok_or("trie indices overflow")?;
    let indices_end = cursor
        .checked_add(indices_bytes_len)
        .ok_or("trie indices end overflow")?;
    if data.len() < indices_end {
        return Err("truncated trie indices");
    }
    let indices: Vec<u32> = if indices_count == 0 {
        Vec::new()
    } else {
        aligned_vec_from_bytes(data.get(cursor..indices_end).ok_or("trie indices slice")?)
    };
    cursor = indices_end;

    let trie = PathTrie::from_raw_parts(nodes, names, offsets, indices).ok_or("trie invariants")?;
    Ok((trie, cursor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_trie::NO_PARENT;

    /// Round-trip a non-trivial bloom: identical `(nbits, k, bits)`
    /// after one write + read cycle.
    #[test]
    fn bloom_round_trip_preserves_bits() {
        let mut bloom = Bloom::with_capacity_and_fpr(1000, 0.01);
        for input in ["alpha", "beta", "gamma", "delta", "epsilon"] {
            bloom.insert(input.as_bytes());
        }

        let mut buf: Vec<u8> = Vec::new();
        push_bloom_section(&mut buf, &bloom);

        let (decoded, end) = read_bloom_section(&buf, 0).expect("bloom round-trip should succeed");
        assert_eq!(end, buf.len(), "decoder should consume the full section");
        assert_eq!(decoded.nbits(), bloom.nbits());
        assert_eq!(decoded.hash_count(), bloom.hash_count());
        assert_eq!(decoded.bits(), bloom.bits());

        for input in ["alpha", "beta", "gamma", "delta", "epsilon"] {
            assert!(
                decoded.contains(input.as_bytes()),
                "post-decode missing {input:?}"
            );
        }
        // Negative case: a string we didn't insert is unlikely (FPR
        // ≈ 1 %) to land in the bloom.  At this load (5 items) the
        // false-positive rate is effectively zero.
        assert!(!decoded.contains(b"unrelated_keyword_xyz"));
    }

    /// Round-trip a non-trivial path trie: structural equality + a
    /// representative `lookup_path` after decode.
    #[test]
    fn trie_round_trip_preserves_structure() {
        // Reuse the `TrieNode` Pod constructor to build a small
        // trie by hand: root "C" with two children "src" and
        // "tests".
        let nodes = vec![
            TrieNode {
                parent_idx: NO_PARENT,
                name_offset: 0,
                name_len: 1,
                padding: 0,
            },
            TrieNode {
                parent_idx: 0,
                name_offset: 1,
                name_len: 3,
                padding: 0,
            },
            TrieNode {
                parent_idx: 0,
                name_offset: 4,
                name_len: 5,
                padding: 0,
            },
        ];
        let names = b"Csrctests".to_vec();
        // Children CSR: root (idx 0) has children [1, 2]; idx 1 + 2
        // are leaves.
        let offsets = vec![0_u32, 2, 2, 2];
        let indices = vec![1_u32, 2];

        let trie = PathTrie::from_raw_parts(nodes, names, offsets, indices)
            .expect("hand-built trie should pass invariant check");

        let mut buf: Vec<u8> = Vec::new();
        push_trie_section(&mut buf, &trie);

        let (decoded, end) = read_trie_section(&buf, 0).expect("trie round-trip should succeed");
        assert_eq!(end, buf.len(), "decoder should consume the full section");
        assert_eq!(decoded.len(), trie.len());
        assert_eq!(decoded.nodes().len(), trie.nodes().len());
        assert_eq!(decoded.names(), trie.names());
        assert_eq!(decoded.child_offsets(), trie.child_offsets());
        assert_eq!(decoded.child_indices(), trie.child_indices());

        // Behavioural equivalence — `lookup_path` should match.
        assert_eq!(decoded.lookup_path(&[b"C"]), Some(0));
        assert_eq!(decoded.lookup_path(&[b"C", b"src"]), Some(1));
        assert_eq!(decoded.lookup_path(&[b"C", b"tests"]), Some(2));
        assert!(decoded.lookup_path(&[b"C", b"missing"]).is_none());
    }

    /// `read_bloom_section` rejects truncated input rather than
    /// panicking.
    #[test]
    fn read_bloom_section_rejects_truncation() {
        let mut buf: Vec<u8> = Vec::new();
        let bloom = Bloom::with_capacity_and_fpr(100, 0.01);
        push_bloom_section(&mut buf, &bloom);

        // Lop off the last byte of the words array.
        let trunc_len = buf.len().saturating_sub(1);
        let truncated = buf.get(..trunc_len).expect("non-empty buffer");
        let result = read_bloom_section(truncated, 0);
        assert!(result.is_err(), "truncated bloom must be rejected");
    }

    /// `read_trie_section` rejects truncated input rather than
    /// panicking.
    #[test]
    fn read_trie_section_rejects_truncation() {
        let trie = PathTrie::from_raw_parts(
            vec![TrieNode {
                parent_idx: NO_PARENT,
                name_offset: 0,
                name_len: 1,
                padding: 0,
            }],
            b"R".to_vec(),
            vec![0, 0],
            vec![],
        )
        .expect("single-root trie");

        let mut buf: Vec<u8> = Vec::new();
        push_trie_section(&mut buf, &trie);

        // Truncate to half the buffer — guaranteed to land mid-section.
        let half = buf.len() / 2;
        let truncated = buf.get(..half).expect("buffer at least half-length");
        let result = read_trie_section(truncated, 0);
        assert!(result.is_err(), "truncated trie must be rejected");
    }

    /// Empty bloom (small but non-zero `nbits`, all words zero)
    /// round-trips correctly.  Pins the COLD → PARKED edge case
    /// where a zero-record drive's bloom is all zeros.
    #[test]
    fn empty_bloom_round_trip() {
        let bloom = Bloom::with_capacity_and_fpr(1, 0.01);
        let mut buf: Vec<u8> = Vec::new();
        push_bloom_section(&mut buf, &bloom);

        let (decoded, _) =
            read_bloom_section(&buf, 0).expect("empty-bloom round-trip should succeed");
        assert_eq!(decoded.nbits(), bloom.nbits());
        assert_eq!(decoded.hash_count(), bloom.hash_count());
        assert!(decoded.bits().iter().all(|&w| w == 0));
    }

    /// Empty trie (zero nodes, zero names) round-trips correctly.
    /// Pins the same COLD → PARKED edge case for the trie side.
    #[test]
    fn empty_trie_round_trip() {
        let trie = PathTrie::from_raw_parts(Vec::new(), Vec::new(), vec![0_u32], Vec::new())
            .expect("empty trie should pass invariant check");

        let mut buf: Vec<u8> = Vec::new();
        push_trie_section(&mut buf, &trie);

        let (decoded, end) =
            read_trie_section(&buf, 0).expect("empty-trie round-trip should succeed");
        assert_eq!(end, buf.len());
        assert!(decoded.is_empty());
        assert!(decoded.nodes().is_empty());
        assert_eq!(decoded.names(), Vec::<u8>::new());
        assert_eq!(decoded.child_offsets(), &[0_u32]);
        assert_eq!(decoded.child_indices(), Vec::<u32>::new());
    }
}
