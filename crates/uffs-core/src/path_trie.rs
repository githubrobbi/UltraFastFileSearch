// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Compact directory-only path trie for the Phase 4 PARKED tier.
//!
//! Phase 4's [memory-tiering plan][plan] keeps each shard's bloom +
//! path-trie resident through the PARKED state (~5–15 MB per drive)
//! while the records / names / trigram / children columns stay dropped.
//! The path-trie answers two operator-facing questions cheaply enough
//! to run on a kernel-evicted process:
//!
//!   1. **Resolve a directory by path** — `lookup_path("C", "Users", "Alice",
//!      ...)` walks segment-by-segment and returns the directory's trie-index,
//!      or `None` if any segment is missing.
//!   2. **Enumerate immediate children** — `children_of(idx)` returns the
//!      trie-indices of every directory directly under `idx`.
//!
//! Combined with the bloom filter (`crate::bloom`) this is enough for
//! the daemon to pre-screen "does drive X contain anything matching
//! pattern Y" without waking the body.  A bloom miss + a trie miss
//! together skip the drive entirely.
//!
//! ## Memory layout — Arrow-IPC-style flat arrays
//!
//! - `nodes: Vec<TrieNode>` — one [`TrieNode`] per directory.  Pod + Zeroable
//!   so the whole array serialises as one `memcpy` to the cache file (Phase 4
//!   Commit D).
//! - `names: Vec<u8>` — concatenated UTF-8 directory basenames; each node
//!   carries `(name_offset, name_len)` slicing into this buffer. Independent
//!   from the records' name buffer so the trie remains self-contained when
//!   PARKED drops `DriveCompactIndex::names`.
//! - `child_offsets: Vec<u32>` + `child_indices: Vec<u32>` — CSR children index
//!   parallel to [`crate::compact::ChildrenIndex`]. Children of node `i` are
//!   `child_indices[child_offsets[i]..child_offsets[i+1]]`.
//!
//! For a typical 7 M-record drive with ~50 K directories: nodes ≈ 600
//! KB, names ≈ 5 MB, child CSR ≈ 200 KB ⇒ ~6 MB per drive's trie.  At
//! 7 idle drives that's ~42 MB — under the plan's "≤ 50 MB on a
//! 7-drive idle box" headline target.
//!
//! ## Build cost — single linear pass
//!
//! [`PathTrie::build`] is one O(N) sweep over the records:
//!
//!   1. **Pass 1 — collect directories**: build a sparse map `record_idx →
//!      trie_idx` for every directory record, copy its basename bytes into the
//!      trie's `names`, and emit a `TrieNode` with the parent's record-index
//!      temporarily stored in `parent_idx` (resolved in pass 2).
//!   2. **Pass 2 — translate parents**: walk the freshly-built nodes and
//!      replace each `parent_idx` (currently a record-index) with its
//!      trie-index via the map.  Records whose parent is a file (impossible on
//!      NTFS but defensive) or `u32::MAX` (root) get `parent_idx = u32::MAX`.
//!   3. **Pass 3 — CSR children**: standard count + prefix-sum + scatter,
//!      identical to [`crate::compact::ChildrenIndex::build`].
//!
//! Plan task 4.4 budgets ≤ 100 ms for 1 M records; with a single
//! linear sweep + one [`rustc_hash::FxHashMap`] lookup per record,
//! the cost is dominated by `memcpy` of the name bytes.  Phase 4
//! Commit G measures on `fixture_large` to confirm.
//!
//! [plan]: ../../../../docs/refactor/memory-tiering-implementation-plan.md

use core::mem::size_of;

use rustc_hash::FxHashMap;
use uffs_mft::len_to_u32;

use crate::compact::CompactRecord;

/// Sentinel value used for "no parent" (root node) and for orphan
/// directories whose parent record is missing or non-directory.
///
/// Mirrors the `u32::MAX` convention [`CompactRecord::parent_idx`]
/// already uses on the records side.
pub(crate) const NO_PARENT: u32 = u32::MAX;

/// One node in the [`PathTrie`].
///
/// 12 bytes, 4-byte aligned.  Pod + Zeroable so a `Vec<TrieNode>` can
/// be serialised in one `memcpy` (Phase 4 Commit D's Arrow-IPC-style
/// cache section).
#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct TrieNode {
    /// Trie-index of this node's parent, or `NO_PARENT` for root /
    /// orphan.
    pub parent_idx: u32,
    /// Byte offset into [`PathTrie::names`] where this node's
    /// basename starts.
    pub name_offset: u32,
    /// Length of the basename in UTF-8 bytes.  `u16` matches
    /// [`CompactRecord::name_len`].
    pub name_len: u16,
    /// Padding to reach 4-byte alignment for the next node.  Always
    /// zero; Pod traits rely on the predictable repr.  Reading this
    /// field is meaningless for application logic, but it's part of
    /// the public on-wire layout that the cache-format serialiser
    /// (Phase 4 Commit D) blits via `bytemuck::cast_slice`.
    pub padding: u16,
}

/// Compact directory-only path trie.
///
/// See module-level docs for the memory layout and build algorithm.
#[derive(Debug, Clone)]
pub struct PathTrie {
    /// One node per directory.  The root entries (drive letters /
    /// orphan roots) have `parent_idx == NO_PARENT`.
    nodes: Vec<TrieNode>,
    /// Concatenated basename bytes.  Each `TrieNode` slices into
    /// this via `(name_offset, name_len)`.
    names: Vec<u8>,
    /// CSR offsets for children-of-parent lookup.  Length =
    /// `nodes.len() + 1`.  Children of node `i` are
    /// `child_indices[child_offsets[i]..child_offsets[i+1]]`.
    child_offsets: Vec<u32>,
    /// Flat array of child trie-indices, grouped by parent.
    child_indices: Vec<u32>,
}

impl PathTrie {
    /// Build a path-trie from a slice of [`CompactRecord`]s and the
    /// shared name byte buffer.
    ///
    /// Only directory records are inserted; non-directory records
    /// are skipped entirely.  Records whose parent is `u32::MAX` or
    /// points at a non-directory record become trie roots
    /// (`parent_idx == NO_PARENT`).
    ///
    /// O(N) over `records.len()`; allocates the trie's name buffer
    /// at exactly the size of the directories' name bytes (no
    /// over-allocation).
    #[must_use]
    pub fn build(records: &[CompactRecord], names: &[u8]) -> Self {
        // ── Pass 1 — collect directories ─────────────────────────
        // record_to_trie maps every directory record's index in
        // `records` to its index in the trie's `nodes` array.
        // FxHashMap because the indices are dense u32s and FxHash
        // beats the std hasher 3-5x for integer keys.
        let dir_count_estimate = records.len() / 16;
        let mut record_to_trie: FxHashMap<u32, u32> =
            FxHashMap::with_capacity_and_hasher(dir_count_estimate, rustc_hash::FxBuildHasher);
        let mut nodes: Vec<TrieNode> = Vec::with_capacity(dir_count_estimate);
        let mut trie_names: Vec<u8> = Vec::with_capacity(dir_count_estimate * 16);

        // Every `usize -> u32` conversion below uses the centralized
        // `len_to_u32` helper (which saturates at `u32::MAX`), so the
        // call sites stay free of `cast_possible_truncation` expects.
        // The saturating fallback is unreachable for any realistic NTFS
        // MFT: records.len() and nodes.len() are bounded by the NTFS
        // ~4 G entries-per-volume cap, and trie_names.len() is bounded
        // by the sum of u16 name_len fields across directories.
        for (record_idx_usize, record) in records.iter().enumerate() {
            if !record.is_directory() {
                continue;
            }
            let record_idx = len_to_u32(record_idx_usize);

            // Slice the basename out of the shared name buffer.
            let name_start = record.name_offset as usize;
            let name_end = name_start + record.name_len as usize;
            let basename = names.get(name_start..name_end).unwrap_or(&[]);

            let trie_name_offset = len_to_u32(trie_names.len());
            trie_names.extend_from_slice(basename);

            let trie_idx = len_to_u32(nodes.len());
            record_to_trie.insert(record_idx, trie_idx);

            // Stash the *record-side* parent_idx temporarily; pass 2
            // will rewrite it into a trie-side index.
            nodes.push(TrieNode {
                parent_idx: record.parent_idx,
                name_offset: trie_name_offset,
                name_len: record.name_len,
                padding: 0,
            });
        }

        // ── Pass 2 — translate parents to trie-indices ───────────
        for node in &mut nodes {
            let record_parent = node.parent_idx;
            if record_parent == u32::MAX {
                node.parent_idx = NO_PARENT;
            } else if let Some(&trie_parent) = record_to_trie.get(&record_parent) {
                node.parent_idx = trie_parent;
            } else {
                // Parent isn't a directory (impossible on NTFS) or is
                // missing from the records slice.  Treat as orphan.
                node.parent_idx = NO_PARENT;
            }
        }

        // ── Pass 3 — CSR children index ──────────────────────────
        let (child_offsets, child_indices) = build_children_csr(&nodes);

        Self {
            nodes,
            names: trie_names,
            child_offsets,
            child_indices,
        }
    }

    /// Number of directory nodes in the trie.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.nodes.len()
    }

    /// `true` iff the trie has no directories.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Heap footprint in bytes.
    ///
    /// Sum of `nodes`, `names`, `child_offsets`, `child_indices`
    /// capacities.  Used by Phase 4 memory-budget tests + the
    /// `shard.transition` event's resident-delta accounting.
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        self.nodes.capacity() * size_of::<TrieNode>()
            + self.names.capacity()
            + self.child_offsets.capacity() * size_of::<u32>()
            + self.child_indices.capacity() * size_of::<u32>()
    }

    /// Borrow the basename of trie node `idx`, or `None` if `idx` is
    /// out of range.
    #[must_use]
    pub fn name_of(&self, idx: u32) -> Option<&[u8]> {
        let node = self.nodes.get(idx as usize)?;
        let start = node.name_offset as usize;
        let end = start + node.name_len as usize;
        self.names.get(start..end)
    }

    /// Trie-index of `idx`'s parent, or `None` if `idx` is a root or
    /// out of range.
    #[must_use]
    pub fn parent_of(&self, idx: u32) -> Option<u32> {
        let node = self.nodes.get(idx as usize)?;
        if node.parent_idx == NO_PARENT {
            None
        } else {
            Some(node.parent_idx)
        }
    }

    /// Slice of immediate-child trie-indices of `idx`.
    ///
    /// Returns an empty slice for unknown / leaf-directory `idx`.
    /// O(1) — a single CSR lookup.
    #[must_use]
    pub fn children_of(&self, idx: u32) -> &[u32] {
        let node_idx = idx as usize;
        let Some(&start) = self.child_offsets.get(node_idx) else {
            return &[];
        };
        let Some(&end) = self.child_offsets.get(node_idx + 1) else {
            return &[];
        };
        let start_us = start as usize;
        let end_us = end as usize;
        self.child_indices.get(start_us..end_us).unwrap_or(&[])
    }

    /// Slice of trie-indices of every node that is a root
    /// (`parent_idx == NO_PARENT`).
    ///
    /// On a single-drive trie there is typically exactly one root
    /// (the drive letter); orphan directories whose parent record was
    /// missing are also surfaced here for diagnostics.
    #[must_use]
    pub fn roots(&self) -> Vec<u32> {
        let mut roots: Vec<u32> = Vec::new();
        for (idx, node) in self.nodes.iter().enumerate() {
            if node.parent_idx == NO_PARENT {
                let trie_idx = len_to_u32(idx);
                roots.push(trie_idx);
            }
        }
        roots
    }

    /// Walk the trie from a root to the directory whose path is
    /// `segments` joined.  Returns the destination's trie-index, or
    /// `None` if any segment is missing.
    ///
    /// `segments[0]` matches a root by `name_of`; subsequent segments
    /// match against [`PathTrie::children_of`].  Linear scan over
    /// children at each level — for a typical drive's branching
    /// factor (~10-100 children per directory) this is faster than a
    /// per-level hash table at trie-build time.
    ///
    /// Plan task 4.5 pins the contract: `lookup_path(["C", "Users"])`
    /// returns `Some(_)` and `children_of` of the result enumerates
    /// the expected list.
    #[must_use]
    pub fn lookup_path(&self, segments: &[&[u8]]) -> Option<u32> {
        let first = segments.first()?;
        // Find a root whose name matches the first segment.
        let mut current = self
            .roots()
            .into_iter()
            .find(|&idx| self.name_of(idx) == Some(*first))?;

        for &segment in segments.iter().skip(1) {
            let child_idx = self
                .children_of(current)
                .iter()
                .copied()
                .find(|&child| self.name_of(child) == Some(segment))?;
            current = child_idx;
        }
        Some(current)
    }

    /// Reconstruct the full path of node `idx` by walking the parent
    /// chain.
    ///
    /// Names are joined with `/` (forward slash) — the platform-
    /// neutral form the daemon's API surface uses.  Returns `None` if
    /// `idx` is out of range; otherwise always succeeds (the parent
    /// chain is guaranteed acyclic by the build algorithm).
    #[must_use]
    pub fn full_path(&self, idx: u32) -> Option<Vec<u8>> {
        if (idx as usize) >= self.nodes.len() {
            return None;
        }
        let mut segments_reversed: Vec<&[u8]> = Vec::new();
        let mut cursor = idx;
        loop {
            let name = self.name_of(cursor)?;
            segments_reversed.push(name);
            match self.parent_of(cursor) {
                Some(parent) => cursor = parent,
                None => break,
            }
        }
        // Join in reverse order with '/' separators.
        let total_len: usize = segments_reversed.iter().map(|seg| seg.len()).sum::<usize>()
            + segments_reversed.len().saturating_sub(1);
        let mut out: Vec<u8> = Vec::with_capacity(total_len);
        for (idx_in_chain, segment) in segments_reversed.iter().rev().enumerate() {
            if idx_in_chain > 0 {
                out.push(b'/');
            }
            out.extend_from_slice(segment);
        }
        Some(out)
    }

    /// Borrow the underlying nodes slice — read-only handle for
    /// Phase 4 Commit D's serialiser.
    #[must_use]
    pub fn nodes(&self) -> &[TrieNode] {
        &self.nodes
    }

    /// Borrow the trie's name byte buffer — read-only handle for
    /// Phase 4 Commit D's serialiser.
    #[must_use]
    pub fn names(&self) -> &[u8] {
        &self.names
    }

    /// Borrow the CSR child-offsets slice.
    #[must_use]
    pub(crate) fn child_offsets(&self) -> &[u32] {
        &self.child_offsets
    }

    /// Borrow the CSR child-indices slice.
    #[must_use]
    pub fn child_indices(&self) -> &[u32] {
        &self.child_indices
    }

    /// Reconstruct a `PathTrie` from raw `(nodes, names, child_offsets,
    /// child_indices)` parts.
    ///
    /// Validates structural invariants:
    ///
    ///   - `child_offsets.len() == nodes.len() + 1`.
    ///   - `child_indices.len() == *child_offsets.last().unwrap_or(&0) as
    ///     usize`.
    ///   - Every node's `(name_offset, name_len)` slice is within the bounds of
    ///     `names`.
    ///
    /// Returns `None` on any violation so the cache-format
    /// deserialiser can reject corrupted files instead of producing
    /// an inconsistent trie that would later panic on lookup.
    #[must_use]
    pub fn from_raw_parts(
        nodes: Vec<TrieNode>,
        names: Vec<u8>,
        child_offsets: Vec<u32>,
        child_indices: Vec<u32>,
    ) -> Option<Self> {
        if child_offsets.len() != nodes.len() + 1 {
            return None;
        }
        let expected_indices_len = *child_offsets.last().unwrap_or(&0) as usize;
        if child_indices.len() != expected_indices_len {
            return None;
        }
        for node in &nodes {
            let start = node.name_offset as usize;
            let end = start.checked_add(node.name_len as usize)?;
            if end > names.len() {
                return None;
            }
        }
        Some(Self {
            nodes,
            names,
            child_offsets,
            child_indices,
        })
    }
}

/// Build the CSR children index from a slice of [`TrieNode`]s whose
/// `parent_idx` field is already in trie-index space.
///
/// Returns `(offsets, indices)`: `offsets.len() == nodes.len() + 1`,
/// `indices.len() == count of nodes whose parent != NO_PARENT`.
fn build_children_csr(nodes: &[TrieNode]) -> (Vec<u32>, Vec<u32>) {
    // Pass 1 — count children per parent.
    let mut counts: Vec<u32> = vec![0_u32; nodes.len()];
    for node in nodes {
        if node.parent_idx != NO_PARENT
            && let Some(slot) = counts.get_mut(node.parent_idx as usize)
        {
            *slot += 1;
        }
    }

    // Prefix-sum into offsets.
    let mut offsets: Vec<u32> = Vec::with_capacity(nodes.len() + 1);
    let mut running: u32 = 0;
    for &count in &counts {
        offsets.push(running);
        running = running.saturating_add(count);
    }
    offsets.push(running);

    // Pass 2 — scatter.
    let mut indices: Vec<u32> = vec![0_u32; running as usize];
    let mut write_pos: Vec<u32> = offsets.clone();
    for (idx_usize, node) in nodes.iter().enumerate() {
        if node.parent_idx == NO_PARENT {
            continue;
        }
        let Some(pos_slot) = write_pos.get_mut(node.parent_idx as usize) else {
            continue;
        };
        let Some(target) = indices.get_mut(*pos_slot as usize) else {
            continue;
        };
        let child_idx = len_to_u32(idx_usize);
        *target = child_idx;
        *pos_slot += 1;
    }

    (offsets, indices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compact::CompactRecord;

    /// Helper: build a minimal `CompactRecord` for a directory or
    /// file.  Only the fields the trie reads are populated; the rest
    /// come from `Default::default()` via struct-update syntax.
    fn make_record(
        name_offset: u32,
        name_len: u16,
        parent_idx: u32,
        is_dir: bool,
    ) -> CompactRecord {
        // The DIRECTORY flag bit on raw NTFS attributes.
        let flags: u32 = if is_dir { 0x0010 } else { 0 };
        CompactRecord {
            name_offset,
            flags,
            parent_idx,
            name_len,
            ..CompactRecord::default()
        }
    }

    /// Smoke: an empty trie is a valid trie with zero nodes.
    #[test]
    fn empty_records_yield_empty_trie() {
        let trie = PathTrie::build(&[], &[]);
        assert!(trie.is_empty());
        assert_eq!(trie.len(), 0);
        assert_eq!(trie.roots(), Vec::<u32>::new());
        assert_eq!(trie.children_of(0), &[] as &[u32]);
    }

    /// Files-only input yields an empty trie (directory-only by
    /// design).
    #[test]
    fn files_only_yields_empty_trie() {
        let names = b"a.txtb.rs".to_vec();
        let records = [
            make_record(0, 5, u32::MAX, false),
            make_record(5, 4, u32::MAX, false),
        ];
        let trie = PathTrie::build(&records, &names);
        assert!(trie.is_empty());
    }

    /// Single-directory trie: one root, no children.
    #[test]
    fn single_root_directory() {
        let names = b"C".to_vec();
        let records = [make_record(0, 1, u32::MAX, true)];
        let trie = PathTrie::build(&records, &names);

        assert_eq!(trie.len(), 1);
        assert_eq!(trie.roots(), vec![0_u32]);
        assert_eq!(trie.name_of(0), Some(b"C" as &[u8]));
        assert_eq!(trie.parent_of(0), None);
        assert_eq!(trie.children_of(0), Vec::<u32>::new());
    }

    /// Two-level hierarchy: `C` (root) with two children `Users` and
    /// `Windows`.  Validates parent-resolution + children CSR.
    #[test]
    fn two_level_hierarchy() {
        // Records layout: index 0 = C (root), 1 = Users (parent 0),
        // 2 = Windows (parent 0).
        let names = b"CUsersWindows".to_vec();
        let records = [
            make_record(0, 1, u32::MAX, true), // C
            make_record(1, 5, 0, true),        // Users
            make_record(6, 7, 0, true),        // Windows
        ];
        let trie = PathTrie::build(&records, &names);

        assert_eq!(trie.len(), 3);
        assert_eq!(trie.roots(), vec![0_u32]);

        let children_of_c = trie.children_of(0);
        assert_eq!(children_of_c.len(), 2);
        // Order of children isn't guaranteed by the spec, but build
        // ordering is record-iteration order, so we expect
        // [Users(1), Windows(2)].
        assert_eq!(children_of_c, &[1_u32, 2_u32]);

        assert_eq!(trie.name_of(1), Some(b"Users" as &[u8]));
        assert_eq!(trie.name_of(2), Some(b"Windows" as &[u8]));
        assert_eq!(trie.parent_of(1), Some(0));
        assert_eq!(trie.parent_of(2), Some(0));
    }

    /// Plan task 4.5: 1000 directories under a common root, look up
    /// each by `lookup_path(["root", "dirN"])`, assert presence and
    /// `children_of(root)` enumerates exactly the expected indices.
    #[test]
    fn lookup_path_finds_thousand_paths() {
        let mut names: Vec<u8> = Vec::new();
        let mut records: Vec<CompactRecord> = Vec::new();

        // Index 0 = root "C".
        names.extend_from_slice(b"C");
        records.push(make_record(0, 1, u32::MAX, true));

        // Indices 1..=1000 = "dir0" .. "dir999" under C.
        let mut expected_dir_names: Vec<String> = Vec::with_capacity(1000);
        for i in 0_u32..1000 {
            let name = format!("dir{i}");
            // Test fixture sizes are statically bounded, so the
            // saturating `try_from` fallbacks are unreachable.
            let off = len_to_u32(names.len());
            names.extend_from_slice(name.as_bytes());
            let len = uffs_mft::len_to_u16(name.len());
            records.push(make_record(off, len, 0, true));
            expected_dir_names.push(name);
        }

        let trie = PathTrie::build(&records, &names);
        assert_eq!(trie.len(), 1001);
        assert_eq!(trie.roots(), vec![0_u32]);

        // children_of(C) should be exactly [1, 2, ..., 1000].
        let children = trie.children_of(0);
        assert_eq!(children.len(), 1000);
        let expected_children: Vec<u32> = (1_u32..=1000).collect();
        assert_eq!(children, expected_children.as_slice());

        // Every dirN looks up correctly.
        for (offset, expected_name) in expected_dir_names.iter().enumerate() {
            let segs: [&[u8]; 2] = [b"C", expected_name.as_bytes()];
            let found = trie.lookup_path(&segs).expect("lookup_path missed");
            // offset < 1000 fits u32 trivially; saturating fallback is
            // unreachable.
            let expected_idx = len_to_u32(offset) + 1;
            assert_eq!(found, expected_idx);
        }
    }

    /// `lookup_path` returns `None` for any missing segment.
    #[test]
    fn lookup_path_missing_returns_none() {
        let names = b"CUsers".to_vec();
        let records = [
            make_record(0, 1, u32::MAX, true),
            make_record(1, 5, 0, true),
        ];
        let trie = PathTrie::build(&records, &names);

        assert!(trie.lookup_path(&[]).is_none());
        assert!(trie.lookup_path(&[b"D"]).is_none()); // wrong root
        assert!(trie.lookup_path(&[b"C", b"NoSuch"]).is_none()); // missing child
        assert!(trie.lookup_path(&[b"C", b"Users", b"Alice"]).is_none()); // too deep
    }

    /// `full_path(idx)` reconstructs the path with `/` separators.
    #[test]
    fn full_path_reconstructs_with_slash_separators() {
        let names = b"CUsersAlice".to_vec();
        let records = [
            make_record(0, 1, u32::MAX, true),
            make_record(1, 5, 0, true),
            make_record(6, 5, 1, true),
        ];
        let trie = PathTrie::build(&records, &names);

        assert_eq!(trie.full_path(0).as_deref(), Some(b"C" as &[u8]));
        assert_eq!(trie.full_path(1).as_deref(), Some(b"C/Users" as &[u8]));
        assert_eq!(
            trie.full_path(2).as_deref(),
            Some(b"C/Users/Alice" as &[u8])
        );
        // Out-of-range idx returns None.
        assert!(trie.full_path(99).is_none());
    }

    /// Orphan handling: a directory whose `parent_idx` points to a
    /// non-directory record gets `NO_PARENT` (becomes a root).
    #[test]
    fn orphan_directory_with_non_directory_parent_becomes_root() {
        // Index 0 = file "f.txt" (NOT a directory).
        // Index 1 = dir "orphan" claiming parent_idx = 0.
        let names = b"f.txtorphan".to_vec();
        let records = [
            make_record(0, 5, u32::MAX, false),
            make_record(5, 6, 0, true),
        ];
        let trie = PathTrie::build(&records, &names);

        assert_eq!(trie.len(), 1);
        assert_eq!(trie.roots(), vec![0_u32]);
        assert_eq!(trie.name_of(0), Some(b"orphan" as &[u8]));
        assert_eq!(trie.parent_of(0), None);
    }

    /// Orphan handling: a directory whose `parent_idx` is out of
    /// records-range gets `NO_PARENT`.
    #[test]
    fn orphan_directory_with_unknown_parent_becomes_root() {
        let names = b"phantom".to_vec();
        let records = [make_record(0, 7, 9999, true)];
        let trie = PathTrie::build(&records, &names);

        assert_eq!(trie.len(), 1);
        assert_eq!(trie.roots(), vec![0_u32]);
        assert_eq!(trie.parent_of(0), None);
    }

    /// `name_of` / `parent_of` / `children_of` return safe defaults
    /// for out-of-range indices.
    #[test]
    fn out_of_range_queries_are_safe() {
        let trie = PathTrie::build(&[], &[]);
        assert_eq!(trie.name_of(0), None);
        assert_eq!(trie.parent_of(0), None);
        assert_eq!(trie.children_of(99_999), &[] as &[u32]);
    }

    /// `size_bytes` is non-zero for a non-empty trie and roughly
    /// matches the analytic estimate.
    #[test]
    fn size_bytes_accounts_for_all_columns() {
        let names = b"CUsers".to_vec();
        let records = [
            make_record(0, 1, u32::MAX, true),
            make_record(1, 5, 0, true),
        ];
        let trie = PathTrie::build(&records, &names);

        // Lower bound: 2 nodes × 12 + 6 name bytes + 3 offsets × 4
        // (header CSR = nodes.len()+1) + 1 child × 4 = 24 + 6 + 12 + 4 = 46.
        assert!(trie.size_bytes() >= 46);
        // Upper bound: capacities can over-allocate by a factor; cap
        // at 4× the analytic floor to catch egregious bloat.
        assert!(trie.size_bytes() <= 46 * 16);
    }

    /// `nodes()` / `names()` / `child_offsets()` / `child_indices()`
    /// borrows are non-empty and length-consistent for a non-empty
    /// trie.  Pins the Commit D serialiser's contract.
    #[test]
    fn raw_buffer_borrows_are_consistent() {
        let names = b"CUsersWindows".to_vec();
        let records = [
            make_record(0, 1, u32::MAX, true),
            make_record(1, 5, 0, true),
            make_record(6, 7, 0, true),
        ];
        let trie = PathTrie::build(&records, &names);

        assert_eq!(trie.nodes().len(), 3);
        // Trie names are independent of the records' name buffer; the
        // trie copies just the directory basenames.
        assert_eq!(trie.names(), b"CUsersWindows");
        // CSR offsets length = nodes.len() + 1.
        assert_eq!(trie.child_offsets().len(), 4);
        // Two children of C.
        assert_eq!(trie.child_indices().len(), 2);
    }

    /// Plan task **4.12** — trie build budget at 1 M directories.
    ///
    /// Pre-build records + names outside the timed region; time only
    /// `PathTrie::build`.  Budget ≤ 100 ms in release mode (debug
    /// runs 10–100× slower; gated `release-only` so default
    /// `cargo test` skips it; run with `cargo test --release ... --
    /// --include-ignored`).
    ///
    /// Synthetic topology: root + `999_999` children all parented to
    /// root.  Build cost is dominated by O(N) record iteration +
    /// hashmap inserts + parent lookups; topology is irrelevant.
    /// Names share a 3-byte buffer ("dir") so fixture-build is
    /// negligible vs the timed region.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only")]
    fn plan_4_12_path_trie_build_under_one_hundred_ms_at_one_million_directories() {
        use alloc::vec::Vec;
        use core::time::Duration;
        use std::time::Instant;

        const DIRS: u32 = 1_000_000;
        let names = b"dir".to_vec();
        let mut records: Vec<CompactRecord> = Vec::with_capacity(DIRS as usize);
        records.push(make_record(0, 3, u32::MAX, true));
        for _ in 1..DIRS {
            records.push(make_record(0, 3, 0, true));
        }

        let start = Instant::now();
        let trie = PathTrie::build(&records, &names);
        let elapsed = start.elapsed();

        let budget = Duration::from_millis(100);
        assert!(
            elapsed <= budget,
            "path_trie build at {DIRS} directories took {elapsed:?} (budget {budget:?})"
        );
        assert_eq!(
            u32::try_from(trie.len()).expect("len fits u32"),
            DIRS,
            "every directory record must land in the trie"
        );
    }
}
