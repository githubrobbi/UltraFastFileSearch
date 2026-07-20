// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Helper functions for the direct-to-index parser.
//!
//! These helpers reduce code duplication in the main parser while maintaining
//! performance through inlining.

use crate::index::{
    ChildInfo, IndexNameRef, IndexStreamInfo, LinkInfo, MftIndex, NO_ENTRY, SizeInfo, frs_to_usize,
    len_to_u16, len_to_u32, u32_as_usize,
};

/// A pending stream, collected while walking a record's attributes and
/// applied to the index in one batch via [`add_stream_to_index`]:
/// `(name, size, allocated, is_sparse, is_resident)`.
pub(crate) type StreamEntry = (String, u64, u64, bool, bool);

/// Adds a stream to the index and returns its index.
#[inline]
pub(crate) fn add_stream_to_index(
    index: &mut MftIndex,
    stream_name: &str,
    stream_size: u64,
    stream_allocated: u64,
    is_sparse: bool,
    is_resident: bool,
) -> u32 {
    let stream_name_offset = index.add_name(stream_name);
    let stream_name_len = stream_name.len();
    let stream_is_ascii = stream_name.is_ascii();
    let extension_id = index.intern_extension(stream_name);
    let stream_name_ref = IndexNameRef::new(
        stream_name_offset,
        len_to_u16(stream_name_len),
        stream_is_ascii,
        extension_id,
    );

    let stream_idx = len_to_u32(index.streams.len());
    index.streams.push(IndexStreamInfo {
        size: SizeInfo {
            length: stream_size,
            allocated: stream_allocated,
        },
        next_entry: NO_ENTRY,
        name: stream_name_ref,
        // bit0=is_sparse, bit1=is_resident, type_name_id=8 for $DATA
        // (0x80 >> 4) in bits 2-7.
        flags: u8::from(is_sparse) | (u8::from(is_resident) << 1) | (8 << 2),
        _pad0: [0; 3],
    });
    stream_idx
}

/// Chains stream indices together and returns the first index.
#[inline]
pub(crate) fn chain_streams(index: &mut MftIndex, stream_indices: &[u32]) {
    for i in 0..stream_indices.len().saturating_sub(1) {
        let current_idx = u32_as_usize(stream_indices[i]);
        let next_idx = stream_indices[i + 1];
        index.streams[current_idx].next_entry = next_idx;
    }
}

/// Chains link indices together.
#[inline]
pub(crate) fn chain_links(index: &mut MftIndex, link_indices: &[u32]) {
    for i in 0..link_indices.len().saturating_sub(1) {
        let current_idx = u32_as_usize(link_indices[i]);
        let next_idx = link_indices[i + 1];
        index.links[current_idx].next_entry = next_idx;
    }
}

/// Adds a link to the index and returns its index.
#[inline]
pub(crate) fn add_link_to_index(index: &mut MftIndex, link_name: &str, link_parent: u64) -> u32 {
    let link_offset = index.add_name(link_name);
    let link_len = link_name.len();
    let link_is_ascii = link_name.is_ascii();
    let extension_id = index.intern_extension(link_name);
    let link_name_ref = IndexNameRef::new(
        link_offset,
        len_to_u16(link_len),
        link_is_ascii,
        extension_id,
    );

    let link_idx = len_to_u32(index.links.len());
    index.links.push(LinkInfo {
        next_entry: NO_ENTRY,
        name: link_name_ref,
        _pad0: [0; 4],
        // Parser locals are still raw `u64`; lift to typed `ParentFrs`
        // at the typed index-struct construction boundary.
        parent_frs: crate::frs::ParentFrs::new(link_parent),
    });
    link_idx
}

/// Adds a child entry to a parent record for tree metrics computation.
#[inline]
pub(crate) fn add_child_entry(
    index: &mut MftIndex,
    parent_frs: u64,
    child_frs: u64,
    name_idx: u16,
) {
    if parent_frs == child_frs || parent_frs == u64::from(NO_ENTRY) {
        return;
    }

    // Ensure parent exists.  `frs_to_idx` is `Vec<u32>` indexed by `usize`,
    // so `parent_frs` stays raw here; typed `Frs` is built only when
    // writing to a typed index field.
    let parent_idx = {
        let p_frs_usize = frs_to_usize(parent_frs);
        if p_frs_usize >= index.frs_to_idx.len() {
            index.frs_to_idx.resize(p_frs_usize + 1, NO_ENTRY);
        }
        if index.frs_to_idx[p_frs_usize] == NO_ENTRY {
            let new_idx = len_to_u32(index.records.len());
            index.frs_to_idx[p_frs_usize] = new_idx;
            index
                .records
                .push(crate::index::FileRecord::new(crate::frs::Frs::new(
                    parent_frs,
                )));
        }
        index.frs_to_idx[p_frs_usize]
    };

    // Add child entry
    let child_idx = len_to_u32(index.children.len());
    let parent = &mut index.records[u32_as_usize(parent_idx)];
    let old_first_child = parent.first_child;
    parent.first_child = child_idx;

    index.children.push(ChildInfo {
        next_entry: old_first_child,
        _pad0: [0; 4],
        // Lift parser-local raw `u64` to typed `Frs` at the boundary.
        child_frs: crate::frs::Frs::new(child_frs),
        name_index: name_idx,
        _pad1: [0; 6],
    });
}
