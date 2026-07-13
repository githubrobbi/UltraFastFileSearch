// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Per-change record mutation for [`super::apply_usn_patch`]: stage a created
//! file into the names blob + extension table, then apply create / delete /
//! rename to the compact records + `frs_to_compact` mapping, collecting the
//! path-length and trigram-delta change sets for the post-loop rebuild.

use super::PatchStats;
use crate::compact::{CompactRecord, DriveCompactIndex};

/// A USN-created file's identity, staged into the index's names blob +
/// extension table via a mutable `drive` borrow BEFORE any record borrow.
///
/// All fields are `Copy`, so the caller can take a `&mut CompactRecord`
/// after this returns without a borrow conflict.
struct StagedCreate {
    /// Byte offset of the staged name in `drive.names`.
    name_offset: u32,
    /// UTF-8 byte length of the staged name.
    name_len: u16,
    /// Cached first byte of the name (hot-path metafile gate).
    name_first_byte: u8,
    /// Interned extension id for the new name (`0` = no extension).
    extension_id: u16,
    /// Compact index of the parent directory (`u32::MAX` if unmapped).
    parent_idx: u32,
    /// Real size/timestamps/flags from a targeted MFT read, or all-zero when
    /// the USN-only change carried no metadata (a later re-warm fills it).
    /// Representation matches `CompactRecord`, so it copies straight in.
    meta: uffs_mft::usn::RecordMeta,
}

/// Append `change`'s filename to the names blob and intern its extension,
/// resolving the parent's compact index.  Mutably borrows `drive`, so it
/// must run before any `&mut CompactRecord` borrow.
fn stage_create(drive: &mut DriveCompactIndex, change: &uffs_mft::usn::FileChange) -> StagedCreate {
    let extension_id = drive.intern_extension(&change.filename);
    let name_start = drive.names.len();
    drive
        .names
        .as_mut_vec()
        .extend_from_slice(change.filename.as_bytes());
    let parent_frs_usize = uffs_mft::frs_to_usize(change.parent_frs.raw());
    let parent_idx = drive
        .frs_to_compact
        .get(parent_frs_usize)
        .copied()
        .unwrap_or(u32::MAX);
    StagedCreate {
        name_offset: uffs_mft::len_to_u32(name_start),
        name_len: uffs_mft::len_to_u16(change.filename.len()),
        name_first_byte: change.filename.as_bytes().first().copied().unwrap_or(0),
        extension_id,
        parent_idx,
        meta: change.meta.unwrap_or_default(),
    }
}

/// Overwrite an existing compact slot with a reused/re-animated file's
/// identity. Per-file metrics come from the staged metadata — real values
/// when a targeted MFT read backfilled them, else zero (a later re-warm
/// fills them; the USN `FileChange` carries only name + parent).
const fn overwrite_slot(rec: &mut CompactRecord, staged: &StagedCreate) {
    rec.name_offset = staged.name_offset;
    rec.name_len = staged.name_len;
    rec.name_first_byte = staged.name_first_byte;
    rec.extension_id = staged.extension_id;
    rec.parent_idx = staged.parent_idx;
    rec.size = staged.meta.size;
    rec.allocated = staged.meta.allocated;
    rec.created = staged.meta.created;
    rec.modified = staged.meta.modified;
    rec.accessed = staged.meta.accessed;
    rec.flags = staged.meta.flags;
    // Tree metrics are recomputed post-loop (CSR rebuild + compute_path_
    // lengths); never carried by a USN change.
    rec.treesize = 0;
    rec.tree_allocated = 0;
    rec.descendants = 0;
    rec.path_len = 0;
}

/// Apply a delete change: tombstone the slot (`name_len = 0`, parent
/// unmapped so the CSR rebuild drops it) and unmap its FRS so a later batch
/// can't re-animate the tombstone.
pub(super) fn apply_delete(
    drive: &mut DriveCompactIndex,
    frs_usize: usize,
    compact_idx: u32,
    stats: &mut PatchStats,
    tombstones: &mut Vec<u32>,
) {
    if compact_idx == u32::MAX {
        stats.skipped += 1;
        return;
    }
    if let Some(rec) = drive.records.as_mut_slice().get_mut(compact_idx as usize) {
        rec.name_len = 0;
        rec.parent_idx = u32::MAX;
        if let Some(slot) = drive.frs_to_compact.get_mut(frs_usize) {
            *slot = u32::MAX;
        }
        // Phase 2b: mask the deleted record's stale base trigram postings.
        tombstones.push(compact_idx);
        stats.deleted += 1;
    }
}

/// Apply a create change: overwrite the mapped slot when the MFT record
/// number was reused (tombstone OR stale live record), or append a fresh
/// record + register its FRS mapping when the slot is new.
pub(super) fn apply_create(
    drive: &mut DriveCompactIndex,
    change: &uffs_mft::usn::FileChange,
    frs_usize: usize,
    compact_idx: u32,
    stats: &mut PatchStats,
    path_changes: &mut Vec<crate::compact::PathChange>,
    tombstones: &mut Vec<u32>,
) {
    if change.filename.is_empty() {
        stats.skipped += 1;
        return;
    }
    // Stage name + interned extension up front (mutable index borrow) so the
    // per-record write can take a `&mut CompactRecord` without conflict.
    let staged = stage_create(drive, change);
    if compact_idx == u32::MAX {
        // Brand-new record: append, then register the FRS mapping. NTFS
        // reuses freed record numbers and a long-running daemon can outgrow
        // the build-time table, so extend + sentinel-fill any gap.
        let new_rec = CompactRecord {
            size: staged.meta.size,
            allocated: staged.meta.allocated,
            treesize: 0,
            tree_allocated: 0,
            created: staged.meta.created,
            modified: staged.meta.modified,
            accessed: staged.meta.accessed,
            // USN strips the sequence number from the file reference
            // (uffs_mft::usn), so a live-created record carries FRS only
            // (seq = 0) until the next full read stamps the real generation.
            file_ref: CompactRecord::pack_file_reference(uffs_mft::usize_to_u64(frs_usize), 0),
            name_offset: staged.name_offset,
            flags: staged.meta.flags,
            parent_idx: staged.parent_idx,
            descendants: 0,
            name_len: staged.name_len,
            extension_id: staged.extension_id,
            // path_len filled by `compute_path_lengths` post-loop.
            path_len: 0,
            name_first_byte: staged.name_first_byte,
            _pad: [0; 1],
        };
        let new_compact_idx = uffs_mft::len_to_u32(drive.records.len());
        drive.records.as_mut_vec().push(new_rec);
        if frs_usize >= drive.frs_to_compact.len() {
            drive
                .frs_to_compact
                .resize(frs_usize.saturating_add(1), u32::MAX);
        }
        if let Some(slot) = drive.frs_to_compact.get_mut(frs_usize) {
            *slot = new_compact_idx;
        }
        // A new record has no descendants yet → O(1) path refresh, no subtree.
        path_changes.push(crate::compact::PathChange {
            idx: new_compact_idx,
            subtree: false,
        });
        stats.created += 1;
    } else if let Some(rec) = drive.records.as_mut_slice().get_mut(compact_idx as usize) {
        // The record number is already mapped. A `created` event means NTFS
        // reused that slot for a NEW file — the old occupant (a tombstone, OR
        // a stale live record whose delete was coalesced/missed) no longer
        // exists. Overwrite it wholesale. Skipping a live slot here is what
        // dropped FRS-reused recreates (the "delta.pdf vanished" report).
        overwrite_slot(rec, &staged);
        // FRS-reuse overwrite: treat as a fresh record (its old subtree, if
        // any, was deleted/remapped and is handled by its own changes).
        path_changes.push(crate::compact::PathChange {
            idx: compact_idx,
            subtree: false,
        });
        // Phase 2b: the reused slot's old occupant's base postings are stale —
        // mask them; the new name is re-added via `path_changes`.
        tombstones.push(compact_idx);
        stats.created += 1;
    }
}

/// Apply a rename change: re-point the name, **re-intern the extension** (a
/// rename can change it: `foo.log` → `foo.pdf`), refresh the first-byte
/// cache, and update `parent_idx`. The FRS keeps its slot, so the mapping is
/// unchanged.
pub(super) fn apply_rename(
    drive: &mut DriveCompactIndex,
    change: &uffs_mft::usn::FileChange,
    compact_idx: u32,
    stats: &mut PatchStats,
    path_changes: &mut Vec<crate::compact::PathChange>,
    tombstones: &mut Vec<u32>,
) {
    if compact_idx == u32::MAX || change.filename.is_empty() {
        stats.skipped += 1;
        return;
    }
    let extension_id = drive.intern_extension(&change.filename);
    let name_start = drive.names.len();
    drive
        .names
        .as_mut_vec()
        .extend_from_slice(change.filename.as_bytes());
    let new_parent_frs = uffs_mft::frs_to_usize(change.parent_frs.raw());
    let new_parent_compact = drive
        .frs_to_compact
        .get(new_parent_frs)
        .copied()
        .unwrap_or(u32::MAX);
    if let Some(rec) = drive.records.as_mut_slice().get_mut(compact_idx as usize) {
        rec.name_offset = uffs_mft::len_to_u32(name_start);
        rec.name_len = uffs_mft::len_to_u16(change.filename.len());
        rec.extension_id = extension_id;
        rec.name_first_byte = change.filename.as_bytes().first().copied().unwrap_or(0);
        rec.parent_idx = new_parent_compact;
        // Apply backfilled size/timestamps/flags when a targeted MFT read
        // attached them (corrects a record previously created USN-only with
        // zeroed metrics); otherwise leave the existing values untouched.
        if let Some(meta) = change.meta {
            rec.size = meta.size;
            rec.allocated = meta.allocated;
            rec.created = meta.created;
            rec.modified = meta.modified;
            rec.accessed = meta.accessed;
            rec.flags = meta.flags;
        }
        // A directory rename shifts every descendant's path by a constant Δ;
        // a file rename only refreshes this record.
        path_changes.push(crate::compact::PathChange {
            idx: compact_idx,
            subtree: rec.is_directory(),
        });
        // Phase 2b: mask the old-name base postings; the new name is re-added
        // via `path_changes`. The trigram_search tombstone logic keeps the
        // record visible under its new name and gone from its old one.
        tombstones.push(compact_idx);
        stats.renamed += 1;
    }
}
