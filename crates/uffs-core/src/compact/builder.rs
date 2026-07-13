// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Build a [`DriveCompactIndex`] from a loaded `MftIndex`: struct-of-arrays
//! column assembly, hardlink + ADS expansion, `$UpCase` case-fold resolution,
//! and the post-build vec shrink.

use alloc::sync::Arc;
use std::time::Instant;

use rayon::prelude::*;
use uffs_mft::index::MftIndex;

use crate::compact::{
    ChildrenIndex, CompactRecord, DriveCompactIndex, ExtensionIndex, IndexSource,
    compute_path_lengths,
};
use crate::compact_storage::ColumnStorage;
use crate::trigram::TrigramIndex;

/// Expand alternate data streams (ADS) for a single record, producing the
/// name × stream cross product as extra `CompactRecord` entries.
#[expect(
    clippy::single_call_fn,
    reason = "Extracted to keep expand_links_and_ads under the too_many_lines limit"
)]
fn expand_ads_streams(
    index: &MftIndex,
    record: &uffs_mft::index::FileRecord,
    resolve_parent: &dyn Fn(uffs_mft::ParentFrs, uffs_mft::Frs) -> u32,
    names: &mut Vec<u8>,
    extra: &mut Vec<CompactRecord>,
) {
    // Collect all names for this record (primary + hardlinks).
    let mut all_names: Vec<(&str, u32)> = Vec::new();
    let primary_name = index.get_name(record.first_name.name);
    if !primary_name.is_empty() {
        let pid = resolve_parent(record.first_name.parent_frs, record.frs);
        all_names.push((primary_name, pid));
    }
    if record.name_count > 1 {
        let mut le = record.first_name.next_entry;
        while le != uffs_mft::NO_ENTRY {
            let Some(lnk) = index.links.get(le as usize) else {
                break;
            };
            let ln = index.get_name(lnk.name);
            if !ln.is_empty() {
                let lp = resolve_parent(lnk.parent_frs, record.frs);
                all_names.push((ln, lp));
            }
            le = lnk.next_entry;
        }
    }

    // Walk output streams (skip default $DATA at head of chain).
    let mut se = record.first_stream.next_entry;
    while se != uffs_mft::NO_ENTRY {
        let Some(stream) = index.streams.get(se as usize) else {
            break;
        };
        if stream.is_output_stream() {
            let sn = index.stream_name(stream);
            if !sn.is_empty() {
                for &(base_name, parent_idx) in &all_names {
                    let combined = format!("{base_name}:{sn}");
                    let name_offset = uffs_mft::len_to_u32(names.len());
                    let name_len = uffs_mft::len_to_u16(combined.len());
                    names.extend_from_slice(combined.as_bytes());

                    extra.push(CompactRecord {
                        size: stream.size.length,
                        allocated: stream.size.allocated,
                        treesize: 0,
                        tree_allocated: 0,
                        created: record.stdinfo.created,
                        modified: record.stdinfo.modified,
                        accessed: record.stdinfo.accessed,
                        file_ref: CompactRecord::pack_file_reference(
                            record.frs.raw(),
                            record.sequence_number,
                        ),
                        name_offset,
                        flags: record.stdinfo.flags,
                        parent_idx,
                        descendants: 0,
                        name_len,
                        extension_id: 0,
                        path_len: 0,
                        name_first_byte: combined.as_bytes().first().copied().unwrap_or(0),
                        _pad: [0; 1],
                    });
                }
            }
        }
        se = stream.next_entry;
    }
}

/// Resolve a typed `ParentFrs` (vs an own typed `Frs`) into a compact-record
/// index, returning `u32::MAX` for the "no real parent" cases (self-reference,
/// `NO_ENTRY` sentinel, or root).
///
/// Extracted as a free helper so the typed `ParentFrs`/`Frs` signature is
/// enforced at every call site AND so `build_compact_index` stays under
/// the clippy `too_many_lines` budget.
#[expect(
    clippy::single_call_fn,
    reason = "Wrapped by a closure in build_compact_index; kept free-standing \
              for clippy::too_many_lines budget headroom"
)]
fn resolve_parent_compact_idx(
    index: &MftIndex,
    parent_frs: uffs_mft::ParentFrs,
    own_frs: uffs_mft::Frs,
) -> u32 {
    let parent = parent_frs.as_frs();
    if parent == own_frs || parent_frs.raw() == u64::from(uffs_mft::NO_ENTRY) || parent.is_root() {
        return u32::MAX;
    }
    let parent_usize = uffs_mft::frs_to_usize(parent.raw());
    index
        .frs_to_idx
        .get(parent_usize)
        .copied()
        .filter(|&idx| idx != uffs_mft::NO_ENTRY)
        .unwrap_or(u32::MAX)
}

/// Expand hardlinks and ADS into additional `CompactRecord` entries.
///
/// Phase 2 (hardlinks): for each valid record with `name_count > 1`, walks the
/// link chain and creates additional records with alternate name/parent.
///
/// Phase 3 (ADS): delegates to [`expand_ads_streams`] for each valid record
/// with `stream_count > 1`.
#[expect(
    clippy::single_call_fn,
    reason = "Extracted to keep build_compact_index under the too_many_lines limit"
)]
fn expand_links_and_ads(
    index: &MftIndex,
    resolver: &uffs_mft::index::PathResolver,
    resolve_parent: &dyn Fn(uffs_mft::ParentFrs, uffs_mft::Frs) -> u32,
    names: &mut Vec<u8>,
) -> Vec<CompactRecord> {
    let mut extra: Vec<CompactRecord> = Vec::new();

    for (idx, record) in index.records.iter().enumerate() {
        if !resolver.is_valid_idx(idx) {
            continue;
        }

        // Phase 2: hardlink expansion.
        if record.name_count > 1 {
            let mut link_entry = record.first_name.next_entry;
            while link_entry != uffs_mft::NO_ENTRY {
                let Some(link) = index.links.get(link_entry as usize) else {
                    break;
                };
                let link_parent = resolve_parent(link.parent_frs, record.frs);
                extra.push(CompactRecord {
                    size: record.first_stream.size.length,
                    allocated: record.first_stream.size.allocated,
                    treesize: record.treesize,
                    tree_allocated: record.tree_allocated,
                    created: record.stdinfo.created,
                    modified: record.stdinfo.modified,
                    accessed: record.stdinfo.accessed,
                    file_ref: CompactRecord::pack_file_reference(
                        record.frs.raw(),
                        record.sequence_number,
                    ),
                    name_offset: link.name.offset,
                    flags: record.stdinfo.flags,
                    parent_idx: link_parent,
                    descendants: record.descendants,
                    name_len: link.name.length(),
                    extension_id: link.name.extension_id(),
                    path_len: 0,
                    name_first_byte: names.get(link.name.offset as usize).copied().unwrap_or(0),
                    _pad: [0; 1],
                });
                link_entry = link.next_entry;
            }
        }

        // Phase 3: ADS expansion (name × stream cross product).
        if record.stream_count > 1 {
            expand_ads_streams(index, record, resolve_parent, names, &mut extra);
        }
    }
    extra
}

/// Build a `DriveCompactIndex` from a loaded `MftIndex`.
///
/// Returns `(DriveCompactIndex, compact_build_ms, trigram_build_ms)`.
#[must_use]
pub fn build_compact_index(
    drive_letter: uffs_mft::platform::DriveLetter,
    index: &MftIndex,
) -> (DriveCompactIndex, u128, u128) {
    use uffs_mft::index::PathResolver;

    let compact_start = Instant::now();

    // Build path resolver to determine which records are valid.
    // This filters out system metafiles (FRS 0-15 except root) and
    // propagates invalidity to descendants (e.g., $Extend children).
    let resolver = PathResolver::build(index, false);

    // Closure wraps the free helper `resolve_parent_compact_idx` so the
    // typed `ParentFrs`/`Frs` signature is enforced at every call site
    // (own↔parent swap becomes a compile error).  Keeping the helper
    // free-standing also keeps `build_compact_index` under the
    // clippy::too_many_lines budget.
    let resolve_parent = |parent_frs: uffs_mft::ParentFrs, own_frs: uffs_mft::Frs| -> u32 {
        resolve_parent_compact_idx(index, parent_frs, own_frs)
    };

    // Phase 1: build primary compact records (parallel).
    let mut records: Vec<CompactRecord> = index
        .records
        .par_iter()
        .enumerate()
        .map(|(idx, record)| {
            // Skip invalid records (system metafiles + descendants).
            if !resolver.is_valid_idx(idx) {
                return CompactRecord::default();
            }

            let name_ref = &record.first_name.name;
            let parent_idx = resolve_parent(record.first_name.parent_frs, record.frs);

            CompactRecord {
                size: record.first_stream.size.length,
                allocated: record.first_stream.size.allocated,
                treesize: record.treesize,
                tree_allocated: record.tree_allocated,
                created: record.stdinfo.created,
                modified: record.stdinfo.modified,
                accessed: record.stdinfo.accessed,
                file_ref: CompactRecord::pack_file_reference(
                    record.frs.raw(),
                    record.sequence_number,
                ),
                name_offset: name_ref.offset,
                flags: record.stdinfo.flags,
                parent_idx,
                descendants: record.descendants,
                name_len: name_ref.length(),
                extension_id: name_ref.extension_id(),
                path_len: 0,
                name_first_byte: index
                    .names
                    .get(name_ref.offset as usize)
                    .copied()
                    .unwrap_or(0),
                _pad: [0; 1],
            }
        })
        .collect();

    // Phase 2+3: expand hardlinks and ADS (sequential — rare, <1% of records).
    let mut names = index.names.clone();
    let expanded = expand_links_and_ads(index, &resolver, &resolve_parent, &mut names);
    records.extend(expanded);

    // Phase 4: compute path_len (in characters) for every record via
    // top-down BFS.  path_len = char count of "C:\dir\name".
    compute_path_lengths(&mut records, &names, drive_letter);

    let compact_elapsed = compact_start.elapsed().as_millis();

    // Try live $UpCase from the NTFS volume; fall back to compiled-in default.
    let fold = resolve_case_fold(drive_letter);

    let tri_start = Instant::now();
    let trigram = TrigramIndex::build(&records, &names, fold);
    let tri_elapsed = tri_start.elapsed().as_millis();

    // Build children CSR index from parent_idx (two-pass: count + scatter).
    let children = ChildrenIndex::build(&records);

    // Copy extension name table from MftIndex (Arc<str> → Box<str>).
    let mut ext_names: Vec<Box<str>> = index
        .extensions
        .names
        .iter()
        .map(|arc| Box::from(arc.as_ref()))
        .collect();

    let ext_t0 = Instant::now();
    let ext_index = ExtensionIndex::build(&records);
    let ext_build_ms = ext_t0.elapsed().as_millis();
    tracing::info!(
        drive = %drive_letter,
        entries = ext_index.total_entries(),
        build_ms = ext_build_ms,
        "ExtensionIndex built"
    );

    shrink_compact_vecs(drive_letter, &mut records, &mut names, &mut ext_names);

    // Phase 8: clone the FRS → mft_idx mapping off the transient
    // `MftIndex` before it goes out of scope.  In the primary
    // `build_compact_index` path compact_idx == mft_idx (records
    // are produced 1:1 by `index.records.par_iter().enumerate()`),
    // so `frs_to_idx` is exactly the FRS → compact_idx mapping the
    // surgical-patch path needs.  Hardlink / ADS-expanded records
    // append at the END with the same FRS but higher compact_idx;
    // those secondary slots are not addressable from journal events
    // (USN events reference primary FRS) so the primary mapping is
    // sufficient.  `uffs_mft::NO_ENTRY == u32::MAX` matches the
    // sentinel `frs_to_compact` uses for unmapped slots.
    let mut compact_index = DriveCompactIndex {
        letter: drive_letter,
        records: ColumnStorage::from_vec(records),
        names: ColumnStorage::from_vec(names),
        trigram: Arc::new(trigram),
        children: Arc::new(children),
        ext_index: Arc::new(ext_index),
        fold,
        ext_names,
        source: IndexSource::MftFile(std::path::PathBuf::from(format!("{drive_letter}:"))),
        source_epoch: index.build_epoch,
        bloom: None,
        path_trie: None,
        frs_to_compact: index.frs_to_idx.clone(),
        // Freshly built from the MFT — base CSR indexes are authoritative,
        // no overlay yet. apply_usn_patch (Phase 2b) starts the delta.
        delta: None,
    };

    // Phase 4: populate bloom + path_trie from the freshly-built
    // index.  These are needed for the search-skip pre-check
    // (Commit F) and serialised into the v9+ cache (Commit D).
    let bloom = compact_index.build_bloom();
    let path_trie = compact_index.build_path_trie();
    compact_index.bloom = Some(bloom);
    compact_index.path_trie = Some(path_trie);

    (compact_index, compact_elapsed, tri_elapsed)
}

/// Shrink all growable Vecs to exact fit after compact index build.
///
/// Reclaims capacity slack from the doubling growth strategy used during
/// construction.  Saves ~500 MB across 7 drives.
fn shrink_compact_vecs(
    drive_letter: uffs_mft::platform::DriveLetter,
    records: &mut Vec<CompactRecord>,
    names: &mut Vec<u8>,
    ext_names: &mut Vec<Box<str>>,
) {
    let pre = records.capacity() * size_of::<CompactRecord>() + names.capacity();
    records.shrink_to_fit();
    names.shrink_to_fit();
    ext_names.shrink_to_fit();
    let post = records.capacity() * size_of::<CompactRecord>() + names.capacity();
    let reclaimed_mb = pre.saturating_sub(post) / (1024 * 1024);
    if reclaimed_mb > 0 {
        tracing::info!(
            drive = %drive_letter,
            reclaimed_mb,
            "shrink_to_fit reclaimed memory"
        );
    }
}

/// Cache TTL in seconds (4 hours — same as Windows CLI).
///
/// USN Journal handles incremental freshness; this is a safety-net full rescan.
pub(crate) const INDEX_TTL_SECONDS: u64 = 14400;

// ── Live $UpCase resolution ──────────────────────────────────────────

/// Try to read the live `$UpCase` table from the NTFS volume for
/// `drive_letter`. On success, log the result at `INFO` and any diffs
/// from the compiled-in default at `WARN`. On failure, log at `WARN`
/// and fall back to [`uffs_text::case_fold::CaseFold::default_table()`].
pub(crate) fn resolve_case_fold(
    drive_letter: uffs_mft::platform::DriveLetter,
) -> uffs_text::case_fold::CaseFold {
    let live_table = match uffs_mft::platform::upcase::read_upcase_table(drive_letter) {
        Ok(table) => table,
        Err(err) => {
            tracing::warn!(
                drive = %drive_letter,
                error = %err,
                "$UpCase live read failed — falling back to compiled-in default table"
            );
            return uffs_text::case_fold::CaseFold::default_table();
        }
    };

    // Leak the box to get a `&'static [u16]` for CaseFold::from_ntfs.
    let live_fold = uffs_text::case_fold::CaseFold::from_ntfs(Box::leak(live_table));
    log_upcase_comparison(drive_letter, &live_fold);
    live_fold
}

/// Log the comparison between live and compiled-in `$UpCase` tables.
fn log_upcase_comparison(
    drive_letter: uffs_mft::platform::DriveLetter,
    live_fold: &uffs_text::case_fold::CaseFold,
) {
    let default = uffs_text::case_fold::CaseFold::default_table();
    let diffs = default.diff(live_fold);

    if diffs.is_empty() {
        tracing::info!(
            drive = %drive_letter,
            "$UpCase loaded from live volume — identical to compiled-in default"
        );
        return;
    }

    tracing::info!(
        drive = %drive_letter,
        diff_count = diffs.len(),
        "$UpCase loaded from live volume — differs from compiled-in default"
    );
    for diff in &diffs {
        tracing::warn!(
            drive = %drive_letter,
            codepoint = format_args!("U+{:04X}", diff.codepoint),
            default = format_args!("U+{:04X}", diff.default_maps_to),
            live = format_args!("U+{:04X}", diff.live_maps_to),
            "$UpCase diff"
        );
    }
}
