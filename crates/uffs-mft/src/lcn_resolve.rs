// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Targeted MFT record reads for bulk content-read jobs.
//!
//! Resolves NTFS file references (FRS) to their on-disk physical
//! location (LCN), and streams whole fixed-up record bytes to a caller
//! callback — the read-order optimization and record-byte source for
//! `uffs-content`.
//!
//! Two public entry points share one targeted-read loop:
//!
//! * `for_each_record` — reads each requested record once, applies the NTFS
//!   Update-Sequence-Array fixup, and hands the bytes to a callback (bounded
//!   memory: two reused record-sized buffers, borrow-only delivery).
//! * `resolve_frs_to_lcn` — the original LCN-only convenience, now a thin
//!   adapter over `for_each_record`.
//!
//! Real-hardware benchmarking found that reading matched candidates in
//! whatever order a search happened to return them in (or even sorted by
//! ascending FRS, which only weakly-to-moderately correlates with
//! physical layout on a volume that's been reorganized over years — see
//! `docs/dev/architecture/content-stream-tool-design.md`) leaves most of a
//! drive's achievable seek-distance reduction on the table. Resolving
//! true LCN up front and sorting by it captures the rest.
//!
//! This lives in `uffs-mft`, not `uffs-content`/`uffs-content-reader`,
//! deliberately: `uffsd` already performs a full MFT parse to build its
//! search index (an already-open, already-broker-authorized volume
//! handle, an already-warm process) — grafting one more targeted-read
//! pass onto that is far cheaper than teaching the intentionally narrow,
//! non-elevated `uffs-content-reader` a whole new MFT-parsing capability
//! it would otherwise never need, and would require re-opening the
//! device and re-deriving everything from scratch.

#[cfg(windows)]
use std::collections::HashMap;

#[cfg(windows)]
use crate::error::Result;
#[cfg(windows)]
use crate::io::{MftExtentMap, MftRecordReader};
use crate::ntfs::{AttributeIterator, AttributeType};
use crate::platform::Lcn;
#[cfg(windows)]
use crate::platform::VolumeHandle;

/// Resolves each FRS in `frs_list` to the starting LCN of its primary
/// (unnamed) `$DATA` attribute's first real (non-sparse) data run.
///
/// `volume` must already be open against the *same device* the caller's
/// FRS values came from — a live drive letter via [`VolumeHandle::open`],
/// or (for content-read jobs, which run against a VSS snapshot)
/// [`VolumeHandle::open_device_path`]. [`VolumeHandle::get_mft_extents`]
/// depends on this distinction; opening the wrong one silently corrupts
/// every offset computed from it (see that method's own doc comment).
///
/// `None` in the returned map for a given FRS means one of: the record
/// couldn't be read (outside the MFT, transient I/O failure, corrupt at
/// a sector boundary), its `$DATA` is resident (a small file — no
/// physical location to speak of, and cheap to read regardless of
/// order), or it has no data runs at all (an empty file). Callers
/// should treat `None` as "no seek-order preference" (e.g. sort first),
/// not as an error.
///
/// `frs_list` holds **48-bit MFT record numbers**, not full 64-bit file
/// references — mask the sequence number off first
/// (`file_reference & 0x0000_FFFF_FFFF_FFFF`). The list is
/// de-duplicated and read in ascending order internally — this keeps
/// the targeted record reads this performs close to sequential within
/// `$MFT` itself, which is typically far less fragmented than the
/// volume at large, not merely for tidiness.
///
/// Record bytes are USA-fixup-verified before parsing (via
/// `for_each_record`, which this delegates to) — a torn record folds
/// to `None` instead of being parsed with sector-boundary bytes still
/// holding the update-sequence sentinel.
///
/// # Errors
/// Returns an error only if `$MFT`'s own extents can't be determined at
/// all (e.g. a bad handle). An individual record's read or parse
/// failure is folded into that FRS's `None` result, never propagated —
/// one unreadable record must not abort resolution for the rest of the
/// want-list.
#[cfg(windows)]
pub fn resolve_frs_to_lcn(
    volume: &VolumeHandle,
    frs_list: &[u64],
) -> Result<HashMap<u64, Option<Lcn>>> {
    let mut result = HashMap::with_capacity(frs_list.len());
    for_each_record(volume, frs_list, |frs, outcome| {
        result.insert(frs, outcome.bytes().and_then(first_data_lcn));
    })?;
    Ok(result)
}

/// Per-record outcome delivered to `for_each_record`'s callback.
///
/// Success carries the fixed-up bytes; the three failure variants
/// preserve *why* a record yielded no bytes, because the distinction is
/// itself a signal: a [`Self::Corrupt`] record **exists and is marked
/// torn/damaged** (forensically interesting), while [`Self::NotInMft`]
/// is a benign "no such record on this volume". Callers that only care
/// about "bytes or not" (the content service) collapse the variants via
/// [`Self::bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome<'a> {
    /// The record was read and its Update-Sequence-Array fixup
    /// verified — the full fixed-up record bytes.
    Bytes(&'a [u8]),
    /// The FRS lies outside `$MFT`'s mapped extents (or in a sparse
    /// region): no such record exists on this volume. Benign.
    NotInMft,
    /// The record's location is known but reading it failed
    /// (transient I/O error, short read). Worth a retry elsewhere.
    Io,
    /// The record was read but failed fixup verification — a torn
    /// write or corrupt sector-boundary sentinel. The record exists
    /// and is damaged; its unverified bytes are deliberately withheld.
    Corrupt,
}

impl<'a> RecordOutcome<'a> {
    /// The verified record bytes, or `None` for any non-success
    /// outcome — the "fall back to the filesystem" collapse used by
    /// callers without forensic interest.
    #[must_use]
    pub const fn bytes(self) -> Option<&'a [u8]> {
        match self {
            Self::Bytes(record) => Some(record),
            Self::NotInMft | Self::Io | Self::Corrupt => None,
        }
    }
}

/// Reads the raw MFT record for each FRS in `frs_list`, applies the NTFS
/// Update-Sequence-Array fixup, and hands the fixed-up bytes to `visit`
/// one record at a time.
///
/// This is the byte-returning generalisation of `resolve_frs_to_lcn`:
/// the same targeted, snapshot-capable read, but the caller receives the
/// whole record and derives whatever it needs (LCN, resident `$DATA`,
/// reparse target, object id, …) instead of this crate pre-parsing one
/// field.
///
/// # Memory
/// Bounded by design. Exactly **two reused record-sized buffers** exist
/// for the whole pass — the reader's internal aligned I/O buffer and
/// the fixup scratch copy — never one allocation per record. `visit`
/// receives a **borrow** valid only for the duration of that call — the
/// borrow makes accidental whole-want-list retention impossible and
/// forces the caller to copy out only the distilled bytes it keeps.
/// `frs_list` is de-duplicated and read in ascending FRS order, keeping
/// the targeted reads near-sequential within `$MFT`.
///
/// # Fixup (mandatory)
/// The fixup is applied before `visit` sees any bytes. It is not
/// hygiene: NTFS overwrites the last two bytes of every 512-byte sector
/// with an update-sequence sentinel, so any field straddling offset
/// 510–511 (a resident `$DATA` value, a runlist) reads the sentinel
/// instead of data without it. A record that fails fixup verification
/// is reported as [`RecordOutcome::Corrupt`] — its unverified bytes are
/// withheld.
///
/// # Arguments
/// * `volume` — must be open against the **same device** the FRS values came
///   from: a live drive via [`VolumeHandle::open`], or a VSS snapshot device
///   via [`VolumeHandle::open_device_path`] (the content-service case). Same
///   requirement as `resolve_frs_to_lcn`.
/// * `frs_list` — **48-bit MFT record numbers**, not full 64-bit file
///   references: mask the sequence number off first (`file_reference &
///   0x0000_FFFF_FFFF_FFFF`). A raw file reference would silently address the
///   wrong record.
/// * `visit(frs, outcome)` — called once per **distinct** FRS, in ascending
///   order, with a [`RecordOutcome`]: verified fixed-up bytes on success, or a
///   classified failure (`NotInMft` / `Io` / `Corrupt`). No failure aborts the
///   rest of the pass. Callers without forensic interest collapse it with
///   [`RecordOutcome::bytes`].
///
/// # Errors
/// Returns `Err` only if `$MFT`'s own extents can't be determined at
/// all (e.g. a bad handle) — i.e. the whole pass cannot start.
/// Per-record failures are delivered as [`RecordOutcome`] variants to
/// `visit`, never propagated.
#[cfg(windows)]
pub fn for_each_record<V: FnMut(u64, RecordOutcome<'_>)>(
    volume: &VolumeHandle,
    frs_list: &[u64],
    mut visit: V,
) -> Result<()> {
    if frs_list.is_empty() {
        return Ok(());
    }

    let extents = volume.get_mft_extents()?;
    let extent_map = MftExtentMap::new(
        extents,
        volume.volume_data().bytes_per_cluster,
        volume.volume_data().bytes_per_file_record_segment,
    );
    let mut reader = MftRecordReader::new_with_extents(extent_map);
    let handle = volume.raw_handle();

    // One scratch copy for the whole pass — records are copied into it
    // so the fixup can mutate them without touching the reader's own
    // aligned I/O buffer. No per-record allocation.
    let mut scratch: Vec<u8> = Vec::new();

    for frs in sorted_deduped(frs_list) {
        if !reader.covers(frs) {
            visit(frs, RecordOutcome::NotInMft);
            continue;
        }
        // `None` = read failed; `Some(bool)` = read succeeded, bool =
        // fixup verified. Splitting the fallible step out keeps the
        // scratch borrow out of the Result combinators.
        let read_and_fixed = reader
            .read_record(handle, frs)
            .map(|raw| fix_into_scratch(raw, &mut scratch))
            .ok();
        let outcome = match read_and_fixed {
            Some(true) => RecordOutcome::Bytes(&scratch),
            Some(false) => RecordOutcome::Corrupt,
            None => RecordOutcome::Io,
        };
        visit(frs, outcome);
    }

    Ok(())
}

/// Sorts and de-duplicates a caller's FRS want-list into the ascending
/// read order both public entry points guarantee.
#[cfg_attr(
    all(not(windows), not(test)),
    expect(
        dead_code,
        reason = "only called by for_each_record (Windows-only) outside tests"
    )
)]
fn sorted_deduped(frs_list: &[u64]) -> Vec<u64> {
    let mut sorted: Vec<u64> = frs_list.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    sorted
}

/// Copies `raw` into the reused `scratch` buffer and applies the NTFS
/// Update-Sequence-Array fixup in place.
///
/// Returns `true` when the fixup verified and `scratch` now holds the
/// fixed-up record bytes; `false` when the record is structurally
/// invalid or corrupt at a sector boundary (torn write) — callers must
/// then treat the record as unreadable and must not parse `scratch`.
///
/// Pure, cross-platform byte manipulation (no Windows dependency), kept
/// testable without Windows even though its only non-test caller,
/// `for_each_record`, is Windows-only.
#[cfg_attr(
    all(not(windows), not(test)),
    expect(
        dead_code,
        reason = "only called by for_each_record (Windows-only) outside tests"
    )
)]
fn fix_into_scratch(raw: &[u8], scratch: &mut Vec<u8>) -> bool {
    scratch.clear();
    scratch.extend_from_slice(raw);
    crate::parse::apply_fixup(scratch)
}

/// Extracts the first real `$DATA` LCN from a raw record buffer.
///
/// Finds the primary (unnamed) `$DATA` attribute and returns the
/// starting LCN of its first real (non-sparse) data run — `None` for
/// resident data, an unparseable record, or a wholly-sparse file.
///
/// Public so `for_each_record` callers can derive the LCN from the
/// record bytes they already hold — one pass yields LCN ordering *and*
/// record contents, with no second `resolve_frs_to_lcn` call and no
/// consumer-side runlist parser. Pure, cross-platform byte parsing (no
/// Windows dependency); expects fixed-up bytes (which is what
/// `for_each_record` delivers).
#[must_use]
pub fn first_data_lcn(record: &[u8]) -> Option<Lcn> {
    let attrs = AttributeIterator::new(record)?;
    let data_attr = attrs
        .filter(|attr| attr.attribute_type() == Some(AttributeType::Data))
        .find(crate::ntfs::AttributeRef::is_unnamed)?;
    if !data_attr.is_non_resident() {
        return None;
    }
    // Lazy runlist decode: stops at the first non-sparse run without
    // materialising the full runlist — this is the per-candidate LCN
    // path that runs on every content job, so it must not allocate.
    data_attr
        .data_runs_iter()
        .find(|run| !run.is_sparse())
        .map(|run| run.lcn)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::indexing_slicing,
        reason = "test code — relaxed linting for test clarity"
    )]

    use core::mem::size_of;

    use super::first_data_lcn;
    use crate::ntfs::{
        AttributeRecordHeader, FileRecordSegmentHeader, NonResidentAttributeData,
        ResidentAttributeData,
    };

    fn write_u16_le(buffer: &mut [u8], offset: usize, value: u16) {
        buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32_le(buffer: &mut [u8], offset: usize, value: u32) {
        buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_i64_le(buffer: &mut [u8], offset: usize, value: i64) {
        buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Writes a valid `FILE`-magic record header with `first_attribute_offset`
    /// right after the header and `bytes_in_use` covering through
    /// `end_marker_offset`'s 4-byte `$END` marker -- mirrors
    /// `ntfs::tests::attribute_iterator_reads_resident_attribute_value`'s
    /// header construction exactly (this crate's established byte-buffer
    /// test convention), reused here since `first_data_lcn` needs a
    /// *whole* record, not a standalone attribute slice.
    fn write_record_header(record: &mut [u8], end_marker_offset: usize) {
        let attr_offset = size_of::<FileRecordSegmentHeader>();
        record[0..4].copy_from_slice(b"FILE");
        write_u16_le(record, 20, crate::len_to_u16(attr_offset));
        write_u16_le(record, 22, 0x0001); // in-use
        write_u32_le(
            record,
            24,
            crate::len_to_u32(end_marker_offset + size_of::<AttributeRecordHeader>()),
        );
        write_u32_le(record, 28, crate::len_to_u32(record.len()));
    }

    #[test]
    fn first_data_lcn_resolves_non_resident_first_run() {
        let attr_offset = size_of::<FileRecordSegmentHeader>();
        let nr_offset = attr_offset + size_of::<AttributeRecordHeader>();
        let mapping_pairs_rel_offset =
            size_of::<AttributeRecordHeader>() + size_of::<NonResidentAttributeData>();
        let attr_len = mapping_pairs_rel_offset + 4;
        let end_marker_offset = attr_offset + attr_len;
        let mut record = vec![0_u8; end_marker_offset + size_of::<AttributeRecordHeader>()];

        write_record_header(&mut record, end_marker_offset);

        // Attribute header: unnamed, non-resident $DATA.
        write_u32_le(
            &mut record,
            attr_offset,
            crate::ntfs::AttributeType::DATA_TYPE,
        );
        write_u32_le(&mut record, attr_offset + 4, crate::len_to_u32(attr_len));
        record[attr_offset + 8] = 1; // is_non_resident
        record[attr_offset + 9] = 0; // name_length = 0 (unnamed/primary stream)
        write_u16_le(&mut record, attr_offset + 12, 0);
        write_u16_le(&mut record, attr_offset + 14, 1);

        // Non-resident header + one real (non-sparse) data run: vcn 7,
        // 5 clusters, lcn 10 -- same mapping-pairs bytes as
        // `ntfs::tests::non_resident_attribute_helpers_decode_mapping_pairs`.
        write_i64_le(&mut record, nr_offset, 7);
        write_i64_le(&mut record, nr_offset + 8, 11);
        write_u16_le(
            &mut record,
            nr_offset + 16,
            crate::len_to_u16(mapping_pairs_rel_offset),
        );
        record[nr_offset + 18] = 0;
        write_i64_le(&mut record, nr_offset + 24, 40);
        write_i64_le(&mut record, nr_offset + 32, 20);
        write_i64_le(&mut record, nr_offset + 40, 20);
        record[attr_offset + mapping_pairs_rel_offset..attr_offset + mapping_pairs_rel_offset + 4]
            .copy_from_slice(&[0x11, 0x05, 0x0A, 0x00]);

        write_u32_le(
            &mut record,
            end_marker_offset,
            crate::ntfs::AttributeType::END_MARKER,
        );

        assert_eq!(first_data_lcn(&record), Some(crate::platform::Lcn::new(10)));
    }

    #[test]
    fn first_data_lcn_returns_none_for_resident_data() {
        let attr_offset = size_of::<FileRecordSegmentHeader>();
        let attr_len = size_of::<AttributeRecordHeader>() + size_of::<ResidentAttributeData>() + 4;
        let end_marker_offset = attr_offset + attr_len;
        let mut record = vec![0_u8; end_marker_offset + size_of::<AttributeRecordHeader>()];

        write_record_header(&mut record, end_marker_offset);

        write_u32_le(
            &mut record,
            attr_offset,
            crate::ntfs::AttributeType::DATA_TYPE,
        );
        write_u32_le(&mut record, attr_offset + 4, crate::len_to_u32(attr_len));
        record[attr_offset + 8] = 0; // resident
        record[attr_offset + 9] = 0; // unnamed
        write_u16_le(&mut record, attr_offset + 12, 0);
        write_u16_le(&mut record, attr_offset + 14, 1);
        write_u32_le(&mut record, attr_offset + 16, 4); // value_length
        write_u16_le(
            &mut record,
            attr_offset + 20,
            crate::len_to_u16(
                size_of::<AttributeRecordHeader>() + size_of::<ResidentAttributeData>(),
            ),
        );
        write_u32_le(
            &mut record,
            end_marker_offset,
            crate::ntfs::AttributeType::END_MARKER,
        );

        assert_eq!(
            first_data_lcn(&record),
            None,
            "resident $DATA has no physical location -- must not be misparsed as a real run"
        );
    }

    #[test]
    fn first_data_lcn_skips_named_data_streams() {
        // Same record shape as the resident test, but the $DATA carries
        // a name (an alternate data stream) — the primary-stream lookup
        // must skip it, via the allocation-free is_unnamed() check.
        let attr_offset = size_of::<FileRecordSegmentHeader>();
        let attr_len = size_of::<AttributeRecordHeader>() + size_of::<ResidentAttributeData>() + 4;
        let end_marker_offset = attr_offset + attr_len;
        let mut record = vec![0_u8; end_marker_offset + size_of::<AttributeRecordHeader>()];

        write_record_header(&mut record, end_marker_offset);

        write_u32_le(
            &mut record,
            attr_offset,
            crate::ntfs::AttributeType::DATA_TYPE,
        );
        write_u32_le(&mut record, attr_offset + 4, crate::len_to_u32(attr_len));
        record[attr_offset + 8] = 1; // non-resident (would have runs)
        record[attr_offset + 9] = 3; // name_length = 3 → named stream
        write_u16_le(&mut record, attr_offset + 12, 0);
        write_u16_le(&mut record, attr_offset + 14, 1);
        write_u32_le(
            &mut record,
            end_marker_offset,
            crate::ntfs::AttributeType::END_MARKER,
        );

        assert_eq!(
            first_data_lcn(&record),
            None,
            "a named $DATA stream is not the primary stream and must be skipped"
        );
    }

    #[test]
    fn first_data_lcn_returns_none_when_no_data_attribute_present() {
        let attr_offset = size_of::<FileRecordSegmentHeader>();
        let end_marker_offset = attr_offset;
        let mut record = vec![0_u8; end_marker_offset + size_of::<AttributeRecordHeader>()];

        write_record_header(&mut record, end_marker_offset);
        write_u32_le(
            &mut record,
            end_marker_offset,
            crate::ntfs::AttributeType::END_MARKER,
        );

        assert_eq!(first_data_lcn(&record), None);
    }

    // ── for_each_record: fixup + ordering plumbing ───────────────────

    use super::{fix_into_scratch, sorted_deduped};

    /// Installs a valid two-sector multi-sector scaffold into a
    /// 1024-byte record buffer, exactly as it would look **on disk
    /// before fixup**: `FILE` magic, USA at offset 48 with 3 entries
    /// (check value + one saved word per sector), the check-value
    /// sentinel overwriting the last two bytes of each 512-byte sector,
    /// and the real bytes for those positions parked in the USA.
    fn write_multi_sector_scaffold(
        record: &mut [u8],
        check: u16,
        real_sector1: [u8; 2],
        real_sector2: [u8; 2],
    ) {
        assert!(record.len() >= 1024, "scaffold needs a two-sector record");
        record[0..4].copy_from_slice(b"FILE");
        write_u16_le(record, 4, 48); // usa_offset
        write_u16_le(record, 6, 3); // usa_count (check + 2 sectors)
        write_u16_le(record, 48, check);
        record[50..52].copy_from_slice(&real_sector1);
        record[52..54].copy_from_slice(&real_sector2);
        write_u16_le(record, 510, check);
        write_u16_le(record, 1022, check);
    }

    #[test]
    fn fix_into_scratch_restores_sector_boundary_bytes() {
        let mut record = vec![0_u8; 1024];
        write_multi_sector_scaffold(&mut record, 0xBEEF, [0xCD, 0xEF], [0x12, 0x34]);

        let mut scratch = Vec::new();
        assert!(
            fix_into_scratch(&record, &mut scratch),
            "valid USA must verify"
        );
        assert_eq!(scratch.len(), record.len());
        assert_eq!(
            &scratch[510..512],
            &[0xCD, 0xEF],
            "sector-1 boundary must hold the real bytes, not the sentinel"
        );
        assert_eq!(
            &scratch[1022..1024],
            &[0x12, 0x34],
            "sector-2 boundary must hold the real bytes, not the sentinel"
        );
        // The caller's raw bytes are untouched — fixup mutates only the
        // scratch copy.
        assert_eq!(u16::from_le_bytes([record[510], record[511]]), 0xBEEF);
    }

    #[test]
    fn fix_into_scratch_rejects_torn_write() {
        let mut record = vec![0_u8; 1024];
        write_multi_sector_scaffold(&mut record, 0xBEEF, [0xCD, 0xEF], [0x12, 0x34]);
        // A torn write: sector 2 was written under a different update
        // sequence, so its sentinel doesn't match the USA check value.
        write_u16_le(&mut record, 1022, 0xDEAD);

        let mut scratch = Vec::new();
        assert!(
            !fix_into_scratch(&record, &mut scratch),
            "mismatched sector sentinel is a torn write and must fail verification"
        );
    }

    #[test]
    fn fix_into_scratch_rejects_non_file_magic() {
        let mut record = vec![0_u8; 1024];
        write_multi_sector_scaffold(&mut record, 0xBEEF, [0xCD, 0xEF], [0x12, 0x34]);
        record[0..4].copy_from_slice(b"BAAD");

        let mut scratch = Vec::new();
        assert!(!fix_into_scratch(&record, &mut scratch));
    }

    #[test]
    fn record_outcome_bytes_collapses_failures_to_none() {
        use super::RecordOutcome;
        let payload = [1_u8, 2, 3];
        assert_eq!(RecordOutcome::Bytes(&payload).bytes(), Some(&payload[..]));
        assert_eq!(RecordOutcome::NotInMft.bytes(), None);
        assert_eq!(RecordOutcome::Io.bytes(), None);
        assert_eq!(RecordOutcome::Corrupt.bytes(), None);
    }

    #[test]
    fn sorted_deduped_yields_ascending_distinct_frs() {
        assert_eq!(sorted_deduped(&[5, 3, 5, 1, 3]), vec![1, 3, 5]);
        assert_eq!(sorted_deduped(&[]), Vec::<u64>::new());
    }

    /// The reason fixup is mandatory, demonstrated end-to-end: a
    /// resident `$DATA` value that straddles the sector-1 boundary
    /// (bytes 510–511) parses to the **real** content only after
    /// `fix_into_scratch` — parsed raw, those two bytes are the USA
    /// sentinel.
    #[test]
    fn resident_data_straddling_sector_boundary_needs_fixup() {
        let attr_offset = 56_usize; // 48-byte FRS header + 6-byte USA, aligned to 8
        let value_rel = size_of::<AttributeRecordHeader>() + size_of::<ResidentAttributeData>();
        let value_start = attr_offset + value_rel;
        let value_len = 516 - value_start; // value covers 510..512 and beyond
        let attr_len = value_rel + value_len;
        let end_marker_offset = attr_offset + attr_len;
        let mut record = vec![0_u8; 1024];

        // FRS header fields (same offsets as `write_record_header`, but
        // with the first attribute at 56 to leave room for the USA).
        write_u16_le(&mut record, 20, crate::len_to_u16(attr_offset));
        write_u16_le(&mut record, 22, 0x0001); // in-use
        write_u32_le(
            &mut record,
            24,
            crate::len_to_u32(end_marker_offset + size_of::<AttributeRecordHeader>()),
        );
        let record_len = record.len();
        write_u32_le(&mut record, 28, crate::len_to_u32(record_len));

        // Resident unnamed $DATA whose value spans the sector boundary.
        write_u32_le(
            &mut record,
            attr_offset,
            crate::ntfs::AttributeType::DATA_TYPE,
        );
        write_u32_le(&mut record, attr_offset + 4, crate::len_to_u32(attr_len));
        record[attr_offset + 8] = 0; // resident
        record[attr_offset + 9] = 0; // unnamed
        write_u16_le(&mut record, attr_offset + 12, 0);
        write_u16_le(&mut record, attr_offset + 14, 1);
        write_u32_le(&mut record, attr_offset + 16, crate::len_to_u32(value_len));
        write_u16_le(&mut record, attr_offset + 20, crate::len_to_u16(value_rel));
        for byte in &mut record[value_start..value_start + value_len] {
            *byte = 0xAB;
        }
        write_u32_le(
            &mut record,
            end_marker_offset,
            crate::ntfs::AttributeType::END_MARKER,
        );

        // On-disk state: the sentinel overwrites the two value bytes at
        // 510–511; the real value bytes live in the USA.
        write_multi_sector_scaffold(&mut record, 0xBEEF, [0xAB, 0xAB], [0x00, 0x00]);

        let mut scratch = Vec::new();
        assert!(fix_into_scratch(&record, &mut scratch));

        let value = crate::ntfs::AttributeIterator::new(&scratch)
            .expect("valid record header")
            .find(|attr| attr.attribute_type() == Some(crate::ntfs::AttributeType::Data))
            .expect("resident $DATA present")
            .resident_value()
            .expect("resident value slice");
        assert_eq!(value.len(), value_len);
        assert!(
            value.iter().all(|&byte| byte == 0xAB),
            "fixed-up value must hold the real bytes across the sector boundary"
        );

        // Contrast: parsed raw (no fixup), the same two bytes read the
        // USA sentinel — the corruption this API is required to prevent.
        assert!(record.len() >= 512);
        assert_eq!(
            &record[510..512],
            0xBEEF_u16.to_le_bytes().as_slice(),
            "pre-fixup bytes at the boundary are the sentinel, not data"
        );
    }

    /// Live-volume parity: `for_each_record` + [`first_data_lcn`] must
    /// reproduce `resolve_frs_to_lcn`'s exact output, with callbacks in
    /// ascending deduplicated order. Requires Windows + admin (or the
    /// Access Broker) — run with `cargo test -- --ignored` elevated.
    #[test]
    #[ignore = "requires Windows with an openable C: volume (elevated or brokered)"]
    #[cfg(windows)]
    fn for_each_record_parity_with_resolve_frs_to_lcn_live() {
        let volume =
            crate::platform::VolumeHandle::open(crate::platform::DriveLetter::C).expect("open C:");
        // Shuffled with duplicates on purpose: 0 ($MFT) and low
        // metafiles always exist; u64::MAX never does (must classify as
        // NotInMft without aborting the pass).
        let want = [16_u64, 0, 5, u64::MAX, 5, 0, 11];

        let mut seen: Vec<u64> = Vec::new();
        let mut derived = std::collections::HashMap::new();
        let mut absent_outcome = None;
        super::for_each_record(&volume, &want, |frs, outcome| {
            seen.push(frs);
            if frs == u64::MAX {
                absent_outcome = Some(outcome == super::RecordOutcome::NotInMft);
            }
            derived.insert(frs, outcome.bytes().and_then(first_data_lcn));
        })
        .expect("for_each_record");

        assert_eq!(
            seen,
            vec![0, 5, 11, 16, u64::MAX],
            "ascending + deduplicated"
        );
        assert_eq!(
            absent_outcome,
            Some(true),
            "an FRS outside the MFT classifies as NotInMft without aborting the pass"
        );

        let resolved = super::resolve_frs_to_lcn(&volume, &want).expect("resolve_frs_to_lcn");
        assert_eq!(
            derived, resolved,
            "one-pass derivation must match the LCN-only API"
        );
    }
}
