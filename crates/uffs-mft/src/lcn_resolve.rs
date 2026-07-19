// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Resolves NTFS file references (FRS) to their on-disk physical
//! location (LCN) — the read-order optimization for bulk content-read
//! jobs (`uffs-content`).
//!
//! Real-hardware benchmarking found that reading matched candidates in
//! whatever order a search happened to return them in (or even sorted by
//! ascending FRS, which only weakly-to-moderately correlates with
//! physical layout on a volume that's been reorganized over years — see
//! `docs/architecture/content-stream-tool-design.md`) leaves most of a
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
/// couldn't be read (outside the MFT, transient I/O failure), its
/// `$DATA` is resident (a small file — no physical location to speak
/// of, and cheap to read regardless of order), or it has no data runs
/// at all (an empty file). Callers should treat `None` as "no seek-order
/// preference" (e.g. sort first), not as an error.
///
/// `frs_list` is de-duplicated and read in ascending order internally —
/// this keeps the targeted record reads this performs close to
/// sequential within `$MFT` itself, which is typically far less
/// fragmented than the volume at large, not merely for tidiness.
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
    if frs_list.is_empty() {
        return Ok(result);
    }

    let extents = volume.get_mft_extents()?;
    let extent_map = MftExtentMap::new(
        extents,
        volume.volume_data().bytes_per_cluster,
        volume.volume_data().bytes_per_file_record_segment,
    );
    let mut reader = MftRecordReader::new_with_extents(extent_map);
    let handle = volume.raw_handle();

    let mut sorted: Vec<u64> = frs_list.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    for frs in sorted {
        let lcn = reader
            .read_record(handle, frs)
            .ok()
            .and_then(first_data_lcn);
        result.insert(frs, lcn);
    }

    Ok(result)
}

/// Finds the primary (unnamed) `$DATA` attribute in a raw record buffer
/// and returns the starting LCN of its first real (non-sparse) data run
/// — `None` for resident data, an unparseable record, or a wholly-sparse
/// file.
///
/// Pure, cross-platform byte parsing (no Windows dependency), kept
/// testable without Windows even though its only non-test caller,
/// `resolve_frs_to_lcn` (Windows-only — not in scope on this platform's
/// rustdoc build), is Windows-only.
#[cfg_attr(
    all(not(windows), not(test)),
    expect(
        dead_code,
        reason = "only called by resolve_frs_to_lcn (Windows-only) outside tests"
    )
)]
fn first_data_lcn(record: &[u8]) -> Option<Lcn> {
    let attrs = AttributeIterator::new(record)?;
    let data_attr = attrs
        .filter(|attr| attr.attribute_type() == Some(AttributeType::Data))
        .find(|attr| attr.name().is_none())?;
    if !data_attr.is_non_resident() {
        return None;
    }
    data_attr
        .data_runs()
        .into_iter()
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
}
