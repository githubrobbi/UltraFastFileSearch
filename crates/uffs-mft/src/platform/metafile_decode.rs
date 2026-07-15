// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Offline decoders for captured NTFS metafiles.
//!
//! The reconstitute / validate side of the capture flow — pure, cross-platform
//! byte parsing (no live volume or Windows I/O), so it runs on the transfer
//! target (macOS/Linux) too.

use super::metafile::{MetafileHeader, MetafileKind};
use crate::error::{MftError, Result};

/// Volume geometry decoded from a captured `$Boot` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootGeometry {
    /// Bytes per sector.
    pub bytes_per_sector: u16,
    /// Sectors per cluster.
    pub sectors_per_cluster: u8,
    /// Cluster size in bytes.
    pub bytes_per_cluster: u32,
    /// MFT file-record size in bytes.
    pub mft_record_size: u32,
    /// Total sectors on the volume.
    pub total_sectors: u64,
    /// Logical cluster number of `$MFT`.
    pub mft_start_lcn: u64,
    /// Volume serial number.
    pub volume_serial: u64,
}

/// Decode the NTFS volume geometry from a captured `$Boot` payload.
///
/// # Errors
///
/// Returns [`MftError::InvalidData`] if the payload is too small or is not a
/// valid NTFS boot sector.
pub fn parse_boot(payload: &[u8]) -> Result<BootGeometry> {
    use zerocopy::FromBytes as _;

    let (boot, _) = crate::ntfs::NtfsBootSector::read_from_prefix(payload)
        .map_err(|_err| MftError::InvalidData("$Boot payload too small".to_owned()))?;
    if !boot.is_valid() {
        return Err(MftError::InvalidData(
            "payload is not a valid NTFS boot sector".to_owned(),
        ));
    }
    Ok(BootGeometry {
        bytes_per_sector: boot.bytes_per_sector,
        sectors_per_cluster: boot.sectors_per_cluster,
        bytes_per_cluster: boot.cluster_size(),
        mft_record_size: boot.file_record_size(),
        total_sectors: boot.total_sectors.cast_unsigned(),
        mft_start_lcn: boot.mft_start_lcn.cast_unsigned(),
        volume_serial: boot.volume_serial_number.cast_unsigned(),
    })
}

/// Cluster-allocation stats decoded from a captured `$Bitmap` payload.
#[expect(
    clippy::struct_field_names,
    reason = "the `_clusters` suffix documents the unit in this public stats struct"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitmapStats {
    /// Total clusters covered by the bitmap (one bit each).
    pub total_clusters: u64,
    /// Allocated (in-use) clusters — the set bits.
    pub used_clusters: u64,
    /// Free clusters — the clear bits.
    pub free_clusters: u64,
}

/// Decode cluster-allocation stats from a captured `$Bitmap` payload.
///
/// Each bit maps one cluster (1 = allocated). Trailing padding bits in the last
/// byte read as free, matching how NTFS rounds the bitmap up to a byte.
#[must_use]
pub fn parse_bitmap(payload: &[u8]) -> BitmapStats {
    let used: u64 = payload
        .iter()
        .map(|byte| u64::from(byte.count_ones()))
        .sum();
    let total = u64::try_from(payload.len()).unwrap_or(0).saturating_mul(8);
    BitmapStats {
        total_clusters: total,
        used_clusters: used,
        free_clusters: total.saturating_sub(used),
    }
}

/// Read a little-endian `u16` at `off`, or `None` if out of bounds.
fn rd_u16(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)
        .and_then(|slice| slice.try_into().ok())
        .map(u16::from_le_bytes)
}

/// Read a little-endian `u32` at `off`, or `None` if out of bounds.
fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_le_bytes)
}

/// Read a little-endian `i64` at `off`, or `None` if out of bounds.
fn rd_i64(buf: &[u8], off: usize) -> Option<i64> {
    buf.get(off..off + 8)
        .and_then(|slice| slice.try_into().ok())
        .map(i64::from_le_bytes)
}

/// Read a little-endian `u64` at `off`, or `None` if out of bounds.
fn rd_u64(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_le_bytes)
}

/// Parse an `$ATTRIBUTE_LIST` payload and return the distinct MFT FRS numbers
/// of the records holding the `$DATA` attribute named `stream_name`.
///
/// NTFS moves attributes into extension records (referenced by
/// `$ATTRIBUTE_LIST`) when a file's base record overflows — as happens for the
/// named `$DATA` streams `$Secure:$SDS` and `$UsnJrnl:$J`. Pure/testable.
#[must_use]
pub fn attribute_list_data_frs(list: &[u8], stream_name: &str) -> Vec<u64> {
    /// NTFS `$DATA` attribute type code.
    const DATA_TYPE: u32 = 0x80;
    /// Minimum `$ATTRIBUTE_LIST` entry size (fixed header before the name).
    const MIN_ENTRY: usize = 0x1A;

    let mut out: Vec<u64> = Vec::new();
    let mut pos = 0_usize;
    while pos + MIN_ENTRY <= list.len() {
        let entry_len = usize::from(rd_u16(list, pos + 4).unwrap_or(0));
        if entry_len < MIN_ENTRY {
            break;
        }
        if rd_u32(list, pos).unwrap_or(0) == DATA_TYPE {
            let name_len = usize::from(*list.get(pos + 6).unwrap_or(&0)); // UTF-16 units
            let name_off = usize::from(*list.get(pos + 7).unwrap_or(&0));
            let name = list
                .get(pos + name_off..pos + name_off + name_len * 2)
                .map(decode_utf16_name)
                .unwrap_or_default();
            if name == stream_name
                && let Some(base_ref) = rd_u64(list, pos + 0x10)
            {
                let frs = crate::ntfs::file_reference_to_frs(base_ref);
                if !out.contains(&frs) {
                    out.push(frs);
                }
            }
        }
        pos = pos.saturating_add(entry_len);
    }
    out
}

/// Decode UTF-16LE bytes naming an NTFS file/stream through the crate's
/// shared, malformed-name-safe decoder (Category 4, WI-4.1) — the same
/// [`crate::io::parser::unified::decode_name_u16`] every live-MFT name
/// decode uses, so a captured `$ATTRIBUTE_LIST`/`$UsnJrnl:$J` payload gets
/// identical surrogate handling instead of `String::from_utf16_lossy`'s
/// silent substitution. Discards the replacement count: these offline
/// decoders have no `LOSSY_NAME_COUNT`-style telemetry sink of their own.
fn decode_utf16_name(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    crate::io::parser::unified::decode_name_u16(&units).0
}

/// One decoded USN change-journal record (the surfaced fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnEntry {
    /// USN of this record.
    pub usn: i64,
    /// Change-reason bitmask (`USN_REASON_*`).
    pub reason: u32,
    /// Affected file/dir name.
    pub name: String,
}

/// Summary of a captured `$UsnJrnl:$J` change-journal payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnSummary {
    /// Number of USN records parsed.
    pub record_count: u64,
    /// First (oldest) USN seen, or 0 when empty.
    pub first_usn: i64,
    /// Last (newest) USN seen, or 0 when empty.
    pub last_usn: i64,
    /// Up to [`USN_SAMPLE_MAX`] leading records, for a quick look.
    pub sample: Vec<UsnEntry>,
}

/// Maximum sample records surfaced from a `$UsnJrnl:$J` payload.
pub const USN_SAMPLE_MAX: usize = 8;

/// Decode a `$UsnJrnl:$J` payload into a record count + a small sample.
///
/// Skips the leading sparse region, then walks `USN_RECORD_V2`/`V3` records
/// (8-byte-aligned; a zero / sub-header `RecordLength` marks a gap).
#[must_use]
pub fn parse_usn(payload: &[u8]) -> UsnSummary {
    // Skip the leading sparse (all-zero) region to the first record, aligned
    // down to an 8-byte boundary.
    let mut pos = payload
        .iter()
        .position(|&byte| byte != 0)
        .map_or(payload.len(), |idx| idx & !0b111);
    let mut summary = UsnSummary {
        record_count: 0,
        first_usn: 0,
        last_usn: 0,
        sample: Vec::new(),
    };

    while pos + 0x3C <= payload.len() {
        let Some(record) = payload.get(pos..) else {
            break;
        };
        let rec_len = rd_u32(record, 0).unwrap_or(0) as usize;
        let major = rd_u16(record, 4).unwrap_or(0);
        let minor = rd_u16(record, 6).unwrap_or(0xFFFF);
        if !(0x3C..=0x400).contains(&rec_len) || minor != 0 || (major != 2 && major != 3) {
            pos += 8; // sparse gap / alignment padding
            continue;
        }
        if pos + rec_len > payload.len() {
            break;
        }
        let usn = rd_i64(record, 0x18).unwrap_or(0);
        // A USN is the record's byte offset in the journal, so it is always
        // positive and 8-byte aligned. A misaligned/negative value means we
        // walked into stale or padding bytes rather than a real record.
        if usn <= 0 || (usn & 0b111) != 0 {
            pos += 8;
            continue;
        }
        let reason = rd_u32(record, 0x28).unwrap_or(0);
        let name_len = usize::from(rd_u16(record, 0x38).unwrap_or(0));
        let name_off = usize::from(rd_u16(record, 0x3A).unwrap_or(0));

        if summary.record_count == 0 {
            summary.first_usn = usn;
        }
        summary.last_usn = usn;
        if summary.sample.len() < USN_SAMPLE_MAX {
            let name = record
                .get(name_off..name_off + name_len)
                .map(decode_utf16_name)
                .unwrap_or_default();
            summary.sample.push(UsnEntry { usn, reason, name });
        }
        summary.record_count += 1;
        pos += (rec_len + 7) & !0b111; // advance to the next 8-aligned record
    }
    summary
}

/// A human-readable summary of a captured metafile (its header, plus
/// kind-specific detail such as `$Boot` geometry).
#[must_use]
pub fn summarize(header: &MetafileHeader, payload: &[u8]) -> String {
    let base = format!(
        "Metafile:  {}\n  Drive:   {}:\n  Serial:  0x{:016X}\n  Captured (epoch s): {}\n  Payload: {} bytes\n",
        header.kind.name(),
        header.drive,
        header.volume_serial,
        header.timestamp,
        payload.len(),
    );
    let detail = match header.kind {
        MetafileKind::Boot => match parse_boot(payload) {
            Ok(geo) => format!(
                "  $Boot:   {} B/sector x {} sec/clu = {} B/cluster; MFT rec {} B; MFT LCN {}; total sectors {}\n",
                geo.bytes_per_sector,
                geo.sectors_per_cluster,
                geo.bytes_per_cluster,
                geo.mft_record_size,
                geo.mft_start_lcn,
                geo.total_sectors,
            ),
            Err(err) => format!("  $Boot parse failed: {err}\n"),
        },
        MetafileKind::Bitmap => {
            let stats = parse_bitmap(payload);
            format!(
                "  $Bitmap: {} clusters total, {} used, {} free\n",
                stats.total_clusters, stats.used_clusters, stats.free_clusters,
            )
        }
        MetafileKind::UsnJrnl => {
            let usn = parse_usn(payload);
            let lines: Vec<String> = usn
                .sample
                .iter()
                .map(|entry| {
                    format!(
                        "    usn {} reason 0x{:08X} {}",
                        entry.usn, entry.reason, entry.name
                    )
                })
                .collect();
            let body = if lines.is_empty() {
                String::new()
            } else {
                format!("{}\n", lines.join("\n"))
            };
            format!(
                "  $UsnJrnl: {} records; USN {}..{}\n{body}",
                usn.record_count, usn.first_usn, usn.last_usn,
            )
        }
        MetafileKind::Secure
        | MetafileKind::AttrDef
        | MetafileKind::MftMirr
        | MetafileKind::Volume
        | MetafileKind::BadClus
        | MetafileKind::LogFile => String::new(),
    };
    format!("{base}{detail}")
}

#[cfg(test)]
mod tests {
    use super::{attribute_list_data_frs, parse_bitmap, parse_boot, parse_usn};

    #[test]
    #[expect(
        clippy::indexing_slicing,
        reason = "test builds a fixed 512-byte boot sector with known in-bounds offsets"
    )]
    fn parse_boot_decodes_geometry() {
        let mut boot = vec![0_u8; 512];
        boot[3..7].copy_from_slice(b"NTFS"); // oem_id
        boot[11..13].copy_from_slice(&512_u16.to_le_bytes()); // bytes_per_sector
        boot[13] = 8; // sectors_per_cluster
        boot[40..48].copy_from_slice(&1_000_000_i64.to_le_bytes()); // total_sectors
        boot[48..56].copy_from_slice(&786_432_i64.to_le_bytes()); // mft_start_lcn
        boot[64] = (-10_i8).cast_unsigned(); // clusters_per_file_record → 2^10 = 1024
        boot[72..80].copy_from_slice(&0x1122_3344_5566_7788_i64.to_le_bytes()); // serial

        let geo = parse_boot(&boot).expect("valid boot sector");
        assert_eq!(geo.bytes_per_sector, 512);
        assert_eq!(geo.sectors_per_cluster, 8);
        assert_eq!(geo.bytes_per_cluster, 4096);
        assert_eq!(geo.mft_record_size, 1024);
        assert_eq!(geo.total_sectors, 1_000_000);
        assert_eq!(geo.mft_start_lcn, 786_432);
        assert_eq!(geo.volume_serial, 0x1122_3344_5566_7788);

        // Not a boot sector → error.
        parse_boot(&[0_u8; 512]).unwrap_err();
    }

    #[test]
    fn parse_bitmap_counts_clusters() {
        // 0xFF = 8 set, 0x00 = 0 set, 0x0F = 4 set → 12 used / 12 free of 24.
        let stats = parse_bitmap(&[0xFF, 0x00, 0x0F]);
        assert_eq!(stats.total_clusters, 24);
        assert_eq!(stats.used_clusters, 12);
        assert_eq!(stats.free_clusters, 12);

        let empty = parse_bitmap(&[]);
        assert_eq!(empty.total_clusters, 0);
        assert_eq!(empty.free_clusters, 0);
    }

    #[test]
    #[expect(
        clippy::indexing_slicing,
        reason = "test builds a fixed USN_RECORD_V2 buffer with known in-bounds offsets"
    )]
    fn parse_usn_reads_records() {
        let name: Vec<u16> = "a.txt".encode_utf16().collect(); // 5 units → 10 bytes
        let name_bytes = u16::try_from(name.len() * 2).unwrap_or(0);
        let rec_len = 0x3C + name.len() * 2; // header + name = 70
        let padded = (rec_len + 7) & !7; // 72
        let base = 16_usize; // 16 leading sparse zero bytes
        let mut buf = vec![0_u8; base + padded];

        buf[base..base + 4].copy_from_slice(&u32::try_from(rec_len).unwrap_or(0).to_le_bytes());
        buf[base + 4..base + 6].copy_from_slice(&2_u16.to_le_bytes()); // major version
        buf[base + 0x18..base + 0x20].copy_from_slice(&1000_i64.to_le_bytes()); // usn
        buf[base + 0x28..base + 0x2C].copy_from_slice(&1_u32.to_le_bytes()); // reason
        buf[base + 0x38..base + 0x3A].copy_from_slice(&name_bytes.to_le_bytes()); // name_len
        buf[base + 0x3A..base + 0x3C].copy_from_slice(&0x3C_u16.to_le_bytes()); // name_off
        for (i, unit) in name.iter().enumerate() {
            let off = base + 0x3C + i * 2;
            buf[off..off + 2].copy_from_slice(&unit.to_le_bytes());
        }

        let summary = parse_usn(&buf);
        assert_eq!(summary.record_count, 1);
        assert_eq!(summary.first_usn, 1000);
        assert_eq!(summary.last_usn, 1000);
        assert_eq!(summary.sample.len(), 1);
        assert_eq!(summary.sample[0].name, "a.txt");
        assert_eq!(summary.sample[0].reason, 1);

        // Empty / all-sparse payload → no records.
        assert_eq!(parse_usn(&[0_u8; 64]).record_count, 0);
    }

    #[test]
    #[expect(
        clippy::indexing_slicing,
        reason = "test builds fixed USN records with known in-bounds offsets"
    )]
    fn parse_usn_rejects_misaligned_usn() {
        // One valid V2 record (usn 800, 8-aligned) followed by a well-formed
        // header whose USN is misaligned (804) — stale bytes, not a real record.
        let rec_len = 0x3C_usize; // header-only record
        let mut buf = vec![0_u8; rec_len * 2];

        // Valid record at offset 0.
        buf[0..4].copy_from_slice(&u32::try_from(rec_len).unwrap_or(0).to_le_bytes());
        buf[4..6].copy_from_slice(&2_u16.to_le_bytes()); // major
        buf[0x18..0x20].copy_from_slice(&800_i64.to_le_bytes()); // usn (8-aligned)

        // Garbage "record" at offset rec_len: plausible header, misaligned usn.
        let garbage = rec_len;
        buf[garbage..garbage + 4]
            .copy_from_slice(&u32::try_from(rec_len).unwrap_or(0).to_le_bytes());
        buf[garbage + 4..garbage + 6].copy_from_slice(&2_u16.to_le_bytes());
        buf[garbage + 0x18..garbage + 0x20].copy_from_slice(&804_i64.to_le_bytes()); // usn & 7 == 4

        let summary = parse_usn(&buf);
        assert_eq!(summary.record_count, 1);
        assert_eq!(summary.first_usn, 800);
        assert_eq!(summary.last_usn, 800);
    }

    #[test]
    #[expect(
        clippy::indexing_slicing,
        reason = "test builds a fixed $ATTRIBUTE_LIST entry with known in-bounds offsets"
    )]
    fn attribute_list_finds_data_extension_frs() {
        // One entry: $DATA (0x80), name "$SDS", base ref → FRS 100.
        let name: Vec<u16> = "$SDS".encode_utf16().collect(); // 4 units → 8 bytes
        let name_off = 0x1A_usize;
        let entry_len = (name_off + name.len() * 2 + 7) & !7; // 8-aligned
        let mut list = vec![0_u8; entry_len];
        list[0..4].copy_from_slice(&0x80_u32.to_le_bytes()); // type = $DATA
        list[4..6].copy_from_slice(&u16::try_from(entry_len).unwrap_or(0).to_le_bytes());
        list[6] = 4; // name length (units)
        list[7] = u8::try_from(name_off).unwrap_or(0); // name offset
        list[0x10..0x18].copy_from_slice(&100_u64.to_le_bytes()); // base file reference → FRS 100
        for (i, unit) in name.iter().enumerate() {
            let off = name_off + i * 2;
            list[off..off + 2].copy_from_slice(&unit.to_le_bytes());
        }

        assert_eq!(attribute_list_data_frs(&list, "$SDS"), vec![100]);
        assert_eq!(attribute_list_data_frs(&list, "$J"), Vec::<u64>::new());
    }
}
