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
        MetafileKind::Secure
        | MetafileKind::AttrDef
        | MetafileKind::MftMirr
        | MetafileKind::Volume
        | MetafileKind::BadClus
        | MetafileKind::LogFile
        | MetafileKind::UsnJrnl => String::new(),
    };
    format!("{base}{detail}")
}

#[cfg(test)]
mod tests {
    use super::{parse_bitmap, parse_boot};

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
}
