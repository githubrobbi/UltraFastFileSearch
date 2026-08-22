// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Extent mapping helpers for fragmented MFT layouts.

use tracing::{debug, info};

use crate::platform::MftExtent;

/// Maps Virtual Cluster Numbers (VCN) to Logical Cluster Numbers (LCN).
///
/// The MFT can be fragmented across multiple non-contiguous extents on disk.
/// This struct provides efficient lookup to find the physical location of any
/// MFT record.
#[derive(Debug, Clone)]
#[expect(
    clippy::partial_pub_fields,
    reason = "extents is private for invariant protection; cluster/record sizes are read by I/O readers"
)]
pub struct MftExtentMap {
    /// Sorted list of extents (by VCN).
    extents: Vec<MftExtent>,
    /// Bytes per cluster.
    pub bytes_per_cluster: u32,
    /// Bytes per file record.
    pub bytes_per_record: u32,
}

impl MftExtentMap {
    /// Creates a new extent map from a list of extents.
    ///
    /// # Arguments
    ///
    /// * `extents` - List of MFT extents from `FSCTL_GET_RETRIEVAL_POINTERS`
    /// * `bytes_per_cluster` - Cluster size in bytes
    /// * `bytes_per_record` - File record size in bytes
    #[must_use]
    pub fn new(extents: Vec<MftExtent>, bytes_per_cluster: u32, bytes_per_record: u32) -> Self {
        let total_clusters: u64 = extents.iter().map(|ext| ext.cluster_count).sum();
        let records_per_cluster = bytes_per_cluster / bytes_per_record;
        let total_records = total_clusters * u64::from(records_per_cluster);
        let total_size_mb = bytes_to_mb(total_clusters * u64::from(bytes_per_cluster));

        log_extent_layout(&extents, total_clusters, total_records, total_size_mb);

        Self {
            extents,
            bytes_per_cluster,
            bytes_per_record,
        }
    }

    /// Creates a simple extent map for a contiguous MFT.
    ///
    /// This is a fallback when extent information is not available.
    #[must_use]
    pub fn contiguous(
        mft_start_lcn: u64,
        mft_size_bytes: u64,
        bytes_per_cluster: u32,
        bytes_per_record: u32,
    ) -> Self {
        let cluster_count = mft_size_bytes.div_ceil(u64::from(bytes_per_cluster));
        let total_records = mft_size_bytes / u64::from(bytes_per_record);
        let mft_size_mb = bytes_to_mb(mft_size_bytes);

        info!(
            mft_start_lcn,
            cluster_count,
            total_records,
            mft_size_mb = format!("{:.2}", mft_size_mb),
            "📁 Creating contiguous MFT extent map (fallback)"
        );

        Self {
            extents: vec![MftExtent {
                vcn: 0,
                cluster_count,
                lcn: crate::platform::Lcn::new(mft_start_lcn.cast_signed()),
            }],
            bytes_per_cluster,
            bytes_per_record,
        }
    }

    /// Returns the physical byte offset for a given File Record Segment number.
    ///
    /// # Arguments
    ///
    /// * `frs` - The File Record Segment number
    ///
    /// # Returns
    ///
    /// `Some(offset)` if the FRS is within the mapped extents,
    /// `None` if the FRS is outside the MFT or in a sparse region.
    #[must_use]
    pub fn physical_offset(&self, frs: u64) -> Option<u64> {
        // Calculate the byte offset within the MFT (virtual offset)
        let virtual_byte_offset = frs * u64::from(self.bytes_per_record);

        // Calculate the VCN containing this record
        let vcn = virtual_byte_offset / u64::from(self.bytes_per_cluster);

        // Find the extent containing this VCN
        let extent = self.find_extent(vcn)?;

        // Check for sparse extent
        if extent.lcn.is_hole() {
            return None;
        }

        // Calculate offset within the extent
        let vcn_offset = vcn - extent.vcn;
        let cluster_byte_offset = vcn_offset * u64::from(self.bytes_per_cluster);

        // Calculate offset within the cluster
        let offset_in_cluster = virtual_byte_offset % u64::from(self.bytes_per_cluster);

        // Physical offset = LCN * bytes_per_cluster + offset within extent + offset in
        // cluster
        let physical = extent.lcn.raw_unsigned() * u64::from(self.bytes_per_cluster)
            + cluster_byte_offset
            + offset_in_cluster;

        Some(physical)
    }

    /// Finds the extent containing a given VCN.
    fn find_extent(&self, vcn: u64) -> Option<&MftExtent> {
        // Binary search for the extent
        let idx = self
            .extents
            .binary_search_by(|extent| {
                if vcn < extent.vcn {
                    core::cmp::Ordering::Greater
                } else if vcn >= extent.vcn + extent.cluster_count {
                    core::cmp::Ordering::Less
                } else {
                    core::cmp::Ordering::Equal
                }
            })
            .ok()?;

        self.extents.get(idx)
    }

    /// Returns the number of extents in the map.
    #[must_use]
    pub const fn extent_count(&self) -> usize {
        self.extents.len()
    }

    /// Returns true if the MFT is fragmented (more than one extent).
    #[must_use]
    pub const fn is_fragmented(&self) -> bool {
        self.extents.len() > 1
    }

    /// Returns an iterator over the extents.
    pub fn extents(&self) -> impl Iterator<Item = &MftExtent> {
        self.extents.iter()
    }

    /// Returns the total size of the MFT in bytes.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.extents
            .iter()
            .map(|ext| ext.cluster_count * u64::from(self.bytes_per_cluster))
            .sum()
    }

    /// Returns the total number of records in the MFT.
    #[must_use]
    pub fn total_records(&self) -> u64 {
        self.total_size() / u64::from(self.bytes_per_record)
    }

    /// Plan the physically contiguous reads that cover every allocated
    /// record up to `total_records`, splitting each extent into pieces of
    /// at most `chunk_bytes` (rounded down to a whole-record multiple).
    ///
    /// This is the pure planning half of the offset-read fallback
    /// (`io::readers::offset_fallback`): the reader walks the plan and
    /// issues one `OVERLAPPED`-offset read per entry, which works on any
    /// handle kind — including the Access Broker's `FILE_FLAG_OVERLAPPED`
    /// duplicates, where an IOCP association is a one-shot per file
    /// object and the synchronous `SetFilePointerEx` readers fail
    /// outright.  Kept on `MftExtentMap` (compiled on every platform) so
    /// the extent/chunk/FRS boundary math is pinned by host unit tests.
    ///
    /// Sparse extents (LCN holes) have no physical bytes and are
    /// skipped; the FRS numbering of later extents follows their VCN, so
    /// records after a hole keep their correct record numbers.  A
    /// `chunk_bytes` smaller than one record yields an empty plan.
    #[must_use]
    pub fn read_plan(&self, chunk_bytes: u64, total_records: u64) -> Vec<PlannedRead> {
        let record_size = u64::from(self.bytes_per_record);
        let cluster_size = u64::from(self.bytes_per_cluster);
        // Whole-record chunks keep every read record-aligned (and, since
        // records are 512-byte multiples, sector-aligned for volume I/O).
        let chunk = (chunk_bytes / record_size) * record_size;
        if chunk == 0 || record_size == 0 {
            return Vec::new();
        }
        let virtual_end = total_records.saturating_mul(record_size);

        let mut plan = Vec::new();
        for extent in &self.extents {
            if extent.lcn.is_hole() {
                continue;
            }
            let virtual_start = extent.vcn.saturating_mul(cluster_size);
            if virtual_start >= virtual_end {
                break;
            }
            let extent_bytes = extent
                .cluster_count
                .saturating_mul(cluster_size)
                .min(virtual_end - virtual_start);
            let physical_start = extent.lcn.raw_unsigned().saturating_mul(cluster_size);

            let mut offset = 0_u64;
            while offset < extent_bytes {
                let byte_len = chunk.min(extent_bytes - offset);
                plan.push(PlannedRead {
                    volume_offset: physical_start + offset,
                    byte_len,
                    base_frs: (virtual_start + offset) / record_size,
                });
                offset += byte_len;
            }
        }
        plan
    }
}

/// One physically contiguous read planned by [`MftExtentMap::read_plan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedRead {
    /// Absolute volume byte offset the read starts at.
    pub volume_offset: u64,
    /// Number of bytes to read — a whole-record multiple in every
    /// standard NTFS geometry (cluster size a multiple of the 1 KiB
    /// record size); the reader floors to whole records regardless.
    pub byte_len: u64,
    /// File Record Segment number of the first record in this read.
    pub base_frs: u64,
}

/// Log MFT extent layout — fragmentation analysis for diagnostics.
fn log_extent_layout(
    extents: &[MftExtent],
    total_clusters: u64,
    total_records: u64,
    total_size_mb: f64,
) {
    let num_extents = extents.len();

    if num_extents > 1 {
        let sparse_extents = extents.iter().filter(|ext| ext.lcn.is_hole()).count();
        info!(
            extents = num_extents,
            sparse_extents,
            total_clusters,
            total_records,
            mft_size_mb = format!("{:.2}", total_size_mb),
            "⚠️  MFT is fragmented"
        );
        log_extent_details(extents);
    } else {
        info!(
            total_clusters,
            total_records,
            mft_size_mb = format!("{:.2}", total_size_mb),
            "✅ MFT is contiguous (single extent)"
        );
    }
}

/// Log per-extent details at debug level.
fn log_extent_details(extents: &[MftExtent]) {
    for (idx, ext) in extents.iter().enumerate() {
        let sparse_label = if ext.lcn.is_hole() { " (SPARSE)" } else { "" };
        debug!(
            extent = idx,
            vcn = ext.vcn,
            lcn = %ext.lcn,
            clusters = ext.cluster_count,
            is_sparse = ext.lcn.is_hole(),
            "  Extent {idx}: VCN {} → LCN {}, {} clusters{sparse_label}",
            ext.vcn,
            ext.lcn,
            ext.cluster_count,
        );
    }
}

/// Convert bytes to megabytes as `f64` for human-readable display.
fn bytes_to_mb(bytes: u64) -> f64 {
    crate::index::bytes_to_mb_f64(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extent_map_contiguous() {
        let map = MftExtentMap::contiguous(100, 1024 * 1024, 4096, 1024);

        assert_eq!(map.physical_offset(0), Some(409_600));
        assert_eq!(map.physical_offset(1), Some(410_624));
        assert_eq!(map.physical_offset(4), Some(413_696));
    }

    #[test]
    fn extent_map_fragmented() {
        let extents = vec![
            MftExtent {
                vcn: 0,
                cluster_count: 10,
                lcn: crate::platform::Lcn::new(100),
            },
            MftExtent {
                vcn: 10,
                cluster_count: 10,
                lcn: crate::platform::Lcn::new(500),
            },
        ];
        let map = MftExtentMap::new(extents, 4096, 1024);

        assert_eq!(map.physical_offset(0), Some(100 * 4096));
        assert_eq!(map.physical_offset(40), Some(500 * 4096));
        assert_eq!(map.physical_offset(44), Some(500 * 4096 + 4096));
    }

    #[test]
    fn read_plan_contiguous_splits_into_chunks() {
        // 1 MiB MFT at LCN 100, 4 KiB clusters, 1 KiB records → 1024
        // records.  512 KiB chunks → exactly two reads.
        let map = MftExtentMap::contiguous(100, 1024 * 1024, 4096, 1024);
        let plan = map.read_plan(512 * 1024, 1024);

        assert_eq!(plan, vec![
            PlannedRead {
                volume_offset: 100 * 4096,
                byte_len: 512 * 1024,
                base_frs: 0,
            },
            PlannedRead {
                volume_offset: 100 * 4096 + 512 * 1024,
                byte_len: 512 * 1024,
                base_frs: 512,
            },
        ]);
    }

    #[test]
    fn read_plan_clamps_to_total_records() {
        // Map covers 1024 records but the volume says only 700 exist:
        // the plan must stop at the 700-record boundary, mid-extent.
        let map = MftExtentMap::contiguous(100, 1024 * 1024, 4096, 1024);
        let plan = map.read_plan(512 * 1024, 700);

        let total_bytes: u64 = plan.iter().map(|read| read.byte_len).sum();
        assert_eq!(total_bytes, 700 * 1024);
        let last = plan.last().copied();
        assert_eq!(
            last.map(|read| read.base_frs + read.byte_len / 1024),
            Some(700)
        );
    }

    #[test]
    fn read_plan_fragmented_keeps_frs_continuity() {
        // Two extents with a VCN gap covered by neither would be a hole;
        // here they are VCN-adjacent but physically scattered — FRS
        // numbering must follow VCN across the physical jump.
        let extents = vec![
            MftExtent {
                vcn: 0,
                cluster_count: 10,
                lcn: crate::platform::Lcn::new(100),
            },
            MftExtent {
                vcn: 10,
                cluster_count: 10,
                lcn: crate::platform::Lcn::new(500),
            },
        ];
        // 4 KiB clusters, 1 KiB records → 4 records/cluster, 40 records
        // per extent, 80 total.  Big chunk → one read per extent.
        let map = MftExtentMap::new(extents, 4096, 1024);
        let plan = map.read_plan(8 * 1024 * 1024, 80);

        assert_eq!(plan, vec![
            PlannedRead {
                volume_offset: 100 * 4096,
                byte_len: 10 * 4096,
                base_frs: 0,
            },
            PlannedRead {
                volume_offset: 500 * 4096,
                byte_len: 10 * 4096,
                base_frs: 40,
            },
        ]);
    }

    #[test]
    fn read_plan_skips_sparse_extents_but_keeps_later_frs() {
        let extents = vec![
            MftExtent {
                vcn: 0,
                cluster_count: 10,
                lcn: crate::platform::Lcn::new(100),
            },
            MftExtent {
                vcn: 10,
                cluster_count: 10,
                lcn: crate::platform::Lcn::HOLE,
            },
            MftExtent {
                vcn: 20,
                cluster_count: 10,
                lcn: crate::platform::Lcn::new(900),
            },
        ];
        let map = MftExtentMap::new(extents, 4096, 1024);
        let plan = map.read_plan(8 * 1024 * 1024, 120);

        // The hole (records 40..80) produces no read; the extent after
        // it starts at FRS 80, not 40.
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.first().map(|read| read.base_frs), Some(0));
        assert_eq!(plan.last().map(|read| read.base_frs), Some(80));
        assert_eq!(plan.last().map(|read| read.volume_offset), Some(900 * 4096));
    }

    #[test]
    fn read_plan_chunk_smaller_than_record_is_empty() {
        let map = MftExtentMap::contiguous(100, 1024 * 1024, 4096, 1024);
        assert_eq!(map.read_plan(512, 1024), vec![]);
        assert_eq!(map.read_plan(0, 1024), vec![]);
    }

    #[test]
    fn read_plan_rounds_chunk_down_to_whole_records() {
        // A 1500-byte chunk floors to one 1024-byte record per read.
        let map = MftExtentMap::contiguous(100, 4096, 4096, 1024);
        let plan = map.read_plan(1500, 4);

        assert_eq!(plan.len(), 4);
        assert!(plan.iter().all(|read| read.byte_len == 1024));
    }
}
