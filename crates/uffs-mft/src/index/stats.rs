// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Build timing and aggregate statistics for `MftIndex` construction.

use super::frs_to_usize;

/// Timing breakdown for `MftIndex` building phases.
#[derive(Debug, Clone, Copy, Default)]
#[expect(
    clippy::struct_field_names,
    reason = "_ms suffix documents the unit — removing it loses critical information"
)]
pub struct IndexBuildTiming {
    /// Time spent inserting records into the index (ms).
    pub record_insert_ms: u64,
    /// Time spent building the extension index (ms).
    pub extension_index_ms: u64,
    /// Time spent sorting directory children (ms).
    pub sort_children_ms: u64,
    /// Time spent computing tree metrics (ms).
    pub tree_metrics_ms: u64,
    /// Total wall-clock time for index building (ms).
    pub total_ms: u64,
}

impl IndexBuildTiming {
    /// Returns the index build time excluding tree metrics.
    #[must_use]
    pub const fn index_only_ms(&self) -> u64 {
        self.record_insert_ms + self.extension_index_ms + self.sort_children_ms
    }
}

impl core::fmt::Display for IndexBuildTiming {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Record insert: {} ms, Ext index: {} ms, Sort: {} ms, Tree metrics: {} ms, Total: {} ms",
            self.record_insert_ms,
            self.extension_index_ms,
            self.sort_children_ms,
            self.tree_metrics_ms,
            self.total_ms
        )
    }
}

/// Statistics collected during MFT parsing for optimization.
#[derive(Debug, Clone, Default)]
pub struct MftStats {
    /// Total number of in-use records parsed.
    pub record_count: u32,
    /// Number of directory records.
    pub dir_count: u32,
    /// Number of file records (`record_count - dir_count`).
    pub file_count: u32,
    /// Maximum FRS seen (for sizing `frs_to_idx`).
    pub max_frs: u64,
    /// Total bytes of all filenames.
    pub total_name_bytes: u64,
    /// Number of records with multiple names.
    pub multi_name_count: u32,
    /// Number of records with ADS.
    pub ads_count: u32,
    /// Number of system metafiles (FRS < 16, except root).
    pub system_metafile_count: u32,
    /// Number of records whose parent FRS is a system metafile.
    pub system_child_count: u32,
    /// Total bytes in all files.
    pub total_bytes: u64,
    /// Total bytes in directory records.
    pub dir_bytes: u64,
    /// Total bytes in hidden files.
    pub hidden_bytes: u64,
    /// Total bytes in system files.
    pub system_bytes: u64,
    /// Total bytes in compressed files.
    pub compressed_bytes: u64,
    /// Total bytes in encrypted files.
    pub encrypted_bytes: u64,
    /// Total bytes in sparse files.
    pub sparse_bytes: u64,
    /// Total bytes in reparse points.
    pub reparse_bytes: u64,
    /// File count per size bucket.
    pub size_bucket_counts: [u32; 8],
    /// Total bytes per size bucket.
    pub size_bucket_bytes: [u64; 8],
    /// Number of U+FFFD substitutions made while decoding NTFS names from
    /// UTF-16 (Category 4, WI-4.1). `0` means every name decoded losslessly;
    /// `> 0` means that many code units were not representable in UTF-8 and
    /// were stored as the replacement character — surfaced via a `warn!` at
    /// index-build time so the loss is visible, not silent.
    pub lossy_name_count: u64,
}

impl MftStats {
    /// Create new empty stats.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            record_count: 0,
            dir_count: 0,
            file_count: 0,
            max_frs: 0,
            total_name_bytes: 0,
            multi_name_count: 0,
            ads_count: 0,
            system_metafile_count: 0,
            system_child_count: 0,
            total_bytes: 0,
            dir_bytes: 0,
            hidden_bytes: 0,
            system_bytes: 0,
            compressed_bytes: 0,
            encrypted_bytes: 0,
            sparse_bytes: 0,
            reparse_bytes: 0,
            size_bucket_counts: [0; 8],
            size_bucket_bytes: [0; 8],
            lossy_name_count: 0,
        }
    }

    /// Compute size bucket index for a given file size.
    #[must_use]
    pub const fn size_bucket(size: u64) -> usize {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if size < KB {
            0
        } else if size < 10 * KB {
            1
        } else if size < 100 * KB {
            2
        } else if size < MB {
            3
        } else if size < 10 * MB {
            4
        } else if size < 100 * MB {
            5
        } else if size < GB {
            6
        } else {
            7
        }
    }

    /// Estimate average path depth based on collected stats.
    #[must_use]
    pub fn estimated_avg_depth(&self) -> usize {
        if self.dir_count == 0 {
            return 5;
        }
        // Number of bits needed to represent dir_count (position of the
        // highest set bit). dir_count > 0 here — the zero case returned
        // above. `bit_width()` == `u32::BITS - leading_zeros()`, spelled the
        // idiomatic way so clippy's `manual_bit_width` lint stays satisfied
        // on newer toolchains.
        let bits = self.dir_count.bit_width() as usize;
        (bits + 1).clamp(3, 20) // +1 keeps the original depth heuristic
    }

    /// Estimate average path length in bytes.
    #[must_use]
    pub fn estimated_avg_path_bytes(&self) -> usize {
        if self.record_count == 0 {
            return 50;
        }
        let avg_name_len = frs_to_usize(self.total_name_bytes / u64::from(self.record_count));
        let depth = self.estimated_avg_depth();
        3 + (avg_name_len + 1) * depth
    }

    /// Check if there are any hard links.
    #[must_use]
    pub const fn has_hard_links(&self) -> bool {
        self.multi_name_count > 0
    }

    /// Check if there are any ADS.
    #[must_use]
    pub const fn has_ads(&self) -> bool {
        self.ads_count > 0
    }

    /// Estimate number of valid (non-system) records for path cache sizing.
    #[must_use]
    pub const fn valid_record_estimate(&self) -> usize {
        let invalid = self.system_metafile_count + self.system_child_count;
        self.record_count.saturating_sub(invalid) as usize
    }
}
