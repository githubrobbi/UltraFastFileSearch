// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! NTFS non-resident attribute data-run parsing.

use core::mem::size_of;

use super::records::{
    AttributeRecordHeader, NonResidentAttributeData, parse_attribute_record_header,
    parse_non_resident_attribute_data,
};

/// A single data run (extent) from a non-resident attribute.
///
/// Data runs describe the physical layout of non-resident attribute data
/// on disk. Each run specifies a contiguous range of clusters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataRun {
    /// Virtual Cluster Number - offset within the attribute data.
    pub vcn: i64,
    /// Number of clusters in this run.
    pub cluster_count: u64,
    /// Logical Cluster Number - physical location on disk.
    ///
    /// `Lcn::ZERO` indicates a sparse (unallocated) run — the
    /// data-run encoding's "no LCN offset emitted" sentinel, which
    /// leaves the running LCN total unchanged.  Distinct from the
    /// retrieval-pointer `LCN_HOLE = -1` convention used by
    /// [`crate::platform::MftExtent`].
    pub lcn: crate::platform::Lcn,
}

impl DataRun {
    /// Returns true if this is a sparse (unallocated) run.
    #[must_use]
    pub const fn is_sparse(&self) -> bool {
        self.lcn.is_zero()
    }

    /// Returns the byte offset of this run on the volume.
    ///
    /// Defensive: negative LCNs (which the data-run encoding
    /// shouldn't produce, but a corrupt buffer could) and sparse
    /// runs both yield `0`, matching the historic `nonneg_to_u64`
    /// clamp.
    #[must_use]
    pub fn byte_offset(&self, bytes_per_cluster: u32) -> u64 {
        if self.lcn.is_hole() {
            0
        } else {
            self.lcn.raw_unsigned() * u64::from(bytes_per_cluster)
        }
    }

    /// Returns the size of this run in bytes.
    #[must_use]
    pub fn byte_size(&self, bytes_per_cluster: u32) -> u64 {
        self.cluster_count * u64::from(bytes_per_cluster)
    }
}

/// Parses data runs (mapping pairs) from a non-resident attribute.
///
/// Convenience over [`parse_data_runs_iter`] that collects the whole
/// runlist. Prefer the iterator on hot paths that only need a prefix of
/// the runs (e.g. the first non-sparse LCN) — it decodes lazily and
/// never allocates.
#[must_use]
pub fn parse_data_runs(data: &[u8], lowest_vcn: i64) -> Vec<DataRun> {
    parse_data_runs_iter(data, lowest_vcn).collect()
}

/// Lazily parses data runs (mapping pairs) from a non-resident
/// attribute's mapping-pairs bytes.
///
/// Decodes one run per `next()` call with no heap allocation. Stops at
/// the runlist terminator or at the first malformed/truncated field
/// (identical stopping behaviour to [`parse_data_runs`], which is this
/// iterator collected).
#[must_use]
pub const fn parse_data_runs_iter(data: &[u8], lowest_vcn: i64) -> DataRunIter<'_> {
    DataRunIter {
        data,
        offset: 0,
        current_vcn: lowest_vcn,
        current_lcn: 0,
    }
}

/// Lazy decoder over NTFS mapping-pairs bytes — see
/// [`parse_data_runs_iter`].
#[derive(Debug, Clone)]
pub struct DataRunIter<'a> {
    /// The mapping-pairs bytes (starting at the first run header).
    data: &'a [u8],
    /// Byte offset of the next run header; pushed past the end of
    /// `data` on termination so the iterator is fused.
    offset: usize,
    /// Running VCN total across decoded runs.
    current_vcn: i64,
    /// Running LCN total across decoded runs (deltas are relative).
    current_lcn: i64,
}

impl Iterator for DataRunIter<'_> {
    type Item = DataRun;

    fn next(&mut self) -> Option<DataRun> {
        let &header = self.data.get(self.offset)?;
        if header == 0 {
            self.offset = self.data.len();
            return None;
        }

        let length_size = (header & 0x0F) as usize;
        let offset_size = ((header >> 4_i32) & 0x0F) as usize;
        let mut offset = self.offset + 1;

        let Some(length_bytes) = self.data.get(offset..offset + length_size) else {
            self.offset = self.data.len();
            return None;
        };
        let run_length = parse_variable_length_unsigned(length_bytes);
        offset += length_size;

        let lcn_delta = if offset_size > 0 {
            let Some(offset_bytes) = self.data.get(offset..offset + offset_size) else {
                self.offset = self.data.len();
                return None;
            };
            parse_variable_length_signed(offset_bytes)
        } else {
            0
        };
        offset += offset_size;
        self.offset = offset;
        self.current_lcn += lcn_delta;

        let run = DataRun {
            vcn: self.current_vcn,
            cluster_count: run_length,
            // A run with no encoded LCN offset is sparse; emit
            // `Lcn::ZERO` so `is_sparse()` keeps returning true
            // without consulting `offset_size` downstream.
            lcn: if offset_size > 0 {
                crate::platform::Lcn::new(self.current_lcn)
            } else {
                crate::platform::Lcn::ZERO
            },
        };

        if let Ok(len_i64) = i64::try_from(run_length) {
            self.current_vcn += len_i64;
        }

        Some(run)
    }
}

impl core::iter::FusedIterator for DataRunIter<'_> {}

#[expect(
    clippy::single_call_fn,
    reason = "extracted for clarity alongside parse_variable_length_signed"
)]
/// Parses a little-endian variable-length unsigned integer from a data run
/// field.
fn parse_variable_length_unsigned(data: &[u8]) -> u64 {
    let mut value: u64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        value |= u64::from(byte) << (i * 8);
    }
    value
}

#[expect(
    clippy::single_call_fn,
    reason = "extracted for clarity alongside parse_variable_length_unsigned"
)]
/// Parses a sign-extended little-endian variable-length integer from a data run
/// field.
fn parse_variable_length_signed(data: &[u8]) -> i64 {
    let Some(&last_byte) = data.last() else {
        return 0;
    };

    let mut value: i64 = 0;
    for (idx, &byte) in data.iter().enumerate() {
        value |= i64::from(byte) << (idx * 8);
    }

    if last_byte & 0x80 != 0 {
        let shift = data.len() * 8;
        if shift < 64 {
            value |= !0_i64 << shift;
        }
    }

    value
}

/// Extracts data runs from a non-resident attribute record.
///
/// Convenience over [`data_runs_iter_from_attribute`] that collects the
/// whole runlist.
#[must_use]
pub fn extract_data_runs_from_attribute(attr_data: &[u8]) -> Vec<DataRun> {
    data_runs_iter_from_attribute(attr_data).collect()
}

/// Lazily extracts data runs from a non-resident attribute record.
///
/// Returns an empty iterator for a resident, truncated, or otherwise
/// unparseable attribute — the same inputs for which
/// [`extract_data_runs_from_attribute`] returns an empty `Vec`.
/// Allocation-free; decodes one run per `next()` call.
#[must_use]
pub fn data_runs_iter_from_attribute(attr_data: &[u8]) -> DataRunIter<'_> {
    /// The shared "nothing to decode" result for malformed inputs.
    const fn empty() -> DataRunIter<'static> {
        parse_data_runs_iter(&[], 0)
    }

    let header_size = size_of::<AttributeRecordHeader>();
    let Some(header_slice) = attr_data.get(0..header_size) else {
        return empty();
    };

    let Some(header) = parse_attribute_record_header(header_slice) else {
        return empty();
    };
    if header.is_non_resident == 0 {
        return empty();
    }

    let nr_size = size_of::<NonResidentAttributeData>();
    let Some(nr_slice) = attr_data.get(header_size..header_size + nr_size) else {
        return empty();
    };

    let Some(nr_data) = parse_non_resident_attribute_data(nr_slice) else {
        return empty();
    };
    let mapping_pairs_offset = nr_data.mapping_pairs_offset as usize;
    let Some(mapping_pairs_data) = attr_data.get(mapping_pairs_offset..) else {
        return empty();
    };

    parse_data_runs_iter(mapping_pairs_data, nr_data.lowest_vcn)
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code — relaxed linting for test clarity"
)]
mod tests {
    use super::{DataRun, parse_data_runs};
    use crate::platform::Lcn;

    #[test]
    fn is_sparse_matches_only_zero_sentinel() {
        // Data-run sparse encoding is `Lcn::ZERO` (no offset emitted),
        // *not* the retrieval-pointer `LCN_HOLE = -1`.  Keep the two
        // conventions surgically separated post-migration.
        assert!(
            DataRun {
                vcn: 0,
                cluster_count: 4,
                lcn: Lcn::ZERO,
            }
            .is_sparse()
        );
        for lcn in [Lcn::HOLE, Lcn::new(1), Lcn::new(-2), Lcn::new(i64::MAX)] {
            assert!(
                !DataRun {
                    vcn: 0,
                    cluster_count: 4,
                    lcn,
                }
                .is_sparse(),
                "{lcn} must not register as a sparse data run",
            );
        }
    }

    #[test]
    fn byte_offset_clamps_holes_and_yields_lcn_times_bpc_otherwise() {
        // Defensive clamp: a negative LCN in a data run (corrupt
        // buffer) and a sparse-marker `Lcn::ZERO` both produce a
        // zero byte offset, matching the historic `nonneg_to_u64`
        // discipline.  Non-sparse runs reproduce the kernel's
        // unsigned `lcn * bpc` exactly.
        let bpc = 4096_u32;
        for hole in [Lcn::HOLE, Lcn::new(-2), Lcn::new(i64::MIN)] {
            assert_eq!(
                DataRun {
                    vcn: 0,
                    cluster_count: 1,
                    lcn: hole,
                }
                .byte_offset(bpc),
                0,
                "hole {hole}"
            );
        }
        assert_eq!(
            DataRun {
                vcn: 0,
                cluster_count: 1,
                lcn: Lcn::ZERO,
            }
            .byte_offset(bpc),
            0
        );
        assert_eq!(
            DataRun {
                vcn: 0,
                cluster_count: 1,
                lcn: Lcn::new(42),
            }
            .byte_offset(bpc),
            42 * u64::from(bpc)
        );
    }

    #[test]
    fn parse_data_runs_marks_sparse_runs_with_zero_lcn() {
        // Two-run NTFS mapping pairs:
        //   header 0x21 → length-size=1, offset-size=2 → length=8,
        //   lcn delta = +0x0010 → first run @ LCN 16, 8 clusters.
        //   header 0x02 → length-size=2, offset-size=0 → length=4,
        //   no LCN delta → sparse run; lcn must be `Lcn::ZERO`,
        //   VCN advances past the previous run.
        //   header 0x00 → terminator.
        let buf = [
            0x21_u8, 0x08, 0x10, 0x00, // run 1
            0x02, 0x04, 0x00, // run 2 (sparse)
            0x00, // terminator
        ];
        let runs = parse_data_runs(&buf, 0);
        assert_eq!(runs.len(), 2, "expected exactly two parsed runs");

        assert_eq!(runs[0].vcn, 0);
        assert_eq!(runs[0].cluster_count, 8);
        assert_eq!(runs[0].lcn, Lcn::new(16));
        assert!(!runs[0].is_sparse());

        assert_eq!(runs[1].vcn, 8, "VCN must advance past run 1");
        assert_eq!(runs[1].cluster_count, 4);
        assert_eq!(runs[1].lcn, Lcn::ZERO, "sparse run must carry Lcn::ZERO");
        assert!(runs[1].is_sparse());
    }
}
