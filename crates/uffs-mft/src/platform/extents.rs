// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Retrieval-pointer helpers for locating MFT extents on disk.

#[cfg(windows)]
use core::mem::size_of;

#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows::Win32::System::Ioctl::{FSCTL_GET_RETRIEVAL_POINTERS, STARTING_VCN_INPUT_BUFFER};

#[cfg(windows)]
use crate::error::{MftError, Result};

/// Represents a contiguous extent of the MFT on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MftExtent {
    /// Virtual Cluster Number (offset within the file).
    pub vcn: u64,
    /// Number of clusters in this extent.
    pub cluster_count: u64,
    /// Logical Cluster Number (physical location on disk).
    /// Negative values (per [`super::Lcn::is_hole`]) indicate sparse /
    /// unallocated regions; the kernel emits `LCN_HOLE = -1` for those.
    pub lcn: super::Lcn,
}

impl MftExtent {
    /// Returns the byte offset of this extent on the volume.
    ///
    /// Sparse extents (negative LCNs) yield `0`; the caller is
    /// expected to filter these out via [`MftExtent::lcn`]
    /// `.is_hole()` before doing seek arithmetic.
    #[must_use]
    pub fn byte_offset(&self, bytes_per_cluster: u32) -> u64 {
        if self.lcn.is_hole() {
            0
        } else {
            self.lcn.raw_unsigned() * u64::from(bytes_per_cluster)
        }
    }

    /// Returns the size of this extent in bytes.
    #[must_use]
    pub fn byte_size(&self, bytes_per_cluster: u32) -> u64 {
        self.cluster_count * u64::from(bytes_per_cluster)
    }
}

/// Convert NTFS `$DATA` data runs into [`MftExtent`]s, dropping sparse runs.
///
/// Used by the non-elevated MFT-extent bootstrap: FRS 0's `$DATA` runlist
/// describes the MFT's own physical layout, so its runs map directly to the
/// extent map the kernel's `FSCTL_GET_RETRIEVAL_POINTERS` would return.  Sparse
/// runs (the MFT has none in practice, but a corrupt record could encode one)
/// are filtered so seek arithmetic never lands on a hole.  Pure — no I/O / FFI
/// — so it is unit-tested directly against golden runlists.
///
/// `cfg(any(windows, test))`: the only production caller is the Windows
/// MFT-read path, but the conversion is platform-agnostic and exercised by the
/// host test below.
#[cfg(any(windows, test))]
#[must_use]
pub(crate) fn data_runs_to_extents(runs: &[crate::ntfs::DataRun]) -> Vec<MftExtent> {
    runs.iter()
        .filter(|run| !run.is_sparse())
        .map(|run| MftExtent {
            vcn: run.vcn.cast_unsigned(),
            cluster_count: run.cluster_count,
            lcn: run.lcn,
        })
        .collect()
}

/// Retrieves the extent map for a file using `FSCTL_GET_RETRIEVAL_POINTERS`.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "FFI: windows API (DeviceIoControl) and mem::zeroed"
)]
pub(super) fn get_retrieval_pointers(handle: HANDLE) -> Result<Vec<MftExtent>> {
    use windows::Win32::System::IO::DeviceIoControl;

    let mut extents = Vec::new();
    // SAFETY: `STARTING_VCN_INPUT_BUFFER` is a plain FFI struct whose all-zero
    // bit pattern represents `StartingVcn == 0`, the initial query window.
    let starting_vcn: STARTING_VCN_INPUT_BUFFER = unsafe { core::mem::zeroed() };

    let input_buffer_size =
        u32::try_from(size_of::<STARTING_VCN_INPUT_BUFFER>()).map_err(|err| {
            MftError::RetrievalPointers(format!(
                "STARTING_VCN_INPUT_BUFFER size {} exceeds u32::MAX ({err})",
                size_of::<STARTING_VCN_INPUT_BUFFER>()
            ))
        })?;

    let mut buffer_size = 64 * 1024;
    let mut buffer: Vec<u8> = vec![0; buffer_size];

    loop {
        let mut bytes_returned: u32 = 0;
        let output_buffer_size = u32::try_from(buffer_size).map_err(|err| {
            MftError::RetrievalPointers(format!(
                "FSCTL retrieval-pointer buffer size {buffer_size} exceeds u32::MAX ({err})"
            ))
        })?;

        // SAFETY: `handle` is an open file handle, `starting_vcn` and `buffer`
        // point to valid initialized storage for the provided lengths, and
        // `bytes_returned` is a valid out-parameter.
        let result = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_GET_RETRIEVAL_POINTERS,
                Some(core::ptr::from_ref(&starting_vcn).cast()),
                input_buffer_size,
                Some(buffer.as_mut_ptr().cast()),
                output_buffer_size,
                Some(&raw mut bytes_returned),
                None,
            )
        };

        match result {
            Ok(()) => {
                parse_retrieval_pointers(&buffer, bytes_returned as usize, &mut extents);
                break;
            }
            Err(err) => {
                let hresult = err.code().0.cast_unsigned();
                let win32_error = if (hresult & 0xFFFF_0000) == 0x8007_0000 {
                    hresult & 0xFFFF
                } else {
                    hresult
                };

                if win32_error == 234 {
                    buffer_size *= 2;
                    buffer.resize(buffer_size, 0);
                    continue;
                }

                if win32_error == 38 {
                    break;
                }

                if extents.is_empty() {
                    return Err(MftError::RetrievalPointers(format!(
                        "FSCTL_GET_RETRIEVAL_POINTERS failed: HRESULT=0x{hresult:08X}, Win32={win32_error}"
                    )));
                }
                break;
            }
        }
    }

    Ok(extents)
}

/// Parses the `RETRIEVAL_POINTERS_BUFFER` structure.
#[cfg(windows)]
fn parse_retrieval_pointers(buffer: &[u8], size: usize, extents: &mut Vec<MftExtent>) {
    if size < size_of::<u32>() + size_of::<i64>() {
        return;
    }

    let read_le_u32 = |offset: usize| -> Option<u32> {
        let bytes = buffer.get(offset..offset + size_of::<u32>())?;
        let mut raw = [0_u8; 4];
        raw.copy_from_slice(bytes);
        Some(u32::from_le_bytes(raw))
    };
    let parse_signed64 = |offset: usize| -> Option<i64> {
        let bytes = buffer.get(offset..offset + size_of::<i64>())?;
        let mut raw = [0_u8; 8];
        raw.copy_from_slice(bytes);
        Some(i64::from_le_bytes(raw))
    };

    let Some(extent_count) = read_le_u32(0).map(|count| count as usize) else {
        return;
    };
    let Some(starting_vcn) = parse_signed64(8) else {
        return;
    };
    let mut prev_vcn = starting_vcn.cast_unsigned();

    let extent_size = 16;
    let extents_offset = 16;

    for i in 0..extent_count {
        let offset = extents_offset + i * extent_size;
        if offset + extent_size > size {
            break;
        }

        let Some(next_vcn) = parse_signed64(offset).map(i64::cast_unsigned) else {
            break;
        };
        let Some(lcn) = parse_signed64(offset + 8) else {
            break;
        };

        let cluster_count = next_vcn.saturating_sub(prev_vcn);

        extents.push(MftExtent {
            vcn: prev_vcn,
            cluster_count,
            lcn: super::Lcn::new(lcn),
        });

        prev_vcn = next_vcn;
    }
}

#[cfg(test)]
mod tests {
    use super::super::Lcn;
    use super::{MftExtent, data_runs_to_extents};

    #[test]
    fn data_runs_map_to_extents_and_drop_sparse() {
        use crate::ntfs::DataRun;
        // Two real MFT fragments with a sparse run between them (the sparse run
        // must be dropped so the read plan never seeks into a hole).
        let runs = [
            DataRun {
                vcn: 0,
                cluster_count: 100,
                lcn: Lcn::new(5_000),
            },
            DataRun {
                vcn: 100,
                cluster_count: 50,
                lcn: Lcn::ZERO, // sparse → filtered
            },
            DataRun {
                vcn: 150,
                cluster_count: 200,
                lcn: Lcn::new(9_000),
            },
        ];
        assert_eq!(data_runs_to_extents(&runs), vec![
            MftExtent {
                vcn: 0,
                cluster_count: 100,
                lcn: Lcn::new(5_000),
            },
            MftExtent {
                vcn: 150,
                cluster_count: 200,
                lcn: Lcn::new(9_000),
            },
        ],);
    }

    #[test]
    fn data_runs_single_contiguous_fragment() {
        use crate::ntfs::DataRun;
        // The common case: a contiguous MFT is one run → one extent (identity
        // mapping of the fields).
        let runs = [DataRun {
            vcn: 0,
            cluster_count: 98_752,
            lcn: Lcn::new(786_432),
        }];
        assert_eq!(data_runs_to_extents(&runs), vec![MftExtent {
            vcn: 0,
            cluster_count: 98_752,
            lcn: Lcn::new(786_432),
        }],);
    }

    #[test]
    fn data_runs_empty_yields_no_extents() {
        assert_eq!(data_runs_to_extents(&[]), Vec::<MftExtent>::new());
    }

    #[test]
    fn byte_offset_returns_zero_for_sparse_extents() {
        // Pin the sparse-extent guard preserved by the `Lcn::is_hole()`
        // migration: any negative LCN (not just `LCN_HOLE = -1`) yields
        // `0` regardless of `bytes_per_cluster`, matching the historic
        // `lcn < 0` discipline so seek arithmetic never underflows.
        for sparse in [Lcn::HOLE, Lcn::new(-2), Lcn::new(i64::MIN)] {
            let extent = MftExtent {
                vcn: 0,
                cluster_count: 8,
                lcn: sparse,
            };
            for bpc in [512_u32, 4096, 65_536] {
                assert_eq!(extent.byte_offset(bpc), 0, "sparse {sparse} @ bpc={bpc}");
            }
        }
    }

    #[test]
    fn byte_offset_matches_lcn_times_bytes_per_cluster() {
        // Non-sparse extents must reproduce the kernel's
        // `LcnPosition * bytes_per_cluster` byte offset exactly — the
        // newtype migration only changes how we *spell* the arithmetic,
        // never the resulting wire bytes.
        // Stay well below `u64::MAX / bpc` so the test mirrors what
        // production code actually evaluates: NTFS volume sizes never
        // approach `i64::MAX` clusters, and `byte_offset` (debug-mode)
        // would itself panic on an unrealistic boundary.
        let cases: [(i64, u32, u64); 4] = [
            (0, 4096, 0),
            (1, 4096, 4096),
            (1_234_567, 4096, 1_234_567_u64 * 4096),
            (1_000_000_000_000, 4096, 1_000_000_000_000_u64 * 4096),
        ];
        for (raw, bpc, expected) in cases {
            let extent = MftExtent {
                vcn: 0,
                cluster_count: 1,
                lcn: Lcn::new(raw),
            };
            assert_eq!(extent.byte_offset(bpc), expected, "lcn={raw} bpc={bpc}");
        }
    }

    #[test]
    fn byte_size_independent_of_lcn() {
        // `byte_size` is purely `cluster_count * bytes_per_cluster`; the
        // LCN newtype must not bleed into that calculation.
        for lcn in [Lcn::ZERO, Lcn::HOLE, Lcn::new(42), Lcn::new(i64::MAX)] {
            let extent = MftExtent {
                vcn: 0,
                cluster_count: 10,
                lcn,
            };
            assert_eq!(extent.byte_size(4096), 10 * 4096);
        }
    }
}
