// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Basic record and batch readers.
//!
//! All `as`-style integer conversions in this module use the typed helpers
//! (`u32_as_usize`, `frs_to_usize`) and the `SECTOR_SIZE_U64` constant so the
//! NTFS disk-offset / record-size casts retain their domain bounds without a
//! module-level lint suppression.

use super::prelude::*;

/// Reads MFT records from a volume, handling fragmented MFTs.
#[derive(Debug)]
pub(crate) struct MftRecordReader {
    /// Size of each file record in bytes.
    record_size: u32,
    /// Extent map for VCN-to-LCN translation.
    extent_map: MftExtentMap,
    /// Aligned buffer for reading records.
    buffer: AlignedBuffer,
}

impl MftRecordReader {
    /// Whether `frs` falls inside the mapped `$MFT` extents, i.e. a
    /// targeted read of it can be attempted at all. Lets callers
    /// distinguish "no such record on this volume" (benign) from a
    /// failed read of a record that does exist.
    #[must_use]
    pub(crate) fn covers(&self, frs: u64) -> bool {
        self.extent_map.physical_offset(frs).is_some()
    }

    /// Creates a new MFT record reader with explicit extent mapping.
    ///
    /// This constructor should be used when the MFT is fragmented.
    ///
    /// # Arguments
    ///
    /// * `extent_map` - The extent map for the MFT
    #[must_use]
    pub(crate) fn new_with_extents(extent_map: MftExtentMap) -> Self {
        let record_size = extent_map.bytes_per_record;

        // Allocate buffer for one record (rounded up to sector boundary)
        let buffer_size = u32_as_usize(record_size).div_ceil(SECTOR_SIZE) * SECTOR_SIZE;
        let buffer = AlignedBuffer::new(buffer_size);

        Self {
            record_size,
            extent_map,
            buffer,
        }
    }

    /// Reads a single MFT record by its File Record Segment number.
    ///
    /// This method handles fragmented MFTs by using the extent map to
    /// translate the FRS to a physical disk location.
    ///
    /// # Arguments
    ///
    /// * `handle` - The raw volume handle
    /// * `frs` - The File Record Segment number to read
    ///
    /// # Errors
    ///
    /// Returns an error if the record cannot be read or is invalid.
    #[expect(
        unsafe_code,
        reason = "FFI: SetFilePointerEx and ReadFile for MFT record access"
    )]
    pub(crate) fn read_record(&mut self, handle: HANDLE, frs: u64) -> Result<&[u8]> {
        // Use extent map to get the physical offset (handles fragmentation)
        let record_offset =
            self.extent_map
                .physical_offset(frs)
                .ok_or_else(|| MftError::RecordRead {
                    frs,
                    reason: "FRS outside MFT extents or in sparse region".to_owned(),
                })?;

        // Align to sector boundary
        let aligned_offset = (record_offset / SECTOR_SIZE_U64) * SECTOR_SIZE_U64;
        let offset_within_sector = frs_to_usize(record_offset - aligned_offset);

        // Seek to the aligned offset
        let mut new_position = 0_i64;
        // SAFETY: `handle` is a live volume handle and `new_position` is valid
        // writable storage for the duration of the seek.
        unsafe {
            SetFilePointerEx(
                handle,
                aligned_offset.cast_signed(),
                Some(&raw mut new_position),
                FILE_BEGIN,
            )
        }?;

        // Read the record
        let mut bytes_read = 0_u32;
        // SAFETY: `handle` is live, the reusable aligned buffer is writable for
        // its full length, and `bytes_read` is a valid out-parameter.
        unsafe {
            ReadFile(
                handle,
                Some(self.buffer.as_mut_slice()),
                Some(&raw mut bytes_read),
                None,
            )
        }?;

        if u32_as_usize(bytes_read) < u32_as_usize(self.record_size) + offset_within_sector {
            return Err(MftError::RecordRead {
                frs,
                reason: format!(
                    "Short read: expected {} bytes, got {}",
                    self.record_size, bytes_read
                ),
            });
        }

        // Return the record data (accounting for sector alignment offset)
        self.buffer
            .as_slice()
            .get(offset_within_sector..offset_within_sector + u32_as_usize(self.record_size))
            .ok_or_else(|| MftError::RecordRead {
                frs,
                reason: format!(
                    "Short read: buffer {} bytes smaller than {} + record_size {}",
                    self.buffer.as_slice().len(),
                    offset_within_sector,
                    self.record_size
                ),
            })
    }
}
