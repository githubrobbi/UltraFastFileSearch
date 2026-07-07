// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! RAW MFT Persistence.
//!
//! Exception: Unified MFT persistence handling UFFS-MFT, UFFS-IOCP, and raw
//! NTFS formats
//!
//! This module provides functionality to save and load complete raw MFT bytes
//! for offline analysis. This allows:
//! - Saving MFT data without requiring admin privileges later
//! - Analyzing MFT data on non-Windows systems
//! - Sharing MFT snapshots for forensic analysis
//!
//! # File Format
//!
//! The raw MFT file format is:
//! ```text
//! [Header: 64 bytes]
//!   - Magic: "UFFS-MFT" (8 bytes)
//!   - Version: u32 (4 bytes) - currently 2
//!   - Flags: u32 (4 bytes) - bit 0: compressed
//!   - Record size: u32 (4 bytes)
//!   - Record count: u64 (8 bytes)
//!   - Original size: u64 (8 bytes) - uncompressed size
//!   - Compressed size: u64 (8 bytes) - 0 if not compressed
//!   - Volume letter: u8 (1 byte) - ASCII drive letter (e.g., 'C') [v2+]
//!   - Reserved: 19 bytes
//! [Data: variable]
//!   - Raw MFT bytes (optionally zstd compressed)
//! ```
//!
//! # Compatibility Mode
//!
//! Use `--raw` flag with the save command to output raw MFT bytes without
//! any header. This format is compatible with other MFT analysis tools like
//! analyzeMFT, MFT2CSV, and ntfstool.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read as _, Write as _};
use std::path::Path;

use crate::error::{MftError, Result};

/// Magic bytes for raw MFT file format.
const MAGIC: &[u8; 8] = b"UFFS-MFT";

/// Magic bytes for IOCP capture format (first 8 bytes of "UFFS-IOCP").
const IOCP_MAGIC_PREFIX: &[u8; 8] = b"UFFS-IOC";

/// NTFS FILE record magic bytes ("FILE" in ASCII).
const NTFS_FILE_MAGIC: &[u8; 4] = b"FILE";

/// Current file format version.
/// - v1: Initial format
/// - v2: Added `volume_letter` field
/// - v3: Added `reserved_allocated_bytes` (root `tree_allocated` adjustment)
const VERSION: u32 = 3;

/// Flag: data is zstd compressed.
const FLAG_COMPRESSED: u32 = 0x0001;

/// Header size in bytes.
const HEADER_SIZE: usize = 64;

/// Default record size for NTFS MFT (1024 bytes is standard).
const DEFAULT_RECORD_SIZE: u32 = 1024;

/// Raw MFT file header.
#[derive(Debug, Clone)]
pub struct RawMftHeader {
    /// File format version.
    pub version: u32,
    /// Flags (bit 0: compressed).
    pub flags: u32,
    /// Size of each MFT record in bytes.
    pub record_size: u32,
    /// Number of MFT records.
    pub record_count: u64,
    /// Original uncompressed size.
    pub original_size: u64,
    /// Compressed size (0 if not compressed).
    pub compressed_size: u64,
    /// Volume letter (e.g., `C`, `D`).  Added in v2.
    ///
    /// For v1 files (and for raw-NTFS dumps with no volume context),
    /// this defaults to [`crate::platform::DriveLetter::X`] — the
    /// historical sentinel meaning "unknown source volume; let the
    /// loader override via `LoadRawOptions::volume_letter`".
    pub volume_letter: crate::platform::DriveLetter,
    /// NTFS reserved-cluster bytes added to the root's `tree_allocated`
    /// (`total_reserved × bytes_per_cluster`). Added in v3; `0` for older
    /// files and raw-NTFS dumps. Lets an offline `.bin` load reproduce the
    /// live root size-on-disk without volume data.
    pub reserved_allocated_bytes: u64,
}

impl RawMftHeader {
    /// Returns true if the data is compressed.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.flags & FLAG_COMPRESSED != 0
    }

    /// Serializes the header to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0_u8; HEADER_SIZE];
        buf[0..8].copy_from_slice(MAGIC);
        buf[8..12].copy_from_slice(&self.version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.flags.to_le_bytes());
        buf[16..20].copy_from_slice(&self.record_size.to_le_bytes());
        buf[20..28].copy_from_slice(&self.record_count.to_le_bytes());
        buf[28..36].copy_from_slice(&self.original_size.to_le_bytes());
        buf[36..44].copy_from_slice(&self.compressed_size.to_le_bytes());
        // Volume letter at byte 44 (v2+) — single ASCII byte.
        buf[44] = self.volume_letter.as_byte();
        // Reserved-allocated bytes at 45-52 (v3+).
        buf[45..53].copy_from_slice(&self.reserved_allocated_bytes.to_le_bytes());
        // Reserved bytes 53-63 are already zero
        buf
    }

    /// Deserializes the header from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the magic bytes don't match or version is
    /// unsupported.
    pub fn from_bytes(buf: &[u8; HEADER_SIZE]) -> Result<Self> {
        // Check magic
        if &buf[0..8] != MAGIC {
            return Err(MftError::InvalidData("Invalid raw MFT file magic".into()));
        }

        let version = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if version > VERSION {
            return Err(MftError::InvalidData(format!(
                "Unsupported raw MFT version: {version}"
            )));
        }

        let flags = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let record_size = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let record_count = u64::from_le_bytes([
            buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27],
        ]);
        let original_size = u64::from_le_bytes([
            buf[28], buf[29], buf[30], buf[31], buf[32], buf[33], buf[34], buf[35],
        ]);
        let compressed_size = u64::from_le_bytes([
            buf[36], buf[37], buf[38], buf[39], buf[40], buf[41], buf[42], buf[43],
        ]);

        // Volume letter at byte 44 (v2+); falls back to the historical
        // [`DriveLetter::X`] sentinel for v1 files and for v2 files where
        // the byte isn't a valid ASCII letter (e.g. truncated or zeroed).
        let volume_letter = if version >= 2 {
            crate::platform::DriveLetter::parse(char::from(buf[44]))
                .unwrap_or(crate::platform::DriveLetter::X)
        } else {
            crate::platform::DriveLetter::X
        };

        // Reserved-allocated bytes at 45-52 (v3+); 0 for older files.
        let reserved_allocated_bytes = if version >= 3 {
            u64::from_le_bytes([
                buf[45], buf[46], buf[47], buf[48], buf[49], buf[50], buf[51], buf[52],
            ])
        } else {
            0
        };

        Ok(Self {
            version,
            flags,
            record_size,
            record_count,
            original_size,
            compressed_size,
            volume_letter,
            reserved_allocated_bytes,
        })
    }
}

/// Options for saving raw MFT.
#[derive(Debug, Clone)]
pub struct SaveRawOptions {
    /// Whether to compress the data with zstd.
    pub compress: bool,
    /// Compression level (1-22, default 3).
    pub compression_level: i32,
    /// Volume letter (e.g., `C`, `D`).  Defaults to
    /// [`crate::platform::DriveLetter::X`] — see
    /// [`RawMftHeader::volume_letter`] for the sentinel convention.
    pub volume_letter: crate::platform::DriveLetter,
    /// If true, save in raw compatibility mode (no header, just raw MFT bytes).
    /// This format is compatible with other MFT tools like analyzeMFT, MFT2CSV.
    pub raw_compat: bool,
    /// NTFS reserved-cluster bytes (`total_reserved × bytes_per_cluster`) to
    /// record in the header for the root `tree_allocated` adjustment. `0` when
    /// unknown (e.g. re-saving a raw dump with no volume data).
    pub reserved_allocated_bytes: u64,
}

impl Default for SaveRawOptions {
    fn default() -> Self {
        Self {
            compress: true,
            compression_level: 3,
            volume_letter: crate::platform::DriveLetter::X,
            raw_compat: false,
            reserved_allocated_bytes: 0,
        }
    }
}

/// Options for loading raw MFT.
#[derive(Debug, Clone, Default)]
pub struct LoadRawOptions {
    /// If true, only load the header without reading data.
    pub header_only: bool,
    /// Override volume letter (useful for raw NTFS files that don't have this
    /// info).  `None` falls back to [`crate::platform::DriveLetter::X`] for raw
    /// files.
    pub volume_letter: Option<crate::platform::DriveLetter>,
    /// Enable forensic mode: include deleted, corrupt, and extension records.
    /// Adds `is_deleted`, `is_corrupt`, `is_extension`, `base_frs` columns to
    /// output. WARNING: May significantly increase output size (10-50% more
    /// rows).
    pub forensic: bool,
}

/// Loaded raw MFT data.
#[derive(Debug)]
pub struct RawMftData {
    /// Header information.
    pub header: RawMftHeader,
    /// Raw MFT bytes (decompressed if was compressed).
    pub data: Vec<u8>,
}

impl RawMftData {
    /// Returns the number of records.
    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.header.record_count
    }

    /// Returns the record size.
    #[must_use]
    pub const fn record_size(&self) -> u32 {
        self.header.record_size
    }

    /// Returns a slice of a single record by FRS.
    ///
    /// # Returns
    ///
    /// `None` if FRS is out of range.
    #[must_use]
    pub fn get_record(&self, frs: u64) -> Option<&[u8]> {
        let record_size = self.header.record_size as usize;
        let offset = crate::index::frs_to_usize(frs) * record_size;
        self.data.get(offset..offset + record_size)
    }

    /// Returns an iterator over all records.
    pub fn iter_records(&self) -> impl Iterator<Item = (u64, &[u8])> {
        let record_size = self.header.record_size as usize;
        self.data
            .chunks_exact(record_size)
            .enumerate()
            .map(|(i, data)| (i as u64, data))
    }
}

/// Prepare MFT data for writing — compress if requested and the `zstd`
/// feature is enabled, otherwise return the original bytes.
///
/// Returns `(flags, compressed_size, write_data)`.
///
/// # Errors
///
/// Returns [`MftError`] if zstd compression fails.
fn prepare_write_data<'a>(
    data: &'a [u8],
    options: &SaveRawOptions,
) -> Result<(u32, u64, alloc::borrow::Cow<'a, [u8]>)> {
    use alloc::borrow::Cow;

    if options.compress {
        let compressed = zstd::encode_all(data, options.compression_level)
            .map_err(|err| MftError::Io(std::io::Error::other(err)))?;
        let compressed_size = compressed.len() as u64;
        return Ok((FLAG_COMPRESSED, compressed_size, Cow::Owned(compressed)));
    }

    Ok((0_u32, 0_u64, Cow::Borrowed(data)))
}

/// Saves raw MFT bytes to a file.
///
/// This function writes the complete MFT data to a file that can be
/// loaded later for offline analysis.
///
/// # Arguments
///
/// * `path` - Output file path
/// * `data` - Raw MFT bytes (must be contiguous, all records concatenated)
/// * `record_size` - Size of each MFT record in bytes
/// * `options` - Save options (compression, etc.)
///
/// # Errors
///
/// Returns an error if writing fails.
#[expect(
    clippy::shadow_reuse,
    reason = "path rebinding from P to &Path is idiomatic"
)]
pub fn save_raw_mft<P: AsRef<Path>>(
    path: P,
    data: &[u8],
    record_size: u32,
    options: &SaveRawOptions,
) -> Result<RawMftHeader> {
    let path = path.as_ref();
    let original_size = data.len() as u64;
    let record_count = original_size / u64::from(record_size);

    // Prepare data (compress if requested)
    let (flags, compressed_size, write_data) = prepare_write_data(data, options)?;

    // Create header
    let header = RawMftHeader {
        version: VERSION,
        flags,
        record_size,
        record_count,
        original_size,
        compressed_size,
        volume_letter: options.volume_letter,
        reserved_allocated_bytes: options.reserved_allocated_bytes,
    };

    // Write file
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    writer.write_all(&header.to_bytes())?;
    writer.write_all(&write_data)?;
    writer.flush()?;

    Ok(header)
}

/// Detects record size from the first MFT record.
///
/// NTFS MFT records have `bytes_allocated` at offset 28-32 which tells us the
/// record size. Standard is 1024 bytes, but some systems use 4096.
#[expect(
    clippy::single_call_fn,
    reason = "extracted for clarity and testability"
)]
fn detect_record_size_from_first_record(data: &[u8]) -> u32 {
    // bytes_allocated is at offset 28 in FileRecordSegmentHeader
    // Use get() with try_into to avoid indexing panics
    if let Some(bytes) = data.get(28..32)
        && let Ok(arr) = <[u8; 4]>::try_from(bytes)
    {
        let bytes_allocated = u32::from_le_bytes(arr);
        // Sanity check: record size should be 1024, 2048, or 4096
        if bytes_allocated == 1024 || bytes_allocated == 2048 || bytes_allocated == 4096 {
            return bytes_allocated;
        }
    }
    DEFAULT_RECORD_SIZE
}

/// Loads raw MFT bytes from a file.
///
/// This function is format-agnostic and can load:
/// - UFFS-MFT format (our custom format with header)
/// - Raw NTFS MFT format (no header, just raw MFT records starting with "FILE")
///
/// # Arguments
///
/// * `path` - Input file path
/// * `options` - Load options
///
/// # Errors
///
/// Returns an error if reading fails or file format is invalid.
#[expect(
    clippy::shadow_reuse,
    reason = "path rebinding from P to &Path is idiomatic"
)]
pub fn load_raw_mft<P: AsRef<Path>>(path: P, options: &LoadRawOptions) -> Result<RawMftData> {
    use std::io::{Seek as _, SeekFrom};

    let path = path.as_ref();
    let file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let mut reader = BufReader::new(file);

    // Read first 8 bytes to detect format
    let mut magic_buf = [0_u8; 8];
    reader.read_exact(&mut magic_buf)?;

    // Check if it's our UFFS-MFT format
    if &magic_buf == MAGIC {
        // Seek back and read full header
        reader.seek(SeekFrom::Start(0))?;
        let mut header_buf = [0_u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;
        let header = RawMftHeader::from_bytes(&header_buf)?;

        // If header-only mode, return empty data
        if options.header_only {
            return Ok(RawMftData {
                header,
                data: Vec::new(),
            });
        }

        // Read data
        let mut compressed_data = Vec::new();
        reader.read_to_end(&mut compressed_data)?;

        // Decompress if needed
        let data = if header.is_compressed() {
            zstd::decode_all(&*compressed_data)
                .map_err(|err| MftError::Io(std::io::Error::other(err)))?
        } else {
            compressed_data
        };

        // Validate size
        let expected_size = header.record_count * u64::from(header.record_size);
        if data.len() as u64 != expected_size {
            return Err(MftError::InvalidData(format!(
                "Data size mismatch: expected {expected_size}, got {}",
                data.len()
            )));
        }

        return Ok(RawMftData { header, data });
    }

    // Check if it's IOCP capture format (starts with "UFFS-IOC")
    if &magic_buf == IOCP_MAGIC_PREFIX {
        return load_iocp_as_raw_mft(path, options);
    }

    // Check if it's raw NTFS format (starts with "FILE")
    if &magic_buf[0..4] == NTFS_FILE_MAGIC {
        // Seek back to start
        reader.seek(SeekFrom::Start(0))?;

        // Read entire file as raw MFT data
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        // Detect record size from first record
        let record_size = detect_record_size_from_first_record(&data);

        // Calculate record count
        let record_count = file_size / u64::from(record_size);

        // Validate file size is a multiple of record size
        if file_size % u64::from(record_size) != 0 {
            return Err(MftError::InvalidData(format!(
                "File size {file_size} is not a multiple of record size {record_size}"
            )));
        }

        // Create synthetic header for raw NTFS format
        // version=0 indicates raw format (no UFFS header)
        let header = RawMftHeader {
            version: 0,
            flags: 0,
            record_size,
            record_count,
            original_size: file_size,
            compressed_size: 0,
            volume_letter: options
                .volume_letter
                .unwrap_or(crate::platform::DriveLetter::X),
            reserved_allocated_bytes: 0, // raw NTFS dump has no volume data
        };

        // If header-only mode, return empty data
        if options.header_only {
            return Ok(RawMftData {
                header,
                data: Vec::new(),
            });
        }

        return Ok(RawMftData { header, data });
    }

    // Unknown format
    Err(MftError::InvalidData(
        "Invalid MFT file: expected UFFS-MFT, UFFS-IOCP, or raw NTFS FILE records".into(),
    ))
}

/// Loads an IOCP capture file and reassembles it as sequential raw MFT data.
///
/// IOCP captures store chunks in completion order (non-deterministic).
/// This function reassembles them in FRS order for compatibility with
/// standard MFT processing pipelines.
///
/// # Errors
///
/// Returns [`MftError`] if the capture file cannot be loaded or reassembled.
fn load_iocp_as_raw_mft<P: AsRef<Path>>(path: P, options: &LoadRawOptions) -> Result<RawMftData> {
    use crate::raw_iocp::load_iocp_capture;

    let capture = load_iocp_capture(path)?;
    let record_size = capture.record_size();
    let total_records = capture.header.total_records;
    let volume_letter = options
        .volume_letter
        .unwrap_or(capture.header.volume_letter);

    // Build header for the reassembled data
    let header = RawMftHeader {
        version: VERSION, // Use current version since we're creating new data
        flags: 0,         // Not compressed (we decompress during load)
        record_size,
        record_count: total_records,
        original_size: total_records * u64::from(record_size),
        compressed_size: 0,
        volume_letter,
        reserved_allocated_bytes: 0, // IOCP reassembly path (carries via IOCP header elsewhere)
    };

    // If header-only mode, return early
    if options.header_only {
        return Ok(RawMftData {
            header,
            data: Vec::new(),
        });
    }

    // Allocate buffer for reassembled MFT data
    let total_size = crate::index::frs_to_usize(total_records * u64::from(record_size));
    let mut data = vec![0_u8; total_size];

    // Collect chunks and sort by start_frs for sequential reassembly
    let mut chunks: Vec<_> = capture.iter_chunks().collect();
    chunks.sort_by_key(|(chunk, _)| chunk.start_frs);

    // Copy each chunk's data to its correct position
    for (chunk, chunk_data) in chunks {
        let start_offset = crate::index::frs_to_usize(chunk.start_frs * u64::from(record_size));
        let expected_size = (chunk.record_count as usize) * (record_size as usize);

        // Validate chunk data size
        if chunk_data.len() != expected_size {
            return Err(MftError::InvalidData(format!(
                "IOCP chunk at FRS {} has wrong size: expected {}, got {}",
                chunk.start_frs,
                expected_size,
                chunk_data.len()
            )));
        }

        // Validate destination bounds
        let end_offset = start_offset + expected_size;
        if end_offset > data.len() {
            return Err(MftError::InvalidData(format!(
                "IOCP chunk at FRS {} extends beyond MFT bounds: {} > {}",
                chunk.start_frs,
                end_offset,
                data.len()
            )));
        }

        // Copy chunk data to correct position
        if let Some(dest) = data.get_mut(start_offset..end_offset) {
            dest.copy_from_slice(chunk_data);
        }
    }

    Ok(RawMftData { header, data })
}

/// Loads only the header from a raw MFT file.
///
/// This is useful for inspecting file metadata without loading the full data.
/// Works with both UFFS-MFT format and raw NTFS format.
///
/// # Errors
///
/// Returns an error if reading fails or file format is invalid.
pub fn load_raw_mft_header<P: AsRef<Path>>(path: P) -> Result<RawMftHeader> {
    let result = load_raw_mft(path, &LoadRawOptions {
        header_only: true,
        volume_letter: None,
        forensic: false,
    })?;
    Ok(result.header)
}

mod streaming_writer;
pub use streaming_writer::StreamingRawMftWriter;

#[cfg(test)]
mod tests;
