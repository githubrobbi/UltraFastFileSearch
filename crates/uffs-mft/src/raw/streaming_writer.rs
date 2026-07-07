// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Streaming Raw MFT Writer for high-performance saves.
//!
//! Extracted from `raw.rs` to keep it under the 800 LOC threshold.

use std::fs::File;
use std::io::{BufWriter, Write as _};
use std::path::Path;

use super::{FLAG_COMPRESSED, HEADER_SIZE, RawMftHeader, SaveRawOptions, VERSION};
use crate::error::{MftError, Result};

/// A streaming writer for raw MFT data.
///
/// This writer enables high-performance saves by writing chunks as they are
/// read, rather than buffering the entire MFT in memory. This is critical
/// for large MFTs (10+ GB) where buffering would be prohibitively expensive.
///
/// # Usage
///
/// ```ignore
/// let mut writer = StreamingRawMftWriter::new(path, record_size, estimated_records, options)?;
/// for chunk in chunks {
///     let data = read_chunk(...);
///     writer.write_chunk(&data)?;
/// }
/// let header = writer.finish()?;
/// ```
pub struct StreamingRawMftWriter {
    /// The underlying file writer.
    writer: BufWriter<File>,
    /// Output file path (needed to reopen for header update in compressed
    /// mode).
    output_path: std::path::PathBuf,
    /// Record size in bytes.
    record_size: u32,
    /// Total bytes written (for record count calculation).
    bytes_written: u64,
    /// Whether compression is enabled.
    compress: bool,
    /// Volume letter (e.g., 'C', 'D').
    volume_letter: crate::platform::DriveLetter,
    /// NTFS reserved-cluster bytes for the header's root-allocated adjustment.
    reserved_allocated_bytes: u64,
    /// Whether raw compatibility mode is enabled (no header).
    raw_compat: bool,
    /// Zstd encoder (if compressing).
    encoder: Option<zstd::stream::Encoder<'static, BufWriter<File>>>,
}

impl StreamingRawMftWriter {
    /// Creates a new streaming writer.
    ///
    /// # Arguments
    ///
    /// * `path` - Output file path
    /// * `record_size` - Size of each MFT record in bytes
    /// * `options` - Save options (compression, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created.
    pub fn new<P: AsRef<Path>>(
        path: P,
        record_size: u32,
        options: &SaveRawOptions,
    ) -> Result<Self> {
        let output_path = path.as_ref().to_path_buf();
        let output_file = File::create(path.as_ref())?;
        let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, output_file); // 8MB buffer

        // In raw compatibility mode, don't write any header
        if options.raw_compat {
            return Ok(Self {
                writer,
                output_path,
                record_size,
                bytes_written: 0,
                compress: false, // Raw compat mode doesn't support compression
                volume_letter: options.volume_letter,
                reserved_allocated_bytes: options.reserved_allocated_bytes,
                raw_compat: true,
                encoder: None,
            });
        }

        // Write placeholder header (will be updated in finish())
        let placeholder_header = RawMftHeader {
            version: VERSION,
            flags: if options.compress { FLAG_COMPRESSED } else { 0 },
            record_size,
            record_count: 0,
            original_size: 0,
            compressed_size: 0,
            volume_letter: options.volume_letter,
            reserved_allocated_bytes: options.reserved_allocated_bytes,
        };
        writer.write_all(&placeholder_header.to_bytes())?;

        if options.compress {
            // For compressed output, we need to use a zstd encoder
            // Flush the header first, then create encoder for the data portion
            writer.flush()?;
            let inner_file = writer
                .into_inner()
                .map_err(|err| MftError::Io(err.into_error()))?;
            let encoder = zstd::stream::Encoder::new(
                BufWriter::with_capacity(8 * 1024 * 1024, inner_file),
                options.compression_level,
            )
            .map_err(|err| MftError::Io(std::io::Error::other(err)))?;

            // Create a dummy writer - we use encoder instead for compressed output
            // We need a valid File handle, so create a temp file that we'll never use
            let temp_path = std::env::temp_dir().join(".uffs_streaming_dummy");
            let dummy_file = File::create(&temp_path)?;

            return Ok(Self {
                writer: BufWriter::new(dummy_file),
                output_path,
                record_size,
                bytes_written: 0,
                compress: true,
                volume_letter: options.volume_letter,
                reserved_allocated_bytes: options.reserved_allocated_bytes,
                raw_compat: false,
                encoder: Some(encoder),
            });
        }

        Ok(Self {
            writer,
            output_path,
            record_size,
            bytes_written: 0,
            compress: options.compress,
            volume_letter: options.volume_letter,
            reserved_allocated_bytes: options.reserved_allocated_bytes,
            raw_compat: false,
            encoder: None,
        })
    }

    /// Writes a chunk of raw MFT data.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw MFT bytes to write
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        if let Some(ref mut encoder) = self.encoder {
            encoder
                .write_all(data)
                .map_err(|err| MftError::Io(std::io::Error::other(err)))?;
            self.bytes_written += data.len() as u64;
            return Ok(());
        }

        self.writer.write_all(data)?;
        self.bytes_written += data.len() as u64;
        Ok(())
    }

    /// Finishes writing and returns the final header.
    ///
    /// This updates the header with the actual record count and sizes,
    /// then flushes all buffers.
    ///
    /// # Errors
    ///
    /// Returns an error if flushing or seeking fails.
    pub fn finish(mut self) -> Result<RawMftHeader> {
        use std::io::{Seek as _, SeekFrom};

        let original_size = self.bytes_written;
        let record_count = original_size / u64::from(self.record_size);

        // For raw compatibility mode, just flush and return a header struct
        // (the file has no header, just raw MFT bytes)
        if self.raw_compat {
            self.writer.flush()?;
            return Ok(RawMftHeader {
                version: 0, // Indicates raw compat mode
                flags: 0,
                record_size: self.record_size,
                record_count,
                original_size,
                compressed_size: 0,
                volume_letter: self.volume_letter,
                reserved_allocated_bytes: self.reserved_allocated_bytes,
            });
        }

        let compressed_size = if let Some(encoder) = self.encoder.take() {
            let mut zstd_writer = encoder
                .finish()
                .map_err(|err| MftError::Io(std::io::Error::other(err)))?;
            zstd_writer.flush()?;
            let zstd_file = zstd_writer
                .into_inner()
                .map_err(|err| MftError::Io(err.into_error()))?;
            let metadata = zstd_file.metadata()?;
            // Compressed size is file size minus header
            metadata.len().saturating_sub(HEADER_SIZE as u64)
        } else {
            0
        };

        // Create final header
        let header = RawMftHeader {
            version: VERSION,
            flags: if self.compress { FLAG_COMPRESSED } else { 0 },
            record_size: self.record_size,
            record_count,
            original_size,
            compressed_size,
            volume_letter: self.volume_letter,
            reserved_allocated_bytes: self.reserved_allocated_bytes,
        };

        // For uncompressed, update the header at the beginning of the file
        if !self.compress {
            self.writer.flush()?;
            let mut output_file = self
                .writer
                .into_inner()
                .map_err(|err| MftError::Io(err.into_error()))?;

            // Seek to beginning and write final header
            output_file.seek(SeekFrom::Start(0))?;
            output_file.write_all(&header.to_bytes())?;
            output_file.flush()?;
        }

        // For compressed files, reopen the file and update the header
        // The zstd encoder has already closed the file, so we reopen it
        if self.compress {
            use std::fs::OpenOptions;

            // Reopen the file for read+write to update the header
            let mut output_file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.output_path)?;

            // Seek to beginning and write final header
            output_file.seek(SeekFrom::Start(0))?;
            output_file.write_all(&header.to_bytes())?;
            output_file.flush()?;
        }

        Ok(header)
    }
}
