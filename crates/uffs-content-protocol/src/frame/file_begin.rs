// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! `FILE_BEGIN` payload (design-doc §12.4).

use super::{FrameError, ReadMode, read_optional_u64, write_optional_u64};
use crate::codec::{Reader, write_i64_le, write_u32_le, write_u64_le};
use crate::path_encoding::WindowsPath;

// ───────────────────────── FILE_BEGIN (§12.4) ─────────────────────────

/// `FILE_BEGIN` payload. Does not imply success (design-doc §12.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBegin {
    /// Candidate identifier.
    pub candidate_id: u64,
    /// Full NTFS file reference.
    pub file_reference: u64,
    /// Lossless Windows path.
    pub path: WindowsPath,
    /// Logical size at snapshot time.
    pub logical_size: u64,
    /// Modification time, Unix milliseconds.
    pub mtime: i64,
    /// Read mode selected for this attempt.
    pub read_mode: ReadMode,
    /// 1-based attempt number for this candidate within the job.
    pub attempt_number: u32,
    /// Optional shared content-object identifier (design-doc §5.3: hard
    /// links may share one emitted content body).
    pub content_object_id: Option<u64>,
}

impl FileBegin {
    /// Encode this payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u64_le(&mut out, self.candidate_id);
        write_u64_le(&mut out, self.file_reference);
        self.path.encode(&mut out);
        write_u64_le(&mut out, self.logical_size);
        write_i64_le(&mut out, self.mtime);
        out.push(self.read_mode.encode());
        write_u32_le(&mut out, self.attempt_number);
        write_optional_u64(&mut out, self.content_object_id);
        out
    }

    /// Decode this payload.
    ///
    /// # Errors
    /// See [`FrameError`].
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, FrameError> {
        let candidate_id = reader.read_u64_le()?;
        let file_reference = reader.read_u64_le()?;
        let path = WindowsPath::decode(reader, crate::manifest::MAX_PATH_BYTES)?;
        let logical_size = reader.read_u64_le()?;
        let mtime = reader.read_i64_le()?;
        let read_mode_byte = reader.read_u8()?;
        let read_mode =
            ReadMode::decode(read_mode_byte).map_err(|byte| FrameError::UnknownDiscriminant {
                field: "read_mode",
                value: u64::from(byte),
            })?;
        let attempt_number = reader.read_u32_le()?;
        let content_object_id = read_optional_u64(reader)?;
        Ok(Self {
            candidate_id,
            file_reference,
            path,
            logical_size,
            mtime,
            read_mode,
            attempt_number,
            content_object_id,
        })
    }
}
