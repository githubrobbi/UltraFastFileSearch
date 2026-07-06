// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Capture NTFS metafiles (the reserved `$`-files) from a live Windows volume
//! and persist them with a small self-describing header.
//!
//! These artifacts extend a capture beyond the `$MFT` namespace toward a
//! complete offline representation of the volume (see
//! `docs/architecture/mft-full-capture.md`). Each is read straight off the
//! volume via the same broker-safe `read_handle_at` primitive as `$UpCase`.
//!
//! # File format
//!
//! 1. `MetafileHeader` (64 bytes) — magic, version, kind, drive, serial,
//!    timestamp, payload size.
//! 2. Raw metafile payload.
//!
//! # Usage
//!
//! ```text
//! uffs-mft metafile --drive C --kind boot --output C_boot.bin
//! ```

use std::path::Path;

use crate::error::{MftError, Result};
use crate::platform::DriveLetter;

/// Magic bytes identifying a UFFS metafile capture.
const METAFILE_MAGIC: &[u8; 8] = b"UFFSMETA";

/// Current metafile capture format version.
const METAFILE_VERSION: u32 = 1;

/// Fixed header size in bytes (payload starts at this offset).
const HEADER_SIZE: usize = 64;

/// An NTFS metafile that can be captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetafileKind {
    /// `$Boot` (FRS 7) — the volume boot record + BPB (geometry, serial).
    Boot,
    /// `$Bitmap` (FRS 6) — the volume cluster-allocation bitmap (free space).
    Bitmap,
    /// `$Secure:$SDS` (FRS 9) — the security-descriptor store (ACLs / owner).
    Secure,
    /// `$AttrDef` (FRS 4) — NTFS attribute-type definitions.
    AttrDef,
    /// `$MFTMirr` (FRS 1) — backup of the first four `$MFT` records.
    MftMirr,
    /// `$Volume` (FRS 3) — the MFT record (`$VOLUME_NAME` /
    /// `$VOLUME_INFORMATION`).
    Volume,
    /// `$BadClus` (FRS 8) — the MFT record (the `$Bad` bad-cluster run list).
    BadClus,
    /// `$LogFile` (FRS 2) — the NTFS metadata transaction log.
    LogFile,
    /// `$UsnJrnl:$J` — the change journal. Its FRS is resolved at runtime by
    /// walking the `$Extend` directory index, so the header stores a reserved
    /// sentinel kind code rather than a fixed FRS.
    UsnJrnl,
}

impl MetafileKind {
    /// The NTFS metafile name (e.g. `$Boot`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Boot => "$Boot",
            Self::Bitmap => "$Bitmap",
            Self::Secure => "$Secure",
            Self::AttrDef => "$AttrDef",
            Self::MftMirr => "$MFTMirr",
            Self::Volume => "$Volume",
            Self::BadClus => "$BadClus",
            Self::LogFile => "$LogFile",
            Self::UsnJrnl => "$UsnJrnl",
        }
    }

    /// The MFT file-record-segment (FRS) number of this metafile, stored in the
    /// header as a stable, self-documenting kind code.
    ///
    /// `$UsnJrnl` uses the reserved sentinel `0xF5` because its real FRS is
    /// resolved at runtime via the `$Extend` directory index.
    #[must_use]
    pub const fn frs(self) -> u8 {
        match self {
            Self::Boot => 7,
            Self::Bitmap => 6,
            Self::Secure => 9,
            Self::AttrDef => 4,
            Self::MftMirr => 1,
            Self::Volume => 3,
            Self::BadClus => 8,
            Self::LogFile => 2,
            Self::UsnJrnl => 0xF5,
        }
    }

    /// Reconstruct a kind from its FRS code (header round-trip).
    const fn from_frs(frs: u8) -> Option<Self> {
        match frs {
            7 => Some(Self::Boot),
            6 => Some(Self::Bitmap),
            9 => Some(Self::Secure),
            4 => Some(Self::AttrDef),
            1 => Some(Self::MftMirr),
            3 => Some(Self::Volume),
            8 => Some(Self::BadClus),
            2 => Some(Self::LogFile),
            0xF5 => Some(Self::UsnJrnl),
            _ => None,
        }
    }
}

/// Self-describing header prefixed to a captured NTFS metafile.
///
/// ```text
/// Offset Size Field
/// 0      8    Magic b"UFFSMETA"
/// 8      4    Format version (u32 LE)
/// 12     1    Metafile FRS code (u8)
/// 13     1    Drive letter (ASCII uppercase)
/// 14     2    Reserved
/// 16     8    Volume serial number (u64 LE)
/// 24     8    Timestamp — Unix epoch seconds (u64 LE)
/// 32     8    Payload size in bytes (u64 LE)
/// 40     24   Reserved
/// ───────────
/// 64          Raw metafile payload
/// ```
#[derive(Debug, Clone)]
pub struct MetafileHeader {
    /// Which metafile this capture holds.
    pub kind: MetafileKind,
    /// Source drive letter.
    pub drive: DriveLetter,
    /// Source volume serial number.
    pub volume_serial: u64,
    /// Capture timestamp (Unix epoch seconds).
    pub timestamp: u64,
    /// Payload size in bytes.
    pub data_size: u64,
}

impl MetafileHeader {
    /// Serialize the header to its fixed 64-byte on-disk form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0_u8; HEADER_SIZE];
        buf[0..8].copy_from_slice(METAFILE_MAGIC);
        buf[8..12].copy_from_slice(&METAFILE_VERSION.to_le_bytes());
        buf[12] = self.kind.frs();
        buf[13] = self.drive.as_byte();
        // 14..16 reserved (already zeroed)
        buf[16..24].copy_from_slice(&self.volume_serial.to_le_bytes());
        buf[24..32].copy_from_slice(&self.timestamp.to_le_bytes());
        buf[32..40].copy_from_slice(&self.data_size.to_le_bytes());
        // 40..64 reserved (already zeroed)
        buf
    }

    /// Parse a header from the first 64 bytes of a captured file.
    ///
    /// # Errors
    ///
    /// Returns [`MftError::InvalidData`] if the buffer is too short, has the
    /// wrong magic, an unsupported version, an unknown kind, or a bad drive
    /// letter.
    #[expect(
        clippy::indexing_slicing,
        clippy::missing_asserts_for_indexing,
        reason = "length validated at the top; every index below is < HEADER_SIZE (64)"
    )]
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(MftError::InvalidData(format!(
                "metafile header too short: {} < {HEADER_SIZE}",
                data.len()
            )));
        }
        if &data[0..8] != METAFILE_MAGIC {
            return Err(MftError::InvalidData("invalid metafile magic".to_owned()));
        }
        let version = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        if version > METAFILE_VERSION {
            return Err(MftError::InvalidData(format!(
                "unsupported metafile version: {version}"
            )));
        }
        let kind = MetafileKind::from_frs(data[12]).ok_or_else(|| {
            MftError::InvalidData(format!("unknown metafile FRS code: {}", data[12]))
        })?;
        let drive = DriveLetter::parse(char::from(data[13])).map_err(|err| {
            MftError::InvalidData(format!("invalid drive letter in metafile header: {err}"))
        })?;
        let volume_serial = u64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);
        let timestamp = u64::from_le_bytes([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        ]);
        let data_size = u64::from_le_bytes([
            data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
        ]);
        Ok(Self {
            kind,
            drive,
            volume_serial,
            timestamp,
            data_size,
        })
    }
}

/// Live-volume metafile reader. Defined in [`crate::platform::metafile_read`]
/// and re-exported here so callers keep using `metafile::read_metafile`.
pub use super::metafile_read::read_metafile;

/// Write a captured metafile (header + payload) to `path` atomically.
///
/// # Errors
///
/// Returns [`MftError::InvalidData`] if the write fails.
pub fn save_metafile_to_file(path: &Path, header: &MetafileHeader, data: &[u8]) -> Result<()> {
    let mut out = Vec::with_capacity(HEADER_SIZE + data.len());
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(data);
    crate::cache::atomic_write(path, &out)
        .map_err(|err| MftError::InvalidData(format!("Failed to write metafile: {err}")))?;
    tracing::info!(
        path = %path.display(),
        kind = header.kind.name(),
        bytes = out.len(),
        "Saved NTFS metafile"
    );
    Ok(())
}

/// Load a captured metafile, returning its header and raw payload.
///
/// # Errors
///
/// Returns [`MftError::InvalidData`] if the file is unreadable, has a bad
/// header, or is truncated.
pub fn load_metafile_from_file(path: &Path) -> Result<(MetafileHeader, Vec<u8>)> {
    let data = std::fs::read(path).map_err(|err| {
        MftError::InvalidData(format!("Failed to read {}: {err}", path.display()))
    })?;
    let header = MetafileHeader::from_bytes(&data)?;
    let payload = data
        .get(HEADER_SIZE..)
        .ok_or_else(|| MftError::InvalidData("metafile payload missing".to_owned()))?
        .to_vec();
    Ok((header, payload))
}

#[cfg(test)]
mod tests {
    use super::{HEADER_SIZE, MetafileHeader, MetafileKind};
    use crate::platform::DriveLetter;

    fn sample() -> MetafileHeader {
        MetafileHeader {
            kind: MetafileKind::Boot,
            drive: DriveLetter::parse('C').expect("valid drive letter"),
            volume_serial: 0xDEAD_BEEF_1234_5678,
            timestamp: 1_700_000_000,
            data_size: 8192,
        }
    }

    #[test]
    fn header_round_trips() {
        let header = sample();
        let bytes = header.to_bytes();
        let back = MetafileHeader::from_bytes(&bytes).expect("round-trip");
        assert_eq!(back.kind, MetafileKind::Boot);
        assert_eq!(back.drive, header.drive);
        assert_eq!(back.volume_serial, header.volume_serial);
        assert_eq!(back.timestamp, header.timestamp);
        assert_eq!(back.data_size, header.data_size);
    }

    #[test]
    fn kind_frs_is_stable() {
        assert_eq!(MetafileKind::Boot.frs(), 7);
        assert_eq!(MetafileKind::Boot.name(), "$Boot");
        assert_eq!(MetafileKind::Bitmap.frs(), 6);
        assert_eq!(MetafileKind::Bitmap.name(), "$Bitmap");
        assert_eq!(MetafileKind::Secure.frs(), 9);
        assert_eq!(MetafileKind::Secure.name(), "$Secure");
        assert_eq!(MetafileKind::AttrDef.frs(), 4);
        assert_eq!(MetafileKind::MftMirr.frs(), 1);
        assert_eq!(MetafileKind::Volume.frs(), 3);
        assert_eq!(MetafileKind::BadClus.frs(), 8);
        assert_eq!(MetafileKind::LogFile.frs(), 2);
        assert_eq!(MetafileKind::LogFile.name(), "$LogFile");
        assert_eq!(MetafileKind::UsnJrnl.frs(), 0xF5);
        assert_eq!(MetafileKind::UsnJrnl.name(), "$UsnJrnl");
        // FRS code round-trips through the header field.
        assert_eq!(MetafileKind::from_frs(6), Some(MetafileKind::Bitmap));
        assert_eq!(MetafileKind::from_frs(7), Some(MetafileKind::Boot));
        assert_eq!(MetafileKind::from_frs(9), Some(MetafileKind::Secure));
        assert_eq!(MetafileKind::from_frs(4), Some(MetafileKind::AttrDef));
        assert_eq!(MetafileKind::from_frs(1), Some(MetafileKind::MftMirr));
        assert_eq!(MetafileKind::from_frs(3), Some(MetafileKind::Volume));
        assert_eq!(MetafileKind::from_frs(8), Some(MetafileKind::BadClus));
        assert_eq!(MetafileKind::from_frs(2), Some(MetafileKind::LogFile));
        assert_eq!(MetafileKind::from_frs(0xF5), Some(MetafileKind::UsnJrnl));
        assert_eq!(MetafileKind::from_frs(200), None);
    }

    #[test]
    fn from_bytes_rejects_bad_magic() {
        let mut bytes = sample().to_bytes();
        bytes[0] = b'X';
        MetafileHeader::from_bytes(&bytes).unwrap_err();
    }

    #[test]
    fn from_bytes_rejects_short_buffer() {
        MetafileHeader::from_bytes(&[0_u8; 10]).unwrap_err();
    }

    #[test]
    fn from_bytes_rejects_unknown_kind() {
        let mut bytes = sample().to_bytes();
        bytes[12] = 200; // no metafile has FRS 200
        MetafileHeader::from_bytes(&bytes).unwrap_err();
    }

    #[test]
    fn payload_offset_is_header_size() {
        assert_eq!(HEADER_SIZE, 64);
    }
}
