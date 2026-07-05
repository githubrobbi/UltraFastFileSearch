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

/// `$Boot` payload size: the boot region is 16 sectors × 512 bytes.
#[cfg(windows)]
const BOOT_BYTES: usize = 8192;

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

/// Read a metafile's raw bytes from a live NTFS volume.
///
/// # Errors
///
/// Returns [`MftError::Io`] / [`MftError::Windows`] if opening the volume or
/// reading fails.
#[cfg(windows)]
pub fn read_metafile(drive: DriveLetter, kind: MetafileKind) -> Result<Vec<u8>> {
    let handle = crate::platform::VolumeHandle::open(drive)?;
    let vol = handle.volume_data();
    match kind {
        // `$Boot` is fixed at LCN 0; read it directly (no data-run parse).
        MetafileKind::Boot => read_boot(&handle),
        // `$Bitmap` is a non-resident unnamed `$DATA` stream.
        MetafileKind::Bitmap => read_data_stream(&handle, vol, 6, None),
        // `$Secure:$SDS` holds deduplicated security descriptors (ACLs).
        MetafileKind::Secure => read_data_stream(&handle, vol, 9, Some("$SDS")),
        // `$AttrDef` / `$MFTMirr` / `$LogFile` are unnamed non-resident `$DATA`
        // streams.
        MetafileKind::AttrDef => read_data_stream(&handle, vol, 4, None),
        MetafileKind::MftMirr => read_data_stream(&handle, vol, 1, None),
        MetafileKind::LogFile => read_data_stream(&handle, vol, 2, None),
        // `$Volume` / `$BadClus` keep their useful data in the MFT record itself
        // (the $VOLUME_* attributes; the $Bad run list), so capture the fixed-up
        // record.
        MetafileKind::Volume => read_frs_record(&handle, vol, 3),
        MetafileKind::BadClus => read_frs_record(&handle, vol, 8),
        // `$UsnJrnl:$J` lives under `$Extend`; resolve its FRS then read `$J`.
        MetafileKind::UsnJrnl => read_usn_journal(&handle, vol),
    }
}

/// Read a metafile's raw bytes (non-Windows stub).
///
/// # Errors
///
/// Always returns [`MftError::PlatformNotSupported`].
#[cfg(not(windows))]
pub const fn read_metafile(_drive: DriveLetter, _kind: MetafileKind) -> Result<Vec<u8>> {
    Err(MftError::PlatformNotSupported)
}

/// `$Boot` is the volume boot region: 8 KiB starting at LCN 0 (byte offset 0).
#[cfg(windows)]
fn read_boot(handle: &crate::platform::VolumeHandle) -> Result<Vec<u8>> {
    let mut buf = vec![0_u8; BOOT_BYTES];
    super::volume::read_handle_at(handle.raw_handle(), 0, &mut buf)?;
    Ok(buf)
}

/// Read a raw MFT file-record segment (FRS) with USA fixup applied.
#[cfg(windows)]
fn read_frs_record(
    handle: &crate::platform::VolumeHandle,
    vol: &crate::platform::NtfsVolumeData,
    frs: u64,
) -> Result<Vec<u8>> {
    let record_size = vol.bytes_per_file_record_segment as usize;
    let offset = handle.mft_byte_offset() + frs * u64::from(vol.bytes_per_file_record_segment);
    let mut record = vec![0_u8; record_size];
    super::volume::read_handle_at(handle.raw_handle(), offset, &mut record)?;
    crate::parse::apply_fixup(&mut record);
    Ok(record)
}

/// Read a metafile's non-resident `$DATA` stream — the unnamed stream when
/// `stream_name` is `None`, or the named stream (e.g. `$SDS`) otherwise — by
/// resolving its data runs and reading the referenced clusters.
#[cfg(windows)]
fn read_data_stream(
    handle: &crate::platform::VolumeHandle,
    vol: &crate::platform::NtfsVolumeData,
    frs: u64,
    stream_name: Option<&str>,
) -> Result<Vec<u8>> {
    use crate::ntfs::{AttributeIterator, AttributeType};

    let record = read_frs_record(handle, vol, frs)?;
    let want_name: Option<Vec<u16>> = stream_name.map(|name| name.encode_utf16().collect());

    let mut attrs = AttributeIterator::new(&record)
        .ok_or_else(|| MftError::InvalidData(format!("FRS {frs}: invalid record header")))?;
    let data_attr = attrs
        .find(|attr| {
            attr.attribute_type() == Some(AttributeType::Data)
                && attr.is_non_resident()
                && want_name
                    .as_deref()
                    .map_or(attr.header.name_length == 0, |want| {
                        attr.name() == Some(want)
                    })
        })
        .ok_or_else(|| {
            MftError::InvalidData(format!(
                "FRS {frs}: no matching non-resident DATA stream (name={stream_name:?})"
            ))
        })?;

    let non_resident = data_attr.non_resident_data().ok_or_else(|| {
        MftError::InvalidData(format!("FRS {frs}: cannot decode non-resident DATA header"))
    })?;
    let data_size = non_resident.data_size.cast_unsigned();
    let runs = data_attr.data_runs();
    read_runs(handle.raw_handle(), &runs, vol.bytes_per_cluster, data_size)
}

/// Assemble a stream's data runs into a `data_size`-byte buffer.
///
/// Sparse runs leave their window zeroed; the buffer is truncated to the
/// attribute's real `data_size` (runs are cluster-rounded).
#[cfg(windows)]
fn read_runs(
    handle: windows::Win32::Foundation::HANDLE,
    runs: &[crate::ntfs::DataRun],
    bytes_per_cluster: u32,
    data_size: u64,
) -> Result<Vec<u8>> {
    let bpc = u64::from(bytes_per_cluster);
    let total = usize::try_from(data_size).map_err(|_err| {
        MftError::InvalidData("metafile data_size exceeds usize::MAX".to_owned())
    })?;
    let mut buf = vec![0_u8; total];
    let mut offset: usize = 0;

    for run in runs {
        if offset >= total {
            break;
        }
        let run_bytes = usize::try_from(run.cluster_count * bpc).map_err(|_err| {
            MftError::InvalidData("metafile run byte count exceeds usize::MAX".to_owned())
        })?;
        let read_len = run_bytes.min(total - offset);
        if run.is_sparse() {
            // Sparse run — leave the buffer window zeroed.
            offset += read_len;
            continue;
        }
        let disk_offset = crate::index::nonneg_to_u64(run.lcn.raw() * bpc.cast_signed());
        let Some(window) = buf.get_mut(offset..offset + read_len) else {
            return Err(MftError::InvalidData(format!(
                "metafile run at offset {offset} len {read_len} exceeds buffer {total}"
            )));
        };
        super::volume::read_handle_at(handle, disk_offset, window)?;
        offset += read_len;
    }
    Ok(buf)
}

/// FRS of the `$Extend` metadata directory.
#[cfg(windows)]
const EXTEND_FRS: u64 = 11;

/// Read the `$UsnJrnl:$J` change journal via `$Extend` directory traversal.
#[cfg(windows)]
fn read_usn_journal(
    handle: &crate::platform::VolumeHandle,
    vol: &crate::platform::NtfsVolumeData,
) -> Result<Vec<u8>> {
    let usn_frs = resolve_extend_child(handle, vol, "$UsnJrnl")?;
    read_data_stream(handle, vol, usn_frs, Some("$J"))
}

/// Resolve the FRS of a `$Extend` (FRS 11) child by name, walking its directory
/// index — `$INDEX_ROOT` first, then `$INDEX_ALLOCATION` if the index is large.
#[cfg(windows)]
fn resolve_extend_child(
    handle: &crate::platform::VolumeHandle,
    vol: &crate::platform::NtfsVolumeData,
    child: &str,
) -> Result<u64> {
    use crate::ntfs::{AttributeIterator, AttributeType, DataRun};

    let record = read_frs_record(handle, vol, EXTEND_FRS)?;
    let target: Vec<u16> = child.encode_utf16().collect();

    let mut root_value: Option<Vec<u8>> = None;
    let mut block_size: usize = 0;
    let mut alloc: Option<(Vec<DataRun>, u64)> = None;

    let attrs = AttributeIterator::new(&record)
        .ok_or_else(|| MftError::InvalidData("$Extend: invalid record header".to_owned()))?;
    for attr in attrs {
        match attr.attribute_type() {
            Some(AttributeType::IndexRoot) => {
                if let Some(value) = attr.resident_value() {
                    // IndexRoot.bytes_per_index_block is at offset 8.
                    block_size = value
                        .get(8..12)
                        .and_then(|slice| slice.try_into().ok())
                        .map_or(0, |bytes| u32::from_le_bytes(bytes) as usize);
                    root_value = Some(value.to_vec());
                }
            }
            Some(AttributeType::IndexAllocation) if attr.is_non_resident() => {
                if let Some(nr) = attr.non_resident_data() {
                    alloc = Some((attr.data_runs(), nr.data_size.cast_unsigned()));
                }
            }
            _ => {}
        }
    }

    // 1. Search the resident $INDEX_ROOT (its INDEX_HEADER begins at offset 16).
    if let Some(frs) = root_value
        .as_deref()
        .and_then(|root| scan_index_entries(root, 16, &target))
    {
        return Ok(frs);
    }

    // 2. Search the $INDEX_ALLOCATION INDX blocks, if the index spilled.
    if let Some((runs, size)) = alloc
        && block_size > 0
    {
        let buf = read_runs(handle.raw_handle(), &runs, vol.bytes_per_cluster, size)?;
        if let Some(frs) = scan_index_blocks(&buf, block_size, &target) {
            return Ok(frs);
        }
    }

    Err(MftError::InvalidData(format!(
        "$Extend index: {child} not found (no active USN journal?)"
    )))
}

/// Scan NTFS directory-index entries for the entry whose `$FILE_NAME` matches
/// `target` (UTF-16), returning its FRS. `header_start` is the byte offset of
/// the `INDEX_HEADER` within `buf` (whose `first_entry_offset` is relative to
/// it).
#[cfg(any(windows, test))]
fn scan_index_entries(buf: &[u8], header_start: usize, target: &[u16]) -> Option<u64> {
    let first_entry_offset =
        u32::from_le_bytes(buf.get(header_start..header_start + 4)?.try_into().ok()?) as usize;
    let mut pos = header_start.checked_add(first_entry_offset)?;
    loop {
        let entry = buf.get(pos..)?;
        let flags = u16::from_le_bytes(entry.get(12..14)?.try_into().ok()?);
        // Last-entry flag (0x02): end of this node.
        if (flags & 0x02) != 0 {
            return None;
        }
        let file_reference = u64::from_le_bytes(entry.get(0..8)?.try_into().ok()?);
        // The $FILE_NAME key starts at entry offset 16: name_length @0x40,
        // UTF-16 name @0x42.
        let name_length = usize::from(*entry.get(16 + 0x40)?);
        let name_bytes = entry.get(16 + 0x42..16 + 0x42 + name_length * 2)?;
        let name: Vec<u16> = name_bytes
            .chunks_exact(2)
            .filter_map(|pair| pair.try_into().ok().map(u16::from_le_bytes))
            .collect();
        if name == target {
            return Some(crate::ntfs::file_reference_to_frs(file_reference));
        }
        let entry_length = usize::from(u16::from_le_bytes(entry.get(8..10)?.try_into().ok()?));
        if entry_length == 0 {
            return None;
        }
        pos = pos.checked_add(entry_length)?;
    }
}

/// Scan the `INDX` blocks in an `$INDEX_ALLOCATION` buffer for `target`.
#[cfg(windows)]
fn scan_index_blocks(buf: &[u8], block_size: usize, target: &[u16]) -> Option<u64> {
    if block_size == 0 {
        return None;
    }
    for start in (0..buf.len()).step_by(block_size) {
        let Some(end) = start.checked_add(block_size) else {
            break;
        };
        let Some(block) = buf.get(start..end) else {
            break;
        };
        if !block.starts_with(b"INDX") {
            continue; // sparse / unused block
        }
        let mut owned = block.to_vec();
        let usa_offset = u16::from_le_bytes(owned.get(4..6)?.try_into().ok()?);
        let usa_count = u16::from_le_bytes(owned.get(6..8)?.try_into().ok()?);
        if !crate::ntfs::apply_usa_fixup(&mut owned, usa_offset, usa_count) {
            continue;
        }
        // The INDEX_HEADER begins at offset 0x18 within an INDX block.
        if let Some(frs) = scan_index_entries(&owned, 0x18, target) {
            return Some(frs);
        }
    }
    None
}

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
    use super::{HEADER_SIZE, MetafileHeader, MetafileKind, scan_index_entries};
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

    #[test]
    #[expect(
        clippy::indexing_slicing,
        reason = "test builds a fixed 256-byte index buffer with known in-bounds offsets"
    )]
    fn scan_index_entries_resolves_child_frs() {
        // Minimal $INDEX_ROOT-style buffer: INDEX_HEADER at offset 0
        // (first_entry_offset = 16), one entry for "$UsnJrnl" → FRS 42.
        let mut buf = vec![0_u8; 256];
        buf[0..4].copy_from_slice(&16_u32.to_le_bytes()); // first_entry_offset
        let entry = 16_usize;
        buf[entry..entry + 8].copy_from_slice(&42_u64.to_le_bytes()); // file_reference
        // flags @ entry+12 stay 0 (not the last entry).
        let name: Vec<u16> = "$UsnJrnl".encode_utf16().collect();
        let key = entry + 16;
        buf[key + 0x40] = 8; // name_length (UTF-16 code units)
        for (i, unit) in name.iter().enumerate() {
            let off = key + 0x42 + i * 2;
            buf[off..off + 2].copy_from_slice(&unit.to_le_bytes());
        }

        let target: Vec<u16> = "$UsnJrnl".encode_utf16().collect();
        assert_eq!(scan_index_entries(&buf, 0, &target), Some(42));

        // A miss: entry_length is 0 after the single entry, so the scan stops.
        let miss: Vec<u16> = "$Nope".encode_utf16().collect();
        assert_eq!(scan_index_entries(&buf, 0, &miss), None);
    }
}
