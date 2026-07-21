// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Helpers for parsing core NTFS attributes from MFT record bytes.

use zerocopy::FromBytes as _;

use crate::index::nonneg_to_u64;
use crate::ntfs::{ExtendedStandardInfo, NameInfo, StreamInfo};

/// Outcome of a `$STANDARD_INFORMATION` parse.
///
/// Exists so a failed parse is distinguishable from a record whose `$SI`
/// genuinely reads 1601-01-01. When the attribute cannot be decoded, the
/// caller's [`ExtendedStandardInfo`] is left untouched — every timestamp
/// stays `0`, i.e. FILETIME 1601-01-01 — which is a legitimate value a real
/// record can hold. Without this status the two are identical, and a
/// consumer building a forensic record would report the default as fact.
///
/// Callers that do not care may simply ignore the returned value; it costs
/// nothing, because the variant is just which branch the parser already took.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StdInfoParse {
    /// No `$STANDARD_INFORMATION` attribute was seen at all.
    ///
    /// Never returned by `parse_standard_info_full` (crate-private, hence no
    /// doc link), which is only called
    /// once an `$SI` attribute has been found: it is the initial state a
    /// record-level parser starts from, and what survives if the attribute
    /// loop never encounters one.
    #[default]
    Absent,
    /// Decoded as the 72-byte NTFS 3.0+ layout. All fields are populated.
    V30,
    /// Decoded as the 36-byte NTFS 1.2 layout. `usn`, `security_id`,
    /// `owner_id`, `quota_charged`, `max_versions`, `version_number` and
    /// `class_id` stay zero because that layout has no such fields — this is
    /// correct, not damage.
    V12,
    /// The attribute is present but could not be decoded: its resident
    /// header ran past the end of the record, its declared value length was
    /// under the 36-byte minimum, or its payload overran the buffer. The
    /// timestamps left behind are defaults, **not** data from the volume.
    Malformed,
}

impl StdInfoParse {
    /// Whether the attribute was present but undecodable.
    ///
    /// Distinct from [`Self::Absent`]: a record with no `$SI` at all is
    /// unusual but not evidence of damage, while a malformed one is.
    #[must_use]
    pub const fn is_malformed(self) -> bool {
        matches!(self, Self::Malformed)
    }

    /// Whether real on-disk values reached the caller's
    /// [`ExtendedStandardInfo`].
    ///
    /// `false` for both [`Self::Absent`] and [`Self::Malformed`], where the
    /// timestamps are defaults rather than volume data.
    #[must_use]
    pub const fn is_decoded(self) -> bool {
        matches!(self, Self::V30 | Self::V12)
    }
}

/// Parses `$STANDARD_INFORMATION` into `ExtendedStandardInfo`.
///
/// Handles both NTFS 1.2 (36 bytes) and NTFS 3.0+ (72 bytes) formats.
/// For NTFS 3.0+, also extracts `usn`, `security_id`, `owner_id`,
/// `quota_charged`, `max_versions`, `version_number`, and `class_id`; these
/// stay zero for NTFS 1.2, whose 36-byte layout has no such fields.
///
/// Returns which layout was decoded, or [`StdInfoParse::Malformed`] when the
/// attribute could not be decoded and `result` was left untouched. See
/// [`StdInfoParse`] for why that distinction matters; callers with no use for
/// it can discard the value by ignoring it — deliberately not `#[must_use]`,
/// since the bulk pipelines have nowhere to record it and dropping it is the
/// correct, zero-cost choice there.
///
/// `pub(crate)`: this is the single source of truth for `$STANDARD_INFORMATION`
/// parsing and is also called directly from `crate::io::parser::unified`, which
/// sits outside the `parse` module tree.
pub(crate) fn parse_standard_info_full(
    data: &[u8],
    attr_offset: usize,
    result: &mut ExtendedStandardInfo,
) -> StdInfoParse {
    use core::mem::size_of;

    use crate::ntfs::{
        STANDARD_INFO_SIZE_V12, STANDARD_INFO_SIZE_V30, StandardInformation,
        StandardInformationExtended,
    };

    // The resident-attribute header fields read below — value length (bytes
    // 16..20) and value offset (20..22) — may fall past the end of a
    // truncated or malformed record. Slice with `get` so fuzzed / corrupt
    // input yields an early return instead of an out-of-bounds panic.
    let Some(value_length_bytes) = data.get(attr_offset + 16..attr_offset + 20) else {
        return StdInfoParse::Malformed;
    };
    let value_length =
        u32::from_le_bytes(value_length_bytes.try_into().unwrap_or([0, 0, 0, 0])) as usize;
    let Some(value_offset_bytes) = data.get(attr_offset + 20..attr_offset + 22) else {
        return StdInfoParse::Malformed;
    };
    let value_offset = u16::from_le_bytes(value_offset_bytes.try_into().unwrap_or([0, 0])) as usize;

    let si_offset = attr_offset + value_offset;

    if value_length >= STANDARD_INFO_SIZE_V30
        && si_offset + size_of::<StandardInformationExtended>() <= data.len()
    {
        let Ok((si, _)) = StandardInformationExtended::read_from_prefix(&data[si_offset..]) else {
            return StdInfoParse::Malformed;
        };

        *result = ExtendedStandardInfo {
            created: si.creation_time,
            modified: si.modification_time,
            accessed: si.access_time,
            mft_changed: si.mft_change_time,
            usn: si.usn,
            security_id: si.security_id,
            owner_id: si.owner_id,
            quota_charged: si.quota_charged,
            max_versions: si.max_versions,
            version_number: si.version_number,
            class_id: si.class_id,
            ..ExtendedStandardInfo::from_attributes(si.file_attributes)
        };

        StdInfoParse::V30
    } else if value_length >= STANDARD_INFO_SIZE_V12
        && si_offset + size_of::<StandardInformation>() <= data.len()
    {
        let Ok((si, _)) = StandardInformation::read_from_prefix(&data[si_offset..]) else {
            return StdInfoParse::Malformed;
        };

        *result = ExtendedStandardInfo {
            created: si.creation_time,
            modified: si.modification_time,
            accessed: si.access_time,
            mft_changed: si.mft_change_time,
            usn: 0,
            security_id: 0,
            owner_id: 0,
            ..ExtendedStandardInfo::from_attributes(si.file_attributes)
        };

        StdInfoParse::V12
    } else {
        // Attribute present, but its declared length is under the 36-byte
        // minimum or its payload overruns the record.
        StdInfoParse::Malformed
    }
}

/// Parses `$FILE_NAME` and returns a `NameInfo` with timestamps.
pub(super) fn parse_file_name_full(
    data: &[u8],
    attr_offset: usize,
    source_frs: u64,
) -> Option<NameInfo> {
    use core::mem::size_of;

    use smallvec::SmallVec;

    use crate::ntfs::{FileNameAttribute, file_reference_to_frs};

    let value_offset_bytes = &data[attr_offset + 20..attr_offset + 22];
    let value_offset = u16::from_le_bytes(value_offset_bytes.try_into().unwrap_or([0, 0])) as usize;

    let fn_offset = attr_offset + value_offset;
    if fn_offset + size_of::<FileNameAttribute>() > data.len() {
        return None;
    }

    let Ok((fn_attr, _)) = FileNameAttribute::read_from_prefix(&data[fn_offset..]) else {
        return None;
    };

    let name_len = usize::from(fn_attr.file_name_length);
    let name_offset = fn_offset + size_of::<FileNameAttribute>();

    if name_offset + name_len * 2 > data.len() {
        return None;
    }

    let name_bytes = &data[name_offset..name_offset + name_len * 2];
    let name_u16: SmallVec<[u16; 128]> = name_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes(*chunk))
        .collect();

    let name = String::from_utf16(&name_u16).ok()?;

    Some(NameInfo {
        name,
        // On-disk → typed boundary: `file_reference_to_frs` keeps its
        // `u64` ABI (it decodes the 48-bit `parent_directory` field of
        // `MFT_SEGMENT_REFERENCE`); we lift into `ParentFrs` here so
        // every downstream consumer reads a typed parent reference.
        parent_frs: crate::frs::ParentFrs::new(file_reference_to_frs(fn_attr.parent_directory)),
        namespace: fn_attr.file_name_namespace,
        fn_created: fn_attr.creation_time,
        fn_modified: fn_attr.modification_time,
        fn_accessed: fn_attr.access_time,
        fn_mft_changed: fn_attr.mft_change_time,
        source_frs: crate::frs::Frs::new(source_frs),
    })
}

/// Parses `$DATA` attribute and returns a `StreamInfo`.
///
/// # Special handling for `$BadClus:$Bad`
/// The `$BadClus` file (FRS 8) has a `$Bad` stream that is a sparse file
/// spanning the entire volume. We use `InitializedSize` instead of `DataSize`
/// for this stream to avoid reporting the full volume size.
pub(super) fn parse_data_attribute_full(
    data: &[u8],
    attr_offset: usize,
    header: &crate::ntfs::AttributeRecordHeader,
    frs: u64,
) -> Option<StreamInfo> {
    use smallvec::SmallVec;

    let stream_name = if header.name_length > 0 {
        let name_offset = attr_offset + usize::from(header.name_offset);
        let name_len = usize::from(header.name_length);
        if name_offset + name_len * 2 > data.len() {
            return None;
        }
        let name_bytes = &data[name_offset..name_offset + name_len * 2];
        let name_u16: SmallVec<[u16; 64]> = name_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| u16::from_le_bytes(*chunk))
            .collect();
        String::from_utf16(&name_u16).unwrap_or_default()
    } else {
        String::new()
    };

    let is_resident = header.is_non_resident == 0;

    if !is_resident {
        let nr_offset = attr_offset + 16;
        if nr_offset + 8 > data.len() {
            return None;
        }
        let lowest_vcn = i64::from_le_bytes(data[nr_offset..nr_offset + 8].try_into().ok()?);
        if lowest_vcn != 0 {
            return None;
        }
    }

    let (size, allocated_size, is_sparse, is_compressed) = if is_resident {
        let value_length_bytes = &data[attr_offset + 16..attr_offset + 20];
        let value_length = u32::from_le_bytes(value_length_bytes.try_into().ok()?);
        (u64::from(value_length), 0, false, false)
    } else {
        let nr_offset = attr_offset + 16;
        if nr_offset + 48 > data.len() {
            return None;
        }

        let allocated_size =
            i64::from_le_bytes(data[nr_offset + 24..nr_offset + 32].try_into().ok()?);
        let data_size = i64::from_le_bytes(data[nr_offset + 32..nr_offset + 40].try_into().ok()?);
        let initialized_size =
            i64::from_le_bytes(data[nr_offset + 40..nr_offset + 48].try_into().ok()?);

        let compression_unit = data[nr_offset + 18];
        let is_compressed = compression_unit > 0;
        let is_sparse = (header.flags & 0x8000) != 0;

        let effective_allocated_raw = if is_compressed {
            if nr_offset + 56 <= data.len() {
                i64::from_le_bytes(data[nr_offset + 48..nr_offset + 56].try_into().ok()?)
            } else {
                allocated_size
            }
        } else {
            allocated_size
        };

        let is_badclus_bad = frs == 8 && stream_name == "$Bad";
        let effective_size = if is_badclus_bad {
            nonneg_to_u64(initialized_size)
        } else {
            nonneg_to_u64(data_size)
        };
        let effective_allocated = if is_badclus_bad {
            nonneg_to_u64(initialized_size)
        } else {
            nonneg_to_u64(effective_allocated_raw)
        };

        (
            effective_size,
            effective_allocated,
            is_sparse,
            is_compressed,
        )
    };

    Some(StreamInfo {
        name: stream_name,
        size,
        allocated_size,
        is_sparse,
        is_compressed,
        is_resident,
    })
}
