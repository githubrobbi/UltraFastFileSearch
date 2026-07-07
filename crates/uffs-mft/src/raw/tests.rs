// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Tests for the raw MFT persistence surface.

use super::*;

type TestResult = core::result::Result<(), Box<dyn core::error::Error>>;

#[test]
fn header_roundtrip() -> TestResult {
    let header = RawMftHeader {
        version: VERSION,
        flags: FLAG_COMPRESSED,
        record_size: 1024,
        record_count: 1000,
        original_size: 1024 * 1000,
        compressed_size: 500_000,
        volume_letter: crate::platform::DriveLetter::G,
        reserved_allocated_bytes: 54_587_392,
    };

    let bytes = header.to_bytes();
    let parsed = RawMftHeader::from_bytes(&bytes)?;

    assert_eq!(parsed.version, header.version);
    assert_eq!(parsed.flags, header.flags);
    assert_eq!(parsed.record_size, header.record_size);
    assert_eq!(parsed.record_count, header.record_count);
    assert_eq!(parsed.original_size, header.original_size);
    assert_eq!(parsed.compressed_size, header.compressed_size);
    assert_eq!(parsed.volume_letter, header.volume_letter);
    assert_eq!(
        parsed.reserved_allocated_bytes,
        header.reserved_allocated_bytes
    );
    assert!(parsed.is_compressed());

    Ok(())
}

#[test]
fn header_invalid_magic() {
    let mut bytes = [0_u8; HEADER_SIZE];
    bytes[0..8].copy_from_slice(b"INVALID!");

    let result = RawMftHeader::from_bytes(&bytes);
    result.unwrap_err();
}

#[test]
#[expect(
    clippy::indexing_slicing,
    reason = "test code with known valid indices"
)]
fn save_load_uncompressed() -> TestResult {
    let temp_dir = std::env::temp_dir();
    let path = temp_dir.join("test_mft_uncompressed.raw");

    let record_size = 1024_u32;
    let mut data = vec![0_u8; 4 * record_size as usize];
    for i in 0_u8..4 {
        data[usize::from(i) * record_size as usize] = i;
    }

    let options = SaveRawOptions {
        compress: false,
        compression_level: 3,
        volume_letter: crate::platform::DriveLetter::C,
        raw_compat: false,
        reserved_allocated_bytes: 0,
    };
    let header = save_raw_mft(&path, &data, record_size, &options)?;

    assert_eq!(header.record_count, 4);
    assert_eq!(header.record_size, record_size);
    assert_eq!(header.volume_letter, crate::platform::DriveLetter::C);
    assert!(!header.is_compressed());

    let loaded = load_raw_mft(&path, &LoadRawOptions::default())?;
    assert_eq!(loaded.data.len(), data.len());
    assert_eq!(loaded.data, data);

    for i in 0_u8..4 {
        let record = loaded.get_record(u64::from(i)).ok_or("Record not found")?;
        assert_eq!(record[0], i);
    }

    std::fs::remove_file(&path)?;

    Ok(())
}

#[test]
fn save_load_compressed() -> TestResult {
    let temp_dir = std::env::temp_dir();
    let path = temp_dir.join("test_mft_compressed.raw");

    let record_size = 1024_usize;
    let record_count = 100_usize;
    let mut data = vec![0xAB_u8; record_count * record_size];
    for idx in 0..record_count {
        if let Some(byte) = data.get_mut(idx * record_size) {
            *byte = u8::try_from(idx % 256).unwrap_or(0);
        }
    }

    let record_size_u32 = crate::len_to_u32(record_size);
    let options = SaveRawOptions::default();
    let header = save_raw_mft(&path, &data, record_size_u32, &options)?;

    assert_eq!(header.record_count, 100);
    assert!(header.is_compressed());
    assert!(header.compressed_size < header.original_size);

    let loaded = load_raw_mft(&path, &LoadRawOptions::default())?;
    assert_eq!(loaded.data.len(), data.len());
    assert_eq!(loaded.data, data);

    std::fs::remove_file(&path)?;

    Ok(())
}

#[test]
fn load_header_only() -> TestResult {
    let temp_dir = std::env::temp_dir();
    let path = temp_dir.join("test_mft_header_only.raw");

    let record_size = 1024_u32;
    let data = vec![0_u8; 10 * record_size as usize];

    let options = SaveRawOptions {
        compress: false,
        compression_level: 3,
        volume_letter: crate::platform::DriveLetter::D,
        raw_compat: false,
        reserved_allocated_bytes: 0,
    };
    save_raw_mft(&path, &data, record_size, &options)?;

    let header = load_raw_mft_header(&path)?;
    assert_eq!(header.record_count, 10);
    assert_eq!(header.record_size, record_size);

    std::fs::remove_file(&path)?;

    Ok(())
}

#[test]
#[expect(
    clippy::indexing_slicing,
    reason = "test code with known valid indices"
)]
fn iter_records() {
    let header = RawMftHeader {
        version: VERSION,
        flags: 0,
        record_size: 4,
        record_count: 3,
        original_size: 12,
        compressed_size: 0,
        volume_letter: crate::platform::DriveLetter::X,
        reserved_allocated_bytes: 0,
    };

    let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let raw = RawMftData { header, data };

    let records: Vec<_> = raw.iter_records().collect();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0], (0, &[1, 2, 3, 4][..]));
    assert_eq!(records[1], (1, &[5, 6, 7, 8][..]));
    assert_eq!(records[2], (2, &[9, 10, 11, 12][..]));
}

#[test]
fn volume_letter_preserved() -> TestResult {
    let temp_dir = std::env::temp_dir();
    let path = temp_dir.join("test_mft_volume_letter.raw");

    let record_size = 1024_u32;
    let data = vec![0_u8; 4 * record_size as usize];

    let options = SaveRawOptions {
        compress: false,
        compression_level: 3,
        volume_letter: crate::platform::DriveLetter::G,
        raw_compat: false,
        reserved_allocated_bytes: 0,
    };
    let header = save_raw_mft(&path, &data, record_size, &options)?;
    assert_eq!(header.volume_letter, crate::platform::DriveLetter::G);

    let loaded = load_raw_mft(&path, &LoadRawOptions::default())?;
    assert_eq!(loaded.header.volume_letter, crate::platform::DriveLetter::G);

    std::fs::remove_file(&path)?;

    Ok(())
}

#[test]
#[expect(
    clippy::indexing_slicing,
    reason = "test code with known valid indices"
)]
fn raw_compat_mode() -> TestResult {
    let temp_dir = std::env::temp_dir();
    let path = temp_dir.join("test_mft_raw_compat.raw");

    let record_size = 1024_u32;
    let mut data = vec![0_u8; 4 * record_size as usize];
    for i in 0_u8..4 {
        data[usize::from(i) * record_size as usize] = i;
    }

    let options = SaveRawOptions {
        compress: false,
        compression_level: 3,
        volume_letter: crate::platform::DriveLetter::G,
        raw_compat: true,
        reserved_allocated_bytes: 0,
    };

    let mut writer = StreamingRawMftWriter::new(&path, record_size, &options)?;
    writer.write_chunk(&data)?;
    let header = writer.finish()?;

    assert_eq!(header.version, 0);
    assert_eq!(header.record_count, 4);

    let file_size = std::fs::metadata(&path)?.len();
    assert_eq!(file_size, data.len() as u64);

    let file_content = std::fs::read(&path)?;
    assert_eq!(file_content, data);

    std::fs::remove_file(&path)?;

    Ok(())
}

#[test]
#[expect(
    clippy::indexing_slicing,
    reason = "test code with known valid indices"
)]
fn load_raw_ntfs_format() -> TestResult {
    let temp_dir = std::env::temp_dir();
    let path = temp_dir.join("test_mft_raw_ntfs.raw");

    let record_size = 1024_u32;
    let record_count = 4_u64;
    let mut data = vec![0_u8; crate::frs_to_usize(record_count) * crate::u32_as_usize(record_size)];

    for i in 0..record_count {
        let offset = crate::frs_to_usize(i) * crate::u32_as_usize(record_size);
        data[offset] = b'F';
        data[offset + 1] = b'I';
        data[offset + 2] = b'L';
        data[offset + 3] = b'E';
        data[offset + 28] = 0x00;
        data[offset + 29] = 0x04;
        data[offset + 30] = 0x00;
        data[offset + 31] = 0x00;
    }

    std::fs::write(&path, &data)?;

    let loaded = load_raw_mft(&path, &LoadRawOptions::default())?;

    assert_eq!(loaded.header.version, 0);
    assert_eq!(loaded.header.record_size, record_size);
    assert_eq!(loaded.header.record_count, record_count);
    assert_eq!(loaded.header.volume_letter, crate::platform::DriveLetter::X);
    assert_eq!(loaded.data, data);

    let options = LoadRawOptions {
        header_only: false,
        volume_letter: Some(crate::platform::DriveLetter::D),
        forensic: false,
    };
    let loaded_with_override = load_raw_mft(&path, &options)?;
    assert_eq!(
        loaded_with_override.header.volume_letter,
        crate::platform::DriveLetter::D
    );

    std::fs::remove_file(&path)?;

    Ok(())
}
