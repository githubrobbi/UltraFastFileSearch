//! Fallback reader that opens `$MFT` as a regular file.
//!
//! On write-protected volumes, raw-volume I/O (`\\.\X:` + `ReadFile`) fails
//! with `ERROR_WRITE_PROTECT` even for reads.  Opening `X:\$MFT` directly lets
//! the filesystem driver handle VCN→LCN translation, bypassing the restriction.
//! The resulting file is the MFT laid out linearly: byte 0 → FRS 0,
//! byte `record_size` → FRS 1, etc.

#![cfg(windows)]

use tracing::{debug, info, warn};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{FILE_BEGIN, ReadFile, SetFilePointerEx};

use crate::error::Result;
use crate::index::{frs_to_usize, u32_as_usize, usize_to_u64};
use crate::io::AlignedBuffer;
use crate::parse::{MftRecordMerger, ParsedRecord, apply_fixup, parse_record_full};

/// Default chunk size for streaming reads through the `$MFT` file handle.
const MFT_FILE_CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MB

/// Reads the MFT via a file handle obtained from
/// [`crate::platform::VolumeHandle::open_mft_read_handle`].
///
/// Returns `Vec<ParsedRecord>` compatible with the legacy pipeline
/// (`from_parsed_records`).
///
/// # Safety contracts
///
/// `mft_handle` must be a valid, readable `HANDLE` to `X:\$MFT`.
/// The caller is responsible for closing the handle after this function
/// returns.
///
/// # Errors
///
/// Returns an error if `SetFilePointerEx` or `ReadFile` fails on the
/// `$MFT` file handle.
#[expect(
    unsafe_code,
    reason = "FFI: SetFilePointerEx and ReadFile for $MFT file-based reading"
)]
pub(crate) fn read_mft_from_file_handle(
    mft_handle: HANDLE,
    record_size: u32,
    total_records: u64,
) -> Result<Vec<ParsedRecord>> {
    let record_size_usize = u32_as_usize(record_size);
    let total_bytes = total_records * u64::from(record_size);
    let chunk_records = MFT_FILE_CHUNK_SIZE / record_size_usize;
    let chunk_bytes = chunk_records * record_size_usize;

    info!(
        total_records,
        total_bytes_mb = total_bytes / (1024 * 1024),
        chunk_bytes_mb = chunk_bytes / (1024 * 1024),
        "📖 Starting $MFT file-based read (write-protect fallback)"
    );

    let mut merger = MftRecordMerger::with_capacity(frs_to_usize(total_records));
    let mut buffer = AlignedBuffer::new(chunk_bytes + 512); // pad for alignment
    let mut file_offset: u64 = 0;
    let mut frs: u64 = 0;
    let mut bytes_read_total: u64 = 0;
    let mut chunks_read: u64 = 0;

    // Seek to start
    let mut new_pos = 0_i64;
    // SAFETY: `mft_handle` is a live file handle; `new_pos` is valid writable
    // storage for the seek output.
    unsafe { SetFilePointerEx(mft_handle, 0, Some(&raw mut new_pos), FILE_BEGIN) }?;

    while frs < total_records {
        let remaining = total_records - frs;
        let records_this_chunk = frs_to_usize(remaining.min(usize_to_u64(chunk_records)));
        let read_size = records_this_chunk * record_size_usize;

        if buffer.len() < read_size {
            buffer = AlignedBuffer::new(read_size);
        }

        // SAFETY: `mft_handle` is a live $MFT file handle (caller's
        // contract).  `read_one_chunk` reborrows `buffer` exclusively for
        // the duration of the call.
        let actual_bytes =
            unsafe { read_one_chunk(mft_handle, &mut buffer, read_size, file_offset, frs) }?;

        let actual_records = actual_bytes / record_size_usize;
        parse_chunk_records(
            buffer.as_mut_slice(),
            record_size_usize,
            frs,
            actual_records,
            &mut merger,
        );

        frs += usize_to_u64(actual_records);
        file_offset += usize_to_u64(actual_bytes);
        bytes_read_total += usize_to_u64(actual_bytes);
        chunks_read += 1;

        if actual_bytes < read_size {
            debug!(
                actual_bytes,
                expected = read_size,
                "Short read — end of $MFT"
            );
            break;
        }
    }

    let records = merger.merge();
    info!(
        records = records.len(),
        bytes_mb = bytes_read_total / (1024 * 1024),
        chunks = chunks_read,
        "✅ $MFT file-based read complete"
    );

    Ok(records)
}

/// Issue one `ReadFile` of `read_size` bytes against `mft_handle` into the
/// front of `buffer` and return the number of bytes actually read.
///
/// `file_offset` and `frs` are passed only for diagnostic logging on
/// failure.
///
/// # Safety
///
/// Caller must guarantee `mft_handle` is a live, readable file handle.
#[expect(
    unsafe_code,
    reason = "FFI: ReadFile against the caller-supplied $MFT file handle"
)]
unsafe fn read_one_chunk(
    mft_handle: HANDLE,
    buffer: &mut AlignedBuffer,
    read_size: usize,
    file_offset: u64,
    frs: u64,
) -> Result<usize> {
    let Some(read_slice) = buffer.as_mut_slice().get_mut(..read_size) else {
        // Unreachable: caller resizes `buffer` to ≥ read_size before
        // invoking this helper.
        return Err(crate::error::MftError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "MFT read buffer shorter than requested read size",
        )));
    };

    let mut bytes_read = 0_u32;
    // SAFETY: caller guarantees `mft_handle` is live; `read_slice` covers
    // `read_size` writable bytes; `bytes_read` is valid out-storage.
    let read_result = unsafe {
        ReadFile(
            mft_handle,
            Some(read_slice),
            Some(&raw mut bytes_read),
            None,
        )
    };

    if let Err(err) = read_result {
        warn!(
            file_offset,
            frs,
            error = %err,
            "Failed to read $MFT chunk — aborting file-based read"
        );
        return Err(crate::error::MftError::Io(
            std::io::Error::from_raw_os_error(err.code().0),
        ));
    }

    Ok(u32_as_usize(bytes_read))
}

/// Apply NTFS fixup to each record slice in `buffer` and feed the parsed
/// results into `merger`.  Records that fail fixup are silently skipped
/// (matches the previous inline behaviour).
fn parse_chunk_records(
    buffer: &mut [u8],
    record_size: usize,
    base_frs: u64,
    record_count: usize,
    merger: &mut MftRecordMerger,
) {
    for i in 0..record_count {
        let offset = i * record_size;
        let Some(record_slice) = buffer.get_mut(offset..offset + record_size) else {
            // Unreachable: caller bounds `record_count` to the buffer's
            // record capacity.
            break;
        };
        if apply_fixup(record_slice) {
            merger.add_result(parse_record_full(record_slice, base_frs + usize_to_u64(i)));
        }
    }
}
