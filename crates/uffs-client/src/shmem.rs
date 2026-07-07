// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Shared-memory transport for bulk search results (D5.0).
//!
//! When a search returns more rows than [`SHMEM_THRESHOLD`], the daemon
//! writes results to a memory-mapped temp file instead of serialising
//! them as inline JSON.  The client then mmaps the same file, reads the
//! rows, and deletes the file.
//!
//! ## Binary layout (little-endian, `repr(C)`)
//!
//! ```text
//! [ShmemHeader: 48 bytes]
//! [ShmemRecord × row_count: 80 bytes each]
//! [String table: concatenated UTF-8 bytes]
//! ```
//!
//! The string table holds all `path` and `name` values back-to-back.
//! Each `ShmemRecord` stores an offset + length pair pointing into the
//! table.

use core::sync::atomic::{AtomicU64, Ordering};
use std::io;
use std::path::{Path, PathBuf};

use crate::protocol::response::{SearchResponse, SearchRow};

/// Result sets larger than this are written to shared memory.
pub const SHMEM_THRESHOLD: usize = 100_000;

/// `paths_blob` payloads larger than this bypass the JSON-RPC string
/// channel and travel through a raw-bytes shmem file instead.
///
/// ## Why a byte threshold instead of a row count
///
/// The cost of the JSON string channel scales with blob **bytes**, not
/// rows: `serde_json` must walk every byte to escape `\`, `"`, and
/// control characters during encode, and walk every byte again to
/// unescape + UTF-8 validate during decode.  At ~4.5 MB of paths on
/// the `C: ext:dll` benchmark this measured at ~80 ms round-trip
/// (~40 ms encode on the daemon + ~40 ms decode on the client), which
/// is roughly 50 % of the observed 209 ms stdout latency.
///
/// Shmem setup is a fixed ~1-2 ms (open + `set_len` + mmap), so the
/// crossover where shmem beats JSON is ~256 KB.  We round up to
/// 512 KB to keep small payloads (e.g. `--limit 10000`) on the inline
/// path and avoid a file-creation syscall for sub-millisecond blobs.
///
/// The constant is in **bytes** — callers compare `blob.len()`
/// directly, not the row count.  See
/// `uffs_daemon::handler::RequestHandler::try_pack_paths_blob` for the
/// dispatch site.
pub const PATHS_BLOB_SHMEM_THRESHOLD: usize = 512 * 1024;

/// Magic bytes identifying a UFFS shmem file (`"UFFS"` as `u32` LE).
const MAGIC: u32 = 0x5346_4655; // b"UFFS" LE

/// Current binary format version (bumped when `ShmemRecord` layout changes).
///
/// v3 (WI-4.4): the two former `ShmemRecord` padding bytes now carry the
/// `malformed` / `malformed_path` forensic bits. Same 88-byte record size;
/// the bump guards against an old reader interpreting stale padding as flags.
/// Shmem blobs are transient per-query temp files, so no migration is needed —
/// a stale blob is simply rejected and regenerated.
const VERSION: u32 = 3;

// ── On-disk structures ────────────────────────────────────────────────────

/// File header — fixed 48 bytes at offset 0.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct ShmemHeader {
    /// Magic identifier ([`MAGIC`]).
    magic: u32,
    /// Format version ([`VERSION`]).
    version: u32,
    /// Number of result rows.
    row_count: u64,
    /// Byte offset of the string table from file start.
    strings_offset: u64,
    /// Search duration in milliseconds.
    duration_ms: u64,
    /// Total records scanned.
    records_scanned: u64,
    /// Whether the result set was truncated (0 or 1).
    truncated: u32,
    /// Reserved for future use.
    _reserved: u32,
}

/// Per-row fixed-size record — 88 bytes, naturally aligned.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct ShmemRecord {
    /// Drive letter as ASCII byte.
    drive: u8,
    /// 1 = directory, 0 = file.
    is_directory: u8,
    /// WI-4.4: 1 = leaf name is ill-formed (not valid UTF-8), else 0.
    /// Repurposes a former alignment-padding byte — zero size cost.
    malformed: u8,
    /// WI-4.4: 1 = some path component is ill-formed, else 0.
    /// Repurposes the second former padding byte — zero size cost.
    malformed_path: u8,
    /// Raw NTFS attribute flags.
    flags: u32,
    /// Logical file size.
    size: u64,
    /// On-disk allocated size.
    allocated: u64,
    /// Last-modified timestamp (Unix µs).
    modified: i64,
    /// Creation timestamp (Unix µs).
    created: i64,
    /// Last-access timestamp (Unix µs).
    accessed: i64,
    /// Descendant count (dirs only).
    descendants: u32,
    /// Padding.
    _pad2: u32,
    /// Subtree total size (dirs only).
    treesize: u64,
    /// Subtree allocated size (dirs only).
    tree_allocated: u64,
    /// Byte offset of the path string in the string table.
    path_off: u32,
    /// Byte length of the path string.
    path_len: u32,
    /// Byte offset of the name string in the string table.
    name_off: u32,
    /// Byte length of the name string.
    name_len: u32,
}

// Compile-time size checks — binary format depends on exact layout.
const _: () = assert!(
    size_of::<ShmemHeader>() == 48,
    "ShmemHeader layout changed — binary format requires exactly 48 bytes"
);
const _: () = assert!(
    size_of::<ShmemRecord>() == 88,
    "ShmemRecord layout changed — binary format requires exactly 88 bytes"
);

// ── Public API ────────────────────────────────────────────────────────────

/// Directory inside the UFFS data folder where shmem files are stored.
const SHMEM_DIR: &str = "shmem";

/// Monotonic counter for unique shmem file names.
static SHMEM_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Return the shmem directory path, creating it if necessary.
///
/// # Errors
///
/// Returns [`std::io::Error`] if the directory cannot be created.
fn shmem_dir() -> io::Result<PathBuf> {
    let base = dirs_next::data_local_dir()
        .unwrap_or_else(|| PathBuf::from(if cfg!(windows) { r"C:\temp" } else { "/tmp" }));
    let dir = base.join("uffs").join(SHMEM_DIR);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Generate a unique shmem file path.
///
/// # Errors
///
/// Returns [`std::io::Error`] if the shmem directory cannot be created.
fn unique_shmem_path() -> io::Result<PathBuf> {
    let dir = shmem_dir()?;
    let pid = std::process::id();
    let seq = SHMEM_COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(dir.join(format!("search_{pid}_{seq}.bin")))
}

/// Write search results to a shared-memory file.
///
/// Returns the file path on success. The caller should include this path
/// in the `SearchResponse.shmem_path` field so the client can read it.
///
/// # Errors
///
/// Returns `io::Error` on file creation, mmap, or write failure.
#[expect(
    unsafe_code,
    reason = "memmap2::MmapMut requires unsafe — mmap is a kernel-level operation"
)]
#[expect(
    clippy::indexing_slicing,
    reason = "mmap is sized to total_size; all slices are within bounds by construction"
)]
pub fn write_search_results(
    rows: &[SearchRow],
    duration_ms: u64,
    records_scanned: u64,
    truncated: bool,
) -> io::Result<PathBuf> {
    let path = unique_shmem_path()?;
    let row_count = rows.len();

    // Build string table and record offsets.
    let mut string_table = Vec::new();
    let mut records: Vec<ShmemRecord> = Vec::with_capacity(row_count);
    for row in rows {
        let path_off = u32::try_from(string_table.len()).unwrap_or(u32::MAX);
        let path_bytes = row.path.as_bytes();
        string_table.extend_from_slice(path_bytes);
        let path_len = u32::try_from(path_bytes.len()).unwrap_or(u32::MAX);

        let name_off = u32::try_from(string_table.len()).unwrap_or(u32::MAX);
        let name_bytes = row.name.as_bytes();
        string_table.extend_from_slice(name_bytes);
        let name_len = u32::try_from(name_bytes.len()).unwrap_or(u32::MAX);

        records.push(ShmemRecord {
            drive: row.drive.as_byte(),
            is_directory: u8::from(row.is_directory),
            malformed: u8::from(row.malformed),
            malformed_path: u8::from(row.malformed_path),
            flags: row.flags,
            size: row.size,
            allocated: row.allocated,
            modified: row.modified,
            created: row.created,
            accessed: row.accessed,
            descendants: row.descendants,
            _pad2: 0,
            treesize: row.treesize,
            tree_allocated: row.tree_allocated,
            path_off,
            path_len,
            name_off,
            name_len,
        });
    }

    let header_size = size_of::<ShmemHeader>();
    let records_size = row_count * size_of::<ShmemRecord>();
    let strings_offset = header_size + records_size;
    let total_size = strings_offset + string_table.len();

    let header = ShmemHeader {
        magic: MAGIC,
        version: VERSION,
        row_count: row_count as u64,
        strings_offset: strings_offset as u64,
        duration_ms,
        records_scanned,
        truncated: u32::from(truncated),
        _reserved: 0,
    };

    // Create file and set size.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?;
    file.set_len(total_size as u64)?;

    // Safety: we just created the file exclusively and set its length.
    // The mmap is used only within this function scope, then flushed
    // and dropped before we return the path to readers.
    // Safety: file is freshly created, exclusively owned, and sized.
    let mut mmap = unsafe { memmap2::MmapMut::map_mut(&file)? };

    // Write header.
    // Safety: ShmemHeader is repr(C), Copy, and has no padding-dependent
    // invariants.
    let header_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(core::ptr::from_ref(&header).cast::<u8>(), header_size)
    };
    mmap[..header_size].copy_from_slice(header_bytes);

    // Write records.
    // Safety: ShmemRecord is repr(C), Copy, and the slice is valid for records_size
    // bytes.
    let records_bytes: &[u8] =
        unsafe { core::slice::from_raw_parts(records.as_ptr().cast::<u8>(), records_size) };
    mmap[header_size..header_size + records_size].copy_from_slice(records_bytes);

    // Write string table.
    mmap[strings_offset..strings_offset + string_table.len()].copy_from_slice(&string_table);

    mmap.flush()?;

    Ok(path)
}

/// Read search results from a shared-memory file and delete it.
///
/// Returns a fully populated [`SearchResponse`] with inline `rows`.
/// The shmem file is removed after successful reading.
///
/// # Errors
///
/// Returns `io::Error` on mmap failure, format mismatch, or invalid UTF-8.
#[expect(
    unsafe_code,
    reason = "memmap2::Mmap::map requires unsafe — mmap is a kernel-level operation"
)]
#[expect(
    clippy::indexing_slicing,
    reason = "validated: bounds-checked before indexing"
)]
pub fn read_search_results(path: &Path) -> io::Result<SearchResponse> {
    let file = std::fs::File::open(path)?;

    // Safety: the file was written by our daemon using the same binary
    // layout. We validate magic + version before interpreting data.
    let mmap = unsafe { memmap2::Mmap::map(&file)? };

    let header_size = size_of::<ShmemHeader>();
    if mmap.len() < header_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shmem file too small",
        ));
    }

    // Read header.
    // Safety: mmap is at least header_size bytes; read_unaligned handles any
    // alignment.
    let header: ShmemHeader =
        unsafe { core::ptr::read_unaligned(mmap.as_ptr().cast::<ShmemHeader>()) };

    if header.magic != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad shmem magic: {:#x}", header.magic),
        ));
    }
    if header.version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported shmem version: {}", header.version),
        ));
    }

    let row_count = usize::try_from(header.row_count)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let record_size = size_of::<ShmemRecord>();
    let records_end = header_size + row_count * record_size;
    let strings_offset = usize::try_from(header.strings_offset)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    if mmap.len() < records_end || mmap.len() < strings_offset {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shmem file truncated",
        ));
    }

    let string_table = &mmap[strings_offset..];
    let mut rows = Vec::with_capacity(row_count);

    for i in 0..row_count {
        let offset = header_size + i * record_size;
        // Safety: offset is within mmap bounds (checked via records_end above).
        let rec_ptr = unsafe { mmap.as_ptr().add(offset) };
        // Safety: rec_ptr points to at least record_size valid bytes.
        let rec: ShmemRecord = unsafe { core::ptr::read_unaligned(rec_ptr.cast::<ShmemRecord>()) };

        let path_start = rec.path_off as usize; // u32→usize lossless on 64-bit
        let path_end = path_start + rec.path_len as usize; // u32→usize lossless on 64-bit
        let name_start = rec.name_off as usize; // u32→usize lossless on 64-bit
        let name_end = name_start + rec.name_len as usize; // u32→usize lossless on 64-bit

        if path_end > string_table.len() || name_end > string_table.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("string offset out of bounds at row {i}"),
            ));
        }

        let path_str = core::str::from_utf8(&string_table[path_start..path_end])
            .map_err(|utf8_err| io::Error::new(io::ErrorKind::InvalidData, utf8_err))?;
        let name_str = core::str::from_utf8(&string_table[name_start..name_end])
            .map_err(|utf8_err| io::Error::new(io::ErrorKind::InvalidData, utf8_err))?;

        rows.push(SearchRow {
            // Shmem records are written with `row.drive.as_byte()`
            // (which is always in `b'A'..=b'Z'`), so the `TryFrom`
            // succeeds in normal operation.  A fallback to
            // `DriveLetter::X` keeps the reader resilient against
            // truncated / corrupted blobs without panicking.
            drive: uffs_mft::platform::DriveLetter::try_from(rec.drive)
                .unwrap_or(uffs_mft::platform::DriveLetter::X),
            path: path_str.to_owned(),
            name: name_str.to_owned(),
            size: rec.size,
            is_directory: rec.is_directory != 0,
            modified: rec.modified,
            created: rec.created,
            accessed: rec.accessed,
            flags: rec.flags,
            allocated: rec.allocated,
            descendants: rec.descendants,
            treesize: rec.treesize,
            tree_allocated: rec.tree_allocated,
            // WI-4.4: the two malformed bits ride in the record's former
            // padding bytes (zero size cost). `name_hex` is intentionally NOT
            // carried by the compact shmem record — adding a variable-length
            // hex region would cost +8 bytes/row on every row for a vanishingly
            // rare field; it is served via the JSON projection path instead.
            malformed: rec.malformed != 0,
            malformed_path: rec.malformed_path != 0,
            name_hex: None,
        });
    }

    // Unmap before deleting.
    drop(mmap);
    drop(file);

    // Best-effort cleanup — don't fail the read if delete fails.
    drop(std::fs::remove_file(path));

    Ok(SearchResponse {
        // The shmem file always carries full SearchRow records, so
        // the decoded payload lands on the `InlineRows` variant —
        // the caller typically treats this `SearchResponse` as if
        // the daemon had returned the rows inline all along.
        payload: crate::protocol::response::SearchPayload::InlineRows(rows),
        total_count: header.row_count,
        records_scanned: usize::try_from(header.records_scanned)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
        duration_ms: header.duration_ms,
        truncated: header.truncated != 0,
        profile: None,
        applied_sorts: Vec::new(),
        applied_projection: Vec::new(),
        response_mode: None,
        projected_rows: None,
        aggregations: vec![],
    })
}

/// Write a raw UTF-8 `paths_blob` to a shmem file for binary transport.
///
/// Unlike [`write_search_results`], which packs `SearchRow` records
/// with a structured header + string table, this function writes
/// `blob.as_bytes()` verbatim to a freshly-created mmap region — the
/// file IS the blob, no framing.  The client then streams it back out
/// with one `write_all` (see [`stream_paths_blob_into`]).
///
/// ## Why the raw-bytes format
///
/// The daemon has already built a newline-terminated UTF-8 buffer in
/// `try_pack_paths_blob`.  Re-serialising it as JSON (4.5 MB of
/// backslash-heavy Windows paths becomes ~9 MB of escaped JSON) and
/// then parsing it back costs ~80 ms on the `C: ext:dll` benchmark.
/// Shmem bypasses both the encode and decode: ~1 ms mmap + ~5 ms
/// `copy_from_slice` on the daemon side, and a zero-copy
/// `write_all(&mmap[..])` on the client side.
///
/// ## Layout
///
/// ```text
/// [blob.len() bytes of UTF-8]
/// ```
///
/// No header, no magic, no version — the byte count is implicit in
/// the file size (`metadata().len()`).  The response envelope already
/// carries the path, so there is no in-band framing that would force
/// a re-read of the bytes to discover structure.
///
/// # Errors
///
/// Returns `io::Error` on directory-create, file-create, `set_len`,
/// mmap, or `flush` failure.  The caller should fall back to inline
/// JSON transport on error rather than failing the response.
#[expect(
    unsafe_code,
    reason = "memmap2::MmapMut::map_mut requires unsafe — mmap is a kernel-level operation"
)]
#[expect(
    clippy::indexing_slicing,
    reason = "mmap is sized to blob.len(); the single slice is within bounds by construction"
)]
pub fn write_paths_blob(blob: &str) -> io::Result<PathBuf> {
    let path = unique_shmem_path()?;
    let bytes = blob.as_bytes();
    let total_size = bytes.len();

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?;
    file.set_len(total_size as u64)?;

    if total_size > 0 {
        // Safety: file is freshly created, exclusively owned, and
        // sized to `total_size`.  The mmap does not escape this
        // function scope — we flush and drop before returning the
        // path to the reader.
        let mut mmap = unsafe { memmap2::MmapMut::map_mut(&file)? };
        mmap[..total_size].copy_from_slice(bytes);
        mmap.flush()?;
    }

    Ok(path)
}

/// Maximum bytes per `write_all` call when streaming a shmem blob to
/// the writer.
///
/// ## Why chunk at all
///
/// A single `write_all` against an mmap view of a multi-hundred-MB
/// file is fine on Linux/macOS (the kernel just walks the pages),
/// but on Windows it hits three concrete caps:
///
/// 1. **`WriteFile` on a pipe** (stdout redirected to `|`, `>`, or captured by
///    a parent like PowerShell ISE) has an undocumented kernel buffer ceiling
///    where huge single writes fail with `ERROR_INSUFFICIENT_BUFFER` /
///    `ERROR_NOT_ENOUGH_MEMORY` or return the non-descriptive OS error 16388
///    that surfaces as "`FormatMessageW` returned 317".
/// 2. **`WriteConsoleW`** (stdout is an interactive console) takes UTF-16 and
///    internally caps per-call length.  Rust's stdlib already chunks this path,
///    but only at ~8 K characters which means a 100 MB ASCII blob translates to
///    ~12 M `WriteConsoleW` calls and can appear to hang.
/// 3. **The userland mmap view** can be paged out during a long single
///    `write_all`, and a touched page-fault that races with the daemon's shmem
///    cleanup manifests as an opaque I/O error.
///
/// 4 MiB chunks give us:
/// - A single `WriteFile` well under any observed pipe ceiling (the 10 M-row /
///   3.5 GiB stress run proved 1 MiB is safe; 4 MiB keeps the same headroom
///   while cutting the syscall count 4×).
/// - ~25 progress points per 100 MB blob for tracing / pin-pointing which byte
///   range failed on Windows regression reports — still plenty of granularity.
/// - Effectively zero overhead on Linux/macOS (the syscall cost of 25 extra
///   `write`s on a 100 MB payload is sub-millisecond).
///
/// We deliberately stay at 4 MiB instead of going bigger (e.g. 16 MiB)
/// because on Windows `WriteConsoleW` internally re-chunks at ~8 K
/// UTF-16 chars — larger user-facing chunks do not reduce its syscall
/// count, they just increase the per-call UTF-8 → UTF-16 transcode
/// work and the blast radius of a cumulative console failure.
pub(crate) const STREAM_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// Stream a raw `paths_blob` shmem file into `writer` with a chunked
/// `write_all` loop, then delete the file.
///
/// Uses a read-only mmap so the kernel page-cache backs the copy
/// directly — there is no intermediate `Vec<u8>` allocation and no
/// UTF-8 re-validation.  The daemon wrote valid UTF-8, and stdout
/// does not care about encoding (it takes bytes).
///
/// The write loop issues at most `STREAM_CHUNK_BYTES` per
/// `writer.write_all` call.  That bounds each underlying syscall
/// (`write(2)` on Unix, `WriteFile` / `WriteConsoleW` on Windows) to
/// a size every tested OS and shell handles cleanly — see the
/// constant docs for the Windows failure modes that motivate it.
///
/// The file is deleted best-effort after the write succeeds.  A
/// delete failure is swallowed: the blob has already reached the
/// client, and stale shmem files are reaped by
/// [`cleanup_stale_shmem_files`] at daemon startup.
///
/// ## Error pinpointing
///
/// Every failure path attaches a step-specific [`std::io::Error`] kind +
/// message identifying which stage broke (`open`, `metadata`,
/// `mmap`, `write_all`) together with the blob byte size and, for
/// write failures, the byte offset reached.  This converts opaque
/// Windows error codes (e.g. OS 16388) into actionable regression
/// reports.
///
/// # Errors
///
/// Returns `io::Error` on `File::open`, `metadata`, mmap, or any
/// intermediate `write_all` failure.  Unlike [`read_search_results`],
/// there is no format validation — the file is raw bytes.
#[expect(
    unsafe_code,
    reason = "memmap2::Mmap::map requires unsafe — mmap is a kernel-level operation"
)]
pub fn stream_paths_blob_into<W: io::Write>(path: &Path, writer: &mut W) -> io::Result<()> {
    let path_display = path.display();

    let file = std::fs::File::open(path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("open shmem blob file {path_display}: {err}"),
        )
    })?;

    let len = file
        .metadata()
        .map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("stat shmem blob file {path_display}: {err}"),
            )
        })?
        .len();

    tracing::debug!(
        path = %path_display,
        len,
        chunk = STREAM_CHUNK_BYTES,
        "stream_paths_blob_into: opened shmem blob"
    );

    if len == 0 {
        // Zero-sized mmap is an error on some platforms; short-circuit.
        drop(file);
        drop(std::fs::remove_file(path));
        return Ok(());
    }

    // Safety: the file was written by our daemon via `write_paths_blob`.
    // We only read from the mmap (no writes), and the file size is
    // non-zero (guarded above).
    let mmap = unsafe { memmap2::Mmap::map(&file) }.map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("mmap shmem blob file {path_display} ({len} bytes): {err}"),
        )
    })?;

    // Tell the kernel we will read the mapping strictly front-to-back
    // so it can prefetch pages ahead of the write cursor.  On Linux
    // this maps to `madvise(MADV_SEQUENTIAL)`, on macOS to
    // `madvise(POSIX_MADV_SEQUENTIAL)`.  memmap2 only exposes
    // `Advice` under `#[cfg(unix)]` (Windows has
    // `PrefetchVirtualMemory` but memmap2 does not wire it up), so
    // we gate the call identically — on Windows the compiler simply
    // omits it, matching memmap2's own feature surface.  The result
    // is intentionally swallowed: even if the OS refuses the advice,
    // the stream still works, just without the prefetch optimisation.
    #[cfg(unix)]
    drop(mmap.advise(memmap2::Advice::Sequential));

    // `&mmap` coerces to `&[u8]` via `Mmap: Deref<Target=[u8]>`.  We
    // walk the slice in [`STREAM_CHUNK_BYTES`]-sized strides so each
    // `write_all` call fits comfortably in every pipe/console write
    // ceiling we've observed (see the constant's doc-comment).
    let bytes: &[u8] = &mmap;
    let total = bytes.len();
    let mut offset: usize = 0;
    while offset < total {
        let end = offset.saturating_add(STREAM_CHUNK_BYTES).min(total);
        // `offset < total` and `end <= total` with `end > offset`, so
        // this range is always in-bounds; use `.get()` to avoid the
        // clippy::indexing_slicing lint while preserving the invariant.
        let chunk = bytes.get(offset..end).ok_or_else(|| {
            io::Error::other(format!(
                "internal: shmem chunk slice {offset}..{end} out of bounds for \
                 total {total} bytes (should be unreachable)"
            ))
        })?;
        writer.write_all(chunk).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "write shmem blob to stdout (offset {offset}, chunk {} bytes, total {total} bytes, \
                     os_error {:?}): {err}",
                    chunk.len(),
                    err.raw_os_error(),
                ),
            )
        })?;
        offset = end;
    }

    drop(mmap);
    drop(file);
    // Best-effort cleanup — the blob was delivered even if delete fails.
    drop(std::fs::remove_file(path));
    Ok(())
}

/// Remove any leftover shmem files (GC).
///
/// Called on daemon startup to clean stale files from previous sessions.
pub fn cleanup_stale_shmem_files() {
    if let Ok(dir) = shmem_dir()
        && let Ok(entries) = std::fs::read_dir(&dir)
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "bin") {
                drop(std::fs::remove_file(&path));
            }
        }
    }
}

// Tests live in a sibling file to keep this file under the
// 800-line policy ceiling.  `#[path]` keeps the tests attached
// as `shmem::tests`, so `super::*` still resolves against `shmem`.
#[cfg(test)]
#[path = "shmem_tests.rs"]
mod tests;
