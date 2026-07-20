# NTFS Structures & Record Parsing

## Introduction

This document provides exhaustive detail on the NTFS on-disk structures and how UFFS parses MFT records from raw bytes into the in-memory index. After reading this document, you should be able to:

1. Parse any MFT FILE record from raw bytes
2. Apply Update Sequence Array (USA) fixups correctly
3. Extract all file metadata (names, timestamps, sizes, attributes, streams)
4. Handle edge cases: extension records, hard links, reparse points, $BadClus

All NTFS structure definitions live in `crates/uffs-mft/src/ntfs/` and are **cross-platform** — they use `zerocopy` for zero-copy parsing and work on macOS/Linux for testing.

---

## NTFS Boot Sector

**Location:** First sector of the volume (offset 0)
**Size:** 512 bytes exactly
**Source:** `ntfs/boot_sector.rs`

```rust
#[repr(C, packed)]
pub struct NtfsBootSector {
    pub jump: [u8; 3],              // 0x00: Jump instruction
    pub oem_id: [u8; 8],           // 0x03: "NTFS    "
    pub bytes_per_sector: u16,     // 0x0B: Usually 512
    pub sectors_per_cluster: u8,   // 0x0D: Power of 2 (1-128)
    // ... padding fields ...
    pub total_sectors: i64,        // 0x28: Volume size
    pub mft_start_lcn: i64,       // 0x30: *** Where $MFT begins ***
    pub mft_mirror_start_lcn: i64, // 0x38: $MFTMirr location
    pub clusters_per_file_record: i8, // 0x40: Usually -10
    pub clusters_per_index_block: u32, // 0x44: Usually 1
    pub volume_serial_number: i64, // 0x48
    // ... bootstrap code ...
}
```

**Key derived values:**

```rust
// Cluster size: typically 4096 bytes
fn cluster_size(&self) -> u32 {
    sectors_per_cluster as u32 * bytes_per_sector as u32
}

// File record size: typically 1024 bytes
// If clusters_per_file_record is negative, it's a power of 2:
//   -10 → 2^10 = 1024 bytes
fn file_record_size(&self) -> u32 {
    if self.clusters_per_file_record >= 0 {
        clusters_per_file_record as u32 * cluster_size()
    } else {
        1u32 << (-clusters_per_file_record as u32)
    }
}

// MFT physical offset on disk
fn mft_byte_offset(&self) -> u64 {
    mft_start_lcn as u64 * cluster_size() as u64
}
```

**Compile-time verification:** `assert!(size_of::<NtfsBootSector>() == 512)`

---

## File Record Segment Header

Each file/directory in NTFS occupies one or more 1024-byte **File Record Segments** (FRS) in the MFT.

**Source:** `ntfs/records.rs`

```rust
#[repr(C, packed)]
pub struct FileRecordSegmentHeader {
    pub multi_sector_header: MultiSectorHeader,  // 0x00: Magic + USA info (8 bytes)
    pub log_file_sequence_number: u64,           // 0x08: $LogFile correlation
    pub sequence_number: u16,                    // 0x10: Incremented on FRS reuse
    pub link_count: u16,                         // 0x12: Hard link count
    pub first_attribute_offset: u16,             // 0x14: Offset to first attribute
    pub flags: u16,                              // 0x16: IN_USE | DIRECTORY
    pub bytes_in_use: u32,                       // 0x18: Used portion of record
    pub bytes_allocated: u32,                    // 0x1C: Total record size
    pub base_file_record_segment: u64,           // 0x20: Base FRS (for extensions)
    pub next_attribute_number: u16,              // 0x28: Next attribute instance ID
    pub reserved: u16,                           // 0x2A
    pub segment_number_lower: u32,               // 0x2C: FRS number (lower 32 bits)
}
// Size: 48 bytes
```

**Critical checks:**
- `magic == 0x454C4946` ("FILE" in little-endian)
- `flags & 0x0001` → record is in use (skip deleted records)
- `flags & 0x0002` → record is a directory
- `base_file_record_segment == 0` → this is a base record (not extension)

### Extension Records

When a file has too many attributes to fit in a single 1024-byte record, NTFS creates **extension records**. The extension's `base_file_record_segment` field points back to the base record's FRS.

```
Base Record (FRS 42):
  base_file_record_segment = 0  (this IS the base)
  $STANDARD_INFORMATION
  $FILE_NAME "longfilename.txt"
  $DATA (first part)

Extension Record (FRS 100003):
  base_file_record_segment = 42  (points to base)
  $DATA (continuation, LowestVCN > 0)
  Additional $FILE_NAME attributes
```

---

## Update Sequence Array (USA) Fixup

### Why USA Exists

NTFS protects against torn writes. Each 512-byte sector's last 2 bytes are replaced with a check value when written to disk. The original bytes are saved in the USA at the record's start.

### Fixup Algorithm

**Source:** `ntfs/records.rs` — `apply_usa_fixup()`

```rust
pub fn apply_usa_fixup(buffer: &mut [u8], usa_offset: u16, usa_count: u16) -> bool {
    // USA layout: [check_value, orig_bytes_sector1, orig_bytes_sector2, ...]
    let check_value = read_u16_le(buffer, usa_offset);

    for sector_idx in 1..usa_count {
        // Last 2 bytes of each 512-byte sector
        let sector_end = sector_idx * 512 - 2;

        // Verify the check value matches
        let current = read_u16_le(buffer, sector_end);
        if current != check_value {
            return false;  // CORRUPTED — torn write detected
        }

        // Restore original bytes from USA
        let replacement = read_u16_le(buffer, usa_offset + sector_idx * 2);
        buffer[sector_end..sector_end+2] = replacement;
    }
    true
}
```

**For a 1024-byte record:**
- USA has 3 entries: `[check, sector0_orig, sector1_orig]`
- Sector 0 ends at byte 510-511
- Sector 1 ends at byte 1022-1023
- Both must contain `check` value; originals restored from USA

**If fixup fails:** The record is marked as corrupt (`'BAAD'`) and skipped. UFFS tracks these in `MftStats::corrupted_records`.

---

## Attribute Types

Every file record contains a list of attributes. Each attribute has a 16-byte header followed by type-specific data.

**Source:** `ntfs/records.rs`

```rust
pub enum AttributeType {
    StandardInformation = 0x10,   // Timestamps, file attributes
    AttributeList       = 0x20,   // Points to extension records
    FileName            = 0x30,   // Filename + parent reference
    ObjectId            = 0x40,   // GUID (internal)
    SecurityDescriptor  = 0x50,   // ACLs (internal)
    VolumeName          = 0x60,   // Volume label
    VolumeInformation   = 0x70,   // NTFS version
    Data                = 0x80,   // File content
    IndexRoot           = 0x90,   // Directory B-tree root
    IndexAllocation     = 0xA0,   // Directory B-tree nodes
    Bitmap              = 0xB0,   // Allocation bitmap
    ReparsePoint        = 0xC0,   // Symlinks, junctions
    EaInformation       = 0xD0,   // Extended attributes info
    Ea                  = 0xE0,   // Extended attributes
    PropertySet         = 0xF0,   // (Obsolete)
    LoggedUtilityStream = 0x100,  // EFS encryption
    End                 = 0xFFFFFFFF, // End marker
}
```

### Attribute Record Header

```rust
#[repr(C, packed)]
pub struct AttributeRecordHeader {
    pub type_code: u32,         // 0x00: Attribute type
    pub length: u32,            // 0x04: Total attribute record length
    pub is_non_resident: u8,    // 0x08: 0=resident, 1=non-resident
    pub name_length: u8,        // 0x09: Name length in chars
    pub name_offset: u16,       // 0x0A: Offset to attribute name
    pub flags: u16,             // 0x0C: Compressed/Encrypted/Sparse
    pub instance: u16,          // 0x0E: Unique ID within this FRS
}
// Size: 16 bytes
```

### Resident vs Non-Resident

Small attributes are **resident** (data stored directly in the MFT record):

```rust
pub struct ResidentAttributeData {
    pub value_length: u32,    // Length of data
    pub value_offset: u16,    // Offset from attribute start to data
    pub flags: u16,           // Indexed flag
}
```

Large attributes are **non-resident** (data stored in clusters elsewhere on disk):

```rust
pub struct NonResidentAttributeData {
    pub lowest_vcn: i64,          // Starting VCN (0 for primary extent)
    pub highest_vcn: i64,         // Ending VCN
    pub mapping_pairs_offset: u16, // Offset to data run list
    pub compression_unit: u8,     // Log2 of compression unit
    pub reserved: [u8; 5],
    pub allocated_size: i64,      // Space allocated on disk
    pub data_size: i64,           // Logical file size
    pub initialized_size: i64,    // Valid data length
}
```

---

## Key Attribute Parsing

### $STANDARD_INFORMATION (0x10)

**Source:** `ntfs/metadata.rs`

Always resident. Contains timestamps and file attribute flags.

```rust
// NTFS 1.2 (36 bytes)
pub struct StandardInformation {
    pub creation_time: i64,       // Windows FILETIME
    pub modification_time: i64,
    pub mft_change_time: i64,
    pub access_time: i64,
    pub file_attributes: u32,     // FILE_ATTRIBUTE_* flags
}

// NTFS 3.0+ (72 bytes) — adds forensic fields
pub struct StandardInformationExtended {
    // ... same timestamps + attributes ...
    pub owner_id: u32,            // Quota tracking
    pub security_id: u32,         // Index into $Secure
    pub quota_charged: u64,       // Quota bytes
    pub usn: u64,                 // USN Journal correlation
}
```

**Timestamp conversion:**

```rust
// Windows FILETIME → Unix microseconds
pub const fn filetime_to_unix_micros(filetime: i64) -> i64 {
    const FILETIME_UNIX_DIFF: i64 = 116_444_736_000_000_000; // 1601→1970
    if filetime == 0 { return 0; }  // Null timestamp
    (filetime - FILETIME_UNIX_DIFF) / 10  // 100ns → μs
}
```

**File attribute flags:**

| Bit | Value | Flag |
|-----|-------|------|
| 0 | 0x0001 | READ_ONLY |
| 1 | 0x0002 | HIDDEN |
| 2 | 0x0004 | SYSTEM |
| 5 | 0x0020 | ARCHIVE |
| 8 | 0x0100 | TEMPORARY |
| 9 | 0x0200 | SPARSE |
| 10 | 0x0400 | REPARSE_POINT |
| 11 | 0x0800 | COMPRESSED |
| 12 | 0x1000 | OFFLINE |
| 13 | 0x2000 | NOT_CONTENT_INDEXED |
| 14 | 0x4000 | ENCRYPTED |
| 15 | 0x8000 | INTEGRITY_STREAM |
| 16 | 0x10000 | VIRTUAL |
| 17 | 0x20000 | NO_SCRUB_DATA |
| 19 | 0x80000 | PINNED |
| 20 | 0x100000 | UNPINNED |

### $FILE_NAME (0x30)

**Source:** `ntfs/metadata.rs`

Always resident. Contains the filename, parent directory reference, and duplicate timestamps.

```rust
#[repr(C, packed)]
pub struct FileNameAttribute {
    pub parent_directory: u64,      // Parent FRS + sequence (48+16 bits)
    pub creation_time: i64,         // Duplicate timestamps (often stale)
    pub modification_time: i64,
    pub mft_change_time: i64,
    pub access_time: i64,
    pub allocated_size: i64,        // Allocated size (from $FILE_NAME)
    pub data_size: i64,             // Logical size (from $FILE_NAME)
    pub file_attributes: u32,       // Duplicate attributes
    pub packed_ea_size: u16,
    pub reserved: u16,
    pub file_name_length: u8,       // Name length in UTF-16 chars
    pub file_name_namespace: u8,    // Namespace flag
    // Followed by: file_name_length × u16 (UTF-16LE filename)
}
```

**Parent reference extraction:**

```rust
pub fn parent_frs(&self) -> u64 {
    self.parent_directory & 0x0000_FFFF_FFFF_FFFF  // Lower 48 bits
}

pub fn parent_sequence(&self) -> u16 {
    (self.parent_directory >> 48) as u16  // Upper 16 bits
}
```

**Filename namespace:**

| Value | Name | Meaning |
|-------|------|---------|
| 0 | POSIX | Case-sensitive, allows most characters |
| 1 | Win32 | Standard Windows long filename |
| 2 | DOS | 8.3 short filename |
| 3 | Win32+DOS | Name valid for both (single entry) |

**UFFS skips DOS-only names** (namespace == 2) to avoid duplicates. Files typically have either a Win32+DOS entry (namespace 3) or separate Win32 (1) and DOS (2) entries.

### $DATA (0x80)

The file's content. Usually unnamed (the default data stream). Named `$DATA` attributes are **Alternate Data Streams** (ADS).

**For search purposes, UFFS extracts sizes only:**

- **Resident:** `value_length` from `ResidentAttributeData`
- **Non-resident:** `data_size` (logical) and `allocated_size` (on-disk)

**Special case — `$BadClus:$Bad`:** Uses `initialized_size` instead of `data_size` because `$BadClus` reports the entire volume size as `data_size`.

### $INDEX_ROOT (0x90) / $INDEX_ALLOCATION (0xA0) / $BITMAP (0xB0)

These three attributes together implement **directory indexes** (the `$I30` index). For directories:

- `$INDEX_ROOT`: B-tree root (always resident, small)
- `$INDEX_ALLOCATION`: B-tree nodes (non-resident, can be large)
- `$BITMAP`: Which index blocks are in use

UFFS accumulates their sizes into `first_stream` using `saturating_add` to get the total directory index size, regardless of whether base or extension records arrive first.

### $REPARSE_POINT (0xC0)

```rust
pub struct ReparsePointHeader {
    pub reparse_tag: u32,    // Identifies the reparse type
    pub data_length: u16,
    pub reserved: u16,
}
```

Common reparse tags:

| Tag | Meaning |
|-----|---------|
| `0xA0000003` | Junction (mount point) |
| `0xA000000C` | Symbolic link |
| `0x80000017` | WOF compressed |
| `0x8000001B` | App execution link |
| `0x9000001A` | OneDrive/Cloud |

---

## Attribute Iteration

**Source:** `ntfs/records.rs` — `AttributeIterator`

```rust
pub struct AttributeIterator<'a> {
    data: &'a [u8],       // Record buffer
    offset: usize,        // Current position
    max_offset: usize,    // bytes_in_use from header
}

impl Iterator for AttributeIterator<'_> {
    type Item = AttributeRef<'_>;

    fn next(&mut self) -> Option<Self::Item> {
        // Read attribute header at current offset
        let header = parse_attribute_record_header(&self.data[self.offset..])?;

        // End marker?
        if header.type_code == 0xFFFFFFFF { return None; }

        // Bounds check
        if header.length < 16 || self.offset + header.length > self.max_offset {
            return None;  // Corrupt or truncated
        }

        let attr_data = &self.data[self.offset..self.offset + header.length];
        self.offset += header.length;

        Some(AttributeRef { data: attr_data, header })
    }
}
```

`AttributeRef` provides convenience methods:
- `attribute_type()` → `Option<AttributeType>`
- `is_non_resident()` → `bool`
- `resident_value()` → `Option<&[u8]>` (resident attribute data)
- `non_resident_data()` → `Option<NonResidentAttributeData>` (size info)
- `data_runs()` → `Vec<DataRun>` (cluster locations)

---

## The Complete Parsing Pipeline

### Base Record Parser

**Source:** `parse/direct_index.rs` — `parse_record_to_index()`

This is the **hot path** — called for every 1KB record during IOCP reading.

```
parse_record_to_index(buffer: &[u8], frs: u64, index: &mut MftIndex) -> bool
    │
    ├─► Validate magic == FILE (0x454C4946)
    ├─► Apply USA fixup (fixup_file_record)
    │   └─► If fails → skip (return false)
    ├─► Check flags & IN_USE
    │   └─► If not in use → skip
    ├─► Check base_file_record_segment
    │   ├─► == 0: This is a base record → process below
    │   └─► != 0: This is an extension → route to extension parser
    │
    ├─► Create FileRecord via get_or_create(frs)
    ├─► Set directory flag from header.flags & DIRECTORY
    │
    └─► Iterate attributes:
        ├─► $STANDARD_INFORMATION (0x10):
        │   Parse ExtendedStandardInfo → StandardInfo::from_extended()
        │   Set timestamps, flags, USN, security_id
        │
        ├─► $FILE_NAME (0x30):
        │   Skip if namespace == DOS (0x02)
        │   Extract: parent_frs, filename (UTF-16 → UTF-8)
        │   Store in first_name or push to links chain
        │   Add ChildInfo to parent's children list
        │   Increment name_count
        │
        ├─► $DATA (0x80):
        │   If unnamed → default data stream:
        │     Resident: size = value_length, allocated = 0
        │     Non-resident: size = data_size, allocated = allocated_size
        │     Set has_default_data flag
        │   If named → Alternate Data Stream:
        │     Push to streams chain, increment stream_count
        │
        ├─► $INDEX_ROOT (0x90) / $INDEX_ALLOCATION (0xA0) / $BITMAP (0xB0):
        │   If attribute name is "$I30" (directory index):
        │     Accumulate sizes into first_stream using saturating_add
        │     Set type_name_id = 0 (directory index marker)
        │
        ├─► $REPARSE_POINT (0xC0):
        │   Extract reparse_tag from header
        │
        └─► Other attributes:
            Track as internal streams for tree metrics
```

### Extension Record Parser

**Source:** `parse/direct_index_extension.rs`

When `base_file_record_segment != 0`, the record is an extension:

```
parse_extension_to_index(buffer, frs, index)
    │
    ├─► Extract base_frs from base_file_record_segment
    ├─► get_or_create(base_frs)  // May create placeholder
    │
    └─► Iterate attributes (same as base, but accumulates into base record):
        ├─► $FILE_NAME → additional hard link
        ├─► $DATA (unnamed) → saturating_add to existing sizes
        ├─► $DATA (named) → additional ADS
        ├─► $I30 attributes → saturating_add to directory index sizes
        └─► $REPARSE_POINT → set reparse_tag on base record
```

### Unified Parser

**Source:** `io/parser/unified.rs` — `process_record()`

The unified parser processes ALL records (base AND extension) through ONE function, ensuring deterministic output regardless of record processing order:

```rust
pub fn process_record(
    buffer: &[u8],
    frs: u64,
    index: &mut MftIndex,
) -> bool {
    // Determines base FRS:
    //   base_file_record_segment == 0 → frs IS the base
    //   base_file_record_segment != 0 → use that as base
    let base_frs = if header.is_base_record() { frs } else { base_ref };

    let record = index.get_or_create(base_frs);
    // Uses FileRecord::new_unified() — counts start at 0

    for attribute in AttributeIterator::new(buffer) {
        match attribute.type_code {
            $STANDARD_INFORMATION → set stdinfo
            $FILE_NAME → push-to-front (last name wins, deterministic)
            $DATA/$INDEX → unified stream handling with accumulation
            $REPARSE_POINT → extract tag
        }
    }
}
```

Key differences from the two-parser approach:
1. **Single function** for base and extension records
2. **Push-to-front** for `$FILE_NAME` (each new name overwrites `first_name`)
3. **Zero-based counts** (`new_unified()` starts at 0, increments for every attribute)
4. **Deterministic name selection** independent of record arrival order

---

## Filename Encoding

NTFS stores filenames in UTF-16LE. UFFS converts to UTF-8 for storage:

```rust
// From raw bytes after FileNameAttribute header:
let name_bytes = &attr_value[66..66 + file_name_length * 2];

// Convert UTF-16LE → UTF-8
let utf16_chars: Vec<u16> = name_bytes.chunks_exact(2)
    .map(|c| u16::from_le_bytes([c[0], c[1]]))
    .collect();
let name = String::from_utf16_lossy(&utf16_chars);

// Track if pure ASCII (optimization for case-insensitive matching)
let is_ascii = name.is_ascii();
```

The `IndexNameRef` stores a compact reference:
- `offset: u32` → byte offset into `MftIndex::names`
- `meta: u32` → packed: length (10 bits) + flags (6 bits) + extension_id (16 bits)

---

## Special MFT Records

The first 16 FRS numbers are reserved system metafiles:

| FRS | Name | Purpose |
|-----|------|---------|
| 0 | `$MFT` | The Master File Table itself |
| 1 | `$MFTMirr` | Mirror of first 4 MFT records |
| 2 | `$LogFile` | Transaction journal |
| 3 | `$Volume` | Volume label and version |
| 4 | `$AttrDef` | Attribute type definitions |
| **5** | **`.` (root)** | **Root directory — parent of all files** |
| 6 | `$Bitmap` | Cluster allocation bitmap |
| 7 | `$Boot` | Boot sector copy |
| 8 | `$BadClus` | Bad cluster list |
| 9 | `$Secure` | Security descriptor database |
| 10 | `$UpCase` | Unicode uppercase table |
| 11 | `$Extend` | Extended metadata directory |
| 12-15 | Reserved | Future use |

**Root directory (FRS 5)** is the anchor for all path resolution. Every file's parent chain eventually reaches FRS 5.

---

## Data Run Decoding

Non-resident attributes store their cluster locations as **data runs** — a compact encoding of (length, offset) pairs.

**Source:** `ntfs/data_runs.rs`

```rust
pub struct DataRun {
    pub cluster_count: u64,  // Number of clusters in this run
    pub lcn: i64,            // Starting LCN (absolute, accumulated)
}

pub fn parse_data_runs(data: &[u8]) -> Vec<DataRun> {
    let mut runs = Vec::new();
    let mut offset = 0;
    let mut prev_lcn: i64 = 0;

    while offset < data.len() {
        let header = data[offset];
        if header == 0 { break; }  // End marker

        let length_size = (header & 0x0F) as usize;
        let offset_size = ((header >> 4) & 0x0F) as usize;
        offset += 1;

        // Read variable-length cluster count
        let cluster_count = read_variable_int(&data[offset..], length_size);
        offset += length_size;

        // Read variable-length LCN offset (signed, relative to previous)
        let lcn_delta = read_variable_signed_int(&data[offset..], offset_size);
        offset += offset_size;

        prev_lcn += lcn_delta;
        runs.push(DataRun { cluster_count, lcn: prev_lcn });
    }
    runs
}
```

The encoding is space-efficient: each run header byte encodes how many bytes follow for the length and offset fields. Most runs need only 3-5 bytes total.

---

## Error Handling

### Defensive Parsing

Every field read uses bounds checking:

```rust
// All reads return Option, allowing graceful failure
fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes = data.get(offset..end)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}
```

### Corrupt Record Handling

```rust
// If USA fixup fails → record is corrupt
if !fixup_file_record(&mut record_buf) {
    stats.corrupted_records += 1;
    // In forensic mode: create record with is_corrupt flag
    // In normal mode: skip entirely
    return false;
}

// If attribute extends beyond record → stop iteration
if offset + attr.length > bytes_in_use {
    break;  // Attribute list truncated
}
```

---

*Document Version: 2.0*
*Last Updated: 2026-04-12*
*UFFS Version: 0.4.106*
