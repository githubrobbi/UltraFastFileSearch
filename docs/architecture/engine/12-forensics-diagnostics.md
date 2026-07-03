# Forensics & Diagnostic Tools

## Introduction

UFFS is not just a file search tool — its direct MFT reading capability makes it a powerful forensic analysis platform. This document describes the forensic mode, the diagnostic toolchain, and workflows for MFT analysis, data collection, and offline investigation.

---

## Forensic Mode

### What Forensic Mode Reveals

In normal mode, UFFS skips deleted records and corrupt entries. **Forensic mode** includes them, exposing:

| Record Type | Normal Mode | Forensic Mode |
|-------------|-------------|---------------|
| Active files/dirs | ✅ Included | ✅ Included |
| Deleted files (MFT record freed) | ❌ Skipped | ✅ Included with `is_deleted` flag |
| Corrupt records (USA fixup failed) | ❌ Skipped | ✅ Included with `is_corrupt` flag |
| Extension records | Merged into base | ✅ Separate rows with `is_extension` + `base_frs` |

### Enabling Forensic Mode

```bash
# CLI: add --forensic flag (works with offline MFT files)
uffs "*" --mft-file C.bin --forensic

# Programmatic: MftReader builder
let reader = MftReader::open('C')?
    .with_forensic(true);
```

### Forensic Columns

When forensic mode is enabled, additional columns are available:

| Column | Type | Description |
|--------|------|-------------|
| `is_deleted` | bool | Record was not in use (FRS freed) |
| `is_corrupt` | bool | USA fixup failed (torn write / disk error) |
| `is_extension` | bool | Extension record (not a standalone file) |
| `base_frs` | u64 | Base FRS for extension records (0 for base records) |
| `sequence_number` | u16 | FRS reuse counter (incremented on delete+reuse) |
| `lsn` | u64 | Log File Sequence Number ($LogFile correlation) |

### Forensic Use Cases

- **Deleted file recovery**: Find recently deleted files whose MFT records haven't been reused
- **Corruption detection**: Identify records with torn writes or disk errors
- **Timeline analysis**: Use `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamp discrepancies to detect anti-forensic timestamp manipulation
- **Extension record analysis**: Understand file fragmentation across MFT records
- **USN correlation**: Cross-reference `usn` field with `$UsnJrnl` change journal

### Implementation Details

**Source:** `parse/forensic/base.rs`, `parse/forensic/extension.rs`

The forensic parsers are separate code paths that process ALL MFT records regardless of the `FRH_IN_USE` flag:

```
For each 1KB record in MFT:
  ├─► Magic == FILE?
  │     No  → skip (not even a record)
  │     Yes → continue
  ├─► USA fixup passes?
  │     No  → create record with is_corrupt=true
  │     Yes → continue
  ├─► FRH_IN_USE flag set?
  │     No  → create record with is_deleted=true, parse remaining attributes
  │     Yes → parse normally
  └─► BaseFileRecordSegment != 0?
        Yes → mark is_extension=true, set base_frs
```

**Output size impact:** Forensic mode typically produces 10–50% more rows depending on volume history. Heavily used volumes with many deleted files can produce 2–3× more rows.

---

## The `uffs-mft` Utility Binary

The `uffs-mft` binary (from the `uffs-mft` crate) provides MFT-specific operations beyond search:

### Save Raw MFT

Capture a byte-perfect snapshot of the MFT for offline analysis:

```bash
# Save with zstd compression (default)
uffs-mft save C: C_mft.bin

# Save uncompressed
uffs-mft save C: C_mft.bin --no-compress

# Save as IOCP capture (preserves chunk boundaries and extent metadata)
uffs-mft save C: C_capture.iocp --iocp
```

The IOCP capture format preserves the exact I/O chunking and extent metadata, enabling replay of the read pipeline on another machine for debugging.

### Load and Analyze Offline MFT

```bash
# Parse offline MFT and display index stats
uffs-mft load C_mft.bin --build-index

# Parse with forensic mode
uffs-mft load C_mft.bin --build-index --forensic

# Export to Parquet for Polars analysis
uffs-mft load C_mft.bin --export parquet --output C_index.parquet
```

### Cross-Platform Workflow

The critical forensic workflow: capture on Windows, analyze anywhere:

```
1. Windows (admin):  uffs-mft save C: C_mft.bin
2. Copy to macOS:    scp C_mft.bin mac:~/analysis/
3. macOS (no admin): uffs "*" --mft-file C_mft.bin --forensic
```

This enables offline NTFS forensic analysis on macOS and Linux — no Windows required after capture.

---

## Diagnostic Binaries (`uffs-diag`)

The `uffs-diag` crate contains 10 specialized diagnostic tools for deep MFT analysis. These are **workspace-only** tools — not included in distribution builds.

### Tool Overview

| Tool | Platform | Purpose |
|------|----------|---------|
| `uffs-dump-mft-records` | Cross-platform | Inspect raw MFT records at byte level |
| `uffs-scan-mft-magic` | Cross-platform | Analyze magic value distribution across all records |
| `uffs-compare-raw-mft` | Cross-platform | Compare two raw MFT files record-by-record |
| `uffs-analyze-mft-parents` | Cross-platform | Analyze parent-child coverage and orphans |
| `uffs-inspect-mft-record-flow` | Cross-platform | Trace the raw→fixup→parse pipeline for specific FRS |
| `uffs-cross-check-mft-reference` | Cross-platform | Cross-check MFT records against reference CSV |
| `uffs-dump-mft-extents` | Windows only | Display $MFT extent map from a live volume |
| `uffs-analyze-diff` | Cross-platform | Deep comparison of two scan outputs |
| `uffs-compare-scan-parity` | Cross-platform | Comprehensive scan output comparison (regression detection) |
| `uffs-verify-iocp-capture` | Cross-platform | Validate IOCP capture file integrity |

### `uffs-dump-mft-records` — Record-Level Inspection

Inspect specific MFT records at the byte level. Essential for debugging parsing issues.

```bash
# Dump specific FRS records
uffs-dump-mft-records C_mft.bin --frs 0,5,42,100003

# Dump with full attribute details
uffs-dump-mft-records C_mft.bin --frs 5 --verbose

# Dump hex bytes
uffs-dump-mft-records C_mft.bin --frs 42 --hex
```

**Output includes:**
- FILE record header (magic, flags, sequence, link count)
- USA fixup status
- All attributes with type, resident/non-resident, sizes
- For `$FILE_NAME`: namespace, parent FRS, filename
- For `$DATA`: data size, allocated size, data runs
- For `$REPARSE_POINT`: reparse tag

### `uffs-scan-mft-magic` — Magic Value Distribution

Scan all records in a raw MFT file and report the distribution of magic values:

```bash
uffs-scan-mft-magic C_mft.bin
```

**Output:**
```
Magic Distribution:
  FILE (valid):     2,312,456 (46.2%)
  0x00000000 (free): 2,687,544 (53.8%)
  BAAD (corrupt):          12 (0.0%)
  Other:                    0 (0.0%)
Total records: 5,000,012
```

Useful for quickly assessing MFT health and utilization.

### `uffs-compare-raw-mft` — Record-by-Record Comparison

Compare two raw MFT snapshots to find differences:

```bash
uffs-compare-raw-mft before.bin after.bin
```

Identifies records that were created, deleted, or modified between the two snapshots. Uses SHA-256 hashing for efficient comparison.

### `uffs-analyze-mft-parents` — Parent-Child Coverage

Analyze the completeness of parent-child relationships:

```bash
uffs-analyze-mft-parents C_index.parquet
```

Finds:
- Orphan records (parent FRS doesn't exist)
- Circular references (A→B→A)
- Records with parent FRS 0 (should only be FRS 5)
- Directory records with no children

### `uffs-inspect-mft-record-flow` — Pipeline Tracing

Trace a specific FRS through the entire parse pipeline:

```bash
# Show raw bytes → USA fixup → parsed attributes → final FileRecord
uffs-inspect-mft-record-flow C_mft.bin --frs 42
```

Shows each transformation step, making it easy to identify where a parsing issue occurs.

### `uffs-dump-mft-extents` — Extent Map (Windows Only)

Display the physical extent map for `$MFT` on a live volume:

```bash
uffs-dump-mft-extents C:
```

**Output:**
```
$MFT Extent Map for C:
  Extent 0: VCN 0       → LCN 786432,   500000 clusters (1.95 GB)
  Extent 1: VCN 500000  → LCN 1200000,  300000 clusters (1.17 GB)
  Extent 2: VCN 800000  → LCN 2000000,  200000 clusters (781 MB)
Total: 3 extents, 1000000 clusters, 3.91 GB
Fragmentation: 3 fragments (moderately fragmented)
```

### `uffs-verify-iocp-capture` — Capture Validation

Validate the integrity of an IOCP capture file:

```bash
uffs-verify-iocp-capture C_capture.iocp
```

Checks: magic bytes, version, chunk count, chunk boundaries, record alignment, and optionally verifies individual record magic values.

---

## Analysis Scripts

### `scripts/dev/compare_outputs.py`

Python script for comparing two scan output CSV files with detailed diff reporting:

```bash
python scripts/dev/compare_outputs.py baseline.csv current.csv
```

Reports: missing rows, extra rows, column-level differences, and summary statistics.

### `scripts/dev/analyze_trial_outputs.rs`

Rust-script for analyzing trial run outputs (multiple scan outputs across drives):

```bash
rust-script scripts/dev/analyze_trial_outputs.rs trial_output_dir/
```

### `scripts/dev/diagnose_mft_counts.rs`

Diagnose record count discrepancies between different scan modes:

```bash
rust-script scripts/dev/diagnose_mft_counts.rs C_mft.bin
```

### `scripts/dev/find_missing_paths.rs`

Find records that exist in one output but not another:

```bash
rust-script scripts/dev/find_missing_paths.rs baseline.csv current.csv
```

### `scripts/dev/analyze_missing_frs.rs`

Analyze which FRS numbers are present in a raw MFT but missing from the parsed index:

```bash
rust-script scripts/dev/analyze_missing_frs.rs C_mft.bin C_index.parquet
```

---

## Common Forensic Workflows

### Workflow 1: Deleted File Discovery

```bash
# 1. Capture MFT on Windows
uffs-mft save C: C_mft.bin

# 2. Search for deleted files (any platform)
uffs "*.docx" --mft-file C_mft.bin --forensic --files-only \
    --columns path,size,modified,is_deleted

# 3. Filter to only deleted records
uffs "*.docx" --mft-file C_mft.bin --forensic --files-only \
    | grep ",1$"  # is_deleted=1 in last column
```

### Workflow 2: MFT Health Check

```bash
# 1. Quick magic distribution scan
uffs-scan-mft-magic C_mft.bin

# 2. Inspect any corrupt records
uffs-dump-mft-records C_mft.bin --corrupt-only

# 3. Check parent-child integrity
uffs-mft load C_mft.bin --build-index --export parquet -o C.parquet
uffs-analyze-mft-parents C.parquet
```

### Workflow 3: Timeline Analysis

```bash
# Export with all timestamps
uffs "*" --mft-file C_mft.bin --forensic \
    --columns path,created,modified,accessed,fn_created,fn_modified

# Compare $STANDARD_INFORMATION vs $FILE_NAME timestamps
# Discrepancies may indicate:
#   - Anti-forensic timestamp manipulation (timestomping)
#   - File copy operations (created ≠ fn_created)
#   - Metadata-only updates ($STD_INFO changed, $FILE_NAME unchanged)
```

### Workflow 4: Before/After Comparison

```bash
# 1. Capture "before" state
uffs-mft save C: before.bin

# 2. (... activity occurs ...)

# 3. Capture "after" state
uffs-mft save C: after.bin

# 4. Compare at record level
uffs-compare-raw-mft before.bin after.bin

# 5. Or compare at scan output level
uffs "*" --mft-file before.bin --forensic > before.csv
uffs "*" --mft-file after.bin --forensic > after.csv
python scripts/dev/compare_outputs.py before.csv after.csv
```

### Workflow 5: Extent Fragmentation Analysis

```bash
# Windows only — inspect live MFT layout
uffs-dump-mft-extents C:
uffs-dump-mft-extents D:
uffs-dump-mft-extents S:

# Compare fragmentation across drives
# More extents = more fragmented = slower HDD reads
```

---

## USN Journal Integration

Beyond forensic MFT analysis, UFFS reads the NTFS **USN Change Journal** (`$UsnJrnl`) for incremental updates and change tracking.

### Reading the Journal

```bash
# Query current NTFS volume / journal state (the separate uffs-mft tool;
# the old `uffs info` subcommand was removed with the thin-client split)
uffs-mft info --drive C
# Shows: journal_id, first_usn, next_usn, max_size

# The journal is used automatically by the caching system:
# cache load → query USN → read changes since checkpoint → apply updates
```

### Journal Change Reasons

The USN journal records granular change types:

| Category | Changes Tracked |
|----------|-----------------|
| **Data** | Overwrite, extend, truncation |
| **Metadata** | Timestamp change, attribute change, security change |
| **Naming** | Create, delete, rename (old + new name) |
| **Streams** | Named stream create/delete, ADS changes |
| **Links** | Hard link create/delete |
| **Special** | Compression change, encryption change, reparse point change |

Each record includes: FRS, parent FRS, timestamp, reason flags, and the filename at time of change.

---

## Limitations

| Limitation | Description |
|------------|-------------|
| **Forensic mode on live volumes** | Not yet supported for live MFT reads. Workaround: save to file first, then load with `--forensic`. |
| **Data recovery** | UFFS reads MFT metadata only — it does not recover file content. Deleted file records show metadata (name, size, timestamps) but the actual data clusters may be overwritten. |
| **Encrypted volumes** | BitLocker-encrypted volumes must be unlocked before MFT reading. UFFS cannot decrypt. |
| **Non-NTFS** | Only NTFS volumes are supported. FAT32, exFAT, ReFS, and network shares are not supported. |
| **Timestamp precision** | NTFS timestamps have 100-nanosecond precision. UFFS stores them as Unix microseconds (truncating the lowest digit). |

---

*Document Version: 2.0*
*Last Updated: 2026-04-12*
*UFFS Version: 0.4.106*
