<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (c) 2025-2026 SKY, LLC. -->

# MFT Capture → Transfer → Verify Runbook

End-to-end flow for capturing a live Windows NTFS volume, moving the bundle to a
Mac, and proving the offline reconstruction is faithful — including a three-way
parity check between the C++ golden tool, `uffs-mft` on Windows, and `uffs-mft`
on the Mac.

> Design/internals: `docs/architecture/mft-full-capture.md`.
> All `uffs-mft` MFT reads require **Windows, elevated (Administrator)**. The
> offline steps (`metafile-info`, `load`, `verify`) run anywhere.

---

## What "tying down the flow" means

Three outputs of the same volume's `$MFT`, compared pairwise:

| Output | Where it comes from |
|--------|---------------------|
| **CPP golden** | the C++ tool, run live on Windows |
| **Rust / Windows** | `uffs-mft load` of the captured `$MFT`, on Windows |
| **Rust / Mac** | `uffs-mft load` of the *same* captured `$MFT`, on the Mac |

- **Rust-Windows == Rust-Mac** proves the capture + offline reconstruction is
  byte-faithful and the parser is platform-independent.
- **Rust ≈ CPP golden** proves the Rust parse matches the reference.

The `verify` command performs each comparison and exits non-zero on any
divergence.

---

## Step 1 — Capture (Windows, elevated)

One drive (full `$MFT` + all 10 metafiles + `manifest.json` + `SHA256SUMS`):

```powershell
uffs-mft capture --drive C --out cap
```

Every eligible NTFS volume, each into its own `cap\drive_<x>\`:

```powershell
uffs-mft capture --all-drives --out cap
```

Package each drive bundle into a single transfer artifact (extract on the Mac
with `tar --zstd -xf`), optionally split into ≤N-GiB parts:

```powershell
uffs-mft capture --all-drives --out cap --zip              # cap\drive_c.tar.zst, ...
uffs-mft capture --drive C   --out cap --zip --split-gib 1 # cap\drive_c.tar.zst.000, .001, ...
```

Each `cap\drive_<x>\` contains:

| File | Contents |
|------|----------|
| `C_mft.bin` | full `$MFT` (zstd) |
| `c_boot.bin` … `c_usnjrnl.bin` | the 10 NTFS metafiles |
| `manifest.json` | volume facts + per-artifact SHA-256 |
| `SHA256SUMS` | transfer-verification hashes |

## Step 2 — Transfer to the Mac

USB is blocked by DLP on the managed Mac — use Google Drive / SMB. Copy the
whole `drive_<x>\` folder (or the `.tar.zst[.NNN]`).

On the Mac, reassemble (if split) and verify integrity **before** trusting the
data:

```bash
cat drive_c.tar.zst.* > drive_c.tar.zst      # only if --split-gib was used
tar --zstd -xf drive_c.tar.zst               # only if --zip was used
cd drive_c
shasum -c SHA256SUMS                          # every line must say "OK"
```

## Step 3 — Inspect the metafiles offline (Mac)

```bash
uffs-mft metafile-info --input c_boot.bin      # geometry (cluster size, MFT LCN, ...)
uffs-mft metafile-info --input c_bitmap.bin    # total/used/free clusters
uffs-mft metafile-info --input c_secure.bin    # $Secure:$SDS payload present
uffs-mft metafile-info --input c_usnjrnl.bin   # USN record count + sample entries
```

## Step 4 — Three-way parity

Export each source to CSV, then `verify`. The Rust CSV schema is identical on
both platforms, so a full-column compare is exact.

```powershell
# Windows: parse the captured $MFT → CSV  (Rust / Windows)
uffs-mft load cap\drive_c\C_mft.bin -o rust_win_c.csv
```

```bash
# Mac: parse the SAME captured file → CSV  (Rust / Mac)
uffs-mft load C_mft.bin -o rust_mac_c.csv

# Rust-Windows vs Rust-Mac — expect ✅ MATCH (exit 0)
uffs-mft verify --left rust_win_c.csv --right rust_mac_c.csv
```

Compare against the **CPP golden**. Because the C++ tool may emit different
column names/order/formatting, restrict the compare to the shared identity
columns (matched by header name, so order does not matter):

```bash
uffs-mft verify --left rust_mac_c.csv --right cpp_c.csv \
  --columns frs,parent_frs,name,size
```

`verify` reports per-side row counts, common rows, rows only on each side (with
a sample), and a final ✅/❌; it exits non-zero on mismatch so you can gate a
script on it.

---

## CLI cheat-sheet

| Command | Purpose | Platform |
|---------|---------|----------|
| `capture --drive C --out DIR` | bundle one drive | Windows (elevated) |
| `capture --all-drives --out DIR` | bundle every NTFS volume | Windows (elevated) |
| `capture … --zip [--split-gib N]` | pack `.tar.zst` (+split) | Windows (elevated) |
| `metafile-info --input FILE` | decode one metafile | any |
| `load FILE -o out.csv` | parse `$MFT` → CSV | any |
| `verify --left A --right B [--columns …]` | CSV parity, exits non-zero on mismatch | any |

## Notes & limits

- `$UsnJrnl:$J` is captured **sparse-compacted** — only the live (allocated)
  journal is stored, not the multi-GB purged hole. Records are self-describing
  by USN, so nothing is lost for change-journal analysis.
- `verify`'s CSV parser handles RFC 4180 quoting (commas/quotes in file names)
  but assumes one record per physical line.
- For a CPP-vs-Rust compare, pick columns both tools emit with the same
  semantics; timestamp/format differences on non-identity columns will show as
  false mismatches otherwise.
