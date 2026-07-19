# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025-2026 SKY, LLC.
#
# Checks whether ascending NTFS file-reference (FRS) order correlates
# with ascending on-disk physical location, for a sample of files.
#
# Step 1 of the "does reading candidates in ascending FRS order actually
# give us near-sequential physical disk access" investigation.
#
# Reads `uffs --format json` output (path + file_reference per row),
# samples a subset, and runs `fsutil file queryextents` on each sampled
# file to find its first extent's starting LCN (logical cluster number
# -- i.e. where it actually sits on the volume). Reports the Spearman
# rank correlation between FRS order and LCN order: a strong positive
# correlation means ascending-FRS read order is a good proxy for
# physical order (sorting reads by FRS should meaningfully cut seeks);
# a weak/no correlation means it won't help -- the files are physically
# scattered independent of allocation order.
#
# Usage:
#   uffs.exe "*.txt" --drive D --format json > d_files.jsonl
#   .\check_frs_vs_lcn.ps1 -JsonPath d_files.jsonl -SampleSize 500
#
# Parameters:
#   -JsonPath    Path to `uffs --format json` output, one JSON object per line.
#   -SampleSize  How many files to sample (querying extents on hundreds of
#                thousands of files would take far too long; a few hundred
#                is enough for a reliable Spearman estimate). Default 500.
param(
    [Parameter(Mandatory = $true)]
    [string]$JsonPath,

    [int]$SampleSize = 500
)

function Get-Frs {
    param([UInt64]$FileReference)
    # Low 48 bits are the FRS (MFT record number); high 16 bits are the
    # sequence number (slot-reuse generation) -- mirrors
    # CompactRecord::pack_file_reference in uffs-core.
    return $FileReference -band 0x0000FFFFFFFFFFFF
}

function Get-FirstExtentLcn {
    param([string]$Path)
    $output = & fsutil file queryextents "$Path" 2>&1
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    foreach ($line in $output) {
        # fsutil's exact wording/case/hex-vs-decimal has drifted across
        # Windows versions, so match loosely: the word "Lcn" (any case),
        # optional colon/space, then either a 0x-hex or plain decimal run.
        if ($line -match '(?i)Lcn\s*:?\s*(0x[0-9A-Fa-f]+|\d+)') {
            $raw = $matches[1]
            if ($raw.StartsWith('0x')) {
                return [Convert]::ToUInt64($raw.Substring(2), 16)
            }
            return [UInt64]$raw
        }
    }
    return $null
}

Write-Host "Reading $JsonPath ..."
$rows = Get-Content $JsonPath | ForEach-Object {
    try { $_ | ConvertFrom-Json } catch { $null }
} | Where-Object { $null -ne $_ -and $_.file_reference -and [UInt64]$_.file_reference -ne 0 }

Write-Host "Loaded $($rows.Count) rows with a nonzero file_reference."

if ($rows.Count -eq 0) {
    Write-Error "No usable rows -- check that JsonPath came from 'uffs ... --format json' (needs the file_reference field)."
    exit 1
}

$sample = $rows | Get-Random -Count ([Math]::Min($SampleSize, $rows.Count))
Write-Host "Sampling $($sample.Count) files; querying extents (this hits the filesystem once per file)..."

$results = @()
$unresolved = 0
$i = 0
foreach ($row in $sample) {
    $i++
    if ($i % 50 -eq 0) { Write-Host "  ... $i / $($sample.Count)" }

    $frs = $null
    try { $frs = Get-Frs -FileReference ([UInt64]$row.file_reference) } catch { }
    if ($null -eq $frs) { $unresolved++; continue }

    $lcn = Get-FirstExtentLcn -Path $row.path
    if ($null -eq $lcn) { $unresolved++; continue }

    $results += [PSCustomObject]@{ Path = $row.path; Frs = $frs; Lcn = $lcn }
}

Write-Host ""
Write-Host "Got extents for $($results.Count) / $($sample.Count) sampled files ($unresolved unresolved -- deleted/locked/no-extent files are skipped)."

if ($results.Count -lt 10) {
    Write-Error "Too few resolvable extents to compute a meaningful correlation."
    exit 1
}

# Spearman correlation: rank both columns independently, then Pearson-
# correlate the ranks via the standard tied-rank-free shortcut formula
# (valid when ranks are a permutation of 1..n, i.e. no duplicate FRS/LCN
# collisions -- close enough for this diagnostic sample size).
$byFrs = $results | Sort-Object Frs
$frsRank = @{}
for ($r = 0; $r -lt $byFrs.Count; $r++) { $frsRank[$byFrs[$r].Path] = $r }

$byLcn = $results | Sort-Object Lcn
$lcnRank = @{}
for ($r = 0; $r -lt $byLcn.Count; $r++) { $lcnRank[$byLcn[$r].Path] = $r }

$n = $results.Count
$sumDSq = 0
foreach ($row in $results) {
    $d = $frsRank[$row.Path] - $lcnRank[$row.Path]
    $sumDSq += $d * $d
}
$spearman = 1 - (6 * $sumDSq) / [double]($n * ($n * $n - 1))

Write-Host ""
Write-Host "=== Result ==="
Write-Host "Sampled files with resolvable extents: $n"
Write-Host ("Spearman correlation (FRS order vs. physical LCN order): {0:N3}" -f $spearman)
Write-Host ""
if ($spearman -gt 0.7) {
    Write-Host "Strong positive correlation -- ascending FRS order is a good proxy for physical order on this volume. Sorting reads by FRS should meaningfully reduce seeks."
} elseif ($spearman -gt 0.3) {
    Write-Host "Weak-to-moderate correlation -- FRS-sorted reads might help somewhat but won't eliminate seeking; this volume has likely been reorganized/fragmented since these files were created."
} else {
    Write-Host "Little to no correlation -- FRS order will NOT meaningfully help; the files are physically scattered independent of allocation order (heavy fragmentation, moves, or FRS-slot reuse)."
}

$outCsv = Join-Path (Split-Path $JsonPath -Parent) "frs_vs_lcn_sample.csv"
$results | Export-Csv -Path $outCsv -NoTypeInformation
Write-Host ""
Write-Host "Full sample written to $outCsv for inspection/plotting."
