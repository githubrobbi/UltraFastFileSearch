# =============================================================================
# Per-drive parity benchmark: UFFS Rust v0.5.66 (daemon HOT) vs C++ (MFT re-read)
#
# Methodology (2026-04-21 revision — see log in repo root):
#   Both tools are given the SAME corpus (all listed drives) and asked the
#   SAME question ('*' with path-only output) with output written to a
#   temporary file per invocation.  The comparison exposes the real-world
#   asymmetry that the v0.4.106 "warm disk" table papered over:
#
#     - UFFS Rust's daemon loads all drives ONCE and serves subsequent
#       per-drive '*' queries from the in-memory index.  Each round is HOT.
#     - UFFS C++ (uffs.com) has no daemon.  It re-reads the MFT of every
#       drive on EVERY invocation regardless of --drives=<X>; the --drives=
#       flag is an output filter, not a load-time filter (confirmed in
#       scripts/windows/cross-tool-benchmark.rs:553 header).
#
#   So the per-drive table below measures the honest workflow difference:
#   how fast can each tool answer an interactive '*' query on one drive?
#
# File-output parity matches scripts/windows/cross-tool-benchmark.rs:
#   Rust:  uffs.exe '*' --drive <X> --out <tmpfile> --columns Path \
#          --hide-system --hide-ads
#   C++:   uffs.com '*' --drives=<X> --columns=path --out=<tmpfile>
#
# The C++ binary internally freopen()'s stdout onto the --out= file, so
# (unlike the Rust CLI) we must NOT pipe or redirect its stdout/stderr —
# the invocation inherits both streams, and row-count validation reads
# the resulting file.
#
# Sequence:
#   1. (Optional) Stop daemon and purge all drive caches with -PurgeCacheFirst.
#      This re-measures the one-time cold daemon warm-up.  Omit to run
#      against whatever cache state the daemon already has.
#   2. Warm-up: start daemon with all drives, force it through a '*'
#      --limit 1 query so every drive is loaded, record the warm-up
#      wall-clock (COLD-if-purged / WARM otherwise).
#   3. For each drive, run N rounds (default 1) of:
#        - Rust HOT '*' query with file output
#        - C++ '*' query with file output (MFT re-read on every round)
#      Capture wall-clock, daemon-side (--profile), and row count per round;
#      report p50 for each tool per drive.
#   4. Emit two pre-formatted markdown tables at the end.
#
# Usage (from elevated PowerShell, project root):
#   .\scripts\windows\cold-parity-per-drive.ps1 -Drives C,D,E,F,M,S,G
#   .\scripts\windows\cold-parity-per-drive.ps1 -Drives C,D -Rounds 3
#   .\scripts\windows\cold-parity-per-drive.ps1 -PurgeCacheFirst          # cold daemon warm-up
#   .\scripts\windows\cold-parity-per-drive.ps1 -SkipCpp                  # Rust-only (fast)
#   .\scripts\windows\cold-parity-per-drive.ps1 -DumpRaw                  # include per-round profile stderr
#
# Binary resolution (auto-fallback when -UffsBin/-CppBin are not passed):
#   1. Explicit path via -UffsBin / -CppBin
#   2. $HOME\bin\uffs.exe / $HOME\bin\uffs.com      (user's local install)
#   3. bare 'uffs.exe' / 'uffs.com' (resolved via PATH)
#
# Requires:
#   - UFFS Rust binary reachable via one of the paths above
#   - UFFS C++ reference binary (uffs.com) reachable (optional; -SkipCpp bypasses)
#   - Admin elevation (MFT read)
# =============================================================================

[CmdletBinding()]
param(
    [string[]] $Drives          = @('C','D','E','F','M','S','G'),
    [string]   $UffsBin         = '',
    [string]   $CppBin          = '',
    [string]   $OutputFile      = 'LOG\Output_per_drive_parity.txt',
    [int]      $Rounds          = 1,
    [int]      $SleepBetween    = 1,
    [switch]   $PurgeCacheFirst,
    [switch]   $SkipCpp,
    [switch]   $DumpRaw
)

$ErrorActionPreference = 'Stop'
$CacheDir = Join-Path $env:LOCALAPPDATA 'uffs\cache'

# ---------- binary resolution ------------------------------------------------

# Track the resolution source so the preflight error can say exactly
# where it looked instead of claiming it tried all three paths when
# an explicit -UffsBin was passed.
$script:UffsBinSource = 'unresolved'
$script:CppBinSource  = 'unresolved'

function Resolve-UffsBinary {
    param(
        [string] $Explicit,
        [string] $HomeBinName,
        [string] $PathName,
        [ref]    $SourceRef
    )
    # 1. Explicit -UffsBin / -CppBin wins if provided.  We still try to
    #    canonicalise to a full path via Resolve-Path when it exists, so
    #    the preflight shows something like
    #    'C:\Users\rnio\GitHub\...\uffs.exe' instead of '.\target\release\...'.
    if ($Explicit) {
        $SourceRef.Value = "explicit -UffsBin/-CppBin ($Explicit)"
        if (Test-Path -LiteralPath $Explicit) {
            return (Resolve-Path -LiteralPath $Explicit).Path
        }
        # Honour the explicit path even if missing — the preflight error
        # then reports it verbatim instead of silently swapping to a
        # different binary.
        return $Explicit
    }
    # 2. $HOME\bin\<name> (user's local install).
    $homeBin = Join-Path $HOME "bin\$HomeBinName"
    if (Test-Path -LiteralPath $homeBin) {
        $SourceRef.Value = "`$HOME\\bin ($homeBin)"
        return $homeBin
    }
    # 3. PATH lookup.
    $cmd = Get-Command $PathName -ErrorAction SilentlyContinue
    if ($cmd) {
        $SourceRef.Value = "PATH ($($cmd.Source))"
        return $cmd.Source
    }
    # 4. Nothing resolved — return the bare name so the preflight can
    #    report all three candidates that were checked.
    $SourceRef.Value = "unresolved (tried: explicit, `$HOME\\bin\\$HomeBinName, PATH)"
    return $PathName
}

$UffsBin = Resolve-UffsBinary -Explicit $UffsBin -HomeBinName 'uffs.exe' -PathName 'uffs.exe' -SourceRef ([ref] $script:UffsBinSource)
$CppBin  = Resolve-UffsBinary -Explicit $CppBin  -HomeBinName 'uffs.com' -PathName 'uffs.com' -SourceRef ([ref] $script:CppBinSource)

function Test-Invokable {
    param([string] $Target)
    if (Test-Path -LiteralPath $Target) { return $true }
    return [bool](Get-Command $Target -ErrorAction SilentlyContinue)
}

# ---------- helpers ---------------------------------------------------------

function Write-Divider {
    param([string] $Title)
    $line = '=' * 118
    Write-Host ''
    Write-Host $line -ForegroundColor Cyan
    if ($Title) { Write-Host "  $Title" -ForegroundColor Cyan }
    Write-Host $line -ForegroundColor Cyan
    Write-Host ''
}

function Stop-UffsDaemon {
    try { & $UffsBin daemon stop 2>&1 | Out-Null } catch {}
    Start-Sleep -Milliseconds 500
    # Fallback: kill any stray uffs-daemon process
    Get-Process uffs-daemon -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

function Remove-DriveCache {
    param([string] $Drive)
    if (-not (Test-Path $CacheDir)) { return }
    $patterns = @(
        "${Drive}_compact.uffs",
        "${Drive}_index.uffs",
        "${Drive}_index.uffs.tmp",
        "${Drive}_index.lock",
        "${Drive}_compact.uffs.tmp"
    )
    foreach ($p in $patterns) {
        $path = Join-Path $CacheDir $p
        if (Test-Path $path) {
            Remove-Item $path -Force -ErrorAction SilentlyContinue
            if ($DumpRaw) { Write-Host "    - removed $path" -ForegroundColor DarkGray }
        }
    }
}

function Get-DaemonTotalRecords {
    # `uffs --daemon status -v` prints "Total records: N" with thousands
    # separators. Returns $null if the daemon isn't running or the line
    # isn't found.
    try {
        $statsOut = & $UffsBin daemon status -v 2>&1 | Out-String
        if ($statsOut -match 'Total records:\s+([0-9,]+)') {
            return [int64]($matches[1] -replace ',', '')
        }
    } catch {}
    return $null
}

function Get-FileLineCount {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        # Count raw lines; large files (~100 MB for multi-million-record
        # drives) stream through -ReadCount 1000 without buffering the
        # whole file in memory.
        return (Get-Content -LiteralPath $Path -ReadCount 1000 | Measure-Object -Line).Lines
    } catch {
        return $null
    }
}

function Get-Median {
    param([double[]] $Values)
    if (-not $Values -or $Values.Count -eq 0) { return 0 }
    $sorted = $Values | Sort-Object
    $mid = [int]([math]::Floor($sorted.Count / 2))
    if ($sorted.Count % 2 -eq 1) { return $sorted[$mid] }
    return ($sorted[$mid - 1] + $sorted[$mid]) / 2
}

function Invoke-UffsHotRound {
    # One round of the Rust HOT per-drive query: '*' with path-only
    # output written via --out.  Daemon must already be warm (all
    # drives loaded) before this is called.  Returns wall-clock ms,
    # daemon-side ms (from --profile), and row count from the file.
    param([string] $Drive)

    $tmpOut = Join-Path $env:TEMP "rust_${Drive}_$([guid]::NewGuid().ToString('N')).csv"

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    # --profile goes to stderr; capture both for post-hoc analysis but
    # do NOT redirect the --out= file path — the daemon writes it
    # directly (OPT-4 daemon-direct file-write path documented in
    # crates/uffs-cli/src/main.rs around the `has_out` branch).
    $stderr = & $UffsBin '*' --drive $Drive --out $tmpOut `
        --columns Path --hide-system --hide-ads --profile 2>&1 | Out-String
    $sw.Stop()
    $wallMs = [int]$sw.Elapsed.TotalMilliseconds

    $rows = Get-FileLineCount $tmpOut
    if (Test-Path -LiteralPath $tmpOut) {
        Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue
    }

    $daemonMs  = if ($stderr -match 'daemon:\s+(\d+)\s+ms')      { [int]$matches[1] } else { $null }
    $readyMs   = if ($stderr -match 'Await ready:\s+(\d+)\s+ms') { [int]$matches[1] } else { $null }

    [pscustomobject]@{
        Tool     = 'UFFS-Rust-v0.5.66'
        Phase    = 'HOT'
        Drive    = $Drive
        WallMs   = $wallMs
        DaemonMs = $daemonMs
        ReadyMs  = $readyMs
        Rows     = $rows
        RawOut   = $stderr
    }
}

function Invoke-UffsCppRound {
    # One round of the C++ '*' per-drive query.  Each invocation re-
    # reads all MFTs regardless of --drives=X — that is the cost being
    # measured.  freopen() requires inherited stdout/stderr so we use
    # Start-Process with -NoNewWindow -Wait instead of piping.
    param([string] $Drive)

    if ($SkipCpp -or -not (Test-Invokable $CppBin)) { return $null }

    $tmpOut = Join-Path $env:TEMP "cpp_${Drive}_$([guid]::NewGuid().ToString('N')).csv"
    $cppArgs = @('*', "--drives=$Drive", '--columns=path', "--out=$tmpOut")

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    # Start-Process -NoNewWindow -Wait keeps stdout/stderr attached to
    # the current console so the C++ binary's internal freopen() can
    # retarget onto --out=.  Any pipe or redirect here would silently
    # empty the output file (documented in cross-tool-benchmark.rs:559).
    $proc = Start-Process -FilePath $CppBin -ArgumentList $cppArgs `
        -NoNewWindow -Wait -PassThru
    $sw.Stop()
    $wallMs = [int]$sw.Elapsed.TotalMilliseconds
    $exit = if ($proc) { $proc.ExitCode } else { -1 }

    $rows = Get-FileLineCount $tmpOut
    if (Test-Path -LiteralPath $tmpOut) {
        Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue
    }

    [pscustomobject]@{
        Tool     = 'UFFS-CPP-reference'
        Phase    = 'MFT-reread'
        Drive    = $Drive
        WallMs   = $wallMs
        DaemonMs = $null
        ReadyMs  = $null
        Rows     = $rows
        ExitCode = $exit
        RawOut   = ''
    }
}

function Remove-AllDriveCaches {
    # Called by -PurgeCacheFirst so the daemon warm-up runs through
    # a true COLD MFT read.  Purges only the drives we're about to
    # benchmark; leaves unrelated cached drives alone.
    if (-not (Test-Path $CacheDir)) { return }
    foreach ($d in $Drives) {
        Remove-DriveCache -Drive $d
    }
}

function Start-DaemonAllDrives {
    # Force the daemon to start and load all drives.  `uffs --daemon start`
    # has no --drive filter (args.rs:109 states daemon auto-discovers
    # all drives on Windows live mode), so a bare daemon start (no -d)
    # gets the right behaviour.  Then we issue a trivial `*` --limit 1
    # query to make the first-use path execute end-to-end (including
    # trigram index rehydration) and block until a full response lands.
    Write-Host '  Starting daemon (auto-discover all drives)...' -ForegroundColor Yellow
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    # First `uffs` call auto-spawns the daemon if it is not already
    # running, with all drives auto-discovered.  --profile prints the
    # ready_ms + daemon_ms breakdown to stderr.
    $stderr = & $UffsBin '*' --limit 1 --profile 2>&1 | Out-String
    $sw.Stop()

    $wallSec   = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    $readyMs   = if ($stderr -match 'Await ready:\s+(\d+)\s+ms') { [int]$matches[1] } else { $null }
    $records   = Get-DaemonTotalRecords

    Write-Host ('    -> wall={0}s  await_ready={1}ms  records_loaded={2}' -f `
        $wallSec, $readyMs, $(if ($records) { '{0:N0}' -f $records } else { 'n/a' })) -ForegroundColor Green
    if ($DumpRaw) { Write-Host $stderr -ForegroundColor DarkGray }

    [pscustomobject]@{
        WallSec     = $wallSec
        ReadyMs     = $readyMs
        TotalRecords = $records
        RawOut      = $stderr
    }
}

# ---------- preflight -------------------------------------------------------

# Ensure output dir exists
$outDir = Split-Path -Parent $OutputFile
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

# Start a transcript so we capture EVERYTHING to the LOG file
Start-Transcript -Path $OutputFile -Force | Out-Null

Write-Divider "UFFS Per-drive parity benchmark — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
Write-Host "  UffsBin         : $UffsBin"
Write-Host "  UffsBin src     : $script:UffsBinSource"
Write-Host "  CppBin          : $(if ($SkipCpp) { '(skipped)' } else { $CppBin })"
if (-not $SkipCpp) {
    Write-Host "  CppBin src      : $script:CppBinSource"
}
Write-Host "  Drives          : $($Drives -join ', ')"
Write-Host "  Rounds/drive    : $Rounds"
Write-Host "  PurgeCacheFirst : $PurgeCacheFirst"
Write-Host "  CacheDir        : $CacheDir"
Write-Host "  OutputFile      : $OutputFile"
Write-Host "  SleepBetween    : $SleepBetween s"
Write-Host ''

# Verify binaries: the resolver above returned either a full path or a
# bare name; Test-Invokable (defined near the top) handles both.
if (-not (Test-Invokable $UffsBin)) {
    Write-Host "ERROR: UFFS Rust binary '$UffsBin' not found." -ForegroundColor Red
    Write-Host "       Source: $script:UffsBinSource" -ForegroundColor Red
    if ($script:UffsBinSource -like 'explicit*') {
        Write-Host "       You passed -UffsBin explicitly; the file at that path does not exist." -ForegroundColor Red
        Write-Host "       Hint: drop -UffsBin to auto-resolve to $HOME\bin\uffs.exe or PATH," -ForegroundColor Red
        Write-Host "             or use an absolute path like `$HOME\GitHub\UltraFastFileSearch\target\release\uffs.exe" -ForegroundColor Red
    } else {
        Write-Host "       Looked in (in order): explicit -UffsBin, $HOME\bin\uffs.exe, PATH." -ForegroundColor Red
        Write-Host "       Pass -UffsBin <full-path> or add the binary to one of those locations." -ForegroundColor Red
    }
    Stop-Transcript | Out-Null
    exit 1
}

& $UffsBin --version 2>&1 | Out-String | Write-Host
if (-not $SkipCpp -and (Test-Invokable $CppBin)) {
    & $CppBin --version 2>&1 | Out-String | Write-Host
} elseif (-not $SkipCpp) {
    Write-Host "  (C++ reference '$CppBin' not found — will skip C++ column per drive)" -ForegroundColor DarkYellow
}

# ---------- phase 0: optional cache purge + daemon warm-up ------------------

if ($PurgeCacheFirst) {
    Write-Divider 'Phase 0a: stop daemon + purge all drive caches (true COLD)'
    Stop-UffsDaemon
    Remove-AllDriveCaches
    Start-Sleep -Seconds $SleepBetween
}

Write-Divider 'Phase 0b: daemon warm-up — load all drives'
$warmup = Start-DaemonAllDrives
Start-Sleep -Seconds $SleepBetween

# ---------- phase 1: per-drive HOT Rust vs MFT-reread C++ -------------------

$results = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($drive in $Drives) {
    Write-Divider "Drive $drive — $Rounds round(s) per tool"

    # Rust HOT rounds (daemon already warm for all drives).
    $rustRounds = [System.Collections.Generic.List[pscustomobject]]::new()
    for ($i = 1; $i -le $Rounds; $i++) {
        Write-Host ("  [Rust HOT r{0}/{1}] uffs '*' --drive {2} --out <tmp> --columns Path --hide-system --hide-ads" -f $i, $Rounds, $drive) -ForegroundColor Yellow
        $r = Invoke-UffsHotRound -Drive $drive
        $rustRounds.Add($r)
        $rowsStr = if ($r.Rows) { '{0:N0}' -f $r.Rows } else { 'n/a' }
        $dmsStr  = if ($null -ne $r.DaemonMs) { "{0} ms" -f $r.DaemonMs } else { 'n/a' }
        Write-Host ('    -> wall={0}ms  daemon={1}  rows={2}' -f $r.WallMs, $dmsStr, $rowsStr) -ForegroundColor Green
        if ($DumpRaw) { Write-Host $r.RawOut -ForegroundColor DarkGray }
    }

    # C++ rounds (each one re-reads all MFTs).
    $cppRounds = [System.Collections.Generic.List[pscustomobject]]::new()
    if (-not $SkipCpp) {
        for ($i = 1; $i -le $Rounds; $i++) {
            Write-Host ("  [C++ MFT-reread r{0}/{1}] uffs.com '*' --drives={2} --columns=path --out=<tmp>" -f $i, $Rounds, $drive) -ForegroundColor Yellow
            $c = Invoke-UffsCppRound -Drive $drive
            if ($c) {
                $cppRounds.Add($c)
                $rowsStr = if ($c.Rows) { '{0:N0}' -f $c.Rows } else { 'n/a' }
                Write-Host ('    -> wall={0}ms  rows={1}  exit={2}' -f $c.WallMs, $rowsStr, $c.ExitCode) -ForegroundColor Green
            }
        }
    }

    # Aggregate: p50 wall-clock + canonical row count (from round 1).
    $rustWalls   = @($rustRounds | ForEach-Object { [double]$_.WallMs })
    $rustMedMs   = [int](Get-Median $rustWalls)
    $rustRows    = ($rustRounds | Select-Object -First 1).Rows
    $rustDaemonP50 = [int](Get-Median @($rustRounds | ForEach-Object { if ($null -ne $_.DaemonMs) { [double]$_.DaemonMs } else { 0.0 } }))

    $cppMedMs  = $null
    $cppRows   = $null
    if ($cppRounds.Count -gt 0) {
        $cppWalls  = @($cppRounds | ForEach-Object { [double]$_.WallMs })
        $cppMedMs  = [int](Get-Median $cppWalls)
        $cppRows   = ($cppRounds | Select-Object -First 1).Rows
    }

    $results.Add([pscustomobject]@{
        Drive         = $drive
        RustMedMs     = $rustMedMs
        RustRows      = $rustRows
        RustDaemonP50 = $rustDaemonP50
        CppMedMs      = $cppMedMs
        CppRows       = $cppRows
    })
    Start-Sleep -Seconds $SleepBetween
}

# ---------- summary tables --------------------------------------------------

Write-Divider 'Summary — daemon warm-up (Phase 0b)'
Write-Host ('  Wall-clock:     {0} s' -f $warmup.WallSec)
if ($null -ne $warmup.ReadyMs) {
    Write-Host ('  Await ready:    {0} ms (daemon spawn + MFT load + index build across all drives)' -f $warmup.ReadyMs)
}
if ($warmup.TotalRecords) {
    Write-Host ('  Total records:  {0:N0}' -f $warmup.TotalRecords)
}
if ($PurgeCacheFirst) {
    Write-Host '  Mode:           COLD — cache purged before warm-up' -ForegroundColor DarkYellow
} else {
    Write-Host '  Mode:           WARM — pre-existing cache reused (pass -PurgeCacheFirst for COLD)'
}

Write-Divider "Summary — table 1: per-drive parity (wall-clock p50 over $Rounds round(s))"

Write-Host '| Drive | C++ (MFT re-read) | Rust (daemon HOT) | Speedup | Rust rows | C++ rows |'
Write-Host '|-------|------------------:|------------------:|--------:|----------:|---------:|'
$totalRustMs = 0
$totalCppMs  = 0
foreach ($row in $results) {
    $totalRustMs += $row.RustMedMs
    if ($null -ne $row.CppMedMs) { $totalCppMs += $row.CppMedMs }
    $speedup  = if ($null -ne $row.CppMedMs -and $row.RustMedMs -gt 0) { [math]::Round($row.CppMedMs / $row.RustMedMs, 1) } else { 'n/a' }
    $cppCell  = if ($null -ne $row.CppMedMs) { '{0:N0} ms' -f $row.CppMedMs } else { '(skipped)' }
    $rustCell = '{0:N0} ms' -f $row.RustMedMs
    $rustRowsCell = if ($null -ne $row.RustRows) { '{0:N0}' -f $row.RustRows } else { 'n/a' }
    $cppRowsCell  = if ($null -ne $row.CppRows)  { '{0:N0}' -f $row.CppRows }  else { 'n/a' }
    $speedCell = if ($speedup -eq 'n/a') { 'n/a' } else { ('{0}x' -f $speedup) }
    Write-Host ('| {0}: | {1} | {2} | {3} | {4} | {5} |' -f $row.Drive, $cppCell, $rustCell, $speedCell, $rustRowsCell, $cppRowsCell)
}
if ($totalCppMs -gt 0) {
    $totalSpeedup = [math]::Round($totalCppMs / $totalRustMs, 1)
    Write-Host ('| **TOTAL (sum of per-drive p50s)** | **{0:N0} ms** | **{1:N0} ms** | **{2}x** | — | — |' -f $totalCppMs, $totalRustMs, $totalSpeedup)
} else {
    Write-Host ('| **TOTAL (sum of Rust p50s)** | — | **{0:N0} ms** | — | — | — |' -f $totalRustMs)
}

Write-Divider 'Summary — table 2: Rust daemon vs CLI breakdown'

Write-Host '| Drive | Rust rows | Rust wall p50 | Rust daemon p50 | CLI overhead |'
Write-Host '|-------|----------:|--------------:|----------------:|-------------:|'
foreach ($row in $results) {
    $overhead = if ($null -ne $row.RustDaemonP50) {
        '{0:N0} ms' -f ([math]::Max(0, $row.RustMedMs - $row.RustDaemonP50))
    } else { 'n/a' }
    $daemonCell = if ($null -ne $row.RustDaemonP50) { '{0:N0} ms' -f $row.RustDaemonP50 } else { 'n/a' }
    $rowsCell   = if ($null -ne $row.RustRows) { '{0:N0}' -f $row.RustRows } else { 'n/a' }
    Write-Host ('| {0}: | {1} | {2:N0} ms | {3} | {4} |' -f $row.Drive, $rowsCell, $row.RustMedMs, $daemonCell, $overhead)
}
Write-Host ''
Write-Host '  Legend:'
Write-Host '    Rust wall p50   = Stopwatch-measured PowerShell-to-CLI-to-daemon-to-file round-trip.'
Write-Host '    Rust daemon p50 = Daemon-reported search duration (from --profile "Search (IPC): ... (daemon: Y ms)").'
Write-Host '    CLI overhead    = wall - daemon (Windows process-creation + IPC + stderr profile print).'
Write-Host '    C++ has no daemon — its wall-clock IS its total cost, dominated by full-MFT re-read.'

Write-Divider 'Done'
Stop-Transcript | Out-Null
Write-Host "Full log written to: $OutputFile" -ForegroundColor Cyan
