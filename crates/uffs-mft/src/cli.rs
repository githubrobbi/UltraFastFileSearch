// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! CLI definitions for the `uffs-mft` binary.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// Output format for the `info` and `drives` commands.
///
/// `Human` is the default rich view (unchanged behaviour). `Table` is a compact
/// aligned table; `Json` is a machine-readable object for tooling (e.g. the
/// benchmark report embeds `drives --format json`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutputFormat {
    /// Rich, human-readable view (the default).
    #[default]
    Human,
    /// Compact aligned table.
    Table,
    /// Machine-readable JSON.
    Json,
}

/// NTFS metafile selectable via `uffs-mft metafile --kind`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum MetafileKind {
    /// `$Boot` — volume boot record + BPB (geometry, volume serial).
    Boot,
    /// `$Bitmap` — volume cluster-allocation bitmap (free space).
    Bitmap,
    /// `$Secure:$SDS` — security-descriptor store (ACLs / owner).
    Secure,
    /// `$AttrDef` — NTFS attribute-type definitions.
    AttrDef,
    /// `$MFTMirr` — backup of the first four `$MFT` records.
    MftMirr,
    /// `$Volume` — the MFT record (volume name / version / flags).
    Volume,
    /// `$BadClus` — the MFT record (bad-cluster run list).
    BadClus,
    /// `$LogFile` — the NTFS metadata transaction log.
    LogFile,
    /// `$UsnJrnl:$J` — the change journal (resolved via `$Extend`).
    UsnJrnl,
}

/// `uffs-mft`: Low-level NTFS MFT reading tool.
#[derive(Parser)]
#[command(name = "uffs-mft")]
#[command(author, version, about, long_about = None)]
pub(crate) struct Cli {
    /// Enable verbose output.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Available subcommands for the `uffs-mft` CLI.
#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Read MFT from a drive and export to Parquet
    Read {
        /// Drive letter (e.g., C, D, E)
        #[arg(short, long)]
        drive: uffs_mft::platform::DriveLetter,

        /// Output file path (Parquet format)
        #[arg(short, long)]
        output: PathBuf,

        /// Read mode: auto, parallel, streaming, prefetch
        /// - auto: Select based on drive type (SSD→parallel, HDD→prefetch)
        /// - parallel: Read all chunks then parse in parallel (best for SSD)
        /// - streaming: Sequential reads with immediate parsing (lower memory)
        /// - prefetch: Double-buffered reads for I/O overlap (best for HDD)
        #[arg(short, long, default_value = "auto")]
        mode: String,

        /// Merge extension records for complete data (slower).
        /// By default, extension records (~1% of files with many hard
        /// links/ADS) are skipped for ~15-25% faster reads.
        #[arg(long)]
        full: bool,

        /// Output one row per unique FRS instead of expanding hard links.
        /// By default, hard links are expanded to separate rows (matching
        /// Explorer). Use this flag for power users who want to
        /// count unique files, not paths.
        #[arg(long)]
        unique: bool,

        /// Include forensic records (deleted, corrupt, extension records).
        /// Adds `is_deleted`, `is_corrupt`, `is_extension`, `base_frs` columns.
        /// WARNING: May significantly increase output size (10-50% more rows).
        #[arg(long)]
        forensic: bool,
    },

    /// Show MFT information for a drive
    Info {
        /// Drive letter (e.g., C, D, E)
        #[arg(short, long)]
        drive: uffs_mft::platform::DriveLetter,

        /// Perform deep scan (reads all MFT records for detailed statistics)
        #[arg(long)]
        deep: bool,

        /// Disable bitmap optimization (read ALL records, not just in-use
        /// ones). Use this to debug if bitmap is causing records to be
        /// skipped incorrectly.
        #[arg(long)]
        no_bitmap: bool,

        /// Output one row per unique FRS instead of expanding hard links.
        /// By default, hard links are expanded to separate rows (matching
        /// Explorer). Use this flag for power users who want to
        /// count unique files, not paths.
        #[arg(long)]
        unique: bool,

        /// Output format: `human` (default), `table`, or `json`.
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },

    /// List all available NTFS drives
    Drives {
        /// Output format: `human`/`table` (default table) or `json`.
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },

    /// Probe the capture host: OS class (client/server), elevation, VSS
    /// availability, and per-drive media/geometry. Runs before a capture and
    /// records the machine the capture was taken on.
    Sysinfo {
        /// Write the report to this file (also printed to stdout).
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Emit machine-readable JSON instead of the text report (Windows
        /// only).
        #[arg(long)]
        json: bool,
    },

    /// Save an NTFS metafile ($Boot, ...) for offline analysis
    Metafile {
        /// Drive letter (e.g., C, D, E)
        #[arg(short, long)]
        drive: uffs_mft::platform::DriveLetter,

        /// Which metafile to capture
        #[arg(short, long, value_enum)]
        kind: MetafileKind,

        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Capture all NTFS metafiles for a drive into a hashed, manifested bundle
    Capture {
        /// Drive letter (e.g., C, D, E). Required unless `--all-drives` is set.
        #[arg(short, long)]
        drive: Option<uffs_mft::platform::DriveLetter>,

        /// Output directory (bundle written to `<out>/drive_<x>/`)
        #[arg(short, long)]
        out: PathBuf,

        /// Capture every eligible NTFS volume, each into its own
        /// `<out>/drive_<x>/` subfolder.
        #[arg(long)]
        all_drives: bool,

        /// Also pack each drive bundle into a `<dir>.tar.zst`
        /// (extract with `tar --zstd -xf`).
        #[arg(long)]
        zip: bool,

        /// With `--zip`, split the archive into parts of this many GiB
        /// (`<dir>.tar.zst.NNN`). 0 = no split.
        #[arg(long, default_value_t = 0, value_name = "GIB")]
        split_gib: u64,
    },

    /// Inspect a captured NTFS metafile offline (header + $Boot geometry, ...)
    MetafileInfo {
        /// Path to a captured metafile (from `metafile` or `capture`)
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Extract the raw `$MFT` from a captured `.bin` (decompress + strip
    /// header) into a byte-exact `$MFT` other tools (analyzeMFT, MFT2CSV,
    /// ntfstool) can read. Cross-platform.
    ExtractMft {
        /// Captured `.bin` (e.g. `C_mft.bin` from `capture`).
        #[arg(short, long)]
        input: PathBuf,

        /// Output path for the raw `$MFT`.
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Compare two MFT CSV exports (from `load`) for parity — e.g. Rust on
    /// Windows vs macOS, or Rust vs a C++ golden. Exits non-zero on mismatch.
    Verify {
        /// First CSV export.
        #[arg(short, long)]
        left: PathBuf,

        /// Second CSV export.
        #[arg(short, long)]
        right: PathBuf,

        /// Columns to compare (matched by header name; default: all columns of
        /// `--left`). Comma-separated, e.g. `frs,parent_frs,name,size`.
        #[arg(long, value_delimiter = ',')]
        columns: Vec<String>,
    },

    /// Benchmark MFT reading with detailed phase timing
    Bench {
        /// Drive letter (e.g., C, D, E)
        #[arg(short, long)]
        drive: uffs_mft::platform::DriveLetter,

        /// Output results as JSON (for scripting)
        #[arg(long)]
        json: bool,

        /// Skip `DataFrame` building (measure I/O + parse only)
        #[arg(long)]
        no_df: bool,

        /// Number of runs for averaging (default: 1)
        #[arg(long, default_value = "1")]
        runs: u32,

        /// Read mode: auto, parallel, streaming, prefetch
        #[arg(short, long, default_value = "auto")]
        mode: String,

        /// Merge extension records for complete data (slower).
        /// By default, extension records (~1% of files) are skipped for faster
        /// reads.
        #[arg(long)]
        full: bool,
    },

    /// Benchmark ALL NTFS drives and save results to a file
    BenchAll {
        /// Output file path (JSON format, default:
        /// `uffs_benchmark_YYYYMMDD_HHMMSS.json`)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Skip `DataFrame` building (measure I/O + parse only)
        #[arg(long)]
        no_df: bool,

        /// Number of runs per drive for averaging (default: 1)
        #[arg(long, default_value = "1")]
        runs: u32,

        /// Merge extension records for complete data (slower).
        /// By default, extension records (~1% of files) are skipped for faster
        /// reads.
        #[arg(long)]
        full: bool,
    },

    /// Diagnose MFT bitmap to investigate record skipping
    BitmapDiag {
        /// Drive letter (e.g., C, D, E)
        #[arg(short, long)]
        drive: uffs_mft::platform::DriveLetter,

        /// Show sample of individual record states
        #[arg(long)]
        samples: bool,
    },

    /// Save MFT bytes to a file for offline analysis
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft save --drive C --output mft_c.mft
    /// uffs-mft save -d C -o mft_c.mft --no-compress
    /// uffs-mft save -d C -o mft_c.raw --raw  # Compatible with other MFT tools
    /// uffs-mft save --upcase                  # Boot drive → upcase.bin
    /// uffs-mft save --upcase -d D -o D_upcase.bin
    /// ```
    Save {
        /// Drive letter to read MFT from (e.g., C, D, E).
        /// Required for MFT save; defaults to boot drive for --upcase.
        #[arg(short, long, value_name = "LETTER")]
        drive: Option<uffs_mft::platform::DriveLetter>,

        /// Output file path.
        /// Required for MFT save; defaults to `upcase.bin` for --upcase.
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Disable compression (default: compressed with zstd)
        #[arg(long)]
        no_compress: bool,

        /// Compression level (1-22, default 3)
        #[arg(long, default_value = "3")]
        compression_level: i32,

        /// Raw compatibility mode: output raw MFT bytes without header.
        /// This format is compatible with other MFT tools like analyzeMFT,
        /// MFT2CSV. Note: --raw implies --no-compress.
        #[arg(long)]
        raw: bool,

        /// IOCP capture mode: save chunks in IOCP completion order.
        /// This captures the non-deterministic order in which Windows IOCP
        /// delivers completed reads, enabling realistic testing of parsers
        /// on non-Windows systems. Uses UFFS-IOCP format.
        #[arg(long)]
        iocp: bool,

        /// IOCP concurrency level (number of reads in flight).
        /// Only used with --iocp. Default: 8.
        #[arg(long, default_value = "8")]
        iocp_concurrency: usize,

        /// Save the 128 KB `$UpCase` table instead of the full MFT.
        ///
        /// Reads FRS 10 from the MFT on the live volume, parses its
        /// DATA attribute data runs, reads the referenced clusters,
        /// and saves the raw `[u16; 65_536]` table to the output file.
        #[arg(long)]
        upcase: bool,
    },

    /// Load MFT from a saved file and export to parquet/csv
    ///
    /// Supports three formats:
    /// - UFFS-MFT: Standard compressed format with header
    /// - UFFS-IOCP: IOCP capture format (chunks in completion order)
    /// - Raw NTFS: Compatible with other MFT tools (requires --drive)
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft load mft_c.mft --info-only
    /// uffs-mft load mft_c.mft --output index.parquet
    /// uffs-mft load mft_c.mft -o index.csv
    /// uffs-mft load mft_c.mft --build-index  # Debug tree metrics
    /// uffs-mft load mft_c.raw --drive C -o output.csv  # Raw NTFS format
    /// uffs-mft load mft_c.iocp -o output.csv  # IOCP capture format
    /// ```
    Load {
        /// Input raw MFT file path (created with 'save' command or other tools)
        #[arg(value_name = "FILE")]
        input: PathBuf,

        /// Output file path (.parquet or .csv based on extension)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Show info about the raw MFT file only (don't export)
        #[arg(long)]
        info_only: bool,

        /// Build `MftIndex` and show tree metrics (for debugging)
        #[arg(long)]
        build_index: bool,

        /// Debug tree metrics computation (detailed hardlink handling output)
        #[arg(long)]
        debug_tree: bool,

        /// Volume letter for path resolution (e.g., C, D, E).
        /// Required for raw NTFS files that don't have this info in header.
        /// For UFFS-MFT format files, this overrides the stored volume letter.
        #[arg(short, long, value_name = "LETTER")]
        drive: Option<uffs_mft::platform::DriveLetter>,

        /// Include forensic records (deleted, corrupt, extension records).
        /// Adds `is_deleted`, `is_corrupt`, `is_extension`, `base_frs` columns.
        /// WARNING: May significantly increase output size (10-50% more rows).
        #[arg(long)]
        forensic: bool,
    },

    /// Raw MFT read benchmark (aligned with the reference `--benchmark-mft`
    /// output)
    ///
    /// Measures pure disk I/O throughput by reading the entire MFT with
    /// synchronous 1MB reads. Does NOT parse records or build `DataFrame`s.
    /// Use this to measure raw disk I/O throughput in isolation.
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft benchmark-mft --drive C
    /// uffs-mft benchmark-mft -d S
    /// ```
    BenchmarkMft {
        /// Drive letter (e.g., C, D, E)
        #[arg(short, long)]
        drive: uffs_mft::platform::DriveLetter,
    },

    /// Full index build benchmark (aligned with the reference
    /// `--benchmark-index` output)
    ///
    /// Measures the complete UFFS indexing pipeline: async I/O + parsing +
    /// `DataFrame` building. This is what users experience when indexing.
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft benchmark-index --drive C
    /// uffs-mft benchmark-index -d S
    /// ```
    BenchmarkIndex {
        /// Drive letter (e.g., C, D, E)
        #[arg(short, long)]
        drive: uffs_mft::platform::DriveLetter,
    },

    /// Lean index build benchmark (no `DataFrame` overhead)
    ///
    /// Measures the UFFS indexing pipeline with lean `MftIndex` instead of
    /// Polars `DataFrame`. This should be significantly faster (~2x) because
    /// it avoids `DataFrame` building overhead.
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft benchmark-index-lean --drive C
    /// uffs-mft benchmark-index-lean -d S
    /// uffs-mft benchmark-index-lean -d S --mode pipelined-parallel
    /// ```
    BenchmarkIndexLean {
        /// Drive letter (e.g., C, D, E)
        #[arg(short, long)]
        drive: uffs_mft::platform::DriveLetter,

        /// Read mode: auto, parallel, streaming, prefetch, pipelined,
        /// pipelined-parallel
        /// - auto: Select based on drive type (SSD→parallel,
        ///   HDD→pipelined-parallel)
        /// - parallel: Read all chunks then parse in parallel (best for SSD)
        /// - streaming: Sequential reads with immediate parsing (lower memory)
        /// - prefetch: Double-buffered reads for I/O overlap
        /// - pipelined: I/O+CPU overlap with single-threaded parsing
        /// - pipelined-parallel: I/O+CPU overlap with multi-core parsing (best
        ///   for HDD)
        #[arg(short, long, default_value = "auto")]
        mode: String,

        /// Disable MFT bitmap optimization (read entire MFT sequentially).
        /// Sequential reads may be faster than seeking to skip unused records
        /// on HDD.
        #[arg(long)]
        no_bitmap: bool,

        /// Disable placeholder creation for missing parent directories.
        /// Without placeholders, paths are resolved lazily. Disabling saves
        /// ~15% of CPU time.
        #[arg(long)]
        no_placeholders: bool,

        /// Number of concurrent I/O operations (reads in flight).
        /// Default: auto (2 for HDD, 8 for SSD, 32 for `NVMe`).
        /// Use this to experiment with I/O parallelism.
        #[arg(long)]
        concurrency: Option<usize>,

        /// I/O chunk size in KB (e.g., 1024 = 1MB, 2048 = 2MB, 4096 = 4MB).
        /// Default: auto (1MB for HDD, 2MB for SSD, 4MB for `NVMe`).
        /// Larger chunks reduce syscall overhead but increase latency per
        /// completion.
        #[arg(long)]
        io_size_kb: Option<usize>,

        /// Enable parallel parsing (M3 optimization).
        /// Uses worker threads to parse MFT records in parallel with I/O.
        /// Beneficial for `NVMe` drives where I/O is faster than parsing.
        /// Default: auto (enabled for `NVMe`, disabled for HDD/SSD).
        #[arg(long)]
        parallel_parse: bool,

        /// Number of parsing worker threads (only used with --parallel-parse).
        /// Default: number of CPU cores.
        #[arg(long)]
        parse_workers: Option<usize>,
    },

    /// Benchmark tree metrics computation in isolation.
    ///
    /// This command measures ONLY the tree metrics computation phase
    /// (descendants, treesize, `tree_allocated`), which corresponds to
    /// the "preprocessing" phase in `--benchmark-index`.
    ///
    /// Use this for direct apples-to-apples comparison of tree algorithm
    /// performance between Rust and the reference benchmark.
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft benchmark-tree --drive C
    /// uffs-mft benchmark-tree -d C --iterations 5
    /// uffs-mft benchmark-tree -d C --no-cache
    /// ```
    BenchmarkTree {
        /// Drive letter (e.g., C, D, E)
        #[arg(short, long)]
        drive: uffs_mft::platform::DriveLetter,

        /// Number of iterations to run (for averaging).
        /// Default: 3
        #[arg(short, long, default_value = "3")]
        iterations: usize,

        /// Skip cache and build fresh index from disk.
        /// By default, uses cached index if available.
        #[arg(long)]
        no_cache: bool,
    },

    /// Benchmark multi-volume indexing using single IOCP (M4 optimization).
    ///
    /// Reads MFTs from multiple drives simultaneously using a single I/O
    /// Completion Port. This allows the OS to optimize I/O scheduling across
    /// all drives.
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft benchmark-multi-volume --drives C,D,S
    /// uffs-mft benchmark-multi-volume -d C,F
    /// ```
    BenchmarkMultiVolume {
        /// Comma-separated list of drive letters (e.g., C,D,S)
        #[arg(short, long, value_delimiter = ',')]
        drives: Vec<uffs_mft::platform::DriveLetter>,
    },

    /// Query USN Journal information for a drive (M5 optimization).
    ///
    /// Shows the USN Journal ID, first/next USN, and other metadata.
    /// This is useful for checking if incremental updates are possible.
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft usn-info --drive C
    /// ```
    UsnInfo {
        /// Drive letter (e.g., C, D, E)
        #[arg(short, long)]
        drive: uffs_mft::platform::DriveLetter,
    },

    /// Read recent USN Journal changes for a drive (M5 optimization).
    ///
    /// Reads changes from the USN Journal since a given USN. If no start USN
    /// is provided, reads from the beginning of the journal.
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft usn-read --drive C
    /// uffs-mft usn-read --drive C --start-usn 12345678
    /// uffs-mft usn-read --drive C --limit 100
    /// ```
    UsnRead {
        /// Drive letter (e.g., C, D, E)
        #[arg(short, long)]
        drive: uffs_mft::platform::DriveLetter,

        /// Starting USN (default: read from journal start)
        #[arg(long)]
        start_usn: Option<i64>,

        /// Maximum number of records to display (default: 50)
        #[arg(long, default_value = "50")]
        limit: usize,
    },

    /// Save index to disk for incremental updates (M5 optimization).
    ///
    /// Saves the current MFT index to a binary file along with USN Journal
    /// checkpoint. This allows fast incremental updates later.
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft index-save --drive C --output c_index.uffs
    /// ```
    IndexSave {
        /// Drive letter (e.g., C, D, E)
        #[arg(short, long)]
        drive: uffs_mft::platform::DriveLetter,

        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Load index from disk and show info (M5 optimization).
    ///
    /// Loads a previously saved index and displays its metadata.
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft index-load --input c_index.uffs
    /// ```
    IndexLoad {
        /// Input file path
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Show cache status and manage cached indices (M5 optimization).
    ///
    /// Shows the status of cached indices in the system temp directory.
    /// Use --clean to remove expired caches, --purge to remove all.
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft cache-status
    /// uffs-mft cache-status --clean
    /// uffs-mft cache-status --purge
    /// ```
    CacheStatus {
        /// Remove expired cache files
        #[arg(long)]
        clean: bool,

        /// Remove ALL cache files
        #[arg(long)]
        purge: bool,
    },

    /// Get or refresh a cached index for a drive (M5 optimization).
    ///
    /// Loads the cached index if fresh, otherwise rebuilds and caches it.
    /// Uses the default TTL of 10 minutes.
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft cache-get --drive C
    /// uffs-mft cache-get --drive C --force
    /// ```
    CacheGet {
        /// Drive letter (e.g., C, D, E)
        #[arg(short, long)]
        drive: uffs_mft::platform::DriveLetter,

        /// Force rebuild even if cache is fresh
        #[arg(long)]
        force: bool,

        /// Custom TTL in seconds (default: 600 = 10 minutes)
        #[arg(long)]
        ttl: Option<u64>,
    },

    /// Clear cached indices (M5 optimization).
    ///
    /// Removes cached indices to force a fresh re-read on next access.
    /// Use --drive to clear a specific drive, or --all to clear everything.
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft cache-clear --drive C
    /// uffs-mft cache-clear --all
    /// ```
    CacheClear {
        /// Drive letter to clear (e.g., C, D, E)
        #[arg(short, long)]
        drive: Option<uffs_mft::platform::DriveLetter>,

        /// Clear ALL cached indices
        #[arg(long)]
        all: bool,
    },

    /// Incremental index update using USN Journal (M5 optimization).
    ///
    /// Loads a cached index and applies USN Journal changes since the last
    /// checkpoint. Much faster than a full MFT scan for typical workloads.
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft index-update --drive C
    /// uffs-mft index-update --drive C --force-full
    /// ```
    IndexUpdate {
        /// Drive letter (e.g., C, D, E)
        #[arg(short, long)]
        drive: uffs_mft::platform::DriveLetter,

        /// Force full MFT scan instead of incremental update
        #[arg(long)]
        force_full: bool,

        /// Custom TTL in seconds (default: 600 = 10 minutes)
        #[arg(long)]
        ttl: Option<u64>,
    },

    /// Index ALL NTFS drives in parallel (optimized lean index path).
    ///
    /// Reads MFTs from all detected NTFS drives simultaneously using the
    /// optimized `SlidingIocpInline` path with parallel parsing. Returns
    /// lean `MftIndex` structures (no `DataFrame` overhead).
    ///
    /// By default, uses cache: loads fresh indices from cache, rebuilds and
    /// saves stale/missing ones. Use `--no-cache` to force fresh reads.
    ///
    /// # Examples
    ///
    /// ```text
    /// uffs-mft index-all
    /// uffs-mft index-all --drives C,D,E
    /// uffs-mft index-all --no-cache
    /// uffs-mft index-all --ttl 300
    /// ```
    IndexAll {
        /// Comma-separated list of drive letters (default: all NTFS drives)
        #[arg(short, long, value_delimiter = ',')]
        drives: Option<Vec<uffs_mft::platform::DriveLetter>>,

        /// Skip cache (always read fresh from disk, still saves to cache)
        #[arg(long)]
        no_cache: bool,

        /// Cache TTL in seconds (default: 600 = 10 minutes)
        #[arg(long, default_value = "600")]
        ttl: u64,
    },
}
