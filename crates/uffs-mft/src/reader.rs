// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! MFT reader configuration and top-level entrypoints.
//!
//! The heavy read pipelines and multi-drive orchestration live in dedicated
//! submodules under `reader/`.

use std::path::PathBuf;

#[cfg(not(windows))]
use crate::error::MftError;
use crate::error::Result;
#[cfg(windows)]
use crate::platform::VolumeHandle;

mod benchmark;
mod dataframe_build;
mod dataframe_read;
mod dataframe_timing;
mod index_cache;
mod index_read;
mod index_timing;
mod multi_drive;
mod persistence;
mod persistence_capture;
mod read_mode;
mod stats;
mod usn_apply;

pub use self::benchmark::{BenchmarkResult, DriveCharacteristics, PhaseTimings};
pub use self::multi_drive::{DriveReadResult, MultiDriveMftReader};
pub use self::read_mode::MftReadMode;
pub use self::stats::{MftProgress, MftStats};

/// Abstraction over the MFT data source.
///
/// The MFT can be read from a live NTFS volume (Windows only, via IOCP) or
/// from a previously captured `.mft` file (cross-platform). This enum lets
/// `MftReader` dispatch to the correct pipeline without `#[cfg]` gates on
/// every public method.
///
/// The `LiveVolume` variant boxes its `VolumeHandle` (Windows-only) so the enum
/// stays compact (one pointer per variant) instead of allocating the
/// `VolumeHandle`-sized inline payload (~120 bytes including the NTFS
/// volume-data block) on every `MftReader` instance — also silences the
/// rustc `variant_size_differences` lint comparing against the
/// pointer-sized `File(PathBuf)` arm.
#[derive(Debug)]
pub(crate) enum MftSource {
    /// Live NTFS volume accessed via Windows IOCP.
    #[cfg(windows)]
    LiveVolume(Box<VolumeHandle>),
    /// Pre-captured `.mft` file (cross-platform).
    File(PathBuf),
}

/// MFT Reader for direct NTFS Master File Table access.
///
/// This struct provides high-performance MFT reading by bypassing
/// Windows file enumeration APIs and reading the MFT directly.
///
/// # Platform Support
///
/// MFT reading is only available on Windows. On other platforms,
/// methods will return `MftError::PlatformNotSupported`.
///
/// # Privileges
///
/// Reading the MFT requires Administrator privileges. The process
/// must be elevated or have `SE_BACKUP_PRIVILEGE`.
///
/// # Example
///
/// ```rust,ignore
/// use uffs_mft::MftReader;
///
/// fn main() -> Result<(), Box<dyn core::error::Error>> {
///     let reader = MftReader::open(crate::platform::DriveLetter::C)?;
///     let df = reader.read_all()?;
///     println!("Found {} files", df.height());
///     Ok(())
/// }
/// ```
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "builder pattern with boolean options"
)]
pub struct MftReader {
    /// The volume letter (e.g., [`crate::platform::DriveLetter::C`]).
    volume: crate::platform::DriveLetter,
    /// Data source: live NTFS volume or pre-captured `.mft` file.
    source: MftSource,
    /// Read mode selection.
    mode: MftReadMode,
    /// Whether to merge extension records.
    ///
    /// - `false` (default): Fast path - skips extension records (~1% of files
    ///   with many hard links/ADS). ~15-25% faster, ideal for file search.
    /// - `true`: Full path - merges extension attributes for complete data.
    merge_extensions: bool,
    /// Whether to use the MFT bitmap for optimization.
    ///
    /// - `true` (default): Use bitmap to skip unused records (faster).
    /// - `false`: Read all records regardless of bitmap (for debugging).
    use_bitmap: bool,
    /// Whether to expand hard links to separate rows.
    ///
    /// - `true` (default): Each hard link becomes a separate row, matching the
    ///   legacy output behavior and user expectations (what they see in
    ///   Explorer).
    /// - `false`: One row per unique FRS (power user mode, smaller output).
    expand_links: bool,
    /// Whether to add placeholder records for missing parent directories.
    ///
    /// - `true` (default): Add placeholders for path resolution.
    /// - `false`: Skip placeholders (faster, but path resolution may fail for
    ///   some files whose parents weren't in the MFT).
    ///
    /// # Performance Optimization (2026-01-23)
    ///
    /// The legacy implementation resolved placeholders lazily instead of adding
    /// them upfront.
    /// Disabling this saves ~15% of CPU time during indexing.
    add_placeholders: bool,
    /// Number of concurrent I/O operations (reads in flight).
    ///
    /// - Default: 2 for HDD (optimal for sequential reads)
    /// - Higher values (8-32) may help on SSD/`NVMe`
    ///
    /// For HDDs, more concurrency can cause seeks and hurt performance.
    /// For `NVMe`, high concurrency (16-32) is needed to saturate the device.
    concurrency: Option<usize>,
    /// I/O chunk size in bytes.
    ///
    /// - Default: 1MB (1024 * 1024)
    /// - Larger chunks (2-4MB) reduce syscall overhead but increase latency
    io_size: Option<usize>,
    /// Whether to use parallel parsing (M3 optimization).
    ///
    /// - `None` (default): Auto-detect based on drive type (enabled for `NVMe`)
    /// - `Some(true)`: Force parallel parsing
    /// - `Some(false)`: Force inline parsing
    ///
    /// Parallel parsing uses worker threads to parse MFT records in parallel
    /// with I/O. This is beneficial for `NVMe` drives where I/O is faster than
    /// parsing.
    parallel_parse: Option<bool>,
    /// Number of parsing worker threads (only used with parallel parsing).
    ///
    /// - `None` (default): Use number of CPU cores
    /// - `Some(n)`: Use exactly n worker threads
    parse_workers: Option<usize>,
    /// Whether to include forensic records (deleted, corrupt, extension).
    ///
    /// - `false` (default): Normal mode - skip deleted/corrupt, merge
    ///   extensions.
    /// - `true`: Forensic mode - include all records with `is_deleted`,
    ///   `is_corrupt`, `is_extension`, `base_frs` columns.
    ///
    /// WARNING: May significantly increase output size (10-50% more rows).
    forensic: bool,
}

impl MftReader {
    /// Open a volume for MFT reading.
    ///
    /// # Arguments
    ///
    /// * `volume` - The drive letter (e.g.,
    ///   [`crate::platform::DriveLetter::C`])
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The volume cannot be opened
    /// - The volume is not NTFS formatted
    /// - Insufficient privileges (not running as Administrator)
    ///
    /// # Platform
    ///
    /// This function is only available on Windows.
    #[cfg(windows)]
    pub fn open(volume: crate::platform::DriveLetter) -> Result<Self> {
        let handle = VolumeHandle::open(volume)?;

        Ok(Self {
            volume,
            source: MftSource::LiveVolume(Box::new(handle)),
            mode: MftReadMode::Auto,
            merge_extensions: true,
            use_bitmap: true,
            expand_links: true,
            add_placeholders: true,
            concurrency: None,
            io_size: None,
            parallel_parse: None,
            parse_workers: None,
            forensic: false,
        })
    }

    /// Open a volume for MFT reading (non-Windows stub).
    ///
    /// # Errors
    ///
    /// Always returns `MftError::PlatformNotSupported` on non-Windows
    /// platforms.
    #[cfg(not(windows))]
    pub const fn open(_volume: crate::platform::DriveLetter) -> Result<Self> {
        Err(MftError::PlatformNotSupported)
    }

    /// Open an arbitrary device path for MFT reading — e.g. a VSS snapshot
    /// device (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`), rather
    /// than a live drive letter's `\\.\<letter>:` path. See
    /// [`crate::platform::VolumeHandle::open_device_path`] for the
    /// full contract (no Access Broker fast-path; caller must already be
    /// elevated) and what `volume` (a diagnostic label only) is for.
    ///
    /// # Errors
    ///
    /// Returns an error if the device path cannot be opened or is not NTFS
    /// formatted.
    ///
    /// # Platform
    ///
    /// This function is only available on Windows.
    #[cfg(windows)]
    pub fn open_device_path(
        device_path: &str,
        volume: crate::platform::DriveLetter,
    ) -> Result<Self> {
        let handle = VolumeHandle::open_device_path(device_path, volume)?;

        Ok(Self {
            volume,
            source: MftSource::LiveVolume(Box::new(handle)),
            mode: MftReadMode::Auto,
            merge_extensions: true,
            use_bitmap: true,
            expand_links: true,
            add_placeholders: true,
            concurrency: None,
            io_size: None,
            parallel_parse: None,
            parse_workers: None,
            forensic: false,
        })
    }

    /// Open an arbitrary device path for MFT reading (non-Windows stub).
    ///
    /// # Errors
    ///
    /// Always returns `MftError::PlatformNotSupported` on non-Windows
    /// platforms.
    #[cfg(not(windows))]
    pub const fn open_device_path(
        _device_path: &str,
        _volume: crate::platform::DriveLetter,
    ) -> Result<Self> {
        Err(MftError::PlatformNotSupported)
    }

    /// Create a reader from a pre-captured `.mft` file (cross-platform).
    ///
    /// This enables the full search/filter/sort pipeline on any platform
    /// using a previously saved MFT capture file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the `.mft` capture file
    /// * `volume` - The volume letter to associate (e.g.,
    ///   [`crate::platform::DriveLetter::C`])
    #[must_use]
    pub fn from_file<P: Into<PathBuf>>(path: P, volume: crate::platform::DriveLetter) -> Self {
        Self {
            volume,
            source: MftSource::File(path.into()),
            mode: MftReadMode::Auto,
            merge_extensions: true,
            use_bitmap: true,
            expand_links: true,
            add_placeholders: true,
            concurrency: None,
            io_size: None,
            parallel_parse: None,
            parse_workers: None,
            forensic: false,
        }
    }

    /// Returns the live-volume `VolumeHandle` for this reader.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::MftError::InvalidInput`] if the reader was
    /// constructed via [`MftReader::from_file`] rather than
    /// [`MftReader::open`].  In production this is a contract violation:
    /// the IOCP read pipelines that call this method are dispatched only
    /// after construction guarantees a live volume.  A typed error keeps
    /// the contract enforceable without panicking.
    #[cfg(windows)]
    pub(crate) fn require_handle(&self) -> Result<&VolumeHandle> {
        match &self.source {
            MftSource::LiveVolume(handle) => Ok(handle),
            MftSource::File(_) => Err(crate::error::MftError::InvalidInput(
                "live-volume operation invoked on file-backed MftReader".into(),
            )),
        }
    }

    /// Returns `true` if this reader is backed by a live NTFS volume.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        #[cfg(windows)]
        {
            matches!(self.source, MftSource::LiveVolume(..))
        }
        #[cfg(not(windows))]
        {
            // self IS used — matches!(self.source, ...) on non-Windows has no
            // LiveVolume variant, so always false.  Reference self to satisfy
            // unused_self lint (API parity).
            let _: &MftSource = &self.source;
            false
        }
    }

    /// Returns `true` if this reader is backed by a file.
    #[must_use]
    pub const fn is_file(&self) -> bool {
        matches!(self.source, MftSource::File(..))
    }

    /// Sets the read mode for this reader.
    ///
    /// # Arguments
    ///
    /// * `mode` - The read mode to use (Auto, Parallel, Streaming, Prefetch)
    #[must_use]
    pub const fn with_mode(mut self, mode: MftReadMode) -> Self {
        self.mode = mode;
        self
    }

    /// Returns the current read mode.
    #[must_use]
    pub const fn mode(&self) -> MftReadMode {
        self.mode
    }

    /// Sets whether to merge extension records.
    ///
    /// Extension records are used when a file has too many attributes to fit
    /// in a single MFT record (e.g., many hard links, alternate data streams).
    /// This affects ~1% of files.
    ///
    /// # Arguments
    ///
    /// * `merge` - If `true`, merge extension records for complete data. If
    ///   `false` (default), skip extensions for ~15-25% faster reads.
    #[must_use]
    pub const fn with_merge_extensions(mut self, merge: bool) -> Self {
        self.merge_extensions = merge;
        self
    }

    /// Returns whether extension record merging is enabled.
    #[must_use]
    pub const fn merge_extensions(&self) -> bool {
        self.merge_extensions
    }

    /// Sets whether to use the MFT bitmap for optimization.
    ///
    /// The bitmap indicates which MFT records are "in use" vs "free".
    /// When enabled (default), unused records are skipped for faster reads.
    /// Disable this for debugging if you suspect the bitmap is causing
    /// records to be incorrectly skipped.
    ///
    /// # Arguments
    ///
    /// * `use_bitmap` - If `true` (default), use bitmap optimization. If
    ///   `false`, read all records regardless of bitmap.
    #[must_use]
    pub const fn with_use_bitmap(mut self, use_bitmap: bool) -> Self {
        self.use_bitmap = use_bitmap;
        self
    }

    /// Returns whether bitmap optimization is enabled.
    #[must_use]
    pub const fn use_bitmap(&self) -> bool {
        self.use_bitmap
    }

    /// Sets whether to expand hard links to separate rows.
    ///
    /// When enabled (default), each hard link becomes a separate row in the
    /// output. This matches the legacy output behavior and user expectations -
    /// if a file has 3 hard links, users see 3 entries in Explorer, so they
    /// expect 3 entries in search results.
    ///
    /// When disabled (`--unique` mode), only one row per unique FRS is output.
    /// This is useful for power users who want to count unique files, not
    /// paths.
    ///
    /// # Arguments
    ///
    /// * `expand` - If `true` (default), expand hard links. If `false`, output
    ///   one row per unique FRS.
    #[must_use]
    pub const fn with_expand_links(mut self, expand: bool) -> Self {
        self.expand_links = expand;
        self
    }

    /// Returns whether hard link expansion is enabled.
    #[must_use]
    pub const fn expand_links(&self) -> bool {
        self.expand_links
    }

    /// Sets whether to add placeholder records for missing parent directories.
    ///
    /// When enabled (default), placeholder records are created for parent
    /// directories that are referenced but not present in the MFT. This ensures
    /// path resolution works for all files.
    ///
    /// When disabled, placeholder creation is skipped. This is faster (~15%
    /// improvement) but path resolution may fail for some files whose parents
    /// weren't in the MFT.
    ///
    /// # Performance Optimization (2026-01-23)
    ///
    /// The legacy implementation resolved placeholders lazily instead of adding
    /// them upfront. Disabling this matches the legacy output behavior and
    /// saves ~15% of CPU time.
    ///
    /// # Arguments
    ///
    /// * `add` - If `true` (default), add placeholders. If `false`, skip.
    #[must_use]
    pub const fn with_add_placeholders(mut self, add: bool) -> Self {
        self.add_placeholders = add;
        self
    }

    /// Returns whether placeholder creation is enabled.
    #[must_use]
    pub const fn add_placeholders(&self) -> bool {
        self.add_placeholders
    }

    /// Sets the number of concurrent I/O operations (reads in flight).
    ///
    /// This controls how many async read operations are queued simultaneously.
    /// The optimal value depends on the drive type:
    ///
    /// - **HDD**: 2 (default) - More concurrency causes seeks and hurts
    ///   performance
    /// - **SSD**: 4-8 - Can benefit from moderate parallelism
    /// - **`NVMe`**: 16-32 - High concurrency needed to saturate the device
    ///
    /// # Arguments
    ///
    /// * `concurrency` - Number of I/O operations in flight (1-64)
    #[must_use]
    pub const fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = Some(concurrency);
        self
    }

    /// Returns the configured concurrency, or None for default.
    #[must_use]
    pub const fn concurrency(&self) -> Option<usize> {
        self.concurrency
    }

    /// Sets the I/O chunk size in bytes.
    ///
    /// This controls the size of each async read operation. Larger chunks
    /// reduce syscall overhead but increase latency per completion.
    ///
    /// - **Default**: 1MB (1024 * 1024)
    /// - **SSD**: 2MB may be slightly better
    /// - **`NVMe`**: 4MB can reduce overhead
    ///
    /// # Arguments
    ///
    /// * `io_size` - I/O chunk size in bytes (e.g., 1024*1024 for 1MB)
    #[must_use]
    pub const fn with_io_size(mut self, io_size: usize) -> Self {
        self.io_size = Some(io_size);
        self
    }

    /// Returns the configured I/O size, or None for default.
    #[must_use]
    pub const fn io_size(&self) -> Option<usize> {
        self.io_size
    }

    /// Sets whether to use parallel parsing (M3 optimization).
    ///
    /// Parallel parsing uses worker threads to parse MFT records in parallel
    /// with I/O. This is beneficial for `NVMe` drives where I/O is faster than
    /// parsing.
    ///
    /// # Arguments
    ///
    /// * `parallel` - If `true`, use parallel parsing. If `false`, use inline
    ///   parsing.
    #[must_use]
    pub const fn with_parallel_parse(mut self, parallel: bool) -> Self {
        self.parallel_parse = Some(parallel);
        self
    }

    /// Returns whether parallel parsing is enabled.
    #[must_use]
    pub const fn parallel_parse(&self) -> Option<bool> {
        self.parallel_parse
    }

    /// Sets the number of parsing worker threads.
    ///
    /// Only used when parallel parsing is enabled.
    ///
    /// # Arguments
    ///
    /// * `workers` - Number of worker threads (None = use available CPU count)
    #[must_use]
    pub const fn with_parse_workers(mut self, workers: Option<usize>) -> Self {
        self.parse_workers = workers;
        self
    }

    /// Returns the configured number of parse workers.
    #[must_use]
    pub const fn parse_workers(&self) -> Option<usize> {
        self.parse_workers
    }

    /// Enables forensic mode for this reader.
    ///
    /// Forensic mode includes deleted, corrupt, and extension records in the
    /// output, adding `is_deleted`, `is_corrupt`, `is_extension`, `base_frs`
    /// columns.
    ///
    /// # Arguments
    ///
    /// * `forensic` - If `true`, enable forensic mode. If `false` (default),
    ///   use normal mode.
    ///
    /// # Warning
    ///
    /// Forensic mode may significantly increase output size (10-50% more rows).
    #[must_use]
    pub const fn with_forensic(mut self, forensic: bool) -> Self {
        self.forensic = forensic;
        self
    }

    /// Returns whether forensic mode is enabled.
    #[must_use]
    pub const fn forensic(&self) -> bool {
        self.forensic
    }

    /// Get the volume letter this reader is attached to.
    #[must_use]
    pub const fn volume(&self) -> crate::platform::DriveLetter {
        self.volume
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::*;
    use crate::error::MftError;

    #[test]
    #[cfg(windows)]
    fn open_valid_volume() {
        let result = MftReader::open(crate::platform::DriveLetter::C);
        // This will fail without admin privileges, but should not panic
        assert!(result.is_ok() || matches!(result, Err(MftError::InsufficientPrivileges)));
    }

    #[test]
    #[cfg(not(windows))]
    fn platform_not_supported() {
        let result = MftReader::open(crate::platform::DriveLetter::C);
        assert!(matches!(result, Err(MftError::PlatformNotSupported)));
    }

    #[test]
    fn progress_percentage() {
        let progress = MftProgress {
            records_read: 50,
            total_records: Some(100),
            bytes_read: 1024,
            elapsed: Duration::from_secs(1),
        };
        assert_eq!(progress.percentage(), Some(50.0_f64));
    }

    #[test]
    fn progress_speed() {
        let progress = MftProgress {
            records_read: 1000,
            total_records: None,
            bytes_read: 10 * 1024 * 1024, // 10 MB
            elapsed: Duration::from_secs(2),
        };
        assert!((progress.speed_mbps() - 5.0_f64).abs() < 0.01_f64);
    }

    #[test]
    fn multi_drive_reader_new() {
        // [`DriveLetter`] canonicalises to uppercase at construction,
        // so the input list is already normalised.  The accessor
        // returns the same letters in order.
        use crate::platform::DriveLetter;
        let reader = MultiDriveMftReader::new(vec![DriveLetter::C, DriveLetter::D, DriveLetter::E]);
        assert_eq!(reader.drives(), &[
            DriveLetter::C,
            DriveLetter::D,
            DriveLetter::E
        ]);
    }

    #[test]
    fn multi_drive_reader_empty() {
        let reader = MultiDriveMftReader::new(vec![]);
        assert!(reader.drives().is_empty());
    }

    #[tokio::test]
    #[cfg(not(windows))]
    async fn multi_drive_platform_not_supported() {
        let reader = MultiDriveMftReader::new(vec![
            crate::platform::DriveLetter::C,
            crate::platform::DriveLetter::D,
        ]);
        let result = reader.read_all().await;
        assert!(matches!(result, Err(MftError::PlatformNotSupported)));
    }

    #[tokio::test]
    #[cfg(not(windows))]
    async fn multi_drive_index_platform_not_supported() {
        let reader = MultiDriveMftReader::new(vec![
            crate::platform::DriveLetter::C,
            crate::platform::DriveLetter::D,
        ]);
        let result = reader.read_all_index().await;
        assert!(matches!(result, Err(MftError::PlatformNotSupported)));
    }

    #[tokio::test]
    #[cfg(not(windows))]
    async fn multi_drive_index_cached_platform_not_supported() {
        let reader = MultiDriveMftReader::new(vec![
            crate::platform::DriveLetter::C,
            crate::platform::DriveLetter::D,
        ]);
        let result = reader.read_all_index_cached(3600).await;
        assert!(matches!(result, Err(MftError::PlatformNotSupported)));
    }

    // =========================================================================
    // Tests for MftReader optimal defaults
    // =========================================================================

    /// Test that `MftReader` stores None for concurrency/`io_size` by default,
    /// allowing the I/O layer to use optimal settings based on drive type.
    #[test]
    #[cfg(windows)]
    fn mft_reader_uses_none_defaults() {
        // This test requires admin privileges, so we check if we can open
        let reader = match MftReader::open(crate::platform::DriveLetter::C) {
            Ok(opened) => opened,
            Err(MftError::InsufficientPrivileges) => {
                // Skip test if not running as admin
                return;
            }
            Err(err) => panic!("Unexpected error: {err:?}"),
        };

        // Verify that concurrency and io_size are None (will use optimal defaults)
        assert!(
            reader.concurrency.is_none(),
            "MftReader should default to None for concurrency"
        );
        assert!(
            reader.io_size.is_none(),
            "MftReader should default to None for io_size"
        );
        assert!(
            reader.parallel_parse.is_none(),
            "MftReader should default to None for parallel_parse"
        );
        assert!(
            reader.parse_workers.is_none(),
            "MftReader should default to None for parse_workers"
        );
    }

    /// Test that `MftReader` builder methods correctly set values
    #[test]
    #[cfg(windows)]
    fn mft_reader_builder_overrides() {
        let reader = match MftReader::open(crate::platform::DriveLetter::C) {
            Ok(opened) => opened,
            Err(MftError::InsufficientPrivileges) => return,
            Err(err) => panic!("Unexpected error: {err:?}"),
        };

        // Apply builder methods
        let configured = reader
            .with_concurrency(16)
            .with_io_size(2 * 1024 * 1024)
            .with_parallel_parse(true)
            .with_parse_workers(Some(4));

        // Verify values are set
        assert_eq!(configured.concurrency, Some(16));
        assert_eq!(configured.io_size, Some(2 * 1024 * 1024));
        assert_eq!(configured.parallel_parse, Some(true));
        assert_eq!(configured.parse_workers, Some(4));
    }

    /// Test that `MftReadMode::Auto` is the default
    #[test]
    #[cfg(windows)]
    fn mft_reader_default_mode_is_auto() {
        let reader = match MftReader::open(crate::platform::DriveLetter::C) {
            Ok(opened) => opened,
            Err(MftError::InsufficientPrivileges) => return,
            Err(err) => panic!("Unexpected error: {err:?}"),
        };

        assert_eq!(
            reader.mode,
            MftReadMode::Auto,
            "MftReader should default to Auto mode"
        );
    }

    /// Test that all boolean defaults are set for optimal performance
    #[test]
    #[cfg(windows)]
    fn mft_reader_boolean_defaults() {
        let reader = match MftReader::open(crate::platform::DriveLetter::C) {
            Ok(opened) => opened,
            Err(MftError::InsufficientPrivileges) => return,
            Err(err) => panic!("Unexpected error: {err:?}"),
        };

        // These defaults are set for optimal performance and baseline-compatible output
        assert!(reader.use_bitmap, "use_bitmap should default to true");
        assert!(reader.expand_links, "expand_links should default to true");
        assert!(
            reader.add_placeholders,
            "add_placeholders should default to true"
        );
        assert!(
            reader.merge_extensions,
            "merge_extensions should default to true"
        );
    }
}
