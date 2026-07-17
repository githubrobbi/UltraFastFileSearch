// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! The [`DisplayRow`] result-row type and its `uffs_format::FormatRow` impl.
//!
//! Extracted from `backend.rs` to keep that file under the 800-LOC file-size
//! policy. `DisplayRow` is re-exported from `backend` (`pub use`) so the
//! single-import convention downstream crates rely on
//! (`uffs_core::search::backend::DisplayRow`) is preserved.

/// A single displayable search result row.
///
/// The filename is **not** stored separately — it is derived from the `path`
/// field using `name_start` (byte offset where the filename begins within
/// `path`).  This avoids one heap allocation per result row.
///
/// `Default` is implemented manually below: [`uffs_mft::platform::DriveLetter`]
/// has no `Default` impl (it's a validated `A..=Z` newtype with no canonical
/// zero), but the `sort_rows_with_fold` hot path uses
/// [`core::mem::take`] to move rows out of a `&mut [DisplayRow]` slice
/// as part of a Schwartzian decorate/sort/undecorate transform.  The
/// take leaves a transient placeholder in the slice that's
/// immediately overwritten by the put-back step, so any consistent
/// drive letter works for the placeholder.
#[derive(Debug, Clone)]
#[expect(
    clippy::partial_pub_fields,
    reason = "name_start is private by design — accessed via name() method"
)]
pub struct DisplayRow {
    /// Record index within the compact/cache file.
    pub record_index: u32,
    /// Drive letter this result belongs to.
    pub drive: uffs_mft::platform::DriveLetter,
    /// Full resolved path (e.g., `C:\Users\file.txt`).
    pub path: String,
    /// Byte offset within `path` where the filename begins.
    ///
    /// `self.name()` returns `&self.path[name_start..]`.
    /// Computed once at construction from the last `\` separator.
    name_start: u32,
    /// File size in bytes.
    pub size: u64,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// Last modified time (Unix microseconds).
    pub modified: i64,
    /// Creation time (Unix microseconds).
    pub created: i64,
    /// Last access time (Unix microseconds).
    pub accessed: i64,
    /// Raw NTFS `FILE_ATTRIBUTE_*` flags.
    pub flags: u32,
    /// Allocated size on disk in bytes.
    pub allocated: u64,
    /// Descendant count (directories only).
    pub descendants: u32,
    /// Sum of logical file sizes in entire subtree (directories only).
    pub treesize: u64,
    /// Sum of allocated sizes in entire subtree (directories only).
    pub tree_allocated: u64,
    /// WI-4.4 forensic flag: this record's own leaf name is ill-formed (its
    /// true bytes are not valid UTF-8 — an unpaired UTF-16 surrogate).
    /// Computed in the hot path from the lossless name bytes; the lossy
    /// `path`/`name()` view cannot recover this (it is always valid UTF-8).
    pub malformed: bool,
    /// WI-4.4 forensic flag: some component of the resolved path is ill-formed
    /// (so a clean-named file under a crooked directory is flagged). Superset
    /// of [`Self::malformed`]; computed during parent-chain resolution.
    pub malformed_path: bool,
    /// WI-4.4 forensic evidence: hex of the true (WTF-8) leaf-name bytes.
    /// `Some` for every malformed leaf and `None` otherwise, so the
    /// hex-encode/allocation cost is paid only for the vanishing fraction of
    /// ill-formed names — it is keyed on name validity, never on projection.
    /// JSON output therefore carries it by default for malformed rows.
    pub name_hex: Option<String>,
    /// NTFS **File Reference** (`(sequence_number << 48) | frs`) — see
    /// [`crate::compact::CompactRecord::file_ref`]. `0` by default;
    /// [`Self::with_file_reference`] carries the real value from the
    /// hot path's `CompactRecord`, mirroring [`Self::with_forensics`]'s
    /// pattern so `new()`'s existing call sites stay untouched.
    pub file_reference: u64,
}

impl DisplayRow {
    /// Construct a `DisplayRow`, computing `name_start` from the path.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "flat struct — all fields are required, no logical grouping"
    )]
    pub fn new(
        record_index: u32,
        drive: uffs_mft::platform::DriveLetter,
        path: String,
        size: u64,
        is_directory: bool,
        modified: i64,
        created: i64,
        accessed: i64,
        flags: u32,
        allocated: u64,
        descendants: u32,
        treesize: u64,
        tree_allocated: u64,
    ) -> Self {
        let name_start = uffs_mft::len_to_u32(path.rfind('\\').map_or(0, |pos| pos + 1));
        Self {
            record_index,
            drive,
            path,
            name_start,
            size,
            is_directory,
            modified,
            created,
            accessed,
            flags,
            allocated,
            descendants,
            treesize,
            tree_allocated,
            // Forensic carriers default to "well-formed / not requested"; the
            // hot path overwrites them via `with_forensics` when it has the
            // lossless name bytes. Keeping them out of `new()`'s arg list
            // leaves the many existing call sites untouched.
            malformed: false,
            malformed_path: false,
            name_hex: None,
            file_reference: 0,
        }
    }

    /// Attach the WI-4.4 forensic facts computed in the hot path against the
    /// lossless name bytes. Chained after [`Self::new`] at the single result-
    /// materialization chokepoint so the lossy `path` boundary is never the
    /// source of these values.
    #[must_use]
    #[inline]
    pub fn with_forensics(
        mut self,
        malformed: bool,
        malformed_path: bool,
        name_hex: Option<String>,
    ) -> Self {
        self.malformed = malformed;
        self.malformed_path = malformed_path;
        self.name_hex = name_hex;
        self
    }

    /// Attach the NTFS file reference from the `CompactRecord` this row
    /// was built from. Chained after [`Self::new`] for the same reason
    /// as [`Self::with_forensics`] — keeps the many existing `new()`
    /// call sites untouched.
    #[must_use]
    #[inline]
    pub const fn with_file_reference(mut self, file_reference: u64) -> Self {
        self.file_reference = file_reference;
        self
    }

    /// Filename portion of the path (e.g., `file.txt`).
    ///
    /// Zero-cost: returns a `&str` slice into the owned `path`.
    ///
    /// The `uffs_format::FormatRow::name` trait method forwards to
    /// this inherent method — keeping the inherent impl named `name`
    /// (rather than e.g. `file_name`) preserves the accessor's
    /// ergonomics across the many `uffs-core` call sites that
    /// predate the trait.  The intentional collision with the trait
    /// method silences `clippy::same_name_method` here.
    #[must_use]
    #[inline]
    #[expect(
        clippy::same_name_method,
        reason = "shared name with the FormatRow trait impl is intentional — see method-level doc"
    )]
    pub fn name(&self) -> &str {
        self.path.get(self.name_start as usize..).unwrap_or("")
    }

    /// Directory portion of path (up to and including the last `\`).
    ///
    /// Uses `name_start` for zero-cost slicing (no `rfind` needed).
    #[must_use]
    #[inline]
    pub fn path_dir(&self) -> &str {
        self.path
            .get(..self.name_start as usize)
            .unwrap_or(&self.path)
    }
}

/// Feed `DisplayRow` straight into the shared `uffs-format` writer.
///
/// The daemon holds `DisplayRow` directly on the search hot path, so
/// this impl lets `uffs_format::write_rows::<DisplayRow, _>` run
/// without an intermediate copy.  Every accessor is O(1) and just
/// hands back a struct field (or the pre-computed filename slice),
/// matching the trait's inlineability requirement.
///
/// Manual `Default` impl — see the struct doc-comment for why we
/// don't derive it.  All fields default to their natural zero
/// (`0`, `String::new()`, `false`) except `drive`, which we set to
/// [`uffs_mft::platform::DriveLetter::A`] purely as a placeholder for
/// [`core::mem::take`] in the sort hot path.  Callers never observe
/// this value: the take is immediately followed by a put-back.
impl Default for DisplayRow {
    fn default() -> Self {
        Self {
            record_index: 0,
            drive: uffs_mft::platform::DriveLetter::A,
            path: String::new(),
            name_start: 0,
            size: 0,
            is_directory: false,
            modified: 0,
            created: 0,
            accessed: 0,
            flags: 0,
            allocated: 0,
            descendants: 0,
            treesize: 0,
            tree_allocated: 0,
            malformed: false,
            malformed_path: false,
            name_hex: None,
            file_reference: 0,
        }
    }
}

/// The trait method `name()` collides with `DisplayRow::name()` (the
/// inherent accessor that pre-dates the trait); the trait impl
/// delegates to the inherent impl so the behaviour is identical.
/// The `clippy::same_name_method` lint is silenced on the inherent
/// method above — see its `#[expect]` attribute.
impl uffs_format::FormatRow for DisplayRow {
    #[inline]
    fn drive(&self) -> char {
        // `uffs-format` is a foundation crate that intentionally
        // doesn't depend on `uffs-mft`, so the trait surface
        // stays `char`.  `DriveLetter::as_char` is the canonical
        // zero-cost conversion to the ASCII letter.
        self.drive.as_char()
    }
    #[inline]
    fn path(&self) -> &str {
        &self.path
    }
    #[inline]
    fn name(&self) -> &str {
        Self::name(self)
    }
    #[inline]
    fn size(&self) -> u64 {
        self.size
    }
    #[inline]
    fn is_directory(&self) -> bool {
        self.is_directory
    }
    #[inline]
    fn modified(&self) -> i64 {
        self.modified
    }
    #[inline]
    fn created(&self) -> i64 {
        self.created
    }
    #[inline]
    fn accessed(&self) -> i64 {
        self.accessed
    }
    #[inline]
    fn flags(&self) -> u32 {
        self.flags
    }
    #[inline]
    fn allocated(&self) -> u64 {
        self.allocated
    }
    #[inline]
    fn descendants(&self) -> u32 {
        self.descendants
    }
    #[inline]
    fn treesize(&self) -> u64 {
        self.treesize
    }
    #[inline]
    fn tree_allocated(&self) -> u64 {
        self.tree_allocated
    }
    #[inline]
    fn malformed(&self) -> bool {
        self.malformed
    }
    #[inline]
    fn malformed_path(&self) -> bool {
        self.malformed_path
    }
    #[inline]
    fn name_hex(&self) -> Option<&str> {
        self.name_hex.as_deref()
    }
}
