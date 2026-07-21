// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Cross-platform NTFS MFT record parsing.
//!
//! This module provides parsing functions for NTFS MFT records that work on
//! any platform. The functions operate on raw byte buffers and don't require
//! Windows APIs.
//!
//! # Key Functions
//!
//! - `apply_fixup()` - Applies multi-sector fixup (Update Sequence Array)
//! - `parse_record()` - Parses a single MFT record
//! - `parse_record_full()` - Parses with extension record support
//! - `parse_record_zero_alloc()` - Zero-allocation parsing using thread-local
//!   buffer
//!
//! # Platform Support

// Low-level NTFS parsing uses manual indexing with bounds verified by:
// 1. Size checks before ptr::read operations
// 2. Range bounds validated against data.len()
// 3. Loop conditions that terminate before overflow
// Performance-critical hot path - 40+ call sites
#![expect(
    clippy::indexing_slicing,
    reason = "NTFS parser hot path; bounds manually verified before all index access"
)]
#![expect(
    clippy::min_ident_chars,
    reason = "'s' for stream is idiomatic in closures"
)]
#![expect(
    clippy::assigning_clones,
    reason = "clone() is clearer than clone_from() here"
)]
//! All functions in this module are cross-platform and can be used to parse
//! saved MFT files on macOS, Linux, or Windows.

mod attribute_helpers;
mod columns;
mod direct_index;
mod direct_index_extension;
#[cfg(test)]
mod direct_index_extension_tests;
mod fixup;
mod forensic;
mod full;
pub(crate) mod index_helpers;
mod merger;
mod name_tracker;
mod placeholders;
#[cfg(test)]
mod tests;
mod types;
mod zero_alloc;

// Re-exported crate-wide: `crate::io::parser::unified` (outside this module
// tree) calls this directly to share the one extended-aware
// $STANDARD_INFORMATION parser with the legacy and direct-index pipelines,
// instead of duplicating it.
pub use attribute_helpers::StdInfoParse;
pub(crate) use attribute_helpers::parse_standard_info_full;
use attribute_helpers::{parse_data_attribute_full, parse_file_name_full};
pub use columns::ParsedColumns;
pub use direct_index::parse_record_to_index;
pub use fixup::apply_fixup;
pub use forensic::parse_record_forensic;
pub use full::{parse_record, parse_record_full};
pub use merger::MftRecordMerger;
use name_tracker::PrimaryNameTracker;
pub use placeholders::{add_missing_parent_placeholders_to_vec, create_placeholder_record};
pub use types::{ExtensionAttributes, ParseOptions, ParseResult, ParsedRecord};
pub use zero_alloc::{parse_record_zero_alloc, parse_record_zero_alloc_forensic};
