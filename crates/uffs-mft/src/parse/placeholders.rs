// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Placeholder record creation for missing parent-directory references.

use tracing::{debug, info, warn};

use super::{ParsedRecord, StdInfoParse};
use crate::frs::{Frs, ParentFrs};
use crate::ntfs::ExtendedStandardInfo;

/// Creates a placeholder record for a missing parent directory.
///
/// This matches established behavior where the `at()` method creates
/// placeholder records for any referenced FRS that hasn't been seen yet. When a
/// file references a parent directory that wasn't parsed (e.g., marked as
/// not-in-use in bitmap but still referenced), we create a placeholder to
/// ensure path resolution can complete.
///
/// # Arguments
///
/// * `frs` - The FRS number for the placeholder record
///
/// # Returns
///
/// A `ParsedRecord` with minimal information suitable for path resolution.
#[must_use]
pub fn create_placeholder_record(frs: u64) -> ParsedRecord {
    ParsedRecord {
        frs: Frs::new(frs),
        sequence_number: 0,
        lsn: 0,
        // Synthetic placeholders default their parent to the NTFS root
        // directory so path resolution terminates cleanly.
        parent_frs: ParentFrs::ROOT,
        name: format!("<dir:{frs}>"),
        namespace: 1, // Win32 namespace
        names: Vec::new(),
        streams: Vec::new(),
        size: 0,
        allocated_size: 0,
        std_info: ExtendedStandardInfo::default(),
        in_use: true,
        is_directory: true,
        fn_created: 0,
        fn_modified: 0,
        fn_accessed: 0,
        fn_mft_changed: 0,
        reparse_tag: 0,
        // Synthetic parent placeholder: there is no MFT record behind it,
        // so there is no $SI to have parsed.
        std_info_parse: StdInfoParse::Absent,
        is_deleted: false,
        is_corrupt: false,
        is_extension: false,
        // Base records carry the documented "no base record" sentinel.
        base_frs: Frs::ZERO,
    }
}

/// Adds placeholder records for parent directories that are referenced
/// but not present in the parsed records.
///
/// This is the `Vec<ParsedRecord>` version of
/// `ParsedColumns::add_missing_parent_placeholders`.
///
/// # Performance Optimization (2026-01-23)
///
/// Uses `FxHashSet` instead of `std::collections::HashSet` for faster hashing.
/// `FxHash` is 5-10x faster than `SipHash` for integer keys.
///
/// # Arguments
///
/// * `records` - Mutable reference to the vector of parsed records
///
/// # Returns
///
/// The number of placeholder records added.
pub fn add_missing_parent_placeholders_to_vec(records: &mut Vec<ParsedRecord>) -> usize {
    /// Maximum iterations for placeholder creation to prevent infinite loops.
    const MAX_ITERATIONS: usize = 10;

    let mut total_added = 0_usize;
    let mut iterations = 0_usize;

    loop {
        iterations += 1;
        if iterations > MAX_ITERATIONS {
            warn!(
                iterations,
                "Max iterations reached in placeholder creation - possible cycle"
            );
            break;
        }

        let added_this_round = insert_missing_parents(records);
        if added_this_round == 0 {
            break;
        }
        total_added += added_this_round;
    }

    if total_added > 0 {
        info!(
            total_added,
            iterations, "Added placeholder records for missing parent directories (Vec path)"
        );
    }

    total_added
}

/// Finds parents referenced by `records` that are not yet present, inserts
/// placeholders for them, and returns how many were added (0 = converged).
fn insert_missing_parents(records: &mut Vec<ParsedRecord>) -> usize {
    use rustc_hash::FxHashSet;

    // Hash-set bookkeeping is keyed on the raw `u64` view because we need
    // to compare own-FRS values against parent-FRS values for set
    // membership, and the two newtypes are intentionally non-coercible.
    // The `.raw()` boundary is the standard down-cast for this case.
    let known_frs: FxHashSet<u64> = records.iter().map(|rec| rec.frs.raw()).collect();
    let referenced: FxHashSet<u64> = records.iter().map(|rec| rec.parent_frs.raw()).collect();

    let missing: Vec<u64> = referenced
        .difference(&known_frs)
        .filter(|&&frs| frs != 0 && frs != 5)
        .copied()
        .collect();

    if missing.is_empty() {
        return 0;
    }

    debug!(
        missing_count = missing.len(),
        "Creating placeholder records for missing parent directories (Vec path)"
    );

    let count = missing.len();
    for frs in missing {
        records.push(create_placeholder_record(frs));
    }
    count
}
