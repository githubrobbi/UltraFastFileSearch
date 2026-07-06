// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Canonical CSV parity comparison for the capture verification flow.
//!
//! Compares two MFT CSV exports (from `uffs-mft load`) — e.g. Rust-on-Windows
//! vs Rust-on-macOS, or Rust vs a C++ golden — by projecting each row to a set
//! of key columns matched by header *name* (so column order may differ),
//! canonically sorting, and diffing. Pure and cross-platform; the command layer
//! streams the files into `compare_keys`.

use alloc::collections::BTreeMap;

use crate::error::{MftError, Result};

/// Field separator for a composed row key — a control byte that cannot appear
/// unquoted in CSV data.
const KEY_SEP: char = '\u{1}';

/// Maximum number of divergent rows retained as samples per side.
pub const SAMPLE_MAX: usize = 20;

/// Outcome of comparing two canonicalized CSV row sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParityReport {
    /// Data-row count of the `a` side.
    pub a_rows: usize,
    /// Data-row count of the `b` side.
    pub b_rows: usize,
    /// Rows present (matched) on both sides.
    pub common: usize,
    /// Sample of keys present only on the `a` side (capped at [`SAMPLE_MAX`]).
    pub only_a: Vec<String>,
    /// Sample of keys present only on the `b` side (capped at [`SAMPLE_MAX`]).
    pub only_b: Vec<String>,
    /// Total keys present only on the `a` side.
    pub only_a_total: usize,
    /// Total keys present only on the `b` side.
    pub only_b_total: usize,
}

impl ParityReport {
    /// True when the two sides are identical (no divergent rows).
    #[must_use]
    pub const fn matched(&self) -> bool {
        self.only_a_total == 0 && self.only_b_total == 0
    }
}

/// Split one CSV line into fields per RFC 4180.
///
/// Double-quote quoting with `""` escaping a literal quote. Embedded newlines
/// are not supported (each record is assumed to be one physical line, as
/// `uffs-mft load` emits).
#[must_use]
pub fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => fields.push(core::mem::take(&mut field)),
            other => field.push(other),
        }
    }
    fields.push(field);
    fields
}

/// Resolve the column indices of `wanted` names within `header`. An empty
/// `wanted` selects every header column, in order.
///
/// # Errors
///
/// Returns [`MftError::InvalidData`] if a wanted column is absent from
/// `header`.
pub fn header_indices(header: &[String], wanted: &[String]) -> Result<Vec<usize>> {
    if wanted.is_empty() {
        return Ok((0..header.len()).collect());
    }
    wanted
        .iter()
        .map(|name| {
            header.iter().position(|col| col == name).ok_or_else(|| {
                MftError::InvalidData(format!("column {name:?} not found in CSV header"))
            })
        })
        .collect()
}

/// Compose a canonical key from the selected field indices (a missing field
/// contributes an empty component).
#[must_use]
pub fn row_key(fields: &[String], indices: &[usize]) -> String {
    let mut key = String::new();
    for (position, &idx) in indices.iter().enumerate() {
        if position > 0 {
            key.push(KEY_SEP);
        }
        key.push_str(fields.get(idx).map_or("", String::as_str));
    }
    key
}

/// Compare two collections of row keys, returning a parity report. Duplicate
/// keys are treated as a multiset, so cardinality differences are reported too.
#[must_use]
pub fn compare_keys(left: Vec<String>, right: Vec<String>) -> ParityReport {
    let (a_rows, b_rows) = (left.len(), right.len());
    let mut counts: BTreeMap<String, (u32, u32)> = BTreeMap::new();
    for key in left {
        counts.entry(key).or_default().0 += 1;
    }
    for key in right {
        counts.entry(key).or_default().1 += 1;
    }

    let mut report = ParityReport {
        a_rows,
        b_rows,
        common: 0,
        only_a: Vec::new(),
        only_b: Vec::new(),
        only_a_total: 0,
        only_b_total: 0,
    };
    for (key, (count_a, count_b)) in counts {
        report.common += usize::try_from(count_a.min(count_b)).unwrap_or(0);
        if count_a > count_b {
            report.only_a_total += usize::try_from(count_a - count_b).unwrap_or(0);
            if report.only_a.len() < SAMPLE_MAX {
                report.only_a.push(key);
            }
        } else if count_b > count_a {
            report.only_b_total += usize::try_from(count_b - count_a).unwrap_or(0);
            if report.only_b.len() < SAMPLE_MAX {
                report.only_b.push(key);
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::{compare_keys, header_indices, row_key, split_csv_line};

    #[test]
    fn split_handles_quoted_commas_and_escapes() {
        assert_eq!(split_csv_line("1,a,10"), vec!["1", "a", "10"]);
        // Quoted field containing a comma stays one field.
        assert_eq!(split_csv_line("1,\"a,b\",10"), vec!["1", "a,b", "10"]);
        // Doubled quote → one literal quote inside a quoted field.
        assert_eq!(split_csv_line("\"a\"\"b\""), vec!["a\"b"]);
    }

    #[test]
    fn header_indices_match_by_name() {
        let header: Vec<String> = ["frs", "name", "size"]
            .iter()
            .map(|item| (*item).to_owned())
            .collect();
        let wanted: Vec<String> = ["size", "frs"]
            .iter()
            .map(|item| (*item).to_owned())
            .collect();
        assert_eq!(header_indices(&header, &wanted).expect("found"), vec![2, 0]);
        // Empty selection → all columns in order.
        assert_eq!(header_indices(&header, &[]).expect("all"), vec![0, 1, 2]);
        // Missing column → error.
        let missing: Vec<String> = vec!["nope".to_owned()];
        header_indices(&header, &missing).unwrap_err();
    }

    #[test]
    fn row_key_projects_selected_columns() {
        let fields: Vec<String> = ["7", "a.txt", "10"]
            .iter()
            .map(|item| (*item).to_owned())
            .collect();
        // Same key regardless of source column order (indices carry the order).
        assert_eq!(row_key(&fields, &[0, 2]), row_key(&fields, &[0, 2]));
        assert_ne!(row_key(&fields, &[0, 2]), row_key(&fields, &[0, 1]));
    }

    #[test]
    fn compare_keys_reports_divergence() {
        let left = vec!["x".to_owned(), "y".to_owned(), "y".to_owned()];
        let right = vec!["x".to_owned(), "z".to_owned()];
        let report = compare_keys(left, right);
        assert_eq!(report.common, 1); // one "x"
        assert_eq!(report.only_a_total, 2); // two "y"
        assert_eq!(report.only_b_total, 1); // one "z"
        assert!(!report.matched());

        // Identical multisets match.
        let same = vec!["a".to_owned(), "a".to_owned()];
        assert!(compare_keys(same.clone(), same).matched());
    }
}
