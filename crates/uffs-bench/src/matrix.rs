// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Stage 0d — drive/pattern matrix negotiation ("match the weakest tool").
//!
//! A cross-tool cell `(drive, pattern)` is only fair to time for *all* required
//! tools when *every* required tool can serve it. Everything else still runs as
//! a clearly-labelled **UFFS-only** cell (with a per-cell reason), so coverage
//! is never silently dropped. [`compute_matrix`] implements execution-plan
//! §8.4; [`render_md`] formats the negotiated matrix for the 0e plan gate and
//! the report; [`write()`] persists it to `bundle/matrix.json`.
//!
//! The only competitor that constrains drives today is Everything: it can serve
//! a drive only when its index is `loaded` *and* `hot`, and a `(drive,
//! pattern)` cell only when the estimated row count is under its IPC ceiling
//! ([`crate::preflight::ES_IPC_ROW_CEILING`]).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{BenchError, Result};
use crate::host::Host;
use crate::preflight::{
    CellFeasibility, DrivePreflight, EsStatus, PreflightResult, UFFS_BYTES_PER_RECORD,
};

/// Tool id of the Everything CLI (es.exe) competitor.
pub const EVERYTHING_TOOL: &str = "everything";
/// Tool id of the Everything GUI (Everything.exe) daemon process.
pub const EVERYTHING_GUI_TOOL: &str = "everything_gui";

/// Inputs that scope a matrix negotiation.
#[derive(Debug, Clone, Default)]
pub struct MatrixSpec {
    /// Tool ids that must all be able to serve a cell for it to be cross-tool.
    pub required_tools: Vec<String>,
    /// Drives the operator asked for, in display order.
    pub candidate_drives: Vec<char>,
    /// Pattern names to negotiate, in display order.
    pub patterns: Vec<String>,
    /// Maximum bytes Everything may use for its in-process index.
    ///
    /// Drives are added greedily (smallest UFFS record count first) until the
    /// cumulative estimated RAM would exceed this budget; any remaining drive
    /// is excluded from cross-tool cells.  `0` means no cap (unlimited).
    pub es_ram_budget_bytes: u64,
}

/// An apples-to-apples cell timed for every required tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossCell {
    /// Drive letter the cell is for.
    pub drive: char,
    /// Pattern name the cell is for.
    pub pattern: String,
}

/// A cell measured for UFFS only, with the reason competitors were excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoloCell {
    /// Drive letter the cell is for.
    pub drive: char,
    /// Pattern name the cell is for.
    pub pattern: String,
    /// Why no competitor could serve this cell (per-cell, operator-facing).
    pub reason: String,
}

/// The negotiated matrix, serialized to `bundle/matrix.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Matrix {
    /// Drives every required tool can serve, in candidate order.
    pub capable_drives: Vec<char>,
    /// Apples-to-apples cells counted in the head-to-head.
    pub cross_cells: Vec<CrossCell>,
    /// UFFS-only cells reported separately, each with a reason.
    pub uffs_only: Vec<SoloCell>,
}

/// Find a drive's preflight record by letter.
fn find_drive(drives: &[DrivePreflight], drive: char) -> Option<&DrivePreflight> {
    drives.iter().find(|state| state.drive == drive)
}

/// Find a `(drive, pattern)` feasibility cell.
fn find_cell<'a>(
    cells: &'a [CellFeasibility],
    drive: char,
    pattern: &str,
) -> Option<&'a CellFeasibility> {
    cells
        .iter()
        .find(|cell| cell.drive == drive && cell.pattern == pattern)
}

/// Greedy RAM-budget drive selector for Everything.
///
/// Accumulates candidate drives in the order the operator specified them
/// until `es_ram_budget_bytes` would be exceeded.  Whether Everything is
/// currently running does NOT gate inclusion — a drive fits if its estimated
/// RAM is within the budget.  When budget is 0 (unlimited), all candidate
/// drives are included.
fn ram_budget_capable_drives(spec: &MatrixSpec, preflight: &PreflightResult) -> Vec<char> {
    // Only consider drives that made it through preflight (known to the UFFS
    // daemon).  Drives absent from preflight.drives were dropped during capture
    // and must not reappear here.
    let known: alloc::collections::BTreeSet<char> = preflight
        .drives
        .iter()
        .map(|preflight_dp| preflight_dp.drive)
        .collect();
    if spec.es_ram_budget_bytes == 0 {
        return spec
            .candidate_drives
            .iter()
            .copied()
            .filter(|letter| known.contains(letter))
            .collect();
    }
    let mut cumulative: u64 = 0;
    let mut result = Vec::new();
    for &drive in &spec.candidate_drives {
        if !known.contains(&drive) {
            continue;
        }
        let count = find_drive(&preflight.drives, drive).map_or(0, |dp| dp.uffs_record_count);
        let est = count.saturating_mul(UFFS_BYTES_PER_RECORD);
        if cumulative.saturating_add(est) <= spec.es_ram_budget_bytes {
            cumulative = cumulative.saturating_add(est);
            result.push(drive);
        }
    }
    result
}

/// Explain why competitors are excluded from a `(drive, pattern)` cell.
///
/// Only reached when Everything is required and the cell is not cross-tool.
/// Uses the fine-grained [`EsStatus`] to surface actionable operator guidance
/// rather than a generic "not loaded" message.
fn solo_reason(preflight: &PreflightResult, drive: char, pattern: &str) -> String {
    let status = find_drive(&preflight.drives, drive)
        .map_or(&EsStatus::NotConfigured, |drive_pf| &drive_pf.es_status);
    match status {
        EsStatus::NotInstalled => format!(
            "{drive}: Everything not installed \
             — download from https://www.voidtools.com/ and re-run"
        ),
        EsStatus::DaemonNotRunning => format!(
            "{drive}: Everything not started \
             — launch Everything.exe (system tray) then re-run; \
             to limit indexed drives open Options → Indexes → NTFS"
        ),
        EsStatus::DaemonStarting => format!(
            "{drive}: Everything is starting (process running but IPC not ready) \
             — wait a moment then re-run"
        ),
        EsStatus::NotConfigured => format!(
            "{drive}: drive not in Everything's index \
             — open Everything Options → Indexes → NTFS and add {drive}:\\"
        ),
        EsStatus::StillIndexing => {
            format!("{drive}: Everything is still indexing — re-run once the tray icon settles")
        }
        EsStatus::Loaded => {
            let est = find_cell(&preflight.cells, drive, pattern).map_or(0, |cell| cell.est_rows);
            let ceiling = crate::preflight::ES_IPC_ROW_CEILING;
            format!(
                "{pattern}: es infeasible (est {est} rows > {ceiling} IPC ceiling) \
                 — consider limiting indexed drives in Everything Options → Indexes → NTFS"
            )
        }
    }
}

/// Negotiate the cross-tool vs UFFS-only matrix (execution-plan §8.4).
///
/// Only drives present in `preflight.drives` (confirmed by the UFFS daemon)
/// participate.  `capable_drives` is the RAM-budget-filtered subset of those.
/// A cell is cross-tool when its drive is capable and Everything finds it
/// feasible; otherwise it is UFFS-only with a per-cell reason.
#[must_use]
pub fn compute_matrix(spec: &MatrixSpec, preflight: &PreflightResult) -> Matrix {
    let everything_required = spec
        .required_tools
        .iter()
        .any(|tool| tool == EVERYTHING_TOOL);

    let capable_drives: Vec<char> = if everything_required {
        ram_budget_capable_drives(spec, preflight)
    } else {
        // No budget constraint: all preflight-confirmed drives, in candidate order.
        let known: alloc::collections::BTreeSet<char> = preflight
            .drives
            .iter()
            .map(|preflight_dp| preflight_dp.drive)
            .collect();
        spec.candidate_drives
            .iter()
            .copied()
            .filter(|letter| known.contains(letter))
            .collect()
    };

    let mut cross_cells = Vec::new();
    let mut uffs_only = Vec::new();
    // Iterate only drives confirmed by preflight, preserving candidate order.
    for &drive in spec
        .candidate_drives
        .iter()
        .filter(|letter| preflight.drives.iter().any(|pdp| pdp.drive == **letter))
    {
        let capable = capable_drives.contains(&drive);
        for pattern in &spec.patterns {
            let feasible = !everything_required
                || find_cell(&preflight.cells, drive, pattern).is_some_and(|cell| cell.es_feasible);
            if capable && feasible {
                cross_cells.push(CrossCell {
                    drive,
                    pattern: pattern.clone(),
                });
            } else {
                uffs_only.push(SoloCell {
                    drive,
                    pattern: pattern.clone(),
                    reason: solo_reason(preflight, drive, pattern),
                });
            }
        }
    }
    Matrix {
        capable_drives,
        cross_cells,
        uffs_only,
    }
}

/// Render the negotiated matrix as markdown for the 0e gate and the report.
///
/// A pure function of its input (no host access), so it is covered by a golden
/// test.
#[must_use]
pub fn render_md(matrix: &Matrix) -> String {
    let capable = if matrix.capable_drives.is_empty() {
        "_none_".to_owned()
    } else {
        matrix
            .capable_drives
            .iter()
            .map(char::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };

    // The negotiation OUTCOME: capable drives, how many head-to-head cells were
    // admitted (their timings live in the Cross-tool results section, so they
    // are not re-listed here), and — only when present — the cells excluded to
    // UFFS-only with their reasons. An empty exclusion list collapses to a
    // single all-clear line instead of a dangling "_none_" subsection.
    let solo = if matrix.uffs_only.is_empty() {
        "_Every negotiated cell runs cross-tool — no UFFS-only exclusions._".to_owned()
    } else {
        let cells: String = matrix
            .uffs_only
            .iter()
            .map(|cell| format!("- `{}:` {} — {}", cell.drive, cell.pattern, cell.reason))
            .collect::<Vec<_>>()
            .join("\n");
        format!("**Excluded to UFFS-only (with reasons):**\n\n{cells}")
    };

    format!(
        "## Negotiated matrix\n\n\
         - **Capable drives (all tools):** {capable}\n\
         - **Cross-tool cells:** {} — timed head-to-head in the Cross-tool results (§1)\n\
         \n{solo}\n",
        matrix.cross_cells.len()
    )
}

/// Render only the capable-drives line of the negotiated matrix.
///
/// Used before the ES launch gate where the full matrix would show only
/// misleading UFFS-only reasons ("ES not started").  The full matrix is
/// rendered after the second-pass preflight once ES is loaded.
#[must_use]
pub fn render_capable_drives(matrix: &Matrix) -> String {
    let capable = if matrix.capable_drives.is_empty() {
        "_none_".to_owned()
    } else {
        matrix
            .capable_drives
            .iter()
            .map(char::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!("## Negotiated matrix\n\n- **Capable drives (all tools):** {capable}\n")
}

/// Serialize `matrix` to `bundle_dir/matrix.json`.
///
/// # Errors
/// Returns an error if serialization fails or the file cannot be written.
pub fn write(host: &dyn Host, matrix: &Matrix, bundle_dir: &Path) -> Result<()> {
    let json = serde_json::to_vec_pretty(matrix)?;
    let path = bundle_dir.join("matrix.json");
    host.write_file(&path, &json)
        .map_err(|err| BenchError::io(&path, err))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Matrix, MatrixSpec, compute_matrix, render_md, write};
    use crate::host::{Call, MockHost};
    use crate::preflight::{CellFeasibility, DrivePreflight, EsStatus, PreflightResult};

    /// A hot, loaded, configured drive record.
    fn hot_drive(drive: char, record_count: u64) -> DrivePreflight {
        DrivePreflight {
            drive,
            configured: true,
            loaded: true,
            hot: true,
            record_count,
            uffs_record_count: record_count,
            es_status: EsStatus::Loaded,
        }
    }

    /// A feasibility cell.
    fn cell(drive: char, pattern: &str, est_rows: u64, es_feasible: bool) -> CellFeasibility {
        CellFeasibility {
            drive,
            pattern: pattern.to_owned(),
            est_rows,
            es_feasible,
        }
    }

    /// The default three-tool requirement (`uffs`, `uffs_cpp`, `everything`).
    fn three_tools() -> Vec<String> {
        vec![
            "uffs".to_owned(),
            "uffs_cpp".to_owned(),
            "everything".to_owned(),
        ]
    }

    #[test]
    fn ram_budget_gates_capable_drives_not_es_running_state() {
        // RAM budget = 0 (unlimited) → all candidate drives are capable.
        // ES running state only gates per-cell feasibility: C and D have
        // feasibility cells and are cross-tool; E/F/M/S have no cell → solo.
        let preflight = PreflightResult {
            drives: vec![hot_drive('C', 1000), hot_drive('D', 2000), DrivePreflight {
                drive: 'E',
                configured: false,
                loaded: false,
                hot: false,
                record_count: 0,
                uffs_record_count: 0,
                es_status: EsStatus::NotConfigured,
            }],
            cells: vec![
                cell('C', "all_dlls", 500, true),
                cell('D', "all_dlls", 600, true),
            ],
        };
        let spec = MatrixSpec {
            required_tools: three_tools(),
            candidate_drives: vec!['C', 'D', 'E', 'F', 'M', 'S'],
            patterns: vec!["all_dlls".to_owned()],
            es_ram_budget_bytes: 0,
        };

        let matrix = compute_matrix(&spec, &preflight);

        // Budget=0 → all preflight-confirmed candidates are capable.
        // F/M/S are in spec.candidate_drives but NOT in preflight.drives
        // (dropped during capture as unknown to daemon) → excluded.
        assert_eq!(matrix.capable_drives, vec!['C', 'D', 'E']);
        // Only C and D have feasibility cells → cross-tool.
        assert_eq!(
            matrix
                .cross_cells
                .iter()
                .map(|cell| cell.drive)
                .collect::<Vec<_>>(),
            vec!['C', 'D']
        );
        // E: confirmed but no feasibility cell → UFFS-only.
        // F/M/S: not in preflight → not emitted at all.
        let solo_drives: Vec<char> = matrix.uffs_only.iter().map(|cell| cell.drive).collect();
        assert_eq!(solo_drives, vec!['E']);
    }

    #[test]
    fn loaded_drive_over_ceiling_is_uffs_only() {
        let preflight = PreflightResult {
            drives: vec![hot_drive('C', 1000)],
            cells: vec![cell('C', "full_scan", 9_000_000, false)],
        };
        let spec = MatrixSpec {
            required_tools: three_tools(),
            candidate_drives: vec!['C'],
            patterns: vec!["full_scan".to_owned()],
            es_ram_budget_bytes: 0,
        };

        let matrix = compute_matrix(&spec, &preflight);

        assert_eq!(
            matrix.cross_cells,
            Vec::<super::CrossCell>::new(),
            "no cross cells expected"
        );
        assert_eq!(matrix.uffs_only.len(), 1);
        let reason = &matrix.uffs_only.first().expect("one solo cell").reason;
        assert!(reason.contains("es infeasible"));
        assert!(reason.contains("9000000"));
    }

    #[test]
    fn indexing_drive_is_capable_but_cell_is_uffs_only() {
        // C is budget-capable (within RAM limit) but ES is still indexing →
        // no feasibility cell → solo.  capable_drives includes C.
        let preflight = PreflightResult {
            drives: vec![DrivePreflight {
                drive: 'C',
                configured: true,
                loaded: false,
                hot: false,
                record_count: 0,
                uffs_record_count: 0,
                es_status: EsStatus::StillIndexing,
            }],
            cells: Vec::new(),
        };
        let spec = MatrixSpec {
            required_tools: three_tools(),
            candidate_drives: vec!['C'],
            patterns: vec!["all_dlls".to_owned()],
            es_ram_budget_bytes: 0,
        };

        let matrix = compute_matrix(&spec, &preflight);

        // Budget=0 → C is capable.
        assert_eq!(matrix.capable_drives, vec!['C']);
        // No feasibility cell → ES can't serve this cell → solo.
        assert!(
            matrix
                .uffs_only
                .first()
                .expect("one solo cell")
                .reason
                .contains("still indexing")
        );
    }

    #[test]
    fn without_everything_every_cell_is_cross_tool() {
        let preflight = PreflightResult {
            drives: vec![hot_drive('C', 100), hot_drive('E', 200)],
            cells: Vec::new(),
        };
        let spec = MatrixSpec {
            required_tools: vec!["uffs".to_owned(), "uffs_cpp".to_owned()],
            candidate_drives: vec!['C', 'E'],
            patterns: vec!["all_dlls".to_owned()],
            es_ram_budget_bytes: 0,
        };

        let matrix = compute_matrix(&spec, &preflight);

        assert_eq!(matrix.capable_drives, vec!['C', 'E']);
        assert_eq!(matrix.cross_cells.len(), 2);
        assert_eq!(
            matrix.uffs_only,
            Vec::<super::SoloCell>::new(),
            "no solo cells expected"
        );
    }

    #[test]
    fn render_md_lists_capable_cross_and_solo() {
        let matrix = Matrix {
            capable_drives: vec!['C', 'D'],
            cross_cells: vec![super::CrossCell {
                drive: 'C',
                pattern: "all_dlls".to_owned(),
            }],
            uffs_only: vec![super::SoloCell {
                drive: 'E',
                pattern: "all_dlls".to_owned(),
                reason: "E: es not loaded (not configured in Everything.ini)".to_owned(),
            }],
        };

        let md = render_md(&matrix);

        assert!(md.contains("**Capable drives (all tools):** C, D"));
        // Cross-tool cells are summarized by count (detailed in the §1 results),
        // not re-listed; UFFS-only exclusions keep their per-cell reason.
        assert!(md.contains("**Cross-tool cells:** 1"));
        assert!(md.contains("- `E:` all_dlls — E: es not loaded"));
        assert!(!md.contains("no UFFS-only exclusions"));
    }

    #[test]
    fn render_md_collapses_empty_exclusions_to_all_clear_line() {
        let matrix = Matrix {
            capable_drives: vec!['C'],
            cross_cells: vec![super::CrossCell {
                drive: 'C',
                pattern: "all_dlls".to_owned(),
            }],
            uffs_only: Vec::new(),
        };

        let md = render_md(&matrix);

        // No dangling "_none_" subsection — a single all-clear sentence.
        assert!(md.contains("no UFFS-only exclusions"));
        assert!(!md.contains("_none_"));
        assert!(!md.contains("Excluded to UFFS-only"));
    }

    #[test]
    fn write_emits_matrix_json_and_round_trips() {
        let host = MockHost::new();
        let matrix = Matrix {
            capable_drives: vec!['C'],
            cross_cells: Vec::new(),
            uffs_only: Vec::new(),
        };
        let dir = PathBuf::from("/bundle");

        write(&host, &matrix, &dir).expect("write matrix json");

        let path = dir.join("matrix.json");
        assert_eq!(host.calls(), vec![Call::WriteFile(path.clone())]);
        let json = host.file(&path).expect("matrix json written");
        let parsed: Matrix = serde_json::from_slice(&json).expect("valid json");
        assert_eq!(parsed, matrix);
    }
}
