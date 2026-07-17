// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Row conversion, sorting, and field projection for search responses.

use uffs_client::protocol::response::SearchRow;
use uffs_client::protocol::{SearchParams, SearchSortDirection, SearchSortSpec};
use uffs_core::search::backend::DisplayRow;
use uffs_core::search::field::{FieldId, SortDirection};

use super::IndexManager;

impl IndexManager {
    // ── Private helpers ─────────────────────────────────────────────

    /// Convert a [`DisplayRow`] to a protocol [`SearchRow`].
    #[expect(
        clippy::single_call_fn,
        reason = "type-conversion helper — clarity over inlining"
    )]
    pub(crate) fn display_row_to_search_row(row: &DisplayRow) -> SearchRow {
        SearchRow {
            drive: row.drive,
            path: row.path.clone(),
            name: row.name().to_owned(),
            size: row.size,
            is_directory: row.is_directory,
            modified: row.modified,
            created: row.created,
            accessed: row.accessed,
            flags: row.flags,
            allocated: row.allocated,
            descendants: row.descendants,
            treesize: row.treesize,
            tree_allocated: row.tree_allocated,
            // WI-4.4 forensic facts, computed in the hot path against the
            // lossless name bytes and carried verbatim onto the wire row.
            malformed: row.malformed,
            malformed_path: row.malformed_path,
            name_hex: row.name_hex.clone(),
            file_reference: row.file_reference,
        }
    }

    /// Normalize the effective canonical sort clauses supported by the daemon.
    #[must_use]
    pub(crate) fn resolve_applied_sorts(params: &SearchParams) -> Vec<SearchSortSpec> {
        params
            .resolved_sorts()
            .into_iter()
            .filter_map(|spec| {
                let field = FieldId::parse(&spec.field)?;
                if !field.metadata().sortable {
                    return None;
                }
                let direction = spec.direction.or_else(|| {
                    Some(
                        if matches!(
                            field.default_sort_direction(),
                            Some(SortDirection::Descending)
                        ) {
                            SearchSortDirection::Desc
                        } else {
                            SearchSortDirection::Asc
                        },
                    )
                });
                Some(SearchSortSpec {
                    field: field.canonical_name().to_owned(),
                    direction,
                })
            })
            .collect()
    }

    /// Convert a canonical sort clause to backend sorting state.
    #[must_use]
    pub(crate) fn sort_spec_to_backend(spec: &SearchSortSpec) -> Option<(FieldId, bool)> {
        let field = FieldId::parse(&spec.field)?;
        let meta = field.metadata();
        if !meta.sortable {
            return None;
        }
        // When no direction is specified, honour the field's natural default
        // (e.g. Size/TreeSize → Descending, Name → Ascending).
        let descending = spec.direction.map_or_else(
            || {
                meta.default_sort_direction
                    .is_some_and(|dir| dir == SortDirection::Descending)
            },
            |dir| dir == SearchSortDirection::Desc,
        );
        tracing::debug!(
            field_name = &*spec.field,
            field = ?field,
            spec_direction = ?spec.direction,
            descending,
            "[0] sort_spec_to_backend"
        );
        Some((field, descending))
    }

    /// Normalize the effective projection fields supported by the daemon.
    #[must_use]
    pub(crate) fn resolve_projection_fields(projection: &[String]) -> Vec<FieldId> {
        let mut resolved = Vec::new();
        for raw in projection {
            if let Some(field) = FieldId::parse(raw)
                && !resolved.contains(&field)
            {
                resolved.push(field);
            }
        }
        resolved
    }

    /// Build one projected JSON object from a `SearchRow`.
    #[must_use]
    pub(crate) fn project_search_row(
        row: &SearchRow,
        projection: &[FieldId],
    ) -> serde_json::Map<String, serde_json::Value> {
        projection
            .iter()
            .map(|&field| {
                (
                    field.canonical_name().to_owned(),
                    Self::projected_value(row, field),
                )
            })
            .collect()
    }

    /// Convert one canonical field from a `SearchRow` into JSON.
    ///
    /// Kept as a named helper (54-line match) for readability — the caller
    /// is already a nested iterator.
    #[must_use]
    #[expect(
        clippy::single_call_fn,
        reason = "54-arm match is clearer as a named helper"
    )]
    pub(crate) fn projected_value(row: &SearchRow, field: FieldId) -> serde_json::Value {
        match field {
            FieldId::Drive => serde_json::Value::String(row.drive.to_string()),
            FieldId::Path => serde_json::Value::String(row.path.clone()),
            FieldId::Name => serde_json::Value::String(row.name.clone()),
            FieldId::PathOnly => serde_json::Value::String(
                row.path
                    .rsplit_once('\\')
                    .map_or_else(String::new, |(path_only, _)| path_only.to_owned()),
            ),
            FieldId::Size => serde_json::Value::from(row.size),
            FieldId::SizeOnDisk => serde_json::Value::from(row.allocated),
            FieldId::Created => serde_json::Value::from(row.created),
            FieldId::Modified => serde_json::Value::from(row.modified),
            FieldId::Accessed => serde_json::Value::from(row.accessed),
            FieldId::Extension => {
                serde_json::Value::String(Self::search_row_extension(row).to_owned())
            }
            FieldId::Type => serde_json::Value::String(Self::search_row_type(row).to_owned()),
            FieldId::Attributes | FieldId::AttributeValue => serde_json::Value::from(row.flags),
            FieldId::Hidden => serde_json::Value::from(Self::flag_set(row.flags, "hidden")),
            FieldId::System => serde_json::Value::from(Self::flag_set(row.flags, "system")),
            FieldId::Archive => serde_json::Value::from(Self::flag_set(row.flags, "archive")),
            FieldId::ReadOnly => serde_json::Value::from(Self::flag_set(row.flags, "readonly")),
            FieldId::Compressed => serde_json::Value::from(Self::flag_set(row.flags, "compressed")),
            FieldId::Encrypted => serde_json::Value::from(Self::flag_set(row.flags, "encrypted")),
            FieldId::Sparse => serde_json::Value::from(Self::flag_set(row.flags, "sparse")),
            FieldId::Reparse => serde_json::Value::from(Self::flag_set(row.flags, "reparse")),
            FieldId::Offline => serde_json::Value::from(Self::flag_set(row.flags, "offline")),
            FieldId::NotIndexed => serde_json::Value::from(Self::flag_set(row.flags, "notindexed")),
            FieldId::Temporary => serde_json::Value::from(Self::flag_set(row.flags, "temporary")),
            FieldId::Virtual => serde_json::Value::from(Self::flag_set(row.flags, "virtual")),
            FieldId::Pinned => serde_json::Value::from(Self::flag_set(row.flags, "pinned")),
            FieldId::Unpinned => serde_json::Value::from(Self::flag_set(row.flags, "unpinned")),
            FieldId::Descendants => serde_json::Value::from(row.descendants),
            FieldId::TreeSize => serde_json::Value::from(row.treesize),
            FieldId::TreeAllocated => serde_json::Value::from(Self::search_row_tree_allocated(row)),
            FieldId::Bulkiness => serde_json::Value::from(Self::search_row_bulkiness(row)),
            FieldId::Integrity => serde_json::Value::from(Self::flag_set(row.flags, "integrity")),
            FieldId::NoScrub => serde_json::Value::from(Self::flag_set(row.flags, "noscrub")),
            FieldId::DirectoryFlag => serde_json::Value::from(row.is_directory),
            FieldId::RecallOnOpen => {
                serde_json::Value::from(row.flags & Self::FLAG_RECALL_ON_OPEN != 0)
            }
            FieldId::RecallOnDataAccess => {
                serde_json::Value::from(row.flags & Self::FLAG_RECALL_ON_DATA_ACCESS != 0)
            }
            FieldId::ParityAttributes => {
                serde_json::Value::from(row.flags & Self::PARITY_FLAG_MASK)
            }
            FieldId::NameLength => serde_json::Value::from(row.name.chars().count()),
            FieldId::PathLength => serde_json::Value::from(row.path.chars().count()),
            // ── WI-4.4 forensic fields (carried from the hot path) ──────
            FieldId::Malformed => serde_json::Value::from(row.malformed),
            FieldId::MalformedPath => serde_json::Value::from(row.malformed_path),
            FieldId::NameHex => row
                .name_hex
                .clone()
                .map_or(serde_json::Value::Null, serde_json::Value::String),
        }
    }
}
