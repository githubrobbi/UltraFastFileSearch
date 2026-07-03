// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! The 15 manifest invariants from
//! `docs/dev/architecture/code_clean/phase_1_manifest_implementation_plan.md`
//! §3, encoded as machine-checkable assertions.
//!
//! Each public function in this module corresponds to one or more
//! invariants and returns a `Vec<Finding>` (empty on success).  The
//! top-level [`audit_all`] entry point calls every check and
//! concatenates the results — exit code is derived from
//! `result.is_empty()`.
//!
//! # Design rationale
//!
//! * Findings are **plain text** (no JSON, no enum taxonomy) because the audit
//!   only fires at PR time and a human is always the next reader.
//! * The invariants are **deliberately conservative**: the audit prefers false
//!   negatives (missing a real drift) over false positives (failing on
//!   intentional exceptions).  The hardcoded exception list in
//!   [`KnownExceptions`] documents every accepted deviation with an in-code
//!   citation.

use alloc::collections::BTreeSet;

use crate::manifest::{MemberManifest, RootManifest, is_workspace_inherited};

/// Single audit finding.  Self-contained diagnostic; the CI log
/// alone tells the contributor what to fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finding {
    /// Phase 1 invariant number (e.g. `"3.7"`).
    pub(crate) invariant: &'static str,
    /// Member crate id (e.g. `"uffs-core"`) for member-scoped findings,
    /// or `"<root>"` for root-scoped ones.
    pub(crate) member: String,
    /// One-line diagnostic.
    pub(crate) detail: String,
}

impl core::fmt::Display for Finding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{}] {}: {}", self.invariant, self.member, self.detail)
    }
}

/// Hardcoded set of intentional manifest deviations.  Update this
/// whenever a new exception lands — the audit fires on every new
/// deviation by default, forcing the contributor to either fix the
/// manifest or extend this list with a citation.
struct KnownExceptions {
    /// Members allowed to set `publish = true` explicitly (not via
    /// workspace inheritance).  Source: `release-automation-baseline.md`
    /// §10 deviation row 5.
    publish_explicit: BTreeSet<&'static str>,
    /// Members allowed underscore-style `[[bin]] name = ...` (vs. the
    /// hyphen convention).  Source: uffs-gen-workflow comment in
    /// `scripts/ci/uffs-gen-workflow/src/main.rs`.
    underscore_bin_ok: BTreeSet<&'static str>,
    /// `(member, dep_name)` pairs allowed to bypass workspace
    /// inheritance.  Documented in Phase 1 §3.6.
    nonworkspace_dep_ok: BTreeSet<(&'static str, &'static str)>,
    /// Members allowed to set `readme = "README.md"` directly (not via
    /// workspace inheritance).  This is the implementation of the
    /// "deliberately overridden value with a justification comment"
    /// escape hatch documented in Phase 1 §3.5 — publishable library
    /// crates that ship their own per-crate `README.md` need to point
    /// crates.io / docs.rs at that file rather than at the workspace-
    /// root app-focused README that gets inherited.  The override is
    /// tightened to the literal value `"README.md"` (same-name pattern,
    /// alongside the crate's `Cargo.toml`) so an exception listed crate
    /// can't accidentally point at an arbitrary path.
    readme_override_ok: BTreeSet<&'static str>,
    /// Members allowed to set `keywords = [...]` directly (not via
    /// workspace inheritance).  Same Phase 1 §3.5 "deliberately
    /// overridden with justification" escape hatch as `readme`.
    /// Publishable library crates benefit from per-crate keywords
    /// tailored to their specific domain (e.g. `uffs-time` is a
    /// generic NTFS FILETIME helper that wants `["ntfs", "filetime",
    /// "datetime", ...]` rather than the workspace-app defaults
    /// `["mft", "ntfs", "file-search", "windows", "polars"]` which
    /// describe the *application*, not the library).  The override
    /// is required to be a **non-empty TOML array** — an empty array
    /// still fires (cargo treats `keywords = []` as legal but it
    /// defeats the discoverability purpose of an override).  Per-
    /// keyword shape (max 5, max 20 chars, `^[a-zA-Z][a-zA-Z0-9_-]*$`)
    /// is *not* re-validated here because `cargo publish --dry-run`
    /// in the weekly `crates-io-dry-run.yml` workflow enforces it
    /// authoritatively against crates.io's own validator.
    keywords_override_ok: BTreeSet<&'static str>,
    /// Members allowed to set `categories = [...]` directly (not via
    /// workspace inheritance).  Same rationale as `keywords_override_ok`
    /// — publishable library crates want category slugs that match
    /// their library role (e.g. `uffs-time` → `["date-and-time"]`)
    /// rather than the workspace-app defaults (`["filesystem",
    /// "command-line-utilities"]`).  Same non-empty-array requirement.
    /// Slug validity (must be on `https://crates.io/category_slugs`)
    /// is enforced authoritatively by `cargo publish --dry-run`.
    categories_override_ok: BTreeSet<&'static str>,
}

impl KnownExceptions {
    /// Build the hardcoded exception set.  Update this list whenever a
    /// new intentional deviation lands (with an in-code citation) — the
    /// audit fires on every new deviation by default.
    fn new() -> Self {
        let publish_explicit: BTreeSet<&'static str> = [
            "uffs-broker",
            "uffs-broker-protocol",
            "uffs-security",
            "uffs-text",
            "uffs-time",
        ]
        .into_iter()
        .collect();

        let underscore_bin_ok: BTreeSet<&'static str> = core::iter::once("uffs-diag").collect();

        // uffs-cli is publishable (`release-automation-baseline.md` §10
        // row 5).  Its `uffs-client` and `uffs-format` path deps pin
        // a snapshotted older version (`0.5.90`) than the current
        // workspace version so `cargo package` semver-validation
        // continues to succeed against the published baseline.
        // Workspace inheritance would force the live version pin,
        // breaking publish.  Documented in `crates/uffs-cli/Cargo.toml`
        // lines 54-71 (uffs-client) and 67-72 (uffs-format).
        //
        // uffs-cli's `uffs-client` also uses `default-features = false`
        // to drop tokio + ws2_32.dll from the CLI binary — workspace
        // inheritance cannot override `default-features` either.
        //
        // uffs-polars is the single canonical consumer of the `polars`
        // crate (every other workspace member goes through it as a
        // facade), and pins a specific git rev + feature set in its
        // own manifest.  Adding `polars` to `[workspace.dependencies]`
        // would either lock every facade-consumer to the same feature
        // set or require per-consumer feature overrides — strictly
        // worse than the current single-source-of-truth pin.
        // Documented in `crates/uffs-polars/Cargo.toml:92+`.
        //
        // uffs-daemon pins `libmimalloc-sys` with the `extended`
        // feature (workspace dep would force the feature on every
        // consumer).  Documented in Phase 1 §3.6.
        let nonworkspace_dep_ok: BTreeSet<(&'static str, &'static str)> = [
            ("uffs-cli", "uffs-client"),
            ("uffs-cli", "uffs-format"),
            ("uffs-polars", "polars"),
            ("uffs-daemon", "libmimalloc-sys"),
        ]
        .into_iter()
        .collect();

        // Per-crate `readme = "README.md"` override allow-list.  Each
        // listed crate ships its own library-focused `README.md` that
        // is the right artifact for crates.io / docs.rs to surface
        // (instead of the inherited workspace-root app README).
        // Adding an entry here requires the crate to actually have a
        // `README.md` alongside its `Cargo.toml` — cargo will emit a
        // packaging error otherwise.
        //
        // All 6 crates of the publishable subset carry their own
        // `README.md` (#237 + #239) and the explicit override silences
        // the cosmetic `cargo package` warning about `../../README.md`
        // being outside the package — see issue #240.
        let readme_override_ok: BTreeSet<&'static str> = [
            "uffs-cli",
            "uffs-client",
            "uffs-mcp",
            "uffs-mft",
            "uffs-text",
            "uffs-time",
        ]
        .into_iter()
        .collect();

        // Per-crate `keywords` + `categories` override allow-list.
        // The four library crates listed below ship a public surface
        // distinct enough from the workspace-app role that
        // discoverability on crates.io demands tailored metadata —
        // see issue #241 (publish-readiness umbrella) and the per-
        // crate `Cargo.toml` `keywords =` / `categories =` lines for
        // the concrete choices.  Crates NOT listed here (`uffs-mft`,
        // `uffs-cli`) inherit the workspace defaults because their
        // role aligns 1:1 with the app's role (`uffs-mft` ships the
        // app's MFT reader; `uffs-cli` IS the app's CLI).
        let keywords_override_ok: BTreeSet<&'static str> =
            ["uffs-client", "uffs-mcp", "uffs-text", "uffs-time"]
                .into_iter()
                .collect();
        let categories_override_ok: BTreeSet<&'static str> =
            ["uffs-client", "uffs-mcp", "uffs-text", "uffs-time"]
                .into_iter()
                .collect();

        Self {
            publish_explicit,
            underscore_bin_ok,
            nonworkspace_dep_ok,
            readme_override_ok,
            keywords_override_ok,
            categories_override_ok,
        }
    }
}

/// One discovered member: path + parsed manifest + raw source text.
pub(crate) struct DiscoveredMember<'a> {
    /// Workspace-relative path (e.g. `"crates/uffs-core/Cargo.toml"`).
    pub(crate) manifest_path: &'a str,
    /// Parsed shape.
    pub(crate) manifest: &'a MemberManifest,
}

/// Run every audit invariant and concatenate findings.  An empty
/// return value means the audit passed.
pub(crate) fn audit_all(
    root: &RootManifest,
    root_text: &str,
    members: &[DiscoveredMember<'_>],
    discovered_paths: &BTreeSet<String>,
) -> Vec<Finding> {
    let exc = KnownExceptions::new();
    let mut findings = Vec::new();

    findings.extend(audit_member_list_accuracy(root, discovered_paths));
    findings.extend(audit_root_is_virtual(root));
    findings.extend(audit_resolver_pinned(root));
    findings.extend(audit_default_members_intent(root_text));

    for member in members {
        let id = member_id_from_path(member.manifest_path);
        findings.extend(audit_no_path_dep_outside_workspace(member, &id, root));
        findings.extend(check_inherited(
            member.manifest.package.edition.as_ref(),
            "edition",
            "3.3",
            &id,
        ));
        // Invariant 3.4 (`rust-version` consistency) was retired on 2026-05-18
        // when the workspace dropped its `[workspace.package].rust-version`
        // claim (refs issue #267 — the polars/nightly transitive feature
        // makes any stable MSRV claim unverifiable).  Per-crate manifests no
        // longer carry `rust-version.workspace = true`.
        findings.extend(audit_metadata_fields(member, &id, &exc));
        findings.extend(audit_deps_inherit_workspace(member, &id, &exc));
        findings.extend(audit_lints_inherit_workspace(member, &id));
        findings.extend(audit_no_workspace_policy_blocks(member, &id));
        findings.extend(audit_lib_bin_name_convention(member, &id, &exc));
        findings.extend(audit_publish_partition(member, &id, &exc));
        findings.extend(audit_docs_rs_metadata_present(member, &id));
    }

    findings
}

/// `"crates/uffs-core/Cargo.toml"` → `"uffs-core"`.
fn member_id_from_path(path: &str) -> String {
    path.rsplit_once('/')
        .and_then(|(parent, _)| parent.rsplit_once('/').map(|(_, last)| last))
        .unwrap_or(path)
        .to_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// Root-scoped invariants
// ─────────────────────────────────────────────────────────────────────────────

/// **Invariant 3.1**: declared `[workspace.members]` matches the
/// set of discovered `Cargo.toml` files exactly.
fn audit_member_list_accuracy(root: &RootManifest, discovered: &BTreeSet<String>) -> Vec<Finding> {
    let Some(ws) = root.workspace.as_ref() else {
        return vec![Finding {
            invariant: "3.1",
            member: "<root>".to_owned(),
            detail: "root Cargo.toml has no [workspace] table".to_owned(),
        }];
    };
    let declared: BTreeSet<&str> = ws.members.iter().map(String::as_str).collect();
    let discovered_set: BTreeSet<&str> = discovered.iter().map(String::as_str).collect();
    let mut findings = Vec::new();
    for missing in discovered_set.difference(&declared) {
        findings.push(Finding {
            invariant: "3.1",
            member: "<root>".to_owned(),
            detail: format!("discovered `{missing}/Cargo.toml` but not in [workspace.members]"),
        });
    }
    for extra in declared.difference(&discovered_set) {
        findings.push(Finding {
            invariant: "3.1",
            member: "<root>".to_owned(),
            detail: format!("[workspace.members] lists `{extra}` but no Cargo.toml exists there"),
        });
    }
    findings
}

/// **Invariant 3.9**: root `Cargo.toml` is a virtual workspace.
fn audit_root_is_virtual(root: &RootManifest) -> Vec<Finding> {
    if root.package.is_some() {
        vec![Finding {
            invariant: "3.9",
            member: "<root>".to_owned(),
            detail: "root Cargo.toml has a [package] block; UFFS uses a virtual workspace"
                .to_owned(),
        }]
    } else {
        Vec::new()
    }
}

/// **Invariant 3.10**: `resolver = "3"` (ed-2024 default).
fn audit_resolver_pinned(root: &RootManifest) -> Vec<Finding> {
    let Some(ws) = root.workspace.as_ref() else {
        return Vec::new();
    };
    match ws.resolver.as_deref() {
        Some("3") => Vec::new(),
        Some(other) => vec![Finding {
            invariant: "3.10",
            member: "<root>".to_owned(),
            detail: format!("[workspace].resolver = {other:?}; UFFS requires \"3\""),
        }],
        None => vec![Finding {
            invariant: "3.10",
            member: "<root>".to_owned(),
            detail: "[workspace].resolver is unset; UFFS requires \"3\"".to_owned(),
        }],
    }
}

/// **Invariant 3.11**: `default-members` is set or the all-members
/// fallback is documented in a nearby comment.
fn audit_default_members_intent(root_text: &str) -> Vec<Finding> {
    if root_text.contains("default-members") {
        return Vec::new();
    }
    // Look for a comment mentioning default-members as a deliberate choice.
    if root_text.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with('#') && trimmed.to_ascii_lowercase().contains("default-members")
    }) {
        return Vec::new();
    }
    vec![Finding {
        invariant: "3.11",
        member: "<root>".to_owned(),
        detail: "root [workspace] neither sets `default-members` nor documents the all-members \
                 fallback in a comment"
            .to_owned(),
    }]
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-member invariants
// ─────────────────────────────────────────────────────────────────────────────

/// **Invariant 3.2**: no `path = "..."` dep points outside the
/// declared `[workspace.members]`.
fn audit_no_path_dep_outside_workspace(
    member: &DiscoveredMember<'_>,
    id: &str,
    root: &RootManifest,
) -> Vec<Finding> {
    let Some(ws) = root.workspace.as_ref() else {
        return Vec::new();
    };
    let allowed: BTreeSet<&str> = ws.members.iter().map(String::as_str).collect();
    let mut findings = Vec::new();
    for (dep_name, dep_value) in &member.manifest.dependencies {
        let Some(table) = dep_value.as_table() else {
            continue;
        };
        let Some(path_str) = table.get("path").and_then(toml::Value::as_str) else {
            continue;
        };
        let resolved = normalise_path_dep(member.manifest_path, path_str);
        if !allowed.contains(resolved.as_str()) {
            findings.push(Finding {
                invariant: "3.2",
                member: id.to_owned(),
                detail: format!(
                    "dep `{dep_name}` uses `path = {path_str:?}` resolving to `{resolved}` — \
                     not in [workspace.members]"
                ),
            });
        }
    }
    findings
}

/// Resolve `../sibling`-style member-relative path against the
/// member's directory.  Returns the path relative to the workspace
/// root (e.g. `"crates/uffs-client"`).
fn normalise_path_dep(member_manifest_path: &str, dep_path: &str) -> String {
    let member_dir = member_manifest_path
        .rsplit_once('/')
        .map_or(member_manifest_path, |(parent, _)| parent);
    let mut components: Vec<&str> = member_dir.split('/').collect();
    for segment in dep_path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            other => components.push(other),
        }
    }
    components.join("/")
}

/// Shared 3.3 / 3.5 helper.  (Invariant 3.4 — `rust-version` consistency —
/// was retired on 2026-05-18; see `audit_all` for the citation.)
fn check_inherited(
    value: Option<&toml::Value>,
    field_name: &str,
    invariant: &'static str,
    id: &str,
) -> Vec<Finding> {
    let Some(inner) = value else {
        return Vec::new();
    };
    if is_workspace_inherited(inner) {
        return Vec::new();
    }
    vec![Finding {
        invariant,
        member: id.to_owned(),
        detail: format!(
            "`{field_name}` is overridden per-crate; should be `{field_name}.workspace = true`"
        ),
    }]
}

/// **Invariant 3.5**: every fingerprint metadata field except
/// `description` must inherit from workspace, with three narrowly
/// scoped exceptions:
///
/// * `readme` — see [`KnownExceptions::readme_override_ok`].
/// * `keywords` — see [`KnownExceptions::keywords_override_ok`].
/// * `categories` — see [`KnownExceptions::categories_override_ok`].
///
/// All three exceptions implement the same Phase 1 §3.5 "deliberately
/// overridden with justification" escape hatch for publishable
/// library crates whose role is distinct from the workspace-app role.
fn audit_metadata_fields(
    member: &DiscoveredMember<'_>,
    id: &str,
    exc: &KnownExceptions,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (name, value) in [
        ("version", member.manifest.package.version.as_ref()),
        ("license", member.manifest.package.license.as_ref()),
        ("authors", member.manifest.package.authors.as_ref()),
        ("repository", member.manifest.package.repository.as_ref()),
        ("readme", member.manifest.package.readme.as_ref()),
        ("keywords", member.manifest.package.keywords.as_ref()),
        ("categories", member.manifest.package.categories.as_ref()),
        (
            "documentation",
            member.manifest.package.documentation.as_ref(),
        ),
    ] {
        // `readme` override: tightened to the literal `"README.md"`
        // same-name pattern so a listed crate can't accidentally
        // point at an arbitrary path.  Any other override pattern
        // still fires a finding even for listed crates.
        if name == "readme"
            && exc.readme_override_ok.contains(id)
            && value.and_then(toml::Value::as_str) == Some("README.md")
        {
            continue;
        }
        // `keywords` / `categories` overrides: tightened to non-empty
        // TOML arrays.  An empty array still fires (defeats the
        // discoverability purpose of overriding).  Per-keyword shape
        // (max 5, max 20 chars, regex) and per-category slug-set
        // validity are enforced authoritatively by `cargo publish
        // --dry-run` in the weekly `crates-io-dry-run.yml` workflow —
        // re-implementing them here would duplicate the source of
        // truth and risk drifting from crates.io's validator.
        if (name == "keywords" && exc.keywords_override_ok.contains(id)
            || name == "categories" && exc.categories_override_ok.contains(id))
            && is_non_empty_array(value)
        {
            continue;
        }
        findings.extend(check_inherited(value, name, "3.5", id));
    }
    findings
}

/// True when `value` is a non-empty TOML array.  Used by the
/// `keywords` / `categories` override allow-list to ensure listed
/// crates can't accidentally set `keywords = []` (which would defeat
/// the override's discoverability purpose).
fn is_non_empty_array(value: Option<&toml::Value>) -> bool {
    value
        .and_then(toml::Value::as_array)
        .is_some_and(|array| !array.is_empty())
}

/// **Invariant 3.6**: every dep should use workspace inheritance,
/// modulo the documented exception list.
fn audit_deps_inherit_workspace(
    member: &DiscoveredMember<'_>,
    id: &str,
    exc: &KnownExceptions,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (dep_name, dep_value) in &member.manifest.dependencies {
        if dep_inherits_workspace(dep_value) {
            continue;
        }
        if exc.nonworkspace_dep_ok.contains(&(id, dep_name.as_str())) {
            continue;
        }
        findings.push(Finding {
            invariant: "3.6",
            member: id.to_owned(),
            detail: format!(
                "dep `{dep_name}` is not workspace-inherited and not in the documented \
                 exception list; declare it via `{dep_name}.workspace = true` and add the \
                 corresponding entry under `[workspace.dependencies]` in root Cargo.toml"
            ),
        });
    }
    findings
}

/// `dep.workspace = true` or `dep = { workspace = true, ... }`?
fn dep_inherits_workspace(value: &toml::Value) -> bool {
    let Some(table) = value.as_table() else {
        return false;
    };
    matches!(table.get("workspace"), Some(toml::Value::Boolean(true)))
}

/// **Invariant 3.7**: every member has `[lints] workspace = true`.
fn audit_lints_inherit_workspace(member: &DiscoveredMember<'_>, id: &str) -> Vec<Finding> {
    let Some(lints) = member.manifest.lints.as_ref() else {
        return vec![Finding {
            invariant: "3.7",
            member: id.to_owned(),
            detail: "no [lints] block; should be `[lints] workspace = true`".to_owned(),
        }];
    };
    match lints.get("workspace") {
        Some(toml::Value::Boolean(true)) => Vec::new(),
        _ => vec![Finding {
            invariant: "3.7",
            member: id.to_owned(),
            detail: "[lints] block does not set `workspace = true`".to_owned(),
        }],
    }
}

/// **Invariant 3.8**: members must not declare workspace-policy
/// blocks (`[profile.*]`, `[patch.*]`, `[workspace.*]`).
fn audit_no_workspace_policy_blocks(member: &DiscoveredMember<'_>, id: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    if member.manifest.profile.is_some() {
        findings.push(Finding {
            invariant: "3.8",
            member: id.to_owned(),
            detail: "member declares `[profile.*]`; profile policy lives at the workspace root"
                .to_owned(),
        });
    }
    if member.manifest.patch.is_some() {
        findings.push(Finding {
            invariant: "3.8",
            member: id.to_owned(),
            detail: "member declares `[patch.*]`; patch policy lives at the workspace root"
                .to_owned(),
        });
    }
    if member.manifest.workspace.is_some() {
        findings.push(Finding {
            invariant: "3.8",
            member: id.to_owned(),
            detail: "member declares `[workspace]`; only root may declare `[workspace]`".to_owned(),
        });
    }
    findings
}

/// **Invariant 3.13**: lib name uses `_`, bin name uses `-` (with
/// the documented `uffs-diag` exception).
fn audit_lib_bin_name_convention(
    member: &DiscoveredMember<'_>,
    id: &str,
    exc: &KnownExceptions,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(lib) = member.manifest.lib.as_ref()
        && let Some(name) = lib.name.as_deref()
        && name.contains('-')
    {
        findings.push(Finding {
            invariant: "3.13",
            member: id.to_owned(),
            detail: format!("`[lib].name = {name:?}` contains `-`; use underscores"),
        });
    }
    for bin in &member.manifest.bin {
        let Some(name) = bin.name.as_deref() else {
            continue;
        };
        if name.contains('_') && !exc.underscore_bin_ok.contains(id) {
            findings.push(Finding {
                invariant: "3.13",
                member: id.to_owned(),
                detail: format!(
                    "`[[bin]].name = {name:?}` contains `_`; bin names use hyphens.  If this \
                     is intentional, add `{id}` to `KnownExceptions::underscore_bin_ok` with a \
                     citation."
                ),
            });
        }
    }
    findings
}

/// **Invariant 3.14**: `publish` is `publish.workspace = true` for
/// most members, or explicit `publish = true` for the documented
/// publishable-set.
fn audit_publish_partition(
    member: &DiscoveredMember<'_>,
    id: &str,
    exc: &KnownExceptions,
) -> Vec<Finding> {
    let Some(publish) = member.manifest.package.publish.as_ref() else {
        return vec![Finding {
            invariant: "3.14",
            member: id.to_owned(),
            detail: "`publish` field is absent; must be `publish.workspace = true` or explicit \
                     `publish = true` for the documented publishable-set"
                .to_owned(),
        }];
    };
    if is_workspace_inherited(publish) {
        return Vec::new();
    }
    if matches!(publish, toml::Value::Boolean(true)) && exc.publish_explicit.contains(id) {
        return Vec::new();
    }
    if matches!(publish, toml::Value::Boolean(false)) {
        return vec![Finding {
            invariant: "3.14",
            member: id.to_owned(),
            detail: "`publish = false` is redundant with workspace default; should be \
                     `publish.workspace = true`"
                .to_owned(),
        }];
    }
    vec![Finding {
        invariant: "3.14",
        member: id.to_owned(),
        detail: format!(
            "`publish` is overridden per-crate ({publish:?}) but `{id}` is not in the \
             documented publishable-set; see `release-automation-baseline.md` §10 row 5"
        ),
    }]
}

/// **Invariant 3.15**: every member has a `[package.metadata.docs.rs]`
/// block.
fn audit_docs_rs_metadata_present(member: &DiscoveredMember<'_>, id: &str) -> Vec<Finding> {
    if let Some(metadata) = member.manifest.package.metadata.as_ref()
        && metadata
            .get("docs")
            .and_then(|docs| docs.get("rs"))
            .is_some()
    {
        return Vec::new();
    }
    vec![Finding {
        invariant: "3.15",
        member: id.to_owned(),
        detail: "no `[package.metadata.docs.rs]` block; Phase R6 requires uniform docs.rs \
                 metadata across every member"
            .to_owned(),
    }]
}

#[cfg(test)]
#[expect(
    clippy::min_ident_chars,
    clippy::indexing_slicing,
    reason = "test code uses idiomatic short bindings + positional indexing against fixed-shape \
              fixtures; failures panic with adequate context (issue #212)"
)]
mod tests {
    use super::*;
    use crate::manifest::parse_member;

    const MEMBER_CLEAN: &str = r#"
[package]
name = "uffs-core"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true
readme.workspace = true
keywords.workspace = true
categories.workspace = true
documentation.workspace = true
publish.workspace = true
description = "per-crate description"

[package.metadata.docs.rs]
all-features = true

[dependencies]
anyhow = { workspace = true }
serde.workspace = true

[lints]
workspace = true
"#;

    fn disc<'a>(path: &'a str, m: &'a MemberManifest) -> DiscoveredMember<'a> {
        DiscoveredMember {
            manifest_path: path,
            manifest: m,
        }
    }

    #[test]
    fn clean_member_passes_every_per_member_check() {
        let m = parse_member(MEMBER_CLEAN).unwrap();
        let d = disc("crates/uffs-core/Cargo.toml", &m);
        let exc = KnownExceptions::new();
        assert!(audit_metadata_fields(&d, "uffs-core", &exc).is_empty());
        assert!(audit_deps_inherit_workspace(&d, "uffs-core", &exc).is_empty());
        assert!(audit_lints_inherit_workspace(&d, "uffs-core").is_empty());
        assert!(audit_no_workspace_policy_blocks(&d, "uffs-core").is_empty());
        assert!(audit_publish_partition(&d, "uffs-core", &exc).is_empty());
        assert!(audit_docs_rs_metadata_present(&d, "uffs-core").is_empty());
    }

    #[test]
    fn missing_lints_block_fires_3_7() {
        let text = MEMBER_CLEAN.replace("[lints]\nworkspace = true\n", "");
        let m = parse_member(&text).unwrap();
        let d = disc("crates/uffs-core/Cargo.toml", &m);
        let findings = audit_lints_inherit_workspace(&d, "uffs-core");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].invariant, "3.7");
    }

    #[test]
    fn edition_override_fires_3_3() {
        let text = MEMBER_CLEAN.replace("edition.workspace = true", "edition = \"2024\"");
        let m = parse_member(&text).unwrap();
        let d = disc("crates/uffs-core/Cargo.toml", &m);
        let findings = check_inherited(
            d.manifest.package.edition.as_ref(),
            "edition",
            "3.3",
            "uffs-core",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].invariant, "3.3");
    }

    #[test]
    fn profile_block_fires_3_8() {
        let text = format!("{MEMBER_CLEAN}\n[profile.release]\nopt-level = 3\n");
        let m = parse_member(&text).unwrap();
        let d = disc("crates/uffs-core/Cargo.toml", &m);
        let findings = audit_no_workspace_policy_blocks(&d, "uffs-core");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].invariant, "3.8");
    }

    #[test]
    fn non_workspace_dep_fires_3_6() {
        let text = MEMBER_CLEAN.replace("anyhow = { workspace = true }", r#"anyhow = "1.0.0""#);
        let m = parse_member(&text).unwrap();
        let d = disc("crates/uffs-core/Cargo.toml", &m);
        let exc = KnownExceptions::new();
        let findings = audit_deps_inherit_workspace(&d, "uffs-core", &exc);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].invariant, "3.6");
    }

    #[test]
    fn known_exception_suppresses_3_6() {
        let text = MEMBER_CLEAN.replace(
            "anyhow = { workspace = true }",
            r#"libmimalloc-sys = { version = "0.1.44", features = ["extended"] }"#,
        );
        let m = parse_member(&text).unwrap();
        let d = disc("crates/uffs-daemon/Cargo.toml", &m);
        let exc = KnownExceptions::new();
        let findings = audit_deps_inherit_workspace(&d, "uffs-daemon", &exc);
        assert!(
            findings.is_empty(),
            "exception should suppress; got: {findings:?}"
        );
    }

    #[test]
    fn missing_docs_rs_metadata_fires_3_15() {
        let text = MEMBER_CLEAN.replace("[package.metadata.docs.rs]\nall-features = true\n", "");
        let m = parse_member(&text).unwrap();
        let d = disc("crates/uffs-core/Cargo.toml", &m);
        let findings = audit_docs_rs_metadata_present(&d, "uffs-core");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].invariant, "3.15");
    }

    #[test]
    fn underscore_bin_name_fires_3_13_except_diag() {
        let text = format!("{MEMBER_CLEAN}\n[[bin]]\nname = \"foo_bar\"\npath = \"src/main.rs\"\n");
        let m = parse_member(&text).unwrap();
        let d = disc("crates/uffs-core/Cargo.toml", &m);
        let exc = KnownExceptions::new();
        let findings = audit_lib_bin_name_convention(&d, "uffs-core", &exc);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].invariant, "3.13");

        // Same shape under uffs-diag — should be suppressed.
        let d_diag = disc("crates/uffs-diag/Cargo.toml", &m);
        let suppressed = audit_lib_bin_name_convention(&d_diag, "uffs-diag", &exc);
        assert!(suppressed.is_empty());
    }

    #[test]
    fn normalise_path_dep_resolves_relative() {
        assert_eq!(
            normalise_path_dep("crates/uffs-cli/Cargo.toml", "../uffs-client"),
            "crates/uffs-client"
        );
        assert_eq!(
            normalise_path_dep(
                "scripts/ci/uffs-gen-hooks/Cargo.toml",
                "../../../crates/uffs-core"
            ),
            "crates/uffs-core"
        );
    }

    // ─────────────────────────────────────────────────────────────
    // Invariant 3.5 — readme override allow-list
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn readme_override_on_allowlisted_crate_is_suppressed() {
        // Every crate in the 6-member publishable subset is on the
        // allow-list and uses the conventional `readme = "README.md"`
        // same-name pattern — none must fire.  Iterating the whole set
        // (not just `uffs-time`) guards against a future regression
        // that silently drops one crate from `readme_override_ok`.
        let text = MEMBER_CLEAN.replace("readme.workspace = true", "readme = \"README.md\"");
        let m = parse_member(&text).unwrap();
        let exc = KnownExceptions::new();
        for id in [
            "uffs-cli",
            "uffs-client",
            "uffs-mcp",
            "uffs-mft",
            "uffs-text",
            "uffs-time",
        ] {
            let path = format!("crates/{id}/Cargo.toml");
            let d = disc(&path, &m);
            let findings = audit_metadata_fields(&d, id, &exc);
            assert!(
                !findings.iter().any(|f| f.detail.contains("`readme`")),
                "allow-listed readme override should be suppressed for `{id}`; got: {findings:?}"
            );
        }
    }

    #[test]
    fn readme_override_on_unlisted_crate_still_fires_3_5() {
        // `uffs-core` is NOT on the allow-list — override must fire.
        let text = MEMBER_CLEAN.replace("readme.workspace = true", "readme = \"README.md\"");
        let m = parse_member(&text).unwrap();
        let d = disc("crates/uffs-core/Cargo.toml", &m);
        let exc = KnownExceptions::new();
        let findings = audit_metadata_fields(&d, "uffs-core", &exc);
        let readme_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.detail.contains("`readme`"))
            .collect();
        assert_eq!(
            readme_findings.len(),
            1,
            "unlisted crate readme override should fire 3.5; got: {findings:?}"
        );
        assert_eq!(readme_findings[0].invariant, "3.5");
    }

    #[test]
    fn readme_override_to_non_readme_path_still_fires_even_for_listed_crate() {
        // `uffs-time` is on the allow-list, but the exception is
        // tightened to the literal `"README.md"`.  An attempt to point
        // at a different path (e.g. `"docs/intro.md"`) must still fire.
        let text = MEMBER_CLEAN.replace("readme.workspace = true", "readme = \"docs/intro.md\"");
        let m = parse_member(&text).unwrap();
        let d = disc("crates/uffs-time/Cargo.toml", &m);
        let exc = KnownExceptions::new();
        let findings = audit_metadata_fields(&d, "uffs-time", &exc);
        let readme_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.detail.contains("`readme`"))
            .collect();
        assert_eq!(
            readme_findings.len(),
            1,
            "non-README.md readme override on listed crate must still fire 3.5; got: {findings:?}"
        );
        assert_eq!(readme_findings[0].invariant, "3.5");
    }

    #[test]
    fn readme_workspace_inherit_passes_for_every_member() {
        // The default state (workspace inheritance) must pass for both
        // allow-listed and non-allow-listed crates.
        let m = parse_member(MEMBER_CLEAN).unwrap();
        let exc = KnownExceptions::new();
        for id in ["uffs-core", "uffs-time", "uffs-text", "uffs-broker"] {
            let path = format!("crates/{id}/Cargo.toml");
            let d = disc(&path, &m);
            let findings = audit_metadata_fields(&d, id, &exc);
            assert!(
                !findings.iter().any(|f| f.detail.contains("`readme`")),
                "`readme.workspace = true` must not fire for `{id}`; got: {findings:?}"
            );
        }
    }

    #[test]
    fn member_id_from_path_strips_prefix_and_filename() {
        assert_eq!(
            member_id_from_path("crates/uffs-core/Cargo.toml"),
            "uffs-core"
        );
        assert_eq!(
            member_id_from_path("scripts/ci/uffs-gen-hooks/Cargo.toml"),
            "uffs-gen-hooks"
        );
    }

    // ─────────────────────────────────────────────────────────────
    // Invariant 3.5 — keywords / categories override allow-list
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn keywords_override_on_allowlisted_crate_is_suppressed() {
        // `uffs-time` is on the keywords allow-list and uses a
        // well-formed non-empty array — must not fire.
        let text = MEMBER_CLEAN.replace(
            "keywords.workspace = true",
            r#"keywords = ["ntfs", "filetime", "datetime"]"#,
        );
        let m = parse_member(&text).unwrap();
        let d = disc("crates/uffs-time/Cargo.toml", &m);
        let exc = KnownExceptions::new();
        let findings = audit_metadata_fields(&d, "uffs-time", &exc);
        assert!(
            !findings.iter().any(|f| f.detail.contains("`keywords`")),
            "allow-listed keywords override should be suppressed; got: {findings:?}"
        );
    }

    #[test]
    fn categories_override_on_allowlisted_crate_is_suppressed() {
        let text = MEMBER_CLEAN.replace(
            "categories.workspace = true",
            r#"categories = ["date-and-time"]"#,
        );
        let m = parse_member(&text).unwrap();
        let d = disc("crates/uffs-time/Cargo.toml", &m);
        let exc = KnownExceptions::new();
        let findings = audit_metadata_fields(&d, "uffs-time", &exc);
        assert!(
            !findings.iter().any(|f| f.detail.contains("`categories`")),
            "allow-listed categories override should be suppressed; got: {findings:?}"
        );
    }

    #[test]
    fn keywords_override_on_unlisted_crate_still_fires_3_5() {
        // `uffs-core` is NOT on the keywords allow-list — override
        // must fire even with a well-formed array.
        let text = MEMBER_CLEAN.replace("keywords.workspace = true", r#"keywords = ["something"]"#);
        let m = parse_member(&text).unwrap();
        let d = disc("crates/uffs-core/Cargo.toml", &m);
        let exc = KnownExceptions::new();
        let findings = audit_metadata_fields(&d, "uffs-core", &exc);
        let kw_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.detail.contains("`keywords`"))
            .collect();
        assert_eq!(
            kw_findings.len(),
            1,
            "unlisted crate keywords override must fire 3.5; got: {findings:?}"
        );
        assert_eq!(kw_findings[0].invariant, "3.5");
    }

    #[test]
    fn empty_keywords_array_on_allowlisted_crate_still_fires_3_5() {
        // `uffs-time` is on the allow-list but the override is
        // tightened to **non-empty** arrays.  `keywords = []` is
        // legal TOML but defeats the discoverability purpose of an
        // override; it must still fire.
        let text = MEMBER_CLEAN.replace("keywords.workspace = true", "keywords = []");
        let m = parse_member(&text).unwrap();
        let d = disc("crates/uffs-time/Cargo.toml", &m);
        let exc = KnownExceptions::new();
        let findings = audit_metadata_fields(&d, "uffs-time", &exc);
        let kw_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.detail.contains("`keywords`"))
            .collect();
        assert_eq!(
            kw_findings.len(),
            1,
            "empty keywords array on listed crate must still fire 3.5; got: {findings:?}"
        );
        assert_eq!(kw_findings[0].invariant, "3.5");
    }

    #[test]
    fn empty_categories_array_on_allowlisted_crate_still_fires_3_5() {
        let text = MEMBER_CLEAN.replace("categories.workspace = true", "categories = []");
        let m = parse_member(&text).unwrap();
        let d = disc("crates/uffs-time/Cargo.toml", &m);
        let exc = KnownExceptions::new();
        let findings = audit_metadata_fields(&d, "uffs-time", &exc);
        let cat_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.detail.contains("`categories`"))
            .collect();
        assert_eq!(
            cat_findings.len(),
            1,
            "empty categories array on listed crate must still fire 3.5; got: {findings:?}"
        );
        assert_eq!(cat_findings[0].invariant, "3.5");
    }

    #[test]
    fn keywords_and_categories_workspace_inherit_passes_for_every_member() {
        // The default state (workspace inheritance) must pass for
        // both allow-listed and non-allow-listed crates.
        let m = parse_member(MEMBER_CLEAN).unwrap();
        let exc = KnownExceptions::new();
        for id in [
            "uffs-core",
            "uffs-time",
            "uffs-text",
            "uffs-client",
            "uffs-mcp",
            "uffs-mft",
            "uffs-cli",
            "uffs-broker",
        ] {
            let path = format!("crates/{id}/Cargo.toml");
            let d = disc(&path, &m);
            let findings = audit_metadata_fields(&d, id, &exc);
            assert!(
                !findings
                    .iter()
                    .any(|f| f.detail.contains("`keywords`") || f.detail.contains("`categories`")),
                "`keywords.workspace = true` / `categories.workspace = true` must not fire for \
                 `{id}`; got: {findings:?}"
            );
        }
    }

    #[test]
    fn is_non_empty_array_distinguishes_shapes() {
        // Empty array → false.
        let empty = toml::Value::Array(Vec::new());
        assert!(!is_non_empty_array(Some(&empty)));
        // Non-empty array → true.
        let one = toml::Value::Array(vec![toml::Value::String("a".to_owned())]);
        assert!(is_non_empty_array(Some(&one)));
        // None → false.
        assert!(!is_non_empty_array(None));
        // Workspace-inheritance shape (table with `workspace = true`) → false.
        let mut table = toml::value::Table::new();
        table.insert("workspace".to_owned(), toml::Value::Boolean(true));
        let inherit_value = toml::Value::Table(table);
        assert!(!is_non_empty_array(Some(&inherit_value)));
    }
}
