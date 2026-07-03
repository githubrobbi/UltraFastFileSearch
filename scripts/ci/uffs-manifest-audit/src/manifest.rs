// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Minimal Cargo.toml model for the uffs-manifest-audit drift detector.
//!
//! Only the fields the audit cares about are deserialised — the rest
//! of every member's `Cargo.toml` is captured as an untyped
//! `toml::Value` so the audit can poke at arbitrary tables (e.g.
//! `[lints]`, `[profile.*]`, `[patch.*]`) without enumerating every
//! permitted shape.  This keeps the audit robust to schema additions
//! upstream — a new top-level table in Cargo.toml doesn't break the
//! audit; it just isn't checked.

use anyhow::{Context as _, Result};
use serde::Deserialize;

/// Parsed root `Cargo.toml`.  Captures only the workspace-shaped
/// fields the audit cares about.
#[derive(Debug, Deserialize)]
pub(crate) struct RootManifest {
    /// `[workspace]` table — every root manifest must have one
    /// because UFFS is a virtual workspace.  Missing `[workspace]`
    /// is itself a finding (handled in `audit::root_is_virtual`).
    pub(crate) workspace: Option<Workspace>,

    /// `[package]` table if present.  Phase 1 invariant 3.9
    /// requires this to be `None` (virtual workspace).
    pub(crate) package: Option<toml::Value>,
}

/// `[workspace]` table contents.
#[derive(Debug, Deserialize)]
pub(crate) struct Workspace {
    /// Mandatory `resolver = "..."` string.  Phase 1 invariant 3.10
    /// requires `"3"`.
    pub(crate) resolver: Option<String>,

    /// Member-list strings.  Phase 1 invariant 3.1 requires this to
    /// match `find crates scripts -name Cargo.toml` 1:1.
    pub(crate) members: Vec<String>,
    // NB: `default-members` is intentionally not captured here —
    // Phase 1 invariant 3.11 is checked via source-text regex on
    // the raw root manifest (because `toml::from_str` strips
    // comments and the invariant's "documented fallback" case
    // is comment-based).  See `audit::audit_default_members_intent`.
}

/// Parsed member `Cargo.toml`.  Captures only the fields the audit
/// cares about; everything else stays untyped (or is dropped).
#[derive(Debug, Deserialize)]
pub(crate) struct MemberManifest {
    /// `[package]` table.  Every workspace member has one; the
    /// virtual-workspace invariant (3.9) is enforced on the root
    /// manifest separately.
    pub(crate) package: MemberPackage,

    /// `[dependencies]` table.  Phase 1 invariant 3.6 requires every
    /// entry to use `*.workspace = true` (with documented exceptions
    /// for features-deltas like `libmimalloc-sys`).
    #[serde(default)]
    pub(crate) dependencies: toml::Table,

    /// `[lib]` section if present.  Phase 1 invariant 3.13 requires
    /// the `name` (if set) to use underscores.
    pub(crate) lib: Option<LibOrBin>,

    /// `[[bin]]` array.  Phase 1 invariant 3.13 requires every
    /// `name` to use hyphens (except `uffs-diag`'s documented
    /// underscore-named diagnostic binaries).
    #[serde(default)]
    pub(crate) bin: Vec<LibOrBin>,

    /// `[lints]` table.  Phase 1 invariant 3.7 requires
    /// `workspace = true`.  Captured untyped so the audit can verify
    /// the exact shape (a single `workspace = true` key, no
    /// per-crate overrides).
    pub(crate) lints: Option<toml::Table>,

    /// `[profile.*]` table.  Phase 1 invariant 3.8 requires this to
    /// be absent — profile policy lives at the workspace root only.
    pub(crate) profile: Option<toml::Value>,

    /// `[patch.*]` table.  Phase 1 invariant 3.8 requires this to be
    /// absent — patch policy lives at the workspace root only.
    pub(crate) patch: Option<toml::Value>,

    /// `[workspace]` table.  Phase 1 invariant 3.8 requires this to
    /// be absent in members — only the root may declare
    /// `[workspace]`.
    pub(crate) workspace: Option<toml::Value>,
}

/// `[package]` table fields the audit cares about.  Every field is
/// optional from the deserialiser's perspective so a misshapen
/// manifest (e.g. missing `name`) surfaces as a clean error instead
/// of a parse failure.
#[derive(Debug, Deserialize)]
pub(crate) struct MemberPackage {
    // NB: the audit derives the member id from the manifest path
    // (`member_id_from_path` in `audit.rs`), so `package.name` is
    // not captured here.  Keeping the file-path-derived id in sync
    // with `package.name` is itself a future Phase-2 audit
    // dimension if it becomes worth checking.
    /// `version = ...` — must be `version.workspace = true`.  When
    /// inherited it appears as the toml-rs `Workspace { workspace =
    /// true }` shape; when overridden it appears as a string.
    pub(crate) version: Option<toml::Value>,

    /// `edition = ...` — Phase 1 invariant 3.3 requires
    /// `.workspace = true`.
    pub(crate) edition: Option<toml::Value>,

    /// `license = ...` — Phase 1 invariant 3.5 requires
    /// `.workspace = true`.
    pub(crate) license: Option<toml::Value>,

    /// `authors = ...` — Phase 1 invariant 3.5 requires
    /// `.workspace = true`.
    pub(crate) authors: Option<toml::Value>,

    /// `repository = ...` — Phase 1 invariant 3.5 requires
    /// `.workspace = true`.
    pub(crate) repository: Option<toml::Value>,

    /// `readme = ...` — Phase 1 invariant 3.5 requires
    /// `.workspace = true`, with one narrowly scoped exception:
    /// crates listed in `KnownExceptions::readme_override_ok` may
    /// instead set the literal value `"README.md"` to point
    /// crates.io / docs.rs at a per-crate library-focused README
    /// alongside their `Cargo.toml`.  Any other override pattern
    /// still fires a finding even for listed crates.
    pub(crate) readme: Option<toml::Value>,

    /// `keywords = ...` — Phase 1 invariant 3.5 requires
    /// `.workspace = true`, with one narrowly scoped exception:
    /// crates listed in `KnownExceptions::keywords_override_ok` may
    /// instead set a **non-empty TOML array** of crates.io-shaped
    /// keywords to tailor discoverability for their library role.
    /// An empty array still fires (defeats the override's purpose).
    /// Per-keyword shape rules (max 5, max 20 chars, regex) are
    /// enforced authoritatively by `cargo publish --dry-run`.
    pub(crate) keywords: Option<toml::Value>,

    /// `categories = ...` — Phase 1 invariant 3.5 requires
    /// `.workspace = true`, with the same narrow exception as
    /// `keywords`: crates listed in
    /// `KnownExceptions::categories_override_ok` may instead set a
    /// **non-empty TOML array** of crates.io category slugs.  Slug
    /// validity (`https://crates.io/category_slugs`) is enforced
    /// authoritatively by `cargo publish --dry-run`.
    pub(crate) categories: Option<toml::Value>,

    /// `documentation = ...` — Phase 1 invariant 3.5 requires
    /// `.workspace = true`.
    pub(crate) documentation: Option<toml::Value>,

    /// `publish = ...` — Phase 1 invariant 3.14 requires either
    /// `publish.workspace = true` (most members) or an explicit
    /// `publish = true` for the small publishable-set documented in
    /// `release-automation-baseline.md` §10 deviation row 5.
    pub(crate) publish: Option<toml::Value>,

    /// `[package.metadata.docs.rs]` table.  Phase 1 invariant 3.15
    /// requires this in every product + publishable crate.  Captured
    /// untyped because the audit only needs to assert presence, not
    /// validate the inner `all-features` / `rustdoc-args` shape (that
    /// would be a separate Phase-2 audit dimension).
    pub(crate) metadata: Option<toml::Value>,
}

/// Shared shape for `[lib]` and `[[bin]]` entries.  Only the `name`
/// field is consulted by the audit (invariant 3.13).
#[derive(Debug, Deserialize)]
pub(crate) struct LibOrBin {
    /// `name = "..."` — optional in Cargo (defaults to the package
    /// name), but every UFFS member sets it explicitly.
    pub(crate) name: Option<String>,
}

/// Parse a root `Cargo.toml` from text.
///
/// # Errors
///
/// Returns an error if the text is not valid TOML or if any captured
/// field has the wrong shape (e.g. `members` not an array).
pub(crate) fn parse_root(text: &str) -> Result<RootManifest> {
    toml::from_str(text).context("parse root Cargo.toml")
}

/// Parse a member `Cargo.toml` from text.
///
/// # Errors
///
/// Returns an error if the text is not valid TOML or if any captured
/// field has the wrong shape (e.g. `[[bin]]` not an array).
pub(crate) fn parse_member(text: &str) -> Result<MemberManifest> {
    toml::from_str(text).context("parse member Cargo.toml")
}

/// Return `true` if `value` is the TOML inline-table `{ workspace =
/// true }` shape that Cargo uses for field-level inheritance.  False
/// for any other shape (e.g. a literal string or array).
pub(crate) fn is_workspace_inherited(value: &toml::Value) -> bool {
    let Some(table) = value.as_table() else {
        return false;
    };
    matches!(table.get("workspace"), Some(toml::Value::Boolean(true)))
}

#[cfg(test)]
#[expect(
    clippy::min_ident_chars,
    reason = "test code uses idiomatic short fixture bindings (e.g. `m` for the parsed \
              manifest); failures panic with adequate context (issue #212)"
)]
mod tests {
    use super::*;

    const ROOT_FIXTURE: &str = r#"
[workspace]
resolver = "3"
members = ["crates/uffs-core", "crates/uffs-cli"]
"#;

    const MEMBER_FIXTURE_CLEAN: &str = r#"
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
description = "per-crate description override is allowed"

[package.metadata.docs.rs]
all-features = true

[dependencies]
anyhow = { workspace = true }

[lints]
workspace = true
"#;

    #[test]
    fn root_parses_with_members() {
        let root = parse_root(ROOT_FIXTURE).unwrap();
        let ws = root.workspace.as_ref().unwrap();
        assert_eq!(ws.resolver.as_deref(), Some("3"));
        assert_eq!(ws.members.len(), 2);
        assert!(root.package.is_none());
    }

    #[test]
    fn member_parses_clean_fixture() {
        let m = parse_member(MEMBER_FIXTURE_CLEAN).unwrap();
        assert!(is_workspace_inherited(m.package.version.as_ref().unwrap()));
        assert!(is_workspace_inherited(m.package.edition.as_ref().unwrap()));
        assert!(m.package.metadata.is_some());
        assert!(m.lints.is_some());
        assert!(m.profile.is_none());
        assert!(m.patch.is_none());
        assert!(m.workspace.is_none());
    }

    #[test]
    fn workspace_inherited_detects_only_true() {
        let inherited: toml::Value = toml::from_str("foo = { workspace = true }").unwrap();
        let inherited_val = inherited.get("foo").unwrap();
        assert!(is_workspace_inherited(inherited_val));

        let literal: toml::Value = toml::from_str(r#"foo = "1.0.0""#).unwrap();
        let literal_val = literal.get("foo").unwrap();
        assert!(!is_workspace_inherited(literal_val));

        let inherited_false: toml::Value = toml::from_str("foo = { workspace = false }").unwrap();
        let inherited_false_val = inherited_false.get("foo").unwrap();
        assert!(!is_workspace_inherited(inherited_false_val));
    }
}
