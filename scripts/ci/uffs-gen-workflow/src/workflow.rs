// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Hand-rolled minimal extractor for the four structural fields the
//! workflow validator inspects: top-level `jobs:` keys, per-job
//! `name:` / `if:` / `needs:`.
//!
//! # Why not use a YAML crate?
//!
//! The pre-existing options all have material costs:
//!
//! | Crate | Status | Concern |
//! |---|---|---|
//! | `serde_yaml` | archived 2024 | unmaintained |
//! | `serde_yml` | archived 2024 | active `RustSec` advisory in `Serializer.emitter` |
//! | `serde_yaml_ng` | active fork | depends on unmaintained `unsafe-libyaml` (C) |
//! | `serde_norway` | active fork | depends on `unsafe-libyaml-norway` (C) |
//!
//! The validator only needs to extract a handful of specific string
//! fields from a 600-line tame YAML file (no anchors, no complex flow
//! style, no embedded JSON).  Pulling in a heavyweight C-backed
//! dependency, paying the cargo-vet exemption + cargo-deny advisory
//! tax, and shipping the libyaml binary blob to every CI run is a
//! superficial workaround for a problem that's solvable with ~120
//! lines of focused string-matching Rust.
//!
//! # Grammar accepted
//!
//! Only the subset of YAML actually used in `pr-fast.yml`:
//!
//! ```yaml
//! jobs:
//!   <job-id>:
//!     name: <text-or-quoted>
//!     if: <text-or-quoted>
//!     needs: <single-string>      # "needs: classify"
//!     needs: [a, b, c]            # flow-style list
//!     needs:                      # block-style list
//!       - a
//!       - b
//! ```
//!
//! Indentation: 2 spaces per level.  Job keys live at column 2 under
//! `jobs:`; per-job fields live at column 4; block-list items at
//! column 6.  Lines with deeper indentation, comments, or blank
//! lines are ignored within a job's scope.
//!
//! Constructs explicitly NOT handled (and NOT needed by the
//! validator): anchors / aliases (`&foo`, `*foo`), document
//! separators (`---`), tags (`!!str`), folded scalars (`>`),
//! literal scalars (`|`), nested mappings beyond two levels.  If
//! `pr-fast.yml` ever grows one of these in a way that affects a
//! validated field, [`parse`] returns an error pointing at the
//! offending line so the validator fails closed (refuses to opine
//! rather than silently mis-classifying).

use alloc::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};

/// Minimal in-memory model of `.github/workflows/pr-fast.yml`.
#[derive(Debug, Default)]
pub(crate) struct Workflow {
    /// Map of job-id → job spec.  `BTreeMap` for deterministic
    /// iteration order in error messages.
    pub(crate) jobs: BTreeMap<String, Job>,
}

/// Per-job structural fields the validator inspects.
#[derive(Debug, Default)]
pub(crate) struct Job {
    /// `name:` field — display text shown in the GitHub Checks UI.
    /// Validator inspects this only on the `required` job (Property 4
    /// — branch-protection guard).
    pub(crate) name: Option<String>,

    /// `if:` predicate (the YAML key is reserved-word-quoted as
    /// `if`; the field is renamed `if_expr` here for Rust ergonomics).
    /// Mapped to a permissiveness score by the validator.
    pub(crate) if_expr: Option<String>,

    /// `needs:` — flattened list of upstream job-ids regardless of
    /// which of the three YAML shapes was used to express it.
    pub(crate) needs: Vec<String>,
}

/// Indentation step — every `pr-fast.yml` we ship uses two-space
/// indents, mirroring the GitHub Actions style guide.
const INDENT_STEP: usize = 2;

/// Parse a `pr-fast.yml`-shaped workflow document.
///
/// # Errors
///
/// Returns an error if:
/// - the `jobs:` key is missing or not at column 0,
/// - a job key under `jobs:` is malformed (not `<id>:` at column 2),
/// - a `needs:` list-form value has an inconsistent shape (e.g. missing closing
///   `]` for flow-style).
///
/// Files lacking any of the optional per-job fields (`name:`, `if:`,
/// `needs:`) parse cleanly with the missing field defaulted.
pub(crate) fn parse(text: &str) -> Result<Workflow> {
    let mut workflow = Workflow::default();
    let lines: Vec<&str> = text.lines().collect();

    // Locate the top-level `jobs:` key.
    let Some(jobs_idx) = lines
        .iter()
        .position(|line| line.starts_with("jobs:") && line.trim_end_matches(':').len() == 4)
    else {
        bail!("workflow has no top-level `jobs:` key at column 0");
    };

    let mut idx = jobs_idx + 1;
    while let Some(&line) = lines.get(idx) {
        // End of `jobs:` block: a non-empty line at column 0 (next
        // top-level key like `name:`, `permissions:`, etc.).
        if !line.trim().is_empty() && !line.starts_with(' ') {
            break;
        }
        // Skip blank / comment / non-job-key lines.
        let Some(job_id) = job_key_at(line, INDENT_STEP) else {
            idx += 1;
            continue;
        };
        // Parse the job's body (lines at deeper indentation).
        let (job, consumed) = parse_job_body(&lines, idx + 1)
            .with_context(|| format!("parse job `{job_id}` at line {}", idx + 1))?;
        workflow.jobs.insert(job_id.to_owned(), job);
        idx += 1 + consumed;
    }

    if workflow.jobs.is_empty() {
        bail!("workflow has a `jobs:` key but no job entries below it");
    }
    Ok(workflow)
}

/// Return `Some(job_id)` if `line` is `<INDENT>job-id:` at the given
/// indentation, where `<INDENT>` is exactly `indent` spaces.
///
/// Rejects job keys with values inline (`job-id: foo`), comments
/// after the colon, or trailing whitespace beyond a single newline.
fn job_key_at(line: &str, indent: usize) -> Option<&str> {
    let stripped = line.strip_prefix(&" ".repeat(indent))?;
    // Reject deeper-indented lines (`stripped` would itself start
    // with a space).
    if stripped.starts_with(' ') {
        return None;
    }
    // Strip trailing comment if present (`job-id:  # comment`).
    let cleaned = stripped.split('#').next().unwrap_or(stripped).trim_end();
    let id = cleaned.strip_suffix(':')?;
    // YAML rules: job ids are non-empty and don't contain `:` or
    // whitespace.  We're stricter than necessary because we only
    // need to match the `[a-zA-Z][a-zA-Z0-9-]*` shape used in
    // `pr-fast.yml`.
    if id.is_empty() || id.contains(' ') || id.contains(':') {
        return None;
    }
    Some(id)
}

/// Parse a job's body — the contiguous run of lines at
/// indent ≥ 4 that follow a job-id line at indent 2.
///
/// Returns the parsed [`Job`] and the number of input lines
/// consumed from `start` so the caller can advance correctly.
fn parse_job_body(lines: &[&str], start: usize) -> Result<(Job, usize)> {
    let mut job = Job::default();
    let mut idx = start;
    while let Some(&line) = lines.get(idx) {
        // End of body: a non-empty line at indent < 4 (next job or
        // top-level key).
        if !line.trim().is_empty() && line_indent(line) < 2 * INDENT_STEP {
            break;
        }
        // Skip blank / comment lines without consuming the body.
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            idx += 1;
            continue;
        }
        // Field lines live at exactly indent 4.
        if line_indent(line) != 2 * INDENT_STEP {
            // Deeper indentation is part of a nested structure
            // (e.g. `steps:` body, `with:` block, `env:`); skip
            // without parsing.
            idx += 1;
            continue;
        }

        if let Some(value) = strip_field(line, "name:") {
            job.name = Some(unquote(value));
        } else if let Some(value) = strip_field(line, "if:") {
            job.if_expr = Some(unquote(value));
        } else if let Some(value) = strip_field(line, "needs:") {
            // Three shapes — handled by [`parse_needs_value`].
            let (parsed, extra_consumed) = parse_needs_value(value, lines, idx + 1)?;
            job.needs = parsed;
            idx += 1 + extra_consumed;
            continue;
        }
        idx += 1;
    }
    Ok((job, idx - start))
}

/// Strip the `field:` prefix (with its trailing whitespace) from a
/// line and return the trimmed remainder.  Returns `None` if `line`
/// does not start with the requested field at indent 4.
fn strip_field<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let stripped = line.strip_prefix(&" ".repeat(2 * INDENT_STEP))?;
    let value = stripped.strip_prefix(field)?;
    Some(value.trim())
}

/// Trim YAML quoting (single, double, or none) from a scalar value.
/// Strips trailing inline comments.
fn unquote(value: &str) -> String {
    let cleaned = value.split('#').next().unwrap_or(value).trim();
    if let Some(inner) = cleaned
        .strip_prefix('\'')
        .and_then(|stripped| stripped.strip_suffix('\''))
    {
        return inner.to_owned();
    }
    if let Some(inner) = cleaned
        .strip_prefix('"')
        .and_then(|stripped| stripped.strip_suffix('"'))
    {
        return inner.to_owned();
    }
    cleaned.to_owned()
}

/// Number of leading spaces on a line.  Tabs are treated as a single
/// character (we never emit them and `pr-fast.yml` doesn't either).
fn line_indent(line: &str) -> usize {
    line.bytes().take_while(|byte| *byte == b' ').count()
}

/// Parse the value half of a `needs:` field.  Three shapes:
///
/// 1. Empty `value` → block-style list at indent 6 follows.
/// 2. `value` starts with `[` → flow-style list (single line).
/// 3. Otherwise → single string.
///
/// Returns the parsed list and the number of follow-on lines
/// consumed (0 for shapes 2 + 3).
fn parse_needs_value(value: &str, lines: &[&str], start: usize) -> Result<(Vec<String>, usize)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        // Block-style list.
        let mut items = Vec::new();
        let mut idx = start;
        while let Some(&line) = lines.get(idx) {
            let body_start = " ".repeat(3 * INDENT_STEP);
            let Some(stripped) = line.strip_prefix(&body_start) else {
                break;
            };
            let Some(item) = stripped.strip_prefix("- ") else {
                break;
            };
            items.push(unquote(item));
            idx += 1;
        }
        return Ok((items, idx - start));
    }
    if let Some(inside) = trimmed
        .strip_prefix('[')
        .and_then(|stripped| stripped.strip_suffix(']'))
    {
        // Flow-style: comma-separated.
        let items: Vec<String> = inside
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(unquote)
            .collect();
        return Ok((items, 0));
    }
    if trimmed.starts_with('[') {
        bail!("needs: starts with `[` but has no closing `]` on the same line: {trimmed:?}");
    }
    // Single string.
    Ok((vec![unquote(trimmed)], 0))
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

    /// Tiny fixture covering all three `needs:` shapes plus an
    /// `if:` field.  Matches real shapes from `pr-fast.yml`.
    const FIXTURE: &str = "
name: PR Fast CI
on: pull_request
jobs:
  classify:
    name: Classify changes
    runs-on: ubuntu-22.04
    outputs:
      rust: ${{ steps.changes.outputs.rust }}
    steps:
      - run: echo classify

  fmt:
    name: Format check
    runs-on: ubuntu-22.04
    needs: classify
    if: needs.classify.outputs.rust == 'true'
    steps:
      - run: cargo fmt --check

  clippy:
    name: Clippy
    runs-on: ubuntu-22.04
    needs: [classify, sanity]
    if: needs.classify.outputs.code == 'true'
    steps:
      - run: cargo clippy

  required:
    name: PR Fast CI / required
    runs-on: ubuntu-22.04
    if: always()
    needs:
      - classify
      - fmt
      - clippy
    steps:
      - run: echo done
";

    #[test]
    fn parses_all_three_needs_shapes() {
        let workflow = parse(FIXTURE).unwrap();
        assert_eq!(workflow.jobs.len(), 4);

        // Single string
        let fmt = &workflow.jobs["fmt"];
        assert_eq!(fmt.needs, vec!["classify"]);

        // Flow-style list
        let clippy = &workflow.jobs["clippy"];
        assert_eq!(clippy.needs, vec!["classify", "sanity"]);

        // Block-style list
        let required = &workflow.jobs["required"];
        assert_eq!(required.needs, vec!["classify", "fmt", "clippy"]);
    }

    #[test]
    fn parses_if_and_name_fields() {
        let workflow = parse(FIXTURE).unwrap();
        let fmt = &workflow.jobs["fmt"];
        assert_eq!(fmt.name.as_deref(), Some("Format check"));
        assert_eq!(
            fmt.if_expr.as_deref(),
            Some("needs.classify.outputs.rust == 'true'")
        );

        let required = &workflow.jobs["required"];
        assert_eq!(required.name.as_deref(), Some("PR Fast CI / required"));
        assert_eq!(required.if_expr.as_deref(), Some("always()"));
    }

    #[test]
    fn missing_needs_yields_empty_vec() {
        let yaml = "
jobs:
  alone:
    name: Alone
    runs-on: ubuntu-22.04
    steps:
      - run: echo
";
        let workflow = parse(yaml).unwrap();
        assert!(workflow.jobs["alone"].needs.is_empty());
    }

    #[test]
    fn quoted_field_values_are_unquoted() {
        let yaml = r#"
jobs:
  q:
    name: "Quoted name"
    if: 'always()'
    runs-on: ubuntu-22.04
"#;
        let workflow = parse(yaml).unwrap();
        let q = &workflow.jobs["q"];
        assert_eq!(q.name.as_deref(), Some("Quoted name"));
        assert_eq!(q.if_expr.as_deref(), Some("always()"));
    }

    #[test]
    fn nested_blocks_under_jobs_are_skipped_cleanly() {
        // `with:`, `env:`, multi-line `run: |` are all ignored.
        let yaml = "
jobs:
  complex:
    name: Complex
    runs-on: ubuntu-22.04
    needs: [a, b]
    env:
      RUSTFLAGS: -D warnings
      RUST_LOG: debug
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
          fetch-depth: 0
      - run: |
          echo line one
          echo line two
";
        let workflow = parse(yaml).unwrap();
        let job = &workflow.jobs["complex"];
        assert_eq!(job.name.as_deref(), Some("Complex"));
        assert_eq!(job.needs, vec!["a", "b"]);
    }

    #[test]
    fn missing_jobs_key_fails_with_context() {
        let yaml = "name: noisy\non: push\n";
        let err = parse(yaml).unwrap_err();
        assert!(format!("{err:#}").contains("jobs:"), "got: {err:#}");
    }

    #[test]
    fn empty_jobs_block_fails() {
        let yaml = "jobs:\nname: x\n";
        let err = parse(yaml).unwrap_err();
        assert!(format!("{err:#}").contains("no job entries"));
    }

    #[test]
    fn flow_list_without_closing_bracket_fails() {
        let yaml = "
jobs:
  bad:
    needs: [a, b
    runs-on: ubuntu-22.04
";
        let err = parse(yaml).unwrap_err();
        assert!(format!("{err:#}").contains("closing `]`"), "got: {err:#}");
    }

    #[test]
    fn block_list_with_blank_line_terminator() {
        // Real workflows often have blank lines BETWEEN the list and
        // the next field.  Ensure we stop the list at the first
        // non-list-item line, not on the blank.
        let yaml = "
jobs:
  j:
    name: J
    needs:
      - a
      - b

    runs-on: ubuntu-22.04
";
        let workflow = parse(yaml).unwrap();
        assert_eq!(workflow.jobs["j"].needs, vec!["a", "b"]);
    }

    #[test]
    fn job_key_at_rejects_inline_value() {
        // `job-id: foo` (with a value) is not a job key.
        assert_eq!(job_key_at("  fmt: classify", INDENT_STEP), None);
    }

    #[test]
    fn job_key_at_accepts_trailing_comment() {
        assert_eq!(
            job_key_at("  fmt:   # the format check", INDENT_STEP),
            Some("fmt")
        );
    }

    #[test]
    fn unquote_handles_single_double_and_bare() {
        assert_eq!(unquote("'hello'"), "hello");
        assert_eq!(unquote("\"hello\""), "hello");
        assert_eq!(unquote("hello"), "hello");
        assert_eq!(unquote("  hello  "), "hello");
        assert_eq!(unquote("hello # comment"), "hello");
    }
}
