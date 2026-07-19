<!--
SPDX-FileCopyrightText: 2025-2026 SKY, LLC.
SPDX-License-Identifier: MPL-2.0
-->
# UFFS Filtering Reference — extensions, type groups, and every other filter axis

**Status:** Reference doc, audited against the code (2026-07-19). Answers one
question precisely: *what can I filter by, and how do I combine multiple
file types in one query?*

---

## 0. The short answer

UFFS filters by **raw, comma-separated, multi-extension lists** — OR-combined,
case-insensitive, no leading dot:

```
uffs "*" --ext pdf,docx,xlsx
```

On top of that there's a **curated named-family layer**, in two independent
forms, both usable as drop-in `--ext`/`--type` values instead of spelling out
every extension:

```
uffs "*" --ext documents,rs        # a collection alias + a literal, mixed
uffs "*" --type document           # a semantic category
```

There is **no magic-byte / content-sniffing classification anywhere in UFFS**
— everything below is extension + MFT-metadata based. If you're coming from a
tool that re-classifies a file after reading its header (magic bytes
overriding a wrong extension), UFFS has no equivalent; a misnamed file is
filtered by whatever its extension says, full stop. See §6.

UFFS also has **two separate filter surfaces**, not one — the interactive
search engine (what the `uffs` CLI and `uffsd` daemon serve) is far richer
than the content-export `JobRequest` (what `uffs-content` accepts for a
streaming export job). §4 has the exact narrower subset the export path
forwards.

---

## 1. The two filter surfaces

| | Interactive search (CLI / `uffsd`) | Content-export (`uffs-content::JobRequest`) |
|---|---|---|
| Struct | `SearchFilterParams` → `SearchFilters` (`crates/uffs-core/src/search/filters/mod.rs`) | `JobRequest` (`crates/uffs-content/src/job/intake.rs`) |
| Purpose | "find/list/aggregate rows" | "stream file *content*, not just metadata, for a set of candidates" |
| Filter breadth | Everything in §2 | A narrow, deliberately curated subset — §4 |

If you only ever use the `uffs` CLI, you want §2 and §3. If you're building a
content-export job (Docenta-style bulk read), you want §4, and you should
assume anything not listed there **is not available** on that path.

---

## 2. Extensions & type groups — the full combination story

### 2.1 Raw extension list (`--ext`)

- Flag: `--ext <csv>` — **one flag, comma-separated value.** Not repeatable —
  a second `--ext` overwrites the first, it does not add to it. Use commas:
  `--ext pdf,docx,rs`, not `--ext pdf --ext docx`.
- Wire field: `SearchParams::ext: Option<String>` — same comma-separated
  string travels over IPC and into `JobRequest::ext` unchanged.
- Parsing: split on `,`, each token trimmed, leading `.` stripped, lowercased.
  Empty tokens skipped.
- Matching: **OR across every value** — a file matches if its extension
  equals *any* entry in the list. Case-insensitive. No leading dot in either
  the filter or the match. Dotless files, dotfiles (`.gitignore`), and
  trailing-dot names (`foo.`) all have "no extension" and never match a
  non-empty `--ext` list.
- Multiple extensions per query is fully supported — this is the primary
  answer to "how do I combine types": list them, comma-separated.

### 2.2 Built-in collection aliases (inline in `--ext`)

Seven names expand to a hardcoded extension list *at `--ext` parse time* —
you can mix an alias with literal extensions in the same comma list:

| Alias(es) | Expands to |
|---|---|
| `pictures`, `images` | jpg, jpeg, png, gif, bmp, tiff, tif, webp, svg, ico, raw, heic |
| `documents`, `docs` | doc, docx, pdf, txt, rtf, odt, xls, xlsx, ppt, pptx, csv, md |
| `videos`, `video` | mp4, avi, mkv, mov, wmv, flv, webm, mpeg, mpg, m4v, 3gp |
| `music`, `audio` | mp3, wav, flac, aac, ogg, wma, m4a, opus, aiff |
| `archives`, `compressed` | zip, rar, 7z, tar, gz, bz2, xz, iso |
| `code`, `source` | rs, py, js, ts, java, c, cpp, h, hpp, go, rb, php, swift, kt |
| `executables`, `exec` | exe, msi, bat, cmd, ps1, com, scr, vbs, wsf, dll, sys |

Source: `crates/uffs-core/src/extensions/mod.rs` (`expand_collection`).

```
uffs "*" --ext documents,rs      # every document extension, plus .rs files
```

### 2.3 `--type` semantic categories (a second, larger taxonomy)

A separate system: **22 semantic categories** (`ALL_TYPE_CATEGORIES` in
`crates/uffs-core/src/search/derived.rs`), each mapping to its own curated
extension list — `document`, `code`, `executable`, `script`, `web`, `font`,
`database`, `config`, `log`, `backup`, `disk_image`, `data`, `cad`,
`shortcut`, `system`, `cert`, `ebook`, plus the five reused from §2.2
(picture/video/music/archive), and `directory`/`file`/`other` (structural,
not extension-mapped).

```
uffs "*" --type document
```

**`--type` + `--ext` combine by intersection, not union** — if both are set,
a file must satisfy *both* (a mappable `--type` is folded into the extension
set and ANDed against whatever `--ext` already listed). If you want a union
of two categories, list their extensions together under `--ext` instead:

```
uffs "*" --ext documents,rs        # union: documents OR rs
uffs "*" --type document --ext txt # intersection: (documents) AND (txt) == just txt, probably not what you want
```

### 2.4 Two taxonomies, not one — a real gap to know about

`extensions::collections` (§2.2) and `search::derived` (§2.3) are
**independently maintained and disagree with each other** — e.g.
`collections::EXECUTABLES` has 11 entries including `dll`/`sys`/`vbs`/`wsf`;
`derived::EXECUTABLES` has 7, and `dll`/`sys` live under `SYSTEM` there
instead. There is no single canonical "what extensions count as an
executable" answer in UFFS the way docenta-core's `family.rs` is canonical
for its families. If precision matters for a given job, list the exact
extensions explicitly rather than relying on either alias system to match
your expectation.

There is also **no ~150-extension "Text" super-family** the way docenta-core
has one. The nearest equivalents are the separate `documents`/`code`/`config`/
`data`/`log` categories — you'd union several of them yourself via `--ext` if
you want docenta's "Text" breadth:

```
uffs "*" --ext txt,md,csv,json,xml,yaml,toml,ini,log,srt,rs,py,js,ts,c,cpp,go,java
```

(spell out whatever subset you actually need — there's no single flag for
"all text-like files" today).

---

## 3. Every other filter axis (interactive search only)

All of these are **AND-combined** with each other and with §2's extension
filter (only §2's multi-value list and the month filter below are internally
OR'd across their own values).

| Axis | Flag(s) | Notes |
|---|---|---|
| Size | `--min-size` / `--max-size` / `--exact-size` | bytes; accepts unit suffixes (`10MB`) |
| Size on disk | `--min-size-on-disk` / `--max-size-on-disk` / `--exact-size-on-disk` | allocated bytes |
| Modified time | `--newer` / `--older` | `"7d"`, `"24h"`, `"2026-01-15"` |
| Created time | `--newer-created` / `--older-created` | same spec syntax |
| Accessed time | `--newer-accessed` / `--older-accessed` | same spec syntax |
| Date range | `--between START,END` | shorthand for newer+older together |
| Month | `--month <spec>` | set of calendar months, OR-combined |
| Attributes | `--attr <csv>` | e.g. `hidden,compressed,!system` — `!` prefix excludes |
| Hide NTFS metafiles | `--hide-system` | `$MFT`, `$LogFile`, etc. — not ordinary `$`-prefixed user files |
| Hide ADS | `--hide-ads` | Alternate Data Streams (names containing `:`) |
| Path scope | `--in-path <glob>` / `--not-in-path <csv>` | directory-path glob(s), matched against the dir portion only |
| Name exclude | `--exclude <glob>` | glob against the leaf name |
| Descendants | `--min-descendants` / `--max-descendants` / `--exact-descendants` | directory child count |
| Tree metrics | `--min-treesize` / `--max-treesize` / `--min-tree-allocated` / `--max-tree-allocated` | recursive subtree totals |
| Name/path length | `--min-name-length` / `--max-name-length` / `--min-path-length` / `--max-path-length` | in characters |
| Bulkiness | `--min-bulkiness` / `--max-bulkiness` | allocated/logical ratio, as a percentage |
| Malformed names | `--malformed` / `--well-formed` / `--malformed-path` | see §7 below |
| Drive scope | `--drive <letter>` / `--drives <csv>` | volume scoping |
| Files/dirs only | `--files-only` / `--dirs-only` | structural filter |

### Malformed-name filter (§7 detail)

`--malformed` / `--well-formed` filter on whether the record's **leaf name
bytes are not valid UTF-8** — checked against the lossless raw name bytes,
never the lossy display string (which is always valid UTF-8 by construction
and would match nothing). `--malformed-path` is the path-derived superset.
This is a distinct axis from extension filtering entirely — it exists for
forensic/corruption-hunting use cases, not content typing.

---

## 3.1 Pattern matching (separate from `--ext`)

The main search pattern is independent of `--ext`, with three
auto-detected modes:

- **Glob** (default) — auto-detected on `*`, `?`, `[`. Supports `**` too.
- **Regex** — pattern starts with `>`, e.g. `uffs ">.*\.(rs|toml)$"`.
- **Literal substring** — no wildcards at all; matched against the full path
  (Everything/WizFile-style bare-text search).

Path-vs-name is also auto-detected: a pattern containing `\` or `/` matches
the full path; otherwise just the filename.

**A bare `*.ext`-style glob pattern is silently promoted into `--ext`** for
speed — `uffs "*.txt"` is exactly equivalent to `uffs "*" --ext txt` (it
rewrites to pattern `*` + `ext=txt` internally, so it hits the fast
extension-index path). Compound patterns like `*.tar.gz` or character classes
like `*.[ch]` are **not** promoted and stay on the general glob path. The
equivalent regex form (`>.*\.(jpg|png|heic)$`, note the required trailing
`$`) is promoted the same way into `ext=jpg,png,heic`.

Practical upshot: for a single extension, `"*.pdf"` and `--ext pdf` are
interchangeable. For multiple extensions, `--ext a,b,c` is the clean form —
there's no single-glob equivalent for "match any of these N extensions."

---

## 4. Content-export (`uffs-content::JobRequest`) — the narrower subset

`JobRequest` (`crates/uffs-content/src/job/intake.rs`) forwards **only**:

- `query` — the pattern (glob/regex/literal, same rules as §3.1)
- `ext` — same comma-separated extension list as §2.1 (aliases from §2.2/§2.3
  are **not** re-expanded on this path — only the raw `--ext`-style
  collection-alias expansion applies if the string is passed through
  unchanged; `type_filter` itself is not forwarded at all, see below)
- `min_size` / `max_size`
- `newer` / `older` — **modified-time only**; created/accessed bounds are not
  available on this path
- `exclude`
- `attr`
- `roots` — scopes to specific directories/drives (empty = every local NTFS
  drive)

Plus one export-specific field with no search analog:

- `max_content_delivery_bytes` — a candidate over this size is still
  enumerated (appears in the manifest as metadata), but its body is never
  streamed. This does not affect *which* files match — only whether their
  content gets sent.

**Not available on the content-export path at all:** `--type` semantic
categories, created/accessed-time bounds, size-on-disk, tree metrics,
descendants, name/path length, bulkiness, month, malformed-name filtering,
`--hide-system`/`--hide-ads`, sort, aggregation. If a job needs any of those,
today the only option is to pre-filter with the interactive search CLI to
confirm the candidate set, then scope the export job's `roots`/`ext`/
`min_size`/`max_size`/`newer`/`older`/`exclude`/`attr` as tightly as those
seven fields allow.

The cross-platform test/dev candidate source (`DirWalkCandidateSource`)
ignores every filter field and always matches every regular file under a
root — it exists for testing the Coordinator's own logic, not for real jobs.

---

## 5. Aggregation (`--agg`) — grouping, not filtering

`--agg <spec>` (repeatable; `--facet`/`--stats`/`--histogram`/`--count` are
shorthand expansions of it) runs **on top of** the already-filtered row set —
it groups/summarizes, it does not add or remove match criteria. Dimensions
include `type`, `extension`/`ext`, `drive`, `size`, and most other indexed
fields; kinds are `Terms`, `Stats`, `Histogram`, `DateHistogram`. Example
used earlier in this session:

```
uffs "*.txt" --drive E --agg size
```

buckets the already-`--ext txt`-filtered (via glob promotion), already-
`--drive E`-scoped rows by size range — it has no bearing on which files
were included in the first place.

---

## 6. No magic-byte / content-sniffing classification

Confirmed by direct code search: UFFS has no dependency on any content-type
sniffing library, and no code path reads a file's header bytes to determine
or correct its type. Every "magic" reference in the codebase is UFFS's own
internal binary-format signature (manifest frames, compact-cache headers, the
NTFS `FILE` record signature used by an MFT diagnostic) — none of it
classifies a *searched* or *exported* file's content type.

Practically: if a file has a `.txt` extension but is actually a renamed ZIP,
UFFS will treat it as a text file for every filter above, forever — there is
no fallback classification step. This is the one capability docenta-core has
that UFFS does not; if content-type correctness (as opposed to extension
correctness) matters for a given job, that check has to happen downstream of
UFFS, after the file is read.

---

## Appendix: source files

| Concept | File |
|---|---|
| Interactive filter struct + parsing | `crates/uffs-core/src/search/filters/mod.rs` |
| Extension-match semantics | `crates/uffs-core/src/search/filters/ext_match.rs` |
| Collection aliases (§2.2) | `crates/uffs-core/src/extensions/mod.rs` |
| Semantic type categories (§2.3) | `crates/uffs-core/src/search/derived.rs` |
| Pattern mode detection (§3.1) | `crates/uffs-core/src/pattern.rs`, `crates/uffs-core/src/pattern/parse.rs` |
| CLI flag parsing | `crates/uffs-client/src/protocol/cli_args.rs` |
| Wire params | `crates/uffs-client/src/protocol/mod.rs` (`SearchParams`) |
| Content-export job intake | `crates/uffs-content/src/job/intake.rs` (`JobRequest`) |
| Content-export filter forwarding | `crates/uffs-content/src/job/candidate_source.rs` (`VssCandidateSource`) |
| Aggregation | `crates/uffs-core/src/aggregate/`, `crates/uffs-daemon/src/index/aggregation.rs` |
