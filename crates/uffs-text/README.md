# uffs-text

**NTFS-bit-exact case folding via the `$UpCase` table.**

[![Crates.io](https://img.shields.io/crates/v/uffs-text.svg)](https://crates.io/crates/uffs-text)
[![Documentation](https://docs.rs/uffs-text/badge.svg)](https://docs.rs/uffs-text)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](../../LICENSE)
[![Repository](https://img.shields.io/badge/repo-skyllc--ai%2FUltraFastFileSearch-blue)](https://github.com/skyllc-ai/UltraFastFileSearch)

> **Part of [Ultra Fast File Search](https://github.com/skyllc-ai/UltraFastFileSearch).**
> UFFS is a Windows-first, high-performance file-search engine that reads the
> NTFS Master File Table directly. `uffs-text` is its case-folding component,
> published standalone because bit-exact NTFS filename comparison is useful
> well beyond UFFS.

NTFS performs every case-insensitive filename operation — directory
lookup, attribute matching, indexed binary-tree comparisons — against
its on-disk **`$UpCase`** table.  That table is a 128 KB flat array
that maps each BMP Unicode codepoint (`U+0000`–`U+FFFF`) to its
NTFS-defined uppercase equivalent.  The mapping is **not** generic
Unicode case folding; it diverges in subtle, well-documented ways and
its definition is part of the filesystem's on-disk format.

`uffs-text` exposes that table as a zero-cost `Copy` engine
([`CaseFold`]) so external code can produce filename comparisons that
**exactly agree** with what NTFS itself would return — across drives,
across machines, and across the wire.

[`CaseFold`]: https://docs.rs/uffs-text/latest/uffs_text/case_fold/struct.CaseFold.html

## Why a dedicated crate?

The Rust ecosystem already has several case-folding crates
(`caseless`, `unicode-case-mapping`, `icu_casemap`).  None of them
matches NTFS bit-for-bit:

| Crate | Source of truth | Coverage |
|---|---|---|
| `unicode-case-mapping` / `caseless` | Unicode `CaseFolding.txt` (UCD) | Generic Unicode |
| `icu_casemap` | Unicode + locale tailorings | Locale-aware |
| **`uffs-text`** | NTFS `$UpCase` (on-disk filesystem mapping) | **Filesystem-correct** |

If you're sorting or comparing filenames that came out of an NTFS
volume — or that need to round-trip back into one — using a generic
Unicode folder will produce subtly wrong answers for specific
codepoints (mostly in the Greek, Cyrillic, and Latin-extended ranges).
This crate is the right primitive for that workload.

For anything that isn't filesystem-rooted, **keep using the generic
crates above.**

## Add it

```toml
[dependencies]
uffs-text = "0.5"
```

## Usage

### Zero-alloc case-insensitive comparison

```rust
use uffs_text::case_fold::CaseFold;
use core::cmp::Ordering;

let fold = CaseFold::default_table();

// NTFS treats these as the same filename.
assert_eq!(fold.cmp_str("ReadMe.TXT", "readme.txt"), Ordering::Equal);

// Lexicographic ordering of the folded forms.
assert_eq!(fold.cmp_str("alpha", "BETA"), Ordering::Less);
```

`CaseFold` is `Copy` and ~8 bytes (one `&'static [u16]` pointer), so
passing it by value into every comparison is free.  `cmp_str` folds
lazily per codepoint and never allocates.

### Pre-folded patterns for hot-path matching

When a pattern is reused across many haystacks (e.g. a search query
applied to every filename on a 25 M-record volume), pre-fold it once
and reuse the folded codepoints:

```rust
use uffs_text::case_fold::CaseFold;

let fold = CaseFold::default_table();
let pattern = fold.fold_to_u16("config");

// Subsequent comparisons are O(n) with zero allocation.
assert!(fold.eq_folded("CONFIG", &pattern));
assert!(fold.starts_with_folded("config.toml", &pattern));
assert!(fold.ends_with_folded("app.config", &pattern));
assert!(fold.contains_folded("MyConfig.json", &pattern));
```

### Buffer-reuse folding (when you need the folded string back)

For pipelines that need the folded form as UTF-8 (e.g. logging, hash
keys), `fold_into` writes into a caller-owned `Vec<u8>` that can be
cleared and reused across iterations:

```rust
use uffs_text::case_fold::CaseFold;

let fold = CaseFold::default_table();
let mut buf = Vec::with_capacity(64);

let folded = fold.fold_into("Crème Brûlée", &mut buf);
assert_eq!(folded, "CRÈME BRÛLÉE");

// The buffer is reusable — no realloc on the next call.
let folded2 = fold.fold_into("hello", &mut buf);
assert_eq!(folded2, "HELLO");
```

### Per-codepoint fold

For custom comparison loops or building higher-level abstractions:

```rust
use uffs_text::case_fold::CaseFold;

let fold = CaseFold::default_table();
assert_eq!(fold.fold_char('a'), u16::from(b'A'));
assert_eq!(fold.fold_char('é'), u16::from('É'));
assert_eq!(fold.fold_char('A'), u16::from(b'A')); // identity
```

### Using a live `$UpCase` table from a mounted volume

Some NTFS deployments ship a customised `$UpCase` (Windows installs
have done this in the past for region-specific behaviour).  If you've
read the live table off a volume, swap it in:

```rust,no_run
use uffs_text::case_fold::CaseFold;

// `live` is a &'static [u16] of length 65_536, typically obtained by
// reading `\$UpCase` off a mounted NTFS volume into a `Vec<u16>` and
// then `Box::leak`-ing it to get the required `'static` lifetime.
fn load_live_upcase_from_volume() -> &'static [u16] {
    // 1. Open the NTFS volume (e.g. `\\.\C:`).
    // 2. Read the 128 KB `$UpCase` attribute into `Vec<u8>`.
    // 3. `bytemuck::cast_slice::<u8, u16>(&bytes).to_vec()` -> `Vec<u16>`.
    // 4. `Box::leak(boxed_slice)` to obtain the required `'static`.
    unimplemented!()
}

let live = load_live_upcase_from_volume();
let fold = CaseFold::from_ntfs(live);
let _ = fold.cmp_str("file.txt", "FILE.TXT");
```

### Diffing two tables

Useful for build-vs-runtime parity audits and for forensic comparisons
across volumes:

```rust,no_run
use uffs_text::case_fold::{CaseFold, UpcaseDiff};

let default_fold = CaseFold::default_table();
let live_fold = default_fold; // in real use, built via CaseFold::from_ntfs
let diffs: Vec<UpcaseDiff> = default_fold.diff(&live_fold);

for d in &diffs {
    println!(
        "U+{:04X}: default→{:04X}, live→{:04X}",
        d.codepoint, d.default_maps_to, d.live_maps_to,
    );
}
```

## Properties

- **`Copy` + zero-alloc** — `CaseFold` is a pointer-thin handle and
  every comparison method holds to zero heap allocations on the hot
  path.
- **Compile-time embedded table** — the 128 KB default `$UpCase` is
  shipped inside the crate via `include_bytes!`, so consumers get
  byte-identical NTFS folding without any runtime I/O.
- **BMP coverage** — every codepoint `U+0000`–`U+FFFF` has a defined
  mapping.  Supplementary planes (`U+10000+`) are pass-through; full
  surrogate-pair handling is on the i18n roadmap.
- **Bring-your-own table** — `from_ntfs` accepts any
  `&'static [u16]` of length ≥ 65 536, so live-volume `$UpCase`
  variants slot in cleanly.

## What this crate does *not* do

- **Generic Unicode case folding.** Use [`caseless`][caseless],
  [`unicode-case-mapping`][ucm], or [`icu_casemap`][icu] when you
  want UCD-defined behaviour, not NTFS-defined behaviour.
- **Normalisation (NFC/NFD).** Decomposition is on the i18n roadmap;
  for now reach for [`unicode-normalization`][un].
- **Collation.** No locale-aware ordering — comparisons fall back to
  folded-codepoint numeric order.

[caseless]: https://crates.io/crates/caseless
[ucm]: https://crates.io/crates/unicode-case-mapping
[icu]: https://crates.io/crates/icu_casemap
[un]: https://crates.io/crates/unicode-normalization

## Relationship to the UFFS workspace

`uffs-text` is part of the [Ultra Fast File Search][uffs-repo]
workspace and is published independently because the case-folding
engine has value beyond UFFS — any tool that needs filename
comparisons to agree bit-for-bit with NTFS can use it.

[uffs-repo]: https://github.com/skyllc-ai/UltraFastFileSearch

## License

Licensed under the [Mozilla Public License 2.0](../../LICENSE).
