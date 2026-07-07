# uffs-time

**NTFS FILETIME arithmetic — pure `const fn`, `no_std`, zero dependencies.**

[![Crates.io](https://img.shields.io/crates/v/uffs-time.svg)](https://crates.io/crates/uffs-time)
[![Documentation](https://docs.rs/uffs-time/badge.svg)](https://docs.rs/uffs-time)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](../../LICENSE)
[![Repository](https://img.shields.io/badge/repo-skyllc--ai%2FUltraFastFileSearch-blue)](https://github.com/skyllc-ai/UltraFastFileSearch)

> **Part of [Ultra Fast File Search](https://github.com/skyllc-ai/UltraFastFileSearch).**
> UFFS is a Windows-first, high-performance file-search engine that reads the
> NTFS Master File Table directly. `uffs-time` provides its FILETIME conversion
> primitives, published standalone because any tool decoding raw NTFS
> timestamps can reuse them.

Windows stores timestamps as **FILETIME**: a 64-bit signed count of
100-nanosecond ticks since `1601-01-01 00:00:00 UTC`.  Every NTFS MFT
record carries four of them (created / modified / MFT-modified /
accessed) and any tool that reads the MFT directly needs to convert
those ticks into something humans (or downstream consumers) can use.

`uffs-time` provides the minimum-viable conversion primitives — a
calendar decomposition, a Unix-microseconds projection, and a timezone
bias adjustment — implemented as pure `const fn` over `i64` with the
calendar logic running Howard Hinnant's civil-from-days algorithm.  No
allocator, no `std`, no external crates.

## Why a dedicated crate?

The Rust time ecosystem (`chrono`, `time`, `jiff`) has no FILETIME
constructor.  `winapi` / `windows-sys` expose the raw `FILETIME` struct
but offer no high-level conversion.  In our own codebase the helpers
originally lived next to the MFT reader, which forced any caller that
just wanted to *format* a timestamp to pull in `polars`, `tokio`,
`reqwest`, and `object_store` transitively.  Splitting these few `const
fn` out into a zero-dep `no_std` crate keeps the dependency cost
proportional to what's actually being used.

The crate is small on purpose — if you need a full calendar library,
keep using `chrono` / `time` / `jiff` and convert at the boundary via
`filetime_to_unix_micros`.

## Add it

```toml
[dependencies]
uffs-time = "0.6"
```

## Usage

### High-level: the `Filetime` newtype

```rust
use uffs_time::{Filetime, CalendarParts};

// Raw FILETIME read from an MFT record (e.g. 2024-01-01 00:00:00 UTC).
let ft = Filetime::from_ticks(133_485_408_000_000_000);

assert_eq!(
    ft.to_calendar(),
    Some(CalendarParts {
        year: 2024,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    }),
);

// The documented "unset / null timestamp" sentinel.
assert_eq!(Filetime::UNSET.to_calendar(), None);
```

`Filetime` is `#[repr(transparent)]` over `i64`, so it carries zero
overhead at the NTFS-parse boundary and can be `transmute`-free from
any source that already holds raw FILETIME ticks.

### Free functions: when you already have an `i64`

The MFT parser reads FILETIME ticks straight off disk as `i64`, so the
free functions let callers skip the wrapper without losing the API:

```rust
use uffs_time::{filetime_to_calendar, filetime_to_unix_micros, CalendarParts};

let ft: i64 = 133_485_408_000_000_000;

assert_eq!(filetime_to_unix_micros(ft), 1_704_067_200_000_000);
assert_eq!(
    filetime_to_calendar(ft),
    Some(CalendarParts {
        year: 2024,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    }),
);
```

### Timezone bias

NTFS stores timestamps in UTC.  Local-time displays apply a bias in
seconds (positive = east of UTC):

```rust
use uffs_time::{Filetime, CalendarParts};

let utc = Filetime::from_ticks(133_485_408_000_000_000); // 2024-01-01 00:00 UTC

// US Pacific (UTC-8): the date rolls back into 2023-12-31.
assert_eq!(
    utc.with_tz_bias(-8 * 3600).to_calendar(),
    Some(CalendarParts {
        year: 2023, month: 12, day: 31, hour: 16, minute: 0, second: 0,
    }),
);

// India Standard Time (UTC+5:30): non-integer hour offset works.
assert_eq!(
    utc.with_tz_bias(5 * 3600 + 1800).to_calendar(),
    Some(CalendarParts {
        year: 2024, month: 1, day: 1, hour: 5, minute: 30, second: 0,
    }),
);
```

## Constants

| Constant | Value | Meaning |
|---|---|---|
| `FILETIME_TICKS_PER_SECOND` | `10_000_000` | 100-ns intervals in 1 s |
| `FILETIME_TICKS_PER_MICROSECOND` | `10` | 100-ns intervals in 1 µs |
| `FILETIME_UNIX_DIFF` | `116_444_736_000_000_000` | Ticks between 1601-01-01 (FILETIME epoch) and 1970-01-01 (Unix epoch) |

## Properties

- **Pure `const fn`** — every conversion can run at compile time.
- **`no_std`** — usable in kernel-adjacent and embedded contexts.
- **Zero dependencies** — including no `chrono` / `time` transitive cost.
- **Pre-1970 dates** — the Hinnant algorithm handles negative Unix
  micros and FILETIME values back to year ~30,828 BCE without losing
  precision.  Leap years (incl. the 1900-not-leap-year edge) are
  exercised in the test suite.
- **Sentinel-aware** — `Filetime::UNSET` (raw `0`) returns `None` from
  `to_calendar` and `0` from `to_unix_micros`, matching the NTFS
  on-disk convention.

## What this crate does *not* do

- **Parse `SYSTEMTIME` or `LARGE_INTEGER` Win32 structures.** Use
  `windows-sys` and convert via `Filetime::from_ticks(raw_i64)`.
- **Format timestamps.** Wire `filetime_to_unix_micros` into your
  favourite display crate (`chrono::DateTime::from_timestamp_micros`,
  `time::OffsetDateTime::from_unix_timestamp_nanos`, etc.).
- **Handle leap seconds.** NTFS itself doesn't model leap seconds, so
  this crate doesn't either — `second` is always `0..=59`.

## Relationship to the UFFS workspace

`uffs-time` is part of the [Ultra Fast File Search][uffs-repo]
workspace and is consumed by `uffs-mft` (raw MFT reader) and downstream
crates that need to render filesystem timestamps without pulling in
the full indexing stack.  It is published independently because the
helpers have value beyond UFFS — any tool reading raw NTFS structures
can use them.

[uffs-repo]: https://github.com/skyllc-ai/UltraFastFileSearch

## License

Licensed under the [Mozilla Public License 2.0](../../LICENSE).
