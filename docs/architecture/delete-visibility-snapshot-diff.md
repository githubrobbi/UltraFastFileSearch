<!--
SPDX-License-Identifier: MPL-2.0
Copyright (c) 2025-2026 SKY, LLC.
-->

# Delete visibility for the `--newer` fallback (snapshot diff + tombstone read)

**Status:** design sketch / proposed slice
**Motivating gap:** the `--newer` (timestamp) delta path can report files
*created or modified* after a date, but it is structurally blind to
*deletions*. A deleted file simply stops appearing; a timestamp cannot express
"this is gone." The native USN path does not have this problem because
`FILE_DELETE` is an explicit journal reason. Slice 8.6 (delete reconciliation)
exists today purely to paper over this with a periodic full walk. This note
proposes turning that blind spot into a first-class, deterministic capability.

## Why timestamps cannot do it

Timestamps are append-only facts about a file that *exists*. Deletion removes
the file, taking its timestamp with it, so there is no value left to compare
against a `--newer <date>` threshold. To recover delete visibility without the
USN journal you need one of two things UFFS can already produce from the MFT:

1. **Two states to compare** (a prior full read vs the current one), or
2. **The corpse of the record itself** (NTFS leaves deleted records behind
   until their slot is reused).

## Background: FRS vs sequence number (the File Reference)

These are two different fields, and the distinction is the crux of reliable
delete detection.

- **FRS** (File Record Segment number) — *which slot* in the MFT the record
  occupies (the record index). When a file is deleted, its slot is later
  recycled and the new file gets the **same FRS**.
- **sequence_number** — a `u16` in the record header (offset `0x10`) that NTFS
  **increments every time it reallocates that slot**. It identifies *which
  generation* of the slot you are looking at.
- Together they form the 64-bit **File Reference**:
  `(sequence_number << 48) | FRS`. This is how directory entries point at their
  children, and why a stale reference to a recycled slot is detectable — the
  sequence number will not match.

`ParsedRecord` (`crates/uffs-mft/src/parse/types.rs`) already carries both
`frs` and `sequence_number` (documented there as "incremented when FRS is
reused"). FRS alone cannot tell "same file" from "slot reused by a different
file"; **`(FRS, sequence_number)` can**, and that is what makes delete-vs-reuse
unambiguous.

## Mechanism 1 — Snapshot diff (primary, deterministic)

UFFS already reads the *entire* MFT into a persisted compact index
(`crates/uffs-core/src/compact_cache.rs`). Retain the prior index as a baseline
and set-difference the next full read by stable identity:

| Class | Predicate |
|-------|-----------|
| **Deleted** | key in baseline, absent in current |
| **Added** | key in current, absent in baseline |
| **Modified** | same key, changed `size` / `written` timestamp |

**Key = File Reference `(frs, sequence_number)`.** Keying on FRS alone would
misclassify a delete-then-reuse of the same slot as a "modify." The sequence
number makes it exact: if `(frs=N, seq=3)` is in the baseline and the current
read has `(frs=N, seq=4)`, that is a **delete of seq 3 plus an add of seq 4**,
not a modification.

### The one real gap

The compact index parses `sequence_number` but does not appear to **persist**
it (the cache keys on frs / name / parent). Persisting it is a cheap ~2
bytes/record and is the only prerequisite that makes the diff reuse-safe.
Without it, a fallback diff can still key on `(frs, name, parent)` — correct
for the common case, but unable to distinguish slot reuse cleanly.

### It reuses the existing tombstone model

`crates/uffs-mft/src/flags.rs` already defines
`FileFlags::DELETED = 0x8000` ("UFFS internal flag for USN tracking; bit 15
reserved in NTFS"). The index *already models* a deleted tombstone, and the USN
path already sets it. The snapshot diff would set the **same** flag on the
fallback path, so the query surface (`--deleted`, projections) is largely
pre-built — the fallback simply is not feeding it yet. This is slice 8.6's
periodic reconciliation promoted from an internal daemon-consistency chore into
a user-facing "what was deleted since snapshot N" answer.

## Mechanism 2 — Tombstone read (forensic bonus, single scan)

When NTFS deletes a file it clears the record's in-use flag and the `$MFT`
allocation bitmap bit, but the record's bytes (name, parent, timestamps)
survive until the slot is reallocated. UFFS already reads that bitmap
(`bitmap.count_in_use()` throughout `crates/uffs-mft/src/reader/`), so it can
surface the **allocated-in-MFT-but-marked-not-in-use** records as
recently-deleted tombstones from a single scan, with no baseline required. This
is the forensic-flow direction.

Honest limits (why this complements, and does not replace, Mechanism 1):

- **Best-effort.** Slots recycle non-deterministically, so you see only
  *recent* deletes, not a complete set.
- **No true deletion time.** The timestamps are the file's own (last written,
  etc.), not when it was deleted.
- **Paths may be unresolvable** if the parent directory was itself deleted or
  its slot reused.

Great as "recently deleted, possibly recoverable"; not a reliable delete-delta.

## Tradeoff vs USN

Snapshot diff is **coarser** than USN: it reports the *net* delete between two
scans, not every intermediate delete the way USN's continuous log does, and it
costs a full read plus a retained baseline. But it is **reliable and
journal-free**, which is exactly what the `--newer` fallback needs (offline
captures, non-Windows, wrapped/disabled journal). USN stays the gold path where
available; this is the fallback's missing half.

## Proposed slice (phased, minimal-viable first)

**Phase 1 — persist identity.** Add `sequence_number: u16` to the compact
record and its serialization (`compact_cache.rs` + the column layout in
`uffs-polars::columns`). Pure data-plumbing; no behavior change yet.

**Phase 2 — the diff engine.** A pure function
`fn diff_indexes(baseline, current) -> DeltaReport { added, modified, deleted }`
keyed on `(frs, sequence_number)`. Deterministic, unit-testable against
synthetic index pairs. Deleted entries carry the baseline's path + metadata and
set `FileFlags::DELETED`.

**Phase 3 — surface it.** A CLI entry point (`uffs diff <baseline>` or a
`--deleted-since` flag on the existing search) that runs a full read, diffs
against the retained baseline, and emits the delta (reusing the existing
`--deleted` projection path). The daemon's slice-8.6 reconciliation becomes a
consumer of the same engine.

**Phase 4 (optional) — tombstone view.** A `--recently-deleted` / forensic flag
that surfaces not-in-use records from a single scan, clearly labelled
best-effort, tying into the forensic-flow feature.

## Testing

- **Phase 2** is the high-value, fully-deterministic target: build two
  synthetic compact indexes (a baseline and a mutated current) covering pure
  add, pure delete, in-place modify, and the tricky **delete-then-reuse of the
  same FRS** (same `frs`, bumped `seq`), and assert the `DeltaReport`
  classifies each correctly. This is exactly the case FRS-only keying gets
  wrong, so it is the anchor test.
- Golden round-trip: persist a baseline, reload, diff against an unchanged
  current → empty delta (no false deletes from serialization drift).
- Tombstone read: fixture MFT with a not-in-use record whose parent is intact
  (resolvable) and one whose parent is also freed (unresolvable path) → assert
  both are surfaced with the right resolvability.

## Open questions

- **Baseline retention policy** — reuse the existing on-disk compact cache as
  the baseline, or keep a dedicated "last reconciled" snapshot per drive?
- **Whether Phase 1 (persisting `sequence_number`) belongs to this slice or a
  prior index-format bump**, given it touches the cache format.
- **Surface naming** — `--deleted-since <snapshot>` vs a standalone `uffs diff`
  subcommand; the latter reads more naturally for the "two states" model.
