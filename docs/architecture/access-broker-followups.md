<!--
SPDX-FileCopyrightText: 2025-2026 SKY, LLC.
SPDX-License-Identifier: MPL-2.0
-->
# UFFS Access Broker — Follow-up Implementation Playbook

**Audience:** an engineer (junior welcome) picking up the broker hardening work
with no prior context. Everything you need to implement each item is here:
where the code lives, what to change, the gotchas, how to know you're done, and
how to test it. Read [§0 Orientation](#0-orientation) first.

**Status:** the broker's core path works end to end as of branch
`fix/broker-service-and-elevation` (verified on a Windows 11 VM, 2026-06-14): a
non-elevated `uffs "<query>"` spawns a non-elevated daemon, which obtains an
elevated volume handle from the broker, reads the MFT through it (zero UAC), and
serves queries. None of the follow-ups below block that path; each is a scoped,
root-cause improvement toward production-grade **multi-drive, resident, at-scale**
operation.

---

## Table of contents

- [0. Orientation](#0-orientation)
- [1. Tracking board](#1-tracking-board)
- [2. How to work an item](#2-how-to-work-an-item)
- [3. Shared building blocks](#3-shared-building-blocks)
- [4. The follow-ups](#4-the-follow-ups)
  - [FU-9 — Gate broker warm-up on `!is_elevated()`](#fu-9--gate-broker-warm-up-on-is_elevated)
  - [FU-2 — USN journal through the broker (+ stop the retry storm)](#fu-2--usn-journal-through-the-broker--stop-the-retry-storm)
  - [FU-3 — `get_mft_extents` through the broker (fragmented MFTs)](#fu-3--get_mft_extents-through-the-broker-fragmented-mfts)
  - [FU-8 — `$UpCase` read on the overlapped handle](#fu-8--upcase-read-on-the-overlapped-handle)
  - [FU-1 — Windows Service dispatcher](#fu-1--windows-service-dispatcher)
  - [FU-4 — `WinVerifyTrust` + Authenticode caching](#fu-4--winverifytrust--authenticode-caching)
  - [FU-5 — Async multi-instance broker + `OwnedHandle`](#fu-5--async-multi-instance-broker--ownedhandle)
  - [FU-6 — Non-connecting client pipe probe](#fu-6--non-connecting-client-pipe-probe)
  - [FU-7 — Volume-data FSCTL on the overlapped handle](#fu-7--volume-data-fsctl-on-the-overlapped-handle)
- [5. Testing strategy](#5-testing-strategy)
- [6. Suggested sequencing](#6-suggested-sequencing)
- [7. Glossary](#7-glossary)

---

## 0. Orientation

### What the broker is

A tiny, elevated Windows service (`uffs-broker`, runs as `LocalSystem`) whose
only job is to hand a non-elevated process an **already-duplicated, elevated NTFS
volume handle** over a named pipe. With that handle, the non-elevated `uffsd`
daemon can read the raw MFT — something that normally needs Administrator. This
is the standard "privilege-separation broker" pattern: keep the big, long-lived,
index-holding daemon **un**elevated, and isolate the elevation into a process
small enough to audit.

### The flow, end to end

```
uffs.exe (non-elevated CLI)
  └─ broker_pipe_present()? ── spawns ──▶ uffsd.exe (non-elevated daemon)
                                              │
        load_live_drives_if_windows() ───────┤
        warm_up_broker_handles(drives)        │  one request per drive
              │ request_volume_handle(drive)  │
              ▼                                │
  \\.\pipe\uffs-broker  ◀──────────────────────┘
   (uffs-broker.exe, LocalSystem)
     • get_pipe_client_pid → open client process ONCE
     • verify it's uffsd (name allowlist) + Authenticode
     • open_volume_read_only(drive)  → elevated overlapped volume HANDLE
     • DuplicateHandle into the daemon's process
     • write 9-byte response { status, handle }
              │
              ▼
  register_broker_handle(drive, handle)   [in uffs-mft registry]
              │
   VolumeHandle::open(drive)  ── peek_broker_handle → DuplicateHandle ─▶ MFT read
```

### The crates you'll touch

| Crate | Role | Key files for this work |
|---|---|---|
| `uffs-broker` | elevated handle vendor (the service) | `src/broker.rs`, `src/broker/service.rs`, `src/main.rs` |
| `uffs-broker-protocol` | the 1-byte request / 9-byte response wire format | `src/lib.rs` |
| `uffs-mft` | MFT reader; holds the broker-handle registry | `src/platform/volume.rs`, `src/usn/windows.rs`, `src/platform/upcase.rs`, `src/lib.rs` |
| `uffs-daemon` | resident index server; client of the broker | `src/lib.rs`, `src/broker_client.rs`, `src/cache/journal_loop.rs` |
| `uffs-client` | non-elevated launcher | `src/broker_probe.rs`, `src/daemon_spawn.rs` |

> **Design references** (gitignored, under `docs/dev/`):
> `docs/dev/architecture/DAEMON_SERVICE_ARCHITECTURE.md` (intent) and
> `docs/dev/architecture/SECURITY_IMPLEMENTATION_PLAN.md` §S5 (broker hardening,
> the `S5.x` / `WI-x` tags you'll see in code comments).

### What works today (baseline — do not regress)

- Broker installs/starts as a service (`uffs-broker --install`) and runs in
  foreground for debugging (`uffs-broker --run`).
- Pipe security lets a **non-elevated** daemon connect (SDDL
  `D:(A;;GRGW;;;AU)S:(ML;;NW;;;LW)` — Authenticated-Users connect + low
  mandatory-integrity label), while the broker still verifies client identity
  before granting.
- The daemon requests **one handle per drive** at load
  (`warm_up_broker_handles`); the broker `DuplicateHandle`s an elevated,
  overlapped volume handle in; the daemon registers it.
- `VolumeHandle::open` adopts a **duplicate** of the registered handle on every
  open (peek + `DuplicateHandle`), so the read pass, the IOCP bulk read, and the
  cache-write pass all succeed without re-requesting.

---

## 1. Tracking board

Update the **Status** cell as you go. Status legend:
`⬜ Not started` · `🟦 In progress` · `🟩 Done (merged)` · `🟥 Blocked`.
Fill **PR** with the merged PR number and **Owner** with your handle when you
pick an item up. `Depends on` must be `🟩` before you start.

| ID | Title | Priority | Effort | Status | Owner | PR | Depends on |
|----|-------|----------|--------|--------|-------|----|-----------|
| FU-9 | Gate warm-up on `!is_elevated()` | HIGH | XS | 🟩 | Robert | #404 | — |
| FU-2a | Journal-poll backoff (stop the storm) | HIGH | S | 🟩 | Robert | #407 | — |
| FU-2b | USN journal read through broker | HIGH | M | 🟩 | Robert | #408 | SBB-1 |
| FU-3 | `get_mft_extents` through broker | HIGH | M | 🟩 | Robert | #409 | SBB-1 |
| FU-8 | `$UpCase` overlapped-handle read | LOW–MED | S | 🟩 | Robert | #410 | FU-3 |
| FU-1 | Windows Service dispatcher | HIGH | M | 🟩 | Robert | #414 | — |
| FU-4 | `WinVerifyTrust` + Authenticode cache | MEDIUM | M | 🟩 | Robert | #412 | — |
| FU-5 | Multi-instance threaded broker + `OwnedHandle` | MEDIUM | L | 🟩 | Robert | #413 #415 | SBB-2 |
| FU-6 | Non-connecting client pipe probe | LOW | S | 🟩 | Robert | #411 | — |
| FU-7 | Volume-data FSCTL overlapped | LOW–MED | S | ✅ moot | Robert | — | — |

**Shared building blocks** (land these as their own PRs first; several items
depend on them — see [§3](#3-shared-building-blocks)):

| ID | Title | Status | PR |
|----|-------|--------|----|
| SBB-1 | `try_adopt_broker_handle` shared peek+duplicate in `uffs-mft` | 🟩 | #405 |
| SBB-2 | `OwnedHandle` Send-safe RAII wrapper | 🟩 | #413 |

Effort key: `XS` <1h · `S` ~half-day · `M` ~1–2 days · `L` ~3–5 days (all
including tests + a VM validation round).

---

## 2. How to work an item

1. **Branch** off `main` (after the broker branch merges) named
   `broker/fu-<id>-<slug>`, e.g. `broker/fu-9-elevation-gate`.
2. **Read the item's section** below in full, plus any `Depends on` building
   block in [§3](#3-shared-building-blocks).
3. **Follow the fix guidelines** (these are hard rules on this repo):
   - **No suppression hacks.** Do not add blanket `#[allow(...)]`, disable
     lints, comment out tests, or hide problems behind `cfg`. A targeted,
     commented `#[expect(...)]` with a `reason` is acceptable only when truly
     necessary (the codebase uses `#[expect]`, not `#[allow]`, so the lint fires
     if the suppression becomes unnecessary).
   - **Surgical, root-cause fixes.** Minimal, idiomatic Rust that fixes the
     actual ownership/type/semantics problem.
   - **Preserve public API & behavior** unless the work proves it wrong — then
     update docs + tests in the same PR.
   - **Strengthen tests, never dodge them.**
   - **Small atomic commits**, message `fix:`/`feat:`/`refactor:` naming the
     root cause. **Never** `--no-verify`; fix the failing gate at its root.
4. **The gate you must pass before pushing** (Windows-target lints — most broker
   code is `#[cfg(windows)]` and is *only* checked under this target):
   ```bash
   cargo xwin clippy --workspace --all-targets --all-features \
       --no-deps --target x86_64-pc-windows-msvc -- -D warnings
   cargo clippy --workspace --all-targets --all-features --no-deps -- -D warnings   # host
   cargo nextest run --workspace            # host-runnable tests
   just fmt                                  # rustfmt
   ```
   The pre-push hook runs `lint-fast` / `lint-pre-push`; let it. If a Windows-only
   change can't be exercised on the host, that's expected — see the VM steps in
   [§5](#5-testing-strategy).
5. **Validate on a Windows VM** for anything touching the live broker/MFT path
   (most items). The host build *cannot* exercise it. Capture the daemon log
   (`%UFFS_LOG_DIR%\uffsd.log`) and the broker terminal in the PR description.
6. **Update the tracking board** row (Status/Owner/PR) in this file as part of
   the PR.

### Watch out for (lints that bite on this codebase)

- `missing_docs_in_private_items = "deny"` — **every** item, including private
  fns/fields/consts, needs a doc comment.
- `cognitive_complexity` ceiling 25 — split big fns into helpers (you'll see
  this pattern everywhere; mirror it).
- `multiple_unsafe_ops_per_block` — **one** FFI op per `unsafe {}` block. E.g.
  `GetCurrentProcess()` and `DuplicateHandle()` go in *separate* `unsafe`
  blocks, each with its own `// SAFETY:` note.
- `unsafe_code = "deny"` at the lint level — wrap FFI in
  `#[expect(unsafe_code, reason = "FFI: …")]` with a `// SAFETY:` comment.
- `print_stdout` / `print_stderr` denied in library code (the broker `main.rs`
  is the deliberate exception — it uses `eprintln!` because there's no tracing
  subscriber yet at `--install` time).
- File-size ceiling 800 LOC (`volume.rs` already has a permanent exception entry;
  if you grow a file past the cap, extract a submodule rather than bumping the
  exception).

---

## 3. Shared building blocks

Two pieces are needed by multiple follow-ups. Build each as its own small PR so
the dependent items can just call into them.

### SBB-1 — shared broker-handle adoption primitive

> **Landed shape (differs from the original sketch below).** The first sketch
> proposed `adopt_or_open_volume(drive, access: u32) -> ResolvedVolume` — one
> function owning both the adopt and the direct-open. Reading the real code
> showed the three call sites use **genuinely different** open flags (`open()`:
> `FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE` + `BACKUP_SEMANTICS |
> SEQUENTIAL_SCAN`; USN: `GENERIC_READ` + `BACKUP_SEMANTICS`; `$MFT`: `0`
> access), so a single `access` param can't express them. Only the **adoption**
> half is truly uniform. What landed (in `crates/uffs-mft/src/platform/volume.rs`):
> - `duplicate_registered_handle(raw, drive) -> Result<HANDLE>` — the
>   `DuplicateHandle` FFI, extracted once.
> - `try_adopt_broker_handle(drive) -> Result<Option<HANDLE>>` — peek registry +
>   duplicate; `Ok(None)` means "no broker handle, caller opens directly with its
>   own flags". **This is the seam FU-2/FU-3 call.** Currently **private** (only
>   `VolumeHandle::open` uses it); FU-2/FU-3 raise it to `pub(crate)` and
>   re-export it from `platform.rs` when they wire the USN / `$MFT` paths.
> - `VolumeHandle::from_adopted_handle(handle, volume)` — descriptor read +
>   `broker_backed` construction, shared by `open()` and `from_broker_handle`.
>
> Pure refactor: no behavior change; the existing VM-validated path produces
> identical logs. Validated by the exact `cargo xwin clippy --workspace
> --all-features` gate + 219 host `uffs-mft` tests green. No host *unit* test —
> the module is `#[cfg(windows)]` FFI; its validation is cross-compile + the VM
> baseline.
>
> The original sketch is kept below for the design rationale.

**Why:** today only `VolumeHandle::open` knows the "adopt a registered broker
handle, else `CreateFileW` directly" dance. FU-2 (USN) and FU-3 (`$MFT`) need the
exact same logic. Duplicating it invites drift. Factor it once.

**Where:** `crates/uffs-mft/src/platform/volume.rs`. The registry lives here:
- `BROKER_HANDLES: OnceLock<Mutex<HashMap<char, u64>>>` (≈ line 62)
- `register_broker_handle(drive, raw_handle)` (≈ line 74, `pub`, re-exported from
  `uffs-mft/src/lib.rs:318`)
- `peek_broker_handle(drive) -> Option<u64>` (≈ line 90, private)
- the adopt logic currently inlined in `VolumeHandle::open` (≈ line 284–342) and
  `from_broker_handle` (≈ line 364)

**What to build:**

```rust
/// Result of resolving a volume handle: a duplicate of a registered broker
/// handle when one exists for `drive`, otherwise a freshly opened handle.
/// `broker_backed` tells the caller whether overlapped semantics apply (the
/// broker vends `FILE_FLAG_OVERLAPPED` handles; a direct open here does not).
#[cfg(windows)]
pub(crate) struct ResolvedVolume {
    /// Owned handle the caller must close (or wrap in `HandleGuard`).
    pub handle: HANDLE,
    /// `true` when `handle` is a duplicate of a broker-supplied overlapped handle.
    pub broker_backed: bool,
}

/// Adopt a duplicate of the registered broker handle for `drive` if present,
/// else open the volume directly with `access`. Centralises the policy so the
/// MFT read, the USN path, and the `$MFT` extent read share one implementation.
#[cfg(windows)]
pub(crate) fn adopt_or_open_volume(
    drive: super::DriveLetter,
    access: u32,          // e.g. GENERIC_READ.0, or 0 for metadata-only
) -> Result<ResolvedVolume> {
    if let Some(raw) = peek_broker_handle(drive) {
        let handle = duplicate_registered_handle(raw, drive)?;  // existing dup logic, extracted
        return Ok(ResolvedVolume { handle, broker_backed: true });
    }
    let handle = create_file_volume(drive, access)?;            // existing CreateFileW path, extracted
    Ok(ResolvedVolume { handle, broker_backed: false })
}
```

**Steps:**
1. Extract the `DuplicateHandle` block from `from_broker_handle` into
   `duplicate_registered_handle(raw_handle: u64, drive) -> Result<HANDLE>`
   (keep the two-separate-`unsafe`-blocks structure for
   `GetCurrentProcess` / `DuplicateHandle`).
2. Extract the `CreateFileW` block from `VolumeHandle::open` into
   `create_file_volume(drive, access: u32) -> Result<HANDLE>`. Keep the existing
   `InsufficientPrivileges` mapping (the access-denied → `InsufficientPrivileges`
   translation currently at ≈ line 326).
3. Add `adopt_or_open_volume` as above.
4. Rewrite `VolumeHandle::open` and `from_broker_handle` to go through it (no
   behavior change — this is a pure refactor; the existing VM-validated path must
   produce identical logs).

**Acceptance:** `VolumeHandle::open` still adopts the broker handle when present
and still falls back to direct open + `InsufficientPrivileges` when not; all
existing `uffs-mft` tests pass; `cargo xwin clippy` clean. No observable change
on the VM (same log lines as the 2026-06-14 baseline run).

### SBB-2 — `OwnedHandle` Send-safe RAII wrapper

**Why:** the broker and the daemon registry pass kernel handles around as bare
`u64` / `windows::Win32::Foundation::HANDLE`, neither of which is `Send` or
self-closing. Every call site re-implements
`with_exposed_provenance_mut(u64 as usize)` reconstruction and is on the hook for
`CloseHandle`. FU-5 (moving a connected pipe handle into a worker task) needs a
`Send` handle; everyone benefits from RAII.

**Where:** new module, e.g. `crates/uffs-mft/src/platform/owned_handle.rs`
(or a shared spot both `uffs-mft` and `uffs-broker` can see — if it must be
shared across crates, put it in `uffs-broker-protocol` or a small new
`uffs-winhandle` crate; prefer keeping it in `uffs-mft` first and only promoting
it if FU-5 genuinely needs the same type).

**What to build:**

```rust
/// Owns a Win32 kernel handle and closes it on drop.
///
/// SAFETY (Send): a Win32 kernel handle is a process-wide value with no
/// thread affinity; moving the integer between threads is sound. Concurrent
/// *use* still requires external synchronisation, exactly as with the raw API.
pub struct OwnedHandle(HANDLE);

// SAFETY: see type-level note — kernel handles have no thread affinity.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    /// Wrap a raw handle, taking ownership of its lifetime.
    pub fn from_raw(handle: HANDLE) -> Self { Self(handle) }
    /// Borrow the raw handle for an FFI call without giving up ownership.
    pub fn as_raw(&self) -> HANDLE { self.0 }
    /// Reconstruct from the `u64` wire form used by the broker protocol.
    pub fn from_u64(raw: u64) -> Self { /* with_exposed_provenance_mut */ }
    /// Release ownership (e.g. when handing to an API that closes it).
    pub fn into_raw(self) -> HANDLE { /* ManuallyDrop */ }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: we own `self.0`; closed exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}
```

**Acceptance:** `OwnedHandle` unit-tested (open a handle to a temp file via the
`windows` crate, wrap, drop, assert no leak by reopening); the registry and at
least one broker call site migrated off raw `u64`/`HANDLE` to it without behavior
change.

---

## 4. The follow-ups

Each section is self-contained. **Where** gives file/function anchors (line
numbers are "as of 2026-06-13" and will drift — trust the function names).

---

### FU-9 — Gate broker warm-up on `!is_elevated()`

**Priority: HIGH · Effort: XS · Self-inflicted regression — do this first.**

#### Why
While fixing the `ERROR_PIPE_BUSY` starvation we made `warm_up_broker_handles`
run **unconditionally**, for every daemon. Correct for killing the racy
`broker_available()` probe — but now an **elevated** daemon with no broker makes
a futile broker pipe-open **per drive**, each failing fast and logging a `WARN`
("Access Broker handle request FAILED"). On a 7-drive elevated load that's 7
pointless opens + 7 WARNs. An elevated daemon never needs the broker — it can
open volumes directly.

The MFT **read** path is *not* regressed when elevated: `VolumeHandle::open`
finds the registry empty (cheap mutex check) and falls through to direct
`CreateFileW`. Only the warm-up probe is wrong.

#### Where
- `crates/uffs-daemon/src/lib.rs` → `load_live_drives_if_windows` (≈ line 289);
  the `warm_up_broker_handles(drives)` call is at ≈ line 309.
- `uffs_mft::is_elevated` is already public and re-exported
  (`uffs-mft/src/lib.rs:307`).

#### What to change
Wrap the call:

```rust
if uffs_mft::is_elevated() {
    tracing::debug!(
        "Daemon is elevated; skipping broker warm-up (direct volume open)."
    );
} else {
    warm_up_broker_handles(drives);
}
```

That's the whole fix. `is_elevated()` is a token query — cheap, **no pipe
interaction**, and free of the race that made the old `broker_available()` probe
dangerous (it never touches the broker's single pipe instance).

> **Implementation note (landed):** the gate lives in a `#[cfg(windows)]` helper
> `warm_up_broker_handles_unless_elevated(drives)` that
> `load_live_drives_if_windows` calls once. Two reasons it's a helper rather than
> an inline `if/else` in the caller: (1) inlining the two-branch `tracing`
> block pushed `load_live_drives_if_windows` over the `cognitive_complexity`
> ceiling (32/25 under the `--workspace --all-features` Windows clippy gate —
> the scoped `-p uffs-daemon` run did **not** surface it, so always run the full
> workspace gate); extracting restores the caller below the limit. (2) The
> helper is `#[cfg(windows)]` (it calls `is_elevated` + `warm_up_broker_handles`,
> both Windows-only), so there's no `dead_code` on the host build. It is **not**
> a `should_warm_up_broker(bool)` pure wrapper — testing `!is_elevated()` adds no
> coverage; this item's real validation is the VM run (see Tests).

#### Gotchas
- `is_elevated` is Windows-only; this whole fn is already `#[cfg(windows)]`, so
  no extra gating needed.
- Don't reintroduce a pipe-touching probe — the point is to gate on the daemon's
  *own* token, not on broker presence.

#### Acceptance
- Elevated daemon (run `uffsd` from an elevated shell): **no** "Access Broker
  handle request" lines in `uffsd.log`; drives still load.
- Non-elevated daemon with broker running: unchanged — warm-up runs, handles
  register, MFT loads (the 2026-06-14 baseline).

#### Tests
- **Core (host unit):** none meaningful — the logic is a single `!is_elevated()`
  inlined into a `#[cfg(windows)]` fn; a wrapper to test the negation would only
  add `dead_code` friction on the host (see the implementation note above).
- **Edge:** N/A logic-wise; the elevation query itself isn't unit-testable
  cross-platform.
- **Manual/VM (this item's real validation):** elevated-shell run — expect a
  single `daemon is elevated — skipping broker warm-up` debug line and **no**
  `Access Broker handle request` WARNs; drives still load. Non-elevated run —
  expect `daemon not elevated — attempting broker warm-up`, handles register,
  MFT loads (the 2026-06-14 baseline). Capture both logs.

---

### FU-2 — USN journal through the broker (+ stop the retry storm)

**Priority: HIGH · Effort: M · Depends on: SBB-1.**

#### Why
Two problems, observed together on 2026-06-14:

1. **Wrong cost.** The USN journal open uses its own direct `CreateFileW`, which
   a non-elevated daemon can't do → `USN journal unavailable; full rebuild ...
   Access is denied`. The daemon then does a **full MFT rebuild** on every
   refresh instead of a cheap incremental USN read. Results are correct; the cost
   is not.
2. **Log/CPU storm.** Once a drive loads, the per-shard journal loop polls every
   ~500 ms and, on the access-denied open, logs `Journal poll failed; retrying
   next tick` **forever** — flooding the log and burning cycles.

#### Where
- USN open: `crates/uffs-mft/src/usn/windows.rs` → `open_volume_handle`
  (≈ line 128). It does a direct `CreateFileW(\\.\X:, GENERIC_READ, …,
  FILE_FLAG_BACKUP_SEMANTICS, …)`.
- USN ioctls: same file, `FSCTL_QUERY_USN_JOURNAL` (≈ line 191),
  `FSCTL_READ_USN_JOURNAL`, and `read_usn_journal` (≈ line 227).
- Retry storm: `crates/uffs-daemon/src/cache/journal_loop.rs` → `poll_blocking`
  (≈ line 540); the `Ok(Err(io_err)) =>` arm logs at ≈ line 547 and returns
  `None` every tick. The sleep/tick driver is just above (`tokio::time::sleep`).
- Loop spawn / poll interval: `crates/uffs-daemon/src/lib.rs` ≈ line 560
  ("Spawning per-shard journal loops", `poll_interval`).

#### What to change

**Part A — broker the USN handle (SBB-1).**
1. Replace the body of `open_volume_handle` with a call to
   `adopt_or_open_volume(volume, GENERIC_READ.0)` (SBB-1). USN FSCTLs operate on
   a **volume** handle, which the broker already vends — a duplicate of the
   registered handle works for `FSCTL_QUERY_USN_JOURNAL` /
   `FSCTL_READ_USN_JOURNAL`.
2. **Overlapped caveat:** the broker handle is `FILE_FLAG_OVERLAPPED`. The USN
   `DeviceIoControl` calls currently pass `None` for `OVERLAPPED`. These FSCTLs
   complete synchronously and generally tolerate a NULL overlapped, but if VM
   testing shows `ERROR_INVALID_PARAMETER` (same class as FU-7/FU-8), switch
   those `DeviceIoControl` calls to the overlapped-event + `GetOverlappedResult`
   pattern when `broker_backed` is true. Plumb `broker_backed` out of SBB-1 so
   the USN code can branch.

**Part B — stop the retry storm.**
In the journal loop, when the source repeatedly fails with access-denied (or any
persistent error), **back off** instead of hammering at the fixed
`poll_interval`. Minimal, deterministic approach:
1. Track a per-drive consecutive-failure count and a current backoff.
2. On success → reset backoff to the base `poll_interval` and log at `debug`.
3. On failure → exponential backoff (e.g. `interval * 2`) capped at a ceiling
   (e.g. 5 min). Log the **first** failure at `warn`, subsequent identical
   failures at `debug`, and emit a single `warn` "USN unavailable for drive X;
   backing off to Ns" on each backoff escalation — not one per tick.
4. Optional: if the error is specifically access-denied **and** the daemon is
   non-elevated **and** no broker handle is registered for the drive, mark USN
   "unavailable" for that drive and stop polling entirely until the next full
   reload (cleanest — no storm at all). Prefer this when SBB-1 confirms there's
   genuinely no broker handle to adopt.

#### Gotchas
- The poll runs on `spawn_blocking`; keep the backoff state in the async loop
  (the `tick` driver), not in the blocking closure.
- Don't change the cursor/save-threshold semantics — only the *cadence* and
  *logging* of failures.
- USN journal may be legitimately disabled on a volume (`ERROR_JOURNAL_NOT_ACTIVE`,
  ≈ line 176 handles this). That's distinct from access-denied; keep that branch.

#### Acceptance
- Non-elevated, broker-backed daemon: USN poll **succeeds** (incremental
  refresh), no full-rebuild-every-time, no `Access is denied` spam.
- A drive with genuinely no USN access: at most a handful of WARNs, then quiet
  (backoff/disabled) — **not** two lines per second.

#### Tests
- **Core (host unit):** a `BackoffSchedule` (or similar) pure type — assert
  base→2x→4x→…→cap progression, reset-on-success, and the "log first WARN then
  demote to debug" decision. This is the bulk of the testable logic; isolate it
  from Windows.
- **Core (host, mock source):** the journal loop already abstracts
  `JournalSource` (`Arc<dyn JournalSource>`); add a mock that returns
  `Err(access-denied)` K times then `Ok(...)`, and assert the loop backs off then
  recovers and resets. No Windows needed.
- **Edge:** error that is `ERROR_JOURNAL_NOT_ACTIVE` (should *not* be treated as
  the access-denied storm); zero-drive case; success-immediately case (backoff
  never engages).
- **Manual/VM:** non-elevated broker-backed run — confirm incremental USN poll
  works (mutate a file, see it reflected) and the log is quiet.

---

### FU-3 — `get_mft_extents` through the broker (fragmented MFTs)

**Priority: MEDIUM · Effort: M · Depends on: SBB-1.**

#### Why
`get_mft_extents` opens `<drive>:\$MFT` directly to read its retrieval pointers
(`FSCTL_GET_RETRIEVAL_POINTERS`). On open failure it **silently falls back to a
single contiguous extent** computed from `NTFS_VOLUME_DATA`
(`mft_start_lcn` + `mft_valid_data_length`). Correct for an **unfragmented** MFT;
**silently wrong for a fragmented one** — it misses every fragment past the
first, producing a partial index with no error.

On the 2026-06-14 VM the MFT happened to be contiguous (`num_extents=1`), so this
didn't bite — but we can't rely on that.

#### Where
- `crates/uffs-mft/src/platform/volume.rs` → `get_mft_extents` (≈ line 736).
  The direct `CreateFileW("<drive>:\$MFT", 0, …)` is the `let Ok(mft_handle) = …`
  block; the `else` arm is the silent single-extent fallback (≈ line 758).
- Retrieval pointers helper: `get_retrieval_pointers(mft_handle)` (called at end
  of the fn).

#### What to change
Two options — **prefer Option 2** (keeps the protocol at one handle per drive):

**Option 2 — bootstrap from the volume handle (no protocol change).**
1. Read FRS 0 (the `$MFT`'s own record) from the known MFT location using the
   **broker volume handle** we already hold (`self.handle`). The MFT byte offset
   is available (`mft_byte_offset()` / `volume_data.mft_start_lcn *
   bytes_per_cluster`); FRS 0 is the first record.
2. Parse its `$DATA` attribute runlist (there is already runlist-parsing code for
   `$UpCase` in `platform/upcase.rs::parse_data_runs` — reuse/share it) to derive
   the full extent map: `(vcn, lcn, cluster_count)` per run.
3. Return that as `Vec<MftExtent>`. This is exactly what
   `FSCTL_GET_RETRIEVAL_POINTERS` would have given us, derived from on-disk data
   we can already read through the broker handle.

**Option 1 — broker an `$MFT` handle (fallback if Option 2 is too invasive).**
Extend the protocol to vend a second handle (an `$MFT` handle the elevated broker
opens) per drive. More moving parts (protocol + registry changes); only do this
if reading FRS 0 + parsing runs proves impractical.

**Interim safety (do this regardless):** make the current fallback **loud** — log
a `warn!` "MFT extents: $MFT open failed; assuming single contiguous extent
(index may be incomplete on a fragmented MFT)" so a partial index is never
silent while Option 2 is pending.

#### Gotchas
- `$MFT` is opened with **zero** desired access (metadata only) — that *may*
  already succeed for a non-elevated caller, in which case the real pointers are
  read and the fallback never fires. **Verify on the VM which path runs** before
  assuming Option 2 is even needed; the loud-warn step tells you.
- Runlist parsing must handle multi-fragment runs and sparse/negative LCN deltas
  correctly — this is the crux; test it hard (see below).

#### Acceptance
- On a **fragmented** MFT, `get_mft_extents` returns **all** fragments (verify
  against `fsutil` / a known-fragmented test volume), not just the first.
- On a contiguous MFT, identical result to today.
- No silent partial index — any fallback is `warn`-logged.

#### Tests
- **Core (host unit):** feed `parse_data_runs` golden `$DATA` runlist byte
  vectors (contiguous; 2-fragment; 5-fragment; sparse) and assert the decoded
  `(vcn, lcn, cluster_count)` set. This is platform-agnostic and the highest-value
  test here.
- **Edge:** single-cluster MFT; run with a negative LCN delta (backwards
  fragment); a runlist with a sparse hole; truncated/malformed runlist → clean
  `MftError`, not a panic.
- **Manual/VM:** create a fragmented MFT (`fsutil` or fill+delete churn) and
  compare extent count against `fsutil file layout` for `$MFT`.

---

### FU-8 — `$UpCase` read on the overlapped handle

**Priority: LOW–MEDIUM · Effort: M.**

#### Why
Reading `$UpCase` (the NTFS uppercase table, used for case-insensitive name
comparison) does a **synchronous `SetFilePointerEx`** seek on the volume handle.
The broker handle is `FILE_FLAG_OVERLAPPED`, which has **no synchronous file
pointer** — so the seek fails. Observed 2026-06-14:

```
WARN $UpCase live read failed — falling back to compiled-in default table
     error=$UpCase: seek to offset 3221235712 failed:
           The parameter is incorrect. (0x80070057)
```

It falls back to the compiled-in default Unicode case table (correct for standard
NTFS, so search is unaffected today), but a volume with a customised `$UpCase`
would silently use the wrong table, and the WARN is noise on every broker-backed
load.

#### Where
- `crates/uffs-mft/src/platform/upcase.rs` → `read_upcase_table` (≈ line 336),
  which calls `volume_read_at` (≈ line 398) and `read_clusters`. `volume_read_at`
  does `SetFilePointerEx(handle, seek_pos, None, FILE_BEGIN)` then `ReadFile`
  (≈ line 404–415) — **this** is the failing seek.
- The fallback/WARN site: `crates/uffs-core/src/compact.rs` ≈ line 1052–1058.

#### What to change
Make the volume reads **overlapped-aware**. Preferred (Option b in the prior
notes): replace the `SetFilePointerEx` + `ReadFile` pair with an offset-carrying
overlapped read whenever the handle is overlapped:
1. Build an `OVERLAPPED` with the 64-bit `offset` split into
   `Offset` / `OffsetHigh` (and a manual-reset event in `hEvent`).
2. `ReadFile(handle, buf, len, None, Some(&mut overlapped))`; if it returns
   `ERROR_IO_PENDING`, wait and call `GetOverlappedResult`.
3. Close the event.

This matches how the MFT bulk read already addresses an overlapped handle, and
keeps the single-handle model (no extra broker handle). Apply the same treatment
to `read_clusters` (it does the same seek+read per run).

Detection: thread the `broker_backed` flag (from SBB-1 /
`VolumeHandle`) so the non-broker (elevated, synchronous) path keeps using the
simpler `SetFilePointerEx` if you prefer — or just always use the overlapped
offset form (it works on both overlapped and non-overlapped handles when you pass
the offset in `OVERLAPPED`, simplest to keep one path).

#### Gotchas
- `Offset`/`OffsetHigh` are the low/high 32 bits of the byte offset — get the
  split right (`offset as u32`, `(offset >> 32) as u32`).
- One `unsafe` op per block (event create, ReadFile, GetOverlappedResult, close —
  separate blocks).
- Don't regress the elevated/synchronous path (covered by existing
  `uffs-mft save --upcase` usage).

#### Acceptance
- Broker-backed load: `Read $UpCase table from live volume` (success), **no**
  `$UpCase live read failed` WARN.
- Elevated load: still works (no regression).

#### Tests
- **Core (host unit):** the offset-split logic (`offset → (low, high)`) as a pure
  function with boundary values (0, `0xFFFF_FFFF`, `0x1_0000_0000`,
  `3_221_235_712` from the actual failure). The parse of the 128 KB table into
  `[u16; 65_536]` already has coverage — extend if needed.
- **Edge:** offset exactly at a 4 GB boundary; a short read (fewer bytes than
  requested) → loop/again rather than silently truncate.
- **Manual/VM:** confirm the WARN is gone on a broker-backed load and the live
  table matches the compiled-in default on a standard volume (they should be
  identical on a default install — a good correctness check).

---

### FU-1 — Windows Service dispatcher

**Priority: HIGH · Effort: M.**

#### Why
`uffs-broker` implements `--install` / `--uninstall` / `--run` but has **no
service control dispatcher**. When the SCM starts the registered service it
launches the binary with **no arguments**; `run()` falls through to
`print_usage()` and exits 0. The service never calls
`StartServiceCtrlDispatcher` or reports `SERVICE_RUNNING`, so it only actually
runs in foreground `--run` mode. Without this, "install once, no future UAC
across reboots" isn't real.

#### Where
- `crates/uffs-broker/src/main.rs` (arg dispatch; `eprintln!` error path).
- `crates/uffs-broker/src/broker.rs` → `serve_pipe_requests` (≈ line 129) — the
  loop the service must drive.
- `crates/uffs-broker/src/broker/service.rs` — install/uninstall (`sc.exe`,
  `binPath=` handling). The service name lives here.

#### What to change
Implement the standard service entry point (raw `windows`-crate FFI — the crate
already depends on it; avoid the `windows-service` crate to dodge a new
cargo-vet/uffs-manifest-audit cost unless the boilerplate proves error-prone):
1. **No-arg invocation** (how the SCM launches it) →
   `StartServiceCtrlDispatcherW` with a `SERVICE_TABLE_ENTRYW` pointing at a
   `ServiceMain` callback. Keep `--run` as the foreground/debug path; both share
   `serve_pipe_requests`.
2. **`ServiceMain`** → `RegisterServiceCtrlHandlerW` (handle
   `SERVICE_CONTROL_STOP` / `SERVICE_CONTROL_SHUTDOWN`), then
   `SetServiceStatus(SERVICE_START_PENDING)` → run the serve loop →
   `SetServiceStatus(SERVICE_RUNNING)`.
3. **Stop handling:** the control handler signals the serve loop to exit (an
   `AtomicBool` / event the loop checks between connections), then
   `SetServiceStatus(SERVICE_STOPPED)` with the right `dwWin32ExitCode`.
4. Make `serve_pipe_requests` cooperatively cancellable (today it's an infinite
   `loop`). If FU-5 lands first, the async serve loop gives you a clean cancel
   token; otherwise add a stop flag checked each iteration.

#### Gotchas
- The SCM gives the service ~30 s to report `SERVICE_RUNNING` — report
  `START_PENDING` quickly, do slow setup after.
- `ServiceMain` runs on an SCM-spawned thread; the control handler on another —
  share state via atomics/events, not `&mut`.
- Logging: at service start there may be no console; ensure the tracing
  subscriber writes to the file sink (`%UFFS_LOG_DIR%`) not stdout.
- Test the **stop** path (`sc stop`) — a service that won't stop cleanly is its
  own bug.

#### Acceptance
- `sc start UffsAccessBroker` → `sc query` shows `RUNNING` with a live process;
  the pipe is served; a non-elevated daemon gets handles **after a reboot** with
  no `--run` terminal.
- `sc stop UffsAccessBroker` → clean `STOPPED`, exit code 0, process gone.

#### Tests
- **Core (host unit):** factor arg-parsing (`no args → ServiceDispatch`,
  `--run → Foreground`, `--install → Install`, …) into a pure
  `parse_mode(args) -> Mode` and unit-test it. The FFI itself isn't host-testable.
- **Edge:** unknown arg → usage + non-zero exit; double-start; stop while a
  client is mid-request (should finish or cleanly abort that connection).
- **Manual/VM:** install → reboot → confirm auto-start (`start= auto`) and a
  cold non-elevated search works with no broker terminal open; then `sc stop`.

---

### FU-4 — `WinVerifyTrust` + Authenticode caching

**Priority: MEDIUM · Effort: M.**

#### Why
`verify_authenticode` shells out to **PowerShell**
(`Get-AuthenticodeSignature`) **per request** — hundreds of ms each, plus a
hard dependency on PowerShell being present/on PATH. The daemon requests handles
**sequentially, one per drive**, so an N-drive estate pays ~N × that up front
(10 drives ≈ several seconds before any load starts). A service hot path should
never spawn PowerShell.

#### Where
- `crates/uffs-broker/src/broker.rs` → `verify_authenticode(exe_path: &str)`
  (≈ line 281). Called from `check_client_identity` (≈ line 207).
- The client process is already opened exactly once in `handle_one_connection`
  (≈ line 165, `OwnedProcessHandle::open_client`) — reuse that identity for the
  cache key.

#### What to change

**(a) Replace PowerShell with `WinVerifyTrust` (the big win).**
1. Use `windows::Win32::Security::WinTrust`. Build a `WINTRUST_FILE_INFO`
   pointing at the client image path (UTF-16), wrap it in `WINTRUST_DATA` with
   `dwUnionChoice = WTD_CHOICE_FILE`, `dwUIChoice = WTD_UI_NONE`,
   `dwStateAction = WTD_STATEACTION_VERIFY`.
2. Call `WinVerifyTrust(HWND(0)/INVALID_HANDLE_VALUE,
   &WINTRUST_ACTION_GENERIC_VERIFY_V2, &mut data)`.
3. Map the result HRESULT to the **same policy** as today:
   - `S_OK` (0) → Valid → accept.
   - `TRUST_E_NOSIGNATURE` → NotSigned → accept (dev builds), matching current
     behavior. (If policy later tightens to require signing in release, gate this
     on a build flag — but **preserve today's behavior** in this PR.)
   - `TRUST_E_BAD_DIGEST` → HashMismatch (tampered) → **reject**.
   - Other `TRUST_E_*` / `CERT_E_*` → reject (fail closed).
4. **Always** call `WinVerifyTrust` again with
   `dwStateAction = WTD_STATEACTION_CLOSE` to free the state data (do this in all
   paths — use a guard).
5. Remove the PowerShell `Command` spawn entirely.

**(b) Cache per client process.**
Key on `(pid, exe_path, image_mtime_or_hash)` so PID reuse can't smuggle a
different binary past a cached "valid". Verify once per client process; reuse for
that process's later drive requests. Lifetime = client process lifetime. Do
**not** weaken verification — only skip re-running it for an already-verified key.

#### Gotchas
- `WinVerifyTrust` FFI is unsafe + Windows-only; one op per `unsafe` block,
  `// SAFETY:` notes.
- **Fail closed** on any decode/HRESULT you don't explicitly accept. The current
  code's "PowerShell missing → allow" graceful degradation goes away (good —
  that was a soft spot); there's no external dependency to be missing now.
- The cache must make a substituted binary a **miss** — include mtime or a
  content hash, not just `(pid, path)`.
- Preserve the audit-log outcomes (`REJECTED ... Authenticode verification
  failed`) exactly.

#### Acceptance
- Signed `uffsd.exe` → accepted; unsigned dev build → accepted; a **tampered**
  binary (flip a byte) → rejected with the same audit line.
- No `powershell.exe` child process spawned (check Process Monitor / no PATH
  dependency).
- Multi-drive warm-up: one verify per client process, not per drive (visible as a
  single verify in the broker debug log).

#### Tests
- **Core (host unit):** the HRESULT→decision mapping as a pure function
  (`fn classify_trust(hr: i32) -> TrustDecision`) — table-test `S_OK`,
  `TRUST_E_NOSIGNATURE`, `TRUST_E_BAD_DIGEST`, an arbitrary `CERT_E_*`, and an
  unknown code (→ reject). High value, fully host-testable.
- **Core (host unit):** the cache key + lookup (`insert`, `hit on same key`,
  `miss on changed mtime`, `miss on changed path`).
- **Edge:** path with spaces/unicode; very large image; concurrent verifies of
  the same PID (cache must not race — guard the map).
- **Manual/VM:** sign a build, verify accept; flip a byte, verify reject; confirm
  no PowerShell spawn and the per-process single-verify.

---

### FU-5 — Async multi-instance broker + `OwnedHandle`

**Priority: MEDIUM · Effort: L · Depends on: SBB-2.**

#### Why
The broker serves a **single** pipe instance (`max_instances = 1`) in a **serial**
loop (`serve_pipe_requests`: create → wait → handle → disconnect → repeat).
Concurrent clients queue or hit `ERROR_PIPE_BUSY`. The common one-daemon flow is
fine, but genuinely concurrent load (multiple daemons, or a future parallel
warm-up) serializes — and combined with the per-request Authenticode cost
(FU-4), throughput is poor at scale. The serial design is also what made the old
client probe starve the real request (now removed; historical).

#### Where
- `crates/uffs-broker/src/broker.rs` → `serve_pipe_requests` (≈ line 129),
  `handle_one_connection` (≈ line 151), `create_broker_pipe` (≈ line 336),
  `wait_for_client` / `disconnect_and_close`. Rate-limit map is the
  `HashMap<char, Instant>` owned by `serve_pipe_requests`.

#### What to change

**Preferred — go async with tokio's named pipes.** The community-standard
scalable Windows pipe server in Rust is
[`tokio::net::windows::named_pipe`](https://docs.rs/tokio/latest/tokio/net/windows/named_pipe/)
(`ServerOptions` + `NamedPipeServer`), not a hand-rolled serial thread loop:
1. `ServerOptions::new().max_instances(N).create(PIPE_NAME)` for the first
   listener, applying the **same** security attributes (SDDL) as
   `create_broker_pipe` does today.
2. `server.connect().await`; **immediately** build the *next* listening instance
   before handling the current connection (the documented tokio accept-loop
   pattern — there's always an instance waiting, closing the "between connections
   we're deaf" gap).
3. `tokio::spawn` the per-connection handler (read request → verify identity →
   `DuplicateHandle` → write response). A connected `NamedPipeServer` is `Send`,
   so it moves into the task cleanly.
4. Share rate-limit/audit state behind `Arc<Mutex<…>>` (or an actor task that
   owns it); per-connection tasks hold `Arc` clones.

Raw-FFI multi-instance + a worker-thread pool is the fallback if pulling tokio
into the broker is unwanted, but it reintroduces the `HANDLE`-`Send` problem that
the async path avoids — which is what **SBB-2 (`OwnedHandle`)** is for.

**Pair with FU-4** so each concurrent connection isn't independently paying the
Authenticode cost.

#### Gotchas
- Keep `max_instances` bounded (DoS surface — a flood of clients shouldn't
  exhaust the system). A tuned cap (e.g. 16) is safer than `PIPE_UNLIMITED_INSTANCES`.
- The rate limiter and audit log must stay correct under parallelism — they're
  now shared mutable state.
- Don't lose the WI-8.1 invariant: open the client process **once** and use that
  same handle for verify **and** `DuplicateHandle` (PID-reuse safety). That logic
  moves into the per-connection task intact.
- Pipe security attributes must be applied to **every** instance, not just the
  first.

#### Acceptance
- Two daemons (or a scripted N parallel clients) get handles concurrently with no
  `ERROR_PIPE_BUSY` and no serialized stall.
- Single-daemon flow unchanged.
- Rate limiting still enforced per drive across concurrent connections.

#### Tests
- **Core (host unit):** the rate-limiter as a pure type (`allow(drive, now)` with
  injected time) — within-window reject, after-window allow, per-drive
  independence. Fully host-testable.
- **Core (host):** `OwnedHandle` (SBB-2) Drop/Send tests.
- **Edge:** N concurrent connections > `max_instances` (excess must queue
  cleanly, not error); a client that connects then hangs without sending (don't
  let one stuck client block others — per-connection timeout); a connection that
  drops mid-handshake (no leaked handle, audited as FAILED).
- **Manual/VM:** launch two non-elevated daemons (or a loop spawning several
  clients) and confirm concurrent grants in the audit log with interleaved PIDs.

---

### FU-6 — Non-connecting client pipe probe

**Priority: LOW · Effort: S.**

#### Why
`uffs-client`'s `broker_pipe_present` (gates the non-elevated daemon spawn) uses
`GetFileAttributesW`, which **connects to** the pipe — the broker logs a rejected
`uffs.exe` connection on every search (you can see this in the 2026-06-14 log:
`REJECTED ... exe="...uffs.exe" ... identity verification failed`). It happens
~1 s before the daemon's real request, so the single-instance broker recovers in
time and it's currently harmless, but it's wasteful and fragile under load.

#### Where
- `crates/uffs-client/src/broker_probe.rs` → `broker_pipe_present()`
  (`GetFileAttributesW`).
- Consumed by `crates/uffs-client/src/daemon_spawn.rs`
  (`spawn_unelevated_or_refuse`).

#### What to change
Switch to a **non-connecting** existence check:
- `WaitNamedPipeW(PIPE_NAME, small_timeout)` returns success/`ERROR_FILE_NOT_FOUND`
  without consuming an instance, **or**
- Accept a brief false-negative and rely on the spawn's existing fallback.

Re-evaluate after FU-5: a multi-instance broker tolerates the probe connection
cleanly, possibly making this moot — if FU-5 lands first, this may reduce to "stop
logging the probe as a rejection."

#### Gotchas
- `WaitNamedPipeW` semantics: it waits for an **instance to become available**,
  not merely for existence — pick a tiny timeout and treat
  `ERROR_FILE_NOT_FOUND` as "no broker", other errors as "assume present, let the
  real request decide".

#### Acceptance
- No `REJECTED ... uffs.exe` line in the broker audit log on a normal search.
- Daemon-spawn gating behaves identically (spawns when broker present, refuses/falls
  back when not).

#### Tests
- **Core (host unit):** the decision mapping (`probe_result → present/absent`) as
  a pure function.
- **Edge:** broker present but momentarily busy (don't false-negative into
  refusing to spawn); broker absent (clean "no broker").
- **Manual/VM:** run a search, grep the broker audit log — no `uffs.exe`
  rejection line.

---

### FU-7 — Volume-data FSCTL on the overlapped handle

**Priority: LOW–MEDIUM · Effort: S · ✅ RESOLVED — moot (no fix needed).**

> **Resolution (2026-06-14):** this was an "if it breaks, fix it" verify item.
> It does **not** break. `get_ntfs_volume_data` (`FSCTL_GET_NTFS_VOLUME_DATA`
> with a NULL `OVERLAPPED`) succeeded on the broker's `FILE_FLAG_OVERLAPPED`
> handle in **every** VM run — the daemon read valid `NtfsVolumeData`
> (`bytes_per_cluster`, `mft_start_lcn`, …) on the broker path each time, and
> the same is true of the USN FSCTLs (FU-2b). This FSCTL completes
> synchronously, so the NULL-overlapped call is fine in practice. No code
> change; closing the item. (The synchronous-completion dependence is noted
> below should a future Windows build ever regress it.)

#### Why
`get_ntfs_volume_data` issues `FSCTL_GET_NTFS_VOLUME_DATA` with a **NULL**
`OVERLAPPED`. The broker handle is `FILE_FLAG_OVERLAPPED`; per Win32 docs a
synchronous `DeviceIoControl` on an overlapped handle is technically undefined,
though this FSCTL completes synchronously and worked on the 2026-06-14 VM. Same
root cause family as FU-8. "Simple-first" was deliberate.

#### Where
- `crates/uffs-mft/src/platform/volume.rs` → `get_ntfs_volume_data(handle, volume)`
  (≈ line 405). Called from both `VolumeHandle::open` and `from_broker_handle`
  (≈ line 398).

#### What to change
Only if VM testing shows a `NotNtfs` / volume-data failure on the broker-backed
path: add an overlapped-safe variant — pass a real `OVERLAPPED` with an event and
`GetOverlappedResult`, used when the handle is overlapped (`broker_backed`).
Otherwise leave as-is and add a one-line code comment noting the dependence on
this FSCTL's synchronous completion. **Do not** speculatively complicate a path
that works; this is a "fix if it breaks" item.

#### Acceptance
- Broker-backed `from_broker_handle` reads valid `NTFS_VOLUME_DATA`
  (`bytes_per_cluster`, `mft_start_lcn`, … sane) — already true on the baseline;
  this item just hardens it if a future failure appears.

#### Tests
- **Core (host unit):** N/A (pure FFI); if you add the overlapped path, reuse the
  offset/overlapped helper from FU-8 and test that helper.
- **Manual/VM:** confirm `from_broker_handle` volume-data fields match the
  elevated direct-open values on the same volume.

---

## 5. Testing strategy

The hard constraint: **the live broker + MFT path cannot run off Windows**
(needs Windows + a real volume; the broker needs elevation). So the strategy is a
pyramid — push as much logic as possible *below* the Windows line into pure,
host-runnable units, and keep the irreducible Windows surface thin and
VM-validated.

### Layer 1 — Core unit tests (host, every PR)

Run on macOS/Linux/CI with `cargo nextest run --workspace`. For **each** item,
extract the decision logic into a pure function/type and test it here. The
recurring pattern: *"pull the policy out of the FFI."* Concretely:

- FU-9 → `should_warm_up_broker(is_elevated)`.
- FU-2 → backoff schedule + the mock-`JournalSource` loop recovery.
- FU-3 → `parse_data_runs` golden runlists (the single most valuable test in this
  whole effort — runlist decode is where fragmented-MFT correctness lives).
- FU-4 → `classify_trust(hr)` + cache key/lookup.
- FU-5 → rate-limiter with injected clock; `OwnedHandle` drop/send.
- FU-6 → probe-result → present/absent mapping.
- FU-8 → 64-bit offset → `(Offset, OffsetHigh)` split, boundary values.
- FU-1 → `parse_mode(args)`.

These must be **deterministic** (inject time, feed fixtures — no sleeps, no real
clocks, no live handles).

### Layer 2 — Edge-case units (host)

For every Layer-1 unit, add the nasty inputs. A checklist to apply per item:

- **Boundaries:** 0, max, and the exact value from a real observed failure (e.g.
  offset `3_221_235_712` for FU-8).
- **Malformed/hostile input:** truncated runlists, invalid drive bytes, unknown
  HRESULTs, non-UTF-8 — must return a structured error, **never panic** (panics
  are denied by lint anyway, but assert it).
- **Error vs. error:** distinguish *kinds* — access-denied (storm) vs.
  journal-not-active (legitimate) in FU-2; tampered vs. unsigned in FU-4.
- **Concurrency:** shared mutable state (FU-5 rate limiter, FU-4 cache) under
  parallel access — exercise with threads and assert no race/corruption.
- **Idempotency/cleanup:** every handle/event/overlapped allocated is freed on
  *all* paths including error (use RAII guards; assert no leak where feasible).

### Layer 3 — Windows host-build checks (every PR touching `#[cfg(windows)]`)

These don't *run* the logic but catch the bulk of breakage:

```bash
cargo xwin clippy --workspace --all-targets --all-features \
    --no-deps --target x86_64-pc-windows-msvc -- -D warnings
cargo xwin check  --workspace --all-targets --all-features \
    --target x86_64-pc-windows-msvc
```

Cross-compiling for `x86_64-pc-windows-msvc` compiles the Windows-only code your
host `cargo build` skips — **always** run this for broker work or you'll merge
code that doesn't compile on the only platform it runs on.

### Layer 4 — Manual VM validation (per item, before merge)

On a Windows 11 VM with the three binaries in `C:\uffs-test`:

```powershell
# Terminal A (elevated): the broker
$env:UFFS_LOG = 'debug'; $env:UFFS_LOG_DIR = 'C:\uffs-test\logs'
C:\uffs-test\uffs-broker.exe --run        # (or: sc start UffsAccessBroker once FU-1 lands)

# Terminal B (NON-elevated): a search → spawns the daemon → exercises the broker
$env:UFFS_LOG = 'debug'; $env:UFFS_LOG_DIR = 'C:\uffs-test\logs'
C:\uffs-test\uffs.exe "hallo"

# Inspect
Get-Content C:\uffs-test\logs\uffsd.log       -Tail 120
Get-Content C:\uffs-test\logs\uffs-broker.log -Tail 80
```

**Per-item VM acceptance** is listed in each section's *Acceptance*. The
universal "did not regress the baseline" check, from the 2026-06-14 known-good
run:

- broker: `AUDIT action="GRANTED" ... exe="...uffsd.exe" drive=C`.
- daemon: `Adopted Access Broker volume handle for MFT read`, `Live drive loaded
  drive=C records=...`, daemon **stays resident**, search returns rows, **no UAC
  prompt**.

Always capture **both** logs in the PR. For elevation-sensitive items (FU-9,
FU-1) run **both** an elevated and a non-elevated daemon and diff the behavior.

### What "done" means for an item

A PR is mergeable when: Layer-1/2 units cover the extracted logic (and pass on
CI), Layer-3 cross-compile is clean, the item's *Acceptance* bullets are verified
on the VM with logs attached, the tracking-board row is updated, and the fix
guidelines in [§2](#2-how-to-work-an-item) are honored (no suppression, atomic
commits, gates green without `--no-verify`).

---

## 6. Suggested sequencing

1. **FU-9** (warm-up gate) — XS, removes a live regression. Do it first.
2. **SBB-1** (`adopt_or_open_volume`) then **SBB-2** (`OwnedHandle`) — unblock the
   correctness + concurrency tiers.
3. **Correctness tier:** **FU-2** (USN through broker + backoff), **FU-3**
   (`get_mft_extents` / fragmented MFTs), **FU-8** (`$UpCase`). These remove
   silent-wrongness and log noise.
4. **Productionization tier:** **FU-1** (service dispatcher) — makes "install
   once, survive reboots" real.
5. **Performance / scale tier:** **FU-4** (`WinVerifyTrust` + cache), then **FU-5**
   (async multi-instance broker + `OwnedHandle`), then **FU-6**.
6. **Verify-if-it-breaks:** **FU-7** only if a VM run surfaces a volume-data
   failure on the broker handle.

Each item is its own atomic PR with a `fix:`/`feat:`/`refactor:` message naming
the root cause, cross-compiled clean for `x86_64-pc-windows-msvc` **and** host,
and VM-validated (the broker path can't be exercised off Windows).

---

## 7. Glossary

| Term | Meaning |
|---|---|
| **Access Broker** | The elevated `uffs-broker` service that vends NTFS volume handles to the non-elevated daemon. |
| **MFT** | Master File Table — the NTFS metadata structure UFFS reads directly instead of using file-enumeration APIs. |
| **FRS** | File Record Segment — one MFT record (FRS 0 = `$MFT` itself, FRS 10 = `$UpCase`). |
| **USN journal** | NTFS change journal; lets the daemon refresh incrementally instead of re-reading the whole MFT. |
| **Overlapped handle** | A handle opened `FILE_FLAG_OVERLAPPED` (async I/O). Has **no** synchronous file pointer, so `SetFilePointerEx` fails on it — offsets must travel in an `OVERLAPPED` struct. The broker vends overlapped handles. |
| **`DuplicateHandle`** | Win32 call that copies a handle from one process into another (how the broker injects its volume handle into the daemon). |
| **Authenticode** | Windows code-signing; the broker checks the client's signature before granting a handle. |
| **SDDL** | Security Descriptor Definition Language — the string form of the pipe's DACL/integrity label. |
| **SCM** | Service Control Manager — Windows component that starts/stops services (launches the binary with no args; see FU-1). |
| **xwin / `cargo xwin`** | Cross-compiles MSVC-target Windows binaries from macOS/Linux. The only way to compile the `#[cfg(windows)]` code off Windows. |
| **SBB** | Shared Building Block (this doc) — a prerequisite refactor several follow-ups depend on. |
