<!--
SPDX-FileCopyrightText: 2025-2026 SKY, LLC.
SPDX-License-Identifier: MPL-2.0
-->
# WinGet manifest — nested-alias seeding

The `SkyLLC.UFFS` WinGet package is **auto-submitted** to `microsoft/winget-pkgs`
by [`.github/workflows/winget-publish.yml`](../../.github/workflows/winget-publish.yml)
on every release, via `winget-releaser` (komac under the hood). The package is a
**zip → portable** installer that exposes its bundled binaries as typed commands
through `NestedInstallerFiles` / `PortableCommandAlias`.

> **✅ Seeding is now AUTOMATIC (since v0.6.3).** `winget-publish.yml` drafts the
> komac PR, runs the seeder below against the new version's manifest, pushes, and
> releases the draft — every release, no manual step. **Adding a future binary is
> a one-line edit to [`nested-aliases.yaml`](nested-aliases.yaml)** and nothing
> else. The procedure below is now the **manual fallback** (e.g. if the auto-seed
> step logs a `::warning::` for a release).

The founding manifest (`microsoft/winget-pkgs#378294`) seeded the four engine
aliases `uffs`, `uffsd`, `uffsmcp`, `uffs-mft`. Everything bundled **after** that
— currently `uffs-tui`, `uffs-broker`, and `uffs-update` (the self-update helper)
— gets its alias from this same list (`uffs-broker` + `uffs-update` first
auto-seeded in v0.6.3).

## Why this needs a one-time seed per binary

komac **preserves** the previous version's `NestedInstallerFiles` list when it
bumps the package (komac v2.14.0 — *"Preserve nested installer metadata during
version updates"*). It does **not** scan the zip and auto-add newly-bundled
executables. So a freshly-bundled binary's alias never appears on its own — it
must be added to the manifest **once**, after which komac carries it forward on
every auto-submitted release.

## Single source of truth

[`nested-aliases.yaml`](nested-aliases.yaml) is the canonical list of those
extra aliases. [`scripts/dev/winget_seed_aliases.sh`](../../scripts/dev/winget_seed_aliases.sh)
reads it and **idempotently** inserts any entry missing from a manifest. Adding
a future binary (e.g. `uffs-gui`) is a one-line edit to that yaml, never a code
change, and never a new script.

The seeder also strips the no-op top-level `Scope:` field (carried over from the
founding template) — a zip/portable installer has no install scope, so winget's
validator warns "Scope is not supported for InstallerType portable" on every
version. Removing it clears the warning; komac preserves the absence going
forward.

## Hard precondition

Only seed an alias whose binary is **actually in** `uffs-windows-x64.zip` for the
version being patched — seeding an absent file fails the winget install-validation
bot. `release.yml` bundles `uffs-tui.exe` and `uffs-broker.exe` into the Windows
`normal`/`full` tiers (`uffs-broker.exe` first shipped in **v0.5.122**), and
`uffs-update.exe` into **every** tier (min/normal/full).

Confirm before seeding:

```bash
TAG=v0.5.XXX
curl -fsSL -o /tmp/uffs.zip \
  "https://github.com/skyllc-ai/UltraFastFileSearch/releases/download/${TAG}/uffs-windows-x64.zip"
unzip -l /tmp/uffs.zip | grep -F 'uffs-windows-x64/uffs-broker.exe'   # must print a line
```

## Procedure

1. After a release, `winget-publish.yml` dispatches `winget-releaser`, which opens
   a PR to `microsoft/winget-pkgs` from the `githubrobbi/winget-pkgs` fork bumping
   `SkyLLC.UFFS` (carrying forward whatever aliases the previous manifest had).
2. Check out that PR branch on the fork and run the seeder against the new
   version's installer manifest:

   ```bash
   scripts/dev/winget_seed_aliases.sh \
     manifests/s/SkyLLC/UFFS/0.5.XXX/SkyLLC.UFFS.installer.yaml
   ```

   It adds only the aliases that are missing; already-present ones are skipped.
3. Commit + push to the PR branch, let the winget validation bot pass, and merge.
4. Verify once the package indexes:

   ```powershell
   winget install --id SkyLLC.UFFS
   uffs-broker --help
   uffs-tui --help
   ```

From then on, every release auto-keeps all aliases — no manual step until the
next *new* bundled binary.

## Pending: seed `uffs-broker` (added in v0.5.122)

The v0.5.122 winget PR (`microsoft/winget-pkgs#387341`) merged before this
contract existed, so it shipped without the `uffs-broker` alias — the binary is
in the zip, but `winget install` does not expose it as a command. Seed it on the
**next** `SkyLLC.UFFS` winget PR with the procedure above (the seeder will add
`uffs-broker` and skip the already-present `uffs-tui`).

Until then, the broker is reachable from its installed path, and the CLI's
`--elevate` flow works without it:

```powershell
# run the broker directly from the winget package dir (no alias needed yet)
& (Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\SkyLLC.UFFS_*\uffs-windows-x64\uffs-broker.exe").FullName --install
```

## Future: `uffs-gui`

When the GUI demo is bundled into the zip, add one entry to
[`nested-aliases.yaml`](nested-aliases.yaml) (`uffs-windows-x64/uffs-gui.exe` →
`uffs-gui`) and seed it on the next winget PR. No other change required.

## Defender false-positive (`Validation-Defender-Error`)

Unsigned Rust binaries recurrently trip Windows Defender's ML/heuristic
detection, which blocks the `SkyLLC.UFFS` winget-pkgs PR with the
`Validation-Defender-Error` label a few hours after a release (it has hit 0.6.18,
0.6.26, and 0.6.27). It is a **false positive**: the release bytes match the
published `SHA256SUMS`, and Microsoft's analyst has cleared prior submissions.

**When a winget PR goes red on Defender, run:**

```bash
just winget-av-submit v0.6.XX          # prep the submission
just winget-av-submit v0.6.XX --open   # prep + open the WDSI form
```

The [`av-submit.sh`](av-submit.sh) helper downloads the release's
`uffs-windows-x64.zip`, builds a password-protected archive (pw `infected`) of
exactly the binaries winget ships, and prints the submission URL
(<https://www.microsoft.com/en-us/wdsi/filesubmission>), the SHA-256s, and every
form field to paste. The WDSI submission is a manual Microsoft-account web form
(no developer API), so the final click-through is by hand.

The release build also runs a **best-effort Defender early-warning scan**
([`release.yml`](../../.github/workflows/release.yml)): if the fresh Windows
binaries scan dirty it flags the release summary and points at this command, so
the block surfaces at release time instead of from the winget PR hours later. A
clean scan is not a guarantee (winget's cloud/ML validation may differ); a hit is
a strong signal.

**Sequence after submitting:** WDSI analyst clears the detection, then the winget
re-validation needs a **moderator** (author `@wingetbot run` is privilege-denied)
— nudge the PR citing the WDSI submission id and the "no positive detection"
result, or wait for wingetbot's auto-retry, and the label lifts.

**Durable fix:** Authenticode code signing (Azure Trusted Signing) stops signed
binaries from tripping the unsigned-Rust heuristic and eliminates this drill.
