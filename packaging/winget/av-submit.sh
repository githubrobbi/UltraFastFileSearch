#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025-2026 SKY, LLC.
#
# UFFS — WinGet / Defender false-positive submission helper.
#
# When a release's winget-pkgs PR trips `Validation-Defender-Error` (the
# recurring unsigned-Rust-binary ML false positive), this scripts gets a WDSI
# (Microsoft Security Intelligence) false-positive submission to the doorstep:
#
#   1. Downloads the release's `uffs-windows-x64.zip` — the EXACT archive the
#      winget package installs — for the given tag.
#   2. Builds a password-protected zip of *whatever binaries that archive
#      actually contains* (so the submission never drifts from the real bin set;
#      e.g. it correctly includes uffs-tui.exe when the release bundles it).
#   3. Prints per-binary + archive SHA-256.
#   4. Prints the WDSI URL and the exact form-field values to paste.
#
# The WDSI submission itself is an interactive Microsoft-account web form with
# no developer API, so the final click-through stays manual. This script does
# everything up to that click.
#
# Usage:
#   packaging/winget/av-submit.sh <tag> [--open]
#   just winget-av-submit v0.6.27
#
# Env overrides:
#   REPO    GitHub repo to pull the release from (default: skyllc-ai/UltraFastFileSearch)
#   ZIP_PW  password for the submission archive (default: infected)

set -euo pipefail

TAG="${1:-}"
OPEN_BROWSER=0
[[ "${2:-}" == "--open" ]] && OPEN_BROWSER=1

REPO="${REPO:-skyllc-ai/UltraFastFileSearch}"
ZIP_PW="${ZIP_PW:-infected}"
WDSI_URL="https://www.microsoft.com/en-us/wdsi/filesubmission"
WINGET_ZIP="uffs-windows-x64.zip"

# sha256 helper (macOS: shasum; Linux: sha256sum).
sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else sha256sum "$1" | awk '{print $1}'; fi
}

# Resolve tag (default to latest published release).
if [[ -z "$TAG" ]]; then
  TAG="$(gh release view --repo "$REPO" --json tagName -q .tagName 2>/dev/null || true)"
  [[ -n "$TAG" ]] && echo "ℹ️  No tag given; using latest release: $TAG"
fi
[[ -z "$TAG" ]] && { echo "❌ usage: av-submit.sh <tag> [--open]" >&2; exit 2; }

VERSION="${TAG#v}"
WORK="dist/winget-av-submit/${TAG}"
BINS="${WORK}/bins"
OUT="${WORK}/uffs-${TAG}-winget-binaries.zip"

rm -rf "$WORK"; mkdir -p "$BINS"

echo "📥 Downloading ${WINGET_ZIP} from ${REPO}@${TAG} ..."
gh release download "$TAG" --repo "$REPO" --pattern "$WINGET_ZIP" --dir "$WORK" --clobber

echo "📦 Extracting the executables the winget package actually ships ..."
# -j junks the `uffs-windows-x64/` prefix; the `*.exe` filter drops any bundled
# docs/brand files so only the binaries Defender flags go into the submission.
unzip -o -j "${WORK}/${WINGET_ZIP}" '*.exe' -d "$BINS" >/dev/null

shopt -s nullglob
EXE_PATHS=("${BINS}"/*.exe)
shopt -u nullglob
[[ ${#EXE_PATHS[@]} -eq 0 ]] && { echo "❌ no .exe found inside ${WINGET_ZIP}" >&2; exit 1; }
mapfile -t EXES < <(for p in "${EXE_PATHS[@]}"; do basename "$p"; done | sort)

echo "🔐 Building password-protected submission archive (pw: ${ZIP_PW}) ..."
rm -f "$OUT"
( cd "$BINS" && zip -q -P "$ZIP_PW" -j "../$(basename "$OUT")" ./*.exe )

ARCHIVE_SHA="$(sha256 "$OUT")"

# ── Report ──────────────────────────────────────────────────────────────
cat <<EOF

════════════════════════════════════════════════════════════════════════
 UFFS WinGet Defender false-positive submission — ${TAG}
════════════════════════════════════════════════════════════════════════

📎 ARCHIVE (upload this):
   $(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")
   password : ${ZIP_PW}
   sha256   : ${ARCHIVE_SHA}
   contains : ${#EXES[@]} binaries

🔢 PER-BINARY SHA-256 (for VirusTotal lookups):
EOF
for e in "${EXES[@]}"; do printf '   %-22s %s\n' "$e" "$(sha256 "${BINS}/${e}")"; done

cat <<EOF

🔗 SUBMISSION URL:
   ${WDSI_URL}
   Sign in (as the maintainer's Microsoft account) → submission type "Software developer".

📝 FORM FIELDS:
   File .................. the archive above
   Archive password ..... ${ZIP_PW}
   "What is this file?" .. I believe this file is clean (false positive)
   Detection name ....... Program:Win32/Wacapew.C!ml   (best guess for unsigned Rust ML FP;
                          use the real one from Protection history if you have it, else "Unknown")
   Definition version ... read the real value on the flagging Windows box:
                            Get-MpComputerStatus | Format-List AntivirusSignatureVersion
   Company / Product .... SKY, LLC / UFFS (Ultra Fast File Search) ${VERSION}
   Contact email ........ the maintainer dev contact

📄 CONTEXT BLURB (paste into "Additional information"):
   Open-source Rust command-line tool. These are unsigned release builds published
   on GitHub Releases and distributed via winget (package id SkyLLC.UFFS). They are
   flagged by ML/heuristic detection purely because they are unsigned native Rust
   executables; there is no malicious behavior. Source + reproducible pipeline:
   https://github.com/${REPO}/releases/tag/${TAG} . Authenticode signing is the
   durable fix (in progress). Requesting correction for all binaries in the archive.

ℹ️  After WDSI clears it, the winget re-validation of the SkyLLC.UFFS PR needs a
   MODERATOR (author @wingetbot run is privilege-denied). Nudge the PR citing the
   WDSI submission id + "no positive detection", or wait for wingetbot auto-retry.
════════════════════════════════════════════════════════════════════════
EOF

if [[ "$OPEN_BROWSER" -eq 1 ]]; then
  if command -v open >/dev/null 2>&1; then open "$WDSI_URL";
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$WDSI_URL"; fi
fi
