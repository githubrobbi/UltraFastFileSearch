#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025-2026 SKY, LLC.
#
# UFFS installer for macOS / Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/skyllc-ai/UltraFastFileSearch/main/install.sh | bash
#
# Downloads the prebuilt UFFS binaries for your platform from the matching
# GitHub release, verifies each against the release SHA256SUMS, and installs
# them to ~/.local/bin. No sudo, no build toolchain required.
#
# Windows users: use `winget install SkyLLC.UFFS` instead.
#
# Environment overrides:
#   UFFS_VERSION=v0.6.17        pin a version (default: latest release)
#   UFFS_INSTALL_DIR=~/bin      install location (default: ~/.local/bin)
#
# Uninstall later with `uffs --uninstall`.

set -euo pipefail

REPO="skyllc-ai/UltraFastFileSearch"
# The non-Windows family (no broker off Windows).
BINARIES=(uffs uffsd uffsmcp uffs-update uffs-mft)
INSTALL_DIR="${UFFS_INSTALL_DIR:-$HOME/.local/bin}"

# ── tiny output helpers ──────────────────────────────────────────────────────
if [ -t 1 ]; then
  C_BLUE=$'\033[0;34m'; C_GREEN=$'\033[0;32m'; C_YELLOW=$'\033[1;33m'
  C_RED=$'\033[1;31m'; C_CYAN=$'\033[36m'; C_OFF=$'\033[0m'
else
  C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_CYAN=""; C_OFF=""
fi
info() { printf '%s==>%s %s\n' "$C_BLUE" "$C_OFF" "$*"; }
err() { printf '%serror:%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; exit 1; }

# ── download / checksum helpers (curl or wget; sha256sum or shasum) ──────────
download() {
  # $1 = output path ("-" for stdout), $2 = url
  local out="$1" url="$2"
  if command -v curl >/dev/null 2>&1; then
    if [ "$out" = "-" ]; then curl -fsSL "$url"; else curl -fsSL -o "$out" "$url"; fi
  elif command -v wget >/dev/null 2>&1; then
    if [ "$out" = "-" ]; then wget -qO- "$url"; else wget -qO "$out" "$url"; fi
  else
    err "need 'curl' or 'wget' to download"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    err "need 'sha256sum' or 'shasum' to verify downloads"
  fi
}

# ── platform detection → the published asset suffix ──────────────────────────
detect_platform() {
  local os arch
  case "$(uname -s)" in
    Darwin) os="macos" ;;
    Linux) os="linux" ;;
    *) err "unsupported OS '$(uname -s)'. On Windows use: winget install SkyLLC.UFFS" ;;
  esac
  case "$(uname -m)" in
    arm64 | aarch64) arch="arm64" ;;
    x86_64 | amd64) arch="x64" ;;
    *) err "unsupported architecture '$(uname -m)'" ;;
  esac
  PLATFORM="$os-$arch"
  # Only the platforms the release actually publishes.
  case "$PLATFORM" in
    macos-arm64 | linux-x64) ;;
    *) err "no prebuilt binaries for '$PLATFORM' yet — build from source: https://github.com/$REPO" ;;
  esac
}

# ── resolve the version to install (latest, or pinned via UFFS_VERSION) ──────
resolve_version() {
  if [ -n "${UFFS_VERSION:-}" ]; then
    # Accept both `v0.6.18` and `0.6.18` — release tags carry the `v`.
    case "$UFFS_VERSION" in
      v*) VERSION="$UFFS_VERSION" ;;
      *) VERSION="v$UFFS_VERSION" ;;
    esac
    return
  fi
  info "Resolving the latest release..."
  # Fetch the WHOLE response first, then parse WITHOUT pipes. The old
  # `curl | grep -m1 | sed` died intermittently: grep -m1 closes the pipe as
  # soon as it sees tag_name (near the top of a large JSON body), the writer
  # takes SIGPIPE, and `pipefail` fails the install even though the parse
  # succeeded (curl exit 23 in the wild). Any early-exiting reader — grep -m1,
  # head, sed q — recreates it, so the parse below is pure parameter
  # expansion: zero subprocesses, zero pipes, zero SIGPIPE (and no jq).
  local body
  body="$(download - "https://api.github.com/repos/$REPO/releases/latest")" \
    || err "could not reach the GitHub releases API"
  case "$body" in
    *'"tag_name"'*) ;;
    *) err "could not resolve the latest release version \
(GitHub API rate limit? Pin one instead: UFFS_VERSION=v0.6.18)" ;;
  esac
  # `"tag_name": "vX.Y.Z"` -> cut everything through the value's opening
  # quote, then keep up to the closing quote.
  VERSION="${body#*\"tag_name\"}"
  VERSION="${VERSION#*:}"
  VERSION="${VERSION#*\"}"
  VERSION="${VERSION%%\"*}"
  [ -n "$VERSION" ] || err "could not resolve the latest release version \
(GitHub API rate limit? Pin one instead: UFFS_VERSION=v0.6.18)"
}

# ── verify one downloaded file against SHA256SUMS ────────────────────────────
verify_asset() {
  # $1 = local file, $2 = asset name (the SHA256SUMS entry), $3 = SHA256SUMS path
  local want got
  want="$(grep -E "[[:space:]][*]?$2\$" "$3" | awk '{print $1}' | head -1)"
  [ -n "$want" ] || err "no checksum for '$2' in SHA256SUMS"
  got="$(sha256_of "$1")"
  [ "$want" = "$got" ] || err "checksum mismatch for '$2' (expected $want, got $got)"
}

main() {
  detect_platform
  resolve_version

  local base="https://github.com/$REPO/releases/download/$VERSION"
  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064  # expand $tmp now so cleanup targets this dir
  trap "rm -rf '$tmp'" EXIT

  info "Installing UFFS ${C_CYAN}${VERSION}${C_OFF} (${PLATFORM}) to ${C_CYAN}${INSTALL_DIR}${C_OFF}"
  download "$tmp/SHA256SUMS" "$base/SHA256SUMS"
  mkdir -p "$INSTALL_DIR"

  # Two-phase install: download + verify EVERYTHING into the temp dir first,
  # then move the whole set into place. A failed download or checksum aborts
  # before a single file is touched, so ~/.local/bin is never left half old /
  # half new (a partial upgrade can pair an old daemon with a new CLI).
  local bin asset
  for bin in "${BINARIES[@]}"; do
    asset="$bin-$PLATFORM"
    info "  $asset"
    download "$tmp/$bin" "$base/$asset"
    verify_asset "$tmp/$bin" "$asset" "$tmp/SHA256SUMS"
    chmod +x "$tmp/$bin"
  done
  for bin in "${BINARIES[@]}"; do
    mv "$tmp/$bin" "$INSTALL_DIR/$bin"
  done

  printf '\n%s✓%s UFFS %s installed: %s\n' "$C_GREEN" "$C_OFF" "$VERSION" "${BINARIES[*]}"

  # PATH guidance — we never edit your shell rc for you (the shell owns PATH).
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
      printf '\n%sNote:%s %s is not on your PATH. Add this to your shell rc\n' \
        "$C_YELLOW" "$C_OFF" "$INSTALL_DIR"
      printf '      (~/.profile, ~/.bashrc, or ~/.zshrc), then restart your shell:\n'
      # `$PATH` is deliberately literal — it goes verbatim into the user's rc.
      # shellcheck disable=SC2016
      printf '  export PATH="%s:$PATH"\n' "$INSTALL_DIR"
      ;;
  esac

  printf '\nNext:\n'
  printf '  %suffs --version%s     check it works\n' "$C_CYAN" "$C_OFF"
  printf '  %suffs --update%s      update later\n' "$C_CYAN" "$C_OFF"
  printf '  %suffs --uninstall%s   remove everything\n' "$C_CYAN" "$C_OFF"
}

main "$@"
