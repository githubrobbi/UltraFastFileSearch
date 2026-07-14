# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025-2026 SKY, LLC.

# UFFS packaging recipes: platform-native bundles + installers.
#
# These recipes wrap the thin shell scripts under `packaging/` with the
# build-release step and the status output the rest of the justfile uses.
# The heavy lifting (plist templating, freedesktop install layout) lives
# in packaging/*/ so the scripts also work outside `just`.

# Build a macOS .app bundle wrapping the release uffs binary.
#
# Output: dist/UFFS.app (dist/ is gitignored — ephemeral build output).
dist-macos:
    @printf "\033[0;34m📦 Building macOS .app bundle...\033[0m\n"
    cargo build --release -p uffs-cli
    ./packaging/macos/bundle.sh target/release/uffs dist/UFFS.app
    @printf "\033[0;32m✅ Bundle ready: dist/UFFS.app\033[0m\n"

# Install UFFS on Linux with desktop integration (requires sudo).
#
# Installs to /usr/local by default; override with `PREFIX=... just install-linux`.
install-linux:
    @printf "\033[0;34m📦 Installing UFFS + desktop integration (sudo required)...\033[0m\n"
    cargo build --release -p uffs-cli
    sudo ./packaging/linux/install.sh target/release/uffs
    @printf "\033[0;32m✅ Install complete\033[0m\n"

# Prep a WDSI Defender false-positive submission for a release's winget binaries.
#
# Use when a SkyLLC.UFFS winget-pkgs PR trips `Validation-Defender-Error`.
# Downloads the release's uffs-windows-x64.zip, builds a password-protected
# archive of the exact binaries winget ships, and prints the WDSI URL + the
# form values to paste. The submission itself is a manual web form (no dev API).
#
#   just winget-av-submit v0.6.27          # prep only
#   just winget-av-submit v0.6.27 --open   # also open the WDSI form
#   ZIP_PW=infected REPO=owner/repo just winget-av-submit v0.6.27
winget-av-submit *ARGS:
    @printf "\033[0;34m🛡️  Preparing WinGet/Defender false-positive submission...\033[0m\n"
    @bash packaging/winget/av-submit.sh {{ ARGS }}
