// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! UFFS Access Broker — Windows service for elevated MFT handle brokering.
//!
//! A tiny Windows service that runs elevated and provides read-only NTFS
//! volume handles to the daemon process (which runs as a normal user).
//!
//! # Usage
//!
//! ```bash
//! uffs-broker --install     # Install as Windows Service
//! uffs-broker --uninstall   # Remove Windows Service
//! uffs-broker --status      # Show state, pid, and pipe-serving status
//! uffs-broker --start       # Start the service
//! uffs-broker --stop        # Stop the service
//! uffs-broker --run         # Run in foreground (for debugging)
//! uffs-broker --version     # Print version (also -V)
//! ```
//!
//! On non-Windows platforms, every subcommand except `--version` prints an
//! error and exits.

// `broker` is gated to `#[cfg(windows)]` because the entire module
// (Win32 named-pipe service, OpenProcess, DuplicateHandle, audit log,
// Authenticode) is meaningful only on Windows.  All of its supporting
// crates (`anyhow`, `tracing-subscriber`, `windows`,
// `uffs-broker-protocol`) live in `[target.'cfg(windows)'.dependencies]`
// in `Cargo.toml`, so they don't even exist as `extern crate`s on
// non-Windows targets — the bin's non-Windows compilation produces no
// `unused_crate_dependencies` warnings without any markers.

// The workspace prefers `alloc::` over `std::` for smart pointers (clippy
// `std_instead_of_alloc`); the broker's FU-5 serve loop uses
// `alloc::sync::Arc`, so bring the crate into scope (Windows-only, like
// `broker`).
#[cfg(windows)]
extern crate alloc;

#[cfg(windows)]
mod broker;

// Snapshot lease lifecycle (VSS lease create/renew/release/query/expire),
// deliberately cross-platform-testable — see the module docs for why
// this crate makes an exception to its usual Windows-only structure for
// this one piece.
mod snapshot_lease;

#[expect(
    clippy::print_stderr,
    reason = "the --install/--uninstall paths run before any tracing subscriber \
              exists, so tracing::error! is silently dropped (a non-elevated \
              `--install` failed with NO output). stderr always reaches the operator."
)]
fn main() {
    // `--version` / `-V` is handled here, before the Windows service dispatch,
    // so it works on every platform and exits 0. The self-update version probe
    // runs `<bin> --version` and parses the output; without this the broker
    // fell through to its usage text and the probe reported the broker as `?`.
    uffs_version::handle_version!("uffs-broker");

    #[cfg(windows)]
    {
        if let Err(run_err) = broker::run() {
            // `{:#}` prints the full anyhow cause chain (e.g. the `sc`
            // stderr or the elevation-required message).
            eprintln!("uffs-broker: {run_err:#}");
            std::process::exit(1);
        }
    }

    #[cfg(not(windows))]
    {
        eprintln!("uffs-broker is a Windows-only component.");
        std::process::exit(1);
    }
}
