// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! UFFS Content Reader — privileged narrow Snapshot Reader.
//!
//! Spawned once per job by `uffs-content` (the Coordinator), while the
//! Coordinator is itself elevated. Opens files directly against one or
//! more leased VSS snapshot devices by NTFS file reference
//! (`OpenFileById`) and streams bounded logical byte ranges back over a
//! private named pipe (`uffs-content-reader-protocol::READER_PIPE_NAME`).
//! Not meant to be run manually outside of debugging.
//!
//! # Usage
//!
//! ```bash
//! uffs-content-reader --version
//! uffs-content-reader --device <SNAPSHOT_DEVICE_PATH>=<SNAPSHOT_LEASE_ID> [--device ...]
//! ```

// `reader::pipe_server` needs `alloc::sync::Arc`, so bring the crate
// into scope (Windows-only, matching `uffs-broker`'s own convention).
#[cfg(windows)]
extern crate alloc;

// `reader::read_plan` is cross-platform (pure logic, no I/O — see its
// own doc comment); the rest of `reader` (`logical`, `pipe_server`,
// dispatch) is `#[cfg(windows)]`-gated within the module itself, so
// this declaration stays unconditional.
mod reader;

// Used only by the Windows-only pieces of the `reader` module tree
// (`reader.rs`'s dispatch, `reader/pipe_server.rs`'s framing) — on
// non-Windows platforms this bin is a tiny `eprintln!`-only stub for
// everything except `reader::read_plan`, so this would otherwise be
// visible-but-unused. Mirrors `uffs-broker`'s / `uffs-vss-requestor`'s
// own convention (F5 / issue #205).
#[cfg(not(windows))]
use uffs_content_reader_protocol as _;

/// Parse repeatable `--device DEVICE_PATH=LEASE_ID` arguments into a
/// `snapshot_lease_id -> device_path` lookup table.
///
/// # Errors
/// Returns an error on an unknown argument, a malformed `--device`
/// value, or zero `--device` arguments (at least one is required).
#[cfg(windows)]
fn parse_device_args() -> anyhow::Result<std::collections::HashMap<u64, String>> {
    let mut devices = std::collections::HashMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--device" {
            let spec = args
                .next()
                .ok_or_else(|| anyhow::anyhow!("--device requires a DEVICE_PATH=LEASE_ID value"))?;
            let (path, lease_id_str) = spec
                .rsplit_once('=')
                .ok_or_else(|| anyhow::anyhow!("--device value '{spec}' is missing '='"))?;
            anyhow::ensure!(
                !path.is_empty(),
                "--device value '{spec}' has an empty path"
            );
            let lease_id: u64 = lease_id_str.parse().map_err(|err| {
                anyhow::anyhow!("--device value '{spec}' has an invalid lease id: {err}")
            })?;
            devices.insert(lease_id, path.to_owned());
        } else {
            anyhow::bail!("unknown argument '{arg}'");
        }
    }
    anyhow::ensure!(
        !devices.is_empty(),
        "at least one --device <PATH>=<LEASE_ID> is required"
    );
    Ok(devices)
}

#[expect(
    clippy::print_stderr,
    reason = "no tracing subscriber exists yet at this point in startup; stderr is the \
              only diagnostic channel and is captured by the spawning Coordinator"
)]
fn main() {
    uffs_version::handle_version!("uffs-content-reader");

    #[cfg(windows)]
    {
        // `.with_max_level(DEBUG)`: without an explicit level, this
        // subscriber's own default caps below `read_logical`'s per-phase
        // timing instrumentation (`tracing::debug!` in
        // `reader/logical.rs`) -- real-hardware runs confirmed zero of
        // those lines ever reached the log file despite candidates
        // actually being read, even though the binary had the
        // instrumentation built in. This is diagnostic-only: every event
        // still lands in this job's own per-run temp log file (see
        // `uffs-content::job::reader_client`), not anywhere persistent.
        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(std::io::stderr)
            .try_init();
        let result = parse_device_args().and_then(|devices| reader::run(&devices));
        if let Err(err) = result {
            eprintln!("uffs-content-reader: {err:#}");
            std::process::exit(1);
        }
    }

    #[cfg(not(windows))]
    {
        eprintln!(
            "uffs-content-reader reads VSS snapshot content and requires Windows (elevated)."
        );
        std::process::exit(1);
    }
}
