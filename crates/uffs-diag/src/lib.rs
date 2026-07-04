// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! UFFS Diagnostic Tools Library
//!
//! This crate provides diagnostic tools for MFT analysis. The library portion
//! exposes shared modules used by the diagnostic binaries.

// Keep dependencies wired in for version-locking, even though the library
// portion does not use them directly (the binaries do).
// Linked for this crate's diagnostic binaries, which call
// `uffs_version::handle_version!` in `main`; the library does not use it.
use anyhow as _;
use chrono as _;
use hex as _;
use rayon as _;
use sha2 as _;
use uffs_mft as _;
use uffs_polars as _;
use uffs_version as _;

/// Parity comparison helpers for validating scan output between reference and
/// Rust implementations.
pub mod parity;

/// Windows-only helpers for inspecting the full uffs-mft raw->fixup->parse
/// pipeline for a single FRS.
#[cfg(windows)]
pub mod uffs_mft_helpers_windows;
