// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Safe numeric conversions used across the index.
//!
//! Every cast that could truncate, wrap, or lose sign lives here rather than
//! at its call sites, so the saturating/clamping behaviour is stated once and
//! the `clippy::cast_*` expects stay in one place. Split out of `types.rs`,
//! which holds the record structs themselves.

/// Convert an FRS number (`u64`) to a `usize` index.
///
/// NTFS File Record Segment numbers are `u64` on disk, but our index uses
/// `Vec` which is addressed by `usize`. On 64-bit platforms (the only
/// supported targets) this conversion is lossless.
///
/// On hypothetical 32-bit targets, saturates to `usize::MAX` instead of
/// silently truncating.
#[inline]
#[must_use]
pub fn frs_to_usize(frs: u64) -> usize {
    usize::try_from(frs).unwrap_or(usize::MAX)
}

/// Convert a `Vec::len()` (`usize`) to a `u32` linked-list index.
///
/// The index uses `u32` for `next_entry` fields to halve memory usage
/// compared to `usize` on 64-bit. MFT indexes never exceed `u32::MAX`
/// entries (each entry is 40+ bytes → would require 160+ GB of RAM).
///
/// Saturates to `u32::MAX` if the value overflows.
#[inline]
#[must_use]
pub fn len_to_u32(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

/// Convert a `Vec::len()` (`usize`) to a `u16` count.
///
/// Used for name counts and stream counts per record, which are bounded
/// by the NTFS record size (max ~64 attributes per 4 KB record).
///
/// Saturates to `u16::MAX` if the value overflows.
#[inline]
#[must_use]
pub fn len_to_u16(len: usize) -> u16 {
    u16::try_from(len).unwrap_or(u16::MAX)
}

/// Widen a `u32` NTFS header field to `usize` for array indexing.
///
/// On any platform where `usize >= 32 bits` (all supported targets) this
/// is a lossless widening.  On hypothetical 16-bit targets it saturates.
#[inline]
#[must_use]
pub const fn u32_as_usize(val: u32) -> usize {
    val as usize
}

/// Clamp a signed NTFS field to non-negative and convert to `u64`.
///
/// NTFS data sizes and allocated sizes are stored as `i64` on disk but
/// represent non-negative byte counts.  Negative values indicate
/// corruption or uninitialised data and are clamped to `0`.
#[inline]
#[must_use]
pub const fn nonneg_to_u64(val: i64) -> u64 {
    if val > 0 {
        // `val > 0` guard makes the reinterpret lossless;
        // `i64::cast_unsigned` is the stable Rust 1.87 exact-bit-pattern
        // converter that does not require a `cast_sign_loss` expect.
        val.cast_unsigned()
    } else {
        0
    }
}

/// Convert a `u128` duration (e.g. from `Duration::as_micros()`) to `i64`.
///
/// Saturates at `i64::MAX` (year ~292,277) instead of truncating.
#[inline]
#[must_use]
pub fn micros_to_i64(us: u128) -> i64 {
    i64::try_from(us).unwrap_or(i64::MAX)
}

/// Convert a `u128` nanosecond count (e.g. from `Duration::as_nanos()`) to
/// `u64`.
///
/// Saturates at `u64::MAX` (~584 years of nanoseconds) instead of truncating.
/// Used wherever per-phase elapsed time is reported as a `u64` ns counter.
#[inline]
#[must_use]
pub fn nanos_to_u64(ns: u128) -> u64 {
    u64::try_from(ns).unwrap_or(u64::MAX)
}

/// Convert a `u128` millisecond count (e.g. from `Duration::as_millis()`) to
/// `u64`.
///
/// Saturates at `u64::MAX` (~584 million years) instead of truncating.
#[inline]
#[must_use]
pub fn millis_to_u64(ms: u128) -> u64 {
    u64::try_from(ms).unwrap_or(u64::MAX)
}

/// Convert a `usize` to `u64`.
///
/// On every supported target (`usize` ≤ 64 bits) this is a lossless widening.
/// On hypothetical >64-bit targets it saturates at `u64::MAX`.
#[inline]
#[must_use]
pub fn usize_to_u64(val: usize) -> u64 {
    u64::try_from(val).unwrap_or(u64::MAX)
}

/// Convert bytes (`u64`) to megabytes as `f64` for display purposes.
///
/// Precision loss beyond 2^53 bytes (~8 PB) is acceptable for human display.
#[inline]
#[must_use]
#[expect(
    clippy::cast_precision_loss,
    reason = "display-only: sub-byte precision irrelevant for MB/GB formatting"
)]
#[expect(clippy::float_arithmetic, reason = "display-only MB conversion")]
pub fn bytes_to_mb_f64(bytes: u64) -> f64 {
    bytes as f64 / (1_024.0_f64 * 1_024.0_f64)
}

/// Convert a `u64` to `f64` for display ratios and percentages.
///
/// Precision loss beyond 2^53 is acceptable for display.
#[inline]
#[must_use]
#[expect(
    clippy::cast_precision_loss,
    reason = "display-only: sub-unit precision irrelevant for ratios"
)]
pub const fn u64_to_f64(val: u64) -> f64 {
    val as f64
}

/// Convert a `usize` to `f64` for display ratios and percentages.
///
/// Precision loss beyond 2^53 is acceptable for display.
#[inline]
#[must_use]
#[expect(
    clippy::cast_precision_loss,
    reason = "display-only: sub-unit precision irrelevant for ratios"
)]
pub const fn usize_to_f64(val: usize) -> f64 {
    val as f64
}

/// Convert a `u32` to `f64` for display.
///
/// This is actually lossless (u32 fits exactly in f64) but provided
/// for API consistency.
#[inline]
#[must_use]
pub fn u32_to_f64(val: u32) -> f64 {
    f64::from(val)
}

/// Convert a non-negative `f64` to `u64`, clamping negative values to 0
/// and values exceeding `u64::MAX` to `u64::MAX`.
///
/// Used for memory budget calculations where floating-point arithmetic
/// produces approximate results that need to be stored as integers.
#[inline]
#[must_use]
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "centralized f64→u64 conversion for budget/estimation math; precision loss in boundary check is acceptable since u64::MAX as f64 rounds up"
)]
pub fn f64_to_u64(val: f64) -> u64 {
    if val <= 0.0 {
        0
    } else if val >= u64::MAX as f64 {
        u64::MAX
    } else {
        val as u64
    }
}

/// Convert a non-negative `f64` to `usize`, clamping negative values to 0.
///
/// Used for capacity estimation where floating-point arithmetic produces
/// approximate results that need to be stored as `usize`.
#[inline]
#[must_use]
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "centralized f64→usize conversion for capacity estimation; precision loss in boundary check is acceptable since usize::MAX as f64 rounds up"
)]
pub fn f64_to_usize(val: f64) -> usize {
    if val <= 0.0 {
        0
    } else if val >= usize::MAX as f64 {
        usize::MAX
    } else {
        val as usize
    }
}
