// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! The VDL/EOF zero-synthesis rule as a pure, allocation-free function.
//!
//! Per `uffs-ingest-implementation-plan.md` §5.1 point 4 (design-doc
//! §6.2):
//!
//! ```text
//! 0 <= offset < min(VDL, EOF)   -> real bytes
//! VDL <= offset < EOF           -> zeros
//! offset >= EOF                 -> nothing
//! ```
//!
//! Deliberately platform-independent — no file handle, no I/O — so it
//! runs on every CI lane and is exhaustively unit-testable. This is
//! "the single highest-value unit-test target in the whole Reader"
//! per the implementation plan.
//!
//! Its only real (non-test) caller, `super::logical`, is
//! `#[cfg(windows)]` — so on every other platform this module is
//! genuinely unused outside its own tests, permanently (not "deferred
//! until wired up" the way other dead-code states in this workspace
//! are). The `expect(dead_code)` attributes below reflect that on
//! purpose rather than silently suppressing an oversight.

/// A validated request range rejected before any read is attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(
    all(not(windows), not(test)),
    expect(
        dead_code,
        reason = "only real (non-test) caller is #[cfg(windows)]; see module doc"
    )
)]
pub(crate) enum ReadPlanError {
    /// `vdl > eof` is never valid NTFS metadata — valid data length can
    /// never exceed the file's own end-of-file. Reject rather than
    /// silently clamp: this signals a Reader-side bug (or a stale/
    /// mismatched handle) worth surfacing, not papering over.
    #[error("invalid metadata: valid data length {vdl} exceeds end of file {eof}")]
    InvalidMetadata {
        /// The (invalid) valid data length.
        vdl: u64,
        /// The (invalid, smaller-than-`vdl`) end of file.
        eof: u64,
    },
}

/// How to satisfy one `(vdl, eof, offset, requested_len)` read request:
/// read `real_bytes` from the file at `offset`, then synthesize
/// `zero_bytes` immediately after. Both may be zero. `real_bytes +
/// zero_bytes <= requested_len` always holds (see
/// [`read_plan`]'s invariant tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    all(not(windows), not(test)),
    expect(
        dead_code,
        reason = "only real (non-test) caller is #[cfg(windows)]; see module doc"
    )
)]
pub(crate) struct ReadPlan {
    /// Bytes to read from the real file, starting at `offset`.
    pub real_bytes: u32,
    /// Zero bytes to synthesize immediately after `real_bytes`.
    pub zero_bytes: u32,
}

impl ReadPlan {
    /// Total bytes this plan produces (`real_bytes + zero_bytes`).
    #[must_use]
    #[cfg_attr(
        all(not(windows), not(test)),
        expect(
            dead_code,
            reason = "only real (non-test) caller is #[cfg(windows)]; see module doc"
        )
    )]
    pub(crate) const fn total_len(self) -> u32 {
        self.real_bytes + self.zero_bytes
    }
}

/// Resolve a logical read request against a file's `vdl` (valid data
/// length) and `eof` (end of file) into a [`ReadPlan`].
///
/// # Errors
/// Returns [`ReadPlanError::InvalidMetadata`] if `vdl > eof` — this
/// combination can never legitimately occur and must never be trusted
/// enough to compute a plan from.
#[cfg_attr(
    all(not(windows), not(test)),
    expect(
        dead_code,
        reason = "only real (non-test) caller is #[cfg(windows)]; see module doc"
    )
)]
pub(crate) const fn read_plan(
    vdl: u64,
    eof: u64,
    offset: u64,
    requested_len: u32,
) -> Result<ReadPlan, ReadPlanError> {
    if vdl > eof {
        return Err(ReadPlanError::InvalidMetadata { vdl, eof });
    }

    if offset >= eof || requested_len == 0 {
        return Ok(ReadPlan {
            real_bytes: 0,
            zero_bytes: 0,
        });
    }

    // `offset < eof` here, so this subtraction never underflows.
    let available_to_eof = eof - offset;
    let requested_len_u64 = requested_len as u64;
    let capped_len = if available_to_eof < requested_len_u64 {
        available_to_eof
    } else {
        requested_len_u64
    };
    // `capped_len <= requested_len_u64 <= u32::MAX`, so this cast is
    // always exact — no `as` truncation risk despite the lack of a
    // `try_into` (this function is `const fn`, which `TryFrom` doesn't
    // support as of this edition).
    #[expect(
        clippy::cast_possible_truncation,
        reason = "capped_len <= requested_len (u32) by construction above"
    )]
    let capped_len_u32 = capped_len as u32;

    if offset >= vdl {
        // Entirely within the zero region `[vdl, eof)`.
        return Ok(ReadPlan {
            real_bytes: 0,
            zero_bytes: capped_len_u32,
        });
    }

    // `offset < vdl` here, so this subtraction never underflows.
    let real_available = vdl - offset;
    let real_len = if real_available < capped_len {
        real_available
    } else {
        capped_len
    };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "real_len <= capped_len_u32 by construction above"
    )]
    let real_len_u32 = real_len as u32;

    Ok(ReadPlan {
        real_bytes: real_len_u32,
        zero_bytes: capped_len_u32 - real_len_u32,
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{ReadPlan, ReadPlanError, read_plan};

    #[test]
    fn offset_zero_within_vdl_is_all_real_bytes() {
        let plan = read_plan(100, 100, 0, 50).expect("valid metadata");
        assert_eq!(plan, ReadPlan {
            real_bytes: 50,
            zero_bytes: 0
        });
    }

    #[test]
    fn offset_at_eof_is_empty() {
        let plan = read_plan(100, 100, 100, 50).expect("valid metadata");
        assert_eq!(plan, ReadPlan {
            real_bytes: 0,
            zero_bytes: 0
        });
    }

    #[test]
    fn offset_past_eof_is_empty() {
        let plan = read_plan(100, 100, 500, 50).expect("valid metadata");
        assert_eq!(plan, ReadPlan {
            real_bytes: 0,
            zero_bytes: 0
        });
    }

    #[test]
    fn offset_exactly_at_vdl_is_all_zeros() {
        // vdl=60, eof=100: offset==vdl starts the zero region exactly.
        let plan = read_plan(60, 100, 60, 20).expect("valid metadata");
        assert_eq!(plan, ReadPlan {
            real_bytes: 0,
            zero_bytes: 20
        });
    }

    #[test]
    fn offset_in_zero_region_is_all_zeros_capped_at_eof() {
        // vdl=60, eof=100, offset=80, requested 50 -> only 20 bytes
        // remain before eof, all zeros.
        let plan = read_plan(60, 100, 80, 50).expect("valid metadata");
        assert_eq!(plan, ReadPlan {
            real_bytes: 0,
            zero_bytes: 20
        });
    }

    #[test]
    fn range_spanning_vdl_eof_boundary_splits_real_then_zero() {
        // vdl=60, eof=100, offset=50, requested 40 -> 10 real bytes
        // (50..60) then 30 zero bytes (60..90).
        let plan = read_plan(60, 100, 50, 40).expect("valid metadata");
        assert_eq!(plan, ReadPlan {
            real_bytes: 10,
            zero_bytes: 30
        });
    }

    #[test]
    fn range_spanning_vdl_and_eof_is_capped_at_eof() {
        // vdl=60, eof=100, offset=50, requested 1000 -> capped at eof:
        // 10 real (50..60) + 40 zero (60..100).
        let plan = read_plan(60, 100, 50, 1000).expect("valid metadata");
        assert_eq!(plan, ReadPlan {
            real_bytes: 10,
            zero_bytes: 40
        });
    }

    #[test]
    fn zero_length_file_is_always_empty() {
        let plan = read_plan(0, 0, 0, 100).expect("valid metadata");
        assert_eq!(plan, ReadPlan {
            real_bytes: 0,
            zero_bytes: 0
        });
    }

    #[test]
    fn zero_requested_len_is_always_empty() {
        let plan = read_plan(100, 100, 0, 0).expect("valid metadata");
        assert_eq!(plan, ReadPlan {
            real_bytes: 0,
            zero_bytes: 0
        });
    }

    #[test]
    fn vdl_equal_eof_never_produces_zero_bytes() {
        // No sparse tail at all: every in-bounds read is pure real bytes.
        let plan = read_plan(100, 100, 10, 50).expect("valid metadata");
        assert_eq!(plan, ReadPlan {
            real_bytes: 50,
            zero_bytes: 0
        });
    }

    #[test]
    fn vdl_greater_than_eof_is_rejected() {
        let err = read_plan(100, 50, 0, 10).expect_err("vdl > eof must be rejected");
        assert_eq!(err, ReadPlanError::InvalidMetadata { vdl: 100, eof: 50 });
    }

    #[test]
    fn total_len_never_exceeds_requested_len() {
        for (vdl, eof, offset, requested_len) in [
            (0_u64, 0_u64, 0_u64, 10_u32),
            (0, 100, 0, 10),
            (50, 100, 0, 200),
            (50, 100, 49, 5),
            (50, 100, 50, 5),
            (50, 100, 99, 5),
            (50, 100, 100, 5),
            (50, 100, 1000, 5),
        ] {
            let plan = read_plan(vdl, eof, offset, requested_len).expect("valid metadata");
            assert!(
                plan.total_len() <= requested_len,
                "plan {plan:?} exceeds requested_len {requested_len} for \
                 (vdl={vdl}, eof={eof}, offset={offset})"
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        /// Core invariant, fuzzed: whenever metadata is valid (`vdl <=
        /// eof`), the plan's total length never exceeds either the
        /// caller's requested length or the bytes actually remaining
        /// before `eof`.
        #[test]
        fn total_len_is_bounded_for_arbitrary_valid_inputs(
            vdl in 0_u64..1_000_000,
            extra_to_eof in 0_u64..1_000_000,
            offset in 0_u64..2_000_000,
            requested_len in 0_u32..1_000_000,
        ) {
            let eof = vdl + extra_to_eof;
            let plan = read_plan(vdl, eof, offset, requested_len)
                .expect("vdl <= eof by construction");
            let remaining_to_eof = eof.saturating_sub(offset);
            prop_assert!(u64::from(plan.total_len()) <= remaining_to_eof);
            prop_assert!(plan.total_len() <= requested_len);
        }
    }
}
