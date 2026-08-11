// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Bit-packed bloom filter for the Phase 4 memory-tiering tier-skip path.
//!
//! Phase 4's headline contract is **"Bloom miss ⇒ zero RAM touch, zero
//! promotion."**  Each shard persists a bloom over its basenames /
//! extensions / directory names; PARKED shards keep only bloom +
//! path-trie resident (~5–15 MB) instead of the full records / names /
//! trigram columns.  When a search dispatches to N drives, every drive's
//! bloom is consulted first; misses skip the drive entirely so the
//! kernel never has to fault its body back into RAM.  This is what
//! unlocks the "≤ 50 MB resident on a 7-drive idle box" target
//! documented at the headline of the
//! `docs/refactor/memory-tiering-implementation-plan.md` §3 Phase 4.
//!
//! ## Design — k=7 hashes, double-hashing trick
//!
//! Per the tiering-plan §6.2 parameter table the filter targets a 1 %
//! FPR at k=7 with `xxh3` as the underlying hash.  This implementation
//! uses the workspace's existing `rustc_hash::FxHasher` (already a
//! workspace dep, no new audit-surface), combined with the
//! **double-hashing** technique of [Kirsch & Mitzenmacher 2006, "Less
//! Hashing, Same Performance"][km06]:
//!
//! 1. Compute two independent base hashes `hash_a`, `hash_b` from the key by
//!    feeding two different 64-bit prefix seeds into `FxHasher`.
//! 2. The k bit positions are `(hash_a + i * hash_b) mod nbits` for `i ∈ 0..k`.
//!
//! This is provably equivalent (in expected FPR) to k independent
//! hashes when `k ≪ √nbits`, which holds at our parameters (k=7,
//! `nbits ≈ 10·n ≥ thousands`).  The benefit is two `FxHasher`
//! invocations per query/insert instead of seven, and zero new
//! dependencies.
//!
//! `FxHash` is non-cryptographic and has known bias on adversarial
//! input distributions — but bloom filters in this codebase are
//! populated from filesystem names that an attacker can't choose (the
//! threat model is covered by the encrypted-cache layer, not the
//! bloom).  For the standard "filesystem names → 1 % FPR target"
//! workload `FxHash` is indistinguishable from `xxh3` in measured FPR.
//!
//! [km06]: https://www.eecs.harvard.edu/~michaelm/postscripts/rsa2008.pdf
//!
//! ## API surface
//!
//! - [`Bloom::with_capacity_and_fpr`] — sized for a target item count and
//!   false-positive rate; computes optimal `(nbits, k)`.
//! - [`Bloom::with_size_and_k`] — explicit size + hash count, for tests and
//!   serialised-on-disk reconstruction.
//! - [`Bloom::insert`] / [`Bloom::contains`] — the hot path.
//! - [`Bloom::estimated_fpr`] — analytic FPR estimate for a given load factor;
//!   used by tests and the `shard.bloom.decision` telemetry.

use core::hash::Hasher as _;

use rustc_hash::FxHasher;

/// First seed for the double-hashing prefix.
///
/// Distinct from [`SEED_B`] to make `hash_a` and `hash_b` independent
/// under `FxHasher`.  The exact bits don't matter — only that
/// `(SEED_A, SEED_B)` aren't trivially related (e.g. one isn't a
/// bit-shift of the other) so that prefix-then-`FxHash` produces
/// statistically independent base hashes.
const SEED_A: u64 = 0xA5A5_C3C3_F0F0_5A5A;

/// Second seed for the double-hashing prefix.
///
/// Distinct from [`SEED_A`] (different high-byte pattern) so the two
/// `FxHasher` streams diverge from the first byte.
const SEED_B: u64 = 0x5A5A_3C3C_0F0F_A5A5;

/// Number of hash functions for the workspace's standard 1 %-FPR
/// target.
///
/// Per tiering-plan §6.2 this is fixed at 7.  Exposed via
/// [`Bloom::k`] so callers can introspect.
pub const DEFAULT_K: u8 = 7;

/// Bit-packed bloom filter with double-hashing.
///
/// Memory layout: `bits` is a `Vec<u64>` where each `u64` packs 64
/// bit-positions of the filter.  `nbits` is always a multiple of 64
/// (constructors round up).  The total heap footprint is
/// `nbits / 8` bytes plus 32 bytes of struct overhead — for the
/// canonical 1 M-item / 1 % FPR sizing that's about 1.2 MB per shard.
#[derive(Debug, Clone)]
pub struct Bloom {
    /// Bit-packed storage.  `bits[i]` holds bit positions
    /// `64*i ..= 64*i + 63`.
    bits: Vec<u64>,
    /// Total bit count, always a multiple of 64.  Stored explicitly
    /// so the modulo in [`Bloom::bit_index`] reads off a `u64`
    /// rather than recomputing `bits.len() * 64` every probe.
    nbits: u64,
    /// Number of hash functions per insert / query.
    ///
    /// Stored as `u8` because the optimal value at any reasonable
    /// load factor is well below 256 (~7 for 1 % FPR, ~10 for 0.1 %
    /// FPR).
    k_hashes: u8,
}

impl Bloom {
    /// Construct a bloom sized for `n_items` distinct elements at the
    /// given target false-positive rate.
    ///
    /// Uses the standard sizing formulas:
    ///   - `m / n = -ln(p) / ln(2)^2`
    ///   - `k = (m / n) * ln(2)`
    ///
    /// ## Panics
    ///
    /// - `n_items == 0`.
    /// - `target_fpr` not in `(0.0, 1.0)`.
    ///
    /// Both conditions indicate caller bugs (a zero-element bloom or
    /// a nonsense FPR target) rather than recoverable runtime states,
    /// so panicking is the correct behaviour.
    #[must_use]
    #[expect(
        clippy::float_arithmetic,
        reason = "bloom sizing formulas are inherently floating-point; the workspace \
                  ban exists to flag accidental float math in integer codepaths, not \
                  to forbid math libraries that are *defined* over the reals"
    )]
    pub fn with_capacity_and_fpr(n_items: usize, target_fpr: f64) -> Self {
        assert!(n_items > 0_usize, "bloom: n_items must be > 0");
        assert!(
            target_fpr > 0.0_f64 && target_fpr < 1.0_f64,
            "bloom: target_fpr must be in (0.0, 1.0), got {target_fpr}",
        );

        // m / n = -ln(p) / ln(2)^2
        let ln2 = core::f64::consts::LN_2;
        // `usize -> f64` precision-loss cast routed through the
        // centralized `uffs_mft::usize_to_f64` helper.  `n_items >
        // 1<<53` would mean a multi-petabyte bloom, which is not a
        // real filesystem-name-filter use case.
        let n_as_float = uffs_mft::usize_to_f64(n_items);
        let bits_per_element = -target_fpr.ln() / (ln2 * ln2);
        let nbits_as_float = (n_as_float * bits_per_element).ceil();

        // Round up to next multiple of 64 so the bit-packed Vec<u64>
        // has whole-word alignment.  Saturate to u64::MAX on overflow
        // (a 16-EB bloom is well outside any realistic call site);
        // `uffs_mft::f64_to_u64` carries the single documented
        // `cast_possible_truncation` / `cast_sign_loss` /
        // `cast_precision_loss` triplet.
        let nbits_raw = uffs_mft::f64_to_u64(nbits_as_float);
        let aligned_nbits = nbits_raw.div_ceil(64).saturating_mul(64).max(64);

        // k = (m / n) * ln(2), clamped to [1, 32].  The clamp bounds
        // the value into u8 range; we go through u64 first via the
        // centralized `f64_to_u64` helper so the only remaining
        // narrowing is the saturating `u8::try_from` (which is
        // lint-free).
        let k_as_float = (bits_per_element * ln2).round();
        let k_clamped_f64 = k_as_float.clamp(1.0_f64, 32.0_f64);
        let k_clamped = u8::try_from(uffs_mft::f64_to_u64(k_clamped_f64)).unwrap_or(32_u8);

        Self::with_size_and_k(aligned_nbits, k_clamped)
    }

    /// Construct a bloom with explicit `nbits` and `k_hashes`.
    ///
    /// `nbits` is rounded up to the next multiple of 64.  `k_hashes`
    /// is clamped to `[1, 32]`.
    ///
    /// Used by [`Bloom::with_capacity_and_fpr`] internally and by the
    /// cache-format deserialiser (Phase 4 Commit D), which
    /// reconstructs the filter from the on-disk header.
    #[must_use]
    pub fn with_size_and_k(nbits: u64, k_hashes: u8) -> Self {
        let aligned_nbits = nbits.div_ceil(64).saturating_mul(64).max(64);
        let clamped_k = k_hashes.clamp(1, 32);
        let nwords_u64 = aligned_nbits / 64;
        // u64-to-usize is lossless on every 64-bit target the workspace
        // supports.  On 32-bit targets the saturating_mul + Vec capacity
        // limit would clip the bloom long before the cast became an issue.
        let nwords = nwords_u64 as usize;
        Self {
            bits: vec![0_u64; nwords],
            nbits: aligned_nbits,
            k_hashes: clamped_k,
        }
    }

    /// Insert `key` into the filter.
    ///
    /// Idempotent: re-inserting an existing key is a no-op (the bits
    /// are already set).  O(k) time, O(1) extra memory.
    pub fn insert(&mut self, key: &[u8]) {
        let (hash_a, hash_b) = Self::base_hashes(key);
        for probe_idx in 0..u64::from(self.k_hashes) {
            let pos = self.bit_index(hash_a, hash_b, probe_idx);
            self.set_bit(pos);
        }
    }

    /// Test whether `key` is *possibly* in the filter.
    ///
    /// Returns `true` if every k-th bit is set (key may be present;
    /// false-positive probability is bounded by
    /// [`Bloom::estimated_fpr`]) or `false` if any bit is clear (key
    /// is *definitely* not present).
    ///
    /// Short-circuits on the first clear bit so a miss is typically
    /// `~k/2` probes on average.
    #[must_use]
    pub fn contains(&self, key: &[u8]) -> bool {
        let (hash_a, hash_b) = Self::base_hashes(key);
        for probe_idx in 0..u64::from(self.k_hashes) {
            let pos = self.bit_index(hash_a, hash_b, probe_idx);
            if !self.get_bit(pos) {
                return false;
            }
        }
        true
    }

    /// Total bit count of the filter (always a multiple of 64).
    #[must_use]
    pub const fn nbits(&self) -> u64 {
        self.nbits
    }

    /// Heap footprint in bytes (`nbits / 8`).
    ///
    /// Used by the Phase 4 memory-budget tests and by the
    /// `shard.transition` event's `freed_mb` / `restored_mb`
    /// accounting.
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        // nbits is always a multiple of 64 and stored as u64; size in
        // bytes is nbits / 8 which fits usize on every 32-bit-or-larger
        // target the workspace supports.  The cast is safe because
        // realistic blooms never exceed a few tens of MB.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "nbits / 8 ≤ a few tens of MB for any realistic bloom; \
                      fits usize even on 32-bit targets"
        )]
        let bytes = self.nbits as usize / 8;
        bytes
    }

    /// Number of hash functions per insert / query (the classic
    /// bloom-filter `k` parameter).
    #[must_use]
    pub const fn hash_count(&self) -> u8 {
        self.k_hashes
    }

    /// Borrow the bit-packed storage as a slice of `u64` words.
    ///
    /// Used by the Phase 4 cache-format serialiser
    /// (`compact_cache::filters_io::write_bloom_section`) to blit the
    /// bloom contents in one `bytemuck::cast_slice` call.
    #[must_use]
    pub fn bits(&self) -> &[u64] {
        &self.bits
    }

    /// Reconstruct a `Bloom` from raw `(nbits, k_hashes, bits)` parts.
    ///
    /// Validates that `bits.len() * 64 == nbits` and `nbits` is a
    /// multiple of 64; returns `None` on either violation so the
    /// cache-format deserialiser can reject corrupted files instead
    /// of producing an inconsistent filter.  `k_hashes` is clamped
    /// to `[1, 32]` (matching the [`Bloom::with_size_and_k`]
    /// contract).
    #[must_use]
    pub fn from_raw_parts(nbits: u64, k_hashes: u8, bits: Vec<u64>) -> Option<Self> {
        if nbits == 0 || !nbits.is_multiple_of(64) {
            return None;
        }
        let expected_words = (nbits / 64) as usize;
        if bits.len() != expected_words {
            return None;
        }
        Some(Self {
            bits,
            nbits,
            k_hashes: k_hashes.clamp(1, 32),
        })
    }

    /// Analytic false-positive rate estimate for `n_inserted` items.
    ///
    /// Formula: `(1 - exp(-k*n/m))^k`.  Useful for telemetry — the
    /// `shard.bloom.decision` event reports this so an operator can
    /// see the live FPR converge on the design target as a shard
    /// fills up.
    #[must_use]
    #[expect(
        clippy::float_arithmetic,
        reason = "FPR formula is inherently floating-point"
    )]
    pub fn estimated_fpr(&self, n_inserted: usize) -> f64 {
        if n_inserted == 0 || self.nbits == 0 {
            return 0.0_f64;
        }
        // Both `usize -> f64` and `u64 -> f64` conversions go through
        // the centralized `uffs_mft::{usize_to_f64, u64_to_f64}`
        // helpers (each of which carries a single documented
        // `cast_precision_loss` expect).  Beyond the 2^53 representable
        // range, the FPR estimate is already saturated near 1.0 and
        // dominated by `k_hashes`, so the precision loss is invisible
        // to callers.
        let n_as_float = uffs_mft::usize_to_f64(n_inserted);
        let m_as_float = uffs_mft::u64_to_f64(self.nbits);
        let k_as_float = f64::from(self.k_hashes);
        let inner = 1.0_f64 - (-k_as_float * n_as_float / m_as_float).exp();
        inner.powf(k_as_float)
    }

    /// Compute the two base hashes used for double-hashing.
    ///
    /// Associated function (no `&self`) because the seeds are global
    /// constants and the result is purely a function of the key.
    fn base_hashes(key: &[u8]) -> (u64, u64) {
        let mut hasher_a = FxHasher::default();
        hasher_a.write_u64(SEED_A);
        hasher_a.write(key);
        let hash_a = hasher_a.finish();

        let mut hasher_b = FxHasher::default();
        hasher_b.write_u64(SEED_B);
        hasher_b.write(key);
        let hash_b = hasher_b.finish();

        // Ensure hash_b is odd so `(hash_a + i*hash_b) mod nbits`
        // walks every residue class as i increments.  An even hash_b
        // would visit only half the bits when nbits is a power-of-two
        // multiple of 64.  Setting the LSB is the standard fix and
        // doesn't materially affect FPR (we just reflect the LSB into
        // the seed space).
        (hash_a, hash_b | 1)
    }

    /// Resolve the i-th bit position for a given key.
    ///
    /// `bit_index(hash_a, hash_b, probe_idx) =
    /// (hash_a + probe_idx * hash_b) mod nbits`.  The `wrapping_*`
    /// operators are correct here — modular arithmetic over `u64`
    /// mod `nbits` is exactly what double-hashing needs.
    const fn bit_index(&self, hash_a: u64, hash_b: u64, probe_idx: u64) -> u64 {
        let raw = hash_a.wrapping_add(probe_idx.wrapping_mul(hash_b));
        raw % self.nbits
    }

    /// Set bit `pos` in the bit-packed storage.
    fn set_bit(&mut self, pos: u64) {
        let word_idx = (pos / 64) as usize;
        let bit_idx = pos & 63;
        // SAFETY of the indexing: pos < self.nbits (caller invariant
        // via `bit_index`), and self.nbits == self.bits.len() * 64
        // (constructor invariant), so word_idx < self.bits.len().
        #[expect(
            clippy::indexing_slicing,
            reason = "pos < nbits ⇒ word_idx < bits.len() by constructor invariant"
        )]
        {
            self.bits[word_idx] |= 1_u64 << bit_idx;
        }
    }

    /// Read bit `pos` from the bit-packed storage.
    fn get_bit(&self, pos: u64) -> bool {
        let word_idx = (pos / 64) as usize;
        let bit_idx = pos & 63;
        #[expect(
            clippy::indexing_slicing,
            reason = "pos < nbits ⇒ word_idx < bits.len() by constructor invariant"
        )]
        let word = self.bits[word_idx];
        (word >> bit_idx) & 1 == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke: an empty bloom returns `false` for every query.
    #[test]
    fn empty_bloom_contains_nothing() {
        let bloom = Bloom::with_capacity_and_fpr(100, 0.01_f64);
        for i in 0_u32..1000 {
            assert!(!bloom.contains(&i.to_le_bytes()));
        }
    }

    /// Insert determinism: every inserted key must report `contains
    /// == true`.  This is the bloom's only hard guarantee (no false
    /// negatives).
    #[test]
    fn no_false_negatives() {
        let mut bloom = Bloom::with_capacity_and_fpr(10_000, 0.01_f64);
        for i in 0_u32..10_000 {
            bloom.insert(&i.to_le_bytes());
        }
        for i in 0_u32..10_000 {
            assert!(
                bloom.contains(&i.to_le_bytes()),
                "key {i} reported as missing — bloom must never false-negative"
            );
        }
    }

    /// Sizing sanity: `with_capacity_and_fpr(1M, 1%)` lands on the
    /// canonical ~10 bits/element envelope from tiering-plan §6.2.
    #[test]
    fn capacity_and_fpr_sizes_to_canonical_envelope() {
        let bloom = Bloom::with_capacity_and_fpr(1_000_000, 0.01_f64);
        // Optimal m/n for p=0.01 is ~9.585; rounded to multiple of 64
        // and post-ceil() that lands in [9_500_000, 9_700_000].
        assert!(
            bloom.nbits() >= 9_500_000 && bloom.nbits() <= 9_700_000,
            "nbits = {} outside canonical 1M-item / 1%-FPR envelope",
            bloom.nbits(),
        );
        // k for 1 % FPR rounds to 7.
        assert_eq!(bloom.hash_count(), 7);
        // Size in bytes is ~1.2 MB.
        assert!(bloom.size_bytes() >= 1_180_000 && bloom.size_bytes() <= 1_220_000);
    }

    /// Plan task 4.2: 100 K random strings inserted into a **1.2
    /// Mbit** bloom (k=7), 100 K *novel* strings queried,
    /// FPR ≤ 1.5 %.
    ///
    /// Sizes the bloom via [`Bloom::with_size_and_k`] to match the
    /// plan's explicit 1.2 Mbit / k=7 envelope rather than going
    /// through [`Bloom::with_capacity_and_fpr`] (which would land on
    /// the formula's optimum of ~960 kbit and trade off some FPR
    /// margin for memory).  At m=1.2M / k=7 / n=100k the analytic
    /// FPR is ≈ 0.5 %, leaving generous headroom under the 1.5 %
    /// gate.
    ///
    /// Insertion universe is `i ∈ [0, 100k)`; query universe is
    /// `i ∈ [10_000_000, 10_000_000 + 100k)` so the two sets are
    /// fully disjoint.
    #[test]
    fn fpr_under_one_and_a_half_percent_at_design_load() {
        // Integer comparison: 1.5 % of 100_000 = 1_500.  Avoids float
        // arithmetic / cast lints by never converting to f64.  Declared
        // here at the top of the fn to satisfy
        // `clippy::items_after_statements`.
        const MAX_ALLOWED: u32 = 1_500;

        let mut bloom = Bloom::with_size_and_k(1_200_000, 7);

        for i in 0_u64..100_000 {
            bloom.insert(&i.to_le_bytes());
        }

        let mut false_positives = 0_u32;
        let novel_start = 10_000_000_u64;
        for i in 0_u64..100_000 {
            let key = (novel_start + i).to_le_bytes();
            if bloom.contains(&key) {
                false_positives += 1;
            }
        }

        assert!(
            false_positives <= MAX_ALLOWED,
            "got {false_positives} false positives in 100k novel queries; \
             target ≤ 1.5 % = {MAX_ALLOWED} (plan task 4.2)"
        );
    }

    /// `with_size_and_k` rounds nbits up to a multiple of 64.
    #[test]
    fn with_size_and_k_rounds_up_to_word_boundary() {
        let bloom = Bloom::with_size_and_k(100, 7);
        assert_eq!(bloom.nbits() % 64, 0);
        assert!(bloom.nbits() >= 100);
    }

    /// `with_size_and_k` clamps k to [1, 32].
    #[test]
    fn with_size_and_k_clamps_k_to_valid_range() {
        let too_small = Bloom::with_size_and_k(64, 0);
        assert_eq!(too_small.hash_count(), 1);
        let too_big = Bloom::with_size_and_k(64, 200);
        assert_eq!(too_big.hash_count(), 32);
    }

    /// `estimated_fpr` returns 0 for an empty filter and a value in
    /// `(0, 1)` for a partially loaded one.
    #[test]
    fn estimated_fpr_bounds() {
        let bloom = Bloom::with_capacity_and_fpr(10_000, 0.01_f64);
        // Empty bloom returns exactly 0.0 (early-return branch).
        // `.abs() < epsilon` avoids `float_cmp` while still pinning
        // the early-return contract.
        assert!(bloom.estimated_fpr(0).abs() < 1e-12_f64);
        let mid = bloom.estimated_fpr(5_000);
        assert!(mid > 0.0_f64 && mid < 0.01_f64);
        let at_capacity = bloom.estimated_fpr(10_000);
        // At design capacity FPR should be approximately the target.
        assert!(at_capacity > 0.005_f64 && at_capacity < 0.015_f64);
    }

    /// Idempotent insert: inserting the same key twice doesn't
    /// change any state observable through the public API.
    #[test]
    fn insert_is_idempotent() {
        let mut bloom = Bloom::with_capacity_and_fpr(100, 0.01_f64);
        bloom.insert(b"hello");
        let snapshot = bloom.bits.clone();
        bloom.insert(b"hello");
        assert_eq!(bloom.bits, snapshot);
        assert!(bloom.contains(b"hello"));
    }

    /// `with_capacity_and_fpr(0, _)` panics — guards against
    /// zero-element-bloom call-site bugs.
    #[test]
    #[should_panic(expected = "bloom: n_items must be > 0")]
    fn with_capacity_and_fpr_panics_on_zero_items() {
        let _bloom = Bloom::with_capacity_and_fpr(0, 0.01_f64);
    }

    /// `with_capacity_and_fpr` panics on FPR ≤ 0.
    #[test]
    #[should_panic(expected = "bloom: target_fpr must be in (0.0, 1.0)")]
    fn with_capacity_and_fpr_panics_on_nonsense_fpr() {
        let _bloom = Bloom::with_capacity_and_fpr(100, 0.0_f64);
    }

    /// Filesystem-name use case: insert basenames, extensions, and
    /// directory names; query a mix of present + novel keys.
    /// Pins the integration shape Phase 4 Commit C will wire up.
    #[test]
    fn filesystem_name_workload() {
        let basenames = ["Cargo.toml", "README.md", "Cargo.lock", "main.rs", "lib.rs"];
        let extensions = ["toml", "md", "lock", "rs"];
        let directories = ["src", "target", "tests", "benches", "examples"];

        let mut bloom = Bloom::with_capacity_and_fpr(64, 0.01_f64);
        for name in basenames.iter().chain(&extensions).chain(&directories) {
            bloom.insert(name.as_bytes());
        }

        for name in basenames {
            assert!(bloom.contains(name.as_bytes()), "missing inserted: {name}");
        }
        // Disjoint novel keys — should overwhelmingly miss.
        let mut hits = 0_u32;
        let novel = ["xyzzy", "plugh", "frob", "qux", "wibble"];
        for name in novel {
            if bloom.contains(name.as_bytes()) {
                hits += 1;
            }
        }
        // FPR is bounded by the design target; on this tiny load it
        // should be effectively zero.  Allow up to 1 false positive
        // out of 5 to cover the ~1 % FPR upper tail.
        assert!(hits <= 1, "got {hits} false positives in 5 novel queries");
    }

    // ── Phase 4 task 4.12 — perf budgets ──────────────────────────
    //
    // Pin the bloom build + query budgets from
    // `docs/refactor/memory-tiering-implementation-plan.md` §3 Phase 4
    // task 4.12: bloom build ≤ 200 ms / bloom query ≤ 1 µs at 1 M
    // items.  These budgets are **release-mode** contracts; debug
    // builds run 10–100× slower because of the lack of inlining +
    // bounds-check elision.  Both tests `cfg_attr(debug_assertions,
    // ignore)` so a default `cargo test` skips them, and
    // `cargo test --release` (or `nextest run --cargo-profile
    // release`) runs them.
    //
    // Run on Mac:
    //   cargo test --release -p uffs-core --lib bloom::tests::plan_4_12
    //
    // The 1 M item count matches the canonical fixture sizing in
    // §6.2 of `docs/refactor/memory-tiering-plan.md` (the sibling
    // doc); the 0.01 FPR target is the production
    // `SHARD_BLOOM_TARGET_FPR`.

    /// Plan task **4.12** — bloom build budget at 1 M items.
    ///
    /// Pre-build the keys outside the timed region; time only
    /// `with_capacity_and_fpr(1_000_000, 0.01)` + 1 M `insert`
    /// calls.  Budget ≤ 200 ms in release mode.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only")]
    fn plan_4_12_bloom_build_under_two_hundred_ms_at_one_million_items() {
        use alloc::format;
        use alloc::string::String;
        use alloc::vec::Vec;
        use core::time::Duration;
        use std::time::Instant;

        const ITEMS: usize = 1_000_000;
        let keys: Vec<String> = (0..ITEMS).map(|i| format!("file_{i:08}.txt")).collect();

        let start = Instant::now();
        let mut bloom = Bloom::with_capacity_and_fpr(ITEMS, 0.01_f64);
        for key in &keys {
            bloom.insert(key.as_bytes());
        }
        let elapsed = start.elapsed();

        let budget = Duration::from_millis(200);
        assert!(
            elapsed <= budget,
            "bloom build at {ITEMS} items took {elapsed:?} (budget {budget:?})"
        );
    }

    /// Plan task **4.12** — bloom query budget at 1 M items.
    ///
    /// Pre-build the bloom outside the timed region; time only
    /// 1 M `contains` calls.  Budget ≤ 1 µs avg per call (1 s
    /// total wall for 1 M calls).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only")]
    fn plan_4_12_bloom_query_under_one_microsecond_average_at_one_million_items() {
        use alloc::format;
        use alloc::string::String;
        use alloc::vec::Vec;
        use core::time::Duration;
        use std::time::Instant;

        const ITEMS: usize = 1_000_000;
        let keys: Vec<String> = (0..ITEMS).map(|i| format!("file_{i:08}.txt")).collect();
        let mut bloom = Bloom::with_capacity_and_fpr(ITEMS, 0.01_f64);
        for key in &keys {
            bloom.insert(key.as_bytes());
        }

        let start = Instant::now();
        let mut hits = 0_u64;
        for key in &keys {
            if bloom.contains(key.as_bytes()) {
                hits += 1;
            }
        }
        let elapsed = start.elapsed();

        // 1 µs / call * 1 M calls = 1 s wall budget.
        let budget = Duration::from_micros(ITEMS as u64);
        let avg = elapsed / u32::try_from(ITEMS).expect("ITEMS fits u32");
        assert!(
            elapsed <= budget,
            "bloom query at {ITEMS} items took {elapsed:?} (avg {avg:?}/call, budget 1µs/call)"
        );
        assert_eq!(
            hits, ITEMS as u64,
            "no false negatives — every inserted key must hit"
        );
    }
}
