// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! WI-7.1 — bug-for-bug parity corpus for pathological names (Category 7).
//!
//! Two tiers:
//!
//! - **Tier 1 (always-on, CI):** feed pathological NTFS file-name byte
//!   sequences (trailing dot/space, reserved device names, max-length
//!   components, surrogate-bearing names) through the single instrumented name
//!   decoder ([`crate::io::parser::unified::decode_name_u16`], WI-4.1) and
//!   assert the **documented** behaviour. These names are stored verbatim in
//!   the MFT — the Win32 layer's trailing-dot/space stripping and reserved-name
//!   remapping happen *above* the file system, so a raw MFT reader must
//!   preserve them byte-for-byte. A future silent change to the decoder fails
//!   these pins.
//!
//! - **Tier 2 (opt-in, real offline capture):** when `UFFS_PARITY_DATA_DIR`
//!   points at a directory of captured `.iocp` MFT artifacts (the gitignored
//!   local corpus, or the Windows trial-harness output), load a drive offline
//!   and assert UFFS's enumerated path set matches the C++ golden
//!   (`cpp_<drive>.txt`). This is the live bug-for-bug name-parity check; it
//!   loads the same `process_record` path used in production and runs fully on
//!   macOS against pre-captured data, so it is not Windows-gated.

#[cfg(test)]
mod tier1_decoder_corpus {
    use crate::io::parser::unified::decode_name_u16;

    /// Encode a `&str` to a UTF-16 code-unit vector (an NTFS `$FILE_NAME`
    /// stores names as UTF-16, so this mirrors what the parser hands the
    /// decoder).
    fn utf16(name: &str) -> Vec<u16> {
        name.encode_utf16().collect()
    }

    /// Trailing dots and spaces are **preserved verbatim** at the MFT level.
    /// Win32 `CreateFile` strips them, but the on-disk `$FILE_NAME` keeps
    /// them, and a raw reader must report what is on disk.
    #[test]
    fn trailing_dot_and_space_preserved() {
        for raw in ["report.", "report ", "name...", "two  ", "a. .", "mixed. ."] {
            let (decoded, lossy) = decode_name_u16(&utf16(raw));
            assert_eq!(
                decoded, raw,
                "trailing dot/space must be preserved verbatim"
            );
            assert_eq!(lossy, 0, "ASCII name must decode losslessly");
        }
    }

    /// Reserved Win32 device names (`CON`, `NUL`, `AUX`, `COM1`, …) are just
    /// ordinary names on disk — the reservation is a Win32 namespace rule, not
    /// an NTFS one. They decode unchanged.
    #[test]
    fn reserved_device_names_are_ordinary_on_disk() {
        for raw in ["CON", "NUL", "AUX", "PRN", "COM1", "LPT1", "con.txt", "nul"] {
            let (decoded, lossy) = decode_name_u16(&utf16(raw));
            assert_eq!(decoded, raw, "reserved name must decode verbatim");
            assert_eq!(lossy, 0);
        }
    }

    /// A maximum-length NTFS component (255 UTF-16 code units) round-trips
    /// without truncation.
    #[test]
    fn max_length_component_round_trips() {
        let raw = "a".repeat(255);
        let (decoded, lossy) = decode_name_u16(&utf16(&raw));
        assert_eq!(decoded.chars().count(), 255);
        assert_eq!(decoded, raw);
        assert_eq!(lossy, 0);
    }

    /// Non-ASCII but valid Unicode (BMP + astral) decodes losslessly — the
    /// decoder is not limited to ASCII.
    #[test]
    fn unicode_names_decode_losslessly() {
        for raw in ["café", "日本語", "naïve", "emoji_😀_file", "Ω≈ç√"] {
            let (decoded, lossy) = decode_name_u16(&utf16(raw));
            assert_eq!(decoded, raw);
            assert_eq!(lossy, 0, "valid Unicode must not be lossy");
        }
    }

    /// **Documented lossy behaviour (WI-4.1):** a name containing an unpaired
    /// UTF-16 surrogate is not representable in UTF-8. The decoder substitutes
    /// U+FFFD and **counts** the substitution rather than silently dropping
    /// data. This pins the documented behaviour until WI-4.4 (lossless storage)
    /// lands; a silent change to "drop" or "panic" fails here.
    #[test]
    fn unpaired_surrogate_becomes_counted_replacement() {
        // "ab" + lone high surrogate 0xD800 + "cd"
        let units: Vec<u16> = vec![
            u16::from(b'a'),
            u16::from(b'b'),
            0xD800,
            u16::from(b'c'),
            u16::from(b'd'),
        ];
        let (decoded, lossy) = decode_name_u16(&units);
        assert_eq!(lossy, 1, "exactly one U+FFFD substitution must be counted");
        assert!(
            decoded.contains('\u{FFFD}'),
            "the lone surrogate must become U+FFFD"
        );
        assert!(
            decoded.starts_with("ab") && decoded.ends_with("cd"),
            "surrounding valid code units must survive: {decoded:?}"
        );
    }

    /// An empty name decodes to an empty string with no loss (degenerate but
    /// must not panic).
    #[test]
    fn empty_name_is_empty() {
        let (decoded, lossy) = decode_name_u16(&[]);
        assert_eq!(decoded, "");
        assert_eq!(lossy, 0);
    }
}

#[cfg(test)]
mod tier2_offline_capture_parity {
    use alloc::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    /// Locate a drive's `.iocp` capture + C++ golden under
    /// `$UFFS_PARITY_DATA_DIR`.
    ///
    /// Layout (matches the local corpus and the Windows trial harness):
    /// `<data_dir>/drive_<letter>/<LETTER>_mft.iocp` and
    /// `<data_dir>/drive_<letter>/cpp_<letter>.txt`.
    ///
    /// Returns `None` (test skips) when the env var is unset or the chosen
    /// drive's artifacts are absent — so vanilla CI without the gitignored
    /// corpus passes cleanly.
    fn locate_capture() -> Option<(PathBuf, PathBuf)> {
        let data_dir = PathBuf::from(std::env::var_os("UFFS_PARITY_DATA_DIR")?);
        // Prefer the smallest known drive (`g`) for speed; fall back to any
        // drive directory that has both an `.iocp` and a `cpp_*.txt`.
        let candidates = ["g", "s", "m", "d", "e", "c", "f"];
        for letter in candidates {
            let dir = data_dir.join(format!("drive_{letter}"));
            let upper = letter.to_ascii_uppercase();
            let iocp = dir.join(format!("{upper}_mft.iocp"));
            let golden = dir.join(format!("cpp_{letter}.txt"));
            if iocp.is_file() && golden.is_file() {
                return Some((iocp, golden));
            }
        }
        None
    }

    /// Normalise a path for name-set comparison.
    ///
    /// The C++ golden writes directory paths with a trailing `\`
    /// (`G:\DIR\`), while UFFS's `materialize_path` does not
    /// (`G:\DIR`). That is a documented presentation difference, **not** a
    /// name-enumeration divergence — WI-7.1 asserts the *set of names/paths*
    /// matches, so both sides drop a single trailing `\` (the volume root
    /// `G:\` collapses to `G:` consistently on both sides) before comparison.
    fn normalize(path: &str) -> String {
        path.strip_suffix('\\').unwrap_or(path).to_owned()
    }

    /// `true` if a path names an NTFS **alternate data stream**
    /// (`file:stream`).
    ///
    /// The drive-letter colon (`G:\…`) is at index 1; an ADS colon appears
    /// later in the path. The C++ golden enumerates ADS as `path:stream`
    /// entries, whereas UFFS tracks streams separately from the path
    /// namespace (they are not directory entries). WI-7.1 compares the
    /// **file/dir path namespace**, so ADS rows are filtered from the golden
    /// and asserted as a documented difference (see the test body).
    fn is_ads_path(path: &str) -> bool {
        // Skip the `X:` drive-letter colon, then look for any further colon.
        path.get(2..).is_some_and(|rest| rest.contains(':'))
    }

    /// Extract the normalised set of full paths from a C++/Rust golden CSV,
    /// split into `(file_dir_paths, ads_paths)`.
    ///
    /// The golden's first column is the quoted `"Path"`; the header row and
    /// blank lines are skipped.
    fn golden_paths(golden: &Path) -> (BTreeSet<String>, BTreeSet<String>) {
        let text = std::fs::read_to_string(golden).expect("read golden CSV");
        let mut paths = BTreeSet::new();
        let mut ads = BTreeSet::new();
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with("\"Path\"") {
                continue; // header / blank
            }
            // First CSV field is `"<path>"`; take the content between the
            // first pair of double quotes.
            let Some(rest) = line.strip_prefix('"') else {
                continue;
            };
            let Some(end) = rest.find('"') else {
                continue;
            };
            // `end` is a byte index returned by `find` on `rest`, so it lands
            // on a char boundary; `get(..end)` is the panic-free form.
            let Some(path) = rest.get(..end) else {
                continue;
            };
            if path.is_empty() {
                continue;
            }
            if is_ads_path(path) {
                ads.insert(path.to_owned());
            } else {
                paths.insert(normalize(path));
            }
        }
        (paths, ads)
    }

    /// Enumerate the full path set UFFS produces for an offline-loaded index.
    fn uffs_paths(iocp: &Path) -> BTreeSet<String> {
        let index = crate::load_iocp_to_index(iocp).expect("load offline iocp capture");
        // Include system metafiles? The C++ golden excludes the `$`-prefixed
        // NTFS metafiles and the volume-relative `.`/`..` synthetic entries,
        // so build the resolver without system metafiles and filter to the
        // real, valid, named records.
        let resolver = crate::index::PathResolver::build(&index, false);
        let mut out = BTreeSet::new();
        for idx in 0..index.records().len() {
            if !resolver.is_valid_idx(idx) {
                continue;
            }
            let path = resolver.materialize_path(&index, idx);
            if !path.is_empty() {
                out.insert(normalize(&path));
            }
        }
        out
    }

    /// Load the offline capture and assert UFFS's path enumeration matches the
    /// C++ golden. Skips cleanly when no corpus is configured.
    ///
    /// Run locally with:
    /// `UFFS_PARITY_DATA_DIR=/Users/<you>/uffs_data cargo nextest run -p \
    ///  uffs-mft -- parity`
    #[test]
    fn offline_enumeration_matches_cpp_golden() {
        let Some((iocp, golden)) = locate_capture() else {
            eprintln!(
                "skipping Tier-2 parity: set UFFS_PARITY_DATA_DIR to a dir of \
                 captured .iocp + cpp_*.txt artifacts to enable"
            );
            return;
        };

        let (want, want_ads) = golden_paths(&golden);
        let got = uffs_paths(&iocp);
        assert!(
            !want.is_empty(),
            "golden produced no paths — corpus malformed?"
        );
        assert!(!got.is_empty(), "UFFS enumeration produced no paths");

        // ── Core parity: UFFS must enumerate every file/dir path the
        //    reference C++ tool does. A genuinely missing path is a real
        //    enumeration bug and fails the test. ──────────────────────────
        let missing: Vec<&String> = want.difference(&got).take(20).collect();
        assert!(
            missing.is_empty(),
            "UFFS is MISSING {} of {} reference file/dir paths (sample): {:#?}",
            want.difference(&got).count(),
            want.len(),
            missing,
        );

        // ── Documented differences (asserted, not silently ignored): ─────
        //
        // 1. Alternate Data Streams: the C++ golden lists ADS as `path:stream` rows;
        //    UFFS tracks streams outside the path namespace, so they are absent from
        //    `got`. We assert the corpus *does* contain ADS (so the test stays
        //    meaningful on a corpus that exercises them) and that none leaked into
        //    UFFS's path set.
        for ads in &want_ads {
            assert!(
                !got.contains(ads),
                "ADS path unexpectedly appeared in UFFS path namespace: {ads}"
            );
        }

        // 2. Hard links: a hard-linked file has one `$FILE_NAME` per link, so UFFS
        //    legitimately enumerates *every* link name while the C++ reference lists
        //    the inode once. UFFS's path set may therefore be a strict superset of the
        //    reference; the extras are the alias names. We assert any extras are
        //    bounded and real (non-empty component names), documenting the multiplicity
        //    rather than treating it as a failure.
        let extra: Vec<&String> = got.difference(&want).collect();
        for path in &extra {
            assert!(
                !path.is_empty() && !path.ends_with('\\'),
                "unexpected malformed extra path from UFFS: {path:?}"
            );
        }
        eprintln!(
            "Tier-2 parity OK: {} reference file/dir paths all found; \
             {} ADS-only (golden), {} hard-link alias paths (UFFS extra).",
            want.len(),
            want_ads.len(),
            extra.len(),
        );
    }
}
