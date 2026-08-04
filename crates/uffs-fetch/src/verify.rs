// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! SHA-256 verification of downloaded artifacts.
//!
//! The **integrity** gate: hash a downloaded file and compare it against
//! the release's published `SHA256SUMS`. Authenticity gates (code
//! signing, etc.) are a separate concern the consumer applies at its own
//! trust boundary — in `uffs-update` that is Authenticode just before an
//! extracted `.exe` replaces anything.

use std::io::Read as _;
use std::path::Path;

use anyhow::{Context as _, Result};
use sha2::{Digest as _, Sha256};

/// Compute the lowercase hex SHA-256 of a file, streaming it in chunks so
/// large bundles don't load into memory at once.
///
/// # Errors
///
/// Propagates any read error.
pub fn sha256_file(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening {} for hashing", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(buf.get(..read).unwrap_or(&[]));
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Parse a `SHA256SUMS` file (`<hex>  <filename>` per line, the standard
/// `sha256sum` format) into `(filename, lowercase-hex)` pairs.
///
/// Pure — unit-testable without I/O.
#[must_use]
pub fn parse_sha256sums(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let hash = parts.next()?;
            // `sha256sum` separates with two spaces; the name may itself
            // contain spaces, so re-join the remainder.
            let name = line
                .get(hash.len()..)
                .map(str::trim_start)
                .map(|rest| rest.trim_start_matches('*')) // binary-mode marker
                .filter(|name| !name.is_empty())?;
            is_hex_sha256(hash).then(|| (name.to_owned(), hash.to_ascii_lowercase()))
        })
        .collect()
}

/// Return the expected hash for `file_name` from parsed sums, matching on
/// the base file name only (sums may list paths).
#[must_use]
pub fn expected_hash<'a>(sums: &'a [(String, String)], file_name: &str) -> Option<&'a str> {
    sums.iter().find_map(|(name, hash)| {
        let base = Path::new(name).file_name().and_then(|os| os.to_str());
        (base == Some(file_name)).then_some(hash.as_str())
    })
}

/// Verify a downloaded file's SHA-256 matches `expected` (case-insensitive
/// hex). Returns `Ok(true)` only on an exact match.
///
/// # Errors
///
/// Propagates a hashing/read error.
pub fn verify_sha256(path: &Path, expected: &str) -> Result<bool> {
    let actual = sha256_file(path)?;
    Ok(actual.eq_ignore_ascii_case(expected))
}

/// `true` when `token` is exactly 64 lowercase-or-uppercase hex digits.
fn is_hex_sha256(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::{expected_hash, is_hex_sha256, parse_sha256sums};

    const HASH_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn parses_standard_sha256sums() {
        let text = format!("{HASH_A}  uffs-windows-x64.zip\n");
        let sums = parse_sha256sums(&text);
        assert_eq!(sums.len(), 1);
        assert_eq!(expected_hash(&sums, "uffs-windows-x64.zip"), Some(HASH_A));
    }

    #[test]
    fn matches_on_base_name_when_sums_list_paths() {
        let text = format!("{HASH_A} *dist/uffs-windows-x64.zip\n");
        let sums = parse_sha256sums(&text);
        assert_eq!(expected_hash(&sums, "uffs-windows-x64.zip"), Some(HASH_A));
    }

    #[test]
    fn skips_garbage_lines() {
        let text = format!("# a comment\n\nnot-a-hash file\n{HASH_A}  ok.zip\n");
        let sums = parse_sha256sums(&text);
        assert_eq!(sums.len(), 1);
        assert_eq!(expected_hash(&sums, "ok.zip"), Some(HASH_A));
    }

    #[test]
    fn hex_validation() {
        assert!(is_hex_sha256(HASH_A));
        assert!(!is_hex_sha256("abc"));
        assert!(!is_hex_sha256(&"z".repeat(64)));
    }
}
