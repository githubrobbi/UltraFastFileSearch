// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Post-removal verification for `uffs --uninstall` (task U-81).
//!
//! After the executor runs (and the daemon is stopped), confirm the targeted
//! locations are actually gone by re-stat-ing them. Daemon-free, so it works
//! even though the search service has been removed. Locations that are
//! reboot-deferred (a locked self-binary) are excluded by the caller.

use std::path::PathBuf;

/// Return the subset of `paths` that still exist on disk (a non-empty result
/// means removal did not fully complete — usually a permission issue or a
/// reboot-deferred lock).
pub(crate) fn still_present(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .iter()
        .filter(|path| path.try_exists().unwrap_or(false))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::still_present;

    #[test]
    fn reports_only_paths_that_exist() {
        let here = std::env::temp_dir();
        let gone = PathBuf::from("/nonexistent/uffs-verify-probe-xyz");
        let remaining = still_present(&[here.clone(), gone]);
        assert_eq!(remaining, vec![here]);
    }

    #[test]
    fn empty_input_is_clean() {
        assert_eq!(still_present(&[]), Vec::<PathBuf>::new());
    }
}
