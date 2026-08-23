// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Unit tests for [`super`] (`daemon_spawn`): the autostart
//! kill-switch, elevation-policy decisions, and `CreateProcessW`
//! argument quoting. Split from the module file to keep it under the
//! workspace file-size policy.

#[cfg(test)]
mod autostart_kill_switch_tests {
    use super::super::{autostart_disabled_error, autostart_disabled_from};

    /// The kill-switch parse: set-and-truthy disables, unset/empty/`0`
    /// leaves autostart on (mirrors `elevation_policy_from`'s idiom).
    #[test]
    fn kill_switch_parses_like_a_boolean_env() {
        assert!(autostart_disabled_from(Some("1")));
        assert!(autostart_disabled_from(Some("true")));
        assert!(!autostart_disabled_from(None));
        assert!(!autostart_disabled_from(Some("")));
        assert!(!autostart_disabled_from(Some("0")));
    }

    /// The refusal names both the mechanism (lowercase "daemon", which
    /// callers and tests match on) and the way out.
    #[test]
    fn refusal_message_names_switch_and_remedy() {
        let message = autostart_disabled_error().to_string();
        assert!(
            message.contains("daemon"),
            "must keep the lowercase-daemon match surface: {message}"
        );
        assert!(
            message.contains("UFFS_NO_AUTOSTART"),
            "must name the switch: {message}"
        );
    }
}

#[cfg(test)]
mod elevation_policy_tests {
    use super::super::{ElevationPolicy, elevation_policy_from};

    /// Explicit `force_allow` (e.g. `--elevate`) always wins, even
    /// against an empty or falsy env value.
    #[test]
    fn force_allow_always_permits_uac() {
        assert_eq!(
            elevation_policy_from(true, None),
            ElevationPolicy::AllowUacPrompt,
        );
        assert_eq!(
            elevation_policy_from(true, Some("")),
            ElevationPolicy::AllowUacPrompt,
        );
        assert_eq!(
            elevation_policy_from(true, Some("0")),
            ElevationPolicy::AllowUacPrompt,
        );
    }

    /// Without `force_allow` and without the env var, the default
    /// policy must refuse UAC.  This is the behavioral change v0.5.36
    /// introduces and the linchpin for the whole P7 fix.
    #[test]
    fn missing_env_defaults_to_require_existing_elevation() {
        assert_eq!(
            elevation_policy_from(false, None),
            ElevationPolicy::RequireExistingElevation,
        );
    }

    /// Every documented truthy token must promote to
    /// `AllowUacPrompt`.  Trimming and case-folding are also expected.
    #[test]
    fn truthy_env_values_permit_uac() {
        for token in [
            "1", "true", "TRUE", "True", "yes", "YES", "on", "ON", "  1  ", " yes\n",
        ] {
            assert_eq!(
                elevation_policy_from(false, Some(token)),
                ElevationPolicy::AllowUacPrompt,
                "token {token:?} should enable UAC",
            );
        }
    }

    /// Falsy / unrecognised tokens must keep the conservative default.
    #[test]
    fn falsy_or_unknown_env_values_keep_default() {
        for token in ["0", "false", "no", "off", "", "maybe", "2", "nope"] {
            assert_eq!(
                elevation_policy_from(false, Some(token)),
                ElevationPolicy::RequireExistingElevation,
                "token {token:?} should not enable UAC",
            );
        }
    }

    /// [`ElevationPolicy::default`] must be the safe option.  New
    /// callers that rely on `..Default::default()` must not silently
    /// get the UAC-triggering variant.
    #[test]
    fn default_policy_is_require_existing_elevation() {
        assert_eq!(
            ElevationPolicy::default(),
            ElevationPolicy::RequireExistingElevation,
        );
    }
}

#[cfg(test)]
mod quote_arg_tests {
    use super::super::quote_arg_for_createprocess;

    /// Ergonomic wrapper: quote a `&str` argument and return the result as a
    /// `String`, so the UTF-16 `quote_arg_for_createprocess` can be asserted
    /// against readable string literals. Encodes input to UTF-16, runs the
    /// real quoting routine, then decodes the produced code units back.
    fn quote_str(arg: &str) -> String {
        let wide: Vec<u16> = arg.encode_utf16().collect();
        let mut out: Vec<u16> = Vec::new();
        quote_arg_for_createprocess(&wide, &mut out);
        String::from_utf16(&out).expect("ASCII quoting output is always valid UTF-16")
    }

    /// **Regression (silent `daemon start` failure, `LOG/Output`):** an
    /// empty argument must round-trip as `""` so `CreateProcessW`'s child
    /// sees it as a zero-length argv entry instead of skipping it
    /// entirely.  Before this fix, `["--log-level", "", "--log-file",
    /// "uffsd.log"]` was concatenated as `"... --log-level  --log-file
    /// uffsd.log"`, and the child's argv parser consumed `--log-file` as
    /// the value of `--log-level`, leaving `uffsd.log` as an unknown
    /// positional — clap bailed with exit code 2 before uffsd could bind
    /// its IPC transports.
    #[test]
    fn empty_arg_becomes_explicit_empty_quotes() {
        assert_eq!(quote_str(""), "\"\"");
    }

    /// Plain alphanumeric / punctuation arguments pass through unquoted.
    /// This guards the fast path that keeps command lines readable for
    /// `tracing::debug!` consumers.
    #[test]
    fn plain_arg_passes_through_unquoted() {
        assert_eq!(quote_str("debug"), "debug");
        assert_eq!(quote_str("--log-level"), "--log-level");
        assert_eq!(quote_str("C:\\Users\\rnio"), "C:\\Users\\rnio");
    }

    /// Arguments containing whitespace must be wrapped in double quotes.
    /// This covers the real-world case of a `Program Files` path in
    /// `--data-dir`.
    #[test]
    fn whitespace_arg_gets_quoted() {
        assert_eq!(
            quote_str(r"C:\Program Files\uffs"),
            "\"C:\\Program Files\\uffs\""
        );
    }

    /// Embedded double quotes must be escaped with a backslash so the
    /// child sees the literal quote instead of a premature string
    /// terminator.
    #[test]
    fn embedded_quote_is_escaped() {
        assert_eq!(quote_str(r#"he said "hi""#), r#""he said \"hi\"""#);
    }

    /// MSVCRT rule: each backslash that precedes a quote must be
    /// doubled.  Non-quote backslashes pass through literally.  Without
    /// this, a path like `a\"b` would be misparsed by the child.
    #[test]
    fn backslashes_before_quote_are_doubled() {
        // Single backslash followed by a quote → two backslashes then an
        // escaped quote inside the quoted string.
        assert_eq!(quote_str(r#"a\"b"#), r#""a\\\"b""#);
        // Two backslashes followed by a quote → four backslashes then an
        // escaped quote.
        assert_eq!(quote_str(r#"a\\"b"#), r#""a\\\\\"b""#);
    }

    /// Trailing backslashes inside a quoted arg must be doubled so the
    /// closing quote is not swallowed as an escape target.  A `C:\`
    /// argument with a space elsewhere (forcing quoting) is the canonical
    /// failure case.
    #[test]
    fn trailing_backslash_in_quoted_arg_is_doubled() {
        // "path has\" → needs quoting (space), and the trailing \
        // must be doubled so the closing " stands on its own.
        assert_eq!(quote_str("path with\\"), "\"path with\\\\\"");
    }

    /// End-to-end: simulate the exact args list that caused the bug.
    /// Assembling them with a single space separator must produce the
    /// *correct* command line (empty arg visibly `""`), not the mangled
    /// one from the old naive concatenation.
    #[test]
    fn full_daemon_start_argv_reassembly_preserves_empty_arg() {
        let args = ["--log-level", "", "--log-file", "uffsd.log"];
        let cmd: String = args
            .iter()
            .map(|arg| quote_str(arg))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(cmd, "--log-level \"\" --log-file uffsd.log");
    }

    /// **WI-4.2 lossless round-trip:** a UTF-16 argument containing an
    /// unpaired surrogate (0xD800) — i.e. a Windows path that is *not*
    /// representable in UTF-8 — must survive quoting verbatim. The old
    /// `to_string_lossy()` path would have replaced 0xD800 with U+FFFD,
    /// silently mangling the path before it reached the child's argv. The
    /// surrogate is not a metacharacter, so it passes through the fast path
    /// unchanged, code unit for code unit.
    #[test]
    fn lone_surrogate_arg_survives_losslessly() {
        let arg: Vec<u16> = vec![
            u16::from(b'C'),
            u16::from(b':'),
            0xD800, // lone high surrogate — not valid UTF-8/UTF-16 scalar
            u16::from(b'x'),
        ];
        let mut out: Vec<u16> = Vec::new();
        quote_arg_for_createprocess(&arg, &mut out);
        // No metacharacters → emitted verbatim, surrogate preserved.
        assert_eq!(out, arg, "lone surrogate must round-trip unchanged");
    }
}
