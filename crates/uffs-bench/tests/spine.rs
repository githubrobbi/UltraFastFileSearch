// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Integration tests for the `uffs-bench` Phase P1 spine.
//!
//! These exercise the core "no crumb left behind" invariants through the public
//! API using the in-memory `MockHost`: LIFO restore ordering, restore-on-panic
//! via the `RunGuard` `Drop` safety net, resume-by-`input_hash`, atomic state
//! persistence, the mode-aware confirmation gate, tooling teardown
//! dispositions, host-fingerprint diffing, and bundle tool resolution.

#![expect(
    unused_crate_dependencies,
    reason = "the tempfile dev-dependency is exercised by the SystemHost unit tests; these MockHost-based spine tests need no real filesystem"
)]

extern crate alloc;

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use clap::Parser as _;
    use sha2::{Digest as _, Sha256};
    use uffs_bench::bundle::{ResolvedTool, ToolSource, new_bundle, resolve_tool};
    use uffs_bench::error::BenchError;
    use uffs_bench::fingerprint::{FingerprintSpec, capture, diff};
    use uffs_bench::gate::{Card, Decision, Mode, confirm};
    use uffs_bench::host::{Call, Host as _, MockHost, ProcOutput};
    use uffs_bench::restore::{RestoreRegistry, RunGuard};
    use uffs_bench::state::{Decisions, State, Status, input_hash};
    use uffs_bench::tooling::{Acquisition, Disposition, teardown};
    use uffs_bench::{Cli, run};

    /// Build a minimal [`Card`] for the gate tests.
    fn make_card() -> Card {
        Card {
            id: "stage1/step".to_owned(),
            stage: "STAGE 1".to_owned(),
            step_num: 1,
            step_total: 1,
            title: "Title".to_owned(),
            why: "why".to_owned(),
            commands: vec!["echo hi".to_owned()],
            resources: Vec::new(),
            backups: Vec::new(),
            est_time: "~1s".to_owned(),
            recovery: "none".to_owned(),
            long_why: "long explanation".to_owned(),
        }
    }

    #[test]
    fn restore_runs_in_lifo_order() {
        let host = MockHost::new();
        let mut registry = RestoreRegistry::new();
        registry.register("first", |inner| {
            inner.out("undo-first");
            Ok(())
        });
        registry.register("second", |inner| {
            inner.out("undo-second");
            Ok(())
        });
        let crumbs = registry.drain(&host);
        assert!(crumbs.is_empty());
        assert_eq!(host.output(), vec![
            "undo-second".to_owned(),
            "undo-first".to_owned()
        ]);
    }

    #[test]
    fn restore_fires_on_panic() {
        let host = MockHost::new();
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
            let mut guard = RunGuard::new(&host);
            guard.register("recreate marker", |inner| {
                inner
                    .write_file(Path::new("/restored"), b"1")
                    .map_err(|err| BenchError::io("/restored", err))
            });
            panic!("simulated stage failure");
        }));
        std::panic::set_hook(previous_hook);
        assert!(outcome.is_err());
        assert!(host.path_exists(Path::new("/restored")));
    }

    #[test]
    fn finish_collects_restore_failures() {
        let host = MockHost::new();
        let mut guard = RunGuard::new(&host);
        guard.register("failing undo", |_| {
            Err(BenchError::io("/x", std::io::Error::other("boom")))
        });
        assert_eq!(guard.finish().len(), 1);
    }

    #[test]
    fn gate_autopilot_proceeds() {
        let host = MockHost::new();
        let mut mode = Mode::AutoPilot;
        let mut seen = BTreeSet::new();
        assert_eq!(
            confirm(&host, &mut mode, &mut seen, &make_card()),
            Decision::Proceed
        );
    }

    #[test]
    fn gate_dry_run_is_noop_and_renders() {
        let host = MockHost::new();
        let mut mode = Mode::DryRun;
        let mut seen = BTreeSet::new();
        assert_eq!(
            confirm(&host, &mut mode, &mut seen, &make_card()),
            Decision::ProceedNoop
        );
        assert_ne!(
            host.output(),
            Vec::<String>::new(),
            "confirm must explain the noop"
        );
    }

    #[test]
    fn gate_guided_without_tty_aborts() {
        let host = MockHost::new().with_tty(false);
        let mut mode = Mode::Guided;
        let mut seen = BTreeSet::new();
        assert_eq!(
            confirm(&host, &mut mode, &mut seen, &make_card()),
            Decision::Abort
        );
    }

    #[test]
    fn gate_guided_teaches_full_card_once_then_terse() {
        let host = MockHost::new().with_key('y').with_key('y');
        let mut mode = Mode::Guided;
        let mut seen = BTreeSet::new();
        let card = make_card();

        assert_eq!(
            confirm(&host, &mut mode, &mut seen, &card),
            Decision::Proceed
        );
        let after_first = host.output().len();
        assert_eq!(
            confirm(&host, &mut mode, &mut seen, &card),
            Decision::Proceed
        );
        let second_lines = host.output().len() - after_first;

        assert!(after_first > second_lines);
    }

    #[test]
    fn gate_interactive_autopilot_upgrades_mode() {
        let host = MockHost::new().with_key('a');
        let mut mode = Mode::Interactive;
        let mut seen = BTreeSet::new();
        assert_eq!(
            confirm(&host, &mut mode, &mut seen, &make_card()),
            Decision::Autopilot
        );
        assert_eq!(mode, Mode::AutoPilot);
    }

    #[test]
    fn gate_skip_and_back_keys() {
        let skip_host = MockHost::new().with_key('s');
        let mut skip_mode = Mode::Interactive;
        let mut skip_seen = BTreeSet::new();
        assert_eq!(
            confirm(&skip_host, &mut skip_mode, &mut skip_seen, &make_card()),
            Decision::Skip
        );

        let back_host = MockHost::new().with_key('b');
        let mut back_mode = Mode::Interactive;
        let mut back_seen = BTreeSet::new();
        assert_eq!(
            confirm(&back_host, &mut back_mode, &mut back_seen, &make_card()),
            Decision::Back
        );
    }

    #[test]
    fn gate_explain_key_loops_without_deciding() {
        let host = MockHost::new().with_key('e').with_key('y');
        let mut mode = Mode::Interactive;
        let mut seen = BTreeSet::new();
        assert_eq!(
            confirm(&host, &mut mode, &mut seen, &make_card()),
            Decision::Proceed
        );
        assert!(
            host.output()
                .iter()
                .any(|line| line.contains("long explanation"))
        );
    }

    #[test]
    fn resume_skips_done_step_until_hash_changes() {
        let host = MockHost::new();
        let mut state = State::new(&host, "0.5.115", Decisions::default());
        let hash = input_hash(&["guided", "C", "3"]);
        state.set_step(&host, "stage1/step", Status::Done, hash.clone(), Vec::new());

        assert!(state.should_skip("stage1/step", &hash));
        let changed = input_hash(&["guided", "C", "5"]);
        assert!(!state.should_skip("stage1/step", &changed));

        state.invalidate("stage1/step");
        assert!(!state.should_skip("stage1/step", &hash));
    }

    #[test]
    fn state_saves_atomically_and_round_trips() {
        let host = MockHost::new();
        let decisions = Decisions {
            mode: "guided".to_owned(),
            drives: vec!["C".to_owned()],
            tools: vec!["es".to_owned()],
            rounds: 3,
            drop_cache: true,
        };
        let mut state = State::new(&host, "0.5.115", decisions);
        let hash = input_hash(&["guided", "C", "3"]);
        state.set_step(&host, "stage1/step", Status::Done, hash.clone(), Vec::new());

        let path = PathBuf::from("/out/state.json");
        state.save(&host, &path).expect("save state");

        let calls = host.calls();
        let write_pos = calls
            .iter()
            .position(|call| matches!(call, Call::WriteFile(target) if target.ends_with("state.json.tmp")))
            .expect("tmp write recorded");
        let rename_pos = calls
            .iter()
            .position(|call| matches!(call, Call::Rename(_, target) if target == &path))
            .expect("rename recorded");
        assert!(write_pos < rename_pos);

        let loaded = State::load(&host, &path).expect("load state");
        assert_eq!(loaded.decisions.mode, "guided");
        assert!(loaded.should_skip("stage1/step", &hash));
    }

    #[test]
    fn teardown_removes_only_remove_disposition() {
        let host = MockHost::new()
            .with_file("/keep.exe", b"k")
            .with_file("/drop.exe", b"d");
        let keep = Acquisition::new(&host, "keep", "/keep.exe", "url", "sha", Disposition::Keep);
        let drop_tool = Acquisition::new(
            &host,
            "drop",
            "/drop.exe",
            "url",
            "sha",
            Disposition::Remove,
        );

        assert!(teardown(&host, &[keep, drop_tool]).is_empty());
        assert!(host.path_exists(Path::new("/keep.exe")));
        assert!(!host.path_exists(Path::new("/drop.exe")));
    }

    #[test]
    fn teardown_skips_missing_acquisition() {
        let host = MockHost::new();
        let absent = Acquisition::new(
            &host,
            "absent",
            "/absent.exe",
            "url",
            "sha",
            Disposition::Remove,
        );
        assert!(teardown(&host, &[absent]).is_empty());
        assert!(
            !host
                .calls()
                .iter()
                .any(|call| matches!(call, Call::RemoveFile(_)))
        );
    }

    #[test]
    fn fingerprint_clean_when_unchanged() {
        let host = MockHost::new().with_file("/uffs.ini", b"v1");
        let spec = FingerprintSpec {
            ini_path: PathBuf::from("/uffs.ini"),
            cache_files: vec![PathBuf::from("/cache.bin")],
            env_keys: vec!["UFFS_BENCH_ABSENT".to_owned()],
            daemon_status_cmd: None,
        };
        let before = capture(&host, &spec);
        let after = capture(&host, &spec);
        assert_eq!(
            diff(&before, &after),
            Vec::<String>::new(),
            "identical captures must not drift"
        );
    }

    #[test]
    fn fingerprint_detects_ini_change() {
        let host = MockHost::new().with_file("/uffs.ini", b"v1");
        let spec = FingerprintSpec {
            ini_path: PathBuf::from("/uffs.ini"),
            cache_files: Vec::new(),
            env_keys: Vec::new(),
            daemon_status_cmd: None,
        };
        let before = capture(&host, &spec);
        host.write_file(Path::new("/uffs.ini"), b"v2")
            .expect("rewrite ini");
        let after = capture(&host, &spec);

        let diffs = diff(&before, &after);
        assert_eq!(diffs.len(), 1);
        assert!(
            diffs
                .first()
                .is_some_and(|line| line.contains("ini changed"))
        );
    }

    #[test]
    fn fingerprint_reports_daemon_state_via_run() {
        let host = MockHost::new()
            .with_file("/uffs.ini", b"v1")
            .with_run_result(ProcOutput {
                code: Some(0_i32),
                stdout: "running\n".to_owned(),
                stderr: String::new(),
            });
        let spec = FingerprintSpec {
            ini_path: PathBuf::from("/uffs.ini"),
            cache_files: Vec::new(),
            env_keys: Vec::new(),
            daemon_status_cmd: Some(("uffs".to_owned(), vec!["status".to_owned()])),
        };
        assert_eq!(capture(&host, &spec).daemon_state, "running");
    }

    #[test]
    fn resolve_tool_follows_precedence() {
        assert_eq!(
            resolve_tool(Some("/bin/es"), "/home", "es.exe"),
            ResolvedTool {
                command: "/bin/es".to_owned(),
                source: ToolSource::Explicit
            }
        );

        let home = resolve_tool(None, "/tools", "es.exe");
        assert_eq!(home.source, ToolSource::Home);
        assert!(home.command.contains("es.exe"));

        assert_eq!(resolve_tool(None, "", "es.exe"), ResolvedTool {
            command: "es.exe".to_owned(),
            source: ToolSource::Path
        });
    }

    #[test]
    fn new_bundle_creates_timestamped_dir() {
        let host = MockHost::new();
        let dir = new_bundle(&host, Path::new("/out"), "0.5.115").expect("create bundle");
        assert!(dir.starts_with("/out"));
        assert!(
            host.calls()
                .iter()
                .any(|call| matches!(call, Call::CreateDirAll(_)))
        );
    }

    /// `fetch-competitors` records a verified acquisition in `state.json`.
    ///
    /// Drives the full public dispatch (`run`): the manifest is seeded at its
    /// repo-relative path and the artifact the (mocked) downloader produces is
    /// pre-seeded at the bundle's tools path, so the post-download SHA-256
    /// check reads real bytes and the acquisition is persisted with its
    /// disposition.
    #[test]
    fn fetch_competitors_records_acquisition_in_state() {
        let artifact = b"pinned-es-artifact".to_vec();
        let mut hasher = Sha256::new();
        hasher.update(&artifact);
        let sha256 = hex::encode(hasher.finalize());

        let manifest = format!(
            "[everything]\nversion = \"1.1.0.30\"\n\
             es_url = \"https://example.test/dir/es.zip\"\nes_sha256 = \"{sha256}\"\n"
        );
        let host = MockHost::new()
            .with_file("scripts/windows/competitors.toml", manifest.into_bytes())
            .with_file("/out/bench/tools/es.zip", artifact);

        let cli = Cli::parse_from([
            "uffs-bench",
            "--keep-tools",
            "--bundle",
            "/out/bench",
            "fetch-competitors",
        ]);
        run(&host, &cli).expect("fetch-competitors succeeds");

        let saved = host
            .file(Path::new("/out/bench/state.json"))
            .expect("state.json is written");
        let state: State = serde_json::from_slice(&saved).expect("state.json parses");
        assert_eq!(state.acquisitions.len(), 1, "one acquisition recorded");
        let acq = state
            .acquisitions
            .first()
            .expect("one acquisition recorded");
        assert_eq!(acq.name, "es.zip");
        assert_eq!(acq.sha256, sha256);
        assert_eq!(acq.disposition, Disposition::Keep);
    }
}
