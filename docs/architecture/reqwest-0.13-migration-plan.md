<!--
SPDX-License-Identifier: MPL-2.0
Copyright (c) 2025-2026 SKY, LLC.

UFFS — reqwest 0.12 to 0.13 Migration Plan
-->

# reqwest 0.12 to 0.13 Migration Plan (v1)

Status: **PLANNING / not started**. Author: Robert S. A. Nio. Owner: SKY, LLC.
Related: [[access-broker-followups]] (TLS/handle plumbing style), the ring
nightly-canary blocker (issue #553), `vet-deps-real-audit-procedure`.

---

## 1. TL;DR

reqwest `0.13` removed the `rustls-tls-native-roots` / `rustls-tls` feature
flags and replaced the whole rustls TLS model with a
**`rustls-platform-verifier` + pluggable-crypto-provider** design. Our pin at
`0.12.28` is therefore still correct today, but `0.12` will eventually stop
receiving fixes and we must migrate.

- **Recommended path: Option B — `reqwest 0.13` with `rustls-no-provider` +
  an explicit `ring` `CryptoProvider` installed at `uffs-update` startup.**
  This keeps the crypto backend we already cross-compile (`ring`), avoids the
  heavy `aws-lc-sys` C build, and stays a single-provider tree.
- The only hard risk is **cross-compilation to `x86_64-pc-windows-msvc` (and
  `x86_64-unknown-linux-musl`) via `cargo xwin`**. Option B inherits the
  already-proven `ring` build; Option A (`aws-lc-rs`) does not and is the main
  thing that makes this a "headache."
- Blast radius is small: reqwest is used in **exactly one crate**
  (`uffs-update`), one file (`github.rs`), one function (`client()`), with **no
  explicit TLS-builder calls**. The code delta is a few lines plus one
  provider-install call.
- This migration does **not** resolve the ring `0.17.14` nightly-canary blocker
  (#553): `ring` is still pulled transitively by `object_store`, `rustls`, and
  `rustls-webpki` regardless of the reqwest feature we pick. Do not conflate the
  two.

---

## 2. Current state (as of 2026-07-14, v0.6.27)

### 2.1 Declaration

`Cargo.toml` (workspace):

```toml
reqwest = { version = "0.12.28", default-features = false, features = [
  "blocking",
  "rustls-tls-native-roots",
  "json",
] }
```

Consumed by **`uffs-update` only** (`crates/uffs-update/Cargo.toml`:
`reqwest.workspace = true`). `uffs-update` is a **separate binary** from `uffs`
precisely so the HTTP + TLS stack never bloats the lean, fast-starting CLI. That
isolation invariant must survive the migration (see §7.4).

### 2.2 Usage surface (the entire thing)

`crates/uffs-update/src/github.rs`:

```rust
fn client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(CONNECT_TIMEOUT) // 30 s
        .timeout(READ_TIMEOUT)            // 60 s
        .build()
        .context("building HTTP client")
}
```

- Requests: `client.get(url).send()?.error_for_status()`, plus a capped
  streaming body copy (`copy_capped`). Blocking. No async runtime.
- Endpoints: GitHub Releases API + asset download hosts (public CAs).
- **No TLS-builder calls at all** (`use_rustls_tls`, `add_root_certificate`,
  `tls_built_in_native_certs`, `danger_*` are all absent). TLS behavior is
  entirely determined by the feature flag: today that means "rustls with the OS
  trust store." This is the single most important fact for the migration: we are
  not configuring rustls by hand, so we only have to preserve the *default*
  behavior ("rustls + system trust"), not reproduce a custom builder.
- Retry/timeout logic (`is_retryable`, `with_retry`) keys on
  `reqwest::Error::{is_timeout, is_connect, status}` and
  `reqwest::Result` / `reqwest::Error`. These APIs are unchanged in 0.13 and
  need no edits (confirm during §6.1).

### 2.3 Lock state (crypto / TLS deps today)

| Crate | Version | Role |
|---|---|---|
| `ring` | 0.17.14 | crypto provider (via `rustls`, `rustls-webpki`, `object_store`) |
| `rustls` | 0.23.40 | TLS |
| `rustls-webpki` | 0.103.13 | cert path validation |
| `rustls-native-certs` | 0.8.4 | loads OS root store into rustls (what `-native-roots` pulls) |
| `aws-lc-rs` | absent | — |
| `aws-lc-sys` | absent | — |
| `rustls-platform-verifier` | absent | — |

---

## 3. Why 0.13 broke the pin (what actually changed)

reqwest `0.13` did not rename the feature. It **replaced the rustls model**:

| reqwest 0.12 (ours) | reqwest 0.13.4 |
|---|---|
| `rustls-tls` = rustls + webpki bundled roots | removed |
| `rustls-tls-native-roots` = rustls + `rustls-native-certs` (OS roots), crypto = `ring` | removed |
| default-tls = `native-tls` (OpenSSL/schannel) | **default-tls = `rustls`** |
| — | `rustls` = `rustls-platform-verifier` + **`aws-lc-rs`** (crypto forced) |
| — | `rustls-no-provider` = `rustls-platform-verifier`, **no** crypto provider |

Two consequences:

1. **Trust model change.** `rustls-native-certs` *imports* the OS root
   certificates into rustls' own webpki verifier. `rustls-platform-verifier`
   instead *delegates verification to the OS* (SecTrust on macOS, CryptoAPI on
   Windows, OpenSSL/native on Linux). For our use (public-CA HTTPS to GitHub)
   these are functionally equivalent; platform-verifier is arguably more correct
   (honors OS revocation and policy). Still, it is a behavior change and must be
   smoke-tested against a real GitHub download on all three platforms (§6.3).
2. **Crypto-provider selection is now explicit.** In 0.12 the `ring` provider
   was implicit. In 0.13 you either accept `aws-lc-rs` (the `rustls` feature) or
   bring your own (`rustls-no-provider`). This is the crux of the decision.

---

## 4. Options

### Option A — `reqwest 0.13` with the `rustls` feature (aws-lc-rs)

```toml
reqwest = { version = "0.13.4", default-features = false, features = [
  "blocking", "json", "rustls",
] }
```

- **Pros:** smallest Cargo change; the idiomatic 0.13 default; no startup code.
- **Cons (why this is the headache path):**
  - Pulls **`aws-lc-rs` + `aws-lc-sys`**, a vendored AWS-LC C/assembly build.
    Cross-compiling `aws-lc-sys` from macOS to `x86_64-pc-windows-msvc` via
    `cargo xwin` needs NASM + a C toolchain for the target and is materially
    harder than `ring`; it is the single most likely thing to break the Windows
    ship job. `musl` (Linux) builds of `aws-lc-sys` are also touchier than ring.
  - **Dual crypto providers.** `ring` stays in the tree (object_store, rustls,
    rustls-webpki still pull it), so both `ring` and `aws-lc-rs` are compiled in.
    rustls then has no unambiguous process default and
    `ClientConfig::builder()` (the path reqwest uses internally) will **panic at
    runtime** with "no process-level CryptoProvider available" unless we call
    `CryptoProvider::install_default(...)` once at startup anyway. So Option A
    does not even save us the startup call.
  - New heavyweight deps to `cargo vet` (real `safe-to-deploy` audits for
    `aws-lc-rs` and the vendored-C `aws-lc-sys`), larger `uffs-update` binary,
    longer build.
- **Verdict:** rejected as the default. Only revisit if upstream forces
  aws-lc-rs or if `rustls-no-provider` is dropped.

### Option B — `reqwest 0.13` with `rustls-no-provider` + explicit `ring` (RECOMMENDED)

```toml
reqwest = { version = "0.13.4", default-features = false, features = [
  "blocking", "json", "rustls-no-provider",
] }
```

Plus a one-time provider install at `uffs-update` startup (see §5.2).

- **Pros:**
  - Keeps **`ring`** as the only crypto provider — the exact backend the xwin
    and musl pipelines already build successfully. Lowest cross-compile risk.
  - Single-provider tree (no dual-provider ambiguity once we install the ring
    default explicitly).
  - No `aws-lc-sys` C build, smaller binary, smaller audit surface.
- **Cons:**
  - `rustls-platform-verifier` still enters the lock (unavoidable in 0.13; it is
    the trust mechanism). Needs a `cargo vet` audit.
  - Requires the explicit `CryptoProvider::install_default` call and a
    `rustls` (with `ring` feature) direct dev/normal dependency in
    `uffs-update` so we can name the provider. Small, contained.
  - Must keep our direct `rustls` version aligned with the one reqwest 0.13
    resolves (single `rustls` in the graph) so `install_default` targets the
    same `CryptoProvider` type reqwest uses.
- **Verdict:** recommended.

### Option C — native-tls

Rejected on principle. `uffs-update`'s design note explicitly commits to rustls
("we never [use OpenSSL/schannel]"). native-tls reintroduces the OS TLS stack we
deliberately avoid.

---

## 5. Recommended implementation (Option B), step by step

### 5.1 Cargo manifest

Workspace `Cargo.toml`:

```toml
# ───── Network (self-update acquire helper only) ─────
# reqwest 0.13 replaced `rustls-tls-native-roots` with a
# `rustls-platform-verifier` (OS-native cert verification) + pluggable
# crypto-provider model. We use `rustls-no-provider` and install the `ring`
# provider ourselves (see uffs-update main) so the crypto backend stays `ring`
# — the one the xwin/musl cross-builds already prove — instead of dragging in
# aws-lc-sys. rustls-platform-verifier replaces rustls-native-certs for trust.
reqwest = { version = "0.13.4", default-features = false, features = [
  "blocking",
  "json",
  "rustls-no-provider",
] }

# Direct handle on rustls so uffs-update can install the ring CryptoProvider as
# the process default. Keep the version pinned to whatever reqwest 0.13 resolves
# so there is exactly one rustls in the graph.
rustls = { version = "0.23", default-features = false, features = ["ring"] }
```

`crates/uffs-update/Cargo.toml`: add `rustls.workspace = true` next to the
existing `reqwest.workspace = true`.

> Confirm the exact resolved `rustls` minor (`cargo tree -p reqwest -i rustls`
> after the bump) and match it; a split rustls graph would make
> `install_default` target the wrong provider type.

### 5.2 Provider install at startup

`crates/uffs-update/src/main.rs`, once, before any HTTPS call (top of `main`
before dispatch), documented and error-tolerant:

```rust
/// Install the process-wide rustls crypto provider (ring) exactly once.
/// reqwest 0.13's `rustls-no-provider` feature ships no default provider, so
/// the first `ClientConfig::builder()` inside reqwest would otherwise panic
/// with "no process-level CryptoProvider available". Idempotent: a second call
/// (or a provider already installed by a dependency) returns Err, which we
/// ignore.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
```

Call it at the very start of `main()`. Add a unit test that asserts the second
call is a no-op / does not panic, and that `github::client()` builds after it.

### 5.3 Code changes in `github.rs`

Expected: **none to the request logic.** `Client::builder().user_agent().connect_timeout().timeout().build()`,
`.get().send()`, `error_for_status()`, `is_timeout/is_connect/status`,
`reqwest::Error`/`reqwest::Result` are all stable across 0.12 to 0.13. Update
only the module doc comment (mention platform-verifier instead of
native-roots). Verify against the 0.13 changelog during §6.1; if any signature
moved, patch the one call site.

### 5.4 Expected lock delta

- **Added:** `rustls-platform-verifier` (+ its small platform shims:
  `rustls-native-certs` may remain or be replaced; on Apple/Windows the verifier
  uses OS APIs via `security-framework` / `windows-sys`, which are already in our
  tree via other deps — confirm).
- **Removed:** possibly `rustls-native-certs` (if nothing else pulls it).
- **Unchanged:** `ring`, `rustls`, `rustls-webpki`.
- **Not added:** `aws-lc-rs`, `aws-lc-sys` (the whole point of Option B).

Record the real delta from `cargo tree` after the change and paste it into the
PR.

---

## 6. Validation plan (the part that de-risks the headache)

### 6.1 Compile + API parity (host)
- [ ] `cargo build -p uffs-update` on macOS host (pinned nightly).
- [ ] Read the reqwest 0.13.0..0.13.4 changelog; confirm no breaking change hits
      our four call sites. Patch if needed.
- [ ] `just lint-prod` + `just lint-tests` clean.

### 6.2 Cross-compile (the primary risk gate)
- [ ] `just lint-ci-windows` (xwin clippy, `x86_64-pc-windows-msvc`) clean.
- [ ] Full `cargo xwin build -p uffs-update --release --target x86_64-pc-windows-msvc`
      succeeds (this is where aws-lc-sys would have failed; ring should sail).
- [ ] Linux `x86_64-unknown-linux-musl` release build of `uffs-update` succeeds.
- [ ] Confirm no `aws-lc-sys` in `cargo tree` for any target.

### 6.3 Runtime TLS smoke (all three platforms, real network)
- [ ] `uffs-update doctor` / `acquire` performs a real HTTPS GET against a live
      GitHub release and downloads an asset, on macOS arm64, Linux x64, Windows
      x64. This exercises `rustls-platform-verifier` against real public CAs.
- [ ] Negative check: a request to a host with an untrusted/self-signed cert is
      rejected (verifier is actually enforcing, not bypassed).
- [ ] Confirm the process does not panic on first request (provider install
      worked).

### 6.4 Supply chain
- [ ] `cargo vet` real `safe-to-deploy` audits for every newly-added crate
      (`rustls-platform-verifier` and any new platform shim). Follow
      `vet-deps-real-audit-procedure`; do **not** rubber-stamp exemptions.
- [ ] `cargo deny check` clean (licenses/advisories for new deps).
- [ ] `cargo vet check --locked` green (matches the committed `imports.lock`;
      remember the imports.lock `--locked` gotcha from the v0.6.27 ship).

### 6.5 Full gate
- [ ] `just lint-pre-push` fully green (all buckets), then normal push.

---

## 7. Risks and mitigations

| Risk | Likelihood (Option B) | Mitigation |
|---|---|---|
| xwin/musl cross-build fails on a new crypto C dep | Low (ring reused) | §6.2 gates before merge; Option B avoids aws-lc-sys entirely |
| Runtime panic: no default CryptoProvider | Medium if forgotten | §5.2 explicit `install_default`; §6.3 first-request smoke |
| Split rustls graph (install targets wrong provider) | Low | Pin direct `rustls` to reqwest's resolved minor; assert single rustls in `cargo tree` |
| platform-verifier trust behaves differently than native-certs | Low | §6.3 real-download smoke on all three OSes + negative test |
| New deps stall the vet gate | Low | §6.4 real audits up front, in the same PR |
| Binary size / build time of `uffs-update` grows | Low | measure; still far smaller than aws-lc-rs path; isolation preserved (§7.4) |

### 7.4 Isolation invariant
reqwest lives only in `uffs-update`. The migration must **not** let
`reqwest`/`rustls-platform-verifier` leak into `uffs`, `uffsd`, or any hot-path
crate. Verify post-change with
`cargo tree -e no-dev -i reqwest` (only `uffs-update`) and confirm the main
`uffs` binary's dep tree is unchanged.

### 7.5 Relationship to the ring nightly-canary blocker (#553)
Neither option removes `ring` from the tree, so **this migration has no effect
on #553** (the `ring 0.17.14` aarch64-apple const-eval regression on the
floating nightly). Track #553 separately; it clears only when upstream ring
ships a fix and we `cargo update -p ring`.

---

## 8. Rollout / sequencing

1. Branch `feat/reqwest-0.13-migration` off `main`. Do **not** bundle with an
   unrelated dep-bump sweep or a release.
2. Implement §5, then walk §6 top to bottom. Treat §6.2 (cross-compile) as the
   go/no-go gate: if aws-lc-sys somehow sneaks in or ring fails to cross, stop
   and reassess.
3. Open a normal PR (not a release PR). Let the merge-queue heavy jobs
   (Windows clippy + tests, Linux, vet, deny) run. Paste the `cargo tree` lock
   delta and the three-platform download-smoke results into the PR body.
4. Merge via the queue. Ship in the next routine `just ship-fresh` (the change
   is code + deps, so it rides a normal version bump).

## 9. Rollback

Trivial and low-stakes: revert the `Cargo.toml`/`Cargo.lock`/`main.rs` changes
back to the `reqwest 0.12.28` pin (still on crates.io and maintained) and the
`ring`/native-certs tree returns. Because reqwest is confined to `uffs-update`,
a rollback cannot affect search, indexing, or the daemon.

## 10. Open questions / decisions to lock before coding

- [ ] Confirm reqwest 0.13's MSRV vs our pinned toolchain and `edition = 2024`.
- [ ] Confirm the exact `rustls` minor reqwest 0.13.4 resolves; pin our direct
      `rustls` to match.
- [ ] Confirm whether `rustls-platform-verifier` on Windows/macOS pulls
      `security-framework` / `windows-sys` versions already in our lock (avoid a
      second copy).
- [ ] Decide whether to keep `rustls-native-certs` if a transitive dep still
      needs it, or let it drop.
- [ ] Confirm `uffs-update`'s existing integration/e2e self-update test can run
      the real-download smoke in CI, or whether it stays a manual per-platform
      check.

---

## 11. Appendix — quick reference

**reqwest 0.13.4 rustls-relevant features**

```
default-tls          = ["rustls"]
rustls               = ["__rustls-aws-lc-rs", "dep:rustls-platform-verifier", "__rustls"]  # aws-lc-rs
rustls-no-provider   = ["dep:rustls-platform-verifier", "__rustls"]                        # bring your own
__rustls             = ["dep:hyper-rustls", "dep:tokio-rustls", "dep:rustls", "__tls"]
(no rustls-tls, no rustls-tls-native-roots, no webpki-roots feature)
```

**One-liners**
- Who pulls ring: `cargo tree -i ring --depth 1`
- Confirm no aws-lc: `cargo tree -i aws-lc-sys` (expect "not found")
- reqwest confinement: `cargo tree -e no-dev -i reqwest`
- Resolved rustls: `cargo tree -p reqwest -i rustls`
