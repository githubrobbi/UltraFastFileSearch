// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! GitHub Releases fetch + asset download (blocking `reqwest` + rustls).
//!
//! One-shot HTTP for an acquire step — a release lookup plus streaming
//! asset downloads. TLS is rustls with the system trust store; we never
//! follow off-host redirects beyond what `reqwest` validates against the
//! pinned `api.github.com` / release host.
//!
//! [`fetch_release`] is GitHub-specific; [`download_to`] streams **any**
//! URL, so it also serves non-GitHub hosts (model registries, package
//! feeds, …). The caller supplies the user-agent product string (GitHub
//! requires one for API requests) and the per-download byte cap.

use core::time::Duration;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;

/// Cap on how long we wait to establish a TCP/TLS connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-operation (connect/read/write) inactivity cap. On the blocking
/// client this is a socket-level read/write timeout, so a stalled socket
/// is killed without bounding the total time of a large download.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Total attempts (initial + retries) for a transient HTTP failure.
const MAX_ATTEMPTS: u32 = 4;

/// Base back-off; the delay before attempt *n* is `BASE_BACKOFF * 2^(n-1)`.
const BASE_BACKOFF: Duration = Duration::from_millis(500);

/// Streaming copy buffer size.
const CHUNK_BYTES: usize = 64 * 1024;

/// A GitHub release (only the fields we use).
#[derive(Debug, Deserialize)]
pub struct Release {
    /// The release tag (e.g. `v0.6.2`).
    pub tag_name: String,
    /// Downloadable assets attached to the release.
    pub assets: Vec<Asset>,
}

/// One downloadable release asset.
#[derive(Debug, Deserialize)]
pub struct Asset {
    /// Asset file name (e.g. `uffs-windows-x64.zip`).
    pub name: String,
    /// Direct download URL.
    pub browser_download_url: String,
}

impl Release {
    /// Find an asset by exact file name.
    #[must_use]
    pub fn asset(&self, name: &str) -> Option<&Asset> {
        self.assets.iter().find(|asset| asset.name == name)
    }
}

/// Build a blocking client with the caller's user agent and the connect
/// + read timeouts (a hung socket can never wedge a download forever).
fn client(user_agent: &str) -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(user_agent)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(READ_TIMEOUT)
        .build()
        .context("building HTTP client")
}

/// Whether a `reqwest` failure is worth retrying: a connect/read timeout
/// or a server-side (5xx / 429) status. Client (4xx) errors and decode
/// errors are deterministic, so they fail fast.
fn is_retryable(err: &reqwest::Error) -> bool {
    if err.is_timeout() || err.is_connect() {
        return true;
    }
    err.status()
        .is_some_and(|status| status.as_u16() == 429 || status.is_server_error())
}

/// Run `op` with bounded exponential back-off (4 attempts, 500ms base).
///
/// Only transient failures are retried: connect/read timeouts, HTTP 429,
/// and 5xx statuses. `label` describes the operation for the final error
/// context.
///
/// # Errors
///
/// Returns the last `op` error once attempts are exhausted, or the first
/// non-retryable one, wrapped with `label` and the attempt count.
pub fn with_retry<T, F>(label: &str, mut op: F) -> Result<T>
where
    F: FnMut() -> reqwest::Result<T>,
{
    let mut attempt: u32 = 1;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) if attempt < MAX_ATTEMPTS && is_retryable(&err) => {
                let backoff = BASE_BACKOFF * 2_u32.pow(attempt.saturating_sub(1));
                std::thread::sleep(backoff);
                attempt = attempt.saturating_add(1);
            }
            Err(err) => {
                return Err(err).with_context(|| format!("{label} (after {attempt} attempt(s))"));
            }
        }
    }
}

/// Stream `reader` into `writer`, aborting if the total exceeds `cap`.
/// Invokes `on_chunk` with the running byte total after every written
/// chunk. Returns the number of bytes written.
fn copy_capped<R, W, P>(reader: &mut R, writer: &mut W, cap: u64, mut on_chunk: P) -> Result<u64>
where
    R: Read,
    W: Write,
    P: FnMut(u64),
{
    let mut buf = vec![0_u8; CHUNK_BYTES];
    let mut total: u64 = 0;
    loop {
        let read = reader.read(&mut buf).context("reading response body")?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if total > cap {
            bail!("asset exceeds the {cap}-byte cap — aborting download");
        }
        let chunk = buf.get(..read).context("response chunk out of range")?;
        writer.write_all(chunk).context("writing to disk")?;
        on_chunk(total);
    }
    Ok(total)
}

/// Fetch a release from `owner/repo`: the `latest` release, or the
/// specific `tag` when given.
///
/// `user_agent` is the product string sent with the request (e.g.
/// `myproduct/1.2.3`) — GitHub rejects agent-less API calls.
///
/// # Errors
///
/// Propagates HTTP, status, and JSON-decode failures.
pub fn fetch_release(user_agent: &str, repo: &str, tag: Option<&str>) -> Result<Release> {
    let url = tag.map_or_else(
        || format!("https://api.github.com/repos/{repo}/releases/latest"),
        |wanted| format!("https://api.github.com/repos/{repo}/releases/tags/{wanted}"),
    );
    let client = client(user_agent)?;
    let response = with_retry(&format!("requesting {url}"), || {
        client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .send()?
            .error_for_status()
    })?;
    response.json::<Release>().context("parsing release JSON")
}

/// Stream `url` (any host, not just GitHub) to `dest`, aborting once
/// the body exceeds `max_bytes`.
///
/// The cap defends the disk against a truncated, malicious, or runaway
/// response — size it to the largest asset the caller legitimately
/// expects.
///
/// # Errors
///
/// Propagates HTTP, status, cap-exceeded, and file-write failures.
pub fn download_to(user_agent: &str, url: &str, dest: &Path, max_bytes: u64) -> Result<()> {
    download_to_with_progress(user_agent, url, dest, max_bytes, |_, _| {})
}

/// [`download_to`] with a progress hook: `on_chunk(bytes_so_far, total)`
/// fires after every written chunk, where `total` is the response's
/// `Content-Length` when the server sent one.
///
/// Multi-GiB downloads are otherwise indistinguishable from a hang — the
/// hook gives callers a heartbeat to drive a progress bar or watchdog.
///
/// # Errors
///
/// Propagates HTTP, status, cap-exceeded, and file-write failures.
pub fn download_to_with_progress<P>(
    user_agent: &str,
    url: &str,
    dest: &Path,
    max_bytes: u64,
    mut on_chunk: P,
) -> Result<()>
where
    P: FnMut(u64, Option<u64>),
{
    let client = client(user_agent)?;
    let mut response = with_retry(&format!("downloading {url}"), || {
        client.get(url).send()?.error_for_status()
    })?;
    let total = response.content_length();
    let mut file =
        std::fs::File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
    copy_capped(&mut response, &mut file, max_bytes, |written| {
        on_chunk(written, total);
    })
    .with_context(|| format!("writing {}", dest.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::copy_capped;

    /// Progress callback that records nothing — for tests not about progress.
    fn no_progress(_total: u64) {}

    #[test]
    fn copy_capped_writes_all_under_cap() {
        let src = vec![7_u8; 200];
        let mut reader = src.as_slice();
        let mut sink: Vec<u8> = Vec::new();
        let written =
            copy_capped(&mut reader, &mut sink, 1024, no_progress).expect("under cap copies");
        assert_eq!(written, 200);
        assert_eq!(sink, src);
    }

    #[test]
    fn copy_capped_aborts_over_cap() {
        let src = vec![0_u8; 4096];
        let mut reader = src.as_slice();
        let mut sink: Vec<u8> = Vec::new();
        let err =
            copy_capped(&mut reader, &mut sink, 100, no_progress).expect_err("over cap must abort");
        assert!(err.to_string().contains("cap"), "unexpected: {err}");
    }

    #[test]
    fn copy_capped_handles_empty_body() {
        let mut reader: &[u8] = &[];
        let mut sink: Vec<u8> = Vec::new();
        let written = copy_capped(&mut reader, &mut sink, 100, no_progress).expect("empty copies");
        assert_eq!(written, 0);
        assert_eq!(sink, Vec::<u8>::new(), "sink must stay untouched");
    }

    #[test]
    fn copy_capped_reports_monotonic_progress() {
        // 3 chunks' worth of data → the hook must fire once per chunk with
        // a strictly increasing running total ending at the full size.
        let size = super::CHUNK_BYTES * 2 + 100;
        let src = vec![1_u8; size];
        let mut reader = src.as_slice();
        let mut sink: Vec<u8> = Vec::new();
        let mut seen: Vec<u64> = Vec::new();
        let written = copy_capped(&mut reader, &mut sink, u64::MAX, |total| seen.push(total))
            .expect("copies with progress");
        assert_eq!(written, u64::try_from(size).expect("fits"));
        assert!(seen.len() >= 3, "one callback per chunk: {seen:?}");
        assert!(
            seen.iter()
                .zip(seen.iter().skip(1))
                .all(|(prev, next)| prev < next),
            "monotonic: {seen:?}"
        );
        assert_eq!(seen.last().copied(), Some(written));
    }
}
