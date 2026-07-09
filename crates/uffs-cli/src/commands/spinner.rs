// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! A braille spinner for blocking CLI steps that have no incremental progress
//! of their own (a `winget upgrade`, a cold-cache daemon start, …). Runs the
//! work on a scoped thread and animates until it finishes, then erases the
//! line — so a ~90 s wait reads as "working", not "hung".

use core::time::Duration;
use std::io::Write as _;

/// Spinner frame interval.
const POLL: Duration = Duration::from_millis(120);

/// Braille spinner frames.
const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Run `body` on a scoped thread while animating a spinner after `label`, then
/// erase the spinner line so the caller's next output lands clean. Returns
/// whatever `body` returns. For a blocking call that prints nothing itself —
/// drive the underlying work in its *quiet* form so the spinner owns the line.
#[expect(clippy::print_stdout, reason = "interactive progress spinner")]
pub(crate) fn spinner_while<T: Send>(label: &str, body: impl FnOnce() -> T + Send) -> T {
    // Width of the line drawn each frame ("  <glyph> <label>…      "), so the
    // final erase covers it exactly — a fixed width shorter than the label
    // leaves a stale tail on screen.
    let line_width = label.chars().count() + 11;
    std::thread::scope(|scope| {
        let handle = scope.spawn(body);
        let mut frame = 0_usize;
        while !handle.is_finished() {
            let glyph = FRAMES.get(frame % FRAMES.len()).copied().unwrap_or("*");
            print!("\r  {glyph} {label}\u{2026}      ");
            let _flushed = std::io::stdout().flush();
            std::thread::sleep(POLL);
            frame = frame.wrapping_add(1);
        }
        print!("\r{:line_width$}\r", "");
        let _flushed = std::io::stdout().flush();
        // Our closures never panic; aborting is safer than an unwrap the
        // workspace lints forbid anyway.
        handle.join().unwrap_or_else(|_| std::process::abort())
    })
}
