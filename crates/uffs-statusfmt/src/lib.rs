// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2025-2026 SKY, LLC.

//! Shared operator-status styling for UFFS `--status` surfaces.
//!
//! One visual language for the daemon, broker, combined-system, and MCP status
//! output: a health [`Glyph`], aligned `key: value` [`field`]s, and [`section`]
//! headers, all through a single [`Palette`] that turns color **off**
//! automatically when stdout is not a terminal or `NO_COLOR` is set.
//!
//! Callers build lines with these helpers and print them; the machine-readable
//! `--json` form is modelled separately by each caller (this crate is purely
//! the human-facing look).

use std::io::IsTerminal as _;

/// ANSI SGR select codes used by [`Palette`]. Kept together so the escape
/// sequences live in exactly one place.
mod sgr {
    /// Reset all attributes.
    pub(super) const RESET: &str = "0";
    /// Bold / bright.
    pub(super) const BOLD: &str = "1";
    /// Dim / faint.
    pub(super) const DIM: &str = "2";
    /// Foreground green.
    pub(super) const GREEN: &str = "32";
    /// Foreground red.
    pub(super) const RED: &str = "31";
    /// Foreground yellow.
    pub(super) const YELLOW: &str = "33";
    /// Foreground cyan.
    pub(super) const CYAN: &str = "36";
}

/// Whether to emit ANSI color, decided once and threaded through the render.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    /// `true` when color escapes should be emitted.
    color: bool,
}

impl Palette {
    /// Auto-detect: color on only when **stdout is a terminal**, `NO_COLOR` is
    /// unset, and `TERM` is not `dumb`. This is the constructor operator
    /// commands should use so piped / redirected output stays plain.
    #[must_use]
    pub fn detect() -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        let dumb = std::env::var("TERM").is_ok_and(|term| term == "dumb");
        Self {
            color: std::io::stdout().is_terminal() && !no_color && !dumb,
        }
    }

    /// A palette that never emits color (for tests, `--json`, or forced-plain).
    #[must_use]
    pub const fn plain() -> Self {
        Self { color: false }
    }

    /// Whether this palette emits color.
    #[must_use]
    pub const fn is_color(self) -> bool {
        self.color
    }

    /// Wrap `text` in the SGR `code`, or return it unchanged when color is off.
    fn wrap(self, code: &str, text: &str) -> String {
        if self.color {
            format!("\u{1b}[{code}m{text}\u{1b}[{}m", sgr::RESET)
        } else {
            text.to_owned()
        }
    }

    /// Bold `text`.
    #[must_use]
    pub fn bold(self, text: &str) -> String {
        self.wrap(sgr::BOLD, text)
    }
    /// Dim / de-emphasize `text` (labels, secondary detail).
    #[must_use]
    pub fn dim(self, text: &str) -> String {
        self.wrap(sgr::DIM, text)
    }
    /// Green `text` (healthy / running).
    #[must_use]
    pub fn green(self, text: &str) -> String {
        self.wrap(sgr::GREEN, text)
    }
    /// Red `text` (error / failed).
    #[must_use]
    pub fn red(self, text: &str) -> String {
        self.wrap(sgr::RED, text)
    }
    /// Yellow `text` (warning / transitional).
    #[must_use]
    pub fn yellow(self, text: &str) -> String {
        self.wrap(sgr::YELLOW, text)
    }
    /// Cyan `text` (values, identifiers).
    #[must_use]
    pub fn cyan(self, text: &str) -> String {
        self.wrap(sgr::CYAN, text)
    }
}

/// A component's health, mapped to a consistent glyph + color across surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Glyph {
    /// Running / serving / healthy — green `●`.
    Up,
    /// Stopped / not running — dim `○`.
    Down,
    /// Transitional or degraded (loading, refreshing) — yellow `◐`.
    Warn,
    /// Not installed / not applicable — dim `·`.
    Off,
}

impl Glyph {
    /// The colored glyph for this health, per `palette`.
    #[must_use]
    pub fn render(self, palette: Palette) -> String {
        match self {
            Self::Up => palette.green("\u{25cf}"),    // ●
            Self::Down => palette.dim("\u{25cb}"),    // ○
            Self::Warn => palette.yellow("\u{25d0}"), // ◐
            Self::Off => palette.dim("\u{b7}"),       // ·
        }
    }
}

/// A top-level banner: `═══ title ═══` (bold when colored).
#[must_use]
pub fn header(palette: Palette, title: &str) -> String {
    let bar = "\u{2550}".repeat(3);
    palette.bold(&format!("{bar} {title} {bar}"))
}

/// A section header: `── title ──` (cyan when colored). Groups related fields.
#[must_use]
pub fn section(palette: Palette, title: &str) -> String {
    let dash = "\u{2500}".repeat(2);
    palette.cyan(&format!("{dash} {title} {dash}"))
}

/// One `  key:<pad> value` line, with the key dimmed and padded to `key_width`
/// so a block of fields aligns. `key` is given without its trailing colon.
#[must_use]
pub fn field(palette: Palette, key: &str, value: &str, key_width: usize) -> String {
    // Pad on the raw (uncolored) key+colon so alignment is escape-agnostic.
    let label = format!("{key}:");
    let pad = key_width.saturating_add(1).saturating_sub(label.len());
    format!("  {}{} {value}", palette.dim(&label), " ".repeat(pad))
}

/// A one-line component summary: `<glyph> <name>  <detail>` — the short-view
/// row (e.g. `● Daemon   running (PID 1234), 7 drives`). `detail` is optional.
#[must_use]
pub fn status_row(palette: Palette, glyph: Glyph, name: &str, detail: &str) -> String {
    let styled = palette.bold(name);
    if detail.is_empty() {
        format!("{} {styled}", glyph.render(palette))
    } else {
        format!("{} {styled}  {detail}", glyph.render(palette))
    }
}

#[cfg(test)]
mod tests {
    use super::{Glyph, Palette, field, header, section, status_row};

    #[test]
    fn plain_palette_emits_no_escapes() {
        let plain = Palette::plain();
        assert!(!plain.is_color());
        assert_eq!(plain.green("ok"), "ok");
        assert_eq!(plain.bold("x"), "x");
        assert!(!header(plain, "UFFS").contains('\u{1b}'));
        assert!(!Glyph::Up.render(plain).contains('\u{1b}'));
    }

    #[test]
    fn field_aligns_to_key_width() {
        let plain = Palette::plain();
        // key_width 10: "Status" (6) + ':' (1) → 4 pad spaces + 1 gap.
        assert_eq!(
            field(plain, "Status", "running", 10),
            "  Status:     running"
        );
        assert_eq!(field(plain, "PID", "42", 10), "  PID:        42");
    }

    #[test]
    fn header_and_section_shapes() {
        let plain = Palette::plain();
        assert_eq!(
            header(plain, "UFFS System Status"),
            "═══ UFFS System Status ═══"
        );
        assert_eq!(section(plain, "Daemon"), "── Daemon ──");
    }

    #[test]
    fn status_row_with_and_without_detail() {
        let plain = Palette::plain();
        assert_eq!(
            status_row(plain, Glyph::Up, "Daemon", "running"),
            "● Daemon  running"
        );
        assert_eq!(status_row(plain, Glyph::Down, "Daemon", ""), "○ Daemon");
    }
}
