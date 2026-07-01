//! Design tokens for the TUI: a single accent color (Cyan) plus grayscale.
//! Every view draws its colors from here so the palette stays consistent
//! and minimal — no ad-hoc `Color::Foo` scattered across renderers.

use ratatui::{
    style::{Color, Modifier, Style},
    text::Span,
};

// These tokens are the theme's public surface; the shell renderer, panels,
// wizards, and status bar all consume them.
/// The single accent color: active tab, selected-row gutter, brand, links.
pub const ACCENT: Color = Color::Cyan;
/// Fuzzy-match highlight color.
pub const MATCH: Color = Color::Yellow;
/// Errors, delete confirm, downgrade warning.
pub const DANGER: Color = Color::Red;
/// Transient success messages.
///
/// Reserved for a transient success indicator; no production caller renders it
/// yet (the success path currently reuses the status-line message). Kept so the
/// palette stays complete and documented rather than sprinkling a literal
/// `Color::Green` later.
#[allow(dead_code)]
pub const OK: Color = Color::Green;

/// The brand word rendered in the shell's top band. Centralized so the shell's
/// `brand_len` arithmetic (derived from `BRAND.chars().count()`) and the accented
/// span never drift apart.
pub const BRAND: &str = "sshrack";

/// Accent style (fg only). Callers add modifiers as needed.
pub fn accent() -> Style {
    Style::new().fg(ACCENT)
}

/// The leading gutter mark for the selected list row.
pub fn selected_gutter() -> Span<'static> {
    Span::styled("▎", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))
}

/// The selection marker shared by list rows and form fields: `▶ ` accented +
/// bold when focused/selected, two spaces when not. Both forms are 2 cells
/// wide, so every row's content starts at the same column regardless of which
/// row is selected (no selected-row left-shift). Mirrors the wizard's
/// focused-field marker.
#[allow(dead_code)]
pub fn focus_marker(focused: bool) -> Span<'static> {
    if focused {
        Span::styled("▶ ", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))
    } else {
        Span::raw("  ")
    }
}

/// The brand word `sshrack`, accented + bold. Uses [`BRAND`] so the literal
/// lives in exactly one place.
pub fn brand_span() -> Span<'static> {
    Span::styled(BRAND, Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accent_is_cyan() {
        assert_eq!(ACCENT, Color::Cyan);
    }

    #[test]
    fn match_is_yellow_danger_is_red_ok_is_green() {
        assert_eq!(MATCH, Color::Yellow);
        assert_eq!(DANGER, Color::Red);
        assert_eq!(OK, Color::Green);
    }

    #[test]
    fn selected_gutter_is_accented_bar() {
        let span = selected_gutter();
        assert_eq!(span.content.as_ref(), "▎");
    }

    #[test]
    fn brand_span_reads_sshrack() {
        let span = brand_span();
        assert_eq!(span.content.as_ref(), "sshrack");
    }

    #[test]
    fn focus_marker_is_accented_arrow_when_focused_else_two_spaces() {
        let on = focus_marker(true);
        let off = focus_marker(false);
        assert_eq!(on.content.as_ref(), "▶ ");
        assert_eq!(off.content.as_ref(), "  ");
        // Both markers occupy the same number of cells, so a selected row's
        // content starts at the same column as an unselected row's — no shift.
        assert_eq!("▶ ".chars().count(), "  ".chars().count());
    }
}
