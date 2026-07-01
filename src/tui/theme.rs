//! Design tokens for the TUI: a single accent color (Cyan) plus grayscale.
//! Every view draws its colors from here so the palette stays consistent
//! and minimal — no ad-hoc `Color::Foo` scattered across renderers.

use ratatui::{
    style::{Color, Modifier, Style},
    text::Span,
};

// These tokens are the theme's public surface; later tasks (shell renderer,
// panels, status bar) consume them. `#[allow(dead_code)]` is the codebase's
// established convention for pre-declared-but-not-yet-wired TUI surface (see
// popup.rs / prompt.rs / launcher.rs); it tolerates the dual build where the
// unit tests already reference the items while production callers land later.
/// The single accent color: active tab, selected-row gutter, brand, links.
#[allow(dead_code)]
pub const ACCENT: Color = Color::Cyan;
/// Fuzzy-match highlight color.
#[allow(dead_code)]
pub const MATCH: Color = Color::Yellow;
/// Errors, delete confirm, downgrade warning.
#[allow(dead_code)]
pub const DANGER: Color = Color::Red;
/// Transient success messages.
#[allow(dead_code)]
pub const OK: Color = Color::Green;

/// Accent style (fg only). Callers add modifiers as needed.
#[allow(dead_code)]
pub fn accent() -> Style {
    Style::new().fg(ACCENT)
}

/// The leading gutter mark for the selected list row.
#[allow(dead_code)]
pub fn selected_gutter() -> Span<'static> {
    Span::styled("▎", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))
}

/// The brand word `sshrack`, accented + bold.
#[allow(dead_code)]
pub fn brand_span() -> Span<'static> {
    Span::styled(
        "sshrack",
        Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
    )
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
}
