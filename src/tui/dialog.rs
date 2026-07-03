//! Centered dialog overlay chrome: a clear-backed bordered area with a title
//! and its own hotkey footer. The shell stays visible behind it (no dark
//! scrim — terminals can't do translucency). The caller fills the returned
//! body rect.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};

use crate::tui::theme;

/// Maximum dialog footprint. On larger terminals the dialog holds at this size
/// rather than growing; on smaller ones it clamps down (see [`dialog_area`]).
const MAX_W: u16 = 80;
const MAX_H: u16 = 24;

/// Centered, content-fit dialog rect inside `screen`. The outer height is
/// `body_rows + 2 (border) + 1 (footer)`, clamped down to [`MAX_H`] and to the
/// screen height (minus a 2-cell margin). Width stays at most [`MAX_W`] (forms
/// need the room for long values). Returns `screen` as-is when either axis < 6.
pub fn dialog_area(screen: Rect, body_rows: u16) -> Rect {
    let w = MAX_W.min(screen.width.saturating_sub(4));
    let outer_h = body_rows
        .saturating_add(3) // border(2) + footer(1)
        .min(MAX_H)
        .min(screen.height.saturating_sub(4));
    // Floor the height at the dialog chrome itself (2 border + 1 footer = 3)
    // so a zero/near-zero body_rows still yields a visible chrome.
    let h = outer_h.max(3);
    if screen.width < 6 || screen.height < 6 {
        return screen;
    }
    // Three-segment layouts with the dialog in the middle, flanked by Fill
    // spacers, center it both horizontally and vertically.
    let [_, vmid, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(h),
        Constraint::Fill(1),
    ])
    .areas(screen);
    let [_, area, _] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(w),
        Constraint::Fill(1),
    ])
    .areas(vmid);
    area
}

/// Clear the dialog area, draw a titled bordered block with a 1-row hotkey
/// footer, and return the body rect for the caller to fill.
///
/// `body_rows` is the caller's content row count; it drives the outer height
/// via [`dialog_area`] so the dialog fits its content instead of always
/// maxing out at [`MAX_H`]. The body is everything inside the border minus the
/// footer row.
///
/// Footer `hints` are `(key, label)` pairs joined by ` · `, with keys in the
/// accent color + bold and labels dimmed.
pub fn draw_dialog(
    frame: &mut Frame,
    title: &str,
    body_rows: u16,
    footer_hints: &[(&str, &str)],
) -> Rect {
    let area = dialog_area(frame.area(), body_rows);
    // Clear the background so the shell behind doesn't bleed through (no dark
    // scrim — terminals can't do translucency, and a Clear is enough).
    frame.render_widget(Clear, area);
    let block = Block::new()
        .borders(Borders::ALL)
        .title(format!(" {title} "))
        .title_style(theme::accent().add_modifier(Modifier::BOLD));
    frame.render_widget(&block, area);
    let inner = block.inner(area);
    // Body gets everything except the bottom 1-row footer.
    let [body, footer] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(inner);

    let mut spans: Vec<Span> = Vec::new();
    for (i, (key, label)) in footer_hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", Style::new().dim()));
        }
        spans.push(Span::styled(
            *key,
            theme::accent().add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(format!(" {label}"), Style::new().dim()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), footer);
    body
}

#[cfg(test)]
mod tests {
    //! Geometry + no-panic tests for the dialog chrome. Rendering itself is
    //! ratatui's job; these pin our `dialog_area` math (content-fit height,
    //! centering, and clamping) and assert `draw_dialog` returns a usable body
    //! rect and doesn't panic over a TestBackend.
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn dialog_area_height_tracks_body_rows_then_clamps_to_max() {
        let screen = Rect::new(0, 0, 100, 40);
        // body 5 -> outer = 5 + 2 border + 1 footer = 8.
        let d = dialog_area(screen, 5);
        assert_eq!(d.height, 8);
        // body 100 -> clamps to MAX_H (24).
        let d = dialog_area(screen, 100);
        assert_eq!(d.height, MAX_H);
    }

    #[test]
    fn dialog_area_height_clamps_to_screen_when_terminal_short() {
        // 12-row screen: outer must fit (minus 4-cell margin -> <= 8), not
        // overflow.
        let screen = Rect::new(0, 0, 100, 12);
        let d = dialog_area(screen, 50);
        assert!(d.height <= screen.height);
        assert!(d.y + d.height <= screen.height, "must not overflow screen");
    }

    #[test]
    fn dialog_area_still_centers_and_clamps_width() {
        let screen = Rect::new(0, 0, 100, 40);
        let d = dialog_area(screen, 5);
        assert!(d.width <= MAX_W);
        let left = d.x;
        let right = screen.width - (d.x + d.width);
        assert_eq!(left, right, "horizontally centered");
    }

    #[test]
    fn dialog_area_clamps_on_tiny_screen() {
        // A terminal too small for the max footprint still yields a rect that
        // fits on screen (no overflow, no panic).
        let tiny = Rect::new(0, 0, 10, 5);
        let d = dialog_area(tiny, 5);
        assert!(d.width <= tiny.width);
        assert!(d.height <= tiny.height);
    }

    #[test]
    fn draw_dialog_returns_body_area_and_renders_without_panic() {
        let backend = TestBackend::new(100, 40);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let body = draw_dialog(
                f,
                " add host ",
                5,
                &[("Tab", "next"), ("^S", "save"), ("Esc", "cancel")],
            );
            // The body is everything inside the border minus the footer, so it
            // must be at least one row tall on a 40-row screen.
            assert!(body.height >= 1);
        })
        .unwrap();
    }
}
