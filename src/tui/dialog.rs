//! Centered dialog overlay chrome: a clear-backed bordered area with a title
//! and its own hotkey footer. The shell stays visible behind it (no dark
//! scrim — terminals can't do translucency). The caller fills the returned
//! body rect.
//!
//! Foundation module: the wizards (host/cred add-edit) and the store-picker
//! overlay (Tasks 6/8/9) are the first production callers; unit tests already
//! exercise this path, so items carry `#[allow(dead_code)]` until the keystone
//! App rewrite wires them in — same pre-wired convention as `theme.rs` /
//! `tab.rs` / `shell.rs`.

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

/// Centered, clamped dialog rect inside `screen`.
///
/// The dialog is at most `MAX_W` x `MAX_H`, shrunk by a 2-cell margin
/// (`w-4` / `h-4`) so it never touches the screen edge, and centered. When the
/// screen is smaller than 6 cells on either axis the screen is returned as-is
/// (we can't center meaningfully and a zero-size rect would panic downstream).
#[allow(dead_code)]
pub fn dialog_area(screen: Rect) -> Rect {
    let w = MAX_W.min(screen.width.saturating_sub(4));
    let h = MAX_H.min(screen.height.saturating_sub(4));
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
/// `_body_area_count` is intentionally unused: it is reserved in the signature
/// so future callers can hint at the body's row count without changing the
/// API (the leading underscore keeps clippy quiet). The body is everything
/// inside the border minus the footer row.
///
/// Footer `hints` are `(key, label)` pairs joined by ` · `, with keys in the
/// accent color + bold and labels dimmed.
#[allow(dead_code)]
pub fn draw_dialog(
    frame: &mut Frame,
    title: &str,
    _body_area_count: u16,
    footer_hints: &[(&str, &str)],
) -> Rect {
    let area = dialog_area(frame.area());
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
    //! ratatui's job; these pin our `dialog_area` math (centering + clamping)
    //! and assert `draw_dialog` returns a usable body rect and doesn't panic
    //! over a TestBackend.
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn dialog_area_is_centered_and_clamped() {
        let screen = Rect::new(0, 0, 100, 40);
        let d = dialog_area(screen);
        // Clamped to the max footprint.
        assert!(d.width <= MAX_W);
        assert!(d.height <= MAX_H);
        // Centered: left margin equals right margin, top equals bottom.
        let left = d.x;
        let right = screen.width - (d.x + d.width);
        assert_eq!(left, right);
        let top = d.y;
        let bottom = screen.height - (d.y + d.height);
        assert_eq!(top, bottom);
    }

    #[test]
    fn dialog_area_clamps_on_tiny_screen() {
        // A terminal too small for the max footprint still yields a rect that
        // fits on screen (no overflow, no panic).
        let tiny = Rect::new(0, 0, 10, 5);
        let d = dialog_area(tiny);
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
